//! 胁迫密码（3.0.0）—— 反胁迫的最后防线。
//!
//! **模型**：任一分区可被其主人指定为「胁迫分区」。用胁迫分区的密码开柜时，
//! 外部观察者看到的是「正常打开了一个柜子」（诱饵文件可经受检查），但在返回
//! 会话**之前**，其他所有分区的头部条目（别名 / 盐 / 认证标签 / 包裹密钥 /
//! 索引定位）被整体覆写为随机字节 —— 与从未使用的条目在结构上不可区分，
//! 其他分区的数据从此**永久不可达**（密文仍在文件中，但没有任何密钥能定位
//! 或解密它们）。
//!
//! **隐蔽性设计**：
//! - 标记只存储在胁迫分区**自己的加密索引**内 —— 头部、文件布局、分区数量
//!   与普通保险柜完全无差异；不持有胁迫分区密码就无法观测标记的存在；
//! - 设置 / 触发均**不写审计日志** —— 诱饵柜的操作记录必须看起来完全正常；
//! - 触发覆写只重写头部一次（约 2 KiB），不产生可观察的批量 I/O。
//!
//! **红线（文档与 UI 均须如实告知）**：
//! - 触发即其他分区数据永久销毁，无任何找回手段；
//! - 演练模式通过对保险柜**临时副本**执行完整触发流程来验证机制，
//!   副本用后即 DoD 擦除，原件零接触。
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::*;
use crate::error::VaultError;

use super::consts::*;
use super::fs_util::load_index_from_file;
use super::header::{alias_field16, auth_tag_header_prefix, key_wrap_aad};
use super::Vault;
use crate::wipe::secure_wipe_vec;

impl Vault {
    /// 当前分区是否已被标记为胁迫分区（需已开柜）。
    pub fn is_duress_marked(&self) -> Result<bool, VaultError> {
        let index = self.cached_index.as_ref().ok_or(VaultError::NotOpen)?;
        Ok(index.duress)
    }

    /// 将**当前分区**标记为胁迫分区。
    ///
    /// 要求：
    /// - 保险柜已打开，且至少存在 2 个分区（单分区保险柜没有保护对象，
    ///   标记没有意义）；
    /// - 必须提供当前分区的密码（或密钥文件）—— 防止他人在已解锁机器上
    ///   恶意标记（把主人的分区变成胁迫分区，主人自己开柜就会销毁一切）；
    /// - **不写审计**（见模块文档）。
    pub fn set_duress_mark(
        &mut self,
        confirm_password: &str,
        key_file_data: Option<&[u8]>,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<(), VaultError> {
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let alias = self.partitions[active].alias.clone();
        self.set_duress_mark_on(&alias, confirm_password, key_file_data, yk_response)
    }

    /// 解除当前分区的胁迫标记（同样要求密码验证，防止恶意解除）。
    pub fn clear_duress_mark(
        &mut self,
        confirm_password: &str,
        key_file_data: Option<&[u8]>,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<(), VaultError> {
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let alias = self.partitions[active].alias.clone();
        self.clear_duress_mark_on(&alias, confirm_password, key_file_data, yk_response)
    }

    /// 3.0.0（UX 重构）：在**当前会话**中把任意分区（含新建的）标记/解除
    /// 胁迫分区 —— 无需先打开该分区。标记仍写入**目标分区自己的加密索引**
    ///（不可观测性不变）：后端用目标分区口令解包其 data_key → 解密其索引 →
    /// 改标志 → 重加密追加落盘 → 更新头部条目定位与审计锚点。
    /// 验证 = 目标分区口令（yk_response 参与二因子分区的双路径验证）；
    /// **不写审计**（胁迫分区承诺）。
    fn duress_mark_on(
        &mut self,
        target_alias: &str,
        target_password: &str,
        key_file_data: Option<&[u8]>,
        yk_response: Option<&[u8; 20]>,
        mark: bool,
    ) -> Result<(), VaultError> {
        if !self.is_open() {
            return Err(VaultError::NotOpen);
        }
        let pos = self
            .partitions
            .iter()
            .position(|p| p.alias == target_alias)
            .ok_or(VaultError::PartitionNotFound)?;
        if self.partitions.len() < 2 {
            return Err(VaultError::Other(
                "胁迫分区至少需要 2 个分区：请先创建用于隐藏真实数据的其他分区".into(),
            ));
        }
        // 允许标记当前分区（用户打开诱饵分区放好文件后原地标记是自然流程）；
        // 也允许标记其他分区（需目标口令解写其索引）。

        // 1. 用目标口令解包目标分区的 data_key（双路径：混合优先）
        let target = self.partitions[pos].clone();
        let alias_field = alias_field16(&target.alias);
        let prefix = auth_tag_header_prefix(&self.salt, self.format_version);
        let kek = Zeroizing::new(derive_kek(target_password, key_file_data, &target.salt)?);
        let wrap_aad = key_wrap_aad(&prefix, &alias_field, &target.salt);
        let stored = target.wrapped_key.unwrap_or([0u8; WRAPPED_KEY_SIZE]);
        let mut dk_opt: Option<Zeroizing<[u8; 32]>> = None;
        if let Some(resp) = yk_response {
            let mixed = Zeroizing::new(mix_kek_with_response(&kek, resp));
            dk_opt = unwrap_data_key(&mixed, &stored, &wrap_aad).map(Zeroizing::new);
        }
        if dk_opt.is_none() {
            dk_opt = unwrap_data_key(&kek, &stored, &wrap_aad).map(Zeroizing::new);
        }
        drop(kek);
        let dk = dk_opt.ok_or(VaultError::Other("目标分区密码（或硬件密钥）不正确".into()))?;
        let target_keys = expand_keys(&dk)?;

        // 2. 解密目标分区的索引（新开只读句柄，不干扰会话句柄游标）
        let path = self.path.clone().ok_or(VaultError::NotOpen)?;
        let mut index = {
            let mut ro = File::open(&path)?;
            load_index_from_file(
                &mut ro,
                &target_keys.enc_key,
                target.index_offset,
                target.index_length,
            )?
        };
        if index.duress == mark {
            return Err(VaultError::Other(if mark {
                format!("分区 '{}' 已是胁迫分区", target_alias)
            } else {
                format!("分区 '{}' 不是胁迫分区", target_alias)
            }));
        }
        index.duress = mark;

        // 3. 重加密索引追加到文件尾（AAD 域分离 b"index"），更新头部定位
        let index_json = serde_json::to_vec(&index)?;
        let enc = encrypt_gcm(&target_keys.enc_key, &index_json, b"index", None)?;
        {
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            let new_offset = file.seek(SeekFrom::End(0))?;
            file.write_all(&enc)?;
            file.flush()?;
            file.sync_all()?;
            self.partitions[pos].index_offset = new_offset;
            self.partitions[pos].index_length = enc.len() as u64;
        }
        // 4. 审计锚点：条目数未变（只改标志），沿用原计数；头部重写（含定位）
        self.update_header()?;
        if let Some(file) = self.file.as_mut() {
            let _ = file.sync_all();
        }
        // 目标分区的 cached_index 仅在 target == active 时需刷新
        if Some(pos) == self.active_partition {
            self.cached_index = Some(index);
        }
        secure_wipe_vec(index_json);
        drop(target_keys);
        Ok(())
    }

    /// 在当前会话中把指定分区标记为胁迫分区（无需先打开该分区）。
    pub fn set_duress_mark_on(
        &mut self,
        target_alias: &str,
        target_password: &str,
        key_file_data: Option<&[u8]>,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<(), VaultError> {
        self.duress_mark_on(
            target_alias,
            target_password,
            key_file_data,
            yk_response,
            true,
        )
    }

    /// 在当前会话中解除指定分区的胁迫标记。
    pub fn clear_duress_mark_on(
        &mut self,
        target_alias: &str,
        target_password: &str,
        key_file_data: Option<&[u8]>,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<(), VaultError> {
        self.duress_mark_on(
            target_alias,
            target_password,
            key_file_data,
            yk_response,
            false,
        )
    }

    /// 胁迫触发：当前会话的分区已带标记时，把**其他所有分区**的头部条目
    /// 覆写为随机字节并重写头部。在开柜成功路径的末尾调用（返回会话前）。
    ///
    /// 失败语义：覆写失败（I/O 错误）时**开柜失败** —— 宁可让胁迫场景下
    /// 出现一次可疑的报错，也不能让攻击者带着完整的隐藏分区离开（fail-closed）。
    pub(crate) fn check_and_trigger_duress(&mut self) -> Result<(), VaultError> {
        let marked = self
            .cached_index
            .as_ref()
            .map(|i| i.duress)
            .unwrap_or(false);
        if !marked {
            return Ok(());
        }
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        // 其他分区条目 → 整体随机（与未使用条目同一随机填充策略，结构上不可区分；
        // 别名经 from_utf8_lossy 后几乎必然失去合理性，重开时自动被当作伪条目过滤）
        for (i, p) in self.partitions.iter_mut().enumerate() {
            if i == active {
                continue;
            }
            let mut rnd = [0u8; 64];
            OsRng.fill_bytes(&mut rnd);
            p.alias = String::from_utf8_lossy(&rnd).into_owned();
            let mut salt = [0u8; 32];
            OsRng.fill_bytes(&mut salt);
            p.salt = salt;
            let mut tag = [0u8; 32];
            OsRng.fill_bytes(&mut tag);
            p.auth_tag = tag;
            p.index_offset = OsRng.next_u64();
            p.index_length = OsRng.next_u64();
            if let Some(w) = p.wrapped_key.as_mut() {
                OsRng.fill_bytes(w);
            }
            p.audit_count = OsRng.next_u32();
        }
        self.update_header()?;
        if let Some(file) = self.file.as_mut() {
            let _ = file.sync_all();
        }
        Ok(())
    }

    /// 演练：对保险柜文件的**临时副本**执行完整触发流程（真实开柜 + 真实覆写），
    /// 验证机制有效后把副本 DoD 擦除。原件零接触。
    /// 返回 (副本上被随机覆写的其他分区数)。
    ///
    /// 需要胁迫分区密码（演练即真实开柜副本）。磁盘成本：完整副本一份（临时）。
    pub fn duress_rehearsal(
        &mut self,
        duress_password: &str,
        key_file_data: Option<&[u8]>,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<usize, VaultError> {
        let path = self.path.clone().ok_or(VaultError::NotOpen)?;
        // UX 重构：演练可从任意会话发起 —— 不再前置检查「当前分区已标记」。
        // 触发目标是胁迫分区（其索引带标记），副本打开时自动生效；若用户给的
        // 密码对应的分区未标记，副本正常开柜、surviving != 1 → 演练报错。
        // 统计当前真实分区数（触发后条目被随机化，需要提前记录）
        let others_before = self.partitions.len().saturating_sub(1);

        // 临时副本（同目录，随机名防符号链接/抢占）。
        // L3（审计修复）：copy 前磁盘预检（完整副本一份）+ copy 失败时**必须**
        // 清理残留 —— 旧实现 `?` 早退会把部分/全部副本留在磁盘上，文件名
        // `<vault>.rehearsal.<hex>` 直接暴露「此柜配置了胁迫分区」（与模块
        // 「不可观测」承诺矛盾）。
        {
            let need = std::fs::metadata(&path)
                .map(|m| m.len())
                .unwrap_or(0)
                .saturating_add(4 * 1024 * 1024);
            if let Ok(free) = crate::vault::fs_util::disk_free_bytes(
                path.parent().unwrap_or(std::path::Path::new(".")),
            ) {
                if free < need {
                    return Err(VaultError::Other(format!(
                        "磁盘可用空间不足（需约 {} MB，仅剩 {} MB），演练已取消",
                        need / (1024 * 1024),
                        free / (1024 * 1024),
                    )));
                }
            }
        }
        let mut suffix = [0u8; 16];
        OsRng.fill_bytes(&mut suffix);
        let copy_path = path.with_extension(format!("rehearsal.{}", hex::encode(suffix)));
        // 3.0.1（F10）：演练副本与本体同等敏感，独占创建 + Unix 0600 落盘
        //（旧 std::fs::copy 按 umask 落盘，通常 0644）
        let copy_result: std::io::Result<()> = (|| {
            let mut dst = crate::vault::fs_util::create_scratch_file(&copy_path)?;
            let mut src = std::fs::File::open(&path)?;
            let r = std::io::copy(&mut src, &mut dst).and_then(|_| dst.sync_all());
            drop(dst);
            drop(src);
            r
        })();
        if let Err(e) = copy_result {
            // 部分写入的副本同样暴露存在性 —— 先擦除再报错
            crate::vault::fs_util::wipe_scratch_file(&copy_path);
            return Err(VaultError::Other(format!("演练副本创建失败：{}", e)));
        }

        let result = (|| -> Result<usize, VaultError> {
            let mut v = Vault::default();
            v.open_and_authenticate(&copy_path, duress_password, key_file_data, yk_response)
                .map_err(|e| {
                    VaultError::Other(format!(
                        "演练失败：胁迫密码未能打开副本（{}）—— 请确认密码",
                        e
                    ))
                })?;
            // 触发在 open 内完成（副本上其他分区条目已被随机覆写）。
            // 过滤发生在「解析头部」时 —— 因此**重开副本**验证：
            // 随机化条目经 is_plausible_alias 过滤后，只应剩胁迫分区自身。
            v.close();
            let mut v2 = Vault::default();
            v2.open_and_authenticate(&copy_path, duress_password, key_file_data, yk_response)
                .map_err(|e| {
                    VaultError::Other(format!("演练失败：触发后胁迫分区应仍可开（{}）", e))
                })?;
            let surviving_real = v2.get_partitions().len();
            v2.close();
            Ok(surviving_real)
        })();

        // 副本用后即擦（无论成败）
        match crate::wipe::dod_erase(&copy_path, None) {
            Ok(()) => {}
            Err(e) => {
                let _ = std::fs::remove_file(&copy_path);
                return Err(VaultError::Other(format!(
                    "演练副本擦除失败（已尽力删除）：{}",
                    e
                )));
            }
        }

        let surviving_real = result?;
        if others_before > 0 && surviving_real != 1 {
            return Err(VaultError::Other(format!(
                "演练异常：触发后副本上仍可见 {} 个分区（预期仅剩胁迫分区），请重新打开保险柜后再试",
                surviving_real
            )));
        }
        Ok(others_before)
    }
}

/// 验证「当前分区密码」—— v4 与信封（v5/v6）两条路径。
/// 与 change_password 的验证语义一致：派生密钥与会话密钥恒定时间比较。
pub(crate) trait VerifyPartitionPassword {
    fn verify_current_partition_password(
        &mut self,
        password: &str,
        key_file_data: Option<&[u8]>,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<(), VaultError>;
}

impl VerifyPartitionPassword for Vault {
    fn verify_current_partition_password(
        &mut self,
        password: &str,
        key_file_data: Option<&[u8]>,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<(), VaultError> {
        use subtle::ConstantTimeEq;
        match self.format_version {
            VERSION_V4 => {
                // 3.0.1（F30 修复）：v4 会话密钥按**活跃分区条目自身的盐**派生
                //（打开路径逐条目 derive_keys(password, key_file_data, &p.salt)）
                // —— 旧实现用保险柜盐派生，比较永远不可能成立（fail-closed 的
                // 功能性 bug，当前仅 yubikey 重包裹路径拒绝 v4 才未暴露）。
                let active = self.active_partition.ok_or(VaultError::NotOpen)?;
                let salt = self.partitions[active].salt;
                let keys = derive_keys(password, key_file_data, &salt)?;
                let session = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
                let ok = bool::from(keys.enc_key.ct_eq(&**session));
                let mut k = keys;
                k.zeroize();
                if !ok {
                    return Err(VaultError::Other("当前分区密码或密钥文件不正确".into()));
                }
                Ok(())
            }
            VERSION_V5 | VERSION_V6 => {
                let active = self.active_partition.ok_or(VaultError::NotOpen)?;
                let session_dk =
                    Zeroizing::new(**self.data_key.as_ref().ok_or(VaultError::NotOpen)?);
                let p = self.partitions[active].clone();
                let alias_field = alias_field16(&p.alias);
                let prefix = auth_tag_header_prefix(&self.salt, self.format_version);
                let kek = Zeroizing::new(derive_kek(password, key_file_data, &p.salt)?);
                let aad = key_wrap_aad(&prefix, &alias_field, &p.salt);
                let stored = p.wrapped_key.unwrap_or([0u8; WRAPPED_KEY_SIZE]);
                // 3.0.0：双路径验证 —— 提供响应时先试「混合 KEK」（二因子分区）
                // 再试普通 KEK（普通分区），与会话状态比对
                let mut unwrapped: Option<[u8; 32]> = None;
                if let Some(resp) = yk_response {
                    let mixed = Zeroizing::new(mix_kek_with_response(&kek, resp));
                    unwrapped = unwrap_data_key(&mixed, &stored, &aad);
                }
                if unwrapped.is_none() {
                    unwrapped = unwrap_data_key(&kek, &stored, &aad);
                }
                let mut verified = false;
                if let Some(cand) = &unwrapped {
                    verified = bool::from(cand.ct_eq(&*session_dk));
                }
                if let Some(mut c) = unwrapped {
                    c.zeroize();
                }
                drop(kek);
                if !verified {
                    return Err(VaultError::Other("当前分区密码或密钥文件不正确".into()));
                }
                Ok(())
            }
            v => Err(VaultError::Other(format!("未知的保险柜格式版本: {}", v))),
        }
    }
}
