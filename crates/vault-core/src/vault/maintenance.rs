//! 维护操作 —— 修改密码 / v4→v5 升级 / 完整性体检 / 搜索 / 碎片整理 / 销毁。
//! 3.0.0 拆分自 vault.rs，逻辑逐字节不变。
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::audit::AuditLog;
use crate::crypto::*;
use crate::error::VaultError;
use crate::index::Index;
use crate::wipe::{dod_erase, dod_overwrite_range, secure_wipe_vec};

use super::consts::*;
use super::fs_util::verify_file_data_layout;
use super::fs_util::*;
use super::header::*;
use super::locked_key::LockedKey;
use super::PartitionInfo;
use super::Vault;

/// 2.8.0：完整性体检的单个异常条目
#[derive(Debug, Clone, serde::Serialize)]
pub struct IntegrityIssue {
    pub vpath: String,
    pub reason: String,
}

/// 2.8.0：搜索结果条目
#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchHit {
    pub vpath: String,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

impl Vault {
    // ═══════════════ 密码修改（2.8.0）═══════════════

    /// 修改当前分区的密码。
    ///
    /// - **v5 / v6 信封保险柜**：仅重写头部（换盐重新包裹 data_key + 重算认证标签 +
    ///   重签名），文件数据一个字节不动，瞬间完成。3.0.0 起 v5 保险柜借此
    ///   **自动升级为 v6**（流式分块格式；v5 与 v6 头部同布局，升级 = 版本字节
    ///   切换 + 按新版本重算包裹 AAD 与认证标签，秒级）。
    /// - **v4 保险柜**：v4 的会话密钥直接由口令派生，改密码必须重加密全部数据。
    ///   借此机会**自动升级**为 v6 信封加密（一次性全库重加密，此后改密码都是头部级）。
    ///   多分区 v4 保险柜无法升级：其余分区口令未知，无法生成信封格式必需的包裹密钥
    ///   （填随机数会让那些分区永久无法打开）—— 明确报错而非静默破坏。
    ///
    /// 必须提供**当前密码**（或等价的密钥文件）：防止他人在已解锁的机器上
    /// 改密锁死真正的主人。新密码 ≥ 12 字符（与创建一致，按字符数）。
    /// 3.0.0：新增 `yk_response` —— 当前分区启用了硬件密钥二因子时必须提供
    /// （验证用；新包裹保留二因子状态）。未启用时传 None。
    pub fn change_password<F: Fn(usize)>(
        &mut self,
        current_password: &str,
        new_password: &str,
        key_file_data: Option<&[u8]>,
        progress: Option<F>,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<(), VaultError> {
        if !self.is_open() {
            return Err(VaultError::NotOpen);
        }
        if new_password.chars().count() < 12 {
            return Err(VaultError::Other("新密码长度至少 12 位".into()));
        }
        match self.format_version {
            // 3.0.0：v5 改密即升级 v6（头部级秒完成）；v6 原地换密。
            // P0-1（3.0.0 审计修复）：多分区 v5 必须拒绝 —— 升级会把头部版本字节
            // 切换为 6，但只有当前分区能按 v6 前缀重新包裹；其余分区的包裹体与
            // 认证标签仍按 v5 前缀绑定，升级后**正确密码也无法解包**（认证标签
            // 同理失配）→ 其他分区永久锁死。与 v4 多分区路径同一防护。
            VERSION_V5 => {
                if self.partitions.len() > 1 {
                    return Err(VaultError::Other(
                        "多分区 v5 保险柜暂不支持修改密码：升级 v6 需要为每个分区重新生成包裹密钥，                         其余分区的口令未知（无法为它们生成 v6 必需的包裹密钥）。                         可先用对应密码打开各分区导出重要数据，或保持 v5 格式继续使用"
                            .into(),
                    ));
                }
                self.change_password_envelope(
                    current_password,
                    new_password,
                    key_file_data,
                    VERSION_V5,
                    VERSION_V6,
                    yk_response,
                )
            }
            VERSION_V6 => self.change_password_envelope(
                current_password,
                new_password,
                key_file_data,
                VERSION_V6,
                VERSION_V6,
                yk_response,
            ),
            VERSION_V4 => self.change_password_v4_upgrade(
                current_password,
                new_password,
                key_file_data,
                progress,
            ),
            v => Err(VaultError::Other(format!("未知的保险柜格式版本: {}", v))),
        }
    }

    /// v5/v6 信封：头部级改密码。验当前密码（解包 + 恒定时间比较 data_key）→
    /// 换盐重新包裹 → 重算认证标签 → 重写头部重签名。
    /// 3.0.0：版本参数化 —— 验证用 `from_version` 的绑定前缀，重包裹/新标签/
    /// 头部版本字节用 `to_version`（v5 改密即升级 v6 的实现点）。
    fn change_password_envelope(
        &mut self,
        current_password: &str,
        new_password: &str,
        key_file_data: Option<&[u8]>,
        from_version: u8,
        to_version: u8,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<(), VaultError> {
        debug_assert!(matches!(from_version, VERSION_V5 | VERSION_V6));
        debug_assert!(matches!(to_version, VERSION_V5 | VERSION_V6));
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        // 2.8.1：会话 data_key 副本用 Zeroizing 包裹，函数任何出口都不残留明文
        let session_dk = Zeroizing::new(**self.data_key.as_ref().ok_or(VaultError::NotOpen)?);
        let p = self.partitions[active].clone();
        let alias_field = alias_field16(&p.alias);
        let prefix = auth_tag_header_prefix(&self.salt, from_version);

        // M-4（审计修复）：二因子检查前置 —— 会话状态已表明当前分区以混合 KEK
        // 包裹，此时不提供响应必然验证失败；提前给出准确指引，
        // 而不是让用户看到误导性的「当前密码或密钥文件不正确」。
        let keep_yk = self.yubikey_wrapped;
        if keep_yk && yk_response.is_none() {
            return Err(VaultError::Other(
                "当前分区启用了硬件密钥二因子：请插入硬件密钥（触摸后重试）再修改密码".into(),
            ));
        }

        // 1. 验证当前密码：用当前盐派生 KEK 解包，与会话中的 data_key 恒定时间比较。
        //    3.0.0：提供响应时先试「混合 KEK」（二因子分区），未命中再试普通。
        let kek = Zeroizing::new(derive_kek(current_password, key_file_data, &p.salt)?);
        let aad = key_wrap_aad(&prefix, &alias_field, &p.salt);
        let stored = p.wrapped_key.unwrap_or([0u8; WRAPPED_KEY_SIZE]);
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
            use subtle::ConstantTimeEq;
            verified = bool::from(cand.ct_eq(&*session_dk));
        }
        // 2.8.1：候选密钥显式清零 —— Option<[u8;32]> 是 Copy，drop() 是空操作，
        // 不能依赖 Drop（clippy dropping_copy_types 也正是这么提示的）
        if let Some(mut c) = unwrapped {
            c.zeroize();
        }
        drop(kek);
        if !verified {
            return Err(VaultError::Other("当前密码或密钥文件不正确".into()));
        }
        // 3.0.0：二因子状态保持（keep_yk 已在验证前计算）—— 新包裹同样混合
        //（响应参与），杜绝「改密码顺手降级二因子」

        // 2. 换盐重新包裹 data_key（数据密钥本身不变 → 所有密文继续有效）。
        //    3.0.0：v5→v6 升级时包裹 AAD / 认证标签按 to_version 重算
        //   （版本字节在头部前缀内参与两个绑定），数据本身零接触。
        let mut new_salt = [0u8; 32];
        OsRng.fill_bytes(&mut new_salt);
        let new_kek = Zeroizing::new(derive_kek(new_password, key_file_data, &new_salt)?);
        // (true, Some(resp)) 时混合响应；否则沿用普通 KEK（值被移动，借用已结束）
        let wrap_kek = if keep_yk {
            let resp = yk_response.expect("keep_yk=true 时响应必已校验存在");
            Zeroizing::new(mix_kek_with_response(&new_kek, resp))
        } else {
            new_kek
        };
        let new_prefix = auth_tag_header_prefix(&self.salt, to_version);
        let new_aad = key_wrap_aad(&new_prefix, &alias_field, &new_salt);
        let wrapped_v = encrypt_gcm(&wrap_kek, &session_dk[..], &new_aad, None)?;
        drop(wrap_kek);
        let mut new_wrapped = [0u8; WRAPPED_KEY_SIZE];
        new_wrapped.copy_from_slice(&wrapped_v);
        secure_wipe_vec(wrapped_v);

        // 3. 重算认证标签（盐变了必须重算）并重写头部（update_header 内部重签名；
        //    sign_key 由未变的 data_key 派生，依然有效）。
        //    2.8.1（崩溃一致性）：先写头部、成功后才提交内存 —— 旧实现先改内存，
        //    头部写入失败时内存已是「新密码」而磁盘还是旧盐，后续任何一次
        //    save_index/update_header 都会把这次「失败的改密」持久化。
        let auth_key = **self.auth_key.as_ref().ok_or(VaultError::NotOpen)?;
        let new_tag = bound_auth_tag(&auth_key, &self.salt, to_version, &alias_field, &new_salt);
        let old_part = self.partitions[active].clone();
        self.partitions[active] = PartitionInfo {
            alias: old_part.alias.clone(),
            salt: new_salt,
            auth_tag: new_tag,
            index_offset: old_part.index_offset,
            index_length: old_part.index_length,
            wrapped_key: Some(new_wrapped),
            // 审计锚点沿用（索引内容未动）
            audit_count: old_part.audit_count,
        };
        // 3.0.0：v5→v6 升级在此切换会话版本号（update_header 按它写头部版本字节）
        let old_version = self.format_version;
        self.format_version = to_version;
        if let Err(e) = self.update_header() {
            // 头部写入失败：恢复内存中的旧条目与旧版本号，向上传播错误（磁盘未动）
            self.partitions[active] = old_part;
            self.format_version = old_version;
            return Err(e);
        }
        self.log_event("修改当前分区密码");
        Ok(())
    }

    /// v4 → v6 升级 + 改密码（一次性全库重加密；3.0.0 起直达 v6 流式格式）。
    ///
    /// 复用碎片整理的安全管线：磁盘预检 → .bak 完整备份 → .tmp 上重建
    /// （逐文件旧密钥解密 / 新 data_key 重加密，AAD 不变）→ v6 头部 →
    /// ReplaceFileW 原子替换 → 失败回滚。仅支持单分区 v4 保险柜。
    fn change_password_v4_upgrade<F: Fn(usize)>(
        &mut self,
        current_password: &str,
        new_password: &str,
        key_file_data: Option<&[u8]>,
        progress: Option<F>,
    ) -> Result<(), VaultError> {
        if self.partitions.len() != 1 {
            return Err(VaultError::Other(
                "多分区 v4 保险柜暂不支持修改密码：其余分区的口令未知，无法为它们生成 \
                 信封格式必需的包裹密钥（填入随机数据会使那些分区永久无法打开）。\
                 可先用对应密码打开各分区导出重要数据，或保持 v4 格式继续使用"
                    .into(),
            ));
        }
        let old_part = self.partitions[0].clone();
        // 3.0.1（#20 修复）：旧会话密钥以 Zeroizing 携带 —— 升级中途任何失败
        // 路径（验证失败 / 备份失败 / 管线失败）出作用域即清零，不再只在
        // 成功分支手工清零
        let old_enc_key = Zeroizing::new(**self.enc_key.as_ref().ok_or(VaultError::NotOpen)?);
        let old_auth_key = Zeroizing::new(**self.auth_key.as_ref().ok_or(VaultError::NotOpen)?);

        // 1. 验证当前密码（v4：直接派生三把密钥并与会话密钥恒定时间比较）
        {
            let keys = derive_keys(current_password, key_file_data, &old_part.salt)?;
            use subtle::ConstantTimeEq;
            let enc_ok = bool::from(keys.enc_key.ct_eq(&*old_enc_key));
            let mut k = keys;
            k.zeroize();
            if !enc_ok {
                return Err(VaultError::Other("当前密码或密钥文件不正确".into()));
            }
        }

        let vault_path = self.path.as_ref().ok_or(VaultError::NotOpen)?.clone();
        let orig_len = std::fs::metadata(&vault_path)?.len();

        // 2. 磁盘预检（备份完整副本 + 临时文件，同一磁盘：约 2× + 4 MiB）
        let need = orig_len.saturating_mul(2).saturating_add(4 * 1024 * 1024);
        match disk_free_bytes(vault_path.parent().unwrap_or(Path::new("."))) {
            Ok(free) => {
                if free < need {
                    return Err(VaultError::Other(format!(
                        "磁盘可用空间不足（需约 {} MB，仅剩 {} MB），已取消操作，未产生任何中间文件",
                        need / (1024 * 1024),
                        free / (1024 * 1024),
                    )));
                }
            }
            // 3.0.1（#48 修复）：预查询失败至少留痕（旧实现静默跳过）
            Err(e) => log::warn!("磁盘可用空间预检失败，跳过预检（继续执行）: {}", e),
        }

        // 3. 随机临时/备份文件名（防符号链接攻击，与碎片整理同一策略）
        let mut rand_suffix = [0u8; 16];
        OsRng.fill_bytes(&mut rand_suffix);
        let temp_path = PathBuf::from(format!(
            "{}.tmp.{}",
            vault_path.display(),
            hex::encode(rand_suffix)
        ));
        let backup_path = PathBuf::from(format!(
            "{}.bak.{}",
            vault_path.display(),
            hex::encode(rand_suffix)
        ));

        // 4. 完整备份（失败统一「先 DoD 擦除再删除」）
        let backup_result: std::io::Result<()> = (|| {
            // 3.0.1（F10）：0600 落盘（见 create_scratch_file）
            let mut backup_file = crate::vault::fs_util::create_scratch_file(&backup_path)?;
            let mut original = File::open(&vault_path)?;
            let copy = std::io::copy(&mut original, &mut backup_file);
            let sync = backup_file.sync_all();
            drop(backup_file);
            drop(original);
            copy.and(sync).map(|_| ())
        })();
        if let Err(e) = backup_result {
            wipe_scratch_file(&backup_path);
            return Err(e.into());
        }

        // 5. 新信封密钥
        // 2.8.1：Zeroizing —— expand_keys 派生失败的 `?` 早退不残留随机 data_key
        let mut dk_buf = [0u8; 32];
        OsRng.fill_bytes(&mut dk_buf);
        let data_key = Zeroizing::new(dk_buf);
        let new_keys = expand_keys(&data_key)?;

        // 6. 加载旧索引（原文件此刻未被修改；审计随后换钥重建）
        let mut index = {
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            load_index_from_file(
                file,
                &old_enc_key,
                old_part.index_offset,
                old_part.index_length,
            )?
        };
        let mut audit_log = AuditLog::from_entries(index.audit.clone(), *old_auth_key);
        // 换钥前先用旧密钥硬校验整条链（篡改即中止，不静默截断），再重建
        audit_log.rekey(&old_auth_key, new_keys.auth_key)?;
        audit_log.add("修改密码并升级为 v6 信封加密（流式分块）");
        index.audit = audit_log.to_vec();

        // 7. 重加密管线（闭包内只读 self 的克隆值，不持有 &mut self）
        let alias_field = alias_field16(&old_part.alias);
        let salt = self.salt;
        let lock_state = self.lock_state.clone();
        let result = (|| -> Result<PartitionInfo, VaultError> {
            // 7a. 临时文件 + v5 占位头部
            // 3.0.1（F10）：0600 落盘（见 create_scratch_file）
            let mut tmp_file = crate::vault::fs_util::create_scratch_file(&temp_path)?;
            tmp_file.write_all(&[0u8; HEADER_SIZE_V5])?;
            tmp_file.flush()?;

            // 7b. 逐文件解密 → 新密钥重加密（AAD 不变，密文长度不变，偏移重排）
            let files_snapshot: Vec<(String, u64, u64)> = index
                .files
                .iter()
                .map(|(k, m)| (k.clone(), m.offset, m.length))
                .collect();
            let total = files_snapshot.len();
            let mut src_file = File::open(&vault_path)?;
            let mut write_cursor = HEADER_SIZE_V5 as u64;
            for (i, (vpath, old_off, old_len)) in files_snapshot.iter().enumerate() {
                // 3.0.1（F6）：分配上限 —— old_len 来自（已认证但可能损坏的）
                // 旧索引，按真实文件长度与 MAX_INMEM_BUFFER 双重设限；v4 写入方
                // 恒满足（导入即按 MAX_INMEM_BUFFER 收口），越界值 alloc-abort
                // 整个进程的路径就此关闭。
                let end = old_off
                    .checked_add(*old_len)
                    .ok_or_else(|| VaultError::Other("升级管线：文件密文范围溢出".into()))?;
                if *old_len > MAX_INMEM_BUFFER as u64 || end > orig_len {
                    return Err(VaultError::Other(format!(
                        "升级管线：{} 的密文范围与保险柜文件不符（索引可能被篡改或损坏）",
                        vpath
                    )));
                }
                let aad_tag = index.files.get(vpath).and_then(|m| m.aad_tag.clone());
                let aad = aad_bytes(aad_tag.as_deref(), vpath).to_vec();
                src_file.seek(SeekFrom::Start(*old_off))?;
                let mut enc_old = vec![0u8; *old_len as usize];
                src_file.read_exact(&mut enc_old)?;
                // 2.8.1：decrypt_into/encrypt_into 消费并复用缓冲 ——
                // 旧实现每文件同时存在「密文 + 明文 + 新密文」三份全尺寸分配
                //（256MiB 文件峰值 768MiB），现在降为 ~1.5 份
                let plain =
                    decrypt_into(&old_enc_key, enc_old, &aad).ok_or(VaultError::DecryptFailed)?;
                let enc_new = encrypt_into(&new_keys.enc_key, plain, &aad)?;
                tmp_file.seek(SeekFrom::Start(write_cursor))?;
                tmp_file.write_all(&enc_new)?;
                index
                    .files
                    .get_mut(vpath)
                    .ok_or_else(|| VaultError::Other("升级管线：文件不在索引中".into()))?
                    .offset = write_cursor;
                write_cursor += enc_new.len() as u64;
                if let Some(ref cb) = progress {
                    cb((i + 1) * 80 / total.max(1));
                }
            }
            drop(src_file);

            // 7c. 新索引（已含换钥后的审计链）
            let idx_json = serde_json::to_vec(&index)?;
            let enc_idx = encrypt_gcm(&new_keys.enc_key, &idx_json, b"index", None)?;
            tmp_file.seek(SeekFrom::Start(write_cursor))?;
            tmp_file.write_all(&enc_idx)?;
            tmp_file.flush()?;
            tmp_file.sync_all()?;
            secure_wipe_vec(idx_json);
            if let Some(ref cb) = progress {
                cb(90);
            }

            // 7d. 构建唯一的 v5 分区条目
            let mut new_part_salt = [0u8; 32];
            OsRng.fill_bytes(&mut new_part_salt);
            let mut kek = derive_kek(new_password, key_file_data, &new_part_salt)?;
            let prefix = auth_tag_header_prefix(&salt, VERSION_V6);
            let wrap_aad = key_wrap_aad(&prefix, &alias_field, &new_part_salt);
            let wrapped_v = encrypt_gcm(&kek, &data_key[..], &wrap_aad, None)?;
            let mut wrapped = [0u8; WRAPPED_KEY_SIZE];
            wrapped.copy_from_slice(&wrapped_v);
            kek.zeroize();
            secure_wipe_vec(wrapped_v);
            let auth_tag = bound_auth_tag(
                &new_keys.auth_key,
                &salt,
                VERSION_V6,
                &alias_field,
                &new_part_salt,
            );
            let new_part = PartitionInfo {
                alias: old_part.alias.clone(),
                salt: new_part_salt,
                auth_tag,
                index_offset: write_cursor,
                index_length: enc_idx.len() as u64,
                wrapped_key: Some(wrapped),
                // 新索引已含换钥后的完整审计链，按实际条目数锚定
                audit_count: index.audit.len() as u32,
            };

            // 7e. v6 头部（v4 布局的锁定区/签名随版本切换到新位置；3.0.0 起升级直达 v6）。
            // 3.0.0（M-2）：升级生成随机挑战盐（v4 存量保留区为全 0，此处一并启用）
            let mut yk_salt = [0u8; 32];
            OsRng.fill_bytes(&mut yk_salt);
            write_header_to_file(
                &mut tmp_file,
                VERSION_V6,
                &lock_state,
                &salt,
                std::slice::from_ref(&new_part),
                &new_keys.sign_key,
                &yk_salt,
            )?;
            tmp_file.flush()?;
            tmp_file.sync_all()?;
            drop(tmp_file);
            if let Some(ref cb) = progress {
                cb(100);
            }

            // 7f. 2.8.1（事务化）：原子替换纳入事务闭包 —— 替换失败与之前任何
            // 一步失败一样走统一回滚（擦 .tmp/.bak、重开原文件）。旧实现在闭包
            // **之外**执行替换且 `?` 直接返回，绕过全部清理：失败时磁盘残留
            // 「.tmp（新密码全库）+ .bak（旧密码全库）」两份完整副本（抗取证死角），
            // 会话也停在 file=None 的半死状态。
            // 释放会话句柄（Windows rename 需 DELETE 权；Unix 需先放 flock）
            self.file = None;
            replace_vault_file(&temp_path, &vault_path)?;
            sync_parent_dir(&vault_path);
            Ok(new_part)
        })();

        match result {
            Ok(new_part) => {
                // 8. 备份已无用（替换已提交）：DoD 擦除。
                // 3.0.1（F29 修复）：与失败路径同一纪律 —— .bak 是**旧口令仍能
                // 打开的整柜副本**，改口令通常正因为旧口令可能已泄露，残留副本
                // 使轮换失效。擦除失败重试后仍有 remove_file 兜底；彻底删不掉
                // 时在审计中留下用户可见的警告（此前只写日志，界面无任何提示）。
                let mut backup_residue = false;
                if backup_path.exists() {
                    let mut wiped = false;
                    for _ in 0..3 {
                        match dod_erase(&backup_path, None) {
                            Ok(()) => {
                                wiped = true;
                                break;
                            }
                            Err(e) => {
                                log::warn!("擦除升级备份失败（将重试，最终回退删除）: {}", e)
                            }
                        }
                        if !backup_path.exists() {
                            wiped = true;
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    if !wiped {
                        let _ = fs::remove_file(&backup_path);
                    }
                    backup_residue = backup_path.exists();
                    if backup_residue {
                        log::error!(
                            "升级备份 .bak 删除失败：保险柜同目录残留旧口令可打开的完整副本，请手动删除"
                        );
                    }
                }
                // 9. 重开句柄 + 会话切换到 v5。
                // 2.8.1（诚实报错）：替换已经提交 —— 此时磁盘必然已是 v5 新密码。
                // 重开若失败（如另一实例在句柄释放窗口抢锁），旧实现直接报错，
                // 用户会误以为「改密失败」而继续用旧密码。改为短重试后给出
                // 明确的「已生效、请重开」语义。
                let mut reopened: Option<File> = None;
                let mut last_err: Option<VaultError> = None;
                for _ in 0..3 {
                    match open_vault_rw(&vault_path) {
                        Ok(f) => match lock_vault_exclusive(&f) {
                            Ok(()) => {
                                reopened = Some(f);
                                break;
                            }
                            Err(e) => {
                                drop(f);
                                last_err = Some(e.into());
                            }
                        },
                        Err(e) => last_err = Some(e.into()),
                    }
                    std::thread::sleep(std::time::Duration::from_millis(150));
                }
                let file = match reopened {
                    Some(f) => f,
                    None => {
                        // 3.0.1（#51 修复）：重开失败时磁盘已是 v6 新布局，内存却
                        // 残留 v4 会话字段（旧密钥/旧分区表）—— 做 abandon_session
                        // 等价的**纯内存**复位（不落盘任何内容），避免半死会话
                        let msg = format!(
                            "密码修改已生效（旧密码已失效），但恢复会话失败（{}）。请用新密码重新打开保险柜",
                            last_err.map(|e| e.to_string()).unwrap_or_default()
                        );
                        self.abandon_session();
                        return Err(VaultError::Other(msg));
                    }
                };
                self.file = Some(file);
                self.format_version = VERSION_V6;
                self.data_key = Some(LockedKey::new(*data_key)); // Zeroizing 解包 → 装箱驻留
                self.enc_key = Some(LockedKey::new(new_keys.enc_key));
                self.auth_key = Some(LockedKey::new(new_keys.auth_key));
                self.sign_key = Some(LockedKey::new(new_keys.sign_key));
                self.partitions = vec![new_part];
                self.active_partition = Some(0);
                self.audit = Some(audit_log);
                self.cached_index = Some(index);
                self.audit_dirty = false; // 新索引（含审计）已随管线落盘
                                          // 3.0.1（F29）：.bak 残留警告入审计（audit_dirty 置位 → close 时
                                          // 随索引落盘，用户在审计日志中可见）
                if backup_residue {
                    if let Some(ref mut audit) = self.audit {
                        audit.add("警告：升级备份删除失败，保险柜同目录可能残留 .bak 文件（旧密码仍可打开全部内容），请手动检查并删除");
                    }
                    self.audit_dirty = true;
                }
                // 3.0.1（#20）：旧密钥为 Zeroizing，drop 即清零（原手工清零删除）
                Ok(())
            }
            Err(e) => {
                // 10. 回滚（2.8.1 重构）：原子替换已纳入闭包 —— 走到这里时
                // **替换要么未发生、要么原子失败即未生效**，原文件始终完好。
                // 旧实现在此处用备份 rename 覆盖原文件：内容虽相同，却把原文件的
                // ACL/属性丢成目录继承（replace_vault_file 恰是为了避免这一点）。
                // 现在只清理中间副本（含完整明文密文数据的 .tmp 与 .bak），再重开原文件。
                self.file = None;
                wipe_scratch_file(&temp_path);
                if backup_path.exists() {
                    if let Err(we) = dod_erase(&backup_path, None) {
                        log::warn!("擦除升级备份失败（将尝试直接删除）: {}", we);
                        let _ = fs::remove_file(&backup_path);
                    }
                }
                let file = open_vault_rw(&vault_path).ok().and_then(|f| {
                    lock_vault_exclusive(&f).ok()?;
                    Some(f)
                });
                self.file = file;
                Err(e)
            }
        }
    }

    // ═══════════════ 完整性体检 / 搜索 / 锁定信息（2.8.0）═══════════════

    /// 2.8.0：全库完整性体检 —— 逐文件解密校验 AES-GCM 认证标签，
    /// 检出坏块 / 位腐 / 云同步损坏。只读操作（不修改任何数据）。
    pub fn verify_integrity<F: Fn(usize, usize, &str)>(
        &mut self,
        progress: Option<F>,
    ) -> Result<(usize, Vec<IntegrityIssue>), VaultError> {
        if !self.is_open() {
            return Err(VaultError::NotOpen);
        }
        // 2.8.2：走只读借用（index_ref），免去整索引深拷贝
        // 3.0.0：携带布局 —— Chunked 逐块校验（内存与文件大小无关）
        let mut items: Vec<(String, u64, u64, Option<String>, crate::index::ChunkLayout)> = {
            let index = self.index_ref()?;
            index
                .files
                .iter()
                .map(|(k, m)| {
                    (
                        k.clone(),
                        m.offset,
                        m.length,
                        m.aad_tag.clone(),
                        m.layout.clone(),
                    )
                })
                .collect()
        };
        // 2.8.2：按物理偏移排序 —— 逐文件解密时对保险柜文件顺序读
        //（HDD / 网络盘收益明显），旧实现按路径排序导致随机跳转
        items.sort_by_key(|x| x.1);
        let total = items.len();
        let enc_key = **self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let mut broken: Vec<IntegrityIssue> = Vec::new();
        for (i, (vpath, off, len, aad_tag, layout)) in items.iter().enumerate() {
            if let Some(ref cb) = progress {
                cb(i + 1, total, vpath);
            }
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            match verify_file_data_layout(
                file,
                &enc_key,
                *off,
                *len,
                aad_tag.as_deref(),
                vpath,
                layout,
            ) {
                Ok(()) => {}
                Err(e) => broken.push(IntegrityIssue {
                    vpath: vpath.clone(),
                    reason: e.to_string(),
                }),
            }
        }
        self.log_event(&format!(
            "完整性体检：{} 个文件，{} 个异常",
            total,
            broken.len()
        ));
        Ok((total, broken))
    }

    /// 2.8.0：按文件名 / vpath 大小写不敏感子串搜索（含文件夹，文件夹在前）。
    /// 2.8.1（性能）：改为**借用**内存缓存（旧实现每次搜索深拷贝整个索引，
    /// 10 万条目 ≈ 每次击键 20-30 万次分配）；大小写折叠走原地 ASCII 折叠
    ///（复用单个缓冲，热路径零分配；CJK 等无大小写字符不受影响）。
    pub fn search_files(&self, query: &str, limit: usize) -> Vec<SearchHit> {
        let Some(index) = self.cached_index.as_ref() else {
            return Vec::new();
        };
        let q = query.trim();
        if q.is_empty() {
            return Vec::new();
        }
        let q_lower = q.to_lowercase();
        // 大小写不敏感匹配（2.8.2 修正 2.8.1 的回归）：先做零分配的
        // 大小写敏感匹配（小写名/中文命中绝大多数查询），未命中再做原地
        // ASCII 折叠；2.8.1 只做了 ASCII 折叠，导致 É↔é、К↔к 等非 ASCII
        // 大小写变形不再命中 —— 现对含大写非 ASCII 字符的候选补一次完整的
        // Unicode 折叠（这类候选是少数，均摊成本可控）。
        fn contains_ci(buf: &mut String, haystack: &str, needle: &str, needle_lower: &str) -> bool {
            if haystack.contains(needle) {
                return true;
            }
            buf.clear();
            buf.push_str(haystack);
            buf.as_mut_str().make_ascii_lowercase();
            if buf.contains(needle_lower) {
                return true;
            }
            // 存在非 ASCII 大写字符 → ASCII 折叠不够，完整 Unicode 折叠后再试
            if haystack.chars().any(|c| c.is_uppercase()) {
                buf.clear();
                buf.push_str(&haystack.to_lowercase());
                return buf.contains(needle_lower);
            }
            false
        }
        let mut fold_buf = String::new();
        let mut hits: Vec<SearchHit> = Vec::new();
        for (vpath, m) in &index.files {
            if contains_ci(&mut fold_buf, vpath, q, &q_lower)
                || contains_ci(&mut fold_buf, &m.name, q, &q_lower)
            {
                hits.push(SearchHit {
                    vpath: vpath.clone(),
                    name: m.name.clone(),
                    size: m.size,
                    is_dir: false,
                });
            }
        }
        for vpath in index.folders.keys() {
            if contains_ci(&mut fold_buf, vpath, q, &q_lower) {
                let name = vpath.rsplit('/').next().unwrap_or(vpath).to_string();
                hits.push(SearchHit {
                    vpath: vpath.clone(),
                    name,
                    size: 0,
                    is_dir: true,
                });
            }
        }
        hits.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.vpath.cmp(&b.vpath)));
        hits.truncate(limit);
        hits
    }

    /// 2.8.0：列出当前分区全部文件夹 vpath（移动选择器用，已排序）。
    /// 2.8.2：走只读借用（index_ref），免去整索引深拷贝。
    pub fn list_all_folders(&self) -> Result<Vec<String>, VaultError> {
        let index = self.index_ref()?;
        let mut v: Vec<String> = index.folders.keys().cloned().collect();
        v.sort();
        Ok(v)
    }

    // ═══════════════ 碎片整理 ═══════════════

    pub fn defragment_vault<F: Fn(usize)>(
        &mut self,
        progress: Option<F>,
    ) -> Result<(), VaultError> {
        let active_enc_key = **self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let sign_key = **self.sign_key.as_ref().ok_or(VaultError::NotOpen)?;
        let vault_path = self.path.as_ref().ok_or(VaultError::NotOpen)?.clone();

        // 2.4.1（P0-3）：记录活跃分区旧布局（旧索引位置 + 全部旧文件数据位置），
        // 整理成功后对这些区域做 DoD 7-pass 擦除。
        // 旧实现把活跃分区数据复制到文件末尾后**不擦旧位置**，导致每整理一次
        // 文件反而膨胀一份活跃分区数据 —— 与「碎片整理释放空间」的语义完全相反。
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let old_part = self.partitions[active].clone();
        let (old_idx_off, old_idx_len) = (old_part.index_offset, old_part.index_length);
        let old_file_ranges: Vec<(u64, u64)> = {
            let index = self.load_index()?;
            index.files.values().map(|m| (m.offset, m.length)).collect()
        };
        // 整理前文件长度：新数据全部追加在 [orig_len, ...) —— 旧数据区与
        // 新数据区天然不相交（blob 均追加写入，互不重叠），擦除旧区不会伤及新数据
        let orig_len = std::fs::metadata(&vault_path)?.len();

        // 2.7.1 修复：整理前预检磁盘可用空间 —— 备份（完整副本）+ 临时文件都在
        // 同一磁盘上，按「约 2× 文件大小 + 4 MiB」预留；不足时明确拒绝且不产生
        // 任何中间文件（旧实现写到一半才失败，留下半份残留副本）。
        let need = orig_len.saturating_mul(2).saturating_add(4 * 1024 * 1024);
        match disk_free_bytes(vault_path.parent().unwrap_or(Path::new("."))) {
            Ok(free) => {
                if free < need {
                    return Err(VaultError::Other(format!(
                        "磁盘可用空间不足（需约 {} MB，仅剩 {} MB），已取消整理，未产生任何中间文件",
                        need / (1024 * 1024),
                        free / (1024 * 1024),
                    )));
                }
            }
            // 3.0.1（#48 修复）：预查询失败至少留痕（旧实现静默跳过）
            Err(e) => log::warn!("磁盘可用空间预检失败，跳过预检（继续执行）: {}", e),
        }

        // 随机临时文件名，防止符号链接攻击
        let mut rand_suffix = [0u8; 16];
        OsRng.fill_bytes(&mut rand_suffix);
        let temp_name = format!("{}.tmp.{}", vault_path.display(), hex::encode(rand_suffix));
        let temp_path = PathBuf::from(&temp_name);
        let backup_name = format!("{}.bak.{}", vault_path.display(), hex::encode(rand_suffix));
        let backup_path = PathBuf::from(&backup_name);

        // C2 修复（关键）：旧实现只迁移活跃分区的文件和索引，
        // fs::rename 后其他分区的索引和文件密文全部丢失。
        // 新实现：遍历所有分区，将每个分区的索引（不解密，直接复制密文）
        // 迁移到临时文件，并更新对应分区的 offset/length。
        // 文件密文也整体复制（按活跃分区的索引定位）。
        // 由于其他分区无密码无法解密索引，我们只能整体复制 vault 文件中
        // 除头部外的所有数据，再重写活跃分区的索引使其紧凑。
        // 简化且正确的做法：复制整个原文件到临时文件，然后在临时文件上
        // 对活跃分区做碎片整理（重写文件数据 + 索引），其他分区数据原样保留。

        // Create unique backup and temporary files exclusively so pre-existing links cannot be followed.
        // 2.7.1 修复：备份 io::copy 中途失败（磁盘不足最常见）时半份 .bak 永久
        // 残留 —— 失败分支统一「先 DoD 擦除再删除」。
        let backup_result: std::io::Result<()> = (|| {
            // 3.0.1（F10）：0600 落盘（见 create_scratch_file）
            let mut backup_file = crate::vault::fs_util::create_scratch_file(&backup_path)?;
            let mut original = File::open(&vault_path)?;
            let copy = std::io::copy(&mut original, &mut backup_file);
            let sync = backup_file.sync_all();
            drop(backup_file);
            drop(original);
            copy.and(sync).map(|_| ())
        })();
        if let Err(e) = backup_result {
            wipe_scratch_file(&backup_path);
            return Err(e.into());
        }

        // 2.4.1：闭包返回整理后的最终索引（供成功分支刷新内存缓存）
        let result = (|| -> Result<Index, VaultError> {
            // 2.4.1（P0-3 增强）：单分区（绝大多数用户的常态）走「紧凑整理」——
            // 新临时文件只包含「头部 + 迁移数据 + 新索引」，旧数据区根本不会
            // 出现在新文件里，物理长度直接缩小，真正回收磁盘空间。
            // 多分区时维持旧行为：整体复制原文件（其他分区数据位置未知，不能丢弃），
            // 旧数据区在成功路径末尾统一 DoD 擦除。
            let single_partition = self.partitions.len() == 1;

            // 步骤 1：准备临时文件
            // 2.8.0：占位头部尺寸必须与当前格式版本一致 —— v4→v5 升级等场景下
            // 版本可能变化，占位不足会让头部覆写越界到数据区
            let hdr_size = header_size_of(self.format_version)?;
            let mut tmp_file = {
                // 3.0.1（F10）：0600 落盘（见 create_scratch_file）
                let mut tmp_file = crate::vault::fs_util::create_scratch_file(&temp_path)?;
                if !single_partition {
                    // 多分区：整体复制原文件，保留所有分区数据
                    let src_file = File::open(&vault_path)?;
                    std::io::copy(&mut &src_file, &mut tmp_file)?;
                    tmp_file.flush()?;
                    tmp_file.sync_all()?;
                } else {
                    // 单分区：头部占位（步骤 6 重写为最终内容）
                    tmp_file.write_all(&vec![0u8; hdr_size])?;
                    tmp_file.flush()?;
                    tmp_file.sync_all()?;
                }
                tmp_file
            };

            // 步骤 2：加载活跃分区索引（直接从原文件读取，原文件此刻未被修改）
            let mut index = {
                let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
                let active = self.active_partition.ok_or(VaultError::NotOpen)?;
                let p = &self.partitions[active];
                load_index_from_file(file, &active_enc_key, p.index_offset, p.index_length)?
            };

            // 步骤 3：迁移活跃分区的文件数据（紧凑排列，流式拷贝防 OOM）
            let files_snapshot: Vec<(String, u64, u64)> = index
                .files
                .iter()
                .map(|(k, m)| (k.clone(), m.offset, m.length))
                .collect();
            let total = files_snapshot.len();

            // 迁移源一律是原文件（读取与写入分离到两个句柄，
            // 避免单文件自拷贝在区间重叠时的数据破坏风险）
            let mut src_file = File::open(&vault_path)?;
            let mut write_cursor = if single_partition {
                hdr_size as u64
            } else {
                tmp_file.seek(SeekFrom::End(0))?
            };
            for (i, (vpath, old_off, old_len)) in files_snapshot.iter().enumerate() {
                copy_between(
                    &mut src_file,
                    &mut tmp_file,
                    *old_off,
                    write_cursor,
                    *old_len,
                )?;
                index
                    .files
                    .get_mut(vpath)
                    .ok_or_else(|| VaultError::Other("defragment: 文件不在索引中".to_string()))?
                    .offset = write_cursor;
                write_cursor += *old_len;
                if let Some(ref cb) = progress {
                    cb((i + 1) * 50 / total.max(1));
                }
            }
            drop(src_file);

            // 步骤 4：写入活跃分区的新索引
            // 2.8.2：去掉整索引深拷贝 —— 先注入审计再直接序列化 index，
            // 成功路径把 index 本身作为最终缓存返回（10k 文件索引省一次数 MB 分配）
            if let Some(ref audit) = self.audit {
                index.audit = audit.to_vec();
            }
            let idx_json = serde_json::to_vec(&index)?;
            let enc_idx = encrypt_gcm(&active_enc_key, &idx_json, b"index", None)?;
            tmp_file.seek(SeekFrom::Start(write_cursor))?;
            tmp_file.write_all(&enc_idx)?;
            tmp_file.flush()?;
            tmp_file.sync_all()?;

            let new_idx_offset = write_cursor;
            let new_idx_length = enc_idx.len() as u64;

            // 步骤 5：空间回收说明
            // - 单分区：临时文件从未写入旧数据（见步骤 1/3），文件本身就是紧凑
            //   布局，无需截断，物理空间已直接回收；
            // - 多分区：不截断文件（其他分区数据位于原文件中部，无密码无法定位
            //   其边界，截断会永久破坏它们）。空间回收靠成功路径末尾对活跃分区
            //   旧数据区/旧索引的 DoD 7-pass 擦除（P0-3）—— 逻辑空间被释放，
            //   物理文件长度保持不变（见 README「已知限制」）。

            let active = self.active_partition.ok_or(VaultError::NotOpen)?;
            self.partitions[active].index_offset = new_idx_offset;
            self.partitions[active].index_length = new_idx_length;
            // 3.0.1（#5 修复）：步骤 4 已把会话内新增审计注入本次落盘的索引，
            // 头部锚点必须与**本次落盘条目数**一致 —— 旧实现头部仍写旧计数，
            // 下次开柜「锚点不符」假篡改警告。
            self.partitions[active].audit_count = index.audit.len() as u32;

            // 步骤 6：写入头部（含所有分区的新偏移）
            let lock_state = &self.lock_state;
            let salt = &self.salt;
            let partitions = &self.partitions;
            let yk_salt = self.yk_challenge_salt;
            write_header_to_file(
                &mut tmp_file,
                self.format_version,
                lock_state,
                salt,
                partitions,
                &sign_key,
                &yk_salt,
            )?;
            tmp_file.flush()?;
            tmp_file.sync_all()?;
            drop(tmp_file);

            // 步骤 7：原子替换
            // 2.7.0 修复：2.6.1 起 open_vault_rw 以 FILE_SHARE_READ 独占共享模式
            // 打开（不共享 DELETE），而替换式 rename 需要对目标文件取得 DELETE
            // 访问权 —— 会话句柄未释放时 rename 在 Windows 上会 sharing violation
            // 失败。先 drop 本进程句柄再替换（成功/失败分支随后都会重新独占打开）。
            self.file = None;
            // 2.7.1 修复：fs::rename 会让保险柜变成新建的临时文件对象，属性/ACL
            // 改为目录继承 —— 用户为 .lyt 单独设置的「仅本人可访问」静默失效，
            // 而 2.7.0 起删除会自动触发整理，该副作用已从偶发变常态。Windows 改用
            // ReplaceFileW（替换内容同时保留安全描述符/属性/创建时间），不支持时
            // 回退 rename；Unix rename 后还原 mode。
            replace_vault_file(&temp_path, &vault_path)?;
            sync_parent_dir(&vault_path);

            // 2.3.0 修复：备份是保险柜的完整副本，直接删除会在磁盘上留下抗取证死角。
            // 先 DoD 7-pass 擦除再删除；失败仅记日志（备份残留不影响主文件正确性）。
            if let Err(e) = dod_erase(&backup_path, None) {
                log::warn!(
                    "擦除碎片整理备份失败（保险柜同目录可能残留 .defrag_backup 文件）: {}",
                    e
                );
            }
            secure_wipe_vec(idx_json);
            Ok(index)
        })();

        match result {
            Ok(final_index) => {
                // 2.6.1：先释放旧句柄（同时释放 flock），再以独占方式重开，
                // 避免同进程两次 flock 冲突，并保证整理后仍持有独占锁。
                self.file = None;
                // 2.8.2（诚实报错）：整理已提交（磁盘已是新布局）—— 旧实现重开
                // 失败时 `?` 直接上抛「整理失败」，用户会误以为失败而重试（再整理
                // 一整轮），而会话停在 file=None 的半死状态。现在先把内存缓存
                // 对齐新布局，短重试重开；仍失败则明确告知「已完成，请重开」。
                self.cached_index = Some(final_index);
                let mut reopened: Option<File> = None;
                let mut last_err: Option<String> = None;
                for _ in 0..3 {
                    match open_vault_rw(&vault_path) {
                        Ok(f) => match lock_vault_exclusive(&f) {
                            Ok(()) => {
                                reopened = Some(f);
                                break;
                            }
                            Err(e) => {
                                drop(f);
                                last_err = Some(e.to_string());
                            }
                        },
                        Err(e) => last_err = Some(e.to_string()),
                    }
                    std::thread::sleep(std::time::Duration::from_millis(150));
                }
                match reopened {
                    Some(file) => self.file = Some(file),
                    None => return Err(VaultError::Other(format!(
                        "碎片整理已完成（磁盘布局已更新），但恢复会话失败（{}）。请用密码重新打开保险柜",
                        last_err.unwrap_or_default()
                    ))),
                }
                // P0-3：擦除活跃分区旧数据区与旧索引（逻辑空间回收）。
                // 仅多分区路径需要：新文件是原文件的完整副本，旧区仍在新文件内。
                // 单分区紧凑整理的新文件从未包含旧数据区，此处擦除反而会毁掉
                // 迁移后的新数据 —— 必须跳过。
                let single_partition = self.partitions.len() == 1;
                // 新数据全部位于 [orig_len, ...)，与旧区不相交；此步失败仅意味着
                // 残留垃圾数据（无害），不影响正确性。
                // 防御性校验：若不变量被破坏（旧区越界进入新区），跳过擦除只留垃圾。
                let wipe_safe = !single_partition
                    && old_idx_off.saturating_add(old_idx_len) <= orig_len
                    && old_file_ranges
                        .iter()
                        .all(|&(o, l)| o.saturating_add(l) <= orig_len);
                if single_partition {
                    // 单分区紧凑整理：旧数据区未进入新文件，无需擦除
                    //（2.7.1：日志器只落 Warn 及以上，移除永不记录的 debug 日志）
                } else if !wipe_safe {
                    log::warn!("碎片整理布局校验未通过，跳过旧数据擦除（残留垃圾，无害）");
                }
                if wipe_safe {
                    let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
                    let mut wiped = true;
                    if old_idx_len > 0 {
                        if let Err(e) = dod_overwrite_range(file, old_idx_off, old_idx_len) {
                            wiped = false;
                            log::warn!("整理后擦除旧索引失败（残留垃圾，无害）: {}", e);
                        }
                    }
                    for (off, len) in &old_file_ranges {
                        if *len == 0 {
                            continue;
                        }
                        if let Err(e) = dod_overwrite_range(file, *off, *len) {
                            wiped = false;
                            log::warn!("整理后擦除旧数据失败（残留垃圾，无害）: {}", e);
                        }
                    }
                    if wiped {
                        let _ = file.flush();
                        let _ = file.sync_all();
                    }
                }
                // 2.4.1：缓存已在重开前对齐新布局（偏移已全部更新）——
                // 2.8.2 重构后此处不再重复赋值（final_index 已被移动）
                self.log_event("执行保险柜碎片整理");
                if let Some(ref cb) = progress {
                    cb(100);
                }
                Ok(())
            }
            Err(e) => {
                // 2.7.0 修复：先释放会话句柄 —— 下方「备份恢复」也是对 vault_path
                // 的替换式 rename，会话句柄未释放时同样会 sharing violation 失败。
                self.file = None;
                // 2.7.1 修复：temp 是保险柜内容的中间副本，先 DoD 擦除再删除
                //（旧实现直接 remove_file，半份副本可恢复）
                wipe_scratch_file(&temp_path);
                if backup_path.exists() {
                    // 2.7.1 修复：备份恢复失败不再被静默吞掉 —— 此时保险柜本体
                    // 已被移走，必须告知用户并保留 .bak 以便手动恢复。
                    // 3.0.0（L-3 审计修复）：恢复改走 replace_vault_file ——
                    // 旧实现 fs::rename 覆盖会让恢复出的保险柜丢失原有 ACL/属性
                    //（继承目录属性），与 replace_vault_file 的存在目的矛盾
                    if let Err(re) = replace_vault_file(&backup_path, &vault_path) {
                        log::error!(
                            "碎片整理失败后从备份恢复保险柜失败：{}；同目录残留的 .bak 备份文件未被删除，请手动恢复",
                            re
                        );
                        return Err(VaultError::Other(format!(
                            "整理失败（{}），且自动恢复失败（{}）：请勿再次写入，同目录的 .bak 备份文件可手动恢复",
                            e, re
                        )));
                    }
                    // 2.4.1 修复：闭包内可能已把 self.partitions[active] 指向**新**偏移，
                    // 而恢复回来的原文件仍是旧布局 —— 不回滚会导致后续读写错位。
                    // （旧实现在此存在状态不一致缺陷）
                    if let Some(active) = self.active_partition {
                        self.partitions[active] = old_part;
                    }
                    self.file = None;
                    let file = open_vault_rw(&vault_path).ok().and_then(|f| {
                        lock_vault_exclusive(&f).ok()?;
                        Some(f)
                    });
                    self.file = file;
                }
                Err(e)
            }
        }
    }

    // ═══════════════ 销毁 ═══════════════

    /// 2.7.1 修复（Windows 上销毁必然失败的回归）：旧流程是命令层按路径以
    /// 「读+写」重新打开同一文件再擦除 —— 但会话句柄以 `FILE_SHARE_READ` 独占
    /// 共享模式打开（2.6.1），任何**写**打开都会被系统拒绝
    /// （`ERROR_SHARING_VIOLATION` / os error 32），销毁从未成功过；失效期间
    /// 用户很可能改用普通文件管理器删除 —— 数据未经任何擦除。
    ///
    /// 现改为销毁全程**交出会话句柄本身**，不按路径二次打开：
    /// - 符号链接 / 重解析点的拒绝前移到**打开阶段**（`open_vault_rw` 的
    ///   `FILE_FLAG_OPEN_REPARSE_POINT` / `O_NOFOLLOW` + 句柄元数据确认），
    ///   句柄锚定的 TOCTOU 防护因此不再削弱；
    /// - 未落盘的审计先随索引持久化（此时仍持有会话句柄），随后交出句柄做
    ///   DoD 7-pass 擦除 + 删除（Windows 下优先 delete-on-close，不经路径）。
    pub fn destroy(&mut self) -> Result<(), VaultError> {
        if !self.is_open() {
            return Err(VaultError::NotOpen);
        }
        let path = self.path.clone().ok_or(VaultError::NotOpen)?;

        // 与 close 相同：先把未落盘的审计持久化（此时仍持有会话句柄）
        if self.audit.is_some() {
            if let Some(ref mut audit) = self.audit {
                audit.add("保险柜已销毁");
            }
            self.audit_dirty = true;
        }
        if self.enc_key.is_some() && self.audit_dirty {
            if let Err(e) = self.load_index().and_then(|idx| self.save_index(idx)) {
                log::warn!("销毁前落盘审计失败（不影响销毁）: {}", e);
            }
        }

        // 交出会话句柄 —— 后续擦除与删除只作用于该句柄代表的文件对象
        let file = self.file.take().ok_or(VaultError::NotOpen)?;

        // 清理会话状态（与 close 相同的密钥/缓存清理）
        self.path = None;
        if let Some(mut idx) = self.cached_index.take() {
            idx.files.clear();
            idx.folders.clear();
            idx.audit.clear();
        }
        // 3.0.0：LockedKey 的 Drop 自带解锁 + 清零
        drop(self.enc_key.take());
        drop(self.auth_key.take());
        drop(self.sign_key.take());
        drop(self.data_key.take());
        self.format_version = 0;
        self.active_partition = None;
        self.audit = None;
        self.audit_dirty = false;

        // 基于已持有的句柄完成 DoD 7-pass 擦除 + 删除（全程不按路径重开）。
        // 3.0.1（#6 修复）：擦除中途失败（瞬时占用 / I/O 错误）时旧实现直接
        // 上抛 —— 会话已清空，重试只会 NotOpen，用户只能重启。改为内部短退避
        // 重试：首次用会话句柄；失败后文件仍在则改走按路径擦除（dod_erase
        // 自带 O_NOFOLLOW / REPARSE 防护），至多 3 次。文件已消失 = 删除达成。
        let erase_err: Option<std::io::Error> =
            match crate::wipe::dod_erase_handle(file, &path, None) {
                Ok(()) => None,
                Err(e) => {
                    let mut err = Some(e);
                    for _ in 0..2 {
                        std::thread::sleep(std::time::Duration::from_millis(150));
                        if !path.exists() {
                            err = None;
                            break;
                        }
                        match crate::wipe::dod_erase(&path, None) {
                            Ok(()) => {
                                err = None;
                                break;
                            }
                            Err(e2) => err = Some(e2),
                        }
                    }
                    err
                }
            };
        // 3.0.1（P0 #1 修复）：头部日志边车随本体一并清理
        let _ = std::fs::remove_file(super::header::journal_path(&path));
        match erase_err {
            None => Ok(()),
            Some(e) => Err(VaultError::from(e)),
        }
    }
}
