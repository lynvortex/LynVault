//! 分区管理 —— 添加 / 删除伪装分区。
//! 3.0.0 拆分自 vault.rs，逻辑逐字节不变。
use std::io::{Seek, SeekFrom, Write};

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::*;
use crate::error::VaultError;
use crate::index::Index;
use crate::wipe::{dod_overwrite_range, secure_wipe_vec};

use super::consts::*;
use super::header::*;
use super::PartitionInfo;
use super::Vault;

impl Vault {
    // ═══════════════ 分区管理 ═══════════════

    pub fn add_partition(
        &mut self,
        alias: &str,
        fake_password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<(), VaultError> {
        if self.file.is_none() {
            return Err(VaultError::NotOpen);
        }
        // 2.3.0：库级 API 也校验分区别名（此前仅 Tauri 命令层校验，
        // 非法别名可能导致重开后分区不可见）
        if !is_valid_alias(alias) {
            return Err(VaultError::Other(
                "分区别名只能包含字母、数字、下划线、短横线和空格，长度 1-16 字符".into(),
            ));
        }
        // 2.4.1 修复（P2-19）：分区密码同样按字符数校验（旧实现无任何强度校验）
        if fake_password.chars().count() < 12 {
            return Err(VaultError::Other("分区密码长度至少 12 位".into()));
        }
        if self.partitions.len() >= MAX_PARTITIONS {
            return Err(VaultError::TooManyPartitions);
        }
        // 3.0.0（审计修复）：分区别名查重 —— 别名是分区在头部条目与会话内
        // 查找（set_duress_mark_on / remove_partition / 前端列表）的唯一键，
        // 重名会让所有按别名定位的代码命中错误分区。与 alias 查找保持同一
        // 精确匹配语义（区分大小写）。
        if self.partitions.iter().any(|p| p.alias == alias) {
            return Err(VaultError::Other(format!("分区别名 '{}' 已存在", alias)));
        }

        let mut part_salt = [0u8; 32];
        OsRng.fill_bytes(&mut part_salt);
        // 2.8.0：信封格式（v5/v6）为新分区生成随机 data_key 并用分区口令包裹；
        // v4 保持旧派生路径。3.0.0：v6 必须同样走包裹分支 —— 否则 v6 保险柜
        // 新增的分区是「无包裹密钥」的 v4 形态条目，重开后永远无法认证。
        let alias_field = alias_field16(alias);
        let (mut keys, wrapped_key) = match self.format_version {
            VERSION_V5 | VERSION_V6 => {
                // 2.8.1：dk/kek 用 Zeroizing —— expand_keys 派生失败的 `?` 早退
                // 路径上随机 data_key 不再以明文残留
                let mut dk = [0u8; 32];
                OsRng.fill_bytes(&mut dk);
                let dk = Zeroizing::new(dk);
                let k = expand_keys(&dk)?;
                let kek = Zeroizing::new(derive_kek(fake_password, key_file_data, &part_salt)?);
                let wrap_aad = key_wrap_aad(
                    &auth_tag_header_prefix(&self.salt, self.format_version),
                    &alias_field,
                    &part_salt,
                );
                let wrapped_v = encrypt_gcm(&kek, &dk[..], &wrap_aad, None)?;
                let mut wrapped = [0u8; WRAPPED_KEY_SIZE];
                wrapped.copy_from_slice(&wrapped_v);
                drop(kek);
                secure_wipe_vec(wrapped_v);
                (k, Some(wrapped))
            }
            _ => (derive_keys(fake_password, key_file_data, &part_salt)?, None),
        };
        // 2.6.1：新分区同样使用绑定头部的认证标签（保险柜 salt + 本分区别名/salt）
        let auth_tag = bound_auth_tag(
            &keys.auth_key,
            &self.salt,
            self.format_version,
            &alias_field,
            &part_salt,
        );

        let empty_index = Index::new();
        let plain = serde_json::to_vec(&empty_index)?;
        let enc = encrypt_gcm(&keys.enc_key, &plain, b"index", None)?;

        // 新分区的空索引先追加到文件尾（获得偏移量）；此步之后头部写入若失败，
        // 这段密文成为无害死空间（头部仍指向旧布局，碎片整理可回收）
        let (offset, enc_len) = {
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            let offset = file.seek(SeekFrom::End(0))?;
            file.write_all(&enc)?;
            file.flush()?;
            file.sync_all()?;
            (offset, enc.len() as u64)
        };

        // 2.8.2（崩溃一致性）：先写头部、成功后才提交内存 —— 旧实现先
        // partitions.push 再 update_header，头部写入失败时内存与磁盘分叉，
        // 后续任意一次 save_index/update_header 都会把「失败的添加」持久化。
        // 3.0.1（P0 #1 修复）：头部写入改经日志边车防撕裂。
        let new_entry = PartitionInfo {
            alias: alias.into(),
            salt: part_salt,
            auth_tag,
            index_offset: offset,
            index_length: enc_len,
            wrapped_key,
            audit_count: 0,
        };
        {
            let mut new_partitions = self.partitions.clone();
            new_partitions.push(new_entry.clone());
            self.write_header_with(&new_partitions)?;
            self.partitions = new_partitions;
        }

        self.log_event(&format!("添加伪装分区 '{}'", new_entry.alias));
        keys.zeroize();
        secure_wipe_vec(plain);
        Ok(())
    }

    pub fn remove_partition(&mut self, alias: &str) -> Result<(), VaultError> {
        if self.file.is_none() {
            return Err(VaultError::NotOpen);
        }
        let pos = self
            .partitions
            .iter()
            .position(|p| p.alias == alias)
            .ok_or(VaultError::PartitionNotFound)?;
        if pos == 0 {
            return Err(VaultError::Other("不能删除主分区".into()));
        }
        if self.active_partition == Some(pos) {
            return Err(VaultError::Other("不能删除当前使用的分区".into()));
        }

        // 2.3.0 顺序修正：先持久化「分区已删除」（update_header），再擦除旧索引区。
        // 旧实现先擦后更新头部，擦除后崩溃会让头部仍指向已被覆盖的索引 → 永久损坏。
        // 2.8.2（崩溃一致性）：先写头部、成功后才提交内存 —— 旧实现先改
        // partitions/active_partition 再 update_header，写入失败时内存与磁盘分叉。
        let p = self.partitions[pos].clone();
        let mut new_partitions = self.partitions.clone();
        new_partitions.remove(pos);
        // 调整活跃分区索引：如果删除的位置在当前活跃分区之前，活跃索引需要减 1
        let new_active = match self.active_partition {
            Some(active) if pos < active => Some(active - 1),
            other => other,
        };
        // 2.8.2（崩溃一致性）：先写头部、成功后才提交内存。
        // 3.0.1（P0 #1 修复）：头部写入改经日志边车防撕裂。
        self.write_header_with(&new_partitions)?;
        self.partitions = new_partitions;
        self.active_partition = new_active;
        self.log_event(&format!("删除分区 '{}'", alias));

        // 擦除旧索引区（尽力而为）。已知限制：该分区的文件密文因无分区密码无法定位，
        // 无法一并擦除（README「已知限制」已说明）；保险柜整体销毁时会一并擦除。
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = dod_overwrite_range(file, p.index_offset, p.index_length) {
                log::warn!("擦除已删除分区的索引失败（不影响正确性）: {}", e);
            }
            let _ = file.flush();
            let _ = file.sync_all();
        }
        Ok(())
    }
}
