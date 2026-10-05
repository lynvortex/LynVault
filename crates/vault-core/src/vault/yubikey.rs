//! 可选硬件密钥二因子（3.0.0）—— YubiKey HMAC-SHA1 挑战-响应。
//!
//! **零格式变更设计**（见 crypto.rs 的 `mix_kek_with_response` 文档）：
//! 启用二因子的分区，其 data_key 包裹在「响应混合 KEK」下（KEK 之上的
//! HKDF 域分离混合），头部条目结构与普通分区完全一致；打开时按
//! 「混合优先、普通兜底」双路径解包，两种分区可共存，无需任何标志位。
//!
//! **挑战**不落盘：从头部保留区的公开「挑战盐」（9..41，create 时随机生成、
//! 终生不变 —— 3.0.1 F19 后开柜不再轮换）HKDF 派生（`derive_yubikey_challenge`）。
//! **响应**不落盘：只有物理钥匙能计算。安全性 = Argon2id 口令 + 钥匙内部
//! HMAC 密钥两段独立因子。响应只能由后端在用点现场挑战获得（3.0.1 F2），
//! 不经 WebView 传递；对文件快照重放的场景由「响应不离开后端进程」收敛。
//!
//! **丢失风险（与密钥文件同级，须如实告知）**：启用分区的钥匙丢失且响应
//! 不可复现时，该分区数据永久无法打开（其他未启用分区不受影响）。
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::crypto::*;
use crate::error::VaultError;

use super::consts::*;
use super::duress::VerifyPartitionPassword;
use super::header::{alias_field16, auth_tag_header_prefix, bound_auth_tag, key_wrap_aad};
use super::PartitionInfo;
use super::Vault;

impl Vault {
    /// 为当前分区启用硬件密钥二因子。
    ///
    /// 验证当前分区密码（响应参与验证路径）→ 换盐重新包裹（混合 KEK）→
    /// 重写头部。头部级操作，瞬间完成。重复启用 = 换盐重包（幂等无害）。
    pub fn enable_yubikey_2fa(
        &mut self,
        confirm_password: &str,
        key_file_data: Option<&[u8]>,
        response: &[u8; 20],
    ) -> Result<(), VaultError> {
        self.rewrap_active_partition(
            confirm_password,
            key_file_data,
            Some(response),
            Some(response),
            "为当前分区启用硬件密钥二因子",
        )
    }

    /// 解除当前分区的硬件密钥二因子（换盐重新以普通 KEK 包裹）。
    pub fn disable_yubikey_2fa(
        &mut self,
        confirm_password: &str,
        key_file_data: Option<&[u8]>,
        response: &[u8; 20],
    ) -> Result<(), VaultError> {
        // 验证用响应（证明持有钥匙）；包裹目标 = 普通 KEK（None）
        self.rewrap_active_partition(
            confirm_password,
            key_file_data,
            Some(response),
            None,
            "解除当前分区的硬件密钥二因子",
        )
    }

    /// 3.0.0（L2 审计修复配套）：当前会话的硬件密钥挑战盐 —— 供命令层
    /// 自行计算挑战-响应（不信任 IPC 提供的响应字节）。盐为头部公开字段，
    /// 与 read_vault_yk_salt 同级；安全性完全落在响应只能由物理钥匙计算。
    pub fn yubikey_challenge_salt(&self) -> Result<[u8; 32], VaultError> {
        if !self.is_open() {
            return Err(VaultError::NotOpen);
        }
        Ok(self.yk_challenge_salt)
    }

    /// 当前分区是否以混合 KEK 包裹（会话状态，由打开时实际命中的路径判定）。
    pub fn is_yubikey_2fa_active(&self) -> Result<bool, VaultError> {
        if !self.is_open() {
            return Err(VaultError::NotOpen);
        }
        Ok(self.yubikey_wrapped)
    }

    /// 分区条目重新包裹的共享实现（启用 / 解除二因子）：
    /// 验证密码（响应参与）→ 换盐 + 按目标状态（混合/普通）重新包裹 data_key
    /// → 重算认证标签 → 重写头部（失败回滚内存，与 change_password 同纪律）。
    /// 仅支持信封格式（v5/v6）—— v4 无包裹层。
    fn rewrap_active_partition(
        &mut self,
        confirm_password: &str,
        key_file_data: Option<&[u8]>,
        verify_response: Option<&[u8; 20]>,
        target_response: Option<&[u8; 20]>,
        log_msg: &str,
    ) -> Result<(), VaultError> {
        if !self.is_open() {
            return Err(VaultError::NotOpen);
        }
        if self.format_version == VERSION_V4 {
            return Err(VaultError::Other(
                "v4 保险柜不支持硬件密钥二因子（请通过「修改密码」升级到 v6 后再启用）".into(),
            ));
        }
        self.verify_current_partition_password(confirm_password, key_file_data, verify_response)?;

        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let session_dk = Zeroizing::new(**self.data_key.as_ref().ok_or(VaultError::NotOpen)?);
        let auth_key = **self.auth_key.as_ref().ok_or(VaultError::NotOpen)?;
        let p = self.partitions[active].clone();
        let alias_field = alias_field16(&p.alias);
        let prefix = auth_tag_header_prefix(&self.salt, self.format_version);

        // 换盐重新包裹：目标 KEK = 普通或混合（响应参与）
        let mut new_salt = [0u8; 32];
        OsRng.fill_bytes(&mut new_salt);
        let kek = Zeroizing::new(derive_kek(confirm_password, key_file_data, &new_salt)?);
        let wrap_key = match target_response {
            Some(resp) => Zeroizing::new(mix_kek_with_response(&kek, resp)),
            None => kek,
        };
        let aad = key_wrap_aad(&prefix, &alias_field, &new_salt);
        let wrapped_v = encrypt_gcm(&wrap_key, &session_dk[..], &aad, None)?;
        let mut new_wrapped = [0u8; WRAPPED_KEY_SIZE];
        new_wrapped.copy_from_slice(&wrapped_v);
        drop(wrap_key);
        crate::wipe::secure_wipe_vec(wrapped_v);

        // 盐变了必须重算认证标签（auth_key 由未变的 data_key 派生，依然有效）
        let new_tag = bound_auth_tag(
            &auth_key,
            &self.salt,
            self.format_version,
            &alias_field,
            &new_salt,
        );
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
        let old_wrapped_state = self.yubikey_wrapped;
        self.yubikey_wrapped = target_response.is_some();
        if let Err(e) = self.update_header() {
            self.partitions[active] = old_part;
            self.yubikey_wrapped = old_wrapped_state;
            return Err(e);
        }
        self.log_event(log_msg);
        Ok(())
    }
}
