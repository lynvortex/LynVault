//! 防篡改审计日志（链式 HMAC）
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::VaultError;

const AUDIT_MAX_EVENTS: usize = 10000;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub ts: f64, // epoch seconds as float64（兼容 Python time.time()）
    pub event: String,
    pub hmac: String, // hex encoded
}

pub struct AuditLog {
    auth_key: [u8; 32],
    // 使用 VecDeque 替代 Vec，避免超过上限时的 O(n) 整体前移
    entries: VecDeque<AuditEntry>,
    chain: [u8; 32],
}

impl AuditLog {
    pub fn new(auth_key: [u8; 32]) -> Self {
        Self {
            auth_key,
            entries: VecDeque::new(),
            chain: [0u8; 32],
        }
    }

    pub fn add(&mut self, event: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let prev = if self.entries.is_empty() {
            &[0u8; 32]
        } else {
            &self.chain
        };

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.auth_key).unwrap();
        mac.update(prev);
        mac.update(&now.to_le_bytes());
        mac.update(event.as_bytes());
        let new_hmac = mac.finalize().into_bytes();
        self.chain = new_hmac.into();

        self.entries.push_back(AuditEntry {
            ts: now,
            event: event.to_string(),
            hmac: hex::encode(&self.chain[..]),
        });

        // VecDeque::pop_front 是 O(1)，避免旧实现的 O(n) 整体前移
        while self.entries.len() > AUDIT_MAX_EVENTS {
            self.entries.pop_front();
        }
    }

    /// 2.8.0：用新密钥重建整条 HMAC 链（v4→v5 升级路径使用 —— 会话密钥全部更换，
    /// 旧链无法在新密钥下通过校验，需在升级事务内完成换钥，历史记录得以保留）。
    ///
    /// 先用 `old_key` 逐条验证现有链（任何一条失败即报错，**不静默丢弃** ——
    /// 升级路径要求明确知道历史是否被篡改，而非悄悄截断），再用新密钥逐条重算。
    pub fn rekey(&mut self, old_key: &[u8; 32], new_key: [u8; 32]) -> Result<(), VaultError> {
        use subtle::ConstantTimeEq;
        // 验证阶段（旧密钥）
        let mut chain = [0u8; 32];
        for entry in &self.entries {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(old_key).unwrap();
            mac.update(&chain);
            mac.update(&entry.ts.to_le_bytes());
            mac.update(entry.event.as_bytes());
            let expected = mac.finalize().into_bytes();
            let entry_hmac = hex::decode(&entry.hmac).unwrap_or_default();
            if entry_hmac.len() != 32
                || !bool::from(expected.as_slice().ct_eq(&entry_hmac.as_slice()))
            {
                return Err(VaultError::Other(
                    "审计链验证失败（历史记录可能被篡改），已中止本次密码修改".into(),
                ));
            }
            chain.copy_from_slice(&entry_hmac);
        }
        // 重建阶段（新密钥）
        self.auth_key = new_key;
        let mut new_chain = [0u8; 32];
        for entry in self.entries.iter_mut() {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.auth_key).unwrap();
            mac.update(&new_chain);
            mac.update(&entry.ts.to_le_bytes());
            mac.update(entry.event.as_bytes());
            new_chain = mac.finalize().into_bytes().into();
            entry.hmac = hex::encode(&new_chain[..]);
        }
        self.chain = new_chain;
        Ok(())
    }

    pub fn to_vec(&self) -> Vec<AuditEntry> {
        self.entries.iter().cloned().collect()
    }

    /// 从持久化条目恢复审计日志（逐条验证链的完整性，篡改的条目将被丢弃）
    pub fn from_entries(entries: Vec<AuditEntry>, auth_key: [u8; 32]) -> Self {
        let mut log = Self::new(auth_key);
        let mut chain = [0u8; 32];
        for entry in &entries {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&log.auth_key).unwrap();
            mac.update(&chain);
            mac.update(&entry.ts.to_le_bytes());
            mac.update(entry.event.as_bytes());
            let expected = mac.finalize().into_bytes();
            let entry_hmac = hex::decode(&entry.hmac).unwrap_or_default();
            if entry_hmac.len() == 32 {
                let mut entry_bytes = [0u8; 32];
                entry_bytes.copy_from_slice(&entry_hmac);
                // 恒定时间比较，防止计时侧信道
                use subtle::ConstantTimeEq;
                if expected.as_slice().ct_eq(&entry_bytes).into() {
                    chain = entry_bytes;
                    log.entries.push_back(entry.clone());
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        log.chain = chain;
        log
    }
}
