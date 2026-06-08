//! 防篡改审计日志（链式 HMAC）
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

const AUDIT_MAX_EVENTS: usize = 10000;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub ts: f64, // epoch seconds as float64（兼容 Python time.time()）
    pub event: String,
    pub hmac: String, // hex encoded
}

pub struct AuditLog {
    auth_key: [u8; 32],
    entries: Vec<AuditEntry>,
    chain: [u8; 32],
}

impl AuditLog {
    pub fn new(auth_key: [u8; 32]) -> Self {
        Self {
            auth_key,
            entries: Vec::new(),
            chain: [0u8; 32],
        }
    }

    pub fn add(&mut self, event: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
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

        self.entries.push(AuditEntry {
            ts: now,
            event: event.to_string(),
            hmac: hex::encode(&self.chain[..]),
        });

        if self.entries.len() > AUDIT_MAX_EVENTS {
            self.entries.remove(0);
        }
    }

    pub fn to_vec(&self) -> Vec<AuditEntry> {
        self.entries.clone()
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
                if expected.as_slice() == entry_bytes {
                    chain = entry_bytes;
                    log.entries.push(entry.clone());
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
