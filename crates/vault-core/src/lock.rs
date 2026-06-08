//! 防暴力破解锁定逻辑
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::derive_lock_key;

pub const MAX_ERRORS: u8 = 5;
pub const LOCKOUT_SECONDS: f64 = 30.0 * 60.0;

#[derive(Debug, Clone)]
pub struct LockState {
    pub lock_count: u8,
    pub lock_until: f64,
    pub lock_key: [u8; 32],
}

impl LockState {
    /// 从保险柜 salt 派生 lock_key，**不存储在文件头部**
    pub fn new(salt: &[u8; 32]) -> Self {
        Self {
            lock_count: 0,
            lock_until: 0.0,
            lock_key: derive_lock_key(salt),
        }
    }

    /// 是否已被锁定
    pub fn is_locked(&self) -> bool {
        if self.lock_until <= 0.0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        now < self.lock_until
    }

    /// 记录一次失败，可能触发锁定
    pub fn record_failure(&mut self) {
        self.lock_count += 1;
        if self.lock_count >= MAX_ERRORS {
            self.lock_until = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs_f64()
                + LOCKOUT_SECONDS;
        }
    }

    /// 重置锁定状态（认证成功后调用）
    pub fn reset(&mut self) {
        self.lock_count = 0;
        self.lock_until = 0.0;
    }

    /// 计算当前锁定参数的 HMAC（兼容 Python FMT_LOCK = '<Bd'）
    pub fn compute_hmac(&self) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.lock_key).unwrap();
        mac.update(&[self.lock_count]);
        mac.update(&self.lock_until.to_le_bytes()); // f64 bytes, matches Python struct.pack('<Bd', ...)
        mac.finalize().into_bytes().into()
    }

    /// 验证外部存储的锁定 HMAC 是否一致（恒定时间比较）
    pub fn verify_hmac(&self, stored: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        let expected = self.compute_hmac();
        expected.ct_eq(stored).into()
    }
}
