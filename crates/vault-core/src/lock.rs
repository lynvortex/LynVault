//! 防暴力破解锁定逻辑
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_ERRORS: u8 = 5;
pub const LOCKOUT_SECONDS: f64 = 30.0 * 60.0;

/// 锁定状态（持久化于头部锁定区，41 字节：count(1) + until(8) + HMAC(32)）。
///
/// 2.3.0 安全性说明（修复了旧版锁定永不生效的问题）：
/// - 锁定区 HMAC 使用从 salt 独立派生的**公开**密钥（`crypto::derive_lock_mac_key`），
///   任意一次打开尝试（无论密码是否正确）都能校验并递增计数 ——
///   错误密码会真正触发锁定（5 次错误 → 锁定 30 分钟）。
/// - 任何分区的合法密码都能打开保险柜并重置锁定（诱饵分区可用）。
/// - 局限：拥有文件写权限的攻击者可伪造「未锁定」记录（与其直接破坏文件同级），
///   锁定针对「在线猜测 / 误输密码」场景；离线复制文件暴力破解不受影响。
/// - `lock_until` 同时记录单调时间戳，防止进程内系统时钟回拨（跨重启回拨仍需
///   系统时钟，属已知限制）。
#[derive(Debug, Clone)]
pub struct LockState {
    pub lock_count: u8,
    pub lock_until: f64,
    /// 单调时钟的锁定到期时刻（秒）。None 表示未锁定或未启动单调计时。
    pub lock_until_monotonic: Option<std::time::Instant>,
}

impl LockState {
    /// 创建未锁定状态（HMAC 由调用方在写入时按需计算）。
    pub fn new() -> Self {
        Self {
            lock_count: 0,
            lock_until: 0.0,
            lock_until_monotonic: None,
        }
    }

    /// 是否已被锁定。
    ///
    /// 双重判定：系统时钟 + 单调时钟。系统时钟可被攻击者回调，
    /// 但单调时钟无法被用户空间修改，因此只要单调时钟未到，就一定判定为锁定。
    pub fn is_locked(&self) -> bool {
        if self.lock_count < MAX_ERRORS {
            return false;
        }
        // 单调时钟优先；无法被用户空间调整
        if let Some(until_mono) = self.lock_until_monotonic {
            return std::time::Instant::now() < until_mono;
        }
        // 回退到系统时钟（持久化恢复时使用）
        if self.lock_until <= 0.0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        now < self.lock_until
    }

    /// 记录一次失败，可能触发锁定
    pub fn record_failure(&mut self) {
        self.lock_count = self.lock_count.saturating_add(1);
        if self.lock_count >= MAX_ERRORS {
            self.lock_until = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64()
                + LOCKOUT_SECONDS;
            // 同时记录单调时钟，防止系统时钟被回拨绕过
            self.lock_until_monotonic =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(LOCKOUT_SECONDS as u64));
        }
    }

    /// 重置锁定状态（认证成功后调用）
    pub fn reset(&mut self) {
        self.lock_count = 0;
        self.lock_until = 0.0;
        self.lock_until_monotonic = None;
    }

    /// 计算当前锁定参数的 HMAC（兼容 Python FMT_LOCK = '<Bd'）。
    /// key 由调用方提供：新保险柜用 `derive_lock_mac_key`（公开），
    /// 旧保险柜迁移前用 `derive_legacy_lock_key`（密码派生）。
    pub fn compute_hmac(&self, key: &[u8; 32]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
        mac.update(&[self.lock_count]);
        mac.update(&self.lock_until.to_le_bytes()); // f64 bytes, matches Python struct.pack('<Bd', ...)
        mac.finalize().into_bytes().into()
    }

    /// 验证外部存储的锁定 HMAC 是否一致（恒定时间比较）
    pub fn verify_hmac(&self, key: &[u8; 32], stored: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        let expected = self.compute_hmac(key);
        expected.ct_eq(stored).into()
    }
}

impl Default for LockState {
    fn default() -> Self {
        Self::new()
    }
}
