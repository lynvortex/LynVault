//! 防篡改审计日志（链式 HMAC）
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::VaultError;

const AUDIT_MAX_EVENTS: usize = 10000;

/// 3.0.1（F7 修复）：审计数组反序列化的硬上限 —— 取运行期上限的 10 倍。
/// AUDIT_MAX_EVENTS 只在追加时生效（add 的 pop_front），from_entries 对输入
/// 列表长度不做限制；索引密文上限 256 MiB ≠ 解密后 JSON 有结构上限，数百万
/// 条恶意条目会在 serde 解析阶段分配数百万个含 String 的 AuditEntry，并在
/// 会话期随 save_index 反复克隆/重序列化。取 10× 而非 AUDIT_MAX_EVENTS 本身：
/// 若历史版本曾写出超限但合法的审计，开柜不受影响（内存上界仍受控），
/// 超过硬上限的才判定为篡改/损坏并拒绝。
const AUDIT_PARSE_HARD_CAP: usize = AUDIT_MAX_EVENTS * 10;

/// 3.0.1（F7 修复）：审计数组的受限反序列化 —— 用 SeqAccess 逐条计数，
/// 超过硬上限立即中止解析（内存上界恒为硬上限条数，而非等整个 JSON 解完）。
pub(crate) fn deserialize_capped<'de, D>(deserializer: D) -> Result<Vec<AuditEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct CappedVec;
    impl<'de> serde::de::Visitor<'de> for CappedVec {
        type Value = Vec<AuditEntry>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("审计条目数组")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut v = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(AUDIT_PARSE_HARD_CAP));
            let mut n = 0usize;
            while let Some(e) = seq.next_element::<AuditEntry>()? {
                n += 1;
                if n > AUDIT_PARSE_HARD_CAP {
                    return Err(<A::Error as serde::de::Error>::custom(format!(
                        "审计条目数超过上限 {}（索引可能被篡改或损坏）",
                        AUDIT_PARSE_HARD_CAP
                    )));
                }
                v.push(e);
            }
            Ok(v)
        }
    }
    deserializer.deserialize_seq(CappedVec)
}

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
    /// 2.8.2：from_entries 恢复时是否存在被丢弃的尾部条目（链式 HMAC 只保证
    /// 「尾部追加不可篡改」，对截断没有锚点）—— 打开路径据此显式告警，不再
    /// 静默接受。根治（条目数锚入头部签名）需要 v6 格式变更。
    truncated: bool,
}

impl AuditLog {
    pub fn new(auth_key: [u8; 32]) -> Self {
        Self {
            auth_key,
            entries: VecDeque::new(),
            chain: [0u8; 32],
            truncated: false,
        }
    }

    /// 2.8.2：恢复时是否丢弃过尾部条目（打开路径据此告警）
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// 3.0.0（审计锚点）：外部校验（头部计数 vs 索引条目数）检出异常时置位
    /// —— 与 HMAC 链断链共用同一告警通道。
    pub fn mark_truncated(&mut self) {
        self.truncated = true;
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

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.auth_key)
            .expect("HMAC-SHA256 接受任意长度密钥，构造不可失败");
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
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(old_key)
                .expect("HMAC-SHA256 接受任意长度密钥，构造不可失败");
            mac.update(&chain);
            mac.update(&entry.ts.to_le_bytes());
            mac.update(entry.event.as_bytes());
            let expected = mac.finalize().into_bytes();
            let entry_hmac = hex::decode(&entry.hmac).unwrap_or_default();
            if entry_hmac.len() != 32
                || !bool::from(expected.as_slice().ct_eq(entry_hmac.as_slice()))
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
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.auth_key)
                .expect("HMAC-SHA256 接受任意长度密钥，构造不可失败");
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

    /// 从持久化条目恢复审计日志（逐条验证链的完整性，篡改的条目将被丢弃）。
    /// 2.8.2：发生丢弃时置位 truncated 标志（is_truncated）—— 旧实现静默
    /// 截断，打开路径无从告警；链式 HMAC 本身对「砍掉尾部」没有锚点，
    /// 但至少要让恢复端知道日志不完整。
    pub fn from_entries(entries: Vec<AuditEntry>, auth_key: [u8; 32]) -> Self {
        let mut log = Self::new(auth_key);
        let mut chain = [0u8; 32];
        let mut processed = 0usize;
        for entry in &entries {
            processed += 1;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&log.auth_key)
                .expect("HMAC-SHA256 接受任意长度密钥，构造不可失败");
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
                    processed -= 1;
                    log.truncated = true;
                    break;
                }
            } else {
                processed -= 1;
                log.truncated = true;
                break;
            }
        }
        if processed < entries.len() {
            log.truncated = true;
        }
        log.chain = chain;
        log
    }
}

#[cfg(test)]
mod tests {
    //! 3.1.1（审计修复）：链式 HMAC 的恢复语义（篡改位点 / 尾部截断 /
    //! 错误密钥）此前没有直接用例，而这正是「审计链被动手脚」的唯一检出点。

    use super::*;

    fn key() -> [u8; 32] {
        [5u8; 32]
    }

    #[test]
    fn chain_roundtrip_and_tamper_detection() {
        let mut log = AuditLog::new(key());
        for i in 0..3 {
            log.add(&format!("事件 {}", i));
        }
        let entries = log.to_vec();

        // 完整链：恢复后不标记截断
        let restored = AuditLog::from_entries(entries.clone(), key());
        assert!(!restored.is_truncated(), "完整链不得标记截断");
        assert_eq!(restored.to_vec().len(), 3);

        // 篡改中间条目 → 从该条起全部丢弃，并标记截断
        let mut bad = entries.clone();
        bad[1].event = "被篡改".into();
        let r = AuditLog::from_entries(bad, key());
        assert!(r.is_truncated(), "篡改必须被检出");
        assert_eq!(r.to_vec().len(), 1, "只保留篡改点之前的条目");

        // 尾部截断：剩余链本身仍有效（截断由头部锚点另行检出）
        let short = entries[..2].to_vec();
        let r = AuditLog::from_entries(short, key());
        assert_eq!(r.to_vec().len(), 2);
        assert!(!r.is_truncated(), "尾部截断不破坏剩余链的有效性");
    }

    #[test]
    fn wrong_auth_key_rejects_everything() {
        let mut log = AuditLog::new(key());
        log.add("x");
        let r = AuditLog::from_entries(log.to_vec(), [6u8; 32]);
        assert!(r.is_truncated());
        assert!(r.to_vec().is_empty());
    }

    #[test]
    fn rekey_preserves_history_and_rejects_tamper() {
        let mut log = AuditLog::new(key());
        log.add("a");
        log.add("b");
        let new_key = [9u8; 32];
        log.rekey(&key(), new_key).expect("合法链必须可换钥");
        // 换钥后旧密钥不再有效，新密钥有效
        let entries = log.to_vec();
        assert!(AuditLog::from_entries(entries.clone(), key()).is_truncated());
        let r = AuditLog::from_entries(entries, new_key);
        assert!(!r.is_truncated());
        assert_eq!(r.to_vec().len(), 2);

        // 换钥前先硬校验：链内条目被篡改时必须中止（不静默截断）。
        // 直接用同模块可访问的私有字段构造「已入内存但已被改」的状态 ——
        // from_entries 会把无效条目过滤掉，无法覆盖这条路径。
        let mut raw = AuditLog::new(key());
        raw.add("a");
        raw.add("b");
        raw.entries[1].event = "被改".into();
        assert!(raw.rekey(&key(), new_key).is_err(), "篡改链换钥必须失败");
    }

    #[test]
    fn add_enforces_runtime_cap() {
        let mut log = AuditLog::new(key());
        for i in 0..(AUDIT_MAX_EVENTS + 5) {
            log.add(&i.to_string());
        }
        assert_eq!(
            log.to_vec().len(),
            AUDIT_MAX_EVENTS,
            "超出运行期上限应淘汰最旧条目"
        );
    }

    #[test]
    fn capped_deserialization_guards_oversized_array() {
        // 超硬上限 → 解析期即拒绝（内存放大 DoS 收口）；恰为上限 → 通过
        let entry = r#"{"ts":0.0,"event":"","hmac":""}"#;
        let over = vec![entry; AUDIT_PARSE_HARD_CAP + 1].join(",");
        let json = format!(r#"{{"files":{{}},"folders":{{}},"audit":[{}]}}"#, over);
        assert!(
            serde_json::from_str::<crate::index::Index>(&json).is_err(),
            "超过硬上限的审计数组必须拒绝解析"
        );
        let at_cap = vec![entry; AUDIT_PARSE_HARD_CAP].join(",");
        let json = format!(r#"{{"files":{{}},"folders":{{}},"audit":[{}]}}"#, at_cap);
        assert!(
            serde_json::from_str::<crate::index::Index>(&json).is_ok(),
            "恰好等于硬上限必须通过（避免误伤历史合法数据）"
        );
    }
}
