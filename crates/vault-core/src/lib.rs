//! LynVault 核心库 - 抗取证加密保险柜
//!
//! 提供保险柜的创建、认证、分区管理、文件索引的加解密等功能。
//! 所有敏感数据均实现零化擦除。

pub mod audit;
pub mod crypto;
pub mod error;
pub mod index;
pub mod lock;
pub mod office;
pub mod vault;
pub mod wipe;

/// 3.0.1（F18/F25 fuzz 工程）：把分块布局解析算术直接暴露给 fuzz 目标 ——
/// 3.0.0 的 fuzz 只覆盖 JSON 反序列化与路径清洗，从未触及提取 / 媒体 /
/// 擦除的算术路径（F3/F4/F5 因此漏网）。仅返回字段快照，不暴露内部类型。
#[doc(hidden)]
pub fn resolve_chunk_plan_for_fuzz(
    length: u64,
    chunk_size: u64,
    chunk_count: u64,
) -> Result<(u64, u64, u64, u64), VaultError> {
    let p = vault::fs_util::resolve_chunk_plan(length, chunk_size, chunk_count)?;
    Ok((p.chunk_size, p.chunk_count, p.full_ct, p.expected_last))
}

pub use error::VaultError;
pub use index::{FileMeta, Index};
pub use vault::{
    is_vault_file, read_lock_info, read_vault_salt, read_vault_yk_salt, IntegrityIssue, LockInfo,
    PartitionInfo, SearchHit, Vault, VAULT_MAGIC,
};
