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

pub use error::VaultError;
pub use index::{FileMeta, Index};
pub use vault::{
    is_vault_file, read_lock_info, read_vault_salt, read_vault_yk_salt, IntegrityIssue, LockInfo,
    PartitionInfo, SearchHit, Vault, VAULT_MAGIC,
};
