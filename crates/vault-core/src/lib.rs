//! LynVault 核心库 - 抗取证加密保险柜
//!
//! 提供保险柜的创建、认证、分区管理、文件索引的加解密等功能。
//! 所有敏感数据均实现零化擦除。

pub mod crypto;
pub mod vault;
pub mod index;
pub mod lock;
pub mod audit;
pub mod wipe;
pub mod office;
pub mod error;

pub use vault::{Vault, PartitionInfo};
pub use index::{Index, FileMeta};
pub use error::VaultError;
