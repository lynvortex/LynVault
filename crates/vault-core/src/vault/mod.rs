//! 保险柜主体（3.0.0 模块化拆分）。
//!
//! 结构与字段定义在此；行为按领域拆分到子模块（session / partition / ops_* /
//! maintenance），对外 API 经本模块 re-export，与拆分前的 vault.rs 完全一致：
//! - consts     格式常量（单一来源）
//! - header     头部读写 / 解析 / 签名 / 认证标签绑定
//! - fs_util    独占打开 / 索引 I/O / 拷贝 / 原子替换等底层工具
//! - session    创建 / 打开认证 / 索引缓存 / 头部更新
//! - partition  伪装分区增删
//! - duress     胁迫密码（标记 / 触发覆写 / 演练）
//! - yubikey    可选硬件密钥二因子（启用 / 解除，零格式变更）
//! - ops_import 导入与内容写入
//! - ops_extract 提取与读取
//! - ops_delete 安全删除与自动整理触发
//! - maintenance 改密码 / 升级 / 体检 / 搜索 / 碎片整理 / 销毁
// 3.0.1：pub(crate) —— Index::validate 需要读取 CHUNK_SIZE_V6 上限
pub(crate) mod consts;
mod duress;
pub(crate) mod fs_util;
mod header;
mod locked_key;
mod maintenance;
mod ops_delete;
mod ops_extract;
mod ops_import;
mod partition;
mod session;
mod yubikey;

pub use consts::VAULT_MAGIC;
pub use fs_util::is_vault_file;
pub use header::{read_lock_info, read_vault_salt, read_vault_yk_salt, LockInfo};
pub use maintenance::{IntegrityIssue, SearchHit};

use std::fs::File;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::audit::AuditLog;
use crate::error::VaultError;
use crate::index::Index;
use crate::lock::LockState;
use consts::WRAPPED_KEY_SIZE;

/// 保险柜主体
#[derive(Default)]
pub struct Vault {
    pub(crate) path: Option<PathBuf>,
    pub(crate) file: Option<File>,

    // 3.0.0（审计加固）：会话密钥装箱驻留（LockedKey：堆上稳定地址 +
    // VirtualLock/mlock 防换出 + Drop 清零），替代裸数组
    pub(crate) enc_key: Option<locked_key::LockedKey>,
    pub(crate) auth_key: Option<locked_key::LockedKey>,
    pub(crate) sign_key: Option<locked_key::LockedKey>,

    /// 2.8.0（v5）：保险柜文件格式版本（4 = 旧格式兼容，5 = 信封加密）。
    /// 仅在会话建立后有意义的元数据；未打开时为 0。
    pub(crate) format_version: u8,
    /// 2.8.0（v5）：当前分区的随机数据密钥（口令包裹层之下的真正密钥）。
    /// v4 会话为 None。修改口令时以它为锚 —— 数据密钥不变，只换包裹。
    pub(crate) data_key: Option<locked_key::LockedKey>,

    pub(crate) salt: [u8; 32],
    pub(crate) lock_state: LockState,

    pub(crate) partitions: Vec<PartitionInfo>,
    pub(crate) active_partition: Option<usize>,

    pub(crate) audit: Option<AuditLog>,

    /// 2.4.1 新增：解密后的索引内存缓存（P0-2 优化核心）。
    /// 旧实现每次操作都要「读磁盘 → AES-GCM 解密 → JSON 反序列化」，
    /// 批量导入 1000 个文件 = 2000+ 次全量解密加载。
    /// 现在打开保险柜后索引常驻内存，save_index 成功后同步刷新缓存。
    /// 注意：缓存与磁盘一致性由「所有索引变更必须走 save_index」这一约定保证。
    pub(crate) cached_index: Option<Index>,

    /// 2.4.1 新增：审计条目有未落盘的变更（关闭时才需要补一次 save_index，
    /// 避免旧实现 close() 无条件全量重写索引 + 7-pass 擦旧索引的开销）。
    pub(crate) audit_dirty: bool,

    /// 3.0.0（可选硬件密钥二因子）：当前分区是否以「响应混合 KEK」包裹。
    /// 打开时由实际匹配的解包路径判定（混合路径命中 = true）；change_password
    /// 据此保留二因子状态。零格式变更设计 —— 头部条目结构不变，见 crypto.rs
    /// 的 mix_kek_with_response 文档。
    pub(crate) yubikey_wrapped: bool,

    /// 3.0.0（M-2）：硬件密钥挑战盐（头部保留区 9..41 的会话副本）。
    /// 3.0.1（F19 修复）：打开时从头部读入后**终生不变** —— 开柜轮换会使
    /// data_key 的旧响应包裹永久不可解（二因子保险柜砖死）。盐只在 create
    /// 时随机生成；v4 会话与 Default 全 0 = 存量兼容形态。
    pub(crate) yk_challenge_salt: [u8; 32],
}

#[derive(Debug, Clone, Zeroize)]
pub struct PartitionInfo {
    pub alias: String,
    pub salt: [u8; 32],
    pub auth_tag: [u8; 32],
    pub index_offset: u64,
    pub index_length: u64,
    /// 2.8.0（v5）：被分区口令包裹的随机 data_key（nonce12 + ct32 + tag16）。
    /// v4 条目为 None（v4 的会话密钥直接由口令派生，无包裹层）。
    /// 未使用条目整体随机填充时该字段同样是随机字节，与真实条目不可区分。
    pub wrapped_key: Option<[u8; WRAPPED_KEY_SIZE]>,
    /// 3.0.0（审计锚点）：本分区的审计条目计数（写入头部保留区 41..73 槽位）。
    /// 随头部签名覆盖；save_index 时与索引落盘内容同步更新。0 = 无锚点
    ///（v4 分区 / 尚未落盘过审计的新分区）。
    pub audit_count: u32,
}

impl Vault {
    /// 2.4.1 新增：写审计并置脏标记（统一入口）。
    /// 旧实现审计在各处手动 add，close() 无条件全量重写索引以持久化审计；
    /// 现在只有 audit_dirty=true 时 close() 才补一次 save_index。
    /// 2.8.2（L13）：审计消息可能含攻击者可控的 vpath —— 入库前把控制字符
    /// 替换为 '?' 并截断到 200 字符，防止伪造审计条目结构 / 超长条目膨胀索引。
    /// 3.0.1（#24 修复）：补齐 RTL 方向控制字符（U+202A..E / U+2066..9，与
    /// sanitize_filename 的 I8 字符集一致）—— 旧实现放行它们，审计条目可被
    /// 视觉伪装（U+202E 反转后续文本方向）。
    pub(crate) fn log_event(&mut self, msg: &str) {
        let sanitized: String = msg
            .chars()
            .map(|c| {
                let cu = c as u32;
                if cu < 0x20 || cu == 0x7f || matches!(cu, 0x202A..=0x202E | 0x2066..=0x2069) {
                    '?'
                } else {
                    c
                }
            })
            .take(200)
            .collect();
        if let Some(ref mut audit) = self.audit {
            audit.add(&sanitized);
        }
        self.audit_dirty = true;
    }

    // ═══════════════ 查询 ═══════════════

    pub fn get_audit_entries(&self) -> Vec<crate::audit::AuditEntry> {
        self.audit.as_ref().map(|a| a.to_vec()).unwrap_or_default()
    }

    /// 3.0.1（#8 修复）：验证当前分区口令 —— 供命令层「降级安全开关需口令
    /// 确认」（save_settings 关防截屏 / 禁用自动锁时）复用；v4/v5/v6 统一
    /// 语义见 duress 模块的 VerifyPartitionPassword 实现（恒定时间比较）。
    pub fn verify_current_password(
        &mut self,
        password: &str,
        key_file_data: Option<&[u8]>,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<(), VaultError> {
        use duress::VerifyPartitionPassword;
        self.verify_current_partition_password(password, key_file_data, yk_response)
    }

    /// 追加一条审计日志。如果审计日志未初始化则什么都不做。
    pub fn add_audit_entry(&mut self, msg: &str) {
        self.log_event(msg);
    }

    pub fn get_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn get_active_partition(&self) -> Option<&PartitionInfo> {
        self.active_partition.and_then(|i| self.partitions.get(i))
    }

    pub fn get_partitions(&self) -> &[PartitionInfo] {
        &self.partitions
    }

    pub fn is_open(&self) -> bool {
        self.enc_key.is_some() && self.file.is_some()
    }

    /// 2.4.1 变更（P1-15）：只在审计有未落盘变更时才补一次 save_index。
    /// 旧实现 close() 无条件 load+save（全量索引重写 + 7-pass 擦旧索引，
    /// 10 次 fsync）—— 而大多数时候索引内容早已随上一次操作落盘，
    /// 这次写入的唯一目的是把「保险柜已关闭」审计条目刷进索引。
    /// 3.0.0（L-2 审计修复）：放弃会话 —— 打开成功路径的后置步骤
    ///（头部重写 / 胁迫触发）失败时调用。与 close 的差异：**不落盘任何内容**
    ///（close 会补写审计；此刻磁盘状态未知，任何写入都可能基于半程状态），
    /// 仅清零全部会话字段，让「Err 返回 + 半开会话」的矛盾状态不再外泄。
    /// 胁迫触发失败场景下内存分区可能已被随机化 —— 磁盘头部未动，下次打开如旧
    /// （fail-closed 且无损）。
    pub(crate) fn abandon_session(&mut self) {
        self.file = None;
        self.path = None;
        if let Some(mut idx) = self.cached_index.take() {
            idx.files.clear();
            idx.folders.clear();
            idx.audit.clear();
        }
        // 3.0.0：LockedKey 的 Drop 自带解锁 + 清零，take 即完成清理
        drop(self.enc_key.take());
        drop(self.auth_key.take());
        drop(self.sign_key.take());
        drop(self.data_key.take());
        self.format_version = 0;
        self.active_partition = None;
        self.audit = None;
        self.audit_dirty = false;
        self.yubikey_wrapped = false;
        self.yk_challenge_salt = [0u8; 32];
    }

    pub fn close(&mut self) {
        if self.audit.is_some() {
            if let Some(ref mut audit) = self.audit {
                audit.add("保险柜已关闭");
            }
            self.audit_dirty = true;
        }
        // M8 修复：close 失败不应掩盖原错误，但 Drop 中无法返回错误，
        // 失败时只记日志
        if self.enc_key.is_some() && self.file.is_some() && self.audit_dirty {
            if let Err(e) = self.load_index().and_then(|idx| self.save_index(idx)) {
                log::error!("关闭保险柜时保存索引失败: {}", e);
            }
        }
        self.file = None;
        self.path = None;
        // 2.4.1：清理索引缓存（含明文审计字符串），避免敏感数据残留在堆上
        if let Some(mut idx) = self.cached_index.take() {
            idx.files.clear();
            idx.folders.clear();
            idx.audit.clear();
        }
        // 3.0.0：LockedKey 的 Drop 自带解锁 + 清零，take 即完成清理
        drop(self.enc_key.take());
        drop(self.auth_key.take());
        drop(self.sign_key.take());
        drop(self.data_key.take());
        self.format_version = 0;
        self.yubikey_wrapped = false;
        self.yk_challenge_salt = [0u8; 32];
        self.active_partition = None;
        self.audit = None;
        self.audit_dirty = false;
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        // M8 修复：避免在 Drop 中做可能 panic 的 I/O；close 已做错误处理
        // 仅清理密钥，不强制 save_index（防止 Drop 中二次失败）
        self.file = None;
        self.path = None;
        // 2.4.1：同样清理索引缓存中的明文内容（含审计条目）
        if let Some(mut idx) = self.cached_index.take() {
            idx.files.clear();
            idx.folders.clear();
            idx.audit.clear();
        }
        // 3.0.0：LockedKey 的 Drop 自带解锁 + 清零，take 即完成清理
        drop(self.enc_key.take());
        drop(self.auth_key.take());
        drop(self.sign_key.take());
        drop(self.data_key.take());
        self.format_version = 0;
        self.yubikey_wrapped = false;
        self.yk_challenge_salt = [0u8; 32];
    }
}
