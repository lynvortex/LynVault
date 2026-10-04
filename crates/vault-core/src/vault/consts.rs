//! 保险柜格式常量（单一来源）—— 头部布局 / 版本 / 容量上限。
//! 3.0.0 拆分自 vault.rs，数值与语义不变；跨模块使用，一律 pub(crate)。
// --- 常量 ---
pub(crate) const MAGIC: &[u8; 8] = b"PYVAULT4";
/// v4 格式（1024 字节头部，会话密钥直接由口令派生）
pub(crate) const VERSION_V4: u8 = 4;
/// v5 格式（2.8.0：信封加密 —— 随机 data_key 由口令包裹存储于头部，
/// 修改口令只需重写头部，数据零接触）
pub(crate) const VERSION_V5: u8 = 5;
/// v6 格式（3.0.0：流式分块加密 —— 头部布局与 v5 完全一致（仅版本字节为 6），
/// 文件数据改为 4 MiB 分块、每块独立 GCM，突破单文件 256 MiB 内存上限；
/// 分块 AAD 绑定冻结 vpath + 块序号 + 总块数，防截断/重排/块交换）
pub(crate) const VERSION_V6: u8 = 6;
pub(crate) const HEADER_SIZE_V4: usize = 1024;
pub(crate) const HEADER_SIZE_V5: usize = 2048;
pub(crate) const MAX_PARTITIONS: usize = 8;
pub(crate) const PARTITION_ENTRY_SIZE_V4: usize = 96;
pub(crate) const PARTITION_ENTRY_SIZE_V5: usize = 192;
pub(crate) const LOCK_OFFSET_V4: usize = 887;
/// v5 头部：106 + 8×192 = 1642
pub(crate) const LOCK_OFFSET_V5: usize = 1642;
/// v5 头部签名覆盖 header[..1984]，签名本体位于 1984..2048
pub(crate) const SIGNED_LENGTH_V5: usize = 1984;
/// 3.0.0（审计锚点）：v5/v6 头部保留区 41..73 = 8 × u32 LE 审计条目计数
///（每分区槽一个）。计数随头部签名覆盖；开柜时与索引实际条目数比对 ——
/// 尾部截断（HMAC 链无法自查的攻击）或索引回滚都会造成不一致而被检出。
/// v4 头部不写此区（保持全 0 = 无锚点，仅信封格式启用）。
pub(crate) const AUDIT_COUNT_OFFSET: usize = 41;

/// 3.0.0（M-2 审计修复）：v5/v6 头部保留区中的硬件密钥挑战盐偏移（9..41，32 字节）。
/// 挑战 = HKDF(挑战盐)——盐在签名覆盖范围内（防篡改、公开无妨），**每次成功开柜
/// 轮换**，响应因此一次性（旧响应立即失效）。v4 头部不使用（保留区保持全 0，
/// 二因子不支持 v4）。v5 存量柜保留区为全 0 → 首次开柜轮换后即生效。
pub(crate) const YK_SALT_OFFSET: usize = 9;
pub(crate) const SIGNATURE_OFFSET_V5: usize = 1984;
/// v5 分区条目中的包裹密钥字段：nonce(12) + data_key 密文(32) + GCM tag(16)
pub(crate) const WRAPPED_KEY_SIZE: usize = 60;

/// LynVault 文件 magic bytes（8 字节），用于启动扫描时识别真正的保险柜文件
pub const VAULT_MAGIC: &[u8; 8] = MAGIC;

pub(crate) const DEFAULT_PARTITION: &str = "Main";

/// 自动整理阈值:删除类操作后,死空间(已被安全擦除但仍占位的区域)同时满足
/// 「绝对值 ≥ 64 MiB」与「占文件大小 ≥ 30%」时,自动执行一次紧凑整理。
/// 仅单分区保险柜启用 —— 多分区整理不回收空间(其他分区数据位置未知,不能
/// 截断文件),自动执行没有收益。
pub(crate) const AUTO_DEFRAG_MIN_DEAD_BYTES: u64 = 64 * 1024 * 1024;
/// 30% 用整数运算表示(3/10),避免浮点比较的边界误差
pub(crate) const AUTO_DEFRAG_DEAD_RATIO_NUM: u64 = 3;
pub(crate) const AUTO_DEFRAG_DEAD_RATIO_DEN: u64 = 10;

/// 单次操作中内存缓冲区的上限（256 MiB）。
/// v4/v5（Legacy 整段布局）单文件上限；v6 中仅约束「载入内存的预览/编辑」路径，
/// 不再约束导入/提取（v6 分块流式，文件上限见 MAX_VAULT_FILE）。
pub(crate) const MAX_INMEM_BUFFER: usize = 256 * 1024 * 1024;
/// v6 单文件大小上限（1 TiB）—— sanity 上限，实际受磁盘空间约束
pub(crate) const MAX_VAULT_FILE: u64 = 1024u64 * 1024 * 1024 * 1024;
/// v6 分块布局的明文块大小（4 MiB）—— 每块独立 nonce + GCM tag，
/// 常量内存流式加解密的单位
pub(crate) const CHUNK_SIZE_V6: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_IMPORT_DEPTH: usize = 64;
pub(crate) const MAX_IMPORT_ENTRIES: usize = 100_000;
