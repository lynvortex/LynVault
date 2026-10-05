//! 头部格式层 —— 头部读写（v4/v5/v6）、解析、签名、认证标签绑定、别名字段。
//! 3.0.0 拆分自 vault.rs，逻辑逐字节不变。
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use rand::rngs::OsRng;
use rand::RngCore;

use crate::crypto::*;
use crate::error::VaultError;
use crate::lock::LockState;

use super::consts::*;
use super::PartitionInfo;

/// 2.8.0：头部锁定区信息（开锁前的失败尝试提示用）
#[derive(Debug, Clone, serde::Serialize)]
pub struct LockInfo {
    /// 累计失败尝试次数（成功打开后清零）
    pub failed_count: u8,
    /// 当前是否处于锁定状态（≥5 次失败且未到期）
    pub locked: bool,
    /// 锁定到期时刻（epoch 秒；未锁定为 0）
    pub lock_until_epoch: f64,
}

/// 2.8.0：读取保险柜头部锁定区的失败计数（无需密码 —— 锁定区 HMAC 用公开密钥）。
///
/// 供开锁前的 UI 提示使用：用户能看到「这个文件已被试错 N 次」，从而察觉
/// 有人动过自己的保险柜。锁定区 HMAC 校验失败（头部被篡改）时返回错误。
pub fn read_lock_info(path: &Path) -> Result<LockInfo, VaultError> {
    let mut f = File::open(path)?;
    let mut sniff = [0u8; 9];
    f.read_exact(&mut sniff)?;
    if &sniff[..8] != MAGIC {
        return Err(VaultError::BadMagic);
    }
    let lock_offset = match sniff[8] {
        VERSION_V4 => LOCK_OFFSET_V4,
        // v6 与 v5 头部逐字节同布局（仅版本字节不同），锁定区偏移一致
        VERSION_V5 | VERSION_V6 => LOCK_OFFSET_V5,
        v => return Err(VaultError::Other(format!("不支持的保险柜格式版本 {}", v))),
    };
    // 保险柜 salt 在 v4/v5 布局中位置一致（73..105）
    f.seek(SeekFrom::Start(73))?;
    let mut salt = [0u8; 32];
    f.read_exact(&mut salt)?;
    f.seek(SeekFrom::Start(lock_offset as u64))?;
    let mut buf = [0u8; 41];
    f.read_exact(&mut buf)?;
    let mut lock_until = f64::from_le_bytes(buf[1..9].try_into().unwrap());
    // 2.8.1：拒绝非有限值（与打开路径同一防护）
    if !lock_until.is_finite() {
        lock_until = 0.0;
    }
    let lock_state = LockState {
        lock_count: buf[0],
        lock_until,
        lock_until_monotonic: None,
    };
    let mac_key = derive_lock_mac_key(&salt);
    if !lock_state.verify_hmac(&mac_key, &buf[9..41].try_into().unwrap()) {
        return Err(VaultError::Other(
            "头部锁定区校验失败 —— 头部可能被篡改".into(),
        ));
    }
    Ok(LockInfo {
        failed_count: lock_state.lock_count,
        locked: lock_state.is_locked(),
        lock_until_epoch: lock_state.lock_until,
    })
}

/// 3.0.0：读取保险柜盐（开柜前的硬件密钥挑战派生用）。
/// 盐本身是头部公开字段（73..105），与 read_lock_info 同级 —— 不泄露任何秘密，
/// 仅用于派生挑战；响应的计算能力在物理钥匙内。
pub fn read_vault_salt(path: &Path) -> Result<[u8; 32], VaultError> {
    let mut f = File::open(path)?;
    let mut sniff = [0u8; 9];
    f.read_exact(&mut sniff)?;
    if &sniff[..8] != MAGIC {
        return Err(VaultError::BadMagic);
    }
    match sniff[8] {
        VERSION_V4 | VERSION_V5 | VERSION_V6 => {}
        v => return Err(VaultError::Other(format!("不支持的保险柜格式版本 {}", v))),
    }
    f.seek(SeekFrom::Start(73))?;
    let mut salt = [0u8; 32];
    f.read_exact(&mut salt)?;
    Ok(salt)
}

/// 3.0.0（M-2）：读取头部硬件密钥挑战盐（保留区 9..41）。
/// v4 存量柜 / 未轮换过的 v5 存量柜读出全 0 —— 与历史行为等价（挑战恒定），
/// 首次成功开柜后即轮换为随机盐。
pub fn read_vault_yk_salt(path: &Path) -> Result<[u8; 32], VaultError> {
    let mut f = File::open(path)?;
    let mut sniff = [0u8; 9];
    f.read_exact(&mut sniff)?;
    if &sniff[..8] != MAGIC {
        return Err(VaultError::BadMagic);
    }
    match sniff[8] {
        VERSION_V4 | VERSION_V5 | VERSION_V6 => {}
        v => return Err(VaultError::Other(format!("不支持的保险柜格式版本 {}", v))),
    }
    f.seek(SeekFrom::Start(YK_SALT_OFFSET as u64))?;
    let mut yk_salt = [0u8; 32];
    f.read_exact(&mut yk_salt)?;
    Ok(yk_salt)
}

/// 写入完整头部（含签名）—— 按格式版本分发。
pub(crate) fn write_header_to_file(
    file: &mut File,
    version: u8,
    lock_state: &LockState,
    salt: &[u8; 32],
    partitions: &[PartitionInfo],
    sign_key: &[u8; 32],
    yk_challenge_salt: &[u8; 32],
) -> Result<(), VaultError> {
    match version {
        // v4 保留区保持全 0（二因子不适用于 v4，挑战盐无意义）
        VERSION_V4 => write_header_v4(file, lock_state, salt, partitions, sign_key),
        // v6 与 v5 头部同布局，仅版本字节不同（认证标签 / 包裹 AAD 按版本绑定）
        VERSION_V5 | VERSION_V6 => write_header_envelope(
            file,
            version,
            lock_state,
            salt,
            partitions,
            sign_key,
            yk_challenge_salt,
        ),
        v => Err(VaultError::Other(format!("未知的保险柜格式版本: {}", v))),
    }
}

/// v4 头部（1024 字节）—— 与 2.x 历史格式逐字节一致。
pub(crate) fn write_header_v4(
    file: &mut File,
    lock_state: &LockState,
    salt: &[u8; 32],
    partitions: &[PartitionInfo],
    sign_key: &[u8; 32],
) -> Result<(), VaultError> {
    let mut header = [0u8; HEADER_SIZE_V4];

    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION_V4;
    // bytes 9..40 reserved
    // bytes 41..73: was lock_key (plaintext) — now zeroed (lock_key is derived from salt)
    header[73..105].copy_from_slice(salt);
    // num_partitions always MAX_PARTITIONS to hide real count
    header[105] = MAX_PARTITIONS as u8;

    let mut off = 106;
    for i in 0..MAX_PARTITIONS {
        if let Some(p) = partitions.get(i) {
            // M7 修复：按字符截断而非字节，避免切断多字节字符产生无效 UTF-8
            // （2.6.1：抽为 alias_field16，保证与 auth_tag 绑定载荷逐字节一致）
            let alias_field = alias_field16(&p.alias);
            header[off..off + 16].copy_from_slice(&alias_field);
            off += 16;
            header[off..off + 32].copy_from_slice(&p.salt);
            off += 32;
            header[off..off + 32].copy_from_slice(&p.auth_tag);
            off += 32;
            header[off..off + 8].copy_from_slice(&p.index_offset.to_le_bytes());
            off += 8;
            header[off..off + 8].copy_from_slice(&p.index_length.to_le_bytes());
            off += 8;
        } else {
            // 2.3.0 修复（防元数据泄露）：未使用的条目**整体**填充随机数据（含别名），
            // 不再以「别名首字节 0」作标记 —— 旧标记使读取者可数出真实分区数量。
            // 打开时会对全部 8 个条目做恒定次数的认证尝试，伪条目认证必然失败。
            let mut rand_buf = [0u8; PARTITION_ENTRY_SIZE_V4];
            OsRng.fill_bytes(&mut rand_buf);
            header[off..off + PARTITION_ENTRY_SIZE_V4].copy_from_slice(&rand_buf);
            off += PARTITION_ENTRY_SIZE_V4;
        }
    }

    header[LOCK_OFFSET_V4] = lock_state.lock_count;
    header[LOCK_OFFSET_V4 + 1..LOCK_OFFSET_V4 + 9]
        .copy_from_slice(&lock_state.lock_until.to_le_bytes());
    // 2.3.0 修复：锁定区 HMAC 使用从 salt 独立派生的公开密钥，
    // 任意密码的打开尝试都能校验并递增计数（详见 crypto::derive_lock_mac_key）
    let mac_key = derive_lock_mac_key(salt);
    let hmac = lock_state.compute_hmac(&mac_key);
    header[LOCK_OFFSET_V4 + 9..LOCK_OFFSET_V4 + 9 + 32].copy_from_slice(&hmac);

    let sig = compute_header_signature(&header[..SIGNED_LENGTH], sign_key);
    header[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE].copy_from_slice(&sig);

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

/// v5/v6 信封头部（2048 字节，2.8.0 起）：与 v4 的差异 ——
/// - 分区条目 96 → 192 字节：新增 60 字节 `wrapped_key`（nonce12 + ct32 + tag16）；
/// - 条目保留字段同样填充随机数（真实条目先整体随机再覆写结构化字段，
///   不给「保留区为 0」这类可区分标记留位置）；
/// - 锁定区移至 1642（106 + 8×192），签名覆盖 header[..1984] 并写在 1984..2048。
///
/// 3.0.0（v6）：头部布局与 v5 完全一致，版本字节参数化（5 或 6）。
pub(crate) fn write_header_envelope(
    file: &mut File,
    version: u8,
    lock_state: &LockState,
    salt: &[u8; 32],
    partitions: &[PartitionInfo],
    sign_key: &[u8; 32],
    yk_challenge_salt: &[u8; 32],
) -> Result<(), VaultError> {
    debug_assert!(matches!(version, VERSION_V5 | VERSION_V6));
    let mut header = [0u8; HEADER_SIZE_V5];

    header[..8].copy_from_slice(MAGIC);
    header[8] = version;
    // 3.0.0（审计锚点）：8 个分区槽的审计条目计数写入 41..73（签名覆盖范围内；
    // auth_tag 前缀按「该区全 0」的规范形合成，不受影响）
    for (i, p) in partitions.iter().take(MAX_PARTITIONS).enumerate() {
        let off = AUDIT_COUNT_OFFSET + i * 4;
        header[off..off + 4].copy_from_slice(&p.audit_count.to_le_bytes());
    }
    // 3.0.0（M-2）：硬件密钥挑战盐写入保留区 9..41（在签名覆盖范围内）。
    // 该盐不参与 auth_tag 前缀与包裹 AAD 的绑定（前缀按「保留区全 0」的规范形
    // 重建，语义不变），仅用于派生挑战。
    // 3.0.1（F19）：盐在 create 时随机生成一次、此后终生不变 —— 开柜路径
    // **禁止**轮换本盐（历史上轮换过一次即砖死二因子保险柜，见 session.rs）。
    header[YK_SALT_OFFSET..YK_SALT_OFFSET + 32].copy_from_slice(yk_challenge_salt);
    header[73..105].copy_from_slice(salt);
    header[105] = MAX_PARTITIONS as u8;

    let mut off = 106;
    for i in 0..MAX_PARTITIONS {
        let mut entry = [0u8; PARTITION_ENTRY_SIZE_V5];
        // 真实/伪条目统一先填随机：保留区不留可区分标记（与 v4 同一策略的延伸）
        OsRng.fill_bytes(&mut entry);
        if let Some(p) = partitions.get(i) {
            let alias_field = alias_field16(&p.alias);
            entry[..16].copy_from_slice(&alias_field);
            entry[16..48].copy_from_slice(&p.salt);
            entry[48..80].copy_from_slice(&p.auth_tag);
            entry[80..88].copy_from_slice(&p.index_offset.to_le_bytes());
            entry[88..96].copy_from_slice(&p.index_length.to_le_bytes());
            let wrapped = p
                .wrapped_key
                .ok_or_else(|| VaultError::Other("v5 分区条目缺少包裹密钥（内部错误）".into()))?;
            entry[96..96 + WRAPPED_KEY_SIZE].copy_from_slice(&wrapped);
            // 156..192 保留（已填随机）
        }
        header[off..off + PARTITION_ENTRY_SIZE_V5].copy_from_slice(&entry);
        off += PARTITION_ENTRY_SIZE_V5;
    }

    header[LOCK_OFFSET_V5] = lock_state.lock_count;
    header[LOCK_OFFSET_V5 + 1..LOCK_OFFSET_V5 + 9]
        .copy_from_slice(&lock_state.lock_until.to_le_bytes());
    let mac_key = derive_lock_mac_key(salt);
    let hmac = lock_state.compute_hmac(&mac_key);
    header[LOCK_OFFSET_V5 + 9..LOCK_OFFSET_V5 + 9 + 32].copy_from_slice(&hmac);

    // 2.8.2（M1）：签名按「锁区置零的规范形」计算 —— 锁区字节本身仍按
    // lock_state 写入文件，但签名只覆盖规范形（见 canonical_signed_bytes_v5）。
    // 会话内写入时锁区恒为零，规范形与实际字节一致；签名因此对失败尝试
    // 写锁区免疫，且任何其他字段的篡改/回滚都会破坏签名。
    let sig = {
        let canonical = canonical_signed_bytes_v5(&header);
        compute_header_signature(&canonical, sign_key)
    };
    header[SIGNATURE_OFFSET_V5..SIGNATURE_OFFSET_V5 + SIGNATURE_SIZE].copy_from_slice(&sig);

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

/// 按格式版本返回头部大小（碎片整理 / 升级管线的占位头部尺寸必须与之一致，
/// 否则 v4→v5 升级时 1024 字节占位会让 v5 头部覆写越界到数据区）。
pub(crate) fn header_size_of(version: u8) -> Result<usize, VaultError> {
    match version {
        VERSION_V4 => Ok(HEADER_SIZE_V4),
        VERSION_V5 | VERSION_V6 => Ok(HEADER_SIZE_V5),
        v => Err(VaultError::Other(format!("未知的保险柜格式版本: {}", v))),
    }
}

/// 校验**新录入**的分区别名（与 commands.rs 前端校验保持一致，供库级 API 直接调用时防护）。
///
/// 2.6.1 加固：字符集收紧为 ASCII-only。旧实现用 `char::is_alphanumeric()`，
/// 会放行 Latin/全角/阿拉伯等 Unicode 字母，产生两个问题：
/// - 别名会进入 16 字节头部字段并参与认证标签绑定，Unicode 同形字符
///   （如全角 "ａ" 与 ASCII "a"）可让不同分区在视觉上「看起来同名」，
///   诱导用户在错误的分区下操作；
/// - `alias.len()`（字节数）与 `alias_field16`（按字符截断）语义不一致，
///   多字节别名更易触及边界。
///
/// 输入侧一律只允许 `[A-Za-z0-9_- ]`。
pub(crate) fn is_valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && !alias.trim().is_empty()
        && alias.len() <= 16
        && alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ' ')
}

/// 解析**已有头部**时的宽松校验：只用于区分「真实分区条目」与「未初始化的
/// 伪条目（随机字节）」。
///
/// 不能收紧为 ASCII-only —— 旧版（≤2.5.1）允许创建非 ASCII 别名，收紧后这些
/// 合法旧保险柜的分区会被误判为伪条目而从 `self.partitions` 丢失，导致
/// 「内部错误：匹配分区丢失」或活动分区错位。
/// 这里保留旧的字符集语义（`is_alphanumeric` 等），随机字节经
/// `from_utf8_lossy` 后几乎必然含替换字符/控制字符而被排除。
pub(crate) fn is_plausible_alias(alias: &str) -> bool {
    !alias.is_empty()
        && !alias.trim().is_empty()
        && alias.len() <= 16
        && alias
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == ' ')
}

/// 别名的 16 字节头部字段（按字符截断，且**截断点必须落在字符边界上**）。
/// 2.7.1 修复：旧实现先按字符取 16 个、再按字节截断到 16 字节 —— 多字节字符
/// 会在字节中间被切断，重开时 `from_utf8_lossy` 产出 U+FFFD，该分区被
/// `is_plausible_alias` 误判为伪条目而消失（表现为「内部错误：匹配分区丢失」）。
/// 现按字符边界累加；ASCII 别名的字节序列与旧实现完全一致。
/// 与 [`write_header_to_file`] 写出的别名字段、以及 [`auth_tag_header_prefix`]
/// 绑定载荷所用字节完全一致。
pub(crate) fn alias_field16(alias: &str) -> [u8; 16] {
    let mut field = [0u8; 16];
    let mut n = 0usize;
    for c in alias.chars() {
        let len = c.len_utf8();
        if n + len > 16 {
            break;
        }
        c.encode_utf8(&mut field[n..]);
        n += len;
    }
    field
}

/// 2.6.1：头部绑定认证标签所用的「头部前缀」，与 `write_header_to_file` 写出的
/// `header[..105]` 逐字节一致：magic(8) || version(1) || 保留区(64, 全 0) || 保险柜 salt(32)。
/// 2.8.0：版本字节参数化（v4 前缀与历史格式逐字节一致）。
pub(crate) fn auth_tag_header_prefix(vault_salt: &[u8; 32], version: u8) -> [u8; 105] {
    let mut p = [0u8; 105];
    p[..8].copy_from_slice(MAGIC);
    p[8] = version;
    p[73..105].copy_from_slice(vault_salt);
    p
}

/// 计算某个分区条目的头部绑定认证标签。`entry_alias` 为已填充的 16 字节别名字段。
pub(crate) fn bound_auth_tag(
    auth_key: &[u8; 32],
    vault_salt: &[u8; 32],
    version: u8,
    entry_alias: &[u8; 16],
    entry_salt: &[u8; 32],
) -> [u8; 32] {
    let prefix = auth_tag_header_prefix(vault_salt, version);
    create_auth_tag_bound(auth_key, &prefix, entry_alias, entry_salt)
}

/// 2.8.0（v5）：包裹密钥的 AAD —— 域分隔 || 头部前缀(105) || 条目别名字段(16) || 条目盐(32)。
///
/// 把包裹体绑定到头部全局字段与该条目自身：调包两个分区的 wrapped_key、或
/// 篡改头部版本/salt 都会让解包失败（与 auth_tag 的绑定互相独立、互为备份）。
pub(crate) fn key_wrap_aad(
    header_prefix: &[u8; 105],
    entry_alias: &[u8],
    entry_salt: &[u8; 32],
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"LYNVAULT-KEY-WRAP-V5";
    let mut aad = Vec::with_capacity(DOMAIN.len() + 105 + 16 + 32);
    aad.extend_from_slice(DOMAIN);
    aad.extend_from_slice(header_prefix);
    aad.extend_from_slice(entry_alias);
    aad.extend_from_slice(entry_salt);
    aad
}

/// 2.8.2（M1）：v5 头部签名的**规范形** —— 计算签名前把锁定区字节（1642..1683）
/// 置零。锁定区位于签名范围（..1984）内，但创建时与会话内锁定区恒为零（失败
/// 尝试只发生在打开阶段，成功打开即重置锁区并全量重签），因此历史上所有合法
/// 签名都等于「锁区置零的规范形」签名。写入与校验共用此规范形：
/// - 失败尝试写锁区不再使签名失真（L4 的根治）；
/// - 签名范围内任何字段被篡改/回滚（含 index_offset/index_length —— 它们不在
///   auth_tag AAD、key_wrap AAD、锁区 HMAC 的任何覆盖范围内）都会破坏签名。
pub(crate) fn canonical_signed_bytes_v5(header: &[u8; HEADER_SIZE_V5]) -> Vec<u8> {
    let mut canonical = *header;
    canonical[LOCK_OFFSET_V5..LOCK_OFFSET_V5 + 41].fill(0);
    canonical[..SIGNED_LENGTH_V5].to_vec()
}

/// 2.8.0（v5）：恒定时间校验 v5 头部签名（覆盖 header[..1984]，签名在 1984..2048）。
/// 2.8.2（M1）：按「锁区置零的规范形」校验 —— 与 write_header_v5 的签名计算
/// 严格一致；仅用于「分区密码正确但索引校验失败」时的诊断取证，以及成功开柜
/// 路径的强制验签。
pub(crate) fn verify_header_signature_v5(
    header: &[u8; HEADER_SIZE_V5],
    sign_key: &[u8; 32],
) -> bool {
    let canonical = canonical_signed_bytes_v5(header);
    let computed = compute_header_signature(&canonical, sign_key);
    use subtle::ConstantTimeEq;
    computed
        .ct_eq(&header[SIGNATURE_OFFSET_V5..SIGNATURE_OFFSET_V5 + SIGNATURE_SIZE])
        .into()
}
