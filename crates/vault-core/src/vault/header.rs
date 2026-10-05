//! 头部格式层 —— 头部读写（v4/v5/v6）、解析、签名、认证标签绑定、别名字段。
//! 3.0.0 拆分自 vault.rs，逻辑逐字节不变。
//! 3.0.1（P0 #1 修复）：所有对**最终保险柜文件**的原地头部写入改经「日志边车」
//! （见 [`write_header_bytes_journaled`]）—— 单缓冲原地覆写在中途掉电/撕裂后
//! 签名与认证必失败且无冗余可恢复，是「无攻击者也砖化整柜」的唯一剩余项。
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;

use crate::crypto::*;
use crate::error::VaultError;
use crate::lock::LockState;

use super::consts::*;
use super::fs_util::sync_parent_dir;
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

/// 写入完整头部（含签名）—— 按格式版本分发（**直接写入**，仅适用于全新文件：
/// create 路径与碎片整理 / 升级管线的临时文件。对已存在保险柜的原地头部更新
/// 一律走 [`write_header_journaled`]，见其文档）。
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
        VERSION_V4 => write_header_bytes(
            file,
            &build_header_v4(lock_state, salt, partitions, sign_key),
        ),
        // v6 与 v5 头部同布局，仅版本字节不同（认证标签 / 包裹 AAD 按版本绑定）
        VERSION_V5 | VERSION_V6 => write_header_bytes(
            file,
            &build_header_envelope(
                version,
                lock_state,
                salt,
                partitions,
                sign_key,
                yk_challenge_salt,
            )?,
        ),
        v => Err(VaultError::Other(format!("未知的保险柜格式版本: {}", v))),
    }
}

/// 3.0.1（P0 #1 修复）：对**已存在的保险柜文件**做头部更新 —— 经日志边车
/// 防撕裂。旧实现 2 KiB 单缓冲在 offset 0 原地覆写，中途掉电/崩溃撕裂后
/// 签名与认证必失败且无冗余可恢复（改密 / save_index / 增删分区均触发，
/// 是「无攻击者也砖化整柜」的唯一路径）。
///
/// 三步协议（与索引 C3 修复同一思想，下沉到头部层）：
/// 1. 完整新头部快照写入边车日志（`.lyt.hdr.journal`，create_new + fsync +
///    目录 fsync）；
/// 2. 头部原地覆写 + fsync；
/// 3. 删除日志 + 目录 fsync。
///
/// 任意一步中断，下次打开由 [`recover_header_from_journal`] 收敛：
/// 日志完好 → 恢复或完成写入；日志撕裂 → 删除（头部要么已写完，要么日志
/// 本就无有效内容）。
#[allow(clippy::too_many_arguments)] // 与 write_header_to_file 保持同形签名
pub(crate) fn write_header_journaled(
    file: &mut File,
    vault_path: &Path,
    version: u8,
    lock_state: &LockState,
    salt: &[u8; 32],
    partitions: &[PartitionInfo],
    sign_key: &[u8; 32],
    yk_challenge_salt: &[u8; 32],
) -> Result<(), VaultError> {
    let header: Vec<u8> = match version {
        VERSION_V4 => build_header_v4(lock_state, salt, partitions, sign_key).to_vec(),
        VERSION_V5 | VERSION_V6 => build_header_envelope(
            version,
            lock_state,
            salt,
            partitions,
            sign_key,
            yk_challenge_salt,
        )?
        .to_vec(),
        v => return Err(VaultError::Other(format!("未知的保险柜格式版本: {}", v))),
    };
    write_header_bytes_journaled(file, vault_path, &header)
}

/// 头部边车日志路径（`<保险柜>.hdr.journal`）。
pub(crate) fn journal_path(vault_path: &Path) -> PathBuf {
    let mut s = vault_path.as_os_str().to_os_string();
    s.push(".hdr.journal");
    PathBuf::from(s)
}

/// 日志边车原子写入：create_new（不跟随链接）+ fsync + 目录 fsync。
/// 目标已存在（上一轮崩溃遗留的未恢复日志）→ 移除后重试一次 —— 新快照
/// 即将取代它，且打开路径已先于任何会话写入执行过恢复。
fn write_journal_atomic(jp: &Path, header: &[u8]) -> Result<(), VaultError> {
    let write_once = || -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
            opts.mode(0o600);
        }
        let mut f = opts.open(jp)?;
        f.write_all(header)?;
        f.sync_all()?;
        Ok(())
    };
    match write_once() {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(jp);
            write_once()?;
        }
        Err(e) => return Err(e.into()),
    }
    sync_parent_dir(jp);
    Ok(())
}

/// 头部字节经日志边车落盘（[`write_header_journaled`] 的字节层收口，
/// 亦供锁定区部分更新复用）。
pub(crate) fn write_header_bytes_journaled(
    file: &mut File,
    vault_path: &Path,
    header: &[u8],
) -> Result<(), VaultError> {
    debug_assert!(header.len() == HEADER_SIZE_V4 || header.len() == HEADER_SIZE_V5);
    let jp = journal_path(vault_path);
    write_journal_atomic(&jp, header)?;
    let write_result = (|| -> std::io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(header)?;
        file.flush()?;
        file.sync_all()
    })();
    if write_result.is_ok() {
        let _ = std::fs::remove_file(&jp);
        sync_parent_dir(vault_path);
    }
    // 写入失败时保留日志（下次打开恢复）；向上传播写入错误 —— 调用方的
    // 崩溃一致性约定（先写头部、成功后才提交内存）不因此改变
    write_result.map_err(VaultError::from)
}

/// 3.0.1（P0 #1 修复）：打开路径调用 —— 收敛上一次头部写入崩溃遗留的日志。
/// 须已持有独占句柄（open_vault_rw + lock_vault_exclusive 之后、任何读判定
/// 之前）。静默容错：任何失败都不阻塞打开（最坏保持现状，日志留给下次）。
pub(crate) fn recover_header_from_journal(file: &mut File, vault_path: &Path) {
    let jp = journal_path(vault_path);
    let Ok(data) = std::fs::read(&jp) else {
        return; // 无日志 = 常态
    };
    let size = data.len();
    // 日志必须是完整头部快照：长度与版本字节互相印证（防半截日志被当成
    // 有效头部恢复）
    let valid = (size == HEADER_SIZE_V4 || size == HEADER_SIZE_V5)
        && &data[..8] == MAGIC
        && matches!(data[8], VERSION_V4 | VERSION_V5 | VERSION_V6)
        && ((size == HEADER_SIZE_V4) == (data[8] == VERSION_V4));
    if !valid {
        // 撕裂的日志无恢复价值：头部要么已更新完成（原地写成功于日志之后），
        // 要么本就等不到有效快照 —— 删除避免永久滞留
        let _ = std::fs::remove_file(&jp);
        sync_parent_dir(vault_path);
        return;
    }
    // 文件本体短于头部：头部层无法修复（外部截断），清日志并放行
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if file_len < size as u64 {
        let _ = std::fs::remove_file(&jp);
        return;
    }
    // 与当前头部逐字节比对：一致 = 原地写已完成（仅日志删除失败遗留）→ 清理
    let mut current = vec![0u8; size];
    let same = file
        .seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut current))
        .is_ok()
        && current == data;
    if same {
        let _ = std::fs::remove_file(&jp);
        sync_parent_dir(vault_path);
        return;
    }
    // 不一致 = 原地写未完成 → 用完整快照恢复头部
    let restored = file
        .seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(&data))
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .is_ok();
    if restored {
        let _ = std::fs::remove_file(&jp);
    }
    // 恢复失败保留日志，下次打开重试
    sync_parent_dir(vault_path);
}

/// 3.0.1（P0 #1 修复）：锁定区部分更新（开柜失败计数 +1）同样经日志防撕裂
/// —— 41 字节小写撕裂同样破坏锁定区 HMAC，下次打开报「头部可能被篡改」。
/// 读全头部 → 内存补丁 → 全量日志协议。
pub(crate) fn write_lock_region_journaled(
    file: &mut File,
    vault_path: &Path,
    lock_offset: usize,
    lock_buf: &[u8; 41],
) -> Result<(), VaultError> {
    let header_size = if lock_offset == LOCK_OFFSET_V4 {
        HEADER_SIZE_V4
    } else {
        HEADER_SIZE_V5
    };
    let mut header = vec![0u8; header_size];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    header[lock_offset..lock_offset + 41].copy_from_slice(lock_buf);
    write_header_bytes_journaled(file, vault_path, &header)
}

/// 把构建好的头部字节直接写入文件 offset 0（全新文件专用，见
/// [`write_header_to_file`] 文档）。
fn write_header_bytes(file: &mut File, header: &[u8]) -> Result<(), VaultError> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(header)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

/// v4 头部构建（1024 字节）—— 与 2.x 历史格式逐字节一致。
pub(crate) fn build_header_v4(
    lock_state: &LockState,
    salt: &[u8; 32],
    partitions: &[PartitionInfo],
    sign_key: &[u8; 32],
) -> [u8; HEADER_SIZE_V4] {
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
    header
}

/// v5/v6 信封头部构建（2048 字节，2.8.0 起）：与 v4 的差异 ——
/// - 分区条目 96 → 192 字节：新增 60 字节 `wrapped_key`（nonce12 + ct32 + tag16）；
/// - 条目保留字段同样填充随机数（真实条目先整体随机再覆写结构化字段，
///   不给「保留区为 0」这类可区分标记留位置）；
/// - 锁定区移至 1642（106 + 8×192），签名覆盖 header[..1984] 并写在 1984..2048。
///
/// 3.0.0（v6）：头部布局与 v5 完全一致，版本字节参数化（5 或 6）。
pub(crate) fn build_header_envelope(
    version: u8,
    lock_state: &LockState,
    salt: &[u8; 32],
    partitions: &[PartitionInfo],
    sign_key: &[u8; 32],
    yk_challenge_salt: &[u8; 32],
) -> Result<[u8; HEADER_SIZE_V5], VaultError> {
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
    Ok(header)
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
