use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use serde_json;
use zeroize::{Zeroize, Zeroizing};

use crate::audit::AuditLog;
use crate::crypto::*;
use crate::error::VaultError;
use crate::index::{FileMeta, Index, IndexManager};
use crate::lock::LockState;
use crate::wipe::{dod_erase, dod_overwrite_range, secure_wipe_vec};

// --- 常量 ---
const MAGIC: &[u8; 8] = b"PYVAULT4";
/// v4 格式（1024 字节头部，会话密钥直接由口令派生）
const VERSION_V4: u8 = 4;
/// v5 格式（2.8.0：信封加密 —— 随机 data_key 由口令包裹存储于头部，
/// 修改口令只需重写头部，数据零接触）
const VERSION_V5: u8 = 5;
const HEADER_SIZE_V4: usize = 1024;
const HEADER_SIZE_V5: usize = 2048;
const MAX_PARTITIONS: usize = 8;
const PARTITION_ENTRY_SIZE_V4: usize = 96;
const PARTITION_ENTRY_SIZE_V5: usize = 192;
const LOCK_OFFSET_V4: usize = 887;
/// v5 头部：106 + 8×192 = 1642
const LOCK_OFFSET_V5: usize = 1642;
/// v5 头部签名覆盖 header[..1984]，签名本体位于 1984..2048
const SIGNED_LENGTH_V5: usize = 1984;
const SIGNATURE_OFFSET_V5: usize = 1984;
/// v5 分区条目中的包裹密钥字段：nonce(12) + data_key 密文(32) + GCM tag(16)
const WRAPPED_KEY_SIZE: usize = 60;

/// LynVault 文件 magic bytes（8 字节），用于启动扫描时识别真正的保险柜文件
pub const VAULT_MAGIC: &[u8; 8] = MAGIC;

/// 快速检查文件是否为 LynVault 保险柜（仅读取并比对头部 8 字节 magic）。
/// 任何 I/O 错误或 magic 不匹配都返回 false（不暴露具体错误）。
pub fn is_vault_file(path: &Path) -> bool {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = [0u8; 8];
    match f.read_exact(&mut buf) {
        Ok(_) => &buf == VAULT_MAGIC,
        Err(_) => false,
    }
}

/// 2.8.0：完整性体检的单个异常条目
#[derive(Debug, Clone, serde::Serialize)]
pub struct IntegrityIssue {
    pub vpath: String,
    pub reason: String,
}

/// 2.8.0：搜索结果条目
#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchHit {
    pub vpath: String,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

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
        VERSION_V5 => LOCK_OFFSET_V5,
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
    if !lock_until.is_finite() { lock_until = 0.0; }
    let lock_state = LockState {
        lock_count: buf[0],
        lock_until,
        lock_until_monotonic: None,
    };
    let mac_key = derive_lock_mac_key(&salt);
    if !lock_state.verify_hmac(&mac_key, &buf[9..41].try_into().unwrap()) {
        return Err(VaultError::Other("头部锁定区校验失败 —— 头部可能被篡改".into()));
    }
    Ok(LockInfo {
        failed_count: lock_state.lock_count,
        locked: lock_state.is_locked(),
        lock_until_epoch: lock_state.lock_until,
    })
}

/// 2.6.1 新增：以「读写 + 独占访问」打开保险柜文件。
///
/// 旧实现直接用 `OpenOptions::read/write` 打开，两个实例（或同进程两次打开）可
/// 同时对同一保险柜写入，头部与索引会互相覆盖、损坏。
/// Windows：以 `FILE_SHARE_READ` 共享模式打开 —— 仍允许只读读取（例如
/// `is_vault_file` 的 magic 探测、杀软扫描），但拒绝其他任何**写**打开，从文件
/// 句柄层面排除并发写（纯 std，无需额外依赖）。
/// Unix 侧由 [`lock_vault_exclusive`] 的 `flock` 提供同等保证。
///
/// 2.7.1 加固：打开阶段即拒绝符号链接 / 重解析点 —— 带
/// `FILE_FLAG_OPEN_REPARSE_POINT` / `O_NOFOLLOW` 打开，并用句柄元数据确认。
/// 销毁路径（`Vault::destroy`）全程复用会话句柄，防护因此不再有「按路径重开」
/// 的削弱窗口。
fn open_vault_rw(path: &Path, create: bool) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);
    if create {
        opts.create(true).truncate(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.share_mode(FILE_SHARE_READ).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    // 句柄级确认：重解析点（含符号链接）一律拒绝 —— 打开必然锚定文件本体
    #[cfg(windows)]
    {
        verify_no_reparse(&file)?;
    }
    Ok(file)
}

/// 2.8.2.1：句柄级确认「不是符号链接」。
///
/// 2.8.2 首版曾扩大为「拒绝一切重解析点」（检查 FILE_ATTRIBUTE_REPARSE_POINT
/// 位），但 OneDrive / 云同步的按需占位文件（IO_REPARSE_TAG_CLOUD 系列）即使
/// 已水合也保留 reparse 属性 —— 同步目录中的合法保险柜被全部误伤（发布当日
/// 兼容性回归）。现恢复 2.8.1 行为：仅拒绝符号链接；打开标志
/// FILE_FLAG_OPEN_REPARSE_POINT 保留（锚定文件本体）。
#[cfg(windows)]
fn verify_no_reparse(file: &File) -> std::io::Result<()> {
    if file.metadata()?.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "拒绝通过符号链接打开保险柜文件",
        ));
    }
    Ok(())
}

/// 2.7.1 新增：以 create_new 语义独占创建保险柜文件（目标已存在时失败，
/// 绝不清零已有内容）。打开标志与 [`open_vault_rw`] 完全一致。
fn open_vault_create_new(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.share_mode(FILE_SHARE_READ).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

/// 2.6.1 新增：取得保险柜文件的独占锁，防止双实例并发写坏头部/索引。
/// - Unix：`flock(LOCK_EX | LOCK_NB)`，非阻塞；锁随文件句柄关闭自动释放。
/// - Windows：由 [`open_vault_rw`] 的共享模式保证，此处为空操作。
/// 返回 `Err` 表示文件已被其他实例独占占用。
#[cfg(unix)]
fn lock_vault_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn lock_vault_exclusive(_file: &File) -> std::io::Result<()> {
    Ok(())
}

// 签名范围仅到 lock_offset 之前；锁定区由自身 HMAC 保护，
// 每次认证失败都会修改锁定区，若包含在签名中会导致后续认证因签名不匹配而失败。
// 2.7.1：常量单一来源收敛到 crypto.rs（本文件经 `use crate::crypto::*` 导入）

const DEFAULT_PARTITION: &str = "Main";

/// 自动整理阈值:删除类操作后,死空间(已被安全擦除但仍占位的区域)同时满足
/// 「绝对值 ≥ 64 MiB」与「占文件大小 ≥ 30%」时,自动执行一次紧凑整理。
/// 仅单分区保险柜启用 —— 多分区整理不回收空间(其他分区数据位置未知,不能
/// 截断文件),自动执行没有收益。
const AUTO_DEFRAG_MIN_DEAD_BYTES: u64 = 64 * 1024 * 1024;
/// 30% 用整数运算表示(3/10),避免浮点比较的边界误差
const AUTO_DEFRAG_DEAD_RATIO_NUM: u64 = 3;
const AUTO_DEFRAG_DEAD_RATIO_DEN: u64 = 10;

/// 单次操作中内存缓冲区的上限（256 MiB）。
/// 超过此大小的文件改用流式读写，避免 OOM（M1 修复）。
const MAX_INMEM_BUFFER: usize = 256 * 1024 * 1024;
const MAX_IMPORT_DEPTH: usize = 64;
const MAX_IMPORT_ENTRIES: usize = 100_000;

// ─────────── 自由函数：避免 &mut self 借用冲突 ───────────

/// 从文件读取并解密索引
fn load_index_from_file(
    file: &mut File,
    enc_key: &[u8; 32],
    offset: u64,
    length: u64,
) -> Result<Index, VaultError> {
    // 2.3.0 修复：索引长度上限校验，防止恶意头部（溢出绕过边界检查后）触发超大分配
    if length > MAX_INMEM_BUFFER as u64 {
        return Err(VaultError::Other(format!(
            "索引数据过大（{} 字节），超过单次加载上限", length
        )));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut enc = vec![0u8; length as usize];
    file.read_exact(&mut enc)?;
    let plain = decrypt_gcm(enc_key, &enc, b"index").ok_or(VaultError::DecryptFailed)?;
    let index: Index = serde_json::from_slice(&plain)?;
    secure_wipe_vec(plain);
    Ok(index)
}

/// 加密索引并追加写入，返回 (new_offset, new_length)。
///
/// C3 修复（关键）：旧实现的写入顺序是
///   1. 写新索引到末尾
///   2. 用随机数据覆写旧索引
///   3. （save_index 调用 update_header）更新头部偏移
///
/// 在第 2 步与第 3 步之间崩溃，头部仍指向已被随机数据覆盖的旧索引位置，
/// 下次打开会因 DecryptFailed 永久锁定。
///
/// 新顺序：
///   1. 写新索引到末尾
///   2. 更新头部偏移指向新索引（旧索引位置暂存）
///   3. 擦除旧索引（此时即使崩溃，新索引已可由头部定位，旧索引只是垃圾）
///
/// 由于头部更新在本函数内无法完成（需要 &mut self 全字段），
/// 此处返回 new_off/new_len，由 save_index 协调顺序。
/// 2.7.1：移除已弃用的 old_offset/old_length 参数（擦除由调用方在头部更新后
/// 经 wipe_old_index_range 完成，本函数从未使用过这两个参数）。
fn save_index_to_file(
    file: &mut File,
    enc_key: &[u8; 32],
    index: &Index,
) -> Result<(u64, u64), VaultError> {
    let plain = serde_json::to_vec(index)?;
    let encrypted = encrypt_gcm(enc_key, &plain, b"index", None)?;

    // 步骤 1：新索引写入文件末尾
    let new_offset = file.seek(SeekFrom::End(0))?;
    file.write_all(&encrypted)?;
    file.flush()?;
    file.sync_all()?;

    // 注意：旧索引的擦除推迟到 save_index 完成 update_header 之后，
    // 以保证头部偏移先于旧索引擦除被持久化（C3 修复）。

    secure_wipe_vec(plain);
    Ok((new_offset, encrypted.len() as u64))
}

/// 在头部已更新后擦除旧索引区段。
/// 即使此步失败，新索引已可由头部偏移定位，不影响正确性。
fn wipe_old_index_range(file: &mut File, old_offset: u64, old_length: u64) {
    if old_length == 0 {
        return;
    }
    // 用 DoD 7-pass 擦除（C7 修复：旧索引含明文 size/路径元数据）
    if let Err(e) = dod_overwrite_range(file, old_offset, old_length) {
        log::warn!("擦除旧索引失败（不影响正确性）: {}", e);
    }
    let _ = file.flush();
}

/// 跨文件流式拷贝（2.4.1 碎片整理紧凑迁移用）。
/// 源/目标为不同文件，天然无单文件自拷贝的重叠破坏风险。
fn copy_between(
    src: &mut File,
    dst: &mut File,
    src_off: u64,
    dst_off: u64,
    len: u64,
) -> std::io::Result<()> {
    const CHUNK: usize = 1024 * 1024;
    let mut buf = vec![0u8; CHUNK];
    let mut remaining = len;
    let mut s = src_off;
    let mut d = dst_off;
    while remaining > 0 {
        let n = remaining.min(CHUNK as u64) as usize;
        src.seek(SeekFrom::Start(s))?;
        src.read_exact(&mut buf[..n])?;
        dst.seek(SeekFrom::Start(d))?;
        dst.write_all(&buf[..n])?;
        s += n as u64;
        d += n as u64;
        remaining -= n as u64;
    }
    Ok(())
}

/// 同步父目录，确保重命名持久化。Windows 上无法用 File::open 打开目录，
/// 需 FILE_FLAG_BACKUP_SEMANTICS；失败时仅记录日志（尽力而为）。
fn sync_parent_dir(path: &Path) {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return,
    };
    #[cfg(unix)]
    {
        let _ = File::open(parent).and_then(|d| d.sync_all());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // 0x02000000 = FILE_FLAG_BACKUP_SEMANTICS（允许以目录句柄打开）
        if let Ok(d) = OpenOptions::new().read(true).custom_flags(0x02000000).open(parent) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = File::open(parent).and_then(|d| d.sync_all());
    }
}

/// 2.7.1 新增：查询路径所在卷的可用空间（碎片整理预检用）。
/// Windows：GetDiskFreeSpaceExW；Unix：statvfs；其他平台返回 u64::MAX（跳过预检）。
fn disk_free_bytes(dir: &Path) -> std::io::Result<u64> {
    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let wide: Vec<u16> = dir
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut free: u64 = 0;
        unsafe {
            GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), Some(&mut free), None, None)
        }
        .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(free)
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(dir.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "路径包含空字节"))?;
        let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut vfs) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(vfs.f_bavail as u64 * vfs.f_frsize as u64)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = dir;
        Ok(u64::MAX)
    }
}

/// 2.7.1 新增：碎片整理中间副本（.tmp/.bak）统一「先 DoD 擦除再删除」——
/// 直接 remove_file 会把可恢复的保险柜内容残留在磁盘上。擦除失败时仍尽力
/// 移除（避免残留占位），失败仅记日志。
fn wipe_scratch_file(path: &Path) {
    if !path.exists() {
        return;
    }
    if let Err(e) = dod_erase(path, None) {
        log::warn!("擦除碎片整理中间文件失败（将尝试直接删除）: {}", e);
        let _ = fs::remove_file(path);
    }
}

/// 2.7.1 修复：用临时文件替换保险柜本体，同时保留原文件的安全属性。
/// 旧实现 `fs::rename` 后保险柜变成新建的临时文件对象，属性/ACL 改为目录继承
/// —— 用户为 `.lyt` 单独设置的「仅本人可访问」静默失效。
/// - Windows：`ReplaceFileW`（替换内容同时保留被替换文件的安全描述符 / 属性 /
///   创建时间），不支持时（旧系统 / 特殊文件系统）回退 rename；
/// - Unix：rename 后把原文件的权限位还原到新文件。
fn replace_vault_file(temp: &Path, dest: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        match replace_file_windows(temp, dest) {
            Ok(()) => return Ok(()),
            Err(e) => {
                log::warn!("ReplaceFileW 替换失败，回退 rename: {}", e);
            }
        }
    }
    #[cfg(unix)]
    let old_perms = fs::metadata(dest).ok().map(|m| m.permissions());
    fs::rename(temp, dest)?;
    #[cfg(unix)]
    if let Some(perms) = old_perms {
        let _ = fs::set_permissions(dest, perms);
    }
    Ok(())
}

/// Windows：ReplaceFileW 替换（保留安全描述符/属性/创建时间）。
/// 调用方需已释放对目标文件的所有句柄（替换式操作需取得 DELETE 访问权）。
#[cfg(windows)]
fn replace_file_windows(temp: &Path, dest: &Path) -> std::io::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        ReplaceFileW, REPLACE_FILE_FLAGS,
        REPLACEFILE_IGNORE_MERGE_ERRORS, REPLACEFILE_WRITE_THROUGH,
    };
    fn to_wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }
    let dest_w = to_wide(dest);
    let temp_w = to_wide(temp);
    unsafe {
        ReplaceFileW(
            PCWSTR(dest_w.as_ptr()),
            PCWSTR(temp_w.as_ptr()),
            PCWSTR::null(), // 不保留备份文件（备份由整理流程自行管理）
            REPLACE_FILE_FLAGS(REPLACEFILE_WRITE_THROUGH.0 | REPLACEFILE_IGNORE_MERGE_ERRORS.0),
            None,
            None,
        )
    }
    .map_err(|e| std::io::Error::other(e.to_string()))
}

/// 写入完整头部（含签名）—— 按格式版本分发。
fn write_header_to_file(
    file: &mut File,
    version: u8,
    lock_state: &LockState,
    salt: &[u8; 32],
    partitions: &[PartitionInfo],
    sign_key: &[u8; 32],
) -> Result<(), VaultError> {
    match version {
        VERSION_V4 => write_header_v4(file, lock_state, salt, partitions, sign_key),
        VERSION_V5 => write_header_v5(file, lock_state, salt, partitions, sign_key),
        v => Err(VaultError::Other(format!("未知的保险柜格式版本: {}", v))),
    }
}

/// v4 头部（1024 字节）—— 与 2.x 历史格式逐字节一致。
fn write_header_v4(
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

/// v5 头部（2048 字节，2.8.0）：与 v4 的差异 ——
/// - 分区条目 96 → 192 字节：新增 60 字节 `wrapped_key`（nonce12 + ct32 + tag16）；
/// - 条目保留字段同样填充随机数（真实条目先整体随机再覆写结构化字段，
///   不给「保留区为 0」这类可区分标记留位置）；
/// - 锁定区移至 1642（106 + 8×192），签名覆盖 header[..1984] 并写在 1984..2048。
fn write_header_v5(
    file: &mut File,
    lock_state: &LockState,
    salt: &[u8; 32],
    partitions: &[PartitionInfo],
    sign_key: &[u8; 32],
) -> Result<(), VaultError> {
    let mut header = [0u8; HEADER_SIZE_V5];

    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION_V5;
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
            let wrapped = p.wrapped_key.ok_or_else(|| {
                VaultError::Other("v5 分区条目缺少包裹密钥（内部错误）".into())
            })?;
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
fn header_size_of(version: u8) -> Result<usize, VaultError> {
    match version {
        VERSION_V4 => Ok(HEADER_SIZE_V4),
        VERSION_V5 => Ok(HEADER_SIZE_V5),
        v => Err(VaultError::Other(format!("未知的保险柜格式版本: {}", v))),
    }
}

/// 解密文件数据时应使用的 AAD。
///
/// 优先用索引里冻结的 `aad_tag`（导入时的 vpath）；旧索引没有该字段时回退到
/// 当前 vpath —— 与修复前的历史行为完全一致，保证存量保险柜不受影响。
fn aad_bytes<'a>(frozen: Option<&'a str>, vpath: &'a str) -> &'a [u8] {
    frozen.unwrap_or(vpath).as_bytes()
}

/// 从保险柜文件读取并解密原始数据
/// `aad` 必须与加密时使用的值一致（用 `aad_bytes` 求值：优先 aad_tag，回退 vpath）
fn read_decrypt_file_data(
    file: &mut File,
    enc_key: &[u8; 32],
    offset: u64,
    length: u64,
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let file_len = file.metadata()?.len();
    let end = offset.checked_add(length)
        .ok_or_else(|| VaultError::Other("文件数据范围溢出".into()))?;
    if end > file_len || length > MAX_INMEM_BUFFER as u64 {
        return Err(VaultError::Other("文件数据超出安全读取范围".into()));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut enc_data = vec![0u8; length as usize];
    file.read_exact(&mut enc_data)?;
    // 2.8.2：改用就地解密（decrypt_into 缓冲复用）—— 热路径（读文件/预览/
    // 提取/体检）省一份全尺寸分配；解密失败时缓冲随 drop 释放（密文非敏感）。
    decrypt_into(enc_key, enc_data, aad).ok_or(VaultError::DecryptFailed)
}

/// 安全文件名清理
/// 2.4.1 变更：由「白名单」改为「黑名单」策略 —— 仅剔除路径危险字符与控制字符，
/// 保留 Unicode 字符与常见符号（!@#$%^& 等）。旧白名单会把 `report#1.txt`
/// 静默改名为 `report1.txt`，批量提取时引发大量「目标已存在」失败。
/// 仍然处理：结尾 '.'/' '（Windows 规范化）、保留设备名（CON/NUL/COM1..）。
fn sanitize_filename(name: &str) -> String {
    let mut safe: String = name
        .chars()
        .filter(|c| {
            let cu = *c as u32;
            // 控制字符与 DEL 剔除；路径分隔符与 Windows 保留字符剔除
            cu >= 0x20 && cu != 0x7f
                && !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
        .collect();
    while safe.ends_with('.') || safe.ends_with(' ') {
        safe.pop();
    }
    let upper = safe.to_uppercase();
    // Windows 保留设备名检查：主名（去掉最后一个扩展名）匹配即视为保留。
    // 旧实现只比对完整名，`CON.txt` 不会被加前缀，提取到 Windows 即创建失败。
    let stem = match upper.rfind('.') {
        Some(pos) => &upper[..pos],
        None => upper.as_str(),
    };
    if matches!(stem,
        "CON" | "PRN" | "AUX" | "NUL"
        | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
        | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9")
    {
        safe.insert(0, '_');
    }
    if safe.is_empty() { "extracted_file".to_string() } else { safe }
}

/// Windows：源文件名为保留设备名（CON/NUL/COM1… 及其带扩展名形式）时，
/// 普通 Win32 路径的打开请求会被路径归一化重写到设备本身 —— 读到的是
/// 控制台/空设备（表现为「函数不正确」错误或读取挂起），而非磁盘上的真实
/// 文件。此类文件可由 msys/WSL/`\\?\` 路径合法创建，导入时需改用 verbatim
/// （`\\?\`）路径打开以禁用重写；其余文件维持原路径不变。
#[cfg(windows)]
fn open_import_source(src_path: &Path) -> std::io::Result<File> {
    const RESERVED_STEMS: &[&str] = &[
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let is_reserved = src_path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| {
            let upper = n.to_uppercase();
            let stem = match upper.rfind('.') { Some(p) => &upper[..p], None => upper.as_str() };
            RESERVED_STEMS.contains(&stem)
        });
    if !is_reserved {
        return File::open(src_path);
    }
    let as_str = match src_path.as_os_str().to_str() {
        Some(s) if src_path.is_absolute() && !s.starts_with(r"\\?\") => s,
        _ => return File::open(src_path),
    };
    // 本地绝对路径 → \\?\C:\...；UNC → \\?\UNC\server\share\...
    let verbatim = if let Some(rest) = as_str.strip_prefix(r"\\") {
        format!(r"\\?\UNC\{}", rest)
    } else {
        format!(r"\\?\{}", as_str)
    };
    match File::open(Path::new(&verbatim)) {
        Ok(f) => Ok(f),
        // verbatim 打开失败（非常规路径形式等）→ 退回普通打开，保持原错误语义
        Err(_) => File::open(src_path),
    }
}

#[cfg(not(windows))]
fn open_import_source(src_path: &Path) -> std::io::Result<File> {
    File::open(src_path)
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
fn is_valid_alias(alias: &str) -> bool {
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
fn is_plausible_alias(alias: &str) -> bool {
    !alias.is_empty()
        && !alias.trim().is_empty()
        && alias.len() <= 16
        && alias
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == ' ')
}

/// 判断 `child` 是否位于 `base` 目录之下（提取时的路径遍历防护）。
///
/// Windows 文件系统大小写不敏感，而 `Path::starts_with` 是**逐组件、大小写敏感**
/// 的比较：`prepare_dest_root` 经 `canonicalize` 得到的大小写与用户传入的可能不同，
/// 直接把两者做 `starts_with` 会把合法路径误判为越界。这里在 Windows 上改为
/// 逐组件、大小写不敏感比较（只在 `base` 的组件数范围内比较，避免 `C:\a` 误配
/// `C:\ab` 这类字符串前缀假阳性）；其他平台保持原生逐组件比较。
fn path_within(child: &Path, base: &Path) -> bool {
    #[cfg(windows)]
    {
        let mut child_comps = child.components();
        for base_comp in base.components() {
            match child_comps.next() {
                Some(c)
                    if c.as_os_str()
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&base_comp.as_os_str().to_string_lossy()) =>
                {
                    continue;
                }
                _ => return false,
            }
        }
        true
    }
    #[cfg(not(windows))]
    {
        child.starts_with(base)
    }
}

/// 别名的 16 字节头部字段（按字符截断，且**截断点必须落在字符边界上**）。
/// 2.7.1 修复：旧实现先按字符取 16 个、再按字节截断到 16 字节 —— 多字节字符
/// 会在字节中间被切断，重开时 `from_utf8_lossy` 产出 U+FFFD，该分区被
/// `is_plausible_alias` 误判为伪条目而消失（表现为「内部错误：匹配分区丢失」）。
/// 现按字符边界累加；ASCII 别名的字节序列与旧实现完全一致。
/// 与 [`write_header_to_file`] 写出的别名字段、以及 [`auth_tag_header_prefix`]
/// 绑定载荷所用字节完全一致。
fn alias_field16(alias: &str) -> [u8; 16] {
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
fn auth_tag_header_prefix(vault_salt: &[u8; 32], version: u8) -> [u8; 105] {
    let mut p = [0u8; 105];
    p[..8].copy_from_slice(MAGIC);
    p[8] = version;
    p[73..105].copy_from_slice(vault_salt);
    p
}

/// 计算某个分区条目的头部绑定认证标签。`entry_alias` 为已填充的 16 字节别名字段。
fn bound_auth_tag(
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
fn key_wrap_aad(header_prefix: &[u8; 105], entry_alias: &[u8], entry_salt: &[u8; 32]) -> Vec<u8> {
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
fn canonical_signed_bytes_v5(header: &[u8; HEADER_SIZE_V5]) -> Vec<u8> {
    let mut canonical = header.clone();
    canonical[LOCK_OFFSET_V5..LOCK_OFFSET_V5 + 41].fill(0);
    canonical[..SIGNED_LENGTH_V5].to_vec()
}

/// 2.8.0（v5）：恒定时间校验 v5 头部签名（覆盖 header[..1984]，签名在 1984..2048）。
/// 2.8.2（M1）：按「锁区置零的规范形」校验 —— 与 write_header_v5 的签名计算
/// 严格一致；仅用于「分区密码正确但索引校验失败」时的诊断取证，以及成功开柜
/// 路径的强制验签。
fn verify_header_signature_v5(header: &[u8; HEADER_SIZE_V5], sign_key: &[u8; 32]) -> bool {
    let canonical = canonical_signed_bytes_v5(header);
    let computed = compute_header_signature(&canonical, sign_key);
    use subtle::ConstantTimeEq;
    computed
        .ct_eq(&header[SIGNATURE_OFFSET_V5..SIGNATURE_OFFSET_V5 + SIGNATURE_SIZE])
        .into()
}

// ─────────────────────────────────────────────────────────────

/// 保险柜主体
#[derive(Default)]
pub struct Vault {
    pub(crate) path: Option<PathBuf>,
    pub(crate) file: Option<File>,

    pub(crate) enc_key: Option<[u8; 32]>,
    pub(crate) auth_key: Option<[u8; 32]>,
    pub(crate) sign_key: Option<[u8; 32]>,

    /// 2.8.0（v5）：保险柜文件格式版本（4 = 旧格式兼容，5 = 信封加密）。
    /// 仅在会话建立后有意义的元数据；未打开时为 0。
    pub(crate) format_version: u8,
    /// 2.8.0（v5）：当前分区的随机数据密钥（口令包裹层之下的真正密钥）。
    /// v4 会话为 None。修改口令时以它为锚 —— 数据密钥不变，只换包裹。
    pub(crate) data_key: Option<[u8; 32]>,

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
}

impl Vault {
    /// 2.4.1 新增：写审计并置脏标记（统一入口）。
    /// 旧实现审计在各处手动 add，close() 无条件全量重写索引以持久化审计；
    /// 现在只有 audit_dirty=true 时 close() 才补一次 save_index。
    /// 2.8.2（L13）：审计消息可能含攻击者可控的 vpath —— 入库前把控制字符
    /// 替换为 '?' 并截断到 200 字符，防止伪造审计条目结构 / 超长条目膨胀索引。
    pub(crate) fn log_event(&mut self, msg: &str) {
        let sanitized: String = msg
            .chars()
            .map(|c| {
                let cu = c as u32;
                if cu < 0x20 || cu == 0x7f { '?' } else { c }
            })
            .take(200)
            .collect();
        if let Some(ref mut audit) = self.audit {
            audit.add(&sanitized);
        }
        self.audit_dirty = true;
    }

    // ═══════════════ 创建 ═══════════════

    /// 2.4.1 变更：创建后直接建立会话（P2-20 优化）。
    /// 旧流程「create → 立刻 open_and_authenticate」要对刚写完的文件
    /// 再跑 8 次 Argon2id（约 1 秒）。现在 create 成功即进入已解锁状态，
    /// 全程只派生 1 组密钥。返回后调用方无需再次认证。
    pub fn create(
        &mut self,
        path: &Path,
        password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<(), VaultError> {
        // 2.4.1 修复：按字符数而非字节数校验（旧实现 4 个汉字即通过）
        if password.chars().count() < 12 {
            return Err(VaultError::Other("密码长度至少 12 位".into()));
        }
        if self.is_open() {
            return Err(VaultError::AlreadyOpen);
        }

        // 2.7.1 修复（检查-再清零竞态）：旧实现先 is_vault_file 检查再以 create+truncate
        // 打开，两步之间目标文件可能被替换 —— 检查失效时直接把另一个保险柜清零且
        // 不可恢复。现改为 **create_new 优先**：目标已存在时不会被清零；确认
        // 「已存在且非保险柜」（用户已在保存对话框确认覆盖普通文件）后才以
        // create+truncate 重开。
        let mut file = match open_vault_create_new(path) {
            Ok(f) => f,
            Err(e) => {
                // create_new 失败：区分「已存在」与目录 / 权限等
                if let Ok(meta) = fs::metadata(path) {
                    if meta.is_dir() {
                        return Err(VaultError::Other("目标路径是目录，无法创建保险柜".into()));
                    }
                }
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(e.into());
                }
                if is_vault_file(path) {
                    return Err(VaultError::Other(
                        "目标路径已存在一个保险柜文件，拒绝覆盖（请选择其他位置或先手动删除）".into(),
                    ));
                }
                // 已存在且非保险柜的普通文件：UI 保存对话框已让用户显式确认覆盖。
                // 2.8.1（TOCTOU 收口）：旧实现 create+truncate 重开，「确认-重开」
                // 窗口内目标仍可能被换成保险柜文件而被清零。现在以**不截断**方式
                // 打开，用**同一句柄**验证 magic 后才 set_len(0) —— 打开与确认
                // 锚定同一文件对象，窗口关闭（句柄打开即锚定，无路径重开）。
                #[allow(clippy::suspicious_open_options)] // 截断延迟到 magic 验证后，见上
                {
                    let mut opts = OpenOptions::new();
                    opts.read(true).write(true).create(true);
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::OpenOptionsExt;
                        const FILE_SHARE_READ: u32 = 0x0000_0001;
                        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                        opts.share_mode(FILE_SHARE_READ).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        opts.custom_flags(libc::O_NOFOLLOW);
                    }
                    opts.open(path)?
                }
            }
        };
        // 2.8.1：覆盖路径用同一句柄验证目标确实不是保险柜后才截断清零
        //（create_new 成功的新文件此处读到 EOF，直接放行）
        {
            use std::io::Read;
            let file_len = file.metadata()?.len();
            if file_len >= 8 {
                file.seek(SeekFrom::Start(0))?;
                let mut magic = [0u8; 8];
                file.read_exact(&mut magic)?;
                if &magic == MAGIC {
                    return Err(VaultError::Other(
                        "目标路径已存在一个保险柜文件，拒绝覆盖（请选择其他位置或先手动删除）".into(),
                    ));
                }
            }
            // 2.8.2：硬链接别名防护 —— 句柄锚定防住了「确认后被换成保险柜」，
            // 但防不住「普通文件是受害者文件的硬链接」：set_len(0) + 后续写入
            // 作用在共享 inode 上，会把用户从未同意覆盖的另一个链接目标清零。
            #[cfg(windows)]
            {
                use std::os::windows::io::AsRawHandle;
                use windows::Win32::Foundation::HANDLE;
                use windows::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
                let mut info = BY_HANDLE_FILE_INFORMATION::default();
                let ok = unsafe {
                    GetFileInformationByHandle(HANDLE(file.as_raw_handle() as isize), &mut info)
                };
                if ok.is_ok() && info.nNumberOfLinks > 1 {
                    return Err(VaultError::Other(
                        "目标文件存在多个硬链接，拒绝覆盖（请先删除其他链接或选择其他位置）".into(),
                    ));
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if file.metadata()?.nlink() > 1 {
                    return Err(VaultError::Other(
                        "目标文件存在多个硬链接，拒绝覆盖（请先删除其他链接或选择其他位置）".into(),
                    ));
                }
            }
            file.set_len(0)?;
            file.seek(SeekFrom::End(0))?;
        }
        // 2.6.1：创建即为独占会话，避免与另一实例并发写同一文件
        lock_vault_exclusive(&file)
            .map_err(|_| VaultError::Other("保险柜文件已被另一个实例占用".into()))?;
        file.write_all(&[0u8; HEADER_SIZE_V5])?;
        file.flush()?;

        // ── 2.8.0（v5 信封加密）──
        // 随机 data_key 承担真正的加密职责；口令只负责「包裹」它存进头部。
        // 修改口令 = 换盐重新包裹 + 重写头部，数据一个字节不动。
        // 2.8.1：data_key/kek 用 Zeroizing —— expand_keys 派生失败的 `?` 早退
        // 路径上随机 data_key 不再以明文残留（数组没有 Drop，旧实现靠不到）。
        let mut vault_salt = [0u8; 32];
        OsRng.fill_bytes(&mut vault_salt);
        let mut dk_buf = [0u8; 32];
        OsRng.fill_bytes(&mut dk_buf);
        let data_key = Zeroizing::new(dk_buf);
        let mut keys = expand_keys(&data_key)?;

        let mut part_salt = [0u8; 32];
        OsRng.fill_bytes(&mut part_salt);
        let kek = Zeroizing::new(derive_kek(password, key_file_data, &part_salt)?);
        let alias_field = alias_field16(DEFAULT_PARTITION);
        let wrap_aad = key_wrap_aad(
            &auth_tag_header_prefix(&vault_salt, VERSION_V5),
            &alias_field,
            &part_salt,
        );
        let wrapped_v = encrypt_gcm(&kek, &data_key[..], &wrap_aad, None)?;
        let mut wrapped = [0u8; WRAPPED_KEY_SIZE];
        wrapped.copy_from_slice(&wrapped_v);
        drop(kek);
        secure_wipe_vec(wrapped_v);

        // 2.6.1：认证标签绑定头部（含保险柜 salt 与本条目别名字段），
        // 消除多分区场景下头部完整性被整体跳过的降级（详见 crypto::create_auth_tag_bound）。
        let auth_tag = bound_auth_tag(
            &keys.auth_key, &vault_salt, VERSION_V5, &alias_field, &part_salt,
        );

        let empty_index = Index::new();
        let index_json = serde_json::to_vec(&empty_index)?;
        let enc_index = encrypt_gcm(&keys.enc_key, &index_json, b"index", None)?;

        let index_offset = file.seek(SeekFrom::End(0))?;
        let index_length = enc_index.len() as u64;
        file.write_all(&enc_index)?;
        file.flush()?;
        file.sync_all()?;

        let partition = PartitionInfo {
            alias: DEFAULT_PARTITION.into(),
            salt: part_salt,
            auth_tag,
            index_offset,
            index_length,
            wrapped_key: Some(wrapped),
        };

        // 2.3.0：锁定区 HMAC 由 write_header_to_file 用公开密钥计算（见 crypto::derive_lock_mac_key），
        // 不再绑定主密码 —— 旧实现导致错误密码无法递增计数（锁定永不生效）且诱饵分区无法打开。
        let lock_state = LockState::new();
        write_header_to_file(&mut file, VERSION_V5, &lock_state, &vault_salt, std::slice::from_ref(&partition), &keys.sign_key)?;

        // ── P2-20：直接建立会话（不再二次认证） ──
        let mut audit = AuditLog::new(keys.auth_key);
        audit.add("保险柜已创建并解锁");
        let mut cached = empty_index;
        cached.audit = audit.to_vec();

        self.file = Some(file);
        self.path = Some(path.to_path_buf());
        self.format_version = VERSION_V5;
        self.data_key = Some(*data_key); // Zeroizing 包装在此处解包存入会话，副本随 drop 清零
        self.salt = vault_salt;
        self.enc_key = Some(keys.enc_key);
        self.auth_key = Some(keys.auth_key);
        self.sign_key = Some(keys.sign_key);
        self.lock_state = lock_state;
        self.partitions = vec![partition];
        self.active_partition = Some(0);
        self.audit = Some(audit);
        self.cached_index = Some(cached);
        self.audit_dirty = true; // 审计尚未随索引落盘，close() 时补写

        keys.zeroize(); // 各密钥副本已存入 self，此处清理临时结构
        secure_wipe_vec(index_json);
        Ok(())
    }

    /// 仅供集成测试构造 v4 旧格式夹具（v4 兼容 / 升级路径的回归测试需要）。
    /// 逻辑为 2.7.1 `create` 的原样复刻（含「库盐即分区盐」的历史行为）。
    #[doc(hidden)]
    pub fn create_v4_for_tests(
        &mut self,
        path: &Path,
        password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<(), VaultError> {
        if password.chars().count() < 12 {
            return Err(VaultError::Other("密码长度至少 12 位".into()));
        }
        if self.is_open() {
            return Err(VaultError::AlreadyOpen);
        }
        let mut file = open_vault_create_new(path)?;
        lock_vault_exclusive(&file)
            .map_err(|_| VaultError::Other("保险柜文件已被另一个实例占用".into()))?;
        file.write_all(&[0u8; HEADER_SIZE_V4])?;
        file.flush()?;

        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let mut keys = derive_keys(password, key_file_data, &salt)?;
        let auth_tag = bound_auth_tag(
            &keys.auth_key, &salt, VERSION_V4, &alias_field16(DEFAULT_PARTITION), &salt,
        );

        let empty_index = Index::new();
        let index_json = serde_json::to_vec(&empty_index)?;
        let enc_index = encrypt_gcm(&keys.enc_key, &index_json, b"index", None)?;
        let index_offset = file.seek(SeekFrom::End(0))?;
        let index_length = enc_index.len() as u64;
        file.write_all(&enc_index)?;
        file.flush()?;
        file.sync_all()?;

        let partition = PartitionInfo {
            alias: DEFAULT_PARTITION.into(),
            salt,
            auth_tag,
            index_offset,
            index_length,
            wrapped_key: None,
        };
        let lock_state = LockState::new();
        write_header_to_file(&mut file, VERSION_V4, &lock_state, &salt, std::slice::from_ref(&partition), &keys.sign_key)?;

        let mut audit = AuditLog::new(keys.auth_key);
        audit.add("保险柜已创建并解锁");
        let mut cached = empty_index;
        cached.audit = audit.to_vec();

        self.file = Some(file);
        self.path = Some(path.to_path_buf());
        self.format_version = VERSION_V4;
        self.data_key = None;
        self.salt = salt;
        self.enc_key = Some(keys.enc_key);
        self.auth_key = Some(keys.auth_key);
        self.sign_key = Some(keys.sign_key);
        self.lock_state = lock_state;
        self.partitions = vec![partition];
        self.active_partition = Some(0);
        self.audit = Some(audit);
        self.cached_index = Some(cached);
        self.audit_dirty = true;

        keys.zeroize();
        secure_wipe_vec(index_json);
        Ok(())
    }

    // ═══════════════ 打开认证 ═══════════════

    pub fn open_and_authenticate(
        &mut self,
        path: &Path,
        password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<usize, VaultError> {
        if self.is_open() {
            return Err(VaultError::AlreadyOpen);
        }
        let mut file = open_vault_rw(path, false)?;
        // 2.6.1：独占打开 —— 第二个实例（或同进程重复打开）必须失败而非并发写入
        lock_vault_exclusive(&file)
            .map_err(|_| VaultError::Other("保险柜文件已被另一个实例占用".into()))?;
        // 2.8.0：先嗅探 magic + 版本字节，再按格式读取对应大小的头部
        // （v4 文件总长可能不足 2048 字节，不能直接按 v5 头部大小读取）
        let mut sniff = [0u8; 9];
        file.read_exact(&mut sniff)?;
        if &sniff[..8] != MAGIC {
            return Err(VaultError::BadMagic);
        }
        match sniff[8] {
            VERSION_V4 => self.open_and_authenticate_v4(path, file, password, key_file_data),
            VERSION_V5 => self.open_and_authenticate_v5(path, file, password, key_file_data),
            v => Err(VaultError::Other(format!(
                "不支持的保险柜格式版本 {}（文件可能来自更新版本的 LynVault，请升级软件后重试）",
                v
            ))),
        }
    }

    /// v4 旧格式打开（2.8.0 起仅为兼容保留；新建保险柜一律 v5）。
    /// 认证逻辑与 2.7.1 的 open_and_authenticate 完全一致。
    fn open_and_authenticate_v4(
        &mut self,
        path: &Path,
        mut file: File,
        password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<usize, VaultError> {
        file.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; HEADER_SIZE_V4];
        file.read_exact(&mut header)?;

        let (magic, version, salt) = Self::parse_header(&header)?;
        if &magic != MAGIC || version != VERSION_V4 {
            return Err(VaultError::BadMagic);
        }

        let lock_count = header[LOCK_OFFSET_V4];
        let mut lock_until = f64::from_le_bytes(header[LOCK_OFFSET_V4+1..LOCK_OFFSET_V4+9].try_into().unwrap());
        // 2.8.1：拒绝非有限值 —— NaN 恒判未锁定、+inf 恒判锁定，均属异常头部
        if !lock_until.is_finite() { lock_until = 0.0; }

        // 2.3.0 修复（关键）：锁定区 HMAC 使用从 salt 独立派生的**公开**密钥，
        // 与密码无关。因此：
        // - 错误密码能通过锁定区校验并进入分区认证 → 认证失败会真正递增 lock_count（锁定生效）；
        // - 诱饵分区（独立密码）也能通过锁定区校验并打开。
        // 旧版（<2.3.0）锁定区用密码派生密钥签名，此处做兼容校验并在后续写入时自动迁移。
        let mac_key = derive_lock_mac_key(&salt);
        let mut lock_state = LockState { lock_count, lock_until, lock_until_monotonic: None };
        let stored_hmac: [u8; 32] = header[LOCK_OFFSET_V4+9..LOCK_OFFSET_V4+9+32].try_into().unwrap();
        let verified = if lock_state.verify_hmac(&mac_key, &stored_hmac) {
            true
        } else {
            // 旧版锁定区：用密码派生密钥（旧格式）再试一次；仅用于旧保险柜打开时校验。
            // 2.5.1：derive_legacy_lock_key 改为返回 Result（不再 panic），
            // 派生失败（如 Argon2id 内存分配失败）按校验失败处理。
            match derive_legacy_lock_key(&salt, password, key_file_data) {
                Ok(legacy_key) => lock_state.verify_hmac(&legacy_key, &stored_hmac),
                Err(_) => false,
            }
        };
        if !verified {
            // 2.7.1 修复：<2.3.0 的旧格式保险柜锁定区用密码派生密钥校验，输错密码
            // 同样走到该分支 —— 旧文案「头部锁定区被篡改」会诱导用户误以为文件
            // 被破坏而丢弃重要保险柜。现明确告知旧版保险柜通常只是密码或密钥
            // 文件不正确。
            return Err(VaultError::Other(
                "头部锁定区校验失败。若是 2.3.0 之前创建的旧版保险柜，这通常只是密码或密钥文件不正确，请确认后重试（文件并未损坏，请勿删除）；新版保险柜出现该错误则说明头部可能被篡改".into(),
            ));
        }
        if lock_state.is_locked() {
            return Err(VaultError::Locked);
        }

        // 解析分区表：始终扫描 MAX_PARTITIONS 个条目（2.3.0 起伪条目整体随机填充，
        // 不再有「别名首字节 0」标记，因此不再跳过任何条目 —— 全部参与认证以保证恒定时间）
        let mut parsed: Vec<PartitionInfo> = Vec::new();
        let mut off = 106;
        for _ in 0..MAX_PARTITIONS {
            if off + PARTITION_ENTRY_SIZE_V4 > HEADER_SIZE_V4 { break; }
            let alias_len = header[off..off+16].iter().position(|&b| b == 0).unwrap_or(16);
            let alias = String::from_utf8_lossy(&header[off..off+alias_len]).to_string();
            let mut p_salt = [0u8; 32];
            p_salt.copy_from_slice(&header[off+16..off+48]);
            let mut auth_tag = [0u8; 32];
            auth_tag.copy_from_slice(&header[off+48..off+80]);
            let index_offset = u64::from_le_bytes(header[off+80..off+88].try_into().unwrap());
            let index_length = u64::from_le_bytes(header[off+88..off+96].try_into().unwrap());
            parsed.push(PartitionInfo { alias, salt: p_salt, auth_tag, index_offset, index_length, wrapped_key: None });
            off += PARTITION_ENTRY_SIZE_V4;
        }

        // C9 修复 + 2.3.0 + 2.4.1：始终对**全部 8 个条目**执行完整 Argon2id 派生
        // （即使中途匹配），消除计时侧信道 —— 总派生工作量恒定，与真实分区数量无关。
        //
        // 2.4.1 优化（P1-6）：8 组密钥改为分块并行派生（块大小 = min(CPU 逻辑核数, 4)），
        // 串行约 1s 降至约 0.25-0.5s。并行只是调度优化：8 次派生仍 100% 完成后
        // 才进入认证比较，恒定时间语义不变；并行度上限 4 同时把瞬时内存峰值
        // 控制在 4×64MB，低配机器按核数自动降为 1（退化为旧行为）。
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let parallel = cpus.clamp(1, 4); // 2.8.1：clamp 化（语义与 min(4).max(1) 一致）
        let mut keys_list: Vec<KeyMaterial> = Vec::with_capacity(parsed.len());
        for chunk in parsed.chunks(parallel) {
            let results: Vec<Result<KeyMaterial, VaultError>> = std::thread::scope(|s| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|p| s.spawn(move || derive_keys(password, key_file_data, &p.salt)))
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join()
                            .unwrap_or_else(|_| Err(VaultError::Other("密钥派生线程失败".into())))
                    })
                    .collect()
            });
            for r in results {
                keys_list.push(r?);
            }
        }

        // 认证比较阶段（此时重计算已完成，循环本身极轻）
        let mut matched_idx: Option<usize> = None;
        let mut matched_index: Option<Index> = None;
        let mut matched_keys: Option<([u8; 32], [u8; 32], [u8; 32])> = None;
        for (idx, keys) in keys_list.iter_mut().enumerate() {
            let p = &parsed[idx];
            // 2.6.1：用「绑定头部」的认证标签校验 —— 头部前缀 + 本条目别名字段 + salt
            // 都被纳入 HMAC，因此篡改头部必然使该分区匹配失败（不再依赖分区计数）。
            let eoff = 106 + idx * PARTITION_ENTRY_SIZE_V4;
            let tag_ok = verify_auth_tag_bound(
                &keys.auth_key,
                &header[..105],
                &header[eoff..eoff + 16],
                &header[eoff + 16..eoff + 48],
                &p.auth_tag,
            );
            if matched_idx.is_none() && tag_ok {
                match Self::try_authenticate_partition(&mut file, &parsed, idx, keys) {
                    Ok(index) => {
                        matched_idx = Some(idx);
                        matched_index = Some(index);
                        matched_keys = Some((keys.enc_key, keys.auth_key, keys.sign_key));
                    }
                    Err(e) => {
                        // 匹配分区但头部/索引校验失败 → 视为篡改，中止并清理全部密钥
                        // 2.7.1 诊断：先以头部 HMAC 签名（此前只写不校验）取证，
                        // 再统一清零全部密钥
                        let sig_ok = verify_header_signature(&header, &keys.sign_key);
                        for k in keys_list.iter_mut() { k.zeroize(); }
                        // 2.7.1 修复：分区密码正确但索引解不出来时，旧实现只抛
                        // 「Invalid ciphertext or corrupted data」，与「密码错误」
                        // 不可区分，也没有下一步指引。现明确告知「分区密码正确」。
                        return Err(VaultError::Other(format!(
                            "分区密码正确，但该分区数据校验失败（{}）。头部签名{}。为避免进一步损坏，请勿再向此保险柜写入任何数据，并改用更早时间点的副本（用其他分区密码打开不受影响）",
                            e,
                            if sig_ok {
                                "校验通过 —— 头部未被篡改，损坏位于索引数据区"
                            } else {
                                "校验失败 —— 头部可能也被篡改"
                            }
                        )));
                    }
                }
            }
            // 不 return，继续遍历剩余条目（恒定时间语义由 8 次派生保证）
        }

        // 全部密钥材料统一清理（匹配项的副本已随 matched_keys 带出）
        for k in keys_list.iter_mut() { k.zeroize(); }

        if let (Some(idx), Some(index), Some((enc_key, auth_key, sign_key))) =
            (matched_idx, matched_index, matched_keys)
        {
            // 过滤出真实分区（别名合理的条目；伪条目随机数据几乎不可能通过校验）
            let real_partitions: Vec<PartitionInfo> = parsed.iter()
                .filter(|p| is_plausible_alias(&p.alias))
                .cloned()
                .collect();
            let matched_salt = parsed[idx].salt;
            let matched_tag = parsed[idx].auth_tag;
            // 恒定时间比较：避免按字节短路泄露「salt/tag 前多少字节匹配」的时序信息
            let active = real_partitions.iter()
                .position(|p| {
                    use subtle::ConstantTimeEq;
                    bool::from(p.salt.ct_eq(&matched_salt) & p.auth_tag.ct_eq(&matched_tag))
                })
                .ok_or_else(|| VaultError::Other(
                    "头部与数据不匹配：找不到对应的分区（文件可能被篡改、损坏或与其他保险柜混用）".into(),
                ))?;

            lock_state.reset();
            self.lock_state = lock_state;
            self.salt = salt;
            // 2.8.0：会话元数据 —— v4 格式无包裹层，data_key 为 None
            self.format_version = VERSION_V4;
            self.data_key = None;
            self.partitions = real_partitions;
            self.active_partition = Some(active);

            // 2.6.1：旧格式（未绑定头部）认证标签 → 首次成功打开即就地迁移为绑定格式，
            // 之后头部完整性由 auth_tag 无条件保证。仅迁移当前分区（其他分区的
            // auth_key 未知，待其各自被打开时迁移），由随后的 update_header 落盘。
            let moff = 106 + idx * PARTITION_ENTRY_SIZE_V4;
            let migrated_tag = create_auth_tag_bound(
                &auth_key,
                &auth_tag_header_prefix(&salt, VERSION_V4),
                &header[moff..moff + 16],
                &header[moff + 16..moff + 48],
            );
            if self.partitions[active].auth_tag != migrated_tag {
                self.partitions[active].auth_tag = migrated_tag;
            }

            self.enc_key = Some(enc_key);
            self.auth_key = Some(auth_key);
            self.sign_key = Some(sign_key);

            let mut audit = AuditLog::from_entries(index.audit.clone(), auth_key);
            // 2.8.2：恢复时丢弃过尾部条目 → 显式写入告警（不再静默截断）
            if audit.is_truncated() {
                audit.add("警告：审计链存在无法校验的条目，部分历史记录可能被篡改或损坏");
            }
            audit.add("保险柜已解锁");
            self.audit = Some(audit);

            self.file = Some(file);
            self.path = Some(path.to_path_buf());
            // 2.4.1：成功打开后把索引放入内存缓存，后续操作不再重复解密加载
            self.cached_index = Some(index);
            self.audit_dirty = true; // "已解锁"审计尚未落盘

            // 成功打开：重置锁定区并重新签名头部（旧保险柜在此完成锁定区格式迁移）
            self.update_header()?;

            return Ok(active);
        }

        // 全部失败：2.3.0 起真正递增锁定计数（公开密钥可计算 HMAC，无需正确密码）。
        // 5 次错误 → 锁定 30 分钟；锁定期间 is_locked() 直接拒绝（包括正确密码）。
        lock_state.record_failure();
        let mut lock_buf = [0u8; 41];
        lock_buf[0] = lock_state.lock_count;
        lock_buf[1..9].copy_from_slice(&lock_state.lock_until.to_le_bytes());
        let hmac = lock_state.compute_hmac(&mac_key);
        lock_buf[9..41].copy_from_slice(&hmac);
        file.seek(SeekFrom::Start(LOCK_OFFSET_V4 as u64))?;
        file.write_all(&lock_buf)?;
        file.flush()?;
        file.sync_all()?;

        Err(VaultError::AuthFailed)
    }

    /// 2.8.0（v5 信封加密）打开认证。
    ///
    /// 与 v4 的恒定时间结构一致：先对全部 8 个条目并行完成 Argon2id（KEK 派生，
    /// 绝对主导成本），再进入逐条目「解包 data_key → 派生会话密钥 → 验证绑定
    /// 认证标签」的轻量比较阶段 —— 每个条目都完整尝试，不因中途匹配而短路。
    /// 口令正确 ⇔ 该条目的 GCM 解包成功（错误口令解包必然失败）。
    fn open_and_authenticate_v5(
        &mut self,
        path: &Path,
        mut file: File,
        password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<usize, VaultError> {
        file.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; HEADER_SIZE_V5];
        file.read_exact(&mut header)?;

        let (magic, version, salt) = Self::parse_header(&header)?;
        if &magic != MAGIC || version != VERSION_V5 {
            return Err(VaultError::BadMagic);
        }

        let lock_count = header[LOCK_OFFSET_V5];
        let mut lock_until = f64::from_le_bytes(header[LOCK_OFFSET_V5+1..LOCK_OFFSET_V5+9].try_into().unwrap());
        // 2.8.1：拒绝非有限值 —— NaN 恒判未锁定、+inf 恒判锁定，均属异常头部
        if !lock_until.is_finite() { lock_until = 0.0; }

        // 锁定区校验（公开密钥，与 v4 同一机制；v5 为新格式，无 legacy 回退）
        let mac_key = derive_lock_mac_key(&salt);
        let mut lock_state = LockState { lock_count, lock_until, lock_until_monotonic: None };
        let stored_hmac: [u8; 32] = header[LOCK_OFFSET_V5+9..LOCK_OFFSET_V5+9+32].try_into().unwrap();
        if !lock_state.verify_hmac(&mac_key, &stored_hmac) {
            return Err(VaultError::Other("头部锁定区校验失败 —— 头部可能被篡改".into()));
        }
        if lock_state.is_locked() {
            return Err(VaultError::Locked);
        }

        // 解析 8 个 192 字节条目（含 60 字节包裹密钥；伪条目为随机字节，认证必然失败）
        let mut parsed: Vec<PartitionInfo> = Vec::new();
        let mut off = 106;
        for _ in 0..MAX_PARTITIONS {
            let alias_len = header[off..off+16].iter().position(|&b| b == 0).unwrap_or(16);
            let alias = String::from_utf8_lossy(&header[off..off+alias_len]).to_string();
            let mut p_salt = [0u8; 32];
            p_salt.copy_from_slice(&header[off+16..off+48]);
            let mut auth_tag = [0u8; 32];
            auth_tag.copy_from_slice(&header[off+48..off+80]);
            let index_offset = u64::from_le_bytes(header[off+80..off+88].try_into().unwrap());
            let index_length = u64::from_le_bytes(header[off+88..off+96].try_into().unwrap());
            let mut wrapped = [0u8; WRAPPED_KEY_SIZE];
            wrapped.copy_from_slice(&header[off+96..off+96+WRAPPED_KEY_SIZE]);
            parsed.push(PartitionInfo { alias, salt: p_salt, auth_tag, index_offset, index_length, wrapped_key: Some(wrapped) });
            off += PARTITION_ENTRY_SIZE_V5;
        }

        // 阶段 1：8 × Argon2id（KEK 派生），分块并行（与 v4 相同的调度优化）。
        // 2.8.1：KEK 用 Zeroizing 包裹 —— `?` 提前返回（派生失败）时已派生的
        // KEK 不再以明文形式残留在堆上（数组没有 Drop，旧实现靠不到）
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let parallel = cpus.clamp(1, 4); // 2.8.1：clamp 化（语义与 min(4).max(1) 一致）
        let mut kek_list: Vec<Zeroizing<[u8; 32]>> = Vec::with_capacity(parsed.len());
        for chunk in parsed.chunks(parallel) {
            let results: Vec<Result<[u8; 32], VaultError>> = std::thread::scope(|s| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|p| s.spawn(move || derive_kek(password, key_file_data, &p.salt)))
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join()
                            .unwrap_or_else(|_| Err(VaultError::Other("密钥派生线程失败".into())))
                    })
                    .collect()
            });
            // 2.8.2：`?` 早退时 results 中尚未 push 的 KEK 是裸 [u8;32] 数组
            // （Copy，drop 是空操作），会以明文残留堆内存 —— 改为先全部收进
            // Zeroizing 容器再决定成败，任何路径 drop 即清零。
            let mut chunk_keks: Vec<Zeroizing<[u8; 32]>> = Vec::with_capacity(results.len());
            let mut first_err: Option<VaultError> = None;
            for r in results {
                match r {
                    Ok(k) => chunk_keks.push(Zeroizing::new(k)),
                    Err(e) => {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    }
                }
            }
            if let Some(e) = first_err {
                // chunk_keks 是 Zeroizing，drop 即清零
                return Err(e);
            }
            kek_list.extend(chunk_keks);
        }

        // 阶段 2：逐条目解包 + 认证标签校验（轻量，全部尝试保持恒定时间语义）。
        // candidate 的 data_key 同样用 Zeroizing：无论走哪条分支（存入会话 /
        // 篡改中止 / 多余候选），drop 时都会清零。
        let prefix = auth_tag_header_prefix(&salt, VERSION_V5);
        let mut matched: Option<(usize, Index, KeyMaterial, Zeroizing<[u8; 32]>)> = None;
        for (idx, kek) in kek_list.iter().enumerate() {
            let p = &parsed[idx];
            let eoff = 106 + idx * PARTITION_ENTRY_SIZE_V5;
            let alias_field = &header[eoff..eoff + 16];
            let wrap_aad = key_wrap_aad(&prefix, alias_field, &p.salt);
            let mut candidate: Option<(KeyMaterial, Zeroizing<[u8; 32]>)> = None;
            if let Some(dk) = unwrap_data_key(kek, &p.wrapped_key.unwrap_or([0u8; WRAPPED_KEY_SIZE]), &wrap_aad) {
                if let Ok(keys) = expand_keys(&dk) {
                    if verify_auth_tag_bound(&keys.auth_key, &prefix, alias_field, &p.salt, &p.auth_tag) {
                        candidate = Some((keys, Zeroizing::new(dk)));
                    } else {
                        let mut dk2 = dk;
                        dk2.zeroize();
                    }
                } else {
                    let mut dk2 = dk;
                    dk2.zeroize();
                }
            }
            if matched.is_none() {
                if let Some((keys, dk)) = candidate {
                    match Self::try_authenticate_partition(&mut file, &parsed, idx, &keys) {
                        Ok(index) => matched = Some((idx, index, keys, dk)),
                        Err(e) => {
                            // 匹配分区但头部/索引校验失败 → 视为篡改，中止并清理全部密钥
                            //（candidate 的 dk 是 Zeroizing，drop 时自动清零）
                            let sig_ok = verify_header_signature_v5(&header, &keys.sign_key);
                            // keys 是 ZeroizeOnDrop，dk 是 Zeroizing —— 出作用域即清零
                            for k in kek_list.iter_mut() { k.zeroize(); }
                            return Err(VaultError::Other(format!(
                                "分区密码正确，但该分区数据校验失败（{}）。头部签名{}。为避免进一步损坏，请勿再向此保险柜写入任何数据，并改用更早时间点的副本",
                                e,
                                if sig_ok {
                                    "校验通过 —— 头部未被篡改，损坏位于索引数据区"
                                } else {
                                    "校验失败 —— 头部可能也被篡改"
                                }
                            )));
                        }
                    }
                }
            } else if let Some((_, dk)) = candidate {
                // 防御分支：理论上至多一个条目能通过认证，多余的密钥立即清零
                drop(dk);
            }
        }
        for k in kek_list.iter_mut() { k.zeroize(); }

        if let Some((idx, index, keys, data_key)) = matched {
            // 2.8.2（M1）→ 2.8.2.1（兼容性修正）：头部签名**校验但不再硬拒**。
            // index_offset/index_length 不在 auth_tag AAD、key_wrap AAD、锁区
            // HMAC 的任何覆盖范围内 —— 验签仍执行，但签名不一致时不再拒绝打开：
            // 多分区保险柜的头部由「最后打开的分区」签名（跨分区打开必然
            // 不一致）、云同步回写/写入中断/历史版本签名形态差异也会造成
            // 良性不一致 —— 硬拒把合法存量柜全部挡在门外（发布当日即回归）。
            // 现改为：写入审计告警 + 下方 update_header 按当前分区密钥重签
            // （迁移到规范形）。全文件级回滚防护的根治仍需 v6 generation 计数器。
            let legacy_signature = !verify_header_signature_v5(&header, &keys.sign_key);
            // 过滤出真实分区（伪条目随机数据几乎不可能通过认证）
            let real_partitions: Vec<PartitionInfo> = parsed.iter()
                .filter(|p| is_plausible_alias(&p.alias))
                .cloned()
                .collect();
            let matched_salt = parsed[idx].salt;
            let matched_tag = parsed[idx].auth_tag;
            // 恒定时间比较（与 v4 相同）
            let active = real_partitions.iter()
                .position(|p| {
                    use subtle::ConstantTimeEq;
                    bool::from(p.salt.ct_eq(&matched_salt) & p.auth_tag.ct_eq(&matched_tag))
                })
                .ok_or_else(|| VaultError::Other(
                    "头部与数据不匹配：找不到对应的分区（文件可能被篡改、损坏或与其他保险柜混用）".into(),
                ))?;

            lock_state.reset();
            self.lock_state = lock_state;
            self.salt = salt;
            self.format_version = VERSION_V5;
            self.partitions = real_partitions;
            self.active_partition = Some(active);

            self.enc_key = Some(keys.enc_key);
            self.auth_key = Some(keys.auth_key);
            self.sign_key = Some(keys.sign_key);
            self.data_key = Some(*data_key); // Zeroizing 解包存入会话

            let mut audit = AuditLog::from_entries(index.audit.clone(), keys.auth_key);
            // 2.8.2：恢复时丢弃过尾部条目 → 显式写入告警（不再静默截断）
            if audit.is_truncated() {
                audit.add("警告：审计链存在无法校验的条目，部分历史记录可能被篡改或损坏");
            }
            // 2.8.2.1：签名与当前分区密钥不一致（多分区跨签名/历史遗留/头部曾被改动）
            // → 审计留痕，随后 update_header 按当前分区密钥重签迁移
            if legacy_signature {
                audit.add("提示：头部签名与当前分区密钥不一致（多分区跨签名或历史版本遗留），已重新签名迁移");
            }
            audit.add("保险柜已解锁");
            self.audit = Some(audit);

            self.file = Some(file);
            self.path = Some(path.to_path_buf());
            self.cached_index = Some(index);
            self.audit_dirty = true;

            // 成功打开：重置锁定区并重新签名头部
            self.update_header()?;

            return Ok(active);
        }

        // 全部失败：递增锁定计数（v5 偏移）
        lock_state.record_failure();
        let mut lock_buf = [0u8; 41];
        lock_buf[0] = lock_state.lock_count;
        lock_buf[1..9].copy_from_slice(&lock_state.lock_until.to_le_bytes());
        let hmac = lock_state.compute_hmac(&mac_key);
        lock_buf[9..41].copy_from_slice(&hmac);
        file.seek(SeekFrom::Start(LOCK_OFFSET_V5 as u64))?;
        file.write_all(&lock_buf)?;
        file.flush()?;
        file.sync_all()?;

        Err(VaultError::AuthFailed)
    }
    /// 2.4.1 新增（从 open_and_authenticate 抽取）：对已通过 auth_tag（头部绑定）校验的
    /// 分区做索引边界检查 + 读取解密。密钥由调用方持有并负责清理。
    /// 头部完整性已由调用方在 auth_tag 校验阶段无条件保证。
    fn try_authenticate_partition(
        file: &mut File,
        parsed: &[PartitionInfo],
        idx: usize,
        keys: &KeyMaterial,
    ) -> Result<Index, VaultError> {
        let p = &parsed[idx];
        // 头部完整性（2.6.1 重构，消除零知识降级）：
        // 旧实现在此按 `real_count = 头部中别名合法的条目数` 决定是否校验头部签名 ——
        // 该计数完全取自攻击者可控的头部：向单分区保险柜塞入一个带合法别名的伪条目，
        // 即可把签名校验整体跳过。现改为：头部完整性由调用方已验证的**头部绑定
        // auth_tag** 无条件保证（篡改 magic/version/保险柜 salt/本条目别名/salt 都会
        // 导致认证失败，见 crypto::create_auth_tag_bound），不再依赖任何分区计数，
        // 因此这里不再做「按分区数条件跳过」的签名校验。
        //
        // 全局头部签名（HMAC-SHA512）仍按旧格式写入以保持头部结构兼容；它能覆盖的
        // 字段已被 auth_tag（身份/全局字段）与索引 GCM 标签（index_offset/length）
        // 分别保护，其无法覆盖的多分区交叉签名场景也不再是安全缺口。

        // 2.3.0 修复：索引边界检查使用 checked_add 防 u64 溢出回绕，
        // 并对索引长度设上限，防止恶意头部触发超大内存分配（进程被杀）
        let file_size = file.metadata()?.len();
        match p.index_offset.checked_add(p.index_length) {
            None => return Err(VaultError::Other("索引超出文件范围".into())),
            Some(end) if end > file_size => {
                return Err(VaultError::Other("索引超出文件范围".into()));
            }
            _ => {}
        }
        if p.index_length > MAX_INMEM_BUFFER as u64 {
            return Err(VaultError::Other(format!(
                "索引过大（{} 字节），超过单次加载上限", p.index_length
            )));
        }

        file.seek(SeekFrom::Start(p.index_offset))?;
        let mut enc_index = vec![0u8; p.index_length as usize];
        file.read_exact(&mut enc_index)?;
        let index_json = match decrypt_gcm(&keys.enc_key, &enc_index, b"index") {
            Some(j) => j,
            None => {
                secure_wipe_vec(enc_index);
                return Err(VaultError::DecryptFailed);
            }
        };
        let index: Index = serde_json::from_slice(&index_json)?;
        secure_wipe_vec(enc_index);
        secure_wipe_vec(index_json);
        Ok(index)
    }

    // ═══════════════ 索引操作 ═══════════════

    pub fn get_index_manager(&mut self) -> Result<IndexManager<'_>, VaultError> {
        if self.enc_key.is_none() || self.file.is_none() {
            return Err(VaultError::NotOpen);
        }
        Ok(IndexManager::new(self))
    }

    /// 2.4.1 优化（P0-2）：索引加载走内存缓存。
    /// 旧实现每次操作都「读磁盘 → AES-GCM 解密 → JSON 反序列化」；
    /// 现在首次加载后常驻缓存，save_index 成功后同步刷新。
    pub fn load_index(&mut self) -> Result<Index, VaultError> {
        if let Some(idx) = &self.cached_index {
            return Ok(idx.clone());
        }
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let (offset, length) = {
            let p = &self.partitions[active];
            (p.index_offset, p.index_length)
        };
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let index = load_index_from_file(file, enc_key, offset, length)?;
        self.cached_index = Some(index.clone());
        Ok(index)
    }

    /// 2.8.1：改为接管索引所有权 —— 旧实现 `index.clone()` 每次保存都深拷贝
    /// 整个 files/folders HashMap（10k 文件 ≈ 数 MB 分配 ×2，含 audit Vec 再克隆一次），
    /// 所有调用方本就在 save 后不再使用索引，直接移动即可。
    /// 2.8.1：只读借用内存索引缓存（list_folder / get_file_info 等只读路径
    /// 免去 load_index 的整索引克隆）
    pub fn index_ref(&self) -> Result<&Index, VaultError> {
        self.cached_index.as_ref().ok_or(VaultError::NotOpen)
    }

    pub fn save_index(&mut self, mut index: Index) -> Result<(), VaultError> {
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let (old_off, old_len) = {
            let p = &self.partitions[active];
            (p.index_offset, p.index_length)
        };

        if let Some(audit) = &self.audit {
            index.audit = audit.to_vec();
        }
        let idx = index;

        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        // 步骤 1：写新索引到末尾（不擦旧索引）
        let (new_off, new_len) = save_index_to_file(file, enc_key, &idx)?;

        // 步骤 2：更新内存中的分区信息
        self.partitions[active].index_offset = new_off;
        self.partitions[active].index_length = new_len;

        // 步骤 3：更新头部偏移（持久化指向新索引）
        self.update_header()?;

        // 步骤 4：头部已落盘，现在安全擦除旧索引（C3 修复关键点）
        // 即使此步失败/崩溃，新索引已可由头部定位，旧索引只是垃圾数据
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        wipe_old_index_range(file, old_off, old_len);

        // 2.4.1：磁盘写入成功后刷新内存缓存（一致性由「变更必须走 save_index」保证）
        self.cached_index = Some(idx);
        self.audit_dirty = false;
        Ok(())
    }

    // ═══════════════ 头部更新 ═══════════════

    fn update_header(&mut self) -> Result<(), VaultError> {
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let sign_key = self.sign_key.as_ref().ok_or(VaultError::NotOpen)?;
        write_header_to_file(
            file, self.format_version, &self.lock_state,
            &self.salt, &self.partitions, sign_key,
        )
    }

    /// 头部前缀解析（magic / 版本 / 保险柜 salt）—— 三个字段在 v4/v5 布局中位置一致。
    fn parse_header(header: &[u8])
        -> Result<([u8; 8], u8, [u8; 32]), VaultError>
    {
        if header.len() < 105 {
            return Err(VaultError::BadMagic);
        }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&header[..8]);
        let version = header[8];
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&header[73..105]);
        Ok((magic, version, salt))
    }

    // ═══════════════ 分区管理 ═══════════════

    pub fn add_partition(&mut self, alias: &str, fake_password: &str, key_file_data: Option<&[u8]>) -> Result<(), VaultError> {
        if self.file.is_none() { return Err(VaultError::NotOpen); }
        // 2.3.0：库级 API 也校验分区别名（此前仅 Tauri 命令层校验，
        // 非法别名可能导致重开后分区不可见）
        if !is_valid_alias(alias) {
            return Err(VaultError::Other("分区别名只能包含字母、数字、下划线、短横线和空格，长度 1-16 字符".into()));
        }
        // 2.4.1 修复（P2-19）：分区密码同样按字符数校验（旧实现无任何强度校验）
        if fake_password.chars().count() < 12 {
            return Err(VaultError::Other("分区密码长度至少 12 位".into()));
        }
        if self.partitions.len() >= MAX_PARTITIONS { return Err(VaultError::TooManyPartitions); }

        let mut part_salt = [0u8; 32];
        OsRng.fill_bytes(&mut part_salt);
        // 2.8.0：v5 为新分区生成随机 data_key 并用分区口令包裹；v4 保持旧派生路径
        let alias_field = alias_field16(alias);
        let (mut keys, wrapped_key) = match self.format_version {
            VERSION_V5 => {
                // 2.8.1：dk/kek 用 Zeroizing —— expand_keys 派生失败的 `?` 早退
                // 路径上随机 data_key 不再以明文残留
                let mut dk = [0u8; 32];
                OsRng.fill_bytes(&mut dk);
                let dk = Zeroizing::new(dk);
                let k = expand_keys(&dk)?;
                let kek = Zeroizing::new(derive_kek(fake_password, key_file_data, &part_salt)?);
                let wrap_aad = key_wrap_aad(
                    &auth_tag_header_prefix(&self.salt, VERSION_V5),
                    &alias_field,
                    &part_salt,
                );
                let wrapped_v = encrypt_gcm(&kek, &dk[..], &wrap_aad, None)?;
                let mut wrapped = [0u8; WRAPPED_KEY_SIZE];
                wrapped.copy_from_slice(&wrapped_v);
                drop(kek);
                secure_wipe_vec(wrapped_v);
                (k, Some(wrapped))
            }
            _ => (derive_keys(fake_password, key_file_data, &part_salt)?, None),
        };
        // 2.6.1：新分区同样使用绑定头部的认证标签（保险柜 salt + 本分区别名/salt）
        let auth_tag = bound_auth_tag(
            &keys.auth_key, &self.salt, self.format_version, &alias_field, &part_salt,
        );

        let empty_index = Index::new();
        let plain = serde_json::to_vec(&empty_index)?;
        let enc = encrypt_gcm(&keys.enc_key, &plain, b"index", None)?;

        // 新分区的空索引先追加到文件尾（获得偏移量）；此步之后头部写入若失败，
        // 这段密文成为无害死空间（头部仍指向旧布局，碎片整理可回收）
        let (offset, enc_len) = {
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            let offset = file.seek(SeekFrom::End(0))?;
            file.write_all(&enc)?;
            file.flush()?;
            file.sync_all()?;
            (offset, enc.len() as u64)
        };

        // 2.8.2（崩溃一致性）：先写头部、成功后才提交内存 —— 旧实现先
        // partitions.push 再 update_header，头部写入失败时内存与磁盘分叉，
        // 后续任意一次 save_index/update_header 都会把「失败的添加」持久化。
        let new_entry = PartitionInfo {
            alias: alias.into(),
            salt: part_salt,
            auth_tag,
            index_offset: offset,
            index_length: enc_len,
            wrapped_key,
        };
        {
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            let sign_key = self.sign_key.as_ref().ok_or(VaultError::NotOpen)?;
            let mut new_partitions = self.partitions.clone();
            new_partitions.push(new_entry.clone());
            write_header_to_file(
                file, self.format_version, &self.lock_state, &self.salt,
                &new_partitions, sign_key,
            )?;
            self.partitions = new_partitions;
        }

        self.log_event(&format!("添加伪装分区 '{}'", new_entry.alias));
        keys.zeroize();
        secure_wipe_vec(plain);
        Ok(())
    }

    pub fn remove_partition(&mut self, alias: &str) -> Result<(), VaultError> {
        if self.file.is_none() { return Err(VaultError::NotOpen); }
        let pos = self.partitions.iter().position(|p| p.alias == alias)
            .ok_or(VaultError::PartitionNotFound)?;
        if pos == 0 { return Err(VaultError::Other("不能删除主分区".into())); }
        if self.active_partition == Some(pos) {
            return Err(VaultError::Other("不能删除当前使用的分区".into()));
        }

        // 2.3.0 顺序修正：先持久化「分区已删除」（update_header），再擦除旧索引区。
        // 旧实现先擦后更新头部，擦除后崩溃会让头部仍指向已被覆盖的索引 → 永久损坏。
        // 2.8.2（崩溃一致性）：先写头部、成功后才提交内存 —— 旧实现先改
        // partitions/active_partition 再 update_header，写入失败时内存与磁盘分叉。
        let p = self.partitions[pos].clone();
        let mut new_partitions = self.partitions.clone();
        new_partitions.remove(pos);
        // 调整活跃分区索引：如果删除的位置在当前活跃分区之前，活跃索引需要减 1
        let new_active = match self.active_partition {
            Some(active) if pos < active => Some(active - 1),
            other => other,
        };
        {
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            let sign_key = self.sign_key.as_ref().ok_or(VaultError::NotOpen)?;
            write_header_to_file(
                file, self.format_version, &self.lock_state, &self.salt,
                &new_partitions, sign_key,
            )?;
        }
        self.partitions = new_partitions;
        self.active_partition = new_active;
        self.log_event(&format!("删除分区 '{}'", alias));

        // 擦除旧索引区（尽力而为）。已知限制：该分区的文件密文因无分区密码无法定位，
        // 无法一并擦除（README「已知限制」已说明）；保险柜整体销毁时会一并擦除。
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = dod_overwrite_range(file, p.index_offset, p.index_length) {
                log::warn!("擦除已删除分区的索引失败（不影响正确性）: {}", e);
            }
            let _ = file.flush();
            let _ = file.sync_all();
        }
        Ok(())
    }

    // ═══════════════ 密码修改（2.8.0）═══════════════

    /// 修改当前分区的密码。
    ///
    /// - **v5 保险柜**：仅重写头部（换盐重新包裹 data_key + 重算认证标签 + 重签名），
    ///   文件数据一个字节不动，瞬间完成。
    /// - **v4 保险柜**：v4 的会话密钥直接由口令派生，改密码必须重加密全部数据。
    ///   借此机会**自动升级**为 v5 信封加密（一次性全库重加密，此后改密码都是头部级）。
    ///   多分区 v4 保险柜无法升级：其余分区口令未知，无法生成 v5 必需的包裹密钥
    ///   （填随机数会让那些分区永久无法打开）—— 明确报错而非静默破坏。
    ///
    /// 必须提供**当前密码**（或等价的密钥文件）：防止他人在已解锁的机器上
    /// 改密锁死真正的主人。新密码 ≥ 12 字符（与创建一致，按字符数）。
    pub fn change_password<F: Fn(usize)>(
        &mut self,
        current_password: &str,
        new_password: &str,
        key_file_data: Option<&[u8]>,
        progress: Option<F>,
    ) -> Result<(), VaultError> {
        if !self.is_open() {
            return Err(VaultError::NotOpen);
        }
        if new_password.chars().count() < 12 {
            return Err(VaultError::Other("新密码长度至少 12 位".into()));
        }
        match self.format_version {
            VERSION_V5 => self.change_password_v5(current_password, new_password, key_file_data),
            VERSION_V4 => self.change_password_v4_upgrade(
                current_password, new_password, key_file_data, progress,
            ),
            v => Err(VaultError::Other(format!("未知的保险柜格式版本: {}", v))),
        }
    }

    /// v5：头部级改密码。验当前密码（解包 + 恒定时间比较 data_key）→
    /// 换盐重新包裹 → 重算认证标签 → 重写头部重签名。
    fn change_password_v5(
        &mut self,
        current_password: &str,
        new_password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<(), VaultError> {
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        // 2.8.1：会话 data_key 副本用 Zeroizing 包裹，函数任何出口都不残留明文
        let session_dk = Zeroizing::new(self.data_key.ok_or(VaultError::NotOpen)?);
        let p = self.partitions[active].clone();
        let alias_field = alias_field16(&p.alias);
        let prefix = auth_tag_header_prefix(&self.salt, VERSION_V5);

        // 1. 验证当前密码：用当前盐派生 KEK 解包，与会话中的 data_key 恒定时间比较
        let kek = Zeroizing::new(derive_kek(current_password, key_file_data, &p.salt)?);
        let aad = key_wrap_aad(&prefix, &alias_field, &p.salt);
        let unwrapped = unwrap_data_key(&kek, &p.wrapped_key.unwrap_or([0u8; WRAPPED_KEY_SIZE]), &aad);
        let mut verified = false;
        if let Some(cand) = &unwrapped {
            use subtle::ConstantTimeEq;
            verified = bool::from(cand.ct_eq(&*session_dk));
        }
        // 2.8.1：候选密钥显式清零 —— Option<[u8;32]> 是 Copy，drop() 是空操作，
        // 不能依赖 Drop（clippy dropping_copy_types 也正是这么提示的）
        if let Some(mut c) = unwrapped { c.zeroize(); }
        drop(kek);
        if !verified {
            return Err(VaultError::Other("当前密码或密钥文件不正确".into()));
        }

        // 2. 换盐重新包裹 data_key（数据密钥本身不变 → 所有密文继续有效）
        let mut new_salt = [0u8; 32];
        OsRng.fill_bytes(&mut new_salt);
        let new_kek = Zeroizing::new(derive_kek(new_password, key_file_data, &new_salt)?);
        let new_aad = key_wrap_aad(&prefix, &alias_field, &new_salt);
        let wrapped_v = encrypt_gcm(&new_kek, &session_dk[..], &new_aad, None)?;
        let mut new_wrapped = [0u8; WRAPPED_KEY_SIZE];
        new_wrapped.copy_from_slice(&wrapped_v);
        drop(new_kek);
        secure_wipe_vec(wrapped_v);

        // 3. 重算认证标签（盐变了必须重算）并重写头部（update_header 内部重签名；
        //    sign_key 由未变的 data_key 派生，依然有效）。
        //    2.8.1（崩溃一致性）：先写头部、成功后才提交内存 —— 旧实现先改内存，
        //    头部写入失败时内存已是「新密码」而磁盘还是旧盐，后续任何一次
        //    save_index/update_header 都会把这次「失败的改密」持久化。
        let auth_key = self.auth_key.ok_or(VaultError::NotOpen)?;
        let new_tag = bound_auth_tag(&auth_key, &self.salt, VERSION_V5, &alias_field, &new_salt);
        let old_part = self.partitions[active].clone();
        self.partitions[active] = PartitionInfo {
            alias: old_part.alias.clone(),
            salt: new_salt,
            auth_tag: new_tag,
            index_offset: old_part.index_offset,
            index_length: old_part.index_length,
            wrapped_key: Some(new_wrapped),
        };
        if let Err(e) = self.update_header() {
            // 头部写入失败：恢复内存中的旧条目，向上传播错误（磁盘未动）
            self.partitions[active] = old_part;
            return Err(e);
        }
        self.log_event("修改当前分区密码");
        Ok(())
    }

    /// v4 → v5 升级 + 改密码（一次性全库重加密）。
    ///
    /// 复用碎片整理的安全管线：磁盘预检 → .bak 完整备份 → .tmp 上重建
    /// （逐文件旧密钥解密 / 新 data_key 重加密，AAD 不变）→ v5 头部 →
    /// ReplaceFileW 原子替换 → 失败回滚。仅支持单分区 v4 保险柜。
    fn change_password_v4_upgrade<F: Fn(usize)>(
        &mut self,
        current_password: &str,
        new_password: &str,
        key_file_data: Option<&[u8]>,
        progress: Option<F>,
    ) -> Result<(), VaultError> {
        if self.partitions.len() != 1 {
            return Err(VaultError::Other(
                "多分区 v4 保险柜暂不支持修改密码：其余分区的口令未知，无法为它们生成 \
                 v5 必需的包裹密钥（填入随机数据会使那些分区永久无法打开）。\
                 可先用对应密码打开各分区导出重要数据，或保持 v4 格式继续使用"
                    .into(),
            ));
        }
        let old_part = self.partitions[0].clone();
        let old_enc_key = *self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let old_auth_key = *self.auth_key.as_ref().ok_or(VaultError::NotOpen)?;

        // 1. 验证当前密码（v4：直接派生三把密钥并与会话密钥恒定时间比较）
        {
            let keys = derive_keys(current_password, key_file_data, &old_part.salt)?;
            use subtle::ConstantTimeEq;
            let enc_ok = bool::from(keys.enc_key.ct_eq(&old_enc_key));
            let mut k = keys;
            k.zeroize();
            if !enc_ok {
                return Err(VaultError::Other("当前密码或密钥文件不正确".into()));
            }
        }

        let vault_path = self.path.as_ref().ok_or(VaultError::NotOpen)?.clone();
        let orig_len = std::fs::metadata(&vault_path)?.len();

        // 2. 磁盘预检（备份完整副本 + 临时文件，同一磁盘：约 2× + 4 MiB）
        let need = orig_len.saturating_mul(2).saturating_add(4 * 1024 * 1024);
        if let Ok(free) = disk_free_bytes(vault_path.parent().unwrap_or(Path::new("."))) {
            if free < need {
                return Err(VaultError::Other(format!(
                    "磁盘可用空间不足（需约 {} MB，仅剩 {} MB），已取消操作，未产生任何中间文件",
                    need / (1024 * 1024),
                    free / (1024 * 1024),
                )));
            }
        }

        // 3. 随机临时/备份文件名（防符号链接攻击，与碎片整理同一策略）
        let mut rand_suffix = [0u8; 16];
        OsRng.fill_bytes(&mut rand_suffix);
        let temp_path = PathBuf::from(format!("{}.tmp.{}", vault_path.display(), hex::encode(rand_suffix)));
        let backup_path = PathBuf::from(format!("{}.bak.{}", vault_path.display(), hex::encode(rand_suffix)));

        // 4. 完整备份（失败统一「先 DoD 擦除再删除」）
        let backup_result: std::io::Result<()> = (|| {
            let mut backup_file = OpenOptions::new().write(true).create_new(true).open(&backup_path)?;
            let mut original = File::open(&vault_path)?;
            let copy = std::io::copy(&mut original, &mut backup_file);
            let sync = backup_file.sync_all();
            drop(backup_file);
            drop(original);
            copy.and(sync).map(|_| ())
        })();
        if let Err(e) = backup_result {
            wipe_scratch_file(&backup_path);
            return Err(e.into());
        }

        // 5. 新信封密钥
        // 2.8.1：Zeroizing —— expand_keys 派生失败的 `?` 早退不残留随机 data_key
        let mut dk_buf = [0u8; 32];
        OsRng.fill_bytes(&mut dk_buf);
        let data_key = Zeroizing::new(dk_buf);
        let new_keys = expand_keys(&data_key)?;

        // 6. 加载旧索引（原文件此刻未被修改；审计随后换钥重建）
        let mut index = {
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            load_index_from_file(file, &old_enc_key, old_part.index_offset, old_part.index_length)?
        };
        let mut audit_log = AuditLog::from_entries(index.audit.clone(), old_auth_key);
        // 换钥前先用旧密钥硬校验整条链（篡改即中止，不静默截断），再重建
        audit_log.rekey(&old_auth_key, new_keys.auth_key)?;
        audit_log.add("修改密码并升级为 v5 信封加密");
        index.audit = audit_log.to_vec();

        // 7. 重加密管线（闭包内只读 self 的克隆值，不持有 &mut self）
        let alias_field = alias_field16(&old_part.alias);
        let salt = self.salt;
        let lock_state = self.lock_state.clone();
        let result = (|| -> Result<PartitionInfo, VaultError> {
            // 7a. 临时文件 + v5 占位头部
            let mut tmp_file = OpenOptions::new()
                .read(true).write(true).create_new(true)
                .open(&temp_path)?;
            tmp_file.write_all(&[0u8; HEADER_SIZE_V5])?;
            tmp_file.flush()?;

            // 7b. 逐文件解密 → 新密钥重加密（AAD 不变，密文长度不变，偏移重排）
            let files_snapshot: Vec<(String, u64, u64)> = index.files.iter()
                .map(|(k, m)| (k.clone(), m.offset, m.length))
                .collect();
            let total = files_snapshot.len();
            let mut src_file = File::open(&vault_path)?;
            let mut write_cursor = HEADER_SIZE_V5 as u64;
            for (i, (vpath, old_off, old_len)) in files_snapshot.iter().enumerate() {
                let aad_tag = index.files.get(vpath).and_then(|m| m.aad_tag.clone());
                let aad = aad_bytes(aad_tag.as_deref(), vpath).to_vec();
                src_file.seek(SeekFrom::Start(*old_off))?;
                let mut enc_old = vec![0u8; *old_len as usize];
                src_file.read_exact(&mut enc_old)?;
                // 2.8.1：decrypt_into/encrypt_into 消费并复用缓冲 ——
                // 旧实现每文件同时存在「密文 + 明文 + 新密文」三份全尺寸分配
                //（256MiB 文件峰值 768MiB），现在降为 ~1.5 份
                let plain = decrypt_into(&old_enc_key, enc_old, &aad)
                    .ok_or(VaultError::DecryptFailed)?;
                let enc_new = encrypt_into(&new_keys.enc_key, plain, &aad)?;
                tmp_file.seek(SeekFrom::Start(write_cursor))?;
                tmp_file.write_all(&enc_new)?;
                index.files.get_mut(vpath)
                    .ok_or_else(|| VaultError::Other("升级管线：文件不在索引中".into()))?
                    .offset = write_cursor;
                write_cursor += enc_new.len() as u64;
                if let Some(ref cb) = progress {
                    cb((i + 1) * 80 / total.max(1));
                }
            }
            drop(src_file);

            // 7c. 新索引（已含换钥后的审计链）
            let idx_json = serde_json::to_vec(&index)?;
            let enc_idx = encrypt_gcm(&new_keys.enc_key, &idx_json, b"index", None)?;
            tmp_file.seek(SeekFrom::Start(write_cursor))?;
            tmp_file.write_all(&enc_idx)?;
            tmp_file.flush()?;
            tmp_file.sync_all()?;
            secure_wipe_vec(idx_json);
            if let Some(ref cb) = progress {
                cb(90);
            }

            // 7d. 构建唯一的 v5 分区条目
            let mut new_part_salt = [0u8; 32];
            OsRng.fill_bytes(&mut new_part_salt);
            let mut kek = derive_kek(new_password, key_file_data, &new_part_salt)?;
            let prefix = auth_tag_header_prefix(&salt, VERSION_V5);
            let wrap_aad = key_wrap_aad(&prefix, &alias_field, &new_part_salt);
            let wrapped_v = encrypt_gcm(&kek, &data_key[..], &wrap_aad, None)?;
            let mut wrapped = [0u8; WRAPPED_KEY_SIZE];
            wrapped.copy_from_slice(&wrapped_v);
            kek.zeroize();
            secure_wipe_vec(wrapped_v);
            let auth_tag = bound_auth_tag(&new_keys.auth_key, &salt, VERSION_V5, &alias_field, &new_part_salt);
            let new_part = PartitionInfo {
                alias: old_part.alias.clone(),
                salt: new_part_salt,
                auth_tag,
                index_offset: write_cursor,
                index_length: enc_idx.len() as u64,
                wrapped_key: Some(wrapped),
            };

            // 7e. v5 头部（v4 布局的锁定区/签名随版本切换到新位置）
            write_header_to_file(&mut tmp_file, VERSION_V5, &lock_state, &salt, std::slice::from_ref(&new_part), &new_keys.sign_key)?;
            tmp_file.flush()?;
            tmp_file.sync_all()?;
            drop(tmp_file);
            if let Some(ref cb) = progress {
                cb(100);
            }

            // 7f. 2.8.1（事务化）：原子替换纳入事务闭包 —— 替换失败与之前任何
            // 一步失败一样走统一回滚（擦 .tmp/.bak、重开原文件）。旧实现在闭包
            // **之外**执行替换且 `?` 直接返回，绕过全部清理：失败时磁盘残留
            // 「.tmp（新密码全库）+ .bak（旧密码全库）」两份完整副本（抗取证死角），
            // 会话也停在 file=None 的半死状态。
            // 释放会话句柄（Windows rename 需 DELETE 权；Unix 需先放 flock）
            self.file = None;
            replace_vault_file(&temp_path, &vault_path)?;
            sync_parent_dir(&vault_path);
            Ok(new_part)
        })();

        match result {
            Ok(new_part) => {
                // 8. 备份已无用（替换已提交）：DoD 擦除（尽力而为）
                if let Err(e) = dod_erase(&backup_path, None) {
                    log::warn!("擦除升级备份失败（保险柜同目录可能残留 .bak 文件）: {}", e);
                }
                // 9. 重开句柄 + 会话切换到 v5。
                // 2.8.1（诚实报错）：替换已经提交 —— 此时磁盘必然已是 v5 新密码。
                // 重开若失败（如另一实例在句柄释放窗口抢锁），旧实现直接报错，
                // 用户会误以为「改密失败」而继续用旧密码。改为短重试后给出
                // 明确的「已生效、请重开」语义。
                let mut reopened: Option<File> = None;
                let mut last_err: Option<VaultError> = None;
                for _ in 0..3 {
                    match open_vault_rw(&vault_path, false) {
                        Ok(f) => match lock_vault_exclusive(&f) {
                            Ok(()) => {
                                reopened = Some(f);
                                break;
                            }
                            Err(e) => {
                                drop(f);
                                last_err = Some(e.into());
                            }
                        },
                        Err(e) => last_err = Some(e.into()),
                    }
                    std::thread::sleep(std::time::Duration::from_millis(150));
                }
                let file = reopened.ok_or_else(|| {
                    VaultError::Other(format!(
                        "密码修改已生效（旧密码已失效），但恢复会话失败（{}）。请用新密码重新打开保险柜",
                        last_err.map(|e| e.to_string()).unwrap_or_default()
                    ))
                })?;
                self.file = Some(file);
                self.format_version = VERSION_V5;
                self.data_key = Some(*data_key); // Zeroizing 解包存入会话
                self.enc_key = Some(new_keys.enc_key);
                self.auth_key = Some(new_keys.auth_key);
                self.sign_key = Some(new_keys.sign_key);
                self.partitions = vec![new_part];
                self.active_partition = Some(0);
                self.audit = Some(audit_log);
                self.cached_index = Some(index);
                self.audit_dirty = false; // 新索引（含审计）已随管线落盘
                let mut old_enc = old_enc_key;
                old_enc.zeroize();
                let mut old_auth = old_auth_key;
                old_auth.zeroize();
                Ok(())
            }
            Err(e) => {
                // 10. 回滚（2.8.1 重构）：原子替换已纳入闭包 —— 走到这里时
                // **替换要么未发生、要么原子失败即未生效**，原文件始终完好。
                // 旧实现在此处用备份 rename 覆盖原文件：内容虽相同，却把原文件的
                // ACL/属性丢成目录继承（replace_vault_file 恰是为了避免这一点）。
                // 现在只清理中间副本（含完整明文密文数据的 .tmp 与 .bak），再重开原文件。
                self.file = None;
                wipe_scratch_file(&temp_path);
                if backup_path.exists() {
                    if let Err(we) = dod_erase(&backup_path, None) {
                        log::warn!("擦除升级备份失败（将尝试直接删除）: {}", we);
                        let _ = fs::remove_file(&backup_path);
                    }
                }
                let file = open_vault_rw(&vault_path, false).ok().and_then(|f| {
                    lock_vault_exclusive(&f).ok()?;
                    Some(f)
                });
                self.file = file;
                Err(e)
            }
        }
    }

    // ═══════════════ 完整性体检 / 搜索 / 锁定信息（2.8.0）═══════════════

    /// 2.8.0：全库完整性体检 —— 逐文件解密校验 AES-GCM 认证标签，
    /// 检出坏块 / 位腐 / 云同步损坏。只读操作（不修改任何数据）。
    pub fn verify_integrity<F: Fn(usize, usize, &str)>(
        &mut self,
        progress: Option<F>,
    ) -> Result<(usize, Vec<IntegrityIssue>), VaultError> {
        if !self.is_open() {
            return Err(VaultError::NotOpen);
        }
        // 2.8.2：走只读借用（index_ref），免去整索引深拷贝
        let mut items: Vec<(String, u64, u64, Option<String>)> = {
            let index = self.index_ref()?;
            index.files.iter()
                .map(|(k, m)| (k.clone(), m.offset, m.length, m.aad_tag.clone()))
                .collect()
        };
        // 2.8.2：按物理偏移排序 —— 逐文件解密时对保险柜文件顺序读
        //（HDD / 网络盘收益明显），旧实现按路径排序导致随机跳转
        items.sort_by_key(|x| x.1);
        let total = items.len();
        let enc_key = *self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let mut broken: Vec<IntegrityIssue> = Vec::new();
        for (i, (vpath, off, len, aad_tag)) in items.iter().enumerate() {
            if let Some(ref cb) = progress {
                cb(i + 1, total, vpath);
            }
            let aad = aad_bytes(aad_tag.as_deref(), vpath).to_vec();
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            match read_decrypt_file_data(file, &enc_key, *off, *len, &aad) {
                Ok(plain) => secure_wipe_vec(plain),
                Err(e) => broken.push(IntegrityIssue { vpath: vpath.clone(), reason: e.to_string() }),
            }
        }
        self.log_event(&format!("完整性体检：{} 个文件，{} 个异常", total, broken.len()));
        Ok((total, broken))
    }

    /// 2.8.0：按文件名 / vpath 大小写不敏感子串搜索（含文件夹，文件夹在前）。
    /// 2.8.1（性能）：改为**借用**内存缓存（旧实现每次搜索深拷贝整个索引，
    /// 10 万条目 ≈ 每次击键 20-30 万次分配）；大小写折叠走原地 ASCII 折叠
    ///（复用单个缓冲，热路径零分配；CJK 等无大小写字符不受影响）。
    pub fn search_files(&self, query: &str, limit: usize) -> Vec<SearchHit> {
        let Some(index) = self.cached_index.as_ref() else {
            return Vec::new();
        };
        let q = query.trim();
        if q.is_empty() {
            return Vec::new();
        }
        let q_lower = q.to_lowercase();
        // 大小写不敏感匹配（2.8.2 修正 2.8.1 的回归）：先做零分配的
        // 大小写敏感匹配（小写名/中文命中绝大多数查询），未命中再做原地
        // ASCII 折叠；2.8.1 只做了 ASCII 折叠，导致 É↔é、К↔к 等非 ASCII
        // 大小写变形不再命中 —— 现对含大写非 ASCII 字符的候选补一次完整的
        // Unicode 折叠（这类候选是少数，均摊成本可控）。
        fn contains_ci(buf: &mut String, haystack: &str, needle: &str, needle_lower: &str) -> bool {
            if haystack.contains(needle) {
                return true;
            }
            buf.clear();
            buf.push_str(haystack);
            buf.as_mut_str().make_ascii_lowercase();
            if buf.contains(needle_lower) {
                return true;
            }
            // 存在非 ASCII 大写字符 → ASCII 折叠不够，完整 Unicode 折叠后再试
            if haystack.chars().any(|c| c.is_uppercase()) {
                buf.clear();
                buf.push_str(&haystack.to_lowercase());
                return buf.contains(needle_lower);
            }
            false
        }
        let mut fold_buf = String::new();
        let mut hits: Vec<SearchHit> = Vec::new();
        for (vpath, m) in &index.files {
            if contains_ci(&mut fold_buf, vpath, q, &q_lower)
                || contains_ci(&mut fold_buf, &m.name, q, &q_lower)
            {
                hits.push(SearchHit { vpath: vpath.clone(), name: m.name.clone(), size: m.size, is_dir: false });
            }
        }
        for vpath in index.folders.keys() {
            if contains_ci(&mut fold_buf, vpath, q, &q_lower) {
                let name = vpath.rsplit('/').next().unwrap_or(vpath).to_string();
                hits.push(SearchHit { vpath: vpath.clone(), name, size: 0, is_dir: true });
            }
        }
        hits.sort_by(|a, b| {
            b.is_dir.cmp(&a.is_dir).then_with(|| a.vpath.cmp(&b.vpath))
        });
        hits.truncate(limit);
        hits
    }

    /// 2.8.0：列出当前分区全部文件夹 vpath（移动选择器用，已排序）。
    /// 2.8.2：走只读借用（index_ref），免去整索引深拷贝。
    pub fn list_all_folders(&self) -> Result<Vec<String>, VaultError> {
        let index = self.index_ref()?;
        let mut v: Vec<String> = index.folders.keys().cloned().collect();
        v.sort();
        Ok(v)
    }

    // ═══════════════ 文件导入 ═══════════════

    /// 导入单个文件（独立命令路径：加载缓存索引 → 写入 → 单次 save_index）。
    pub fn import_file(&mut self, src_path: &Path, vpath: &str) -> Result<(), VaultError> {
        let mut index = self.load_index()?;
        self.import_file_into_index(&mut index, src_path, vpath, true)?;
        self.save_index(index)
    }

    /// 2.4.1 新增：批量导入多个文件（P0-2 优化核心）。
    /// 单次 load_index（缓存）+ 内存更新 + **一次** save_index。
    /// 旧实现（前端循环调用 import_file）N 个文件 = N 次全量索引重写
    /// + N×10 次 fsync；现在批量路径只有 1 次。
    ///
    /// 返回 (成功数, 失败数, 失败明细)。单个文件失败记录日志后继续。
    /// 2.8.2：新增条目数上限与失败明细返回 —— 旧实现只返回计数，注释声称
    /// 「明细已反馈前端」但根本没有明细出口。
    pub fn import_files_batch(
        &mut self,
        src_paths: &[String],
        dest_base: &str,
    ) -> Result<(usize, usize, Vec<String>), VaultError> {
        if src_paths.len() > MAX_IMPORT_ENTRIES {
            return Err(VaultError::Other(format!(
                "单次导入条目数超过安全上限（{}）",
                MAX_IMPORT_ENTRIES
            )));
        }
        let mut index = self.load_index()?;
        let base_clean = dest_base.trim_end_matches('/');
        let mut ok = 0usize;
        let mut fail = 0usize;
        let mut errors: Vec<String> = Vec::new();
        for p in src_paths {
            let src = std::path::Path::new(p);
            let name = src.file_name().unwrap_or_default().to_string_lossy().to_string();
            let vpath = format!("{}/{}", base_clean, name);
            match self.import_file_into_index(&mut index, src, &vpath, false) {
                Ok(()) => ok += 1,
                Err(e) => {
                    fail += 1;
                    errors.push(format!("{}: {}", name, e));
                    // 2.8.1：不再把含 vpath 的错误写入明文日志（违反 2.6.1 自定规则），
                    // 失败明细经返回值反馈给前端逐项展示
                    log::warn!("批量导入有失败项（明细已随返回值反馈）");
                }
            }
        }
        // 2.4.1（P1-14）：批量操作记一条摘要审计，不再逐文件刷审计链
        if ok > 0 || fail > 0 {
            self.log_event(&format!("批量导入：成功 {} 个，失败 {} 个", ok, fail));
        }
        if ok > 0 {
            // 2.8.2：批量路径的密文写入省掉了逐文件 fsync —— save_index 的
            // sync_all 作用于同一句柄，会连带刷出全部已写密文，崩溃安全不变
            self.save_index(index)?;
        }
        Ok((ok, fail, errors))
    }

    /// 2.4.1 新增（从 import_file 抽取）：把一个文件加密追加到保险柜并更新**内存中的**索引。
    /// 不写盘、不审计 —— 由调用方决定单文件（import_file：逐次落盘）
    /// 或批量（import_files_batch / import_folder：最后一次落盘）策略。
    /// 2.8.2：`sync_each` 控制是否逐文件 fsync —— 批量路径传 false，由调用方在
    /// save_index 时统一 sync_all（同句柄 sync_all 会连带刷出全部已写密文），
    /// 千文件批量导入从 N 次 fsync 降为 1 次。
    fn import_file_into_index(
        &mut self,
        index: &mut Index,
        src_path: &Path,
        vpath: &str,
        sync_each: bool,
    ) -> Result<(), VaultError> {
        // M5 修复：归一化 + 校验虚拟路径（2.8.2：收敛到 clean_vpath 单一来源）
        let vpath = Index::clean_vpath(vpath)
            .ok_or_else(|| VaultError::Other("无效的虚拟路径".into()))?;

        // C5 修复：检查重名，避免静默覆盖
        // 2.8.1：同时检查文件夹命名空间 —— file/folder 同名碰撞会让
        // rename/delete/move 的语义变得含混（两套删除实现对同一 vpath 行为不同）
        if index.files.contains_key(&vpath) {
            return Err(VaultError::Other(format!("目标路径已存在: {}", vpath)));
        }
        if index.folders.contains_key(&vpath) {
            return Err(VaultError::Other(format!(
                "目标路径已存在同名文件夹，无法导入为文件: {}", vpath
            )));
        }

        // 2.7.0 修复（TOCTOU）：旧实现「fs::metadata 查大小 → fs::read 整读」，
        // 两步之间源文件可被替换/膨胀，fs::read 会按实际内容无限分配内存（OOM）。
        // 现改为句柄化读取：按元数据预分配（封顶 MAX_INMEM_BUFFER），并用
        // take(MAX+1) 硬性限制读取总量，读取后超限即拒绝 —— 无论文件中途如何
        // 变化，分配都有上界。
        let src_file = open_import_source(src_path)?;
        let src_meta = src_file.metadata()?;
        if src_meta.len() > MAX_INMEM_BUFFER as u64 {
            return Err(VaultError::Other(format!(
                "文件过大（{} 字节），超过单次导入上限 {} 字节",
                src_meta.len(), MAX_INMEM_BUFFER
            )));
        }
        let mut data = Vec::with_capacity(
            std::cmp::min(src_meta.len() as usize, MAX_INMEM_BUFFER),
        );
        if let Err(e) = (&src_file)
            .take((MAX_INMEM_BUFFER as u64) + 1)
            .read_to_end(&mut data)
        {
            secure_wipe_vec(data); // 读到一半失败的明文也一并零化
            return Err(e.into());
        }
        drop(src_file);
        if data.len() > MAX_INMEM_BUFFER {
            secure_wipe_vec(data);
            return Err(VaultError::Other(format!(
                "文件过大（读取时超过 {} 字节），超过单次导入上限",
                MAX_INMEM_BUFFER
            )));
        }
        let size = data.len() as u64;
        let name = src_path.file_name()
            .unwrap_or_default().to_string_lossy().to_string();

        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let encrypted = encrypt_gcm(enc_key, &data, vpath.as_bytes(), None)?;

        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(&encrypted)?;
        if sync_each {
            file.flush()?;
            file.sync_all()?;
        }

        // 直接更新内存索引（与 IndexManager::add_file 相同语义），
        // 由调用方统一 save_index
        index.files.insert(
            vpath.clone(),
            FileMeta {
                name,
                size,
                offset,
                length: encrypted.len() as u64,
                // 冻结导入时的 vpath 作为 AAD，此后重命名不再影响解密
                aad_tag: Some(vpath.clone()),
            },
        );
        if let Some(pos) = vpath.rfind('/') {
            if pos > 0 {
                index.folders.insert(vpath[..pos].to_string(), true);
            }
        }
        secure_wipe_vec(data);
        Ok(())
    }

    /// 2.5.1 新增：原地更新文件内容（TXT 编辑保存路径）。
    ///
    /// 安全顺序与 secure_delete_file 一致：
    /// 1. 加密新内容追加到文件末尾；
    /// 2. 更新索引指向新密文位置并 save_index（先落盘）；
    /// 3. DoD 7-pass 覆写旧密文区段（失败时残留无害 —— 索引已指向新位置）。
    ///
    /// 任何时点崩溃，索引要么仍指向旧密文（内容未变），要么已指向新密文，
    /// 不会出现索引指向半损坏密文的永久损坏。
    pub fn update_file_content(&mut self, vpath: &str, data: &[u8]) -> Result<(), VaultError> {
        let vpath = Index::normalize_vpath(vpath)
            .filter(|p| Index::validate_vpath(p))
            .ok_or_else(|| VaultError::Other("无效的虚拟路径".into()))?;

        // 防御性上限（调用方 commands.rs 已按 64MB 预检，此处兜底）
        if data.len() > MAX_INMEM_BUFFER {
            return Err(VaultError::Other(format!(
                "内容过大（{} 字节），超过单次写入上限",
                data.len()
            )));
        }

        let mut index = self.load_index()?;
        let meta = index.files.get(&vpath)
            .ok_or_else(|| VaultError::Other("文件不存在".into()))?
            .clone();

        // 加密新内容：AAD 用导入时冻结的标识（旧索引回退到当前 vpath）。
        // 这里刻意不用当前 vpath —— 否则「重命名后再保存」会把 AAD 悄悄改成新路径，
        // 看起来自愈，实际是又一次把 AAD 绑回可变标识。
        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let encrypted = encrypt_gcm(enc_key, data, aad_bytes(meta.aad_tag.as_deref(), &vpath), None)?;

        // 追加新密文到文件末尾
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(&encrypted)?;
        file.flush()?;
        file.sync_all()?;

        // 索引改指向新密文（保留原文件名）
        index.files.insert(
            vpath.clone(),
            FileMeta {
                name: meta.name,
                size: data.len() as u64,
                offset,
                length: encrypted.len() as u64,
                // 沿用原有冻结标识（旧索引为 None），不因保存内容而重新绑定
                aad_tag: meta.aad_tag,
            },
        );

        self.log_event(&format!("更新文件内容 '{}'", vpath));
        self.save_index(index)?;

        // 索引已安全落盘，覆写旧密文（失败残留无害）
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = dod_overwrite_range(file, meta.offset, meta.length) {
                log::warn!("覆写旧密文失败（残留无害）: {}", e);
            }
            let _ = file.flush();
            let _ = file.sync_all();
        }
        Ok(())
    }

    /// 2.4.1 重写（P0-2）：文件夹导入改为两阶段 ——
    /// 阶段 1 纯文件系统遍历收集 (源路径, 目标虚拟路径)；
    /// 阶段 2 用**单份内存索引**逐文件加密追加，最后一次性 save_index。
    /// 旧实现每导入一个文件都 load_index ×2 + save_index 全量重写一次，
    /// 1000 个文件 ≈ 2000 次解密加载 + 1000 次全量索引写 + 7000+ 次 fsync。
    /// 返回 (成功数, 失败数, 跳过的符号链接数)。
    /// 2.8.2 修复两点：① 空目录（或全部内容都是符号链接）也会登记文件夹
    /// 条目 —— 旧实现静默丢弃，用户以为导入成功却什么都没有；② 符号链接
    /// 跳过数真实计入返回值（旧日志谎称「已计入失败计数」）。
    pub fn import_folder(&mut self, src: &Path, base: &str) -> Result<(usize, usize, usize), VaultError> {
        let source_meta = fs::symlink_metadata(src)?;
        if source_meta.file_type().is_symlink() || !source_meta.is_dir() {
            return Err(VaultError::Other("导入源必须是非链接目录".into()));
        }
        let base_name = src.file_name()
            .unwrap_or_default().to_string_lossy().to_string();
        let base_clean = base.trim_end_matches('/');

        // 阶段 1：收集（无 self 借用，纯遍历）
        let mut collected: Vec<(PathBuf, String)> = Vec::new();
        let mut entries_seen = 0usize;
        let mut skipped_symlinks = 0usize;
        Self::collect_import_files(
            src,
            &format!("{}/{}", base_clean, base_name),
            0,
            &mut entries_seen,
            &mut collected,
            &mut skipped_symlinks,
        )?;

        // 阶段 2：单份索引逐文件导入，最后一次落盘
        let mut index = self.load_index()?;

        // 2.8.2：根文件夹条目先登记（空目录也要有）；若同名**文件**已存在
        // 则是命名空间碰撞，明确拒绝
        let root_vpath = Index::clean_vpath(&format!("{}/{}", base_clean, base_name))
            .ok_or_else(|| VaultError::Other("无效的目标路径".into()))?;
        if index.files.contains_key(&root_vpath) {
            return Err(VaultError::Other(format!(
                "目标路径已存在同名文件，无法导入为文件夹: {}", root_vpath
            )));
        }
        let root_folder_new = !index.folders.contains_key(&root_vpath);
        if root_folder_new {
            index.folders.insert(root_vpath, true);
        }

        if collected.is_empty() {
            // 空目录：仅登记文件夹本身
            self.log_event(&format!(
                "导入空文件夹 '{}'（含 0 个文件，跳过 {} 个符号链接）",
                base_name, skipped_symlinks
            ));
            self.save_index(index)?;
            return Ok((0, 0, skipped_symlinks));
        }

        let mut ok = 0usize;
        let mut fail = 0usize;
        let mut errors: Vec<String> = Vec::new();
        for (src_path, dest_vpath) in collected {
            match self.import_file_into_index(&mut index, &src_path, &dest_vpath, false) {
                Ok(()) => ok += 1,
                Err(e) => {
                    fail += 1;
                    errors.push(format!("{}: {}", dest_vpath.rsplit('/').next().unwrap_or(""), e));
                    // 2.8.1：不再把含 vpath 的错误写入明文日志（违反 2.6.1 自定规则），
                    // 失败明细经返回值反馈给前端逐项展示
                    log::warn!("批量导入有失败项（明细已随返回值反馈）");
                }
            }
        }
        self.log_event(&format!(
            "导入文件夹 '{}'：成功 {} 个文件，失败 {} 个，跳过 {} 个符号链接",
            base_name, ok, fail, skipped_symlinks
        ));
        // 2.8.2：失败但根文件夹是新登记时也要落盘（保持「文件夹已导入」语义）
        if ok > 0 || root_folder_new {
            if ok > 0 {
                let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
                file.flush()?;
                file.sync_all()?;
            }
            self.save_index(index)?;
        }
        Ok((ok, fail, skipped_symlinks))
    }

    /// 2.4.1 新增：递归收集待导入文件（原 walk_import 的遍历部分，去掉了 self 依赖）。
    /// 2.8.2：`skipped_symlinks` 真实统计跳过的符号链接数。
    fn collect_import_files(
        current: &Path,
        dest_root: &str,
        depth: usize,
        entries_seen: &mut usize,
        out: &mut Vec<(PathBuf, String)>,
        skipped_symlinks: &mut usize,
    ) -> Result<(), VaultError> {
        if depth > MAX_IMPORT_DEPTH {
            return Err(VaultError::Other("导入目录层级超过安全上限".into()));
        }
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            *entries_seen += 1;
            if *entries_seen > MAX_IMPORT_ENTRIES {
                return Err(VaultError::Other("导入项目数量超过安全上限".into()));
            }
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.file_type().is_symlink() {
                *skipped_symlinks += 1;
                log::warn!("跳过符号链接（未计入失败项，已随返回值反馈）");
                continue;
            }
            let name = path.file_name()
                .unwrap_or_default().to_string_lossy().to_string();
            let dest_path = format!("{}/{}", dest_root, name);
            if meta.is_dir() {
                Self::collect_import_files(&path, &dest_path, depth + 1, entries_seen, out, skipped_symlinks)?;
            } else if meta.is_file() {
                out.push((path, dest_path));
            }
        }
        Ok(())
    }

    // ═══════════════ 文件提取 ═══════════════

    /// 2.4.1 新增（P1-12）：批量提取前的目标根目录准备（创建 + 规范化，只做一次）。
    /// 旧实现在 extract_file_inner 里对**每个文件**做 canonicalize，
    /// 批量提取 1000 个文件 = 2000 次冗余系统调用。
    fn prepare_dest_root(dest_folder: &Path) -> Result<PathBuf, VaultError> {
        fs::create_dir_all(dest_folder)?;
        fs::canonicalize(dest_folder)
            .map_err(|_| VaultError::Other("目标目录无法访问".into()))
    }

    /// 提取单个文件。2.4.1：`overwrite` 参数显式控制覆盖语义
    /// （true = 覆盖已存在文件；false = 拒绝并报错，与旧行为一致）。
    ///
    /// 2.5.1 变更：单文件提取**直接放入目标目录**，不再重建其在保险柜内的
    /// 上级目录结构 —— 旧行为提取 /docs/readme.txt 到 D:\out 会生成
    /// D:\out\docs\readme.txt，只提取一个文件也要套一层同名文件夹；
    /// 现在结果为 D:\out\readme.txt。多选批量提取与「提取全部」仍保留完整
    /// 目录结构（避免不同子目录的同名文件在目标根冲突）。
    pub fn extract_file(
        &mut self,
        vpath: &str,
        dest_folder: &Path,
        overwrite: bool,
    ) -> Result<(), VaultError> {
        // 单次 load_index：获取文件名、密文位置和冻结的 AAD 标识
        let (file_name, offset, length, aad_tag) = {
            let index = self.load_index()?;
            let meta = index.files.get(vpath)
                .ok_or_else(|| VaultError::Other("文件不存在".into()))?;
            (meta.name.clone(), meta.offset, meta.length, meta.aad_tag.clone())
        };
        let dest_abs = Self::prepare_dest_root(dest_folder)?;
        let aad = aad_bytes(aad_tag.as_deref(), vpath);
        // 委托给内部实现（rel_dir 传空 = 直接放入目标目录，见上方 2.5.1 说明）
        self.extract_file_inner(vpath, "", &file_name, offset, length, aad, &dest_abs, overwrite)?;
        // 2.4.1（P1-14）：审计移到调用方 —— 批量提取只记一条摘要
        self.log_event(&format!("提取文件 '{}'", vpath));
        Ok(())
    }

    /// 内部提取实现：已从索引中取出元数据，不再重复 load_index。
    /// 2.4.1 变更：
    /// - `dest_abs` 由调用方提前规范化和校验（P1-12），此处只对非空相对子目录
    ///   做符号链接防御；
    /// - `overwrite` 控制覆盖语义（P0-5）：旧实现固定 create_new 拒绝覆盖，
    ///   与前端「继续提取将覆盖同名文件」确认文案矛盾 —— 用户确认后反而大批失败；
    /// - 成功审计移至调用方（P1-14）；
    /// - `aad` 由调用方用 `aad_bytes` 求值后传入（优先索引里冻结的 aad_tag），
    ///   不能再拿 vpath 现算 —— vpath 可能已被重命名。
    #[allow(clippy::too_many_arguments)] // 2.8.1：历史稳定内部 API，拆参数结构收益为负
    fn extract_file_inner(
        &mut self,
        vpath: &str,
        rel_dir: &str,
        file_name: &str,
        offset: u64,
        length: u64,
        aad: &[u8],
        dest_abs: &Path,
        overwrite: bool,
    ) -> Result<(), VaultError> {

        // 解密文件数据
        let data = {
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
            read_decrypt_file_data(file, enc_key, offset, length, aad)?
        };

        let safe_name = sanitize_filename(file_name);

        let rel_path: PathBuf = rel_dir
            .split('/')
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
            .map(sanitize_filename)
            .collect();

        let output_dir = if rel_path.components().count() > 0 {
            dest_abs.join(&rel_path)
        } else {
            dest_abs.to_path_buf()
        };
        fs::create_dir_all(&output_dir)?;
        // 仅当存在相对子目录时才需要 canonicalize 防符号链接逃逸；
        // 目标根目录已由 prepare_dest_root 规范化（P1-12）
        let output_dir_abs = if rel_path.components().count() > 0 {
            let abs = fs::canonicalize(&output_dir)
                .map_err(|_| VaultError::Other("输出目录无法访问".into()))?;
            if !path_within(&abs, dest_abs) {
                secure_wipe_vec(data);
                return Err(VaultError::Other("输出目录包含符号链接".into()));
            }
            abs
        } else {
            output_dir
        };

        let dest_path = output_dir_abs.join(&safe_name);

        // 路径遍历防护：验证最终路径在目标目录下
        if !path_within(&dest_path, dest_abs) {
            self.log_event(&format!("拦截路径遍历攻击: '{}'", vpath));
            secure_wipe_vec(data);
            return Err(VaultError::Other("路径遍历攻击已拦截".into()));
        }

        // C8 修复（强化）：使用 O_NOFOLLOW 打开目标文件，防止 TOCTOU 符号链接竞态。
        // 旧实现在 Windows 上仅检查-再-write，存在时间窗口。
        // 现在两端都使用 NO_FOLLOW 等价标志打开。
        // 2.4.1（P0-5）：overwrite=true 时用 create+truncate（仍带 NO_FOLLOW），
        // 让「提取全部」的覆盖确认框名副其实。
        // 2.8.2：删除「写入后验证仍是普通文件」的不实注释 —— 实现从未做该验证，
        // 防护依赖打开标志本身（重解析点在打开时即被拒绝或以本体形式打开）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = OpenOptions::new();
            opts.write(true).custom_flags(libc::O_NOFOLLOW);
            if overwrite {
                opts.create(true).truncate(true);
            } else {
                opts.create_new(true);
            }
            let mut f = opts
                .open(&dest_path)
                .map_err(|_| VaultError::Other("目标文件已存在或路径异常（符号链接？）".into()))?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            // FILE_FLAG_OPEN_REPARSE_POINT prevents following a final reparse point.
            use std::os::windows::fs::OpenOptionsExt;
            let mut opts = OpenOptions::new();
            opts.write(true).custom_flags(0x00200000 | 0x08000000);
            if overwrite {
                opts.create(true).truncate(true);
            } else {
                opts.create_new(true);
            }
            let mut f = opts
                .open(&dest_path)
                .map_err(|_| VaultError::Other("目标文件已存在或路径异常（重解析点？）".into()))?;
            f.write_all(&data)?;
            f.sync_all()?;
        }

        secure_wipe_vec(data);
        Ok(())
    }

    // ═══════════════ 文件删除 ═══════════════

    /// 估算单分区保险柜的死空间(文件中已被安全擦除、但仍占位的空间总量):
    /// 文件长度 − 头部 − 活跃分区索引长度 − 全部有效文件密文长度。
    /// 多分区保险柜无法得知其他分区的死区,返回 None(自动整理跳过)。
    fn estimate_dead_bytes(&self) -> Option<u64> {
        if self.partitions.len() != 1 {
            return None;
        }
        let file_len = self.file.as_ref()?.metadata().ok()?.len();
        let index = self.cached_index.as_ref()?;
        let used = index
            .files
            .values()
            .fold(0u64, |acc, m| acc.saturating_add(m.length));
        let dead = file_len
            .saturating_sub(header_size_of(self.format_version).ok()? as u64)
            .saturating_sub(self.partitions[0].index_length)
            .saturating_sub(used);
        Some(dead)
    }

    /// 2.7.0 新增:删除类操作末尾调用。死空间达到阈值时自动执行一次紧凑整理,
    /// 把已擦除区域从文件中物理移除(抗取证:死区尽快从磁盘上消失)。
    /// 返回 Some(回收字节数) 表示已整理;未达阈值 / 多分区 / 估算失败返回 None。
    fn auto_defragment_if_worthwhile(&mut self) -> Result<Option<u64>, VaultError> {
        let Some(dead) = self.estimate_dead_bytes() else {
            return Ok(None);
        };
        if dead < AUTO_DEFRAG_MIN_DEAD_BYTES {
            return Ok(None);
        }
        let file_len = self
            .file
            .as_ref()
            .ok_or(VaultError::NotOpen)?
            .metadata()?
            .len();
        if dead.saturating_mul(AUTO_DEFRAG_DEAD_RATIO_DEN)
            < file_len.saturating_mul(AUTO_DEFRAG_DEAD_RATIO_NUM)
        {
            return Ok(None); // 死空间占比不足 30%,攒一攒再整理
        }
        self.defragment_vault(None::<fn(usize)>)?;
        self.log_event(&format!("自动整理保险柜:回收约 {} 字节死空间", dead));
        Ok(Some(dead))
    }

    pub fn secure_delete_file(&mut self, vpath: &str) -> Result<Option<u64>, VaultError> {
        // 2.7.1 修复：删除入口统一走 normalize_vpath —— 旧实现只有 delete_folder
        // 去过尾斜杠，`/docs//a.txt`、`/docs/./a.txt` 之类输入会「文件不存在」静默失配
        let vpath = Index::normalize_vpath(vpath)
            .filter(|p| Index::validate_vpath(p))
            .ok_or_else(|| VaultError::Other("无效的虚拟路径".into()))?;
        // 2.3.0 顺序修正：先更新索引并 save_index（标记已删除），再覆写密文。
        // 旧实现先擦密文后存索引，中途崩溃会让索引仍指向已损坏的密文 → GCM 认证失败 → 永久损坏。
        // 与 secure_delete_files_batch 的「先存索引再擦密文」策略保持一致。
        let mut index = self.load_index()?;
        let meta = index.files.get(&vpath)
            .ok_or_else(|| VaultError::Other("文件不存在".into()))?
            .clone();
        index.files.remove(&vpath);
        self.log_event(&format!("安全删除文件 '{}'", vpath));
        self.save_index(index)?;

        // 覆写密文（尽力而为：失败时密文残留无害，索引已不指向）
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = dod_overwrite_range(file, meta.offset, meta.length) {
                log::warn!("覆写密文失败（残留无害）: {}", e);
            }
            let _ = file.flush();
            let _ = file.sync_all();
        }

        Ok(self.auto_defragment_if_worthwhile().unwrap_or_else(|e| {
            log::warn!("删除后自动整理失败（不影响删除结果）: {}", e);
            None
        }))
    }

    pub fn delete_folder(&mut self, vpath: &str) -> Result<Option<u64>, VaultError> {
        // 2.7.1 修复：带尾斜杠的删除请求 `delete_folder("/a/")` 会得到前缀 "/a//"，
        // 一个文件都没删却返回成功 —— 入口统一按索引键规则归一化；删除根目录
        // 改为明确报错（不再静默全删）
        let vpath = Index::normalize_vpath(vpath)
            .filter(|p| Index::validate_vpath(p))
            .ok_or_else(|| VaultError::Other("无效的虚拟路径".into()))?;
        if vpath == "/" {
            return Err(VaultError::Other("拒绝删除根目录".into()));
        }
        let prefix = format!("{}/", vpath);

        // 1. 一次性加载索引，收集所有需要移除的条目
        let mut index = self.load_index()?;

        let files_to_wipe: Vec<(String, u64, u64)> = index.files.iter()
            .filter(|(k, _)| k.starts_with(&prefix) || **k == vpath)
            .map(|(k, m)| (k.clone(), m.offset, m.length))
            .collect();

        // 2. 先从索引中批量移除（一次 save_index；与 secure_delete_files_batch 同策略）
        for (vpath_key, _, _) in &files_to_wipe {
            index.files.remove(vpath_key);
        }

        let dirs_to_delete: Vec<String> = index.folders.keys()
            .filter(|d| d.starts_with(&prefix))
            .cloned()
            .collect();
        for d in dirs_to_delete {
            index.folders.remove(&d);
        }
        if vpath != "/" {
            index.folders.remove(&vpath);
        }

        self.log_event(&format!("删除文件夹 '{}'（含 {} 个文件）", vpath, files_to_wipe.len()));
        self.save_index(index)?;

        // 3. 索引已安全落盘后再批量覆写密文（失败残留无害）
        for (_, offset, length) in &files_to_wipe {
            if let Some(file) = self.file.as_mut() {
                if let Err(e) = dod_overwrite_range(file, *offset, *length) {
                    log::warn!("覆写密文失败（残留无害）: {}", e);
                }
            }
        }
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
            let _ = file.sync_all();
        }

        Ok(self.auto_defragment_if_worthwhile().unwrap_or_else(|e| {
            log::warn!("删除后自动整理失败（不影响删除结果）: {}", e);
            None
        }))
    }

    /// 批量安全删除多个文件/文件夹（DoD 7-pass 覆写密文 + 索引移除）。
    ///
    /// 关键安全顺序：**先更新索引 + save_index（标记为已删除），再覆写密文**。
    /// 这样即使覆写过程中磁盘满/断电，索引已安全落盘：
    /// - 已被覆写的文件：索引已删除，不可达，碎片整理可清理
    /// - 未被覆写的文件：索引已删除，不可达，密文残留不影响功能
    ///
    /// 旧实现先覆写后 save_index，覆写中途失败会导致索引仍指向已损坏密文 → GCM 认证失败 → 永久损坏。
    ///
    /// 2.4.1 变更：
    /// - P1-11：旧实现对**每个**选中的文件夹都全表扫描一遍索引（选 m 个文件夹
    ///   = O(n×m)）；现在先分类一次（直接文件集合 + 文件夹前缀集合），再**单遍**
    ///   扫描索引判断归属，复杂度 O(n+m)。
    /// - P1-14：逐文件审计改为一条摘要审计（旧实现删 1000 个文件会追加 2000+ 条
    ///   审计，索引与 HMAC 链同步膨胀）。
    /// - 返回 (删除文件数, 删除文件夹数, Some(自动整理回收字节数))，供 UI 精确反馈。
    ///   2.7.0 起：删除完成后若死空间达到自动整理阈值（见 auto_defragment_if_worthwhile），
    ///   会追加一次紧凑整理并物理回收空间。
    pub fn secure_delete_files_batch(
        &mut self,
        vpaths: &[String],
    ) -> Result<(usize, usize, Option<u64>), VaultError> {
        let mut index = self.load_index()?;

        // 1. 分类：直接文件 → 集合；文件夹 → 前缀（含自身匹配）
        let mut direct_files: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut folder_prefixes: Vec<String> = Vec::new();
        let mut folder_self: std::collections::HashSet<&str> = std::collections::HashSet::new();
        // 归一化结果统一落到这里（String），随后的分类只借用
        let mut normalized: Vec<String> = Vec::with_capacity(vpaths.len());
        for vp in vpaths {
            // 2.7.1 修复：入口统一按索引键规则归一化（与 secure_delete_file /
            // delete_folder 一致），`/docs//a.txt` 之类输入不再静默失配
            match Index::normalize_vpath(vp) {
                Some(p) if Index::validate_vpath(&p) && p != "/" => normalized.push(p),
                _ => continue,
            }
        }
        for vp_norm in &normalized {
            if index.files.contains_key(vp_norm.as_str()) {
                direct_files.insert(vp_norm.as_str());
            } else if index.folders.contains_key(vp_norm.as_str()) {
                folder_prefixes.push(format!("{}/", vp_norm));
                folder_self.insert(vp_norm.as_str());
            }
            // 既不是文件也不是文件夹的 vpath 静默跳过（防御性）
        }
        if direct_files.is_empty() && folder_prefixes.is_empty() {
            return Ok((0, 0, None));
        }

        // 2. 单遍扫描索引：命中「直接文件」或「任一文件夹前缀」即收集
        //    R6：HashSet 去重，防嵌套选中（/a + /a/b）重复收集
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut to_wipe: Vec<(String, u64, u64)> = Vec::new();
        for (k, m) in &index.files {
            let hit = direct_files.contains(k.as_str())
                || folder_prefixes.iter().any(|p| k.starts_with(p.as_str()));
            if hit && seen.insert(k.clone()) {
                to_wipe.push((k.clone(), m.offset, m.length));
            }
        }
        let mut folders_to_delete: Vec<String> = Vec::new();
        for d in index.folders.keys() {
            let hit = folder_self.contains(d.as_str())
                || folder_prefixes.iter().any(|p| d.starts_with(p.as_str()));
            if hit && seen.insert(d.clone()) {
                folders_to_delete.push(d.clone());
            }
        }

        if to_wipe.is_empty() && folders_to_delete.is_empty() {
            return Ok((0, 0, None));
        }

        // 3. 先从索引移除所有文件和文件夹（一次 save_index）+ 摘要审计（P1-14）
        for (vp, _, _) in &to_wipe {
            index.files.remove(vp);
        }
        for d in &folders_to_delete {
            index.folders.remove(d);
        }
        self.log_event(&format!(
            "批量安全删除：{} 个文件，{} 个文件夹",
            to_wipe.len(),
            folders_to_delete.len()
        ));
        self.save_index(index)?;

        // 4. 索引已安全落盘后再批量 DoD 7-pass 覆写密文
        //    此时即使覆写失败，索引已不指向这些 offset，不会导致数据损坏
        for (_, offset, length) in &to_wipe {
            if let Some(file) = self.file.as_mut() {
                // 单个覆写失败不影响整体，密文残留无害（索引已删除）
                if let Err(e) = dod_overwrite_range(file, *offset, *length) {
                    log::warn!("覆写密文失败（残留无害）: {}", e);
                }
            }
        }
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
            let _ = file.sync_all();
        }

        let reclaimed = self.auto_defragment_if_worthwhile().unwrap_or_else(|e| {
            log::warn!("删除后自动整理失败（不影响删除结果）: {}", e);
            None
        });

        Ok((to_wipe.len(), folders_to_delete.len(), reclaimed))
    }

    // ═══════════════ 文件读取 ═══════════════

    pub fn load_file_data(&mut self, vpath: &str) -> Result<Vec<u8>, VaultError> {
        let (offset, length, aad_tag) = {
            let index = self.load_index()?;
            let meta = index.files.get(vpath)
                .ok_or_else(|| VaultError::Other("文件不存在".into()))?;
            (meta.offset, meta.length, meta.aad_tag.clone())
        };
        // M1 修复：超大文件拒绝全量加载（避免 OOM + Tauri IPC 膨胀）
        // 2.8.2：改用 u64 比较 —— 旧写法 `length as usize` 在 32 位目标上会
        // 回绕（大 u64 变小 usize）使该检查失效（真正的防线在
        // read_decrypt_file_data 内，这里属于纵深防御，因此修正而非删除）
        if length > MAX_INMEM_BUFFER as u64 {
            return Err(VaultError::Other(format!(
                "文件过大（{} 字节），超过单次加载上限 {} 字节，请使用提取功能导出后查看",
                length, MAX_INMEM_BUFFER
            )));
        }
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        read_decrypt_file_data(file, enc_key, offset, length, aad_bytes(aad_tag.as_deref(), vpath))
    }

    // ═══════════════ 碎片整理 ═══════════════

    pub fn defragment_vault<F: Fn(usize)>(&mut self, progress: Option<F>) -> Result<(), VaultError> {
        let active_enc_key = *self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let sign_key = *self.sign_key.as_ref().ok_or(VaultError::NotOpen)?;
        let vault_path = self.path.as_ref().ok_or(VaultError::NotOpen)?.clone();

        // 2.4.1（P0-3）：记录活跃分区旧布局（旧索引位置 + 全部旧文件数据位置），
        // 整理成功后对这些区域做 DoD 7-pass 擦除。
        // 旧实现把活跃分区数据复制到文件末尾后**不擦旧位置**，导致每整理一次
        // 文件反而膨胀一份活跃分区数据 —— 与「碎片整理释放空间」的语义完全相反。
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let old_part = self.partitions[active].clone();
        let (old_idx_off, old_idx_len) = (old_part.index_offset, old_part.index_length);
        let old_file_ranges: Vec<(u64, u64)> = {
            let index = self.load_index()?;
            index.files.values().map(|m| (m.offset, m.length)).collect()
        };
        // 整理前文件长度：新数据全部追加在 [orig_len, ...) —— 旧数据区与
        // 新数据区天然不相交（blob 均追加写入，互不重叠），擦除旧区不会伤及新数据
        let orig_len = std::fs::metadata(&vault_path)?.len();

        // 2.7.1 修复：整理前预检磁盘可用空间 —— 备份（完整副本）+ 临时文件都在
        // 同一磁盘上，按「约 2× 文件大小 + 4 MiB」预留；不足时明确拒绝且不产生
        // 任何中间文件（旧实现写到一半才失败，留下半份残留副本）。
        let need = orig_len.saturating_mul(2).saturating_add(4 * 1024 * 1024);
        if let Ok(free) = disk_free_bytes(vault_path.parent().unwrap_or(Path::new("."))) {
            if free < need {
                return Err(VaultError::Other(format!(
                    "磁盘可用空间不足（需约 {} MB，仅剩 {} MB），已取消整理，未产生任何中间文件",
                    need / (1024 * 1024),
                    free / (1024 * 1024),
                )));
            }
        }

        // 随机临时文件名，防止符号链接攻击
        let mut rand_suffix = [0u8; 16];
        OsRng.fill_bytes(&mut rand_suffix);
        let temp_name = format!("{}.tmp.{}", vault_path.display(), hex::encode(rand_suffix));
        let temp_path = PathBuf::from(&temp_name);
        let backup_name = format!("{}.bak.{}", vault_path.display(), hex::encode(rand_suffix));
        let backup_path = PathBuf::from(&backup_name);

        // C2 修复（关键）：旧实现只迁移活跃分区的文件和索引，
        // fs::rename 后其他分区的索引和文件密文全部丢失。
        // 新实现：遍历所有分区，将每个分区的索引（不解密，直接复制密文）
        // 迁移到临时文件，并更新对应分区的 offset/length。
        // 文件密文也整体复制（按活跃分区的索引定位）。
        // 由于其他分区无密码无法解密索引，我们只能整体复制 vault 文件中
        // 除头部外的所有数据，再重写活跃分区的索引使其紧凑。
        // 简化且正确的做法：复制整个原文件到临时文件，然后在临时文件上
        // 对活跃分区做碎片整理（重写文件数据 + 索引），其他分区数据原样保留。

        // Create unique backup and temporary files exclusively so pre-existing links cannot be followed.
        // 2.7.1 修复：备份 io::copy 中途失败（磁盘不足最常见）时半份 .bak 永久
        // 残留 —— 失败分支统一「先 DoD 擦除再删除」。
        let backup_result: std::io::Result<()> = (|| {
            let mut backup_file =
                OpenOptions::new().write(true).create_new(true).open(&backup_path)?;
            let mut original = File::open(&vault_path)?;
            let copy = std::io::copy(&mut original, &mut backup_file);
            let sync = backup_file.sync_all();
            drop(backup_file);
            drop(original);
            copy.and(sync).map(|_| ())
        })();
        if let Err(e) = backup_result {
            wipe_scratch_file(&backup_path);
            return Err(e.into());
        }

        // 2.4.1：闭包返回整理后的最终索引（供成功分支刷新内存缓存）
        let result = (|| -> Result<Index, VaultError> {
            // 2.4.1（P0-3 增强）：单分区（绝大多数用户的常态）走「紧凑整理」——
            // 新临时文件只包含「头部 + 迁移数据 + 新索引」，旧数据区根本不会
            // 出现在新文件里，物理长度直接缩小，真正回收磁盘空间。
            // 多分区时维持旧行为：整体复制原文件（其他分区数据位置未知，不能丢弃），
            // 旧数据区在成功路径末尾统一 DoD 擦除。
            let single_partition = self.partitions.len() == 1;

            // 步骤 1：准备临时文件
            // 2.8.0：占位头部尺寸必须与当前格式版本一致 —— v4→v5 升级等场景下
            // 版本可能变化，占位不足会让头部覆写越界到数据区
            let hdr_size = header_size_of(self.format_version)?;
            let mut tmp_file = {
                let mut tmp_file = OpenOptions::new()
                    .read(true).write(true).create_new(true)
                    .open(&temp_path)?;
                if !single_partition {
                    // 多分区：整体复制原文件，保留所有分区数据
                    let src_file = File::open(&vault_path)?;
                    std::io::copy(&mut &src_file, &mut tmp_file)?;
                    tmp_file.flush()?;
                    tmp_file.sync_all()?;
                } else {
                    // 单分区：头部占位（步骤 6 重写为最终内容）
                    tmp_file.write_all(&vec![0u8; hdr_size])?;
                    tmp_file.flush()?;
                    tmp_file.sync_all()?;
                }
                tmp_file
            };

            // 步骤 2：加载活跃分区索引（直接从原文件读取，原文件此刻未被修改）
            let mut index = {
                let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
                let active = self.active_partition.ok_or(VaultError::NotOpen)?;
                let p = &self.partitions[active];
                load_index_from_file(file, &active_enc_key, p.index_offset, p.index_length)?
            };

            // 步骤 3：迁移活跃分区的文件数据（紧凑排列，流式拷贝防 OOM）
            let files_snapshot: Vec<(String, u64, u64)> = index.files.iter()
                .map(|(k, m)| (k.clone(), m.offset, m.length))
                .collect();
            let total = files_snapshot.len();

            // 迁移源一律是原文件（读取与写入分离到两个句柄，
            // 避免单文件自拷贝在区间重叠时的数据破坏风险）
            let mut src_file = File::open(&vault_path)?;
            let mut write_cursor = if single_partition {
                hdr_size as u64
            } else {
                tmp_file.seek(SeekFrom::End(0))?
            };
            for (i, (vpath, old_off, old_len)) in files_snapshot.iter().enumerate() {
                copy_between(&mut src_file, &mut tmp_file, *old_off, write_cursor, *old_len)?;
                index.files.get_mut(vpath)
                    .ok_or_else(|| VaultError::Other("defragment: 文件不在索引中".to_string()))?
                    .offset = write_cursor;
                write_cursor += *old_len;
                if let Some(ref cb) = progress {
                    cb((i + 1) * 50 / total.max(1));
                }
            }
            drop(src_file);

            // 步骤 4：写入活跃分区的新索引
            // 2.8.2：去掉整索引深拷贝 —— 先注入审计再直接序列化 index，
            // 成功路径把 index 本身作为最终缓存返回（10k 文件索引省一次数 MB 分配）
            if let Some(ref audit) = self.audit {
                index.audit = audit.to_vec();
            }
            let idx_json = serde_json::to_vec(&index)?;
            let enc_idx = encrypt_gcm(&active_enc_key, &idx_json, b"index", None)?;
            tmp_file.seek(SeekFrom::Start(write_cursor))?;
            tmp_file.write_all(&enc_idx)?;
            tmp_file.flush()?;
            tmp_file.sync_all()?;

            let new_idx_offset = write_cursor;
            let new_idx_length = enc_idx.len() as u64;

            // 步骤 5：空间回收说明
            // - 单分区：临时文件从未写入旧数据（见步骤 1/3），文件本身就是紧凑
            //   布局，无需截断，物理空间已直接回收；
            // - 多分区：不截断文件（其他分区数据位于原文件中部，无密码无法定位
            //   其边界，截断会永久破坏它们）。空间回收靠成功路径末尾对活跃分区
            //   旧数据区/旧索引的 DoD 7-pass 擦除（P0-3）—— 逻辑空间被释放，
            //   物理文件长度保持不变（见 README「已知限制」）。

            let active = self.active_partition.ok_or(VaultError::NotOpen)?;
            self.partitions[active].index_offset = new_idx_offset;
            self.partitions[active].index_length = new_idx_length;

            // 步骤 6：写入头部（含所有分区的新偏移）
            let lock_state = &self.lock_state;
            let salt = &self.salt;
            let partitions = &self.partitions;
            write_header_to_file(&mut tmp_file, self.format_version, lock_state, salt, partitions, &sign_key)?;
            tmp_file.flush()?;
            tmp_file.sync_all()?;
            drop(tmp_file);

            // 步骤 7：原子替换
            // 2.7.0 修复：2.6.1 起 open_vault_rw 以 FILE_SHARE_READ 独占共享模式
            // 打开（不共享 DELETE），而替换式 rename 需要对目标文件取得 DELETE
            // 访问权 —— 会话句柄未释放时 rename 在 Windows 上会 sharing violation
            // 失败。先 drop 本进程句柄再替换（成功/失败分支随后都会重新独占打开）。
            self.file = None;
            // 2.7.1 修复：fs::rename 会让保险柜变成新建的临时文件对象，属性/ACL
            // 改为目录继承 —— 用户为 .lyt 单独设置的「仅本人可访问」静默失效，
            // 而 2.7.0 起删除会自动触发整理，该副作用已从偶发变常态。Windows 改用
            // ReplaceFileW（替换内容同时保留安全描述符/属性/创建时间），不支持时
            // 回退 rename；Unix rename 后还原 mode。
            replace_vault_file(&temp_path, &vault_path)?;
            sync_parent_dir(&vault_path);

            // 2.3.0 修复：备份是保险柜的完整副本，直接删除会在磁盘上留下抗取证死角。
            // 先 DoD 7-pass 擦除再删除；失败仅记日志（备份残留不影响主文件正确性）。
            if let Err(e) = dod_erase(&backup_path, None) {
                log::warn!("擦除碎片整理备份失败（保险柜同目录可能残留 .defrag_backup 文件）: {}", e);
            }
            secure_wipe_vec(idx_json);
            Ok(index)
        })();

        match result {
            Ok(final_index) => {
                // 2.6.1：先释放旧句柄（同时释放 flock），再以独占方式重开，
                // 避免同进程两次 flock 冲突，并保证整理后仍持有独占锁。
                self.file = None;
                // 2.8.2（诚实报错）：整理已提交（磁盘已是新布局）—— 旧实现重开
                // 失败时 `?` 直接上抛「整理失败」，用户会误以为失败而重试（再整理
                // 一整轮），而会话停在 file=None 的半死状态。现在先把内存缓存
                // 对齐新布局，短重试重开；仍失败则明确告知「已完成，请重开」。
                self.cached_index = Some(final_index);
                let mut reopened: Option<File> = None;
                let mut last_err: Option<String> = None;
                for _ in 0..3 {
                    match open_vault_rw(&vault_path, false) {
                        Ok(f) => match lock_vault_exclusive(&f) {
                            Ok(()) => {
                                reopened = Some(f);
                                break;
                            }
                            Err(e) => {
                                drop(f);
                                last_err = Some(e.to_string());
                            }
                        },
                        Err(e) => last_err = Some(e.to_string()),
                    }
                    std::thread::sleep(std::time::Duration::from_millis(150));
                }
                match reopened {
                    Some(file) => self.file = Some(file),
                    None => return Err(VaultError::Other(format!(
                        "碎片整理已完成（磁盘布局已更新），但恢复会话失败（{}）。请用密码重新打开保险柜",
                        last_err.unwrap_or_default()
                    ))),
                }
                // P0-3：擦除活跃分区旧数据区与旧索引（逻辑空间回收）。
                // 仅多分区路径需要：新文件是原文件的完整副本，旧区仍在新文件内。
                // 单分区紧凑整理的新文件从未包含旧数据区，此处擦除反而会毁掉
                // 迁移后的新数据 —— 必须跳过。
                let single_partition = self.partitions.len() == 1;
                // 新数据全部位于 [orig_len, ...)，与旧区不相交；此步失败仅意味着
                // 残留垃圾数据（无害），不影响正确性。
                // 防御性校验：若不变量被破坏（旧区越界进入新区），跳过擦除只留垃圾。
                let wipe_safe = !single_partition
                    && old_idx_off.saturating_add(old_idx_len) <= orig_len
                    && old_file_ranges.iter().all(|&(o, l)| o.saturating_add(l) <= orig_len);
                if single_partition {
                    // 单分区紧凑整理：旧数据区未进入新文件，无需擦除
                    //（2.7.1：日志器只落 Warn 及以上，移除永不记录的 debug 日志）
                } else if !wipe_safe {
                    log::warn!("碎片整理布局校验未通过，跳过旧数据擦除（残留垃圾，无害）");
                }
                if wipe_safe {
                    let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
                    let mut wiped = true;
                    if old_idx_len > 0 {
                        if let Err(e) = dod_overwrite_range(file, old_idx_off, old_idx_len) {
                            wiped = false;
                            log::warn!("整理后擦除旧索引失败（残留垃圾，无害）: {}", e);
                        }
                    }
                    for (off, len) in &old_file_ranges {
                        if *len == 0 { continue; }
                        if let Err(e) = dod_overwrite_range(file, *off, *len) {
                            wiped = false;
                            log::warn!("整理后擦除旧数据失败（残留垃圾，无害）: {}", e);
                        }
                    }
                    if wiped {
                        let _ = file.flush();
                        let _ = file.sync_all();
                    }
                }
                // 2.4.1：缓存已在重开前对齐新布局（偏移已全部更新）——
                // 2.8.2 重构后此处不再重复赋值（final_index 已被移动）
                self.log_event("执行保险柜碎片整理");
                if let Some(ref cb) = progress {
                    cb(100);
                }
                Ok(())
            }
            Err(e) => {
                // 2.7.0 修复：先释放会话句柄 —— 下方「备份恢复」也是对 vault_path
                // 的替换式 rename，会话句柄未释放时同样会 sharing violation 失败。
                self.file = None;
                // 2.7.1 修复：temp 是保险柜内容的中间副本，先 DoD 擦除再删除
                //（旧实现直接 remove_file，半份副本可恢复）
                wipe_scratch_file(&temp_path);
                if backup_path.exists() {
                    // 2.7.1 修复：备份恢复的 rename 失败不再被静默吞掉 —— 此时
                    // 保险柜本体已被移走，必须告知用户并保留 .bak 以便手动恢复
                    if let Err(re) = fs::rename(&backup_path, &vault_path) {
                        log::error!(
                            "碎片整理失败后从备份恢复保险柜失败：{}；同目录残留的 .bak 备份文件未被删除，请手动恢复",
                            re
                        );
                        return Err(VaultError::Other(format!(
                            "整理失败（{}），且自动恢复失败（{}）：请勿再次写入，同目录的 .bak 备份文件可手动恢复",
                            e, re
                        )));
                    }
                    // 2.4.1 修复：闭包内可能已把 self.partitions[active] 指向**新**偏移，
                    // 而恢复回来的原文件仍是旧布局 —— 不回滚会导致后续读写错位。
                    // （旧实现在此存在状态不一致缺陷）
                    if let Some(active) = self.active_partition {
                        self.partitions[active] = old_part;
                    }
                    self.file = None;
                    let file = open_vault_rw(&vault_path, false).ok().and_then(|f| {
                        lock_vault_exclusive(&f).ok()?;
                        Some(f)
                    });
                    self.file = file;
                }
                Err(e)
            }
        }
    }

    // ═══════════════ 查询 ═══════════════

    pub fn get_audit_entries(&self) -> Vec<crate::audit::AuditEntry> {
        self.audit.as_ref().map(|a| a.to_vec()).unwrap_or_default()
    }

    /// 提取保险柜内所有文件到指定目录，保留 vpath 目录结构。
    /// R3 修复：真正单次 load_index，循环调用 extract_file_inner（不再重复 load）。
    /// 2.4.1 变更：目标目录只校验/规范化一次（P1-12）；新增 overwrite 参数（P0-5，
    /// 由前端确认框传入 —— 旧实现确认「覆盖」后实际用 create_new 拒绝覆盖，大批失败）。
    /// 返回 (成功数, 失败数, 失败明细)。
    pub fn extract_all_files(
        &mut self,
        dest_folder: &Path,
        overwrite: bool,
    ) -> Result<(usize, usize, Vec<String>), VaultError> {
        let dest_abs = Self::prepare_dest_root(dest_folder)?;
        // 单次 load_index，收集所有文件的元数据
        let file_infos: Vec<(String, String, String, u64, u64, Option<String>)> = {
            let index = self.index_ref()?;
            index.files.iter().map(|(vpath, meta)| {
                let vpath_trimmed = vpath.trim_matches('/');
                let rel_dir = match vpath_trimmed.rfind('/') {
                    Some(pos) => vpath_trimmed[..pos].to_string(),
                    None => "".to_string(),
                };
                (vpath.clone(), rel_dir, meta.name.clone(), meta.offset, meta.length, meta.aad_tag.clone())
            }).collect()
        };
        let mut ok = 0usize;
        let mut fail = 0usize;
        let mut errors: Vec<String> = Vec::new();
        for (vpath, rel_dir, file_name, offset, length, aad_tag) in &file_infos {
            let aad = aad_bytes(aad_tag.as_deref(), vpath);
            match self.extract_file_inner(vpath, rel_dir, file_name, *offset, *length, aad, &dest_abs, overwrite) {
                Ok(_) => ok += 1,
                Err(e) => {
                    fail += 1;
                    errors.push(format!("{}: {}", vpath, e));
                    // 2.8.1：错误串含 vpath，不再落明文日志（明细经返回值反馈前端）
                    log::warn!("提取全部有失败项（明细已随返回值反馈）");
                }
            }
        }
        // 2.8.1：审计串不再携带真实文件系统路径（抗取证：审计在加密索引内，
        // 但备份/内存转储场景下目的路径属于用户敏感信息）
        self.log_event(&format!(
            "提取全部文件（成功 {}，失败 {}）",
            ok, fail
        ));
        Ok((ok, fail, errors))
    }

    /// 批量提取指定文件/文件夹到目标目录（单次 load_index，避免 O(n²) 重复加载）。
    /// 文件夹自动展开为其下所有文件；返回 (成功数, 失败数, 失败明细)。
    /// 2.3.0 修复：`extract_files` 命令原先对每个文件重复 load_index，大数据量下退化 O(n²)。
    /// 2.4.1：目标目录只校验一次（P1-12）+ 摘要审计（P1-14）。
    pub fn extract_files_batch(&mut self, vpaths: &[String], dest_folder: &Path) -> Result<(usize, usize, Vec<String>), VaultError> {
        let dest_abs = Self::prepare_dest_root(dest_folder)?;
        let targets: Vec<(String, String, String, u64, u64, Option<String>)> = {
            let index = self.index_ref()?;
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut targets: Vec<(String, String, String, u64, u64, Option<String>)> = Vec::new();
            for vp in vpaths {
                let vp_norm = vp.trim_end_matches('/');
                if vp_norm.is_empty() || vp_norm == "/" {
                    continue;
                }
                if index.files.contains_key(vp_norm) {
                    if seen.insert(vp_norm.to_string()) {
                        let m = index.files.get(vp_norm).unwrap();
                        let vpath_trimmed = vp_norm.trim_matches('/');
                        let rel_dir = match vpath_trimmed.rfind('/') {
                            Some(pos) => vpath_trimmed[..pos].to_string(),
                            None => String::new(),
                        };
                        targets.push((vp_norm.to_string(), rel_dir, m.name.clone(), m.offset, m.length, m.aad_tag.clone()));
                    }
                } else if index.folders.contains_key(vp_norm) {
                    let prefix = format!("{}/", vp_norm);
                    for (fv, m) in &index.files {
                        if (fv.starts_with(&prefix) || fv == vp_norm) && seen.insert(fv.clone()) {
                            let vpath_trimmed = fv.trim_matches('/');
                            let rel_dir = match vpath_trimmed.rfind('/') {
                                Some(pos) => vpath_trimmed[..pos].to_string(),
                                None => String::new(),
                            };
                            targets.push((fv.clone(), rel_dir, m.name.clone(), m.offset, m.length, m.aad_tag.clone()));
                        }
                    }
                }
            }
            targets
        };

        let mut ok = 0usize;
        let mut fail = 0usize;
        let mut errors: Vec<String> = Vec::new();
        for (vpath, rel_dir, file_name, offset, length, aad_tag) in &targets {
            let aad = aad_bytes(aad_tag.as_deref(), vpath);
            // 批量提取保持「拒绝覆盖」的安全默认；需要覆盖语义时走提取全部（P0-5）
            match self.extract_file_inner(vpath, rel_dir, file_name, *offset, *length, aad, &dest_abs, false) {
                Ok(_) => ok += 1,
                Err(e) => {
                    fail += 1;
                    errors.push(format!("{}: {}", vpath, e));
                    log::warn!("批量提取有失败项（明细已随返回值反馈）");
                }
            }
        }
        self.log_event(&format!("批量提取：成功 {} 个文件，失败 {} 个", ok, fail));
        Ok((ok, fail, errors))
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

    // ═══════════════ 销毁 ═══════════════

    /// 2.7.1 修复（Windows 上销毁必然失败的回归）：旧流程是命令层按路径以
    /// 「读+写」重新打开同一文件再擦除 —— 但会话句柄以 `FILE_SHARE_READ` 独占
    /// 共享模式打开（2.6.1），任何**写**打开都会被系统拒绝
    /// （`ERROR_SHARING_VIOLATION` / os error 32），销毁从未成功过；失效期间
    /// 用户很可能改用普通文件管理器删除 —— 数据未经任何擦除。
    ///
    /// 现改为销毁全程**交出会话句柄本身**，不按路径二次打开：
    /// - 符号链接 / 重解析点的拒绝前移到**打开阶段**（`open_vault_rw` 的
    ///   `FILE_FLAG_OPEN_REPARSE_POINT` / `O_NOFOLLOW` + 句柄元数据确认），
    ///   句柄锚定的 TOCTOU 防护因此不再削弱；
    /// - 未落盘的审计先随索引持久化（此时仍持有会话句柄），随后交出句柄做
    ///   DoD 7-pass 擦除 + 删除（Windows 下优先 delete-on-close，不经路径）。
    pub fn destroy(&mut self) -> Result<(), VaultError> {
        if !self.is_open() {
            return Err(VaultError::NotOpen);
        }
        let path = self.path.clone().ok_or(VaultError::NotOpen)?;

        // 与 close 相同：先把未落盘的审计持久化（此时仍持有会话句柄）
        if self.audit.is_some() {
            if let Some(ref mut audit) = self.audit {
                audit.add("保险柜已销毁");
            }
            self.audit_dirty = true;
        }
        if self.enc_key.is_some() && self.audit_dirty {
            if let Err(e) = self.load_index().and_then(|idx| self.save_index(idx)) {
                log::warn!("销毁前落盘审计失败（不影响销毁）: {}", e);
            }
        }

        // 交出会话句柄 —— 后续擦除与删除只作用于该句柄代表的文件对象
        let file = self.file.take().ok_or(VaultError::NotOpen)?;

        // 清理会话状态（与 close 相同的密钥/缓存清理）
        self.path = None;
        if let Some(mut idx) = self.cached_index.take() {
            idx.files.clear();
            idx.folders.clear();
            idx.audit.clear();
        }
        if let Some(mut key) = self.enc_key.take() { key.zeroize(); }
        if let Some(mut key) = self.auth_key.take() { key.zeroize(); }
        if let Some(mut key) = self.sign_key.take() { key.zeroize(); }
        if let Some(mut key) = self.data_key.take() { key.zeroize(); }
        self.format_version = 0;
        self.active_partition = None;
        self.audit = None;
        self.audit_dirty = false;

        // 基于已持有的句柄完成 DoD 7-pass 擦除 + 删除（全程不按路径重开）
        Ok(crate::wipe::dod_erase_handle(file, &path, None)?)
    }

    // ═══════════════ 关闭 ═══════════════

    /// 2.4.1 变更（P1-15）：只在审计有未落盘变更时才补一次 save_index。
    /// 旧实现 close() 无条件 load+save（全量索引重写 + 7-pass 擦旧索引，
    /// 10 次 fsync）—— 而大多数时候索引内容早已随上一次操作落盘，
    /// 这次写入的唯一目的是把「保险柜已关闭」审计条目刷进索引。
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
        if let Some(mut key) = self.enc_key.take() { key.zeroize(); }
        if let Some(mut key) = self.auth_key.take() { key.zeroize(); }
        if let Some(mut key) = self.sign_key.take() { key.zeroize(); }
        if let Some(mut key) = self.data_key.take() { key.zeroize(); }
        self.format_version = 0;
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
        if let Some(mut key) = self.enc_key.take() { key.zeroize(); }
        if let Some(mut key) = self.auth_key.take() { key.zeroize(); }
        if let Some(mut key) = self.sign_key.take() { key.zeroize(); }
        if let Some(mut key) = self.data_key.take() { key.zeroize(); }
        self.format_version = 0;
    }
}
