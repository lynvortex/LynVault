//! 文件系统与底层 I/O 工具 —— 独占打开 / 索引 I/O / 跨文件拷贝 / 原子替换 / 名称清理。
//! 3.0.0 拆分自 vault.rs，逻辑逐字节不变。
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::{chunk_aad, decrypt_gcm, decrypt_into, encrypt_gcm};
use crate::error::VaultError;
use crate::index::{ChunkLayout, Index};
use crate::wipe::{dod_erase, dod_overwrite_range, secure_wipe_vec};

use super::consts::*;

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
// 3.0.1（#46 修复）：删除 `create` 参数与 `create(true).truncate(true)` 死分支
// —— 无任何调用方，且 truncate 语义是「打开即清空整柜」的脚枪；创建保险柜
// 一律走 open_vault_create_new（目标存在时失败，绝不清零）。
pub(crate) fn open_vault_rw(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        // 3.0.1（#47 修复）：显式访问掩码 = GENERIC 读写之外补 DELETE 权 ——
        // 销毁路径的 delete-on-close（POSIX 语义，wipe::mark_delete_on_close）
        // 要求本句柄持有 DELETE；旧实现句柄无 DELETE 权，该分支必然失败回退
        // 按路径删除（文档高估了交付语义）。共享模式不变，其他进程的打开
        // 行为不受影响。
        use windows::Win32::Storage::FileSystem::{DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE};
        opts.access_mode(FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0);
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
pub(crate) fn verify_no_reparse(file: &File) -> std::io::Result<()> {
    if file.metadata()?.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "拒绝通过符号链接打开保险柜文件",
        ));
    }
    Ok(())
}

/// 3.0.1（F10 修复）：以独占创建（create_new）打开保险柜的临时/备份/演练
/// 副本 —— 与本体同等敏感（整柜密文副本，旧口令即可离线爆破），Unix 下按
/// 0600 落盘；旧实现按 umask（通常 0644），同机其他用户可读走副本。
/// Windows 的 ACL 语义不同，不受影响。
pub(crate) fn create_scratch_file(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// 2.7.1 新增：以 create_new 语义独占创建保险柜文件（目标已存在时失败，
/// 绝不清零已有内容）。打开标志与 [`open_vault_rw`] 完全一致。
pub(crate) fn open_vault_create_new(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
        // 3.0.1（F10 修复）：保险柜按 0600 落盘 —— 旧实现只有 umask（通常
        // 0644），同机其他用户可读走密文做离线口令爆破。Windows 的 ACL 语义
        // 不同，不受影响。
        opts.mode(0o600);
    }
    opts.open(path)
}

/// 2.6.1 新增：取得保险柜文件的独占锁，防止双实例并发写坏头部/索引。
/// - Unix：`flock(LOCK_EX | LOCK_NB)`，**建议性**锁，非阻塞；锁随文件句柄
///   关闭自动释放。
/// - Windows：无独立实现 —— [`open_vault_rw`] 以「请求读写 + 只共享读」
///   打开，Windows 共享模式是**内核强制锁**：会话存续期间任何其他进程对
///   同一文件的读写打开都得到 sharing violation。语义强于 Unix 的建议性
///   flock。3.0.1（F17 复核）：审计提出的「Windows 跨进程互斥为空」不成立
///   —— 共享模式本身即独占保证，无需边车锁文件。
/// 返回 `Err` 表示文件已被其他实例独占占用。
#[cfg(unix)]
pub(crate) fn lock_vault_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn lock_vault_exclusive(_file: &File) -> std::io::Result<()> {
    // Windows：独占由 open_vault_rw 的共享模式（FILE_SHARE_READ）在内核层
    // 强制 —— 见上方文档。此函数保留以维持打开流程的调用点对称。
    Ok(())
}

/// 从文件读取并解密索引
pub(crate) fn load_index_from_file(
    file: &mut File,
    enc_key: &[u8; 32],
    offset: u64,
    length: u64,
) -> Result<Index, VaultError> {
    // 2.3.0 修复：索引长度上限校验，防止恶意头部（溢出绕过边界检查后）触发超大分配
    if length > MAX_INMEM_BUFFER as u64 {
        return Err(VaultError::Other(format!(
            "索引数据过大（{} 字节），超过单次加载上限",
            length
        )));
    }
    // 3.0.1（F1 纵深防御）：范围校验提前到 seek/分配之前
    let file_len = file.metadata()?.len();
    let end = offset
        .checked_add(length)
        .ok_or_else(|| VaultError::Other("索引范围溢出".into()))?;
    if end > file_len {
        return Err(VaultError::Other("索引超出文件范围".into()));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut enc = vec![0u8; length as usize];
    file.read_exact(&mut enc)?;
    let plain = decrypt_gcm(enc_key, &enc, b"index").ok_or(VaultError::DecryptFailed)?;
    let index: Index = serde_json::from_slice(&plain)?;
    // 3.0.1（F3/F4/F5 根治）：布局自洽性校验（与打开路径同一防线）
    index.validate(file_len)?;
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
pub(crate) fn save_index_to_file(
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
pub(crate) fn wipe_old_index_range(file: &mut File, old_offset: u64, old_length: u64) {
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
pub(crate) fn copy_between(
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
pub(crate) fn sync_parent_dir(path: &Path) {
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
        if let Ok(d) = OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000)
            .open(parent)
        {
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
pub(crate) fn disk_free_bytes(dir: &Path) -> std::io::Result<u64> {
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
        unsafe { GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), Some(&mut free), None, None) }
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
pub(crate) fn wipe_scratch_file(path: &Path) {
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
pub(crate) fn replace_vault_file(temp: &Path, dest: &Path) -> std::io::Result<()> {
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
pub(crate) fn replace_file_windows(temp: &Path, dest: &Path) -> std::io::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        ReplaceFileW, REPLACEFILE_IGNORE_MERGE_ERRORS, REPLACEFILE_WRITE_THROUGH,
        REPLACE_FILE_FLAGS,
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

/// 解密文件数据时应使用的 AAD。
///
/// 优先用索引里冻结的 `aad_tag`（导入时的 vpath）；旧索引没有该字段时回退到
/// 当前 vpath —— 与修复前的历史行为完全一致，保证存量保险柜不受影响。
pub(crate) fn aad_bytes<'a>(frozen: Option<&'a str>, vpath: &'a str) -> &'a [u8] {
    frozen.unwrap_or(vpath).as_bytes()
}

/// 从保险柜文件读取并解密原始数据
/// `aad` 必须与加密时使用的值一致（用 `aad_bytes` 求值：优先 aad_tag，回退 vpath）
pub(crate) fn read_decrypt_file_data(
    file: &mut File,
    enc_key: &[u8; 32],
    offset: u64,
    length: u64,
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let file_len = file.metadata()?.len();
    let end = offset
        .checked_add(length)
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

/// 分块密文每块开销：nonce(12) + GCM tag(16)
pub(crate) const CHUNK_OVERHEAD: u64 = 28;

/// 3.0.1（F3/F4 统一收口）：分块布局解析结果 —— 逐块几何的唯一事实来源。
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChunkPlan {
    pub chunk_size: u64,
    pub chunk_count: u64,
    /// 满块密文长度 = chunk_size + CHUNK_OVERHEAD
    pub full_ct: u64,
    /// 末块明文长度 ∈ (0, chunk_size]
    pub expected_last: u64,
}

impl ChunkPlan {
    /// 第 i 块的明文长度（末块 = expected_last，其余 = chunk_size）
    pub fn plain_len(&self, i: u64) -> u64 {
        if i + 1 == self.chunk_count {
            self.expected_last
        } else {
            self.chunk_size
        }
    }

    /// 第 i 块的密文长度
    pub fn ct_len(&self, i: u64) -> u64 {
        self.plain_len(i) + CHUNK_OVERHEAD
    }

    /// 明文总长（= 索引 size 字段在写入时的值）。
    /// saturating：resolve_chunk_plan 的校验已保证真实值不溢出（(count-1)*full_ct
    /// ≤ length），此处 saturate 仅作为纵深防御，杜绝任何 panic 路径。
    pub fn plaintext_total(&self) -> u64 {
        (self.chunk_count - 1)
            .saturating_mul(self.chunk_size)
            .saturating_add(self.expected_last)
    }
}

/// 3.0.1（F3 修复）：由密文总长 + 索引布局解析分块几何 —— 所有读取路径
/// （整段 / 流式提取 / 媒体区间 / 体检）共用，不得自行演算。校验：
/// - `chunk_size ∈ (0, CHUNK_SIZE_V6]`：唯一曾是「非零」检查 —— chunk_count=1
///   时 `length` 全额通过，`vec![0u8; 2^40]` 直接 alloc-abort 整个进程；
///   写入方恒用 CHUNK_SIZE_V6 分块，超限值必属篡改/损坏；
/// - `chunk_count > 0`，全程 checked 运算（release 档 overflow-checks 开启，
///   但显式报错优于 panic）；
/// - 末块明文 ∈ (0, chunk_size]：密文长度与索引布局矛盾即拒绝（截断/篡改）。
pub(crate) fn resolve_chunk_plan(
    length: u64,
    chunk_size: u64,
    chunk_count: u64,
) -> Result<ChunkPlan, VaultError> {
    if chunk_size == 0 || chunk_count == 0 {
        return Err(VaultError::Other("分块布局参数非法".into()));
    }
    if chunk_size > CHUNK_SIZE_V6 {
        return Err(VaultError::Other(format!(
            "分块大小非法（{} 字节，超过上限 {} 字节）",
            chunk_size, CHUNK_SIZE_V6
        )));
    }
    let full_ct = chunk_size
        .checked_add(CHUNK_OVERHEAD)
        .ok_or_else(|| VaultError::Other("分块布局参数非法".into()))?;
    let full_ct_total = full_ct
        .checked_mul(chunk_count - 1)
        .ok_or_else(|| VaultError::Other("分块布局参数非法（块数溢出）".into()))?;
    let expected_last = match length.checked_sub(full_ct_total) {
        Some(v) if v > CHUNK_OVERHEAD && v <= full_ct => v - CHUNK_OVERHEAD,
        _ => {
            return Err(VaultError::Other(
                "分块密文长度与索引布局不一致（密文可能被截断或篡改）".into(),
            ))
        }
    };
    Ok(ChunkPlan {
        chunk_size,
        chunk_count,
        full_ct,
        expected_last,
    })
}

/// 3.0.0（v6）：布局感知的整段读取解密 —— Chunked 布局按块流式解密后拼接，
/// 对外行为（返回完整明文 Vec）与 Legacy 一致；调用方仍需自行施加
/// MAX_INMEM_BUFFER 上限（本函数不重复校验，供预览/编辑等确需整段的路径用）。
/// `frozen` 为索引冻结的 aad_tag（None 回退 `vpath`）—— Legacy 与 Chunked
/// 的 AAD 语义一致（chunk_aad 内部再叠加块序号/总块数）。
pub(crate) fn read_decrypt_file_data_layout(
    file: &mut File,
    enc_key: &[u8; 32],
    offset: u64,
    length: u64,
    frozen: Option<&str>,
    vpath: &str,
    layout: &ChunkLayout,
) -> Result<Vec<u8>, VaultError> {
    use zeroize::Zeroize;
    match layout {
        ChunkLayout::Legacy => {
            let aad = frozen.unwrap_or(vpath).as_bytes().to_vec();
            read_decrypt_file_data(file, enc_key, offset, length, &aad)
        }
        ChunkLayout::Chunked {
            chunk_size,
            chunk_count,
        } => {
            // 3.0.1（F3）：统一布局解析（含 chunk_size 上限与末块校验）
            let plan = resolve_chunk_plan(length, *chunk_size, *chunk_count)?;
            // 3.0.1（#27 修复）：checked_add 结果与文件长度比对（旧实现求值后
            // 丢弃，等于没查）
            let file_len = file.metadata()?.len();
            let end = offset
                .checked_add(length)
                .ok_or_else(|| VaultError::Other("文件数据范围溢出".into()))?;
            if end > file_len {
                return Err(VaultError::Other(
                    "文件密文范围超出保险柜文件（索引可能被篡改或损坏）".into(),
                ));
            }
            let frozen = frozen.unwrap_or(vpath);
            // L-8（审计修复）：分配前按明文总长设容量（plan 已保证不溢出）
            let plaintext_total = plan.plaintext_total();
            let mut out = Vec::with_capacity(plaintext_total as usize);
            let mut pos = offset;
            for i in 0..plan.chunk_count {
                let ct_len = plan.ct_len(i);
                file.seek(SeekFrom::Start(pos))?;
                let mut enc = vec![0u8; ct_len as usize];
                file.read_exact(&mut enc)?;
                let mut plain = decrypt_into(enc_key, enc, &chunk_aad(frozen, i, plan.chunk_count))
                    .ok_or(VaultError::DecryptFailed)?;
                out.extend_from_slice(&plain);
                // L5（审计修复）：与 read_media_range / stream_decrypt_to_writer 同一纪律
                plain.zeroize();
                pos = pos.checked_add(ct_len).ok_or_else(|| {
                    VaultError::Other("分块密文位置溢出（索引可能被篡改）".into())
                })?;
            }
            Ok(out)
        }
    }
}

/// 3.0.0（v6）：布局感知的完整性校验 —— 不拼装完整明文（Chunked 逐块解密后
/// 立即丢弃），体检路径的内存占用与文件大小无关。Legacy 行为与历史一致。
pub(crate) fn verify_file_data_layout(
    file: &mut File,
    enc_key: &[u8; 32],
    offset: u64,
    length: u64,
    frozen: Option<&str>,
    vpath: &str,
    layout: &ChunkLayout,
) -> Result<(), VaultError> {
    match layout {
        ChunkLayout::Legacy => {
            let aad = frozen.unwrap_or(vpath).as_bytes().to_vec();
            let plain = read_decrypt_file_data(file, enc_key, offset, length, &aad)?;
            secure_wipe_vec(plain);
            Ok(())
        }
        ChunkLayout::Chunked {
            chunk_size,
            chunk_count,
        } => {
            // 3.0.1（F3）：统一布局解析
            let plan = resolve_chunk_plan(length, *chunk_size, *chunk_count)?;
            let frozen = frozen.unwrap_or(vpath);
            let mut pos = offset;
            for i in 0..plan.chunk_count {
                let ct_len = plan.ct_len(i);
                file.seek(SeekFrom::Start(pos))?;
                let mut enc = vec![0u8; ct_len as usize];
                file.read_exact(&mut enc)?;
                let plain = decrypt_into(enc_key, enc, &chunk_aad(frozen, i, plan.chunk_count))
                    .ok_or(VaultError::DecryptFailed)?;
                secure_wipe_vec(plain);
                pos = pos.checked_add(ct_len).ok_or_else(|| {
                    VaultError::Other("分块密文位置溢出（索引可能被篡改）".into())
                })?;
            }
            Ok(())
        }
    }
}

/// 安全文件名清理
/// 2.4.1 变更：由「白名单」改为「黑名单」策略 —— 仅剔除路径危险字符与控制字符，
/// 保留 Unicode 字符与常见符号（!@#$%^& 等）。旧白名单会把 `report#1.txt`
/// 静默改名为 `report1.txt`，批量提取时引发大量「目标已存在」失败。
/// 仍然处理：结尾 '.'/' '（Windows 规范化）、保留设备名（CON/NUL/COM1..）。
pub(crate) fn sanitize_filename(name: &str) -> String {
    let mut safe: String = name
        .chars()
        .filter(|c| {
            let cu = *c as u32;
            // 控制字符与 DEL 剔除；路径分隔符与 Windows 保留字符剔除；
            // I8（审计修复）：RTL 方向控制字符（U+202A..E / U+2066..9）一并
            // 剔除 —— 它们可将提取文件名的扩展名视觉伪装（社会工程面）
            cu >= 0x20
                && cu != 0x7f
                && !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
                && !matches!(cu, 0x202A..=0x202E | 0x2066..=0x2069)
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
    if matches!(
        stem,
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        safe.insert(0, '_');
    }
    if safe.is_empty() {
        "extracted_file".to_string()
    } else {
        safe
    }
}

/// Windows：源文件名为保留设备名（CON/NUL/COM1… 及其带扩展名形式）时，
/// 普通 Win32 路径的打开请求会被路径归一化重写到设备本身 —— 读到的是
/// 控制台/空设备（表现为「函数不正确」错误或读取挂起），而非磁盘上的真实
/// 文件。此类文件可由 msys/WSL/`\\?\` 路径合法创建，导入时需改用 verbatim
/// （`\\?\`）路径打开以禁用重写；其余文件维持原路径不变。
#[cfg(windows)]
pub(crate) fn open_import_source(src_path: &Path) -> std::io::Result<File> {
    const RESERVED_STEMS: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let is_reserved = src_path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| {
            let upper = n.to_uppercase();
            let stem = match upper.rfind('.') {
                Some(p) => &upper[..p],
                None => upper.as_str(),
            };
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
pub(crate) fn open_import_source(src_path: &Path) -> std::io::Result<File> {
    File::open(src_path)
}

/// 判断 `child` 是否位于 `base` 目录之下（提取时的路径遍历防护）。
///
/// Windows 文件系统大小写不敏感，而 `Path::starts_with` 是**逐组件、大小写敏感**
/// 的比较：`prepare_dest_root` 经 `canonicalize` 得到的大小写与用户传入的可能不同，
/// 直接把两者做 `starts_with` 会把合法路径误判为越界。这里在 Windows 上改为
/// 逐组件、大小写不敏感比较（只在 `base` 的组件数范围内比较，避免 `C:\a` 误配
/// `C:\ab` 这类字符串前缀假阳性）；其他平台保持原生逐组件比较。
pub(crate) fn path_within(child: &Path, base: &Path) -> bool {
    #[cfg(windows)]
    {
        // 3.0.1（F8 修复）：base 组件耗尽后，子路径的剩余组件不得包含
        // ParentDir / Prefix —— 旧实现只逐组件比较 base 的组件数，base 用尽
        // 即返回 true，`path_within(C:\out\..\..\Windows\x, C:\out)` 误判为
        // true（非 Windows 分支的 `child.starts_with(base)` 无此缺陷）。
        // 当前调用点传入的路径均已 canonicalize 或经 sanitize_filename，
        // 不可利用；本修复属纵深防御。
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
        for c in child_comps {
            match c {
                std::path::Component::Normal(_) => continue,
                std::path::Component::CurDir => continue,
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

#[cfg(all(test, windows))]
mod path_within_tests {
    use super::*;

    /// 3.0.1（F8 回归）：Windows 分支 base 耗尽后剩余组件含 ParentDir 必须拒绝
    #[test]
    fn rejects_parent_dir_remaining() {
        use std::path::Path;
        assert!(path_within(Path::new(r"C:\out\sub"), Path::new(r"C:\out")));
        assert!(path_within(Path::new(r"C:\out"), Path::new(r"C:\out")));
        assert!(path_within(
            Path::new(r"C:\out\sub\x.txt"),
            Path::new(r"C:\out")
        ));
        // 旧缺陷用例：非 Windows 分支的 starts_with 语义正确，Windows 分支曾误判
        assert!(!path_within(
            Path::new(r"C:\out\..\Windows\x"),
            Path::new(r"C:\out")
        ));
        // 完全在 base 之外
        assert!(!path_within(Path::new(r"C:\Windows"), Path::new(r"C:\out")));
    }
}
