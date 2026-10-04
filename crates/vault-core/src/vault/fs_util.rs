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
pub(crate) fn open_vault_rw(path: &Path, create: bool) -> std::io::Result<File> {
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
        opts.share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
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
    }
    opts.open(path)
}

/// 2.6.1 新增：取得保险柜文件的独占锁，防止双实例并发写坏头部/索引。
/// - Unix：`flock(LOCK_EX | LOCK_NB)`，非阻塞；锁随文件句柄关闭自动释放。
/// - Windows：由 [`open_vault_rw`] 的共享模式保证，此处为空操作。
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
            let (chunk_size, chunk_count) = (*chunk_size, *chunk_count);
            if chunk_size == 0 || chunk_count == 0 || offset.checked_add(length).is_none() {
                return Err(VaultError::Other("分块布局参数非法".into()));
            }
            // 由密文总长反推末块明文长度：前 count-1 块每块 chunk_size + 28 字节密文，
            // 末块 = 末块明文 + 28。反推结果必须在 (0, chunk_size] 内 —— 否则密文
            // 长度与索引布局矛盾（截断/篡改），拒绝解密。
            // 3.0.0 安全：chunk_count/chunk_size 来自不可信索引，全程 checked 运算
            let overhead = 28u64; // nonce(12) + GCM tag(16)
            let full_ct = chunk_size
                .checked_add(overhead)
                .ok_or_else(|| VaultError::Other("分块布局参数非法".into()))?;
            let full_ct_total = full_ct
                .checked_mul(chunk_count - 1)
                .ok_or_else(|| VaultError::Other("分块布局参数非法（块数溢出）".into()))?;
            let expected_last = match length.checked_sub(full_ct_total) {
                Some(v) if v > overhead && v <= full_ct => v - overhead,
                _ => {
                    return Err(VaultError::Other(
                        "分块密文长度与索引布局不一致（密文可能被截断或篡改）".into(),
                    ))
                }
            };
            let frozen = frozen.unwrap_or(vpath);
            // L-8（审计修复）：与同函数上方 full_ct.checked_mul 同一防护风格
            //（实际不可达：expected_last 校验已蕴含 length > overhead*chunk_count，
            // 但同一函数内防护风格必须一致）
            let plaintext_total = length
                .checked_sub(
                    overhead
                        .checked_mul(chunk_count)
                        .ok_or_else(|| VaultError::Other("分块布局参数非法（块数溢出）".into()))?,
                )
                .ok_or_else(|| VaultError::Other("分块密文长度不足".into()))?;
            let mut out = Vec::with_capacity(plaintext_total as usize);
            let mut pos = offset;
            for i in 0..chunk_count {
                let plain_n = if i + 1 == chunk_count {
                    expected_last
                } else {
                    chunk_size
                };
                let ct_len = plain_n + overhead;
                file.seek(SeekFrom::Start(pos))?;
                let mut enc = vec![0u8; ct_len as usize];
                file.read_exact(&mut enc)?;
                let mut plain = decrypt_into(enc_key, enc, &chunk_aad(frozen, i, chunk_count))
                    .ok_or(VaultError::DecryptFailed)?;
                out.extend_from_slice(&plain);
                // L5（审计修复）：与 read_media_range / stream_decrypt_to_writer 同一纪律
                plain.zeroize();
                pos += ct_len;
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
            let (chunk_size, chunk_count) = (*chunk_size, *chunk_count);
            if chunk_size == 0 || chunk_count == 0 {
                return Err(VaultError::Other("分块布局参数非法".into()));
            }
            let overhead = 28u64;
            let full_ct = chunk_size
                .checked_add(overhead)
                .ok_or_else(|| VaultError::Other("分块布局参数非法".into()))?;
            let full_ct_total = full_ct
                .checked_mul(chunk_count - 1)
                .ok_or_else(|| VaultError::Other("分块布局参数非法（块数溢出）".into()))?;
            let expected_last = match length.checked_sub(full_ct_total) {
                Some(v) if v > overhead && v <= full_ct => v - overhead,
                _ => {
                    return Err(VaultError::Other(
                        "分块密文长度与索引布局不一致（密文可能被截断或篡改）".into(),
                    ))
                }
            };
            let frozen = frozen.unwrap_or(vpath);
            let mut pos = offset;
            for i in 0..chunk_count {
                let plain_n = if i + 1 == chunk_count {
                    expected_last
                } else {
                    chunk_size
                };
                let ct_len = plain_n + overhead;
                file.seek(SeekFrom::Start(pos))?;
                let mut enc = vec![0u8; ct_len as usize];
                file.read_exact(&mut enc)?;
                let plain = decrypt_into(enc_key, enc, &chunk_aad(frozen, i, chunk_count))
                    .ok_or(VaultError::DecryptFailed)?;
                secure_wipe_vec(plain);
                pos += ct_len;
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
