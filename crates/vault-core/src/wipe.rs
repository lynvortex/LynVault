//! 安全擦除与内存零化辅助函数
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::Zeroize;

/// DoD 7-pass 擦除模式枚举（替代原 Box<dyn Fn> 堆分配）
enum Pass {
    AllOnes,
    AllZeros,
    Random,
}

const DOD_PASSES: [Pass; 7] = [
    Pass::AllOnes,
    Pass::AllZeros,
    Pass::Random,
    Pass::AllOnes,
    Pass::AllZeros,
    Pass::Random,
    Pass::Random,
];

/// 安全擦除 Vec<u8> 并释放
pub fn secure_wipe_vec(mut v: Vec<u8>) {
    v.as_mut_slice().zeroize();
    v.clear();
    v.shrink_to_fit(); // 释放底层堆内存，增强抗取证
}

/// 在已打开的 File 上对指定区间做 DoD 7-pass 覆写。
///
/// C7 修复：vault 内部文件删除原先只做 1 次随机覆写，与 README 宣称的
/// "DoD 5220.22-M 7-pass" 不符。此函数提供与外部源文件擦除一致的强度，
/// 供 secure_delete_file / remove_partition / save_index 复用。
///
/// 区间为 [offset, offset+length)，不会截断文件。
pub fn dod_overwrite_range(file: &mut File, offset: u64, length: u64) -> io::Result<()> {
    dod_overwrite_range_progress(file, offset, length, None)
}

/// 2.8.2：带进度的覆写实现 —— 每 pass 完成并落盘后回调一次（0→100 真实递进）。
/// 旧实现 dod_erase 在 7 个 pass 全部写完后才把进度连发 7 次，大文件擦除期间
/// 进度条全程 0%，用户以为卡死。
pub(crate) fn dod_overwrite_range_progress(
    file: &mut File,
    offset: u64,
    length: u64,
    progress: Option<&dyn Fn(usize)>,
) -> io::Result<()> {
    if length == 0 {
        return Ok(());
    }
    // 3.0.1（F1 修复，硬边界）：区间必须完全落在文件内。调用方传入的
    // offset/length 可能来自头部/索引（部分字段不受认证保护）或损坏数据；
    // 越过 EOF 的 write_all 会把文件撑大（7 遍 × 越界长度且不截断），最坏
    // 可耗尽磁盘并摧毁整柜。任何越界一律拒绝 —— 擦除失败对调用方是
    // 「不影响正确性」的告警，而越界写入是数据毁灭。
    let file_len = file.metadata()?.len();
    let end = offset.checked_add(length).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "擦除区间溢出（offset+length）")
    })?;
    if end > file_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "擦除区间超出文件边界，已拒绝执行",
        ));
    }
    // 2.3.0 修复：32 位平台上 u64 → usize 会截断导致只擦除部分数据，显式拒绝
    //（3.0.1：该检查在边界校验后已不可达（length ≤ file_len ≤ usize 档位），
    // 保留作为纵深防御）
    if length > usize::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "擦除区间超出本平台地址空间",
        ));
    }
    const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB
    let length = length as usize;
    // 2.4.1 优化：随机 pass 改用 ChaCha20Rng（OsRng 一次性播种）流式生成，
    // 旧实现每个 1MB 块都走系统熵源（慢 1-2 个数量级），大文件擦除耗时大幅下降；
    // 覆写随机数据的安全语义不变（攻击者无法预测覆写内容与原数据的关系）
    let mut rng = ChaCha20Rng::from_entropy();
    for (i, pass) in DOD_PASSES.iter().enumerate() {
        let mut written = 0usize;
        while written < length {
            let chunk = std::cmp::min(CHUNK_SIZE, length - written);
            let mut buf = vec![0u8; chunk];
            match pass {
                Pass::AllOnes => buf.fill(0xFF),
                Pass::AllZeros => buf.fill(0x00),
                Pass::Random => rng.fill_bytes(&mut buf),
            }
            file.seek(SeekFrom::Start(offset + written as u64))?;
            file.write_all(&buf)?;
            written += chunk;
        }
        file.sync_all()?;
        if let Some(cb) = progress {
            cb((i + 1) * 100 / DOD_PASSES.len());
        }
    }
    Ok(())
}

/// DoD 5220.22-M 7 次擦除
///
/// 标准 7-pass 模式：
///   Pass 1: 0xFF
///   Pass 2: 0x00
///   Pass 3: 随机
///   Pass 4: 0xFF
///   Pass 5: 0x00
///   Pass 6: 随机
///   Pass 7: 随机
///
/// 每次写入后 fsync 确保落盘，最后删除文件。
///
/// 拒绝操作符号链接，防止被利用删除系统文件。
///
/// 注意：在 COW 文件系统（ZFS/Btrfs/APFS）上覆写同一 offset 不会覆盖物理块，
/// 此函数仍会写入 7 份副本但无法保证擦除原始数据 —— 这是安全擦除的固有限制。
pub fn dod_erase(path: &Path, progress_callback: Option<&dyn Fn(usize)>) -> io::Result<()> {
    // 先检查是否为符号链接，确认文件长度
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "拒绝删除符号链接，跳过",
        ));
    }
    let length = meta.len();

    if length == 0 {
        return fs::remove_file(path);
    }

    // 打开文件（Unix: O_NOFOLLOW, Windows: FILE_FLAG_OPEN_REPARSE_POINT）
    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    #[cfg(windows)]
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(false)
        .custom_flags(0x00200000) // FILE_FLAG_OPEN_REPARSE_POINT
        .open(path)?;
    #[cfg(not(any(unix, windows)))]
    let mut file = OpenOptions::new().write(true).truncate(false).open(path)?;

    // 复用统一的 7-pass 覆写逻辑（C7 修复）；
    // 2.8.2：进度随每个 pass 完成真实上报（旧实现在全部写完后连发 7 次）
    dod_overwrite_range_progress(&mut file, 0, length, progress_callback)?;

    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

/// 2.5.1 新增：基于调用方**预打开句柄**做 DoD 7-pass 擦除并删除文件。
///
/// 消除销毁路径上的 TOCTOU：旧的 `dod_erase(path)` 是「symlink 检查 →
/// 按路径重新打开 → 擦除 → 按路径删除」，检查与擦除之间存在竞态窗口 ——
/// 同用户目录写权限的攻击者可在窗口内把目标替换为指向受害者文件的
/// 硬链接/符号链接，使 7-pass 覆写作用于受害者文件。
///
/// 调用方约定：以 `O_NOFOLLOW`（Unix）/ `FILE_FLAG_OPEN_REPARSE_POINT`
/// （Windows）打开并通过句柄元数据确认非符号链接后，把句柄交给本函数；
/// 擦除与删除全程只作用于该句柄代表的文件对象。
///
/// 删除方式：Windows 优先 delete-on-close（POSIX 语义，句柄关闭即由系统
/// 删除，不经路径，失败时回退 `remove_file`）；非 Windows 回退
/// `remove_file`（此时数据已被覆写，残余风险仅为删除目标被替换，
/// 无法造成保险柜内容泄露）。
pub fn dod_erase_handle(
    file: File,
    path: &Path,
    progress_callback: Option<&dyn Fn(usize)>,
) -> io::Result<()> {
    let length = file.metadata()?.len();
    let mut file = file;
    if length > 0 {
        dod_overwrite_range_progress(&mut file, 0, length, progress_callback)?;
    }
    #[cfg(windows)]
    {
        if mark_delete_on_close(&file) {
            // 标记成功：句柄 drop 时由系统直接删除文件（不经路径）
            drop(file);
            return Ok(());
        }
        // 不支持 delete-on-close（旧系统 / 特殊文件系统）→ 回退按路径删除
    }
    drop(file);
    fs::remove_file(path)
}

/// Windows：把已打开句柄标记为「关闭时删除」（POSIX 删除语义）。
/// 成功返回 true；失败（旧系统 / 文件系统不支持）返回 false 由调用方回退。
#[cfg(windows)]
fn mark_delete_on_close(file: &File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    // 注意：windows-rs 0.57 中 `FileDispositionInfoEx` 是模块级常量（该版本将其生成为
    // 带 pub i32 的 newtype + 自由常量），而非常量项；`SetFileInformationByHandle`
    // 期望 `HANDLE(isize)`，而 `as_raw_handle()` 返回 `*mut c_void`，故需显式转换。
    use windows::Win32::Storage::FileSystem::{
        FileDispositionInfoEx, SetFileInformationByHandle, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX,
        FILE_DISPOSITION_INFO_EX_FLAGS,
    };

    // POSIX_SEMANTICS：即使其他进程仍持有该文件句柄也强制在关闭时删除，
    // 与 unlink 语义一致（避免杀毒软件等第三方句柄导致文件残留）。
    let mut info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0 | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0,
        ),
    };
    let ok = unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle() as isize),
            FileDispositionInfoEx,
            &mut info as *mut _ as *const core::ffi::c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    ok.is_ok()
}

#[cfg(test)]
mod tests {
    //! 3.1.1（审计修复）：擦除层的硬边界（F1）与 7-pass 行为此前只有集成测试
    //! 间接覆盖。越界覆写是「数据毁灭」级别的缺陷，必须有直接用例。

    use super::*;
    use std::io::Read;

    fn temp_file(tag: &str, len: usize) -> (std::path::PathBuf, File) {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "lynvault-wipe-test-{}-{}.bin",
            tag,
            std::process::id()
        ));
        // 读写打开：断言需要回读覆写结果
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&p)
            .expect("创建临时文件失败");
        f.set_len(len as u64).expect("设置长度失败");
        (p, f)
    }

    #[test]
    fn overwrite_rejects_out_of_bounds_without_growing_file() {
        let (p, mut f) = temp_file("oob", 1024);
        // 越过 EOF 的区间必须拒绝 —— 旧实现的 write_all 会把文件撑大
        assert!(dod_overwrite_range(&mut f, 512, 1024).is_err());
        assert!(dod_overwrite_range(&mut f, 0, 2048).is_err());
        // offset + length 溢出必须显式报错而不是 panic
        assert!(dod_overwrite_range(&mut f, u64::MAX - 8, 32).is_err());
        assert_eq!(
            f.metadata().unwrap().len(),
            1024,
            "拒绝路径不得改变文件长度"
        );
        // 合法区间照常执行；零长区间是无操作
        assert!(dod_overwrite_range(&mut f, 0, 1024).is_ok());
        assert!(dod_overwrite_range(&mut f, 1024, 0).is_ok());
        drop(f);
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn overwrite_scribbles_the_range() {
        let (p, mut f) = temp_file("scribble", 64);
        dod_overwrite_range(&mut f, 0, 64).expect("合法区间必须可覆写");
        let mut buf = vec![0u8; 64];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read_exact(&mut buf).unwrap();
        // 7-pass 的最后一轮是随机数据 —— 结果不应仍是全零
        assert!(buf.iter().any(|&b| b != 0), "7-pass 覆写后不应仍是全零");
        drop(f);
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn secure_wipe_vec_clears_before_release() {
        let mut v = vec![0xAAu8; 32];
        // 手工模拟：零化后内容必须全 0（函数会 shrink_to_fit，无法再读取）
        v.as_mut_slice().zeroize();
        assert!(v.iter().all(|&b| b == 0));
        secure_wipe_vec(v); // 仅验证不 panic
    }
}
