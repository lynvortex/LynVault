//! 安全擦除与内存零化辅助函数
use rand::{rngs::OsRng, RngCore};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
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
    if length == 0 {
        return Ok(());
    }
    // 2.3.0 修复：32 位平台上 u64 → usize 会截断导致只擦除部分数据，显式拒绝
    if length > usize::MAX as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "擦除区间超出本平台地址空间"));
    }
    const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB
    let length = length as usize;
    for pass in DOD_PASSES.iter() {
        let mut written = 0usize;
        while written < length {
            let chunk = std::cmp::min(CHUNK_SIZE, length - written);
            let mut buf = vec![0u8; chunk];
            match pass {
                Pass::AllOnes => buf.fill(0xFF),
                Pass::AllZeros => buf.fill(0x00),
                Pass::Random => OsRng.fill_bytes(&mut buf),
            }
            file.seek(SeekFrom::Start(offset + written as u64))?;
            file.write_all(&buf)?;
            written += chunk;
        }
        file.sync_all()?;
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
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "拒绝删除符号链接，跳过"));
    }
    let length = meta.len();

    if length == 0 {
        return fs::remove_file(path);
    }

    // 打开文件（Unix: O_NOFOLLOW, Windows: FILE_FLAG_OPEN_REPARSE_POINT）
    #[cfg(unix)]
    let mut file = OpenOptions::new().write(true).truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    #[cfg(windows)]
    let mut file = OpenOptions::new().write(true).truncate(false)
        .custom_flags(0x00200000) // FILE_FLAG_OPEN_REPARSE_POINT
        .open(path)?;
    #[cfg(not(any(unix, windows)))]
    let mut file = OpenOptions::new().write(true).truncate(false).open(path)?;

    // 复用统一的 7-pass 覆写逻辑（C7 修复）
    dod_overwrite_range(&mut file, 0, length)?;

    for (i, _) in DOD_PASSES.iter().enumerate() {
        if let Some(cb) = progress_callback {
            cb((i + 1) * 100 / DOD_PASSES.len());
        }
    }

    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

/// 安全删除多个文件（DoD 7-pass）
pub fn dod_erase_files(paths: &[&Path], progress_callback: Option<&dyn Fn(usize, &str)>) -> io::Result<()> {
    for (i, path) in paths.iter().enumerate() {
        let name = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let file_progress = |pct: usize| {
            if let Some(cb) = &progress_callback {
                // 当前文件进度映射到总体进度
                let base = i * 100 / paths.len();
                let range = 100 / paths.len();
                let overall = base + pct * range / 100;
                cb(overall, &name);
            }
        };
        dod_erase(path, Some(&file_progress))?;
    }
    Ok(())
}
