//! 安全擦除与内存零化辅助函数
use rand::{rngs::OsRng, RngCore};
use std::fs::{self, OpenOptions};
use std::io::{self, Write, Seek, SeekFrom};
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
pub fn dod_erase(path: &Path, progress_callback: Option<&dyn Fn(usize)>) -> io::Result<()> {
    // 先检查是否为符号链接，确认文件长度
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "拒绝删除符号链接，跳过"));
    }
    let length = meta.len() as usize;
    if length == 0 {
        return fs::remove_file(path);
    }
    let length = length; // 移除 shadowing warning

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

    // 分块写入，避免大文件 OOM
    const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB

    for (i, pass) in DOD_PASSES.iter().enumerate() {
        let mut written = 0usize;

        while written < length {
            let chunk = std::cmp::min(CHUNK_SIZE, length - written);
            let mut buf = vec![0u8; chunk];
            match pass {
                Pass::AllOnes => buf.fill(0xFF),
                Pass::AllZeros => buf.fill(0x00),
                Pass::Random => OsRng.fill_bytes(&mut buf),
            }

            file.seek(SeekFrom::Start(written as u64))?;
            file.write_all(&buf)?;
            written += chunk;
        }

        file.sync_all()?;

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
