//! 安全擦除与内存零化辅助函数
use rand::{rngs::OsRng, RngCore};
use std::fs::{self, OpenOptions};
use std::io::{self, Write, Seek, SeekFrom};
use std::path::Path;

/// 安全擦除 Vec<u8> 并释放
pub fn secure_wipe_vec(mut v: Vec<u8>) {
    for byte in &mut v {
        *byte = 0;
    }
    v.clear();
    v.shrink_to_fit();
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
pub fn dod_erase(path: &Path, progress_callback: Option<&dyn Fn(usize)>) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    let length = metadata.len() as usize;
    if length == 0 {
        return fs::remove_file(path);
    }

    let _rng = OsRng;

    // 7-pass 模式定义
    let passes: Vec<Box<dyn Fn(&mut [u8])>> = vec![
        Box::new(|buf: &mut [u8]| { for b in buf.iter_mut() { *b = 0xFF; } }),
        Box::new(|buf: &mut [u8]| { for b in buf.iter_mut() { *b = 0x00; } }),
        Box::new(|buf: &mut [u8]| { OsRng.fill_bytes(buf); }),
        Box::new(|buf: &mut [u8]| { for b in buf.iter_mut() { *b = 0xFF; } }),
        Box::new(|buf: &mut [u8]| { for b in buf.iter_mut() { *b = 0x00; } }),
        Box::new(|buf: &mut [u8]| { OsRng.fill_bytes(buf); }),
        Box::new(|buf: &mut [u8]| { OsRng.fill_bytes(buf); }),
    ];

    // 分块写入，避免大文件 OOM
    const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB

    for (i, fill_fn) in passes.iter().enumerate() {
        let mut file = OpenOptions::new().write(true).truncate(false).open(path)?;
        let mut written = 0usize;

        while written < length {
            let chunk = std::cmp::min(CHUNK_SIZE, length - written);
            let mut buf = vec![0u8; chunk];
            fill_fn(&mut buf);

            file.seek(SeekFrom::Start(written as u64))?;
            file.write_all(&buf)?;
            written += chunk;
        }

        file.sync_all()?;

        if let Some(cb) = progress_callback {
            cb((i + 1) * 100 / passes.len());
        }
    }

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
