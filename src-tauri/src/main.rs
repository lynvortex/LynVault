// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
#[cfg(windows)]
mod file_assoc;
mod single_instance;

use std::fs::OpenOptions;

// ───────────────── 2.5.1 新增：日志初始化 ─────────────────
//
// 2.4.1 及之前：main 从未初始化任何 logger —— vault-core / commands /
// single_instance / file_assoc 里的全部 log::warn! / log::error! 都是空操作，
// 「安全擦除失败」「单实例端口降级」「.lyt 关联注册失败」等安全相关告警被
// 静默吞掉，出问题时完全无线索可查。
//
// 现在内置一个零依赖的文件 logger（不引入 env_logger 等新依赖）：
// - 仅记录 Warn 及以上 —— info/debug 不落盘；
// - **日志内容不得包含用户路径、文件名或虚拟路径**（2.6.1 修复）：
//   旧实现的告警会写入导入失败的真实路径、批量提取失败的 vpath，而
//   %TEMP%\LynVault.log 是不加密、跨重启残留、且落在取证工具常规扫描位置上的
//   文件 —— 对本产品而言「用户拿哪些文件来加密」本身就是最敏感的信息，
//   这与抗取证承诺直接矛盾。vault-core 内所有 warn/error 现已只记错误本身；
//   需要逐条追溯的场景请用保险柜内的加密审计日志（AuditLog）；
// - 写入 %TEMP%\LynVault.log，超过 1 MB 时**先覆写旧内容再截断**，
//   不再用 set_len(0)（那会在磁盘上留下可恢复的旧日志残留）；
// - 发布版（windows_subsystem="windows"）没有控制台，文件是唯一出口；
//   debug 构建同时输出到 stderr 便于开发调试。

/// 日志文件体积上限（1 MB）
const LOG_FILE_MAX: u64 = 1024 * 1024;

struct FileLogger {
    path: std::path::PathBuf,
    /// 2.6.1：轮转需要覆写文件头部，因此必须去掉 O_APPEND ——
    /// 旧实现依赖 append 模式提供的原子追加语义，现在改为自行串行化。
    lock: std::sync::Mutex<()>,
}

impl log::Log for FileLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "[{}] {:5} {}\n",
            utc_timestamp(),
            record.level(),
            record.args()
        );
        #[cfg(debug_assertions)]
        eprint!("[LynVault] {}", line);
        use std::io::{Seek, SeekFrom, Write};
        let _guard = self.lock.lock();
        if let Ok(mut f) = OpenOptions::new().create(true).write(true).open(&self.path) {
            // 2.6.1 安全轮转：先整体覆写再截断。
            // 旧实现直接 set_len(0)，只是把旧内容标记为可复用，磁盘上仍可恢复 ——
            // 对一个把「擦除」当卖点的产品，这种残留不能留。
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            if len > LOG_FILE_MAX {
                let zeros = [0u8; 8192];
                if f.seek(SeekFrom::Start(0)).is_ok() {
                    let mut left = len;
                    while left > 0 {
                        let n = std::cmp::min(left, zeros.len() as u64) as usize;
                        if f.write_all(&zeros[..n]).is_err() {
                            break;
                        }
                        left -= n as u64;
                    }
                    let _ = f.sync_all();
                }
                let _ = f.set_len(0);
            }
            if f.seek(SeekFrom::End(0)).is_ok() {
                let _ = f.write_all(line.as_bytes());
            }
        }
    }

    fn flush(&self) {}
}

fn init_logging() {
    let path = std::env::temp_dir().join("LynVault.log");
    let _ = log::set_boxed_logger(Box::new(FileLogger {
        path,
        lock: std::sync::Mutex::new(()),
    }));
    log::set_max_level(log::LevelFilter::Warn);
}

/// epoch 秒 → UTC 时间戳（手写 civil-from-days，避免引入 chrono）
fn utc_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60
    )
}

/// Howard Hinnant 的 days→(y,m,d) 算法（公历，UTC）
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn main() {
    // 2.5.1 修复：必须在一切可能产生告警的逻辑（单实例、命令线程）之前初始化
    init_logging();
    // ── 2.4.1 新功能：.lyt 文件导航到软件后自动识别 ──
    // 场景 1：文件管理器双击 .lyt（程序启动时已自注册用户级文件关联，
    //        见 file_assoc.rs）→ 系统以「LynVault.exe <文件路径>」启动 →
    //        解析 argv 存入全局，前端启动时经 get_launch_vault_arg 读取
    //        并直接进入密码输入。
    // 场景 2：程序已在运行时再次双击 .lyt → 单实例端口被占 → 把路径
    //        转发给已运行实例后本进程立即退出；已运行实例聚焦窗口并
    //        向前端发 vault-file-requested 事件。
    // 场景 3：把 .lyt 拖到窗口（拖放识别在前端 check_vault_file 完成）。
    let argv: Vec<String> = std::env::args().skip(1).collect();
    commands::set_launch_vault_arg(single_instance::extract_vault_arg(argv.iter().cloned()));

    // 单实例竞争：非首实例在此转发参数并退出（不创建窗口，无闪烁）
    if !single_instance::acquire_or_forward(argv) {
        return;
    }

    tauri::Builder::default()
        .manage(commands::AppState::new())
        .setup(|app| {
            // 首实例：启动单实例监听线程（持有端口监听器直到进程退出）
            let handle = app.handle().clone();
            std::thread::spawn(move || single_instance::server_loop(handle));
            // 2.4.1：后台注册 .lyt 用户级文件关联（best-effort，不阻塞启动；
            // 用户已关联到其他程序时不覆盖）—— 仅 Windows
            #[cfg(windows)]
            std::thread::spawn(file_assoc::register_if_absent);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::create_vault,
            commands::open_vault,
            commands::close_vault,
            commands::list_folder,
            commands::import_file,
            commands::import_files_batch,
            commands::import_folder,
            commands::import_dropped_paths,
            commands::extract_file,
            commands::extract_files,
            commands::delete_files,
            commands::delete_folder,
            commands::new_folder,
            commands::rename_item,
            commands::add_partition,
            commands::remove_partition,
            commands::list_partitions,
            commands::defragment_vault,
            commands::destroy_vault,
            commands::get_file_info,
            commands::load_file_content,
            commands::preview_office_file,
            // 2.5.1 新增：txt 预览直接编辑保存
            commands::update_file_content,

            commands::scan_vault_files,
            commands::check_extract_all_dest,
            commands::extract_all_files,
            commands::get_file_icon,

            // 2.4.1 新增：.lyt 自动识别 + 前端就绪通知
            commands::check_vault_file,
            commands::get_launch_vault_arg,
            commands::frontend_ready,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
