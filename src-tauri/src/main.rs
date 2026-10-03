// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
// 2.8.0：剪贴板保护 —— 模块本身跨平台（start/stop 在非 Windows 为空实现），
// 内部 win32 代码全部 cfg(windows) 隔离；不要在声明处 gate，
// 否则 commands.rs 的无条件调用在 Linux 编译失败
mod clipboard_guard;
#[cfg(windows)]
mod file_assoc;
mod settings;
mod single_instance;
#[cfg(windows)]
mod system_events;

use std::fs::OpenOptions;

/// 2.8.0：窗口标题版本号单一来源（2.8.2/I3：与其他三处版本号统一）
const APP_VERSION: &str = "2.8.2";

/// 2.8.0：防截屏开关（对主窗口应用 SetWindowDisplayAffinity）。
/// - 开启：WDA_EXCLUDEFROMCAPTURE（Win10 2004+，截屏/录屏/远程共享中窗口直接消失）；
///   该值不被支持时（旧系统）退化为 WDA_MONITOR（截屏中变黑块）；
/// - 关闭：WDA_NONE。
///
/// 2.8.1 修复返回值语义：返回「请求的保护状态是否实际生效」——
/// 旧实现成功时返回 true 而调用方拿它当「失败」告警，恰好写反。
pub fn apply_anti_screenshot(app: &tauri::AppHandle, enable: bool) -> bool {
    #[cfg(windows)]
    {
        use tauri::Manager;
        use windows::Win32::Foundation::HWND;
        let want = if enable {
            windows::Win32::UI::WindowsAndMessaging::WDA_EXCLUDEFROMCAPTURE
        } else {
            windows::Win32::UI::WindowsAndMessaging::WDA_NONE
        };
        let Some(win) = app.get_window("main") else {
            return false;
        };
        let Ok(h) = win.hwnd() else {
            return false;
        };
        // tauri 1.x 的 hwnd() 返回其内部 windows 版本的 HWND（isize 语义），
        // 按数值转换到本 crate 的 windows 0.57 HWND
        let hwnd = HWND(h.0);
        if unsafe {
            windows::Win32::UI::WindowsAndMessaging::SetWindowDisplayAffinity(hwnd, want)
        }
        .is_ok()
        {
            return true;
        }
        if enable {
            // WDA_EXCLUDEFROMCAPTURE 需 Win10 2004+：退化为 WDA_MONITOR（截屏中变黑块）
            unsafe {
                windows::Win32::UI::WindowsAndMessaging::SetWindowDisplayAffinity(
                    hwnd,
                    windows::Win32::UI::WindowsAndMessaging::WDA_MONITOR,
                )
            }
            .is_ok()
        } else {
            false
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (app, enable);
        false
    }
}

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
//   日志文件是不加密、跨重启残留、且落在取证工具常规扫描位置上的
//   文件 —— 对本产品而言「用户拿哪些文件来加密」本身就是最敏感的信息，
//   这与抗取证承诺直接矛盾。vault-core 内所有 warn/error 现已只记错误本身；
//   需要逐条追溯的场景请用保险柜内的加密审计日志（AuditLog）；
// - 2.8.2（M5）：日志迁出公开可预测的 `%TEMP%\LynVault.log` —— 该路径可被
//   预建为指向受害者文件的 NTFS 硬链接（日志内容注入目标文件；1MB 轮转的
//   清零覆写会直接毁掉目标文件）。现写入 `%LOCALAPPDATA%\LynVault\logs\`
//   （不可用回退 `%TEMP%\LynVault\logs\`），且每次写入以
//   `FILE_FLAG_OPEN_REPARSE_POINT` 打开（符号链接不跟随）并经句柄元数据
//   校验「非重解析点 + 硬链接数为 1」，校验失败放弃本次写入；
// - 超过 1 MB 时**先覆写旧内容再截断**，不再用 set_len(0)（那会在磁盘上
//   留下可恢复的旧日志残留）；
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
        let _guard = self.lock.lock();

        // 2.8.2（M5）：每次写入都以 FILE_FLAG_OPEN_REPARSE_POINT 打开
        //（符号链接不跟随），并用句柄元数据校验「非重解析点 + 硬链接数 1」
        // —— 校验失败放弃本次写入（防硬链接注入 / 轮转覆写用户文件）。
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&self.path)
            {
            // 硬链接数须为 1（std 的 number_of_links 在 stable 不可用，
            // 走 GetFileInformationByHandle）；重解析点拒绝
            use std::os::windows::fs::MetadataExt;
            use std::os::windows::io::AsRawHandle;
                use windows::Win32::Foundation::HANDLE;
                use windows::Win32::Storage::FileSystem::{
                    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
                };
                let mut info = BY_HANDLE_FILE_INFORMATION::default();
                let links_ok = unsafe {
                    GetFileInformationByHandle(HANDLE(f.as_raw_handle() as isize), &mut info)
                }
                .map(|_| info.nNumberOfLinks == 1)
                .unwrap_or(false);
                let attrs = f.metadata().map(|m| m.file_attributes()).unwrap_or(0xFFFF);
                if !links_ok || attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return; // 目标被做了手脚：宁可不写日志也不注入/覆写他人文件
                }
                rotate_and_write(&mut f, &line);
            }
        }
        #[cfg(not(windows))]
        {
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&self.path)
            {
                rotate_and_write(&mut f, &line);
            }
        }
    }

    fn flush(&self) {}
}

/// 2.6.1 安全轮转：先整体覆写再截断（从 FileLogger::log 抽出）。
#[cfg(windows)]
fn rotate_and_write(f: &mut std::fs::File, line: &str) {
    rotate_and_write_inner(f, line)
}

#[cfg(not(windows))]
fn rotate_and_write(f: &mut std::fs::File, line: &str) {
    rotate_and_write_inner(f, line)
}

fn rotate_and_write_inner(f: &mut std::fs::File, line: &str) {
    use std::io::{Seek, SeekFrom, Write};
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

/// 2.8.2（M5）：日志目录候选 —— 优先 `%LOCALAPPDATA%\LynVault\logs`，
/// 不可用回退 `%TEMP%\LynVault\logs`（不再直接落在公开可预测的
/// `%TEMP%\LynVault.log`）。
fn log_file_candidates() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Some(base) = std::env::var_os("LOCALAPPDATA") {
        let dir = std::path::PathBuf::from(base).join("LynVault").join("logs");
        if std::fs::create_dir_all(&dir).is_ok() {
            paths.push(dir.join("LynVault.log"));
        }
    }
    let fallback = std::env::temp_dir().join("LynVault").join("logs");
    if std::fs::create_dir_all(&fallback).is_ok() {
        let p = fallback.join("LynVault.log");
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    paths
}

fn init_logging() {
    let path = log_file_candidates()
        .into_iter()
        .next()
        .unwrap_or_else(|| std::env::temp_dir().join("LynVault.log"));
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

/// 启动失败的最终出口：日志已由调用方落盘，这里弹系统消息框告知原因。
/// 发布版（windows_subsystem="windows"）没有控制台，弹窗是用户唯一能看到的线索。
#[cfg(windows)]
fn fatal_startup_error(title: &str, msg: &str) {
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    let t = to_wide(title);
    let m = to_wide(msg);
    unsafe {
        MessageBoxW(None, PCWSTR(m.as_ptr()), PCWSTR(t.as_ptr()), MB_OK | MB_ICONERROR);
    }
}

#[cfg(not(windows))]
fn fatal_startup_error(title: &str, msg: &str) {
    let _ = title;
    eprintln!("[LynVault] {}", msg);
}

/// WebView2 数据目录候选列表（按优先级）：
/// 不再直接用 %LOCALAPPDATA%\<bundle identifier>（该目录被残留进程持有句柄 /
/// 处于删除挂起态时无法恢复），改为 %LOCALAPPDATA%\LynVault\WebView2Data；
/// 不可用时回退临时目录。两个目录都创建失败时返回空表（调用方不设置环境变量，
/// WebView2 用系统默认位置）。
fn webview2_data_dir_candidates() -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    if let Some(base) = std::env::var_os("LOCALAPPDATA") {
        let dir = std::path::PathBuf::from(base)
            .join("LynVault")
            .join("WebView2Data");
        if std::fs::create_dir_all(&dir).is_ok() {
            dirs.push(dir);
        }
    }
    let fallback = std::env::temp_dir().join("LynVault").join("WebView2Data");
    if std::fs::create_dir_all(&fallback).is_ok() && !dirs.contains(&fallback) {
        dirs.push(fallback);
    }
    dirs
}

/// 创建主窗口。`transparent` 失败时由调用方降级重试（透明 → 不透明）。
/// 2.7.1 起窗口由代码创建（tauri.conf.json 的 windows 置空），启动失败可控。
/// 2.8.0：窗口尺寸支持从设置持久化读取（无配置时 960×620 默认值）。
fn create_main_window(app: &tauri::App, transparent: bool, width: f64, height: f64) -> Result<(), String> {
    tauri::WindowBuilder::new(app, "main", tauri::WindowUrl::default())
        .title(format!("LynVault {}", APP_VERSION))
        .inner_size(width, height)
        .resizable(true)
        .fullscreen(false)
        .decorations(false)
        .transparent(transparent)
        .build()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// 2.8.2：空闲自动锁定的后端兜底（仅 Windows）。
///
/// 前端的空闲锁定依赖 JS setTimeout —— WebView2 后台计时器节流（最小化窗口
/// 的 intensive throttling 下定时器可被拖延数分钟）或渲染进程挂起/崩溃期间，
/// 保险柜保持解锁。本线程每 5 秒检查一次**系统级**空闲时间
///（GetLastInputInfo：任何键鼠输入都会重置），超过设置的 autolock_minutes 且
/// 保险柜处于打开状态时，执行与锁屏相同的关闭流程（system_lock_vault）。
///
/// 取值来源：settings::load_active()（未启用持久化时为默认 2 分钟，与前端
/// 默认一致；用户改了时长但未启用持久化时，前端放宽、后端仍按默认收紧 ——
/// 偏保守方向，可接受）。
#[cfg(windows)]
fn idle_lock_watchdog(app: tauri::AppHandle) {
    use tauri::Manager;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        {
            let state = app.state::<commands::AppState>();
            if !state.vault_open() {
                continue;
            }
        }
        let minutes = settings::load_active()
            .map(|(_, s)| s.autolock_minutes)
            .unwrap_or(2);
        if minutes == 0 {
            continue; // 用户显式禁用自动锁定
        }
        let idle_ms = last_input_idle_ms();
        if idle_ms >= minutes as u64 * 60 * 1000 {
            // 与锁屏同一关闭流程：关柜 + 停剪贴板保护 + 通知前端回启动弹窗
            let _ = commands::system_lock_vault(&app);
        }
    }
}

/// 系统级空闲毫秒数（距最后一次键鼠输入）
#[cfg(windows)]
fn last_input_idle_ms() -> u64 {
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    unsafe {
        let mut info = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        if GetLastInputInfo(&mut info).as_bool() {
            GetTickCount().saturating_sub(info.dwTime) as u64
        } else {
            0 // 查询失败不触发锁定（前端定时器仍在）
        }
    }
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
    // 2.8.2（M6）：改用 args_os —— 旧实现 std::env::args() 遇到无法转 UTF-8
    // 的参数（如带未配对代理项的 .lyt 文件名）直接 panic，GUI 子系统无控制台，
    // 表现为「双击后什么都没发生」。
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    commands::set_launch_vault_arg(single_instance::extract_vault_arg(argv.iter().cloned()));

    // 单实例竞争：非首实例在此转发参数并退出（不创建窗口，无闪烁）
    if !single_instance::acquire_or_forward(argv) {
        return;
    }

    // 2.7.1 修复：启动失败不再表现为「闪退」。旧实现把 Builder::run() 的结果交给
    // .expect()，窗口 / WebView2 初始化一旦失败（E_UNEXPECTED / ERROR_BUSY /
    // ACCESS_DENIED，或数据目录 create_dir_all 的 PermissionDenied）只会让进程
    // panic 退出；发布版是 windows_subsystem="windows"、没有控制台，panic 不走
    // log，用户看到的就是「双击后什么都没发生」，%TEMP%\LynVault.log 里同样
    // 一片空白。现改为 build() 后手动创建主窗口（tauri.conf.json 的 windows 置空），
    // 失败依次降级重试：透明 → 不透明 → 换备用 WebView2 数据目录 → 不透明；
    // 仍失败才记日志并弹系统消息框告之原因。
    let app = match tauri::Builder::default()
        .manage(commands::AppState::new())
        .setup(|app| {
            // 首实例：启动单实例监听线程（持有端口监听器直到进程退出）
            let handle = app.handle().clone();
            std::thread::spawn(move || single_instance::server_loop(handle));
            // 2.8.0：启动系统事件监听（锁屏 / 睡眠 / 注销 → 自动关闭保险柜）
            #[cfg(windows)]
            system_events::spawn(app.handle().clone());
            // 2.8.2：空闲自动锁定的后端兜底（前端 JS 定时器可被 WebView 后台
            // 节流 / 渲染进程挂起拖住，主防线不能只放在 JS 上）
            #[cfg(windows)]
            {
                let handle = app.handle().clone();
                std::thread::spawn(move || idle_lock_watchdog(handle));
            }
            // 2.4.1：后台注册 .lyt 用户级文件关联（best-effort，不阻塞启动；
            // 用户已关联到其他程序时不覆盖）—— 仅 Windows
            #[cfg(windows)]
            std::thread::spawn(file_assoc::register_if_absent);
            Ok(())
        })
        // 2.8.2（H2）：记录主进程侧真实拖放载荷 —— 导入命令要求传入路径
        // 与该载荷完全一致，WebView 伪造的字符串不再被信任。
        // 全局窗口事件处理器挂在 Builder 上（App/Window 级 API 在 Tauri 1.x
        // 的形态不同，全局处理器覆盖全部窗口且在窗口创建前生效）。
        .on_window_event(|event| {
            if let tauri::WindowEvent::FileDrop(drop_event) = event.event() {
                // tauri 1.x：tauri::FileDropEvent::Dropped(Vec<PathBuf>)
                if let tauri::FileDropEvent::Dropped(paths) = drop_event {
                    let strs: Vec<String> = paths
                        .iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect();
                    commands::record_dropped_paths(strs);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::create_vault,
            commands::open_vault,
            commands::close_vault,
            commands::list_folder,
            commands::import_files_batch,
            commands::import_folder,
            commands::import_dropped_paths,
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

            // 2.8.0 新增：改密码 / 移动 / 搜索 / 审计 / 体检 / 锁定信息 / 设置
            commands::change_password,
            commands::move_items,
            commands::list_all_folders,
            commands::search_files,
            commands::get_audit_log,
            commands::verify_vault_integrity,
            commands::get_lock_info,
            commands::get_settings,
            commands::enable_persistence,
            commands::disable_persistence,
            commands::save_settings,

            // 2.8.2（H2）新增：对话框令牌化 —— 文件/目录选择改由后端弹出，
            // 所选路径登记进一次性令牌表，导入/提取命令凭令牌取路径
            commands::dialog_pick_files,
            commands::dialog_pick_folder,
        ])
        .build(tauri::generate_context!())
    {
        Ok(app) => app,
        Err(e) => {
            log::error!("Tauri 应用初始化失败: {:?}", e);
            fatal_startup_error(
                "LynVault 启动失败",
                &format!(
                    "应用初始化失败：{:?}

常见原因：WebView2 Runtime 缺失或损坏、用户数据目录无写权限。请修复后重新启动。",
                    e
                ),
            );
            return;
        }
    };

    // 主窗口降级重试：每个 WebView2 数据目录先试透明（与旧版观感一致）再试
    // 不透明；全部失败才放弃并告之原因。候选目录为空时不设置环境变量
    //（WebView2 用系统默认位置）。
    // 2.8.0：窗口尺寸 / 防截屏从设置持久化读取（未启用时用默认值，防截屏默认开启）
    let (cfg_w, cfg_h, anti_screenshot) = match settings::load_active() {
        Some((_, s)) => (s.window_width, s.window_height, s.anti_screenshot),
        None => (960.0, 620.0, true),
    };
    let data_dirs = webview2_data_dir_candidates();
    let attempts: Vec<Option<&std::path::Path>> = if data_dirs.is_empty() {
        vec![None]
    } else {
        data_dirs.iter().map(|d| Some(d.as_path())).collect()
    };
    let mut last_err: Option<String> = None;
    let mut created = false;
    'outer: for dir in attempts {
        if let Some(d) = dir {
            std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", d);
        }
        for &transparent in &[true, false] {
            match create_main_window(&app, transparent, cfg_w, cfg_h) {
                Ok(()) => {
                    created = true;
                    break 'outer;
                }
                Err(e) => {
                    log::warn!("主窗口创建失败（transparent={}，降级重试）: {}", transparent, e);
                    last_err = Some(e);
                }
            }
        }
    }
    if !created {
        let err = last_err.unwrap_or_default();
        log::error!("主窗口创建失败（含全部降级重试）: {}", err);
        fatal_startup_error(
            "LynVault 启动失败",
            &format!(
                "主窗口创建失败：{}

常见原因：WebView2 Runtime 缺失或损坏、用户数据目录无写权限或被占用。请修复后重新启动。",
                err
            ),
        );
        return;
    }

    // 2.8.0：按设置应用防截屏（默认开启）。
    // 2.8.1：仅在实际未生效且用户要求开启时告警（旧判断恰好写反）
    let applied = apply_anti_screenshot(&app.handle(), anti_screenshot);
    if anti_screenshot && !applied {
        log::warn!("防截屏保护未生效（系统不支持或窗口句柄异常）");
    }

    app.run(|_app, _event| {});
}
