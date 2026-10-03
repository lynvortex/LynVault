//! 2.4.1 新增：单实例运行 + .lyt 文件关联参数转发（纯 std 实现，无新增依赖）。
//!
//! 为什么不用 tauri-plugin-single-instance：crates.io 上的该插件从 2.0 起只支持
//! Tauri v2，Tauri v1 只能用 git 依赖（plugins-workspace v1 分支）。为避免引入
//! 重量级 git 依赖，这里用「127.0.0.1 固定端口 + 协议握手」实现同等能力：
//!
//! - 首个实例：绑定派生端口，起监听线程；收到合法请求后聚焦窗口、
//!   向前端发 `vault-file-requested` 事件（负载为文件路径）。
//! - 第二个实例：绑定失败 → 与占用者做协议握手 → 握手成功说明是本程序的
//!   既有实例 → 把双击的 .lyt 路径转发过去后立即退出（不闪窗口）；
//!   握手失败说明端口被无关程序占用 → 降级为普通启动（不做单实例）。
//!
//! 安全性说明：监听只绑定 127.0.0.1（不接受外部网络连接）；收到路径后会做
//! 扩展名 + magic bytes 双重校验，非保险柜文件直接忽略。最坏影响只是本地
//! 其他进程让本程序弹出一个密码输入框，等价于用户自己拖放文件。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager};

/// 前端就绪标志：app.js 初始化完成后调用 `frontend_ready` 命令置位。
/// 转发请求到达时若前端尚未就绪，最多等待 60 秒再发事件，避免事件丢失。
pub static FRONTEND_READY: AtomicBool = AtomicBool::new(false);

/// 协议握手串：区分「本程序的单实例端口」与「恰好占用同端口的无关程序」
const PROTO_HELLO: &str = "LYNVAULT_SI_V1";

/// 2.5.1 新增：单实例协议单行长度上限。本地恶意进程连上端口后发送
/// 无换行的超长数据，旧 read_line 会无限分配内存（本地 DoS）。
/// Windows 长路径上限约 32K 字符，64 KB 足够且留有余量。
const MAX_LINE_BYTES: u64 = 64 * 1024;

/// 2.6.1 新增：单实例连接的最大并发处理数。每个连接独立线程处理（见
/// `server_loop`），无上限会让本地恶意进程通过快速建立大量连接耗尽线程栈；
/// 正常使用（用户双击 .lyt）远不会超过该值。
const MAX_CONCURRENT_CONNS: usize = 8;

/// 应用标识（与 tauri.conf.json 的 identifier 一致），用于派生端口
const APP_ID: &str = "com.lynvault.app";

/// 首实例绑定的监听器（main 里绑定成功后暂存，setup 回调中取走）
static LISTENER: Mutex<Option<TcpListener>> = Mutex::new(None);

/// FNV-1a 哈希：稳定派生端口，避免硬编码端口与其他常用服务冲突
fn fnv1a(s: &str) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for b in s.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn si_port() -> u16 {
    20000 + (fnv1a(APP_ID) % 20000) as u16
}

/// 2.8.1 新增：拒绝远程 / 设备路径。
///
/// 单实例端口接受任意本地进程的连接（2.7.1 已把「打开动作」置于用户确认之后），
/// 但 `looks_like_vault` 的 magic bytes 预检发生在确认**之前** —— 路径若是
/// `\\server\share\...`（UNC）或 `\\.\device`，OpenClipboard 式的文件打开会
/// 无提示地发起 SMB 访问，构成免交互的 NTLM 凭据外泄 / 中继触发原语。
/// 本程序的用户场景永远是「本地磁盘上的保险柜文件」，直接拒绝一切
/// UNC / 设备路径（`\\?\C:\...` verbatim 本地路径仍放行）。
fn is_remote_or_device_path(p: &str) -> bool {
    let t = p.trim_start_matches('"');
    // verbatim 前缀剥掉后再判断：\\?\C:\... 是本地路径，\\?\UNC\... 是远程
    let t = t.strip_prefix(r"\\?\").unwrap_or(t);
    t.starts_with(r"\\")
}

/// 判断路径是否为 LynVault 保险柜文件（扩展名 + magic bytes 双重校验）。
/// 2.8.1：远程 / 设备路径不做文件打开（见 is_remote_or_device_path）。
fn looks_like_vault(p: &str) -> bool {
    if is_remote_or_device_path(p) {
        return false;
    }
    let path = Path::new(p);
    let ext_ok = path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("lyt") || e.eq_ignore_ascii_case("vault"))
        .unwrap_or(false);
    ext_ok && vault_core::is_vault_file(path)
}

/// 从命令行参数中提取第一个保险柜文件路径（供启动参数识别用）
pub fn extract_vault_arg<I: Iterator<Item = String>>(args: I) -> Option<String> {
    args.map(|a| a.trim_matches('"').to_string())
        .find(|a| looks_like_vault(a))
}

/// 单实例竞争入口。返回 true = 我是首实例（正常启动）；
/// 返回 false = 已有实例在运行且参数已转发，调用方应立即退出。
pub fn acquire_or_forward(args: Vec<String>) -> bool {
    let port = si_port();
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => {
            // 首实例：暂存监听器，setup 回调中取走上监听线程
            if let Ok(mut guard) = LISTENER.lock() {
                *guard = Some(listener);
            }
            true
        }
        Err(_) => {
            // 端口被占：确认是不是本程序的既有实例
            if try_forward(&args, port) {
                false // 转发成功 → 调用方退出
            } else {
                // 被无关程序占用 → 放弃单实例能力，正常启动
                eprintln!("[LynVault] 单实例端口 {} 被无关程序占用，降级为普通启动", port);
                true
            }
        }
    }
}

/// 尝试把参数转发给既有实例（带回执）。返回 true = 转发成功。
fn try_forward(args: &[String], port: u16) -> bool {
    let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let mut reader = BufReader::new(stream);

    // 1. 握手
    if reader.get_mut().write_all(format!("{}\n", PROTO_HELLO).as_bytes()).is_err() {
        return false;
    }
    if !read_expect(&mut reader, "OK") {
        return false;
    }

    // 2. 发送保险柜路径（无则空行），"." 结束
    let vault = extract_vault_arg(args.iter().cloned()).unwrap_or_default();
    let payload = format!("{}\n.\n", vault);
    if reader.get_mut().write_all(payload.as_bytes()).is_err() {
        return false;
    }

    // 3. 等回执
    read_expect(&mut reader, "OK")
}

/// 读一行并比对期望值（忽略行尾空白）。
/// 2.5.1 修复：take() 限制单行长度，超长行按协议失败处理，不再无限分配。
fn read_expect<R: BufRead>(reader: &mut R, expect: &str) -> bool {
    let mut line = String::new();
    if reader.take(MAX_LINE_BYTES).read_line(&mut line).is_err() {
        return false;
    }
    line.trim() == expect
}

/// 首实例监听循环（由 main 的 setup 回调在独立线程启动）
///
/// 2.6.1 修复（并发化）：旧实现对连接**串行**处理。任何一个客户端「连上但迟迟
/// 不发数据」都会让 accept 循环卡在读超时上（最长 5 秒），期间其他双击 .lyt 的
/// 请求全部超时 → 单实例转发名存实亡（本地 DoS）。现在每个连接在独立线程处理；
/// 并用 `MAX_CONCURRENT_CONNS` 限制同时处理数，避免恶意进程狂发连接耗尽线程。
pub fn server_loop(handle: AppHandle) {
    let listener = {
        match LISTENER.lock() {
            Ok(mut guard) => guard.take(),
            Err(_) => None,
        }
    };
    let Some(listener) = listener else {
        eprintln!("[LynVault] 单实例监听器缺失，参数转发不可用");
        return;
    };

    let inflight = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        // 并发上限：超限直接丢弃（仅影响同一时刻的并发打开请求，不影响正常单次双击）
        if inflight.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT_CONNS {
            inflight.fetch_sub(1, Ordering::SeqCst);
            drop(stream);
            continue;
        }
        let handle = handle.clone();
        let inflight = inflight.clone();
        std::thread::spawn(move || {
            handle_connection(&handle, stream);
            inflight.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// 处理单个转发连接（握手 → 收路径 → 回执 → 触发打开）。
/// 在独立线程中运行，因此 `handle_vault_request` 等待前端就绪（最长 60 秒）
/// 不再阻塞 accept 循环。
fn handle_connection(handle: &AppHandle, stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(stream);

    // 1. 握手校验：非本程序协议的连接直接断开
    if !read_expect(&mut reader, PROTO_HELLO) {
        return;
    }
    if reader.get_mut().write_all(b"OK\n").is_err() {
        return;
    }
    // 2. 读路径行 + 结束符（2.5.1：同样限制单行长度；
    //    (&mut reader) 显式借用 —— 直接 reader.take() 会移动 reader，
    //    后续 get_mut() 无法使用）
    let mut path_line = String::new();
    if (&mut reader).take(MAX_LINE_BYTES).read_line(&mut path_line).is_err() {
        return;
    }
    let mut dot = String::new();
    let _ = (&mut reader).take(8).read_line(&mut dot);
    let _ = reader.get_mut().write_all(b"OK\n");
    drop(reader);

    // 3. 校验并处理
    let path = path_line.trim().to_string();
    if path.is_empty() {
        // 2.7.1 修复：双击 exe（不带 .lyt 路径）的转发请求同样把已运行实例
        // 带到前台 —— 旧实现静默忽略，用户看到「双击后什么都没发生」
        focus_existing_window(handle);
        return;
    }
    if looks_like_vault(&path) {
        handle_vault_request(handle, path);
    }
}

/// 把已运行实例的主窗口带到前台（可能被最小化）。
/// 2.7.1 新增：单实例转发不再只处理「带 .lyt 路径」的请求 —— 用户直接再次双击
/// exe（空参数）时同样聚焦已运行实例，旧实现转发完即静默退出，而旧窗口可能
/// 并不在前台，看上去就是「双击后什么都没发生」。
/// Windows 下 `SetForegroundWindow` 对非前台进程有限制：先短暂置顶再聚焦后
/// 取消，避免只闪任务栏图标。
pub fn focus_existing_window(handle: &AppHandle) {
    if let Some(win) = handle.get_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        #[cfg(windows)]
        {
            let _ = win.set_always_on_top(true);
            let _ = win.set_focus();
            let _ = win.set_always_on_top(false);
        }
        #[cfg(not(windows))]
        {
            let _ = win.set_focus();
        }
    }
}

/// 处理转发来的打开请求：等前端就绪 → 聚焦窗口 → 发事件
fn handle_vault_request(handle: &AppHandle, path: String) {
    // 等前端就绪（最长 60 秒），避免事件发出去时 webview 还没注册监听器
    let deadline = Instant::now() + Duration::from_secs(60);
    while !FRONTEND_READY.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if !FRONTEND_READY.load(Ordering::SeqCst) {
        eprintln!("[LynVault] 前端 60 秒内未就绪，丢弃打开请求: {}", path);
        return;
    }
    focus_existing_window(handle);
    if let Err(e) = handle.emit_all("vault-file-requested", path) {
        eprintln!("[LynVault] 发送 vault-file-requested 失败: {}", e);
    }
}
