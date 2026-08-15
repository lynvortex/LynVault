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

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager};

/// 前端就绪标志：app.js 初始化完成后调用 `frontend_ready` 命令置位。
/// 转发请求到达时若前端尚未就绪，最多等待 60 秒再发事件，避免事件丢失。
pub static FRONTEND_READY: AtomicBool = AtomicBool::new(false);

/// 协议握手串：区分「本程序的单实例端口」与「恰好占用同端口的无关程序」
const PROTO_HELLO: &str = "LYNVAULT_SI_V1";

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

/// 判断路径是否为 LynVault 保险柜文件（扩展名 + magic bytes 双重校验）
fn looks_like_vault(p: &str) -> bool {
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

/// 读一行并比对期望值（忽略行尾空白）
fn read_expect<R: BufRead>(reader: &mut R, expect: &str) -> bool {
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    line.trim() == expect
}

/// 首实例监听循环（由 main 的 setup 回调在独立线程启动）
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

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let mut reader = BufReader::new(stream);

        // 1. 握手校验：非本程序协议的连接直接断开
        if !read_expect(&mut reader, PROTO_HELLO) {
            continue;
        }
        if reader.get_mut().write_all(b"OK\n").is_err() {
            continue;
        }
        // 2. 读路径行 + 结束符
        let mut path_line = String::new();
        if reader.read_line(&mut path_line).is_err() {
            continue;
        }
        let mut dot = String::new();
        let _ = reader.read_line(&mut dot);
        let _ = reader.get_mut().write_all(b"OK\n");
        drop(reader);

        // 3. 校验并处理
        let path = path_line.trim().to_string();
        if !path.is_empty() && looks_like_vault(&path) {
            handle_vault_request(&handle, path);
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
    // 聚焦已运行实例的窗口（可能被最小化）
    if let Some(win) = handle.get_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
    if let Err(e) = handle.emit_all("vault-file-requested", path) {
        eprintln!("[LynVault] 发送 vault-file-requested 失败: {}", e);
    }
}
