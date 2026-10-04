//! 2.8.0：系统锁屏 / 睡眠 / 注销事件监听 —— 触发自动关闭保险柜。
//!
//! 专用线程创建 message-only 窗口：
//! - `WTSRegisterSessionNotification` → 收 `WM_WTSSESSION_CHANGE`：
//!   `WTS_SESSION_LOCK`（锁屏）/ `WTS_SESSION_LOGOFF`（注销）；
//! - `WM_POWERBROADCAST`：`PBT_APMSUSPEND`（睡眠，含笔记本合盖）。
//!
//! 事件触发后异步执行「关闭保险柜 + 通知前端回到启动弹窗」—— 异步是为了
//! 不阻塞消息循环（睡眠窗口期内系统只给很短的处理时间；Vault::close 的
//! 索引落盘沿用 C3 崩溃安全顺序，中途被冻结/杀死也不会损坏文件）。
//!
//! 仅 Windows：Linux 桌面的 logind 事件暂未支持（已知限制）。
//!
//! 2.8.2（M4）加固：
//! 1. **修复致命常量错误** —— `WTS_SESSION_LOGOFF` 旧实现写成 0x9（实为
//!    `WTS_SESSION_REMOTE_CONTROL`），导致注销事件从不触发关柜、远程控制
//!    会话反而误触发；正确值为 0x6。
//! 2. `wnd_proc` 拦截 `WM_CLOSE`（同 clipboard_guard，防外部进程销毁窗口）。
//! 3. 类名随机化（pid + 启动纳秒 + 序号）。
//! 4. `GetMessageW` 三态区分 + 重建循环。
//! 5. 关闭线程 `catch_unwind` —— 旧实现 `LOCK_IN_FLIGHT` 在线程末尾才复位，
//!    途中 panic（如 WinRT 调用）会让标志永久为 true，本会话后续所有
//!    锁屏/睡眠自动关柜静默失效。

#![cfg(windows)]

use std::sync::Mutex;
use tauri::{AppHandle, Manager};

static APP: Mutex<Option<AppHandle>> = Mutex::new(None);
/// 2.8.1：in-flight 合并标志 —— 快速锁屏/解锁、事件风暴（多个事件排队）时
/// 旧实现会并发派生多个关闭线程，每个都 emit 一次 vault-locked，
/// 前端重复跑启动扫描
static LOCK_IN_FLIGHT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// 2.8.2（M4）：类名序号（随机类名组成成分之一）
static CLASS_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// 启动监听线程（仅 Windows；setup 钩子里调用一次）
pub fn spawn(app: AppHandle) {
    {
        // 2.8.2：锁中毒恢复（旧实现 if let Ok 静默跳过 → APP 永久 None，
        // 之后所有事件空转，自动关柜整体失效）
        let mut guard = match APP.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some(app);
    }
    std::thread::Builder::new()
        .name("system-events".into())
        .spawn(event_loop)
        .map_err(|e| log::warn!("系统事件监听线程启动失败: {:?}", e))
        .ok();
}

fn trigger_lock() {
    use std::sync::atomic::Ordering;
    // 已有关闭流程在跑则合并（锁屏期间不会有新的解锁操作产生竞态）
    if LOCK_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    // 2.8.2：锁中毒恢复
    let app = {
        let guard = match APP.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.clone()
    };
    if let Some(app) = app {
        if app.get_webview_window("main").is_none() {
            LOCK_IN_FLIGHT.store(false, Ordering::SeqCst);
            return; // 应用已退出中
        }
        std::thread::spawn(move || {
            // 2.8.2：catch_unwind 保证 LOCK_IN_FLIGHT 无论成败都复位 ——
            // 旧实现线程 panic（WinRT / emit）后标志永久卡 true，
            // 本会话后续所有锁屏/睡眠自动关柜静默失效
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = crate::commands::system_lock_vault(&app);
            }));
            if result.is_err() {
                log::warn!("系统事件触发的关柜线程 panic（已恢复）");
            }
            LOCK_IN_FLIGHT.store(false, Ordering::SeqCst);
        });
    } else {
        LOCK_IN_FLIGHT.store(false, Ordering::SeqCst);
    }
}

fn event_loop() {
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::RemoteDesktop::{
        WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, RegisterClassW, HWND_MESSAGE, WNDCLASSW,
    };

    const WM_POWERBROADCAST: u32 = 0x0218;
    const PBT_APMSUSPEND: usize = 4;
    const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
    // 2.8.2（M4 关键修复）：WTS_SESSION_LOGOFF = 0x6 —— 旧实现误写 0x9
    // （实为 WTS_SESSION_REMOTE_CONTROL），导致注销永不关柜、远程控制
    // 会话误触发。手抄魔法数正是这一错误的直接产物，windows crate 已启用
    // RemoteDesktop feature，此处显式定义并注明与 SDK 一致。
    const WTS_SESSION_LOCK: usize = 0x7;
    const WTS_SESSION_LOGOFF: usize = 0x6;
    const WM_CLOSE: u32 = 0x0010;

    // 类名随机化（pid + 启动纳秒 + 序号），防同会话进程定位后杀死窗口
    let seq = CLASS_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let class_name: Vec<u16> = format!("LVSys-{}-{}-{}\0", std::process::id(), nanos, seq)
        .encode_utf16()
        .collect();

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_POWERBROADCAST if wparam.0 == PBT_APMSUSPEND => {
                trigger_lock();
                LRESULT(1) // TRUE：已处理
            }
            WM_WTSSESSION_CHANGE if matches!(wparam.0, WTS_SESSION_LOCK | WTS_SESSION_LOGOFF) => {
                trigger_lock();
                LRESULT(0)
            }
            // 2.8.2（M4）：拦截 WM_CLOSE —— DefWindowProcW 会销毁窗口，
            // GetMessageW 随之返回 0，监听线程静默死亡
            WM_CLOSE => LRESULT(0),
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    let class_name = windows::core::PCWSTR(class_name.as_ptr());
    let wc = WNDCLASSW {
        lpfnWndProc: Some(wnd_proc),
        lpszClassName: class_name,
        ..Default::default()
    };
    if unsafe { RegisterClassW(&wc) } == 0 {
        log::warn!("系统事件窗口注册失败，锁屏/睡眠自动关闭未生效");
        return;
    }
    let hwnd = unsafe {
        CreateWindowExW(
            windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE::default(),
            class_name,
            windows::core::PCWSTR::null(),
            windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE::default(),
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            None,
            None,
            None,
        )
    };
    // windows 0.57 的 CreateWindowExW 直接返回 HWND（失败为 0），而非 Result
    if hwnd.0 == 0 {
        log::warn!("系统事件窗口创建失败");
        return;
    }
    if unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) }.is_err() {
        log::warn!("WTS 注册失败（服务未运行？），锁屏/注销自动关闭未生效");
    }

    // 2.8.2（M4）：GetMessageW 三态 + 重建循环（与 clipboard_guard 同型）
    let mut rebuilds = 0u32;
    'rebuild: loop {
        let mut msg = windows::Win32::UI::WindowsAndMessaging::MSG::default();
        loop {
            let r = unsafe {
                windows::Win32::UI::WindowsAndMessaging::GetMessageW(&mut msg, hwnd, 0, 0)
            };
            if r.0 == -1 {
                break; // 错误 → 重建
            }
            if r.0 == 0 {
                break; // 窗口被销毁 → 重建
            }
            unsafe {
                let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
                windows::Win32::UI::WindowsAndMessaging::DispatchMessageW(&msg);
            }
        }
        rebuilds += 1;
        if rebuilds > 60 {
            log::error!(
                "系统事件窗口反复异常退出（{} 次），放弃本会话重建",
                rebuilds
            );
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        // 重新注册会话通知（窗口句柄未变；WTS 通知绑定在句柄上，重建窗口
        // 的场景已在wnd_proc 拦截 WM_CLOSE 后大幅减少，此处尽力而为）
        let _ = unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) };
        continue 'rebuild;
    }
}
