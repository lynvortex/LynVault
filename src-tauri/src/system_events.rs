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

#![cfg(windows)]

use std::sync::Mutex;
use tauri::{AppHandle, Manager};

static APP: Mutex<Option<AppHandle>> = Mutex::new(None);
/// 2.8.1：in-flight 合并标志 —— 快速锁屏/解锁、事件风暴（多个事件排队）时
/// 旧实现会并发派生多个关闭线程，每个都 emit 一次 vault-locked，
/// 前端重复跑启动扫描
static LOCK_IN_FLIGHT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 启动监听线程（仅 Windows；setup 钩子里调用一次）
pub fn spawn(app: AppHandle) {
    if let Ok(mut guard) = APP.lock() {
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
    let app = APP.lock().ok().and_then(|g| g.clone());
    if let Some(app) = app {
        if app.get_window("main").is_none() {
            LOCK_IN_FLIGHT.store(false, Ordering::SeqCst);
            return; // 应用已退出中
        }
        std::thread::spawn(move || {
            let _ = crate::commands::system_lock_vault(&app);
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
    const WTS_SESSION_LOCK: usize = 0x7;
    const WTS_SESSION_LOGOFF: usize = 0x9;

    const CLASS_NAME: &[u16] = &[
        b'L' as u16, b'V' as u16, b'S' as u16, b'y' as u16, b's' as u16, 0,
    ];

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
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    let class_name = windows::core::PCWSTR(CLASS_NAME.as_ptr());
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

    let mut msg = windows::Win32::UI::WindowsAndMessaging::MSG::default();
    loop {
        let r = unsafe {
            windows::Win32::UI::WindowsAndMessaging::GetMessageW(&mut msg, hwnd, 0, 0)
        };
        if r.0 <= 0 {
            break;
        }
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
            windows::Win32::UI::WindowsAndMessaging::DispatchMessageW(&msg);
        }
    }
}
