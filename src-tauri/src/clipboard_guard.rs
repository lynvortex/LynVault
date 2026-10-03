//! 2.8.0：剪贴板保护 —— 保险柜打开期间全系统即时清空剪贴板（含 Win+V 历史）。
//!
//! 工作方式：专用线程创建 message-only 窗口并 `AddClipboardFormatListener`；
//! 任何程序（含本应用）向剪贴板放入内容时收到 `WM_CLIPBOARDUPDATE` →
//! `EmptyClipboard` 清空当前剪贴板 + WinRT `Clipboard::ClearHistory()` 清除
//! Win10 1809+ 的剪贴板历史。保险柜关闭时停止监听，系统剪贴板自动恢复
//! 正常（没有真正的「系统剪贴板开关」，停止清空即是「重新开启」）。
//!
//! 已知副作用（用户已确认接受）：开柜期间在其他软件里复制的内容也会被
//! 即时清空。已清空内容无法恢复 —— 这正是该功能的目的（不留明文残留）。
//!
//! start() 非阻塞（只启动线程，不等待窗口就绪），保证开柜路径零延迟；
//! stop() 发退出消息并 join 线程。非 Windows 平台为空实现。

// 以下状态仅 Windows 实现使用；非 Windows 平台 start/stop 为空实现，静默即可
#[cfg_attr(not(windows), allow(unused_imports, dead_code))]
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering};

// 以下状态仅 Windows 实现使用；非 Windows 平台 start/stop 为空实现，静默即可
#[cfg_attr(not(windows), allow(dead_code))]
static LAST_CLEARED_SEQ: AtomicU32 = AtomicU32::new(0);
#[cfg_attr(not(windows), allow(dead_code))]
static GUARD_HWND: AtomicIsize = AtomicIsize::new(0);
#[cfg_attr(not(windows), allow(dead_code))]
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
#[cfg_attr(not(windows), allow(dead_code))]
static THREAD: std::sync::Mutex<Option<std::thread::JoinHandle<()>>> =
    std::sync::Mutex::new(None);

/// 启动剪贴板保护（幂等）。失败仅记日志 —— 剪贴板保护是尽力而为的附加防线，
/// 不阻塞开柜。
pub fn start() {
    #[cfg(windows)]
    {
        let mut guard = match THREAD.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.is_some() {
            return;
        }
        STOP_REQUESTED.store(false, Ordering::Relaxed);
        GUARD_HWND.store(0, Ordering::Relaxed);
        match std::thread::Builder::new()
            .name("clipboard-guard".into())
            .spawn(event_loop)
        {
            Ok(h) => *guard = Some(h),
            Err(e) => log::warn!("剪贴板保护线程启动失败: {:?}", e),
        }
    }
}

/// 停止剪贴板保护（幂等）。向监听线程发退出消息并回收线程。
pub fn stop() {
    #[cfg(windows)]
    {
        let mut guard = match THREAD.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(handle) = guard.take() {
            STOP_REQUESTED.store(true, Ordering::Relaxed);
            let hwnd = GUARD_HWND.swap(0, Ordering::Relaxed);
            if hwnd != 0 {
                unsafe { post_message_w(hwnd, WM_STOP) };
            }
            let _ = handle.join();
        }
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
const WM_STOP: u32 = 0x8000 + 1; // WM_APP + 1：监听线程的自定义退出消息

#[cfg(windows)]
fn event_loop() {
    const WM_CLIPBOARDUPDATE: u32 = 0x031D;

    // WinRT Clipboard::ClearHistory 需要已初始化的 COM 单元
    unsafe {
        let _ = windows::Win32::System::Com::CoInitializeEx(
            None,
            windows::Win32::System::Com::COINIT_APARTMENTTHREADED,
        );
    }

    let hwnd = match create_message_window() {
        Ok(h) => h,
        Err(e) => {
            log::warn!("剪贴板监听窗口创建失败: {}", e);
            return;
        }
    };
    if STOP_REQUESTED.load(Ordering::Relaxed) {
        return; // stop() 在窗口创建前就已请求退出
    }
    GUARD_HWND.store(hwnd.0 as isize, Ordering::Release);
    if unsafe { windows::Win32::System::DataExchange::AddClipboardFormatListener(hwnd) }.is_err() {
        log::warn!("AddClipboardFormatListener 失败，剪贴板保护未生效");
        return;
    }

    let mut msg = windows::Win32::UI::WindowsAndMessaging::MSG::default();
    loop {
        let r = unsafe {
            windows::Win32::UI::WindowsAndMessaging::GetMessageW(&mut msg, hwnd, 0, 0)
        };
        if r.0 <= 0 {
            break;
        }
        if msg.message == WM_STOP || STOP_REQUESTED.load(Ordering::Relaxed) {
            break;
        }
        if msg.message == WM_CLIPBOARDUPDATE {
            clear_clipboard();
        }
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
            windows::Win32::UI::WindowsAndMessaging::DispatchMessageW(&msg);
        }
    }
    unsafe {
        let _ = windows::Win32::System::DataExchange::RemoveClipboardFormatListener(hwnd);
    }
    GUARD_HWND.store(0, Ordering::Release);
}

/// 清空当前剪贴板 + Win+V 历史。序列号回声防护防止自触发循环。
#[cfg(windows)]
fn clear_clipboard() {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
    };
    // 回声检查：序列号没变说明仍是上一轮我们自己清空后的状态
    let seq = unsafe { GetClipboardSequenceNumber() };
    if seq != 0 && seq == LAST_CLEARED_SEQ.load(Ordering::Relaxed) {
        return;
    }
    unsafe {
        if OpenClipboard(HWND::default()).is_err() {
            return; // 被其他程序短暂占用：下一条更新消息会再触发
        }
        let emptied = EmptyClipboard();
        let _ = CloseClipboard();
        if emptied.is_ok() {
            LAST_CLEARED_SEQ.store(GetClipboardSequenceNumber(), Ordering::Relaxed);
        }
    }
    // Win+V 剪贴板历史（普通 EmptyClipboard 清不掉；1809 前的系统/未开历史会失败，忽略）
    let _ = windows::ApplicationModel::DataTransfer::Clipboard::ClearHistory();
}

/// 创建 message-only 窗口（HWND_MESSAGE，永不可见）
#[cfg(windows)]
fn create_message_window() -> Result<windows::Win32::Foundation::HWND, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, RegisterClassW, HWND_MESSAGE, WNDCLASSW,
    };

    const CLASS_NAME: &[u16] = &[
        b'L' as u16, b'V' as u16, b'C' as u16, b'l' as u16, b'i' as u16, b'p' as u16, 0,
    ];

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    let class_name = PCWSTR(CLASS_NAME.as_ptr());
    let wc = WNDCLASSW {
        lpfnWndProc: Some(wnd_proc),
        lpszClassName: class_name,
        ..Default::default()
    };
    if unsafe { RegisterClassW(&wc) } == 0 {
        return Err("RegisterClassW 失败".into());
    }
    let hwnd = unsafe {
        CreateWindowExW(
            windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE::default(),
            class_name,
            PCWSTR::null(),
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
        return Err("CreateWindowExW 失败".into());
    }
    Ok(hwnd)
}

// 只用到 PostMessageW（停止信号），独立声明避免引入更多 feature
#[cfg(windows)]
#[link(name = "user32")]
extern "system" {
    fn PostMessageW(hwnd: isize, msg: u32, wparam: usize, lparam: isize) -> i32;
}

#[cfg(windows)]
unsafe fn post_message_w(hwnd: isize, msg: u32) {
    let _ = PostMessageW(hwnd, msg, 0, 0);
}
