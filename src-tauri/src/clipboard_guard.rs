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
//!
//! 2.8.2（M4）加固 —— message-only 窗口此前可被同会话恶意进程用固定类名
//! 定位后杀死（发 `WM_APP+1` 冒充停止、发 `WM_CLOSE` 经 DefWindowProcW 销毁，
//! 线程死亡后 start() 永久 no-op，防护全程静默失效）：
//! 1. `WM_STOP` 处理加 `STOP_REQUESTED` 前置条件 —— 外部伪造消息按普通消息忽略；
//! 2. `wnd_proc` 拦截 `WM_CLOSE` 返回 0，阻止销毁；
//! 3. `GetMessageW` 三态区分：-1/0 跳出内层循环，外层**重建监听窗口继续**
//!    （sleep 250ms，上限 60 次防风暴，超限放弃，下个开柜周期 start() 重新武装）；
//! 4. 类名随机化（pid + 启动纳秒 + 序号），退出时 `UnregisterClassW` 防类泄漏；
//! 5. `start()` 检测死亡线程并重新武装。
//!
//! 2.8.2（L6）：清理防抖 —— 剪贴板管理器类软件高频写入时每条
//! `WM_CLIPBOARDUPDATE` 都执行 EmptyClipboard + ClearHistory 会形成全系统
//! 清空风暴（WinRT RPC 洪水）。80ms 防抖：风暴窗口内更新置位 `PENDING_CLEAR`
//! + `SetTimer` 尾沿定时器，`WM_TIMER` 统一补清。
//!
//! 2.8.2：回声检查竞态修复 —— 旧实现在 `EmptyClipboard` 之后才读序列号存储，
//! 窗口期内其他程序抢先写入时存下的是「别人的」序列号，其对应的更新会被误判
//! 为自己触发而跳过清空（明文残留）。现改为「清空前记 S0、清空后读 S1，
//! 仅当 S1 == S0+1（其间无他人写入）才存储」，否则不存储，让排队的更新消息
//! 重新触发清理。

// 以下状态仅 Windows 实现使用；非 Windows 平台 start/stop 为空实现，静默即可
#[cfg_attr(not(windows), allow(unused_imports, dead_code))]
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicU64, Ordering};

// 以下状态仅 Windows 实现使用；非 Windows 平台 start/stop 为空实现，静默即可
#[cfg_attr(not(windows), allow(dead_code))]
static LAST_CLEARED_SEQ: AtomicU32 = AtomicU32::new(0);
#[cfg_attr(not(windows), allow(dead_code))]
static GUARD_HWND: AtomicIsize = AtomicIsize::new(0);
#[cfg_attr(not(windows), allow(dead_code))]
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
#[cfg_attr(not(windows), allow(dead_code))]
static THREAD: std::sync::Mutex<Option<std::thread::JoinHandle<()>>> = std::sync::Mutex::new(None);
// 2.8.2（L6）防抖状态
#[cfg_attr(not(windows), allow(dead_code))]
static PENDING_CLEAR: AtomicBool = AtomicBool::new(false);
#[cfg_attr(not(windows), allow(dead_code))]
static LAST_CLEAR_MS: AtomicU64 = AtomicU64::new(0);
#[cfg_attr(not(windows), allow(dead_code))]
static CLASS_SEQ: AtomicU32 = AtomicU32::new(0);

/// L6：清空防抖窗口（毫秒）
#[cfg(windows)]
const CLEAR_DEBOUNCE_MS: u32 = 80;
/// L6：防抖定时器 ID（SetTimer 的 nIDEvent，与 WM_TIMER 的 wparam 匹配）
#[cfg(windows)]
const CLEAR_TIMER_ID: usize = 1;

/// 启动剪贴板保护（幂等；2.8.2/M4：线程已死亡时重新武装）。
/// 失败仅记日志 —— 剪贴板保护是尽力而为的附加防线，不阻塞开柜。
pub fn start() {
    #[cfg(windows)]
    {
        let mut guard = match THREAD.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(h) = guard.as_ref() {
            if !h.is_finished() {
                return;
            }
            // 监听线程已死亡（窗口创建失败 / 消息循环异常退出）：
            // 清掉死句柄重新武装 —— 旧实现 is_some() 直接 return，本会话
            // 剪贴板保护静默失效
            log::warn!("剪贴板保护线程已死亡，重新武装");
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
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

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

    // 2.8.2（M4）：外层重建循环 —— 内层消息循环因 GetMessageW 出错（-1）或
    // 窗口被销毁（0）退出时，重建监听窗口继续；上限 60 次防风暴。
    let mut rebuilds = 0u32;
    'rebuild: loop {
        let hwnd = match create_message_window() {
            Ok(h) => h,
            Err(e) => {
                log::warn!("剪贴板监听窗口创建失败: {}", e);
                return;
            }
        };
        // 2.8.1（竞态修复）：先发布句柄、再检查停止标志。
        GUARD_HWND.store(hwnd.0 as isize, Ordering::Release);
        if STOP_REQUESTED.load(Ordering::Acquire) {
            destroy_guard_window(hwnd);
            return;
        }
        if unsafe { windows::Win32::System::DataExchange::AddClipboardFormatListener(hwnd) }
            .is_err()
        {
            log::warn!("AddClipboardFormatListener 失败，剪贴板保护未生效");
            destroy_guard_window(hwnd);
            return;
        }

        let mut msg = windows::Win32::UI::WindowsAndMessaging::MSG::default();
        let mut stop = false;
        loop {
            let r = unsafe {
                windows::Win32::UI::WindowsAndMessaging::GetMessageW(&mut msg, hwnd, 0, 0)
            };
            // 2.8.2（M4）三态区分：-1 = 错误（重建），0 = WM_DESTROY（重建），
            // 0 值消息按正常路径分发。旧实现 `r.0 <= 0` 把错误当退出，
            // 线程死亡后防护静默失效。
            if r.0 == -1 {
                break; // 内层出错 → 重建
            }
            if r.0 == 0 {
                break; // 窗口被销毁（外部 WM_DESTROY）→ 重建
            }
            if (msg.message == WM_STOP && STOP_REQUESTED.load(Ordering::Acquire))
                || STOP_REQUESTED.load(Ordering::Acquire)
            {
                // 仅 STOP_REQUESTED 置位后的 WM_STOP 才是合法停止信号；
                // 外部伪造的 WM_APP+1 落到 else 分支按普通消息忽略
                stop = true;
                break;
            }
            if msg.message == WM_CLIPBOARDUPDATE {
                clear_clipboard_debounced();
            }
            unsafe {
                let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
                windows::Win32::UI::WindowsAndMessaging::DispatchMessageW(&msg);
            }
        }
        // 清理当前窗口（2.8.1：销毁监听窗口，防句柄跨 start/stop 泄漏）
        unsafe {
            let _ = windows::Win32::System::DataExchange::RemoveClipboardFormatListener(hwnd);
        }
        destroy_guard_window(hwnd);
        GUARD_HWND.store(0, Ordering::Release);
        if stop {
            return;
        }
        // 异常退出 → 重建（sleep 250ms 防风暴；超限放弃，等下个开柜周期
        // start() 的死亡检测重新武装）
        rebuilds += 1;
        if rebuilds > 60 {
            log::error!(
                "剪贴板监听窗口反复异常退出（{} 次），放弃本会话重建",
                rebuilds
            );
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        continue 'rebuild;
    }
}

/// 2.8.2（M4）：销毁窗口 + 反注册随机类名（防类表泄漏）
#[cfg(windows)]
fn destroy_guard_window(hwnd: windows::Win32::Foundation::HWND) {
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(hwnd);
        // 类名随机化后每个窗口一个类，必须反注册
        let _ = windows::Win32::UI::WindowsAndMessaging::UnregisterClassW(
            windows::core::PCWSTR(guard_class_name().as_ptr()),
            windows::Win32::Foundation::HMODULE::default(),
        );
    }
}

/// 2.8.2（M4）：返回当前 guard 窗口的随机类名（宽字符，NUL 结尾）。
/// 销毁时用同名反注册，因此类名由确定性算法生成并可复算。
#[cfg(windows)]
fn guard_class_name() -> Vec<u16> {
    // 单线程使用（监听线程），用静态缓存保证 create/destroy 用同一名字
    use std::sync::Mutex;
    static NAME: Mutex<Option<Vec<u16>>> = Mutex::new(None);
    let mut guard = match NAME.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(n) = guard.as_ref() {
        return n.clone();
    }
    let seq = CLASS_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let name = format!("LVC-{}-{}-{}\0", std::process::id(), nanos, seq);
    let wide: Vec<u16> = name.encode_utf16().collect();
    *guard = Some(wide.clone());
    wide
}

/// 2.8.2（L6）：带防抖的清空入口（WM_CLIPBOARDUPDATE 触发）。
/// 风暴窗口（距上次真实清空 < 80ms）内只置位 PENDING_CLEAR 并设尾沿定时器，
/// WM_TIMER 统一补清 —— 避免对剪贴板管理器类软件的每次写入都执行
/// EmptyClipboard + WinRT ClearHistory 形成的 RPC 洪水。
#[cfg(windows)]
fn clear_clipboard_debounced() {
    let now = wall_ms();
    let last = LAST_CLEAR_MS.load(Ordering::Relaxed);
    if last != 0 {
        let delta = now.saturating_sub(last);
        if delta < CLEAR_DEBOUNCE_MS as u64 {
            PENDING_CLEAR.store(true, Ordering::Relaxed);
            let hwnd = GUARD_HWND.load(Ordering::Relaxed);
            if hwnd != 0 {
                unsafe {
                    let _ = windows::Win32::UI::WindowsAndMessaging::SetTimer(
                        windows::Win32::Foundation::HWND(hwnd),
                        CLEAR_TIMER_ID,
                        CLEAR_DEBOUNCE_MS,
                        None,
                    );
                }
            }
            return;
        }
    }
    do_clear_clipboard();
}

/// WM_TIMER 触发的尾沿补清（由 wnd_proc 分发，监听线程内执行）
#[cfg(windows)]
fn on_clear_timer() {
    unsafe {
        let hwnd = GUARD_HWND.load(Ordering::Relaxed);
        if hwnd != 0 {
            let _ = windows::Win32::UI::WindowsAndMessaging::KillTimer(
                windows::Win32::Foundation::HWND(hwnd),
                CLEAR_TIMER_ID,
            );
        }
    }
    if PENDING_CLEAR.swap(false, Ordering::Relaxed) {
        do_clear_clipboard();
    }
}

/// 清空当前剪贴板 + Win+V 历史。2.8.2：回声检查修复为「S0/S1 对比」——
/// 仅当清空动作本身是 S0→S1 之间的唯一变化时才记录回声序列号。
#[cfg(windows)]
fn do_clear_clipboard() {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
    };
    // 清空前的基准序列号
    let seq_before = unsafe { GetClipboardSequenceNumber() };
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
            // 2.8.2 竞态修复：仅当「清空后序列号 == 清空前 + 1」（即两次读取
            // 之间没有其他程序写入）时才记录 —— 否则不记录，让排队的
            // WM_CLIPBOARDUPDATE 重新触发清理，明文不会被误判为回声而漏清
            let seq_after = GetClipboardSequenceNumber();
            if seq_after == seq_before.wrapping_add(1) {
                LAST_CLEARED_SEQ.store(seq_after, Ordering::Relaxed);
            }
        }
    }
    LAST_CLEAR_MS.store(wall_ms(), Ordering::Relaxed);
    // Win+V 剪贴板历史（普通 EmptyClipboard 清不掉；1809 前的系统/未开历史会失败，忽略）
    let _ = windows::ApplicationModel::DataTransfer::Clipboard::ClearHistory();
}

/// 创建 message-only 窗口（HWND_MESSAGE，永不可见）。
/// 2.8.2（M4）：类名随机化 —— 固定类名 "LVC" 可被同会话恶意进程
/// `FindWindowExW` 定位后杀死监听窗口。
#[cfg(windows)]
fn create_message_window() -> Result<windows::Win32::Foundation::HWND, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, RegisterClassW, HWND_MESSAGE, WNDCLASSW,
    };

    const WM_TIMER: u32 = 0x0113;
    const WM_CLOSE: u32 = 0x0010;

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            // 2.8.2（L6）：防抖尾沿定时器
            WM_TIMER if wparam.0 == CLEAR_TIMER_ID => {
                on_clear_timer();
                LRESULT(0)
            }
            // 2.8.2（M4）：拦截 WM_CLOSE —— DefWindowProcW 会销毁窗口，
            // 监听线程随之死亡，防护全程静默失效
            WM_CLOSE => LRESULT(0),
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    // 类名随机化（pid + 启动纳秒 + 序号），销毁时按同名反注册
    let class_name = guard_class_name(); // Vec<u16>，NUL 结尾
    let class_name = PCWSTR(class_name.as_ptr());
    let wc = WNDCLASSW {
        lpfnWndProc: Some(wnd_proc),
        lpszClassName: class_name,
        ..Default::default()
    };
    // 随机类名几乎不可能已存在；仍保留 ERROR_CLASS_ALREADY_EXISTS 容错
    if unsafe { RegisterClassW(&wc) } == 0 {
        let err = unsafe { windows::Win32::Foundation::GetLastError() };
        if err != windows::Win32::Foundation::ERROR_CLASS_ALREADY_EXISTS {
            return Err(format!("RegisterClassW 失败: {:?}", err));
        }
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
