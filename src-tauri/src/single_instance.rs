//! 2.4.1 新增：单实例运行 + .lyt 文件关联参数转发（纯 std 实现，无新增依赖）。
//!
//! 为什么不用 tauri-plugin-single-instance：crates.io 上的该插件从 2.0 起只支持
//! Tauri v2，Tauri v1 只能用 git 依赖（plugins-workspace v1 分支）。为避免引入
//! 重量级 git 依赖，这里用「127.0.0.1 随机端口 + 令牌握手」实现同等能力。
//!
//! - 首个实例：绑定配置端口，起监听线程；收到**令牌匹配**的合法请求后聚焦
//!   窗口、向前端发 `vault-file-requested` 事件（负载为文件路径）。
//! - 第二个实例：绑定失败 → 读取同一份 si.json 配置做令牌握手 → 握手成功
//!   说明是本程序的既有实例 → 把双击的 .lyt 路径转发过去后立即退出（不闪窗口）；
//!   握手失败说明端口被无关程序占用 → 降级为普通启动（不做单实例）。
//!
//! 2.8.2（L2）安全升级：端口（20000-39999）与 128 位令牌按安装随机生成并
//! 持久化到 `%LOCALAPPDATA%\LynVault\si.json` —— 旧实现的端口由 APP_ID 确定性
//! 派生 + 常量握手串，本地进程可离线推算端口并伪装实例（路径泄露 / 拒绝服务）。
//! 转发握手为 `HELLO + token`，对端令牌校验失败/超时一律不发送路径并继续
//! 正常启动；服务端令牌不符直接断开。同用户进程仍可读配置文件（同用户边界
//! 内无法根治，文档化残余风险）——攻击门槛从「离线静态计算」提高到「读文件
//! 并模仿协议」。
//!
//! 2.8.2（H1）：远程 / 设备路径守卫覆盖 magic bytes 预检 —— 路径若是
//! `\\server\share\...`、`\\?\UNC\...` 或 `//server/share`（正斜杠被 Win32
//! 规范化为 UNC），打开文件会无提示地发起 SMB 访问，构成免交互的 NTLM 凭据
//! 外泄 / 中继触发原语。本程序的用户场景永远是本地磁盘上的保险柜文件，
//! 直接拒绝一切 UNC / 设备路径（`\\?\C:\...` verbatim 本地路径仍放行）。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager};

/// 前端就绪标志：app.js 初始化完成后调用 `frontend_ready` 命令置位。
/// 转发请求到达时若前端尚未就绪，最多等待 60 秒再发事件，避免事件丢失。
pub static FRONTEND_READY: AtomicBool = AtomicBool::new(false);

/// 协议握手串（2.8.2 起 V2：hello 行携带 per-安装随机令牌）
const PROTO_HELLO: &str = "LYNVAULT_SI_V2";

/// 2.5.1 新增：单实例协议单行长度上限。本地恶意进程连上端口后发送
/// 无换行的超长数据，旧 read_line 会无限分配内存（本地 DoS）。
/// Windows 长路径上限约 32K 字符，64 KB 足够且留有余量。
const MAX_LINE_BYTES: u64 = 64 * 1024;

/// 2.6.1 新增：单实例连接的最大并发处理数。每个连接独立线程处理（见
/// `server_loop`），无上限会让本地恶意进程通过快速建立大量连接耗尽线程栈；
/// 正常使用（用户双击 .lyt）远不会超过该值。
/// 3.0.1（F24 修复）：该槽位改为**令牌握手通过后**才占用 —— 旧实现 accept
/// 即计数，8 条未认证空闲连接即可占满槽位整整 5 秒（读超时），让所有合法
/// 转发失败、单实例退化为双实例。
const MAX_CONCURRENT_CONNS: usize = 8;

/// 3.0.1（F24）：待处理连接上限（宽松，只为限制线程数）—— 未认证连接
/// 不再占用上面的并发槽位，但线程总数仍需有界。
const MAX_PENDING_CONNS: usize = 64;

/// 3.0.1（F24）：panic 安全的并发槽位释放（Drop 兜底，处理线程 catch_unwind
/// 不再泄漏计数）
struct ConnSlotGuard(Arc<AtomicUsize>);
impl Drop for ConnSlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// si.json 配置（2.8.2 / L2）：随机端口 + 随机令牌，随安装持久化
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SiConfig {
    pub port: u16,
    pub token: String,
}

/// 运行期缓存（acquire_or_forward 写入、server_loop 读取）
static SI: Mutex<Option<SiConfig>> = Mutex::new(None);

/// 首实例绑定的监听器（main 里绑定成功后暂存，setup 回调中取走）
static LISTENER: Mutex<Option<TcpListener>> = Mutex::new(None);

/// 读取（或首装生成）单实例配置。
/// 位置：`%LOCALAPPDATA%\LynVault\si.json`。
/// 3.0.1（F20 修复）：**删除 %TEMP% 回退** —— TEMP 的风险面超出模块文档
/// 声明（环境重定向 / 共享临时目录），且 si.json 本就无敏感信息：配置不可用
/// 时纯内存运行即可（本次进程内自洽，单实例转发退化为尽力而为语义）。
/// 文件缺失 / 捅坏 / 字段非法 → 重新随机生成并覆写。
fn load_or_create_si_config() -> SiConfig {
    fn config_path() -> Option<PathBuf> {
        #[cfg(windows)]
        let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        #[cfg(not(windows))]
        let base = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"));
        base.map(|b| b.join("LynVault").join("si.json"))
    }

    // 尝试读取既有配置
    let path = config_path();
    if let Some(p) = &path {
        if let Ok(text) = std::fs::read_to_string(p) {
            if let Ok(cfg) = serde_json::from_str::<SiConfig>(&text) {
                // 字段合法性：端口在授权区间、令牌为 32 位 hex（128-bit）
                if (20000..40000).contains(&cfg.port) && cfg.token.len() == 32 {
                    return cfg;
                }
            }
        }
    }

    // 生成新配置
    use rand::RngCore;
    let mut pb = [0u8; 2];
    rand::rngs::OsRng.fill_bytes(&mut pb);
    let port = 20000u16 + (u16::from_le_bytes(pb) % 20000);
    let mut tb = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut tb);
    let token: String = tb.iter().map(|b| format!("{:02x}", b)).collect();
    let cfg = SiConfig { port, token };

    // 持久化（目录不存在则创建；写入失败时仍用内存配置，本次进程内自洽）
    if let Some(p) = &path {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(&cfg) {
            if write_si_config(p, &json).is_ok() {
                return cfg;
            }
        }
    }
    cfg
}

/// 3.0.1（F21 修复）：si.json 安全写入 —— 旧实现 `std::fs::write`
///（= File::create + write_all）**跟随符号链接**且以默认权限创建：首次运行前
/// 在候选路径预置链接，配置 JSON 会写进链接目标（任意文件覆写/创建）。
/// 与 settings.rs 的 save_at / main.rs 日志同一威胁模型同一套检查：
/// 随机临时名 create_new + 不跟随重解析点 + 句柄级「非重解析点 + 硬链接数
/// 为 1」校验，rename 原子替换。
fn write_si_config(path: &Path, json: &str) -> std::io::Result<()> {
    use rand::RngCore;
    use std::io::Write;
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let name = format!(
        "si.json.tmp.{}",
        suffix
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    let tmp = path.with_file_name(name);
    let f = {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
            opts.mode(0o600);
        }
        opts.open(&tmp)?
    };
    #[cfg(windows)]
    {
        // 句柄级确认（create_new 新文件本应满足；失败 = 竞态，放弃）
        use std::os::windows::fs::MetadataExt;
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        let ok =
            unsafe { GetFileInformationByHandle(HANDLE(f.as_raw_handle() as isize), &mut info) }
                .map(|_| info.nNumberOfLinks == 1)
                .unwrap_or(false);
        let attrs = f.metadata().map(|m| m.file_attributes()).unwrap_or(0xFFFF);
        if !ok || attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            drop(f);
            let _ = std::fs::remove_file(&tmp);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "单实例配置临时文件校验失败（疑似链接注入）",
            ));
        }
    }
    {
        let mut f = f;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn si_config() -> SiConfig {
    let mut guard = match SI.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.is_none() {
        *guard = Some(load_or_create_si_config());
    }
    guard.clone().unwrap()
}

/// 2.8.2（H1）：拒绝远程 / 设备路径（pub 供 commands::check_vault_file 复用）。
///
/// 规范化顺序：去首尾引号 → 正斜杠统一为反斜杠（`//server/share` 会被 Win32
/// 规范化为 UNC）→ 剥 `\\?\` verbatim 前缀 → 大小写不敏感识别 `UNC\` 前缀
/// （`\\?\UNC\server\share` 剥掉 verbatim 后剩 `UNC\...`）→ 剩余以 `\\` 开头
/// （普通 UNC 或 `\\.\` 设备命名空间）即拒绝。`\\?\C:\...` verbatim 本地路径放行。
pub fn is_remote_or_device_path(p: &str) -> bool {
    let t = p.trim().trim_matches('"');
    let t = if t.contains('/') {
        t.replace('/', "\\")
    } else {
        t.to_string()
    };
    let t = t.strip_prefix(r"\\?\").unwrap_or(&t).to_string();
    // 2.8.2 后续修复：按字节比较 —— t[..4] 在多字节 UTF-8 路径（如中文目录）
    // 上会切在字符边界内直接 panic；"UNC\" 全 ASCII，字节级忽略大小写比较等价
    let b = t.as_bytes();
    if b.len() >= 4 && b[..4].eq_ignore_ascii_case(b"UNC\\") {
        return true;
    }
    // 3.0.0（L-12 审计修复）：GLOBALROOT 设备命名空间同样拒绝 ——
    // `\\?\GLOBALROOT\Device\...` 剥掉 verbatim 前缀后剩 `GLOBALROOT\...`，
    // 旧实现只查 UNC\ 与 \\ 开头会放行这条设备路径缝
    if b.len() >= 10 && b[..10].eq_ignore_ascii_case(b"GLOBALROOT\\") {
        return true;
    }
    t.starts_with(r"\\")
}

/// 判断路径是否为 LynVault 保险柜文件（扩展名 + magic bytes 双重校验）。
/// 2.8.1：远程 / 设备路径不做文件打开（见 is_remote_or_device_path）。
fn looks_like_vault(p: &str) -> bool {
    if is_remote_or_device_path(p) {
        return false;
    }
    let path = Path::new(p);
    let ext_ok = path
        .extension()
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
    let cfg = si_config();
    match TcpListener::bind(("127.0.0.1", cfg.port)) {
        Ok(listener) => {
            // 首实例：暂存监听器，setup 回调中取走上监听线程
            if let Ok(mut guard) = LISTENER.lock() {
                *guard = Some(listener);
            }
            true
        }
        Err(_) => {
            // 端口被占：确认是不是本程序的既有实例（令牌握手）
            if try_forward(&args, &cfg) {
                false // 转发成功 → 调用方退出
            } else {
                // 被无关程序占用 / 令牌不符 → 放弃单实例能力，正常启动
                //（2.8.2/L2：令牌校验失败一律不发送路径并继续正常启动）
                log::warn!(
                    "单实例端口 {} 被无关程序占用或握手失败，降级为普通启动",
                    cfg.port
                );
                true
            }
        }
    }
}

/// 尝试把参数转发给既有实例（令牌握手，带回执）。返回 true = 转发成功。
fn try_forward(args: &[String], cfg: &SiConfig) -> bool {
    let Ok(stream) = TcpStream::connect(("127.0.0.1", cfg.port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let mut reader = BufReader::new(stream);

    // 1. 握手：HELLO + token —— 令牌不符的实例不会回 OK，路径不会发出
    let hello = format!("{} {}\n", PROTO_HELLO, cfg.token);
    if reader.get_mut().write_all(hello.as_bytes()).is_err() {
        return false;
    }
    if !read_expect(&mut reader, "OK") {
        return false;
    }

    // 2. 发送保险柜路径（无则空行）
    let vault = extract_vault_arg(args.iter().cloned()).unwrap_or_default();
    if reader
        .get_mut()
        .write_all(format!("{}\n", vault).as_bytes())
        .is_err()
    {
        return false;
    }

    // 3. 等回执：服务端在**校验路径之后**才回 OK；非法路径回 ERR，
    //    此时本实例降级为正常启动（用户看得见窗口，而不是「什么都没发生」）
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
/// 2.6.1 修复（并发化）：每个连接在独立线程处理；并用 `MAX_CONCURRENT_CONNS`
/// 限制同时处理数。
pub fn server_loop(handle: AppHandle) {
    let cfg = si_config();
    let listener = {
        match LISTENER.lock() {
            Ok(mut guard) => guard.take(),
            Err(_) => None,
        }
    };
    let Some(listener) = listener else {
        log::warn!("单实例监听器缺失，参数转发不可用");
        return;
    };
    let expected_token = cfg.token;

    // 3.0.1（F24）：两个独立计数器 —— pending（accept 起算，限线程数，宽松）
    // 与 active（令牌握手通过后才占用，限真实处理并发）。旧实现共用一个
    // accept 侧计数，8 条未认证空闲连接即可占满槽位 5 秒。
    let pending = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if pending.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING_CONNS {
            pending.fetch_sub(1, Ordering::SeqCst);
            drop(stream);
            continue;
        }
        let handle = handle.clone();
        let pending = pending.clone();
        let active = active.clone();
        let expected_token = expected_token.clone();
        std::thread::spawn(move || {
            // 2.8.2：处理线程 panic 不得泄漏计数（否则累计后单实例转发
            // 永久失效）
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle_connection(&handle, stream, &expected_token, active);
            }));
            if result.is_err() {
                log::warn!("单实例连接处理线程 panic（已恢复）");
            }
            pending.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// 处理单个转发连接（令牌握手 → 收路径 → 校验 → 回执 → 触发打开）。
/// 在独立线程中运行，因此 `handle_vault_request` 等待前端就绪（最长 60 秒）
/// 不再阻塞 accept 循环。
/// 2.8.2（L2）：令牌不符直接断开，不回执、不收路径。
fn handle_connection(
    handle: &AppHandle,
    stream: TcpStream,
    expected_token: &str,
    active: Arc<AtomicUsize>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(stream);

    // 1. 握手：必须为 "PROTO_HELLO <token>" 且令牌逐字节一致
    //（(&mut reader) 显式借用 —— 直接 reader.take() 会移动 reader）
    let mut hello = String::new();
    if (&mut reader)
        .take(MAX_LINE_BYTES)
        .read_line(&mut hello)
        .is_err()
    {
        return;
    }
    let mut parts = hello.split_whitespace();
    // 3.0.0（L-7）：令牌核对恒定时间（与对话框令牌同一整理）
    let proto_ok = parts
        .next()
        .is_some_and(|p| crate::commands::ct_eq_str(p, PROTO_HELLO));
    let token_ok = parts
        .next()
        .is_some_and(|t| crate::commands::ct_eq_str(t, expected_token));
    if !proto_ok || !token_ok {
        return; // 令牌不符直接断开（无回执、无路径）
    }
    // 3.0.1（F24）：并发槽位在**令牌握手通过后**才占用。panic 经
    // ConnSlotGuard 的 Drop 兜底释放（外层 catch_unwind 的 unwind 过程中
    // guard 正常析构）。
    if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT_CONNS {
        active.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    let _slot = ConnSlotGuard(active);
    if reader.get_mut().write_all(b"OK\n").is_err() {
        return;
    }

    // 2. 读路径行（2.5.1：限制单行长度；(&mut reader) 显式借用避免移动）
    let mut path_line = String::new();
    if (&mut reader)
        .take(MAX_LINE_BYTES)
        .read_line(&mut path_line)
        .is_err()
    {
        return;
    }

    // 3. 先校验、后回执（2.8.2：旧实现回执先于校验且结束符是死变量，
    //    非法路径也回 OK，双击方拿「成功」回执退出后什么都没发生）。
    //    非法路径回 ERR → 对端降级为正常启动（窗口可见，不会静默消失）。
    let path = path_line.trim().to_string();
    let reply = if path.is_empty() || looks_like_vault(&path) {
        "OK\n"
    } else {
        "ERR\n"
    };
    let _ = reader.get_mut().write_all(reply.as_bytes());
    drop(reader);

    if path.is_empty() {
        // 2.7.1 修复：双击 exe（不带 .lyt 路径）的转发请求同样把已运行实例带到前台
        focus_existing_window(handle);
        return;
    }
    if looks_like_vault(&path) {
        handle_vault_request(handle, path);
    }
}

/// 把已运行实例的主窗口带到前台（可能被最小化）。
/// Windows 下 `SetForegroundWindow` 对非前台进程有限制：先短暂置顶再聚焦后
/// 取消，避免只闪任务栏图标。
pub fn focus_existing_window(handle: &AppHandle) {
    if let Some(win) = handle.get_webview_window("main") {
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
    // 等前端就绪（最长 60 秒），避免事件发出去时 webview 还没注册监听器。
    // 2.8.2：以 100ms 忙轮询等待 —— 等待期间占用一个并发槽（上限 8），
    // 超时即放弃，不无限占用。
    let deadline = Instant::now() + Duration::from_secs(60);
    while !FRONTEND_READY.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if !FRONTEND_READY.load(Ordering::SeqCst) {
        log::warn!("前端 60 秒内未就绪，丢弃打开请求");
        return;
    }
    focus_existing_window(handle);
    if let Err(e) = tauri::Emitter::emit(handle, "vault-file-requested", path) {
        log::warn!("发送 vault-file-requested 失败: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2.8.2（H1）：远程 / 设备路径守卫的规范化全覆盖
    #[test]
    fn remote_guard_rejects_unc_variants() {
        // 普通 UNC
        assert!(is_remote_or_device_path(r"\\server\share\v.lyt"));
        // verbatim UNC（剥 \\?\ 后剩 UNC\...）
        assert!(is_remote_or_device_path(r"\\?\UNC\server\share\v.lyt"));
        // 正斜杠 UNC（Win32 会规范化为 UNC）
        assert!(is_remote_or_device_path("//server/share/v.lyt"));
        // 设备命名空间
        assert!(is_remote_or_device_path(r"\\.\PhysicalDrive0"));
        // 带引号包裹
        assert!(is_remote_or_device_path(r#""\\server\share\v.lyt""#));
    }

    #[test]
    fn remote_guard_allows_local_paths() {
        // verbatim 本地路径仍放行
        assert!(!is_remote_or_device_path(r"\\?\C:\data\v.lyt"));
        // 普通本地路径
        assert!(!is_remote_or_device_path(r"C:\data\v.lyt"));
        assert!(!is_remote_or_device_path(r"D:\保险柜\v.lyt"));
        // 相对路径
        assert!(!is_remote_or_device_path("v.lyt"));
        // 本地路径包含大写 UNC 字样的目录名不误伤
        assert!(!is_remote_or_device_path(r"C:\unc\v.lyt"));
    }
}
