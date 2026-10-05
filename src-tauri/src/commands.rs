use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use vault_core::Vault;
use zeroize::Zeroize;

// ───────────────── 全局状态 ─────────────────

/// 全局状态：保险柜实例 + 认证频率限制
pub struct AppState {
    vault: Mutex<Option<Vault>>,
    last_auth_attempt: Mutex<Option<Instant>>,
}

/// 2.8.2（H2）：对话框令牌表 —— dialog_pick_files / dialog_pick_folder 弹出
/// 原生对话框后，把所选路径登记进该表并签发一次性 128 位随机令牌。
/// 导入/提取命令必须凭令牌取路径，且要求 IPC 传入路径与登记**逐条完全一致**，
/// 令牌用后即焚 —— 被攻陷的 WebView 无法再直接 `invoke('import_files_batch',
/// { src_paths: [...] })` 读取任意用户文件（渲染层任意文件读取等价物）。
/// 用 Vec<(token, paths, 签发时刻)> 而非 HashMap（static 初始化须为 const，
/// 条目数 ≤ 64）。
/// 3.0.1（F16 修复）：条目带签发时刻，登记时清理超过 10 分钟的旧令牌 ——
/// peek 不消费令牌，旧表会无限期保留「已选但未验证」的路径。
static DIALOG_TOKENS: Mutex<Vec<(String, Vec<String>, Instant)>> = Mutex::new(Vec::new());

/// 3.0.1（F16）：对话框令牌有效期 —— 正常流程（选完即导入/提取）远短于此
const DIALOG_TOKEN_TTL: Duration = Duration::from_secs(600);

/// 3.0.0（优化2）：媒体流式预览令牌表 —— (token, vpath)。
/// 非一次性（播放/拖动进度条会对同一 URL 发多次 Range 请求），随会话
/// 生命周期：开柜时签发、关柜/锁定/销毁即全部作废。被攻陷的 WebView
/// 最多流式读取「已由用户点开预览的那个文件」—— 与 load_file_content
/// 的既有信任模型一致，且受扩展名白名单与分块布局双重约束。
static MEDIA_TOKENS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// 清空媒体令牌（会话结束点调用）
pub fn clear_media_tokens() {
    if let Ok(mut guard) = MEDIA_TOKENS.lock() {
        guard.clear();
    }
}

/// 3.0.1（F13 修复）：媒体请求并发闸 —— 被攻陷的 WebView 可对
/// `lynvault-media://` 发起大量并发 Range 请求，每个最多分配 16 MiB 明文
/// 并排队占用全局保险柜互斥锁（可用性 DoS，数据暴露面已受令牌约束）。
/// try-acquire 语义：闸满直接 404（播放器会自行重试），请求不排队堆积。
static MEDIA_INFLIGHT: Mutex<usize> = Mutex::new(0);
const MEDIA_MAX_INFLIGHT: usize = 4;

struct MediaSlot;

impl MediaSlot {
    fn try_acquire() -> Option<MediaSlot> {
        let mut guard = MEDIA_INFLIGHT.lock().ok()?;
        if *guard >= MEDIA_MAX_INFLIGHT {
            return None;
        }
        *guard += 1;
        Some(MediaSlot)
    }
}

impl Drop for MediaSlot {
    fn drop(&mut self) {
        if let Ok(mut guard) = MEDIA_INFLIGHT.lock() {
            *guard = guard.saturating_sub(1);
        }
    }
}

/// 媒体扩展名 → MIME（白名单即映射表）
fn media_mime(ext: &str) -> Option<&'static str> {
    Some(match ext.to_ascii_lowercase().as_str() {
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "ogg" | "oga" | "opus" => "audio/ogg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        _ => return None,
    })
}

/// 2.8.2（H2）：主进程侧记录的真实拖放载荷（main.rs 的 on_window_event 写入）。
/// 拖放导入不再信任 WebView 字符串 —— 命令要求传入路径与该载荷排序后完全一致。
static DROPPED_PATHS: Mutex<Option<Vec<String>>> = Mutex::new(None);

/// main.rs 的 on_window_event 调用：记录真实拖放载荷（覆盖式 —— 每次新的
/// drop 事件刷新；消费后清空）
pub fn record_dropped_paths(paths: Vec<String>) {
    if let Ok(mut guard) = DROPPED_PATHS.lock() {
        *guard = Some(paths);
    }
}

/// 3.0.0（M-1 审计修复）：本地路径守卫 —— 一处实现全命令复用。
/// 路径若是 UNC / 设备命名空间，任何文件打开都会无提示发起 SMB 访问，
/// 构成免交互 NTLM 凭据外泄/中继触发原语（2.8.2 H1 确立的原则）。
/// 此前守卫只覆盖 check_vault_file / yubikey_challenge，本次统一收口
///（open_vault / create_vault / get_lock_info / scan_vault_files / load_key_file）。
fn ensure_local_path(path: &str) -> Result<(), String> {
    if crate::single_instance::is_remote_or_device_path(path) {
        return Err("不支持的保险柜路径（远程或设备路径）".into());
    }
    Ok(())
}

/// 消费拖放载荷：与传入路径做「排序后完全一致」比较，不符或缺失即拒绝
fn take_dropped_paths_matches(paths: &[String]) -> Result<(), String> {
    let mut guard = match DROPPED_PATHS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let recorded = guard
        .take()
        .ok_or_else(|| "没有已记录的拖放操作（请通过窗口拖放触发导入）".to_string())?;
    let mut a = recorded.clone();
    let mut b = paths.to_vec();
    a.sort();
    b.sort();
    if a != b {
        return Err("拖放路径与主进程记录不一致（请求可能被伪造）".to_string());
    }
    Ok(())
}

/// 登记路径并签发一次性令牌
fn register_dialog_paths(paths: Vec<String>) -> Result<String, String> {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let token: String = b.iter().map(|x| format!("{:02x}", x)).collect();
    let mut guard = match DIALOG_TOKENS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    // 3.0.1（F16）：先清理过期令牌（peek 不消费，旧条目否则无限期滞留）
    guard.retain(|(_, _, issued)| issued.elapsed() < DIALOG_TOKEN_TTL);
    // 防御：令牌表无限膨胀（恶意高频调用对话框命令），超限时最旧条目淘汰
    if guard.len() > 64 {
        guard.remove(0);
    }
    guard.push((token.clone(), paths, Instant::now()));
    Ok(token)
}

/// 核验令牌并要求传入路径与登记逐条完全一致（消费式 —— 用后即焚）
/// 3.0.0（L-7 审计修复）：恒定时间字符串比较 —— 令牌核对不再用短路 `==`
///（与 HMAC/标签/密码路径的 ct_eq 纪律对齐；实际可利用性趋近零，一致性整理）。
pub(crate) fn ct_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn verify_dialog_paths(token: &str, paths: &[String]) -> Result<(), String> {
    let mut guard = match DIALOG_TOKENS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let pos = guard
        .iter()
        .position(|(t, _, _)| ct_eq_str(t, token))
        .ok_or_else(|| "对话框令牌无效或已使用".to_string())?;
    let (_, registered, issued) = guard.remove(pos);
    // 3.0.1（F16）：过期令牌视为无效
    if issued.elapsed() >= DIALOG_TOKEN_TTL {
        return Err("对话框令牌无效或已使用".to_string());
    }
    if registered.len() != paths.len() || registered.iter().zip(paths.iter()).any(|(a, b)| a != b) {
        return Err("传入路径与对话框登记不一致（请求可能被伪造）".to_string());
    }
    Ok(())
}

/// 核验令牌但**不消费**（两段式流程的预检用 —— check_extract_all_dest
/// 预检不焚令牌，最终提取才焚）
fn peek_dialog_paths(token: &str) -> Result<Vec<String>, String> {
    let guard = match DIALOG_TOKENS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    // I2（审计整理）：与 verify_dialog_paths 同一恒定时间纪律
    guard
        .iter()
        .find(|(t, _, _)| ct_eq_str(t, token))
        .map(|(_, paths, _)| paths.clone())
        .ok_or_else(|| "对话框令牌无效或已使用".to_string())
}

/// 2.4.1 新增：通过启动参数 / 文件关联传入的保险柜路径。
/// main() 启动时解析 argv 写入，前端就绪后用 `get_launch_vault_arg` 读取。
static LAUNCH_VAULT_ARG: Mutex<Option<String>> = Mutex::new(None);

/// 写入启动参数中的保险柜路径（main.rs 调用）
pub fn set_launch_vault_arg(path: Option<String>) {
    if let Ok(mut guard) = LAUNCH_VAULT_ARG.lock() {
        *guard = path;
    }
}

/// 2.3.0 修复（Mutex 中毒恢复）：任何命令在持有锁期间 panic 会使锁永久中毒，
/// 后续所有命令都返回「内部错误」直到重启。这里从中毒锁中恢复出 guard 继续使用
/// （锁内的 Vault 值本身并未损坏，panic 只发生在操作执行中）。
fn lock_vault<'a>(state: &'a AppState) -> Result<std::sync::MutexGuard<'a, Option<Vault>>, String> {
    match state.vault.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => Ok(poisoned.into_inner()),
    }
}

fn lock_cooldown<'a>(
    state: &'a AppState,
) -> Result<std::sync::MutexGuard<'a, Option<Instant>>, String> {
    match state.last_auth_attempt.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => Ok(poisoned.into_inner()),
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            vault: Mutex::new(None),
            last_auth_attempt: Mutex::new(None),
        }
    }

    /// 2.8.2：轻量查询保险柜是否打开（空闲锁看门狗用，锁中毒可恢复）
    ///（空闲锁看门狗目前仅 Windows；非 Windows 平台允许 dead_code）
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn vault_open(&self) -> bool {
        match self.vault.lock() {
            Ok(g) => g.is_some(),
            Err(p) => p.into_inner().is_some(),
        }
    }

    /// 检查认证冷却（防止暴力破解绕过 per-instance 限制）
    fn check_auth_cooldown(&self) -> Result<(), String> {
        let mut guard = lock_cooldown(self)?;
        if let Some(last) = *guard {
            if last.elapsed() < Duration::from_secs(3) {
                return Err("请稍后再试（冷却中）".into());
            }
        }
        *guard = Some(Instant::now());
        Ok(())
    }
}

/// 包装闭包，捕获 panic 防止闪退
fn catch<R, F: FnOnce() -> Result<R, String>>(label: &str, f: F) -> Result<R, String> {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else {
                format!("{:?}", e)
            };
            // 2.8.2（I1）：panic 载荷只写日志（落文件日志），不回传 WebView ——
            // 内部路径等细节不再直达渲染层
            log::error!("[LynVault] PANIC in {}: {}", label, msg);
            Err(format!("内部错误 ({}): 操作失败，详情已记录日志", label))
        }
    }
}

/// 2.4.1 新增（P0-1）：把重 I/O 命令丢到阻塞线程池执行，避免冻结 UI 主线程。
/// 闭包在阻塞线程中拿到 AppState 引用（锁语义与旧同步命令完全一致）。
/// 3.0.0（优化1）：构造节流（≥100ms 一次）的文件级进度回调 ——
/// 闭包内直接向 WebView 发事件；复用完整性体检的节流策略。
fn make_progress_fn(
    app: AppHandle,
    event: &'static str,
    done_key: &'static str,
    total_key: &'static str,
) -> impl Fn(usize, usize) {
    let last = std::cell::Cell::new(Instant::now() - Duration::from_millis(200));
    move |done: usize, total: usize| {
        if last.get().elapsed() >= Duration::from_millis(100) {
            last.set(Instant::now());
            // json! 的键用括号表达式 —— 裸标识符会被当作字段名简写
            let _ = app.emit(
                event,
                serde_json::json!({ (done_key): done, (total_key): total }),
            );
        }
    }
}

async fn run_blocking<T, F>(app: &AppHandle, label: &str, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&AppState) -> Result<T, String> + Send + 'static,
{
    let app = app.clone();
    let label = label.to_string();
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        catch(&label, move || f(&state))
    })
    .await
    .map_err(|e| format!("后台任务失败: {}", e))?
}

// ───────────────── 保险柜生命周期 ─────────────────

#[tauri::command]
pub async fn create_vault(
    app: AppHandle,
    path: String,
    mut password: String,
    key_file_path: Option<String>,
    token: Option<String>,
) -> Result<(), String> {
    run_blocking(&app, "create_vault", move |state| {
        // 2.8.1：冷却检查移入内层闭包 —— 旧实现它在零化作用域之外 `?` 提前返回，
        // 密码未经 zeroize 就被丢弃
        let result: Result<(), String> = (|| {
            state.check_auth_cooldown()?;
            // 3.0.0（M-1）：UNC / 设备路径守卫
            ensure_local_path(&path)?;
            // 3.0.0（H-1 审计修复）：必须凭后端对话框令牌 —— 被攻陷的 WebView
            // 此前可绕过保存对话框的确认直接清零任意可写文件（与「读任意文件
            // 进柜」对称的破坏性原语）。
            // 3.0.1（F12 修复）：令牌要求**无条件** —— 旧实现只对「目标已存在」
            // 分支核验，WebView 可在无原生确认的情况下于任意可写路径创建新文件
            //（新文件走 create_new 不会覆盖，但属于免确认的文件创建原语）。
            // 前端本就总是先经 dialog_pick_save 取令牌，对正常流程零影响。
            let token = token
                .as_deref()
                .ok_or("缺少对话框令牌（请通过「新建保险柜」对话框选择位置）")?;
            verify_dialog_paths(token, std::slice::from_ref(&path))?;
            let key_data = load_key_file(&key_file_path)?;
            let created: Result<(), String> = (|| {
                // 2.4.1（P2-20）：Vault::create 成功即进入已解锁会话
                // （旧流程 create 后再 open_and_authenticate 要重复 8 次 Argon2id）
                let mut vault = Vault::default();
                vault
                    .create(Path::new(&path), &password, key_data.as_deref())
                    .map_err(|e| e.to_string())?;
                let mut guard = lock_vault(state)?;
                *guard = Some(vault);
                // 2.8.0：保险柜已打开 → 启动剪贴板保护（开柜期间即时清空）
                crate::clipboard_guard::start();
                Ok(())
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            created
        })();
        password.as_mut_str().zeroize();
        result
    })
    .await
}

/// 3.0.1（F2 修复）：硬件密钥响应一律由后端在用点现场挑战 —— WebView 不再
/// 接触响应字节。旧 `yubikey_challenge` 命令把 20 字节响应交给 JS 且无认证、
/// 无限速、不消费，使「第二因子」退化为对任意文件快照静态可重放的秘密。
/// 现在响应只在 open / 改密 / 胁迫标记等命令内部派生，用完即弃。
fn compute_yk_response(salt: &[u8; 32]) -> Result<[u8; 20], String> {
    let challenge = vault_core::crypto::derive_yubikey_challenge(salt);
    crate::yubikey::challenge_response(&challenge).map_err(|e| format!("硬件密钥验证失败：{}", e))
}

/// 3.0.1（F2 修复）：会话内命令的响应获取 —— 当前分区已启用二因子时现场
/// 挑战硬件；普通分区返回 None（不做任何硬件调用）。
fn session_yk_response(vault: &Vault) -> Result<Option<[u8; 20]>, String> {
    if vault.is_yubikey_2fa_active().map_err(|e| e.to_string())? {
        let salt = vault.yubikey_challenge_salt().map_err(|e| e.to_string())?;
        Ok(Some(compute_yk_response(&salt)?))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub async fn open_vault(
    app: AppHandle,
    path: String,
    mut password: String,
    key_file_path: Option<String>,
    use_yubikey: Option<bool>,
) -> Result<usize, String> {
    run_blocking(&app, "open_vault", move |state| {
        // 2.8.1：冷却检查移入内层（同 create_vault，覆盖密码零化）
        let result: Result<usize, String> = (|| {
            state.check_auth_cooldown()?;
            // 3.0.0（M-1）：UNC / 设备路径守卫
            ensure_local_path(&path)?;
            let key_data = load_key_file(&key_file_path)?;
            // 3.0.1（F2）：前端只声明意图（useYubikey），响应由后端现场挑战
            // 硬件计算 —— 旧实现接受 WebView 提供的任意 20 字节（静态重放面）
            let yk = match use_yubikey {
                Some(true) => {
                    let salt = vault_core::read_vault_yk_salt(Path::new(&path))
                        .map_err(|e| e.to_string())?;
                    Some(compute_yk_response(&salt)?)
                }
                _ => None,
            };
            let opened: Result<usize, String> = (|| {
                let mut vault = Vault::default();
                let idx = vault
                    .open_and_authenticate(
                        Path::new(&path),
                        &password,
                        key_data.as_deref(),
                        yk.as_ref(),
                    )
                    .map_err(|e| e.to_string())?;
                let mut guard = lock_vault(state)?;
                // 3.0.0（L-10 审计修复）：顶替已打开会话前先正常关闭旧会话 ——
                // 旧实现直接覆盖，旧 Vault 走 Drop 只清密钥不落盘，
                // 自上次 save_index 之后的审计条目静默丢失
                if let Some(ref mut old) = *guard {
                    old.close();
                }
                *guard = Some(vault);
                // 2.8.0：保险柜已打开 → 启动剪贴板保护（开柜期间即时清空）
                crate::clipboard_guard::start();
                // 3.0.0（优化2）：新会话作废旧媒体令牌
                clear_media_tokens();
                Ok(idx)
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            opened
        })();
        password.as_mut_str().zeroize();
        result
    })
    .await
}

#[tauri::command]
pub async fn close_vault(app: AppHandle) -> Result<(), String> {
    run_blocking(&app, "close_vault", move |state| {
        let mut guard = lock_vault(state)?;
        if let Some(v) = guard.as_mut() {
            v.close(); // 2.4.1：清理索引缓存 + 审计补落盘，再释放会话
        }
        *guard = None;
        // 2.8.0：会话已结束 → 停止剪贴板保护（系统剪贴板恢复正常）
        crate::clipboard_guard::stop();
        // 3.0.0（优化2）：媒体令牌作废
        clear_media_tokens();
        Ok(())
    })
    .await
}

// ───────────────── 文件浏览 ─────────────────

/// 2.4.1（P1-16）：返回结构化数组而非手工序列化的 JSON 字符串。
/// 2.8.1（性能）：改用 vault-core 的只读索引借用（免整索引克隆）+ 类型化
/// struct 序列化（比逐项 serde_json::json! 构造 Map 便宜一个量级）。
#[derive(serde::Serialize)]
pub struct ListItem {
    pub name: String,
    pub vpath: String,
    #[serde(rename = "type")]
    pub item_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[tauri::command]
pub async fn list_folder(app: AppHandle, folder: String) -> Result<Vec<ListItem>, String> {
    run_blocking(&app, "list_folder", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;

        // 2.3.0 修复：归一化目录参数（去掉结尾 '/'，根目录保持 "/"），
        // 避免用户在路径框输入 "dir/" 时返回空列表
        // 2.5.1 修复：改用 Index::normalize_vpath 统一归一化 —— 旧实现只去掉
        // 结尾 '/'，路径框输入 "foo//bar"、"///" 等仍会因不匹配返回空列表，
        // 与其他模块（导入/删除/提取）的归一化规则不一致
        let folder_norm = vault_core::Index::normalize_vpath(&folder)
            .filter(|p| vault_core::Index::validate_vpath(p))
            .ok_or_else(|| "无效的目录路径".to_string())?;

        let index = vault.index_ref().map_err(|e| e.to_string())?;

        let mut items: Vec<ListItem> = Vec::new();

        for vpath in index.folders.keys() {
            if vpath.is_empty() || *vpath == "/" {
                continue;
            }
            let parent = vpath.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            let display_parent = if parent.is_empty() { "/" } else { parent };
            if display_parent == folder_norm {
                let name = vpath.rsplit_once('/').map(|(_, n)| n).unwrap_or(vpath);
                if !name.is_empty() {
                    items.push(ListItem {
                        name: name.to_string(),
                        vpath: vpath.clone(),
                        item_type: "folder",
                        size: None,
                    });
                }
            }
        }

        for (vpath, meta) in &index.files {
            let dir = vpath.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            let display_dir = if dir.is_empty() { "/" } else { dir };
            if display_dir == folder_norm {
                items.push(ListItem {
                    name: meta.name.clone(),
                    vpath: vpath.clone(),
                    item_type: "file",
                    size: Some(meta.size),
                });
            }
        }

        items.sort_by(|a, b| {
            if a.item_type == b.item_type {
                a.name.cmp(&b.name)
            } else if a.item_type == "folder" {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });

        Ok(items)
    })
    .await
}

// ───────────────── 文件导入 ─────────────────

// 2.7.1：移除死命令 `import_file` / `extract_file` —— 自 2.4.1 批量路径上线后
// 无前端调用方，且后者硬编码 overwrite=true（静默覆盖语义），留着是无调用方
// 约束的危险默认值。批量入口：import_files_batch / extract_files。
//
// 2.8.2（H2）：导入类命令的路径必须来自后端对话框令牌 —— 命令同时接收
// `token` 与路径列表，核验「令牌有效 + 逐条一致」后消费令牌。被 XSS 攻陷的
// WebView 直接 invoke 导入命令并把任意用户可读文件（.ssh、浏览器 Cookies）
// 灌进已解锁保险柜的路径已被封死。

/// 2.8.2（H2）：弹出原生多选文件对话框，所选路径登记为一次性令牌。
/// 对话框在 spawn_blocking 线程弹出（blocking builder 不能在主线程用）。
/// 3.0.0（Tauri 2）：改走 tauri-plugin-dialog 的 blocking API（需 AppHandle）。
#[tauri::command]
pub async fn dialog_pick_files(app: AppHandle) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        catch("dialog_pick_files", || {
            let picked = app
                .dialog()
                .file()
                .add_filter("所有文件", &["*"])
                .blocking_pick_files();
            match picked {
                Some(paths) if !paths.is_empty() => {
                    let strs: Vec<String> = paths
                        .into_iter()
                        .filter_map(|fp| fp.into_path().ok())
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect();
                    let token = register_dialog_paths(strs.clone())?;
                    Ok(serde_json::json!({ "token": token, "paths": strs }))
                }
                _ => Ok(serde_json::json!({ "token": serde_json::Value::Null, "paths": [] })),
            }
        })
    })
    .await
    .map_err(|e| format!("后台任务失败: {}", e))?
}

/// 2.8.2（H2）：弹出原生目录对话框，所选目录登记为一次性令牌
#[tauri::command]
pub async fn dialog_pick_folder(app: AppHandle) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        catch("dialog_pick_folder", || {
            let picked = app
                .dialog()
                .file()
                .set_title("选择文件夹")
                .blocking_pick_folder();
            match picked {
                Some(p) => {
                    let p = p.into_path().map_err(|e| e.to_string())?;
                    let s = p.to_string_lossy().into_owned();
                    let token = register_dialog_paths(vec![s.clone()])?;
                    Ok(serde_json::json!({ "token": token, "paths": [s] }))
                }
                None => Ok(serde_json::json!({ "token": serde_json::Value::Null, "paths": [] })),
            }
        })
    })
    .await
    .map_err(|e| format!("后台任务失败: {}", e))?
}

/// 3.0.0（H-1 审计修复）：后端弹出「保存保险柜」对话框，所选路径登记为
/// 一次性令牌 —— create_vault 的覆盖分支（目标已存在）必须凭此令牌放行，
/// 封死「被攻陷的 WebView 直接 invoke create_vault 清零任意可写文件」的
/// 破坏性原语（保存对话框的用户确认因此不可绕过）。
#[tauri::command]
pub async fn dialog_pick_save(app: AppHandle) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        catch("dialog_pick_save", || {
            let picked = app
                .dialog()
                .file()
                .add_filter("LynVault 保险柜", &["lyt"])
                .add_filter("LynVault 保险柜（旧版）", &["vault"])
                .set_file_name("新建保险柜.lyt")
                .blocking_save_file();
            match picked {
                Some(fp) => {
                    let p = fp
                        .into_path()
                        .map_err(|e| e.to_string())?
                        .to_string_lossy()
                        .into_owned();
                    let token = register_dialog_paths(vec![p.clone()])?;
                    Ok(serde_json::json!({ "token": token, "paths": [p] }))
                }
                None => Ok(serde_json::json!({ "token": serde_json::Value::Null, "paths": [] })),
            }
        })
    })
    .await
    .map_err(|e| format!("后台任务失败: {}", e))?
}

/// 2.4.1 新增（P0-2）：批量导入文件。
/// 单次索引加密落盘替代 N 次（旧版前端循环 import_file 时每个文件都全量重写索引 + 10 次 fsync）。
/// 返回 { ok, fail, errors } 供前端展示结果（2.8.2：失败明细真实可达）。
#[tauri::command]
pub async fn import_files_batch(
    app: AppHandle,
    token: Option<String>,
    src_paths: Vec<String>,
    dest_base: String,
) -> Result<serde_json::Value, String> {
    let app_progress = app.clone();
    run_blocking(&app, "import_files_batch", move |state| {
        // 2.8.2（H2）：令牌核验（消费式）
        let token = token.ok_or("缺少对话框令牌（请通过「导入文件」对话框选择）")?;
        verify_dialog_paths(&token, &src_paths)?;
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let (ok, fail, errors) = vault
            .import_files_batch(
                &src_paths,
                &dest_base,
                Some(&make_progress_fn(
                    app_progress,
                    "import-progress",
                    "filesDone",
                    "filesTotal",
                )),
                None,
            )
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "ok": ok, "fail": fail, "errors": errors }))
    })
    .await
}

#[tauri::command]
pub async fn import_folder(
    app: AppHandle,
    token: Option<String>,
    src_folder: String,
    dest_base: String,
) -> Result<serde_json::Value, String> {
    let app_progress = app.clone();
    run_blocking(&app, "import_folder", move |state| {
        let token = token.ok_or("缺少对话框令牌（请通过「导入文件夹」对话框选择）")?;
        verify_dialog_paths(&token, std::slice::from_ref(&src_folder))?;
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let (ok, fail, skipped) = vault
            .import_folder(
                Path::new(&src_folder),
                &dest_base,
                Some(&make_progress_fn(
                    app_progress,
                    "import-progress",
                    "filesDone",
                    "filesTotal",
                )),
            )
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "ok": ok, "fail": fail, "skippedSymlinks": skipped }))
    })
    .await
}

/// 拖放导入：自动判断路径是文件还是文件夹，批量导入到 dest_base 下
/// 2.4.1（P1-16）：返回结构化对象 { summary, files, folders, errors? } 供前端提示安全删除源文件
/// 2.8.2（H2）：路径必须与主进程 on_window_event 记录的真实拖放载荷排序后
/// 完全一致 —— WebView 伪造的字符串不再被信任。
#[tauri::command]
pub async fn import_dropped_paths(
    app: AppHandle,
    paths: Vec<String>,
    dest_base: String,
) -> Result<serde_json::Value, String> {
    run_blocking(&app, "import_dropped_paths", move |state| {
        // 3.0.0（R4）：先确认柜已打开再消费拖放载荷 —— 旧顺序在柜未开时白白
        // 焚毁一次性载荷，用户需要重新拖一次
        {
            let guard = lock_vault(state)?;
            if guard.is_none() {
                return Err("保险柜未打开".into());
            }
        }
        // 2.8.2（H2）：核验拖放载荷
        take_dropped_paths_matches(&paths)?;
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;

        let mut imported_files: Vec<String> = Vec::new();
        let mut imported_folders: Vec<String> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut dir_paths: Vec<String> = Vec::new();
        let mut file_paths: Vec<String> = Vec::new();

        // 2.4.1 新功能：拖入的 .lyt/.vault 是保险柜文件而非待加密文件 —— 分流处理，
        // 由前端走「打开保险柜」流程，这里直接跳过（不导入、不报错）。
        // 2.8.2（M8 补充）：magic 探测本身即文件打开，远程/设备路径先被守卫拦截。
        let (vault_files, normal_paths): (Vec<String>, Vec<String>) =
            paths.into_iter().partition(|p| {
                let path = Path::new(p);
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|s| s.eq_ignore_ascii_case("lyt") || s.eq_ignore_ascii_case("vault"))
                    .unwrap_or(false);
                ext && !crate::single_instance::is_remote_or_device_path(p)
                    && vault_core::is_vault_file(path)
            });

        for p in &normal_paths {
            let path = Path::new(p);
            if path.is_dir() {
                dir_paths.push(p.clone());
            } else if path.is_file() {
                file_paths.push(p.clone());
            } else {
                errors.push(format!("跳过 '{}': 不是有效文件或目录", p));
            }
        }

        // 2.8.1（性能）：文件走单次批量导入 —— 旧实现每文件一次 import_file =
        // 每文件一次完整索引落盘（9 次 fsync + 8×索引体积写放大），拖入 50 个
        // 文件 ≈ 450 次 fsync；批量后只有 1 次保存。
        if !file_paths.is_empty() {
            match vault.import_files_batch(&file_paths, &dest_base, None, None) {
                Ok((ok, fail, batch_errors)) => {
                    if fail == 0 {
                        imported_files = file_paths;
                    } else {
                        // 部分失败：成功的文件名单保留（可安全删除源文件的仅限
                        // 成功项），失败明细进 errors —— 旧实现整体置空导致
                        // 用户一个源文件都不敢删
                        imported_files = file_paths
                            .iter()
                            .filter(|p| {
                                let name = Path::new(p)
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_default();
                                let prefix = name + ":";
                                !batch_errors.iter().any(|e| e.starts_with(&prefix))
                            })
                            .cloned()
                            .collect();
                        errors.push(format!("文件批量导入：成功 {} 个，失败 {} 个", ok, fail));
                        for e in &batch_errors {
                            errors.push(format!("  {}", e));
                        }
                    }
                }
                Err(e) => errors.push(format!("文件批量导入失败: {}", e)),
            }
        }
        for p in &dir_paths {
            match vault.import_folder(Path::new(p), &dest_base, None) {
                Ok((ok, fail, skipped)) => {
                    imported_folders.push(p.clone());
                    if fail > 0 {
                        errors.push(format!("文件夹 '{}'：{} 个文件导入失败", p, fail));
                    }
                    if skipped > 0 {
                        errors.push(format!(
                            "文件夹 '{}'：跳过 {} 个符号链接（成功 {} 个）",
                            p, skipped, ok
                        ));
                    }
                }
                Err(e) => errors.push(format!("文件夹 '{}': {}", p, e)),
            }
        }

        let mut parts = Vec::new();
        if !imported_files.is_empty() {
            parts.push(format!("{} 个文件", imported_files.len()));
        }
        if !imported_folders.is_empty() {
            parts.push(format!("{} 个文件夹", imported_folders.len()));
        }
        let summary = if parts.is_empty() {
            "未导入任何内容".into()
        } else {
            format!("拖放导入完成：{}", parts.join("，"))
        };

        let mut result = serde_json::json!({
            "summary": summary,
            "files": imported_files,
            "folders": imported_folders,
        });
        // 2.4.1：把识别出的保险柜文件带回给前端（触发打开流程）
        if !vault_files.is_empty() {
            result["vault_files"] = serde_json::json!(vault_files);
        }
        if !errors.is_empty() {
            result["errors"] = serde_json::json!(errors);
            result["summary"] = serde_json::json!(format!(
                "{}\n以下项目导入失败：\n{}",
                summary,
                errors.join("\n")
            ));
        }
        Ok(result)
    })
    .await
}

// ───────────────── 文件提取 ─────────────────

/// 2.8.2（M7）：提取目标目录保护 —— 拒绝 Windows 目录、Program Files、
/// ProgramData、开始菜单子树（覆盖「启动文件夹持久化」原语）。
/// 目标先 canonicalize（剥 `\\?\`），再做大小写不敏感的带分隔符边界比较。
#[cfg(windows)]
fn reject_protected_dest(dest_folder: &Path) -> Result<(), String> {
    let canon = std::fs::canonicalize(dest_folder).map_err(|_| "目标目录无法访问".to_string())?;
    let s = canon
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_ascii_lowercase();

    // 系统级保护目录（含环境变量解析出的实际位置，避免系统盘非 C: 时漏判）
    let mut protected: Vec<String> = vec![r"c:\windows".to_string()];
    for var in [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
    ] {
        if let Ok(v) = std::env::var(var) {
            protected.push(v.trim_end_matches('\\').to_ascii_lowercase());
        }
    }
    // 开始菜单（当前用户 + 全用户）—— 覆盖「往启动文件夹放东西」的持久化原语
    if let Ok(appdata) = std::env::var("APPDATA") {
        protected.push(
            PathBuf::from(appdata)
                .join(r"Microsoft\Windows\Start Menu")
                .to_string_lossy()
                .trim_end_matches('\\')
                .to_ascii_lowercase(),
        );
    }
    if let Ok(pd) = std::env::var("ProgramData") {
        protected.push(
            PathBuf::from(pd)
                .join(r"Microsoft\Windows\Start Menu")
                .to_string_lossy()
                .trim_end_matches('\\')
                .to_ascii_lowercase(),
        );
    }

    let within = |base: &str| s == base || s.starts_with(&format!("{}\\", base));
    for p in &protected {
        if within(p) {
            return Err(format!("目标目录位于受保护的系统位置（{}），已拒绝提取", p));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_protected_dest(_dest_folder: &Path) -> Result<(), String> {
    Ok(())
}

/// 2.8.2：与保险柜同名的导出根目录名（check_extract_all_dest / extract_all_files
/// 共用，消除逐行复制的清洗逻辑）
fn export_stem(vault_path: &Path) -> String {
    let stem = vault_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("LynVault_Export")
        .to_string();
    let safe_stem: String = stem
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
            )
        })
        .collect();
    if safe_stem.trim().is_empty() {
        "LynVault_Export".to_string()
    } else {
        safe_stem
    }
}

#[tauri::command]
pub async fn extract_files(
    app: AppHandle,
    vpaths: Vec<String>,
    token: Option<String>,
    dest_folder: String,
) -> Result<serde_json::Value, String> {
    let app_progress = app.clone();
    run_blocking(&app, "extract_files", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 2.8.2（H2/M7）：目标目录必须来自后端对话框令牌 + 保护目录拒绝
        let token = token.ok_or("缺少对话框令牌（请通过「提取」对话框选择目标）")?;
        verify_dialog_paths(&token, std::slice::from_ref(&dest_folder))?;
        reject_protected_dest(Path::new(&dest_folder))?;
        // 2.3.0 修复：委托给 vault-core 批量提取（单次 load_index + extract_file_inner，
        // 避免对每个文件重复 load_index 的 O(n²) 退化）
        // 2.7.1 修复：失败数不再被静默丢弃 —— 旧实现只回传成功数且前端连它都
        // 不用，默认拒绝覆盖同名文件时整批失败也报「提取完成」
        let (ok, fail, errors) = vault
            .extract_files_batch(
                &vpaths,
                Path::new(&dest_folder),
                Some(&make_progress_fn(
                    app_progress,
                    "extract-progress",
                    "filesDone",
                    "filesTotal",
                )),
                None,
            )
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "ok": ok, "fail": fail, "errors": errors }))
    })
    .await
}

// ───────────────── 文件/文件夹删除 ─────────────────

/// 2.4.1：vault-core 的批量删除现在同时展开文件夹并返回 (文件数, 文件夹数)，
/// 结构化返回 { files, folders } 供 UI 精确反馈。
#[tauri::command]
pub async fn delete_files(
    app: AppHandle,
    vpaths: Vec<String>,
) -> Result<serde_json::Value, String> {
    run_blocking(&app, "delete_files", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 委托给 vault-core 的批量删除方法：一次 load + 批量 DoD 7-pass 擦除 + 一次 save
        let (files, folders, reclaimed) = vault
            .secure_delete_files_batch(&vpaths)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "files": files, "folders": folders, "reclaimed": reclaimed }))
    })
    .await
}

#[tauri::command]
pub async fn delete_folder(app: AppHandle, vpath: String) -> Result<serde_json::Value, String> {
    run_blocking(&app, "delete_folder", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let reclaimed = vault.delete_folder(&vpath).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "reclaimed": reclaimed }))
    })
    .await
}

// ───────────────── 新建文件夹 / 重命名 ─────────────────

#[tauri::command]
pub async fn new_folder(app: AppHandle, vpath: String) -> Result<(), String> {
    run_blocking(&app, "new_folder", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let mut im = vault.get_index_manager().map_err(|e| e.to_string())?;
        im.add_folder(&vpath).map_err(|e| e.to_string())
    })
    .await
}

#[tauri::command]
pub async fn rename_item(
    app: AppHandle,
    old_vpath: String,
    new_name: String,
    is_folder: bool,
) -> Result<(), String> {
    run_blocking(&app, "rename_item", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let mut im = vault.get_index_manager().map_err(|e| e.to_string())?;
        if is_folder {
            im.rename_folder(&old_vpath, &new_name)
        } else {
            im.rename_file(&old_vpath, &new_name)
        }
        .map_err(|e| e.to_string())
    })
    .await
}

// ───────────────── 分区管理 ─────────────────

#[tauri::command]
pub async fn add_partition(
    app: AppHandle,
    alias: String,
    mut password: String,
    key_file_path: Option<String>,
) -> Result<(), String> {
    run_blocking(&app, "add_partition", move |state| {
        // 分区别名校验：只允许安全字符，防止 XSS。
        // 2.6.1：收紧为 ASCII-only，禁止 Unicode 同形字符造成「视觉同名」的
        // 分区别名混淆（与 vault-core::is_valid_alias 保持一致）。
        if !alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ' ')
        {
            return Err("分区别名只能包含 ASCII 字母、数字、下划线、短横线和空格".into());
        }
        if alias.trim().is_empty() || alias.len() > 16 {
            return Err("分区别名长度需在 1-16 字符之间".into());
        }
        // 2.3.0 修复：密码 / 密钥文件在所有路径上零化（旧实现 `?` 提前返回会跳过）
        let result: Result<(), String> = (|| {
            let key_data = load_key_file(&key_file_path)?;
            let added: Result<(), String> = (|| {
                let mut guard = lock_vault(state)?;
                let vault = guard.as_mut().ok_or("保险柜未打开")?;
                vault
                    .add_partition(&alias, &password, key_data.as_deref())
                    .map_err(|e| e.to_string())
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            added
        })();
        password.as_mut_str().zeroize();
        result
    })
    .await
}

#[tauri::command]
pub async fn remove_partition(app: AppHandle, alias: String) -> Result<(), String> {
    run_blocking(&app, "remove_partition", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.remove_partition(&alias).map_err(|e| e.to_string())
    })
    .await
}

/// 2.4.1（P1-16）：返回结构化数组
#[tauri::command]
pub async fn list_partitions(app: AppHandle) -> Result<Vec<serde_json::Value>, String> {
    run_blocking(&app, "list_partitions", move |state| {
        let guard = lock_vault(state)?;
        let vault = guard.as_ref().ok_or("保险柜未打开")?;
        let parts: Vec<serde_json::Value> = vault
            .get_partitions()
            .iter()
            .enumerate()
            .map(|(i, p)| serde_json::json!({ "index": i, "alias": p.alias }))
            .collect();
        Ok(parts)
    })
    .await
}

// ───────────────── 碎片整理 / 销毁 ─────────────────

#[tauri::command]
pub async fn defragment_vault(app: AppHandle) -> Result<String, String> {
    run_blocking(&app, "defragment_vault", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault
            .defragment_vault(None::<fn(usize)>)
            .map_err(|e| e.to_string())?;
        Ok("碎片整理完成".into())
    })
    .await
}

#[tauri::command]
pub async fn destroy_vault(app: AppHandle) -> Result<(), String> {
    let result = run_blocking(&app, "destroy_vault", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 2.7.1 修复（关键回归）：销毁改为全程使用会话句柄（Vault::destroy），
        // 不再按路径二次打开 —— 2.6.1 起会话句柄以 FILE_SHARE_READ 独占共享模式
        // 打开，旧实现按「读+写」重新打开同一文件必然被系统拒绝
        // （ERROR_SHARING_VIOLATION / os error 32），销毁在 Windows 上从未成功过。
        // 符号链接 / 重解析点的拒绝已前移到会话打开阶段（vault-core open_vault_rw），
        // 句柄锚定的 TOCTOU 防护不再削弱。
        vault.destroy().map_err(|e| e.to_string())?;
        // 2.8.1：清空会话槽位 —— 旧实现残留 Some（is_open=false 的空壳），
        // 后续命令报「保险柜未打开」的内部态而非干净的用户语义
        *guard = None;
        // 3.0.1（F16）：销毁同样是会话结束点 —— 媒体令牌一并作废
        clear_media_tokens();
        Ok(())
    })
    .await;
    // 2.8.0：销毁后会话不存在 → 停止剪贴板保护
    crate::clipboard_guard::stop();
    result
}

// ───────────────── 文件信息与预览 ─────────────────

/// 2.4.1（P1-16）：返回结构化对象
#[tauri::command]
pub async fn get_file_info(app: AppHandle, vpath: String) -> Result<serde_json::Value, String> {
    run_blocking(&app, "get_file_info", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 2.8.2：走只读借用（index_ref），免去整索引深拷贝
        let index = vault.index_ref().map_err(|e| e.to_string())?;
        if let Some(meta) = index.files.get(&vpath) {
            Ok(serde_json::json!({
                "name": meta.name, "size": meta.size, "vpath": vpath,
            }))
        } else {
            Err("文件不存在".into())
        }
    })
    .await
}

/// 预览大小上限（64 MiB）：预览走「整文件读入内存」路径，
/// 超大文件直接提示提取后查看，避免一次性占用数百 MB 内存。
const MAX_PREVIEW_SIZE: u64 = 64 * 1024 * 1024;

/// 2.4.1（P0-4）：返回 base64 字符串而不是 Vec<u8>。
/// Tauri 1.x 把 Vec<u8> 序列化成 JSON 数字数组（每字节一个数字 + 逗号），
/// 预览一张 5MB 图片实际要在 IPC 上传输几十 MB 的 JSON 文本；
/// base64 只有 1.33× 膨胀，且前端图片可直接拼 data URL。
/// 同时在读取前校验文件大小，超过 64 MiB 拒绝预览。
#[tauri::command]
pub async fn load_file_content(app: AppHandle, vpath: String) -> Result<String, String> {
    run_blocking(&app, "load_file_content", move |state| {
        use base64::Engine;
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let size = {
            let index = vault.load_index().map_err(|e| e.to_string())?;
            index
                .files
                .get(&vpath)
                .map(|m| m.size)
                .ok_or("文件不存在")?
        };
        if size > MAX_PREVIEW_SIZE {
            return Err(format!(
                "文件过大（{}），预览上限 64 MB，请使用「提取」导出后查看",
                size
            ));
        }
        let data = vault.load_file_data(&vpath).map_err(|e| e.to_string())?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        vault_core::wipe::secure_wipe_vec(data);
        Ok(b64)
    })
    .await
}

#[tauri::command]
pub async fn preview_office_file(
    app: AppHandle,
    vpath: String,
    mut password: Option<String>,
) -> Result<String, String> {
    run_blocking(&app, "preview_office_file", move |state| {
        // 2.8.2：带口令的尝试走认证冷却（3 秒）—— 旧实现文档口令可全速暴力
        // 尝试，与开柜口令的限速不对称。无口令（OFFICE_ENCRYPTED 哨兵探测）
        // 不消耗冷却。
        if password.is_some() {
            state.check_auth_cooldown()?;
        }
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 2.5.1 修复（OOM）：旧实现直接 load_file_data（内部上限 256 MiB），
        // 而 load_file_content 的预览路径有 64 MiB 上限 —— 同为「预览」，
        // Office 路径却允许整读 256 MiB 再做解压解析，恶意/超大文件可瞬间
        // 占用数百 MB 内存。现与预览路径统一 64 MiB 上限。
        let size = {
            let index = vault.load_index().map_err(|e| e.to_string())?;
            index
                .files
                .get(&vpath)
                .map(|m| m.size)
                .ok_or("文件不存在")?
        };
        if size > MAX_PREVIEW_SIZE {
            return Err(format!(
                "文件过大（{} 字节），预览上限 64 MB，请使用「提取」导出后查看",
                size
            ));
        }
        let data = vault.load_file_data(&vpath).map_err(|e| e.to_string())?;
        let filename = vpath.rsplit('/').next().unwrap_or(&vpath);
        // 2.7.0：password 为 Some 时解密 Agile Encryption 加密文档（纯内存）；
        // 为 None 且文档已加密时返回 OFFICE_ENCRYPTED 哨兵，由前端弹出口令输入
        let text = vault_core::office::extract_office_text(&data, filename, password.as_deref());
        if let Some(ref mut p) = password {
            p.as_mut_str().zeroize();
        }
        vault_core::wipe::secure_wipe_vec(data);
        text
    })
    .await
}

/// 2.5.1 新增：把编辑后的文件内容（base64）写回保险柜内同名 vpath。
/// 供 txt 预览的「直接编辑保存」使用 —— 全程不解密到磁盘：
/// 新内容加密追加到保险柜末尾 → 更新索引（先落盘）→ DoD 7-pass 覆写旧密文。
/// 编辑上限与预览一致（64 MiB）。
#[tauri::command]
pub async fn update_file_content(
    app: AppHandle,
    vpath: String,
    content_b64: String,
) -> Result<(), String> {
    run_blocking(&app, "update_file_content", move |state| {
        use base64::Engine;
        // 2.8.2（L7）：解码**前**按 base64 长度估算解码后大小并拒绝 ——
        // 旧实现先解码后限长，超大参数在解码期就完成 OOM 式分配
        if content_b64.len() / 4 * 3 > MAX_PREVIEW_SIZE as usize {
            return Err("内容过大：文本编辑上限 64 MB".into());
        }
        let data = base64::engine::general_purpose::STANDARD
            .decode(content_b64.as_bytes())
            .map_err(|e| format!("内容编码无效: {}", e))?;
        if data.len() as u64 > MAX_PREVIEW_SIZE {
            vault_core::wipe::secure_wipe_vec(data);
            return Err("内容过大：文本编辑上限 64 MB".into());
        }
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let result = vault
            .update_file_content(&vpath, &data)
            .map_err(|e| e.to_string());
        vault_core::wipe::secure_wipe_vec(data);
        result
    })
    .await
}

// ───────────────── 辅助函数 ─────────────────

fn load_key_file(path: &Option<String>) -> Result<Option<Vec<u8>>, String> {
    // 3.0.0（M-1）：UNC / 设备路径守卫（密钥文件读取也是文件打开，NTLM 面收口）
    if let Some(p) = path {
        ensure_local_path(p)?;
    }
    const MAX_KEY_FILE_SIZE: u64 = 64 * 1024 * 1024;
    match path {
        Some(p) => {
            // 2.7.1 修复：旧实现直接 std::fs::read，误选超大文件（或特殊设备路径）
            // 会无界分配内存直至 OOM。现按元数据预检 + take 限制读取总量，
            // 与导入路径的句柄化读取（2.7.0）同一策略。
            use std::io::Read;
            let f = std::fs::File::open(p).map_err(|e| e.to_string())?;
            let meta = f.metadata().map_err(|e| e.to_string())?;
            if !meta.is_file() {
                return Err("密钥文件不可用（不是普通文件）".into());
            }
            if meta.len() > MAX_KEY_FILE_SIZE {
                return Err(format!("密钥文件过大（{} 字节），上限 64 MB", meta.len()));
            }
            let mut data = Vec::with_capacity(meta.len() as usize);
            if let Err(e) = (&f).take(MAX_KEY_FILE_SIZE + 1).read_to_end(&mut data) {
                return Err(e.to_string());
            }
            if data.len() as u64 > MAX_KEY_FILE_SIZE {
                vault_core::wipe::secure_wipe_vec(data);
                return Err("密钥文件过大（读取时超过 64 MB 上限）".into());
            }
            Ok(Some(data))
        }
        None => Ok(None),
    }
}

// ───────────────── .lyt 文件自动识别（2.4.1 新功能） ─────────────────

/// 检查一个路径是否为 LynVault 保险柜文件（扩展名 + magic bytes 双重校验）。
/// 供前端拖放 .lyt 到窗口时自动识别并直接进入密码输入流程，
/// 避免把保险柜文件本身误当作待加密文件导入另一个保险柜。
/// 2.8.2：async 化（Tauri 1.x 同步命令在主线程执行，网络盘路径会冻结 UI）；
/// 2.8.2（M8）：远程/设备路径直接返回 false，magic 探测本身即文件打开。
#[tauri::command]
pub async fn check_vault_file(path: String) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || {
        catch("check_vault_file", || {
            if crate::single_instance::is_remote_or_device_path(&path) {
                return Ok(false);
            }
            let p = Path::new(&path);
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.eq_ignore_ascii_case("lyt") || s.eq_ignore_ascii_case("vault"))
                .unwrap_or(false);
            if !ext {
                return Ok(false);
            }
            // N6：magic bytes 校验，避免把其他工具的同后缀文件（HashiCorp Vault 等）
            // 误识别为 LynVault 保险柜
            Ok(vault_core::is_vault_file(p))
        })
    })
    .await
    .map_err(|e| format!("后台任务失败: {}", e))?
}

/// 读取启动参数中传入的保险柜路径（文件关联双击 .lyt 启动时由 main.rs 写入）。
/// 前端启动时调用；读取后清除，保证重载页面不会重复弹出。
#[tauri::command]
pub fn get_launch_vault_arg() -> Result<Option<String>, String> {
    catch("get_launch_vault_arg", || {
        if let Ok(mut guard) = LAUNCH_VAULT_ARG.lock() {
            Ok(guard.take())
        } else {
            Ok(None)
        }
    })
}

/// 2.4.1 新增：前端初始化完成后调用，置位就绪标志。
/// 单实例转发的打开请求会等到前端就绪后才发 `vault-file-requested` 事件，
/// 避免事件在监听器注册前发出而丢失。
#[tauri::command]
pub fn frontend_ready() -> Result<(), String> {
    crate::single_instance::FRONTEND_READY.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

// ───────────────── 2.8.0：改密码 / 移动 / 搜索 / 审计 / 体检 / 锁定信息 / 设置 ─────────────────

/// 2.8.0：修改当前分区密码。
/// - v5 保险柜：头部级操作（换盐重新包裹 data_key），数据零接触；
/// - v4 保险柜：自动升级为 v5（一次性全库重加密）。
/// 必须验证当前密码，防止他人在已解锁的机器上改密锁死真正的主人。
#[tauri::command]
pub async fn change_password(
    app: AppHandle,
    mut current_password: String,
    mut new_password: String,
    key_file_path: Option<String>,
) -> Result<(), String> {
    run_blocking(&app, "change_password", move |state| {
        let result: Result<(), String> = (|| {
            // 3.0.0（L-11 审计修复）：与 open_vault 同款认证冷却 —— 当前密码验证
            // 不再无限制速（口令复用场景的在线猜测面收敛）
            state.check_auth_cooldown()?;
            let key_data = load_key_file(&key_file_path)?;
            let changed: Result<(), String> = (|| {
                let mut guard = lock_vault(state)?;
                let vault = guard.as_mut().ok_or("保险柜未打开")?;
                // 3.0.1（F2）：二因子分区的验证响应由后端现场挑战硬件
                let yk = session_yk_response(vault)?;
                vault
                    .change_password(
                        &current_password,
                        &new_password,
                        key_data.as_deref(),
                        None::<fn(usize)>,
                        yk.as_ref(),
                    )
                    .map_err(|e| e.to_string())
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            changed
        })();
        current_password.as_mut_str().zeroize();
        new_password.as_mut_str().zeroize();
        result
    })
    .await
}

// ───────────────── 3.0.0：胁迫密码 ─────────────────
//
// 标记存储于胁迫分区自身的加密索引（外部不可见）；设置/解除/触发均不写审计。
// 触发语义（在 vault-core 的 open 成功路径内）：用带标记分区的密码开柜成功后，
// 其他所有分区的头部条目被随机覆写 —— 数据永久不可达，无找回手段。

/// 3.0.0：把当前分区标记为胁迫分区（要求当前分区密码验证）。
#[tauri::command]
pub async fn set_duress_mark(
    app: AppHandle,
    target_alias: String,
    mut target_password: String,
    key_file_path: Option<String>,
) -> Result<(), String> {
    run_blocking(&app, "set_duress_mark", move |state| {
        let result: Result<(), String> = (|| {
            // 3.0.0（L-11 审计修复）：与 open_vault 同款认证冷却 —— 当前密码验证
            // 不再无限制速（口令复用场景的在线猜测面收敛）
            state.check_auth_cooldown()?;
            let key_data = load_key_file(&key_file_path)?;
            let marked: Result<(), String> = (|| {
                let mut guard = lock_vault(state)?;
                let vault = guard.as_mut().ok_or("保险柜未打开")?;
                // 3.0.1（F2）：二因子分区的验证响应由后端现场挑战硬件
                let yk = session_yk_response(vault)?;
                // UX 重构：在当前会话中直接标记目标分区（含当前分区——
                // 用户打开它放好诱饵文件后原地标记是自然流程）
                vault
                    .set_duress_mark_on(
                        &target_alias,
                        &target_password,
                        key_data.as_deref(),
                        yk.as_ref(),
                    )
                    .map_err(|e| e.to_string())
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            marked
        })();
        target_password.as_mut_str().zeroize();
        result
    })
    .await
}

/// 3.0.0：解除当前分区的胁迫标记（要求当前分区密码验证）。
#[tauri::command]
pub async fn clear_duress_mark(
    app: AppHandle,
    target_alias: String,
    mut target_password: String,
    key_file_path: Option<String>,
) -> Result<(), String> {
    run_blocking(&app, "clear_duress_mark", move |state| {
        let result: Result<(), String> = (|| {
            // 3.0.0（L-11 审计修复）：与 open_vault 同款认证冷却 —— 当前密码验证
            // 不再无限制速（口令复用场景的在线猜测面收敛）
            state.check_auth_cooldown()?;
            let key_data = load_key_file(&key_file_path)?;
            let cleared: Result<(), String> = (|| {
                let mut guard = lock_vault(state)?;
                let vault = guard.as_mut().ok_or("保险柜未打开")?;
                // 3.0.1（F2）：二因子分区的验证响应由后端现场挑战硬件
                let yk = session_yk_response(vault)?;
                vault
                    .clear_duress_mark_on(
                        &target_alias,
                        &target_password,
                        key_data.as_deref(),
                        yk.as_ref(),
                    )
                    .map_err(|e| e.to_string())
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            cleared
        })();
        target_password.as_mut_str().zeroize();
        result
    })
    .await
}

/// 3.0.0：胁迫状态查询（当前分区是否带标记 + 分区总数；不触碰标记本身）。
#[tauri::command]
pub async fn get_duress_status(app: AppHandle) -> Result<serde_json::Value, String> {
    run_blocking(&app, "get_duress_status", move |state| {
        let guard = lock_vault(state)?;
        let vault = guard.as_ref().ok_or("保险柜未打开")?;
        let active = vault.get_active_partition().map(|p| p.alias.clone());
        let partitions: Vec<String> = vault
            .get_partitions()
            .iter()
            .map(|p| p.alias.clone())
            .collect();
        Ok(serde_json::json!({
            "marked": vault.is_duress_marked().map_err(|e| e.to_string())?,
            "partitions": partitions,
            "active": active,
        }))
    })
    .await
}

/// 3.0.0：胁迫演练 —— 对保险柜临时副本执行完整触发流程（真实开柜 + 真实覆写），
/// 验证「其他分区条目被随机覆写、副本上仅剩胁迫分区」，副本用后 DoD 擦除。
/// 返回 { wiped: 副本上被覆写的其他分区数 }。原件零接触。
#[tauri::command]
pub async fn duress_rehearsal(
    app: AppHandle,
    mut duress_password: String,
    key_file_path: Option<String>,
) -> Result<serde_json::Value, String> {
    run_blocking(&app, "duress_rehearsal", move |state| {
        let result: Result<serde_json::Value, String> = (|| {
            // 3.0.0（L-11）：同款认证冷却（演练会真实验证胁迫密码）
            state.check_auth_cooldown()?;
            let key_data = load_key_file(&key_file_path)?;
            let rehearsal: Result<serde_json::Value, String> = (|| {
                let mut guard = lock_vault(state)?;
                let vault = guard.as_mut().ok_or("保险柜未打开")?;
                // 3.0.1（F2）：二因子分区的验证响应由后端现场挑战硬件
                let yk = session_yk_response(vault)?;
                let wiped = vault
                    .duress_rehearsal(&duress_password, key_data.as_deref(), yk.as_ref())
                    .map_err(|e| e.to_string())?;
                Ok(serde_json::json!({ "wiped": wiped }))
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            rehearsal
        })();
        duress_password.as_mut_str().zeroize();
        result
    })
    .await
}

// 3.0.1（F2 修复）：删除 `parse_yk_response` —— IPC 不再传递响应字节，
// 响应由后端 `compute_yk_response` / `session_yk_response` 现场挑战硬件获得。

/// 3.0.0（优化2）：为媒体流式预览签发令牌 —— 校验「柜已开 + 文件存在 +
/// 扩展名白名单 + 分块布局（Legacy 拒绝）」，返回登记的会话级令牌。
#[tauri::command]
pub async fn mint_media_token(app: AppHandle, vpath: String) -> Result<String, String> {
    run_blocking(&app, "mint_media_token", move |state| {
        let ext = vpath.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        let mime = media_mime(&ext).ok_or("不支持的媒体格式（仅支持常见的音视频容器）")?;
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let (size, streamable) = vault.media_file_info(&vpath).map_err(|e| e.to_string())?;
        if !streamable {
            return Err(if size == 0 {
                "空文件无法预览".into()
            } else {
                "该文件为旧版整段布局，不支持流式预览 —— 请提取后查看".into()
            });
        }
        // 签发（上限 64 个，超出丢弃最早的）
        use rand::RngCore;
        let mut tb = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut tb);
        let token: String = tb.iter().map(|b| format!("{:02x}", b)).collect();
        if let Ok(mut guard) = MEDIA_TOKENS.lock() {
            if guard.len() >= 64 {
                guard.remove(0);
            }
            guard.push((token.clone(), vpath));
        }
        let _ = mime; // MIME 在协议层按扩展名再取（路径在此不含用户可控部分）
        Ok(token)
    })
    .await
}

/// 3.0.0（优化2）：媒体流式请求处理 —— 自定义协议 `lynvault-media://` 的
/// Rust 侧。URL 路径 = `/<token>/<b64url(vpath)>`（两者均为 URL 安全字符集，
/// 无需百分号编解码）；Range 请求映射到分块解密，明文内存占用 = 请求窗口。
/// 安全：令牌随会话签发/作废；扩展名白名单；分块布局校验；响应 no-store
///（禁止 WebView 磁盘缓存，维持「明文不落盘」承诺）。
pub fn media_stream_response(
    app: &AppHandle,
    request: &tauri::http::Request<Vec<u8>>,
) -> tauri::http::Response<Vec<u8>> {
    // L4（审计修复）：接入 catch() 纪律（panic 兜底为 500，与其余命令一致）
    match catch("media_stream", || media_stream_inner(app, request)) {
        Ok(resp) => resp,
        Err(e) => {
            log::warn!("媒体流式请求处理失败（区间已脱敏）: {}", e);
            tauri::http::Response::builder()
                .status(500)
                .body(Vec::new())
                .unwrap()
        }
    }
}

fn media_stream_inner(
    app: &AppHandle,
    request: &tauri::http::Request<Vec<u8>>,
) -> Result<tauri::http::Response<Vec<u8>>, String> {
    use tauri::Manager;

    let not_found = || {
        Ok(tauri::http::Response::builder()
            .status(404)
            .body(Vec::new())
            .unwrap())
    };
    if request.method() != "GET" {
        return not_found();
    }
    // 解析路径：<token>/<b64url(vpath)> —— vpath 以令牌登记为准（不信任 URL）
    let path = request.uri().path().trim_start_matches('/');
    let Some((token, _b64)) = path.split_once('/') else {
        return not_found();
    };
    let vpath = {
        let guard = match MEDIA_TOKENS.lock() {
            Ok(g) => g,
            Err(_) => return not_found(),
        };
        match guard.iter().find(|(t, _)| ct_eq_str(t, token)) {
            Some((_, v)) => v.clone(),
            None => return not_found(),
        }
    };
    let ext = vpath.rsplit('.').next().unwrap_or("");
    let Some(mime) = media_mime(ext) else {
        return not_found();
    };
    // 3.0.1（F13）：并发闸 —— 满载直接 404，不排队
    let _media_slot = match MediaSlot::try_acquire() {
        Some(s) => s,
        None => return not_found(),
    };

    let state = app.state::<AppState>();
    let mut guard = match state.vault.lock() {
        Ok(g) => g,
        Err(_) => return not_found(),
    };
    let vault = match guard.as_mut() {
        Some(v) => v,
        None => return not_found(),
    };
    let (file_size, streamable) = match vault.media_file_info(&vpath) {
        Ok(v) => v,
        Err(_) => return not_found(),
    };
    if !streamable {
        return not_found();
    }

    // Range 解析（缺省视为 bytes=0-）；窗口封顶 16 MiB
    let range = request
        .headers()
        .get("range")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("bytes="))
        .unwrap_or("0-");
    const WINDOW: u64 = 16 * 1024 * 1024;
    let (start, mut end) = if let Some(n) = range.strip_prefix('-') {
        let n: u64 = n.parse().unwrap_or(0).min(file_size);
        (file_size - n, file_size)
    } else if let Some((a, b)) = range.split_once('-') {
        let s: u64 = a.parse().unwrap_or(0).min(file_size);
        let e = b
            .parse::<u64>()
            .map(|v| v.saturating_add(1).min(file_size))
            .unwrap_or(file_size);
        (s, e.max(s))
    } else {
        (0, file_size)
    };
    end = end.min(start + WINDOW).max(start);
    if start >= end {
        return Ok(tauri::http::Response::builder()
            .status(416)
            .header("Content-Range", format!("bytes */{}", file_size))
            .body(Vec::new())
            .unwrap());
    }

    match vault.read_media_range(&vpath, start, end) {
        Ok(data) => {
            let status = if request.headers().get("range").is_some() {
                206
            } else {
                200
            };
            Ok(tauri::http::Response::builder()
                .status(status)
                .header("Content-Type", mime)
                .header("Accept-Ranges", "bytes")
                .header("Cache-Control", "no-store")
                .header(
                    "Content-Range",
                    format!("bytes {}-{}/{}", start, end - 1, file_size),
                )
                .header("Content-Length", data.len().to_string())
                .body(data)
                .unwrap())
        }
        Err(e) => {
            log::warn!("媒体流式读取失败（区间已脱敏）: {}", e);
            not_found()
        }
    }
}

/// 3.0.0：为当前分区启用硬件密钥二因子（YubiKey HMAC-SHA1 挑战-响应）。
#[tauri::command]
pub async fn enable_yubikey_2fa(
    app: AppHandle,
    mut confirm_password: String,
    key_file_path: Option<String>,
) -> Result<(), String> {
    run_blocking(&app, "enable_yubikey_2fa", move |state| {
        let result: Result<(), String> = (|| {
            // 3.0.0（L-11 审计修复）：与 open_vault 同款认证冷却 —— 当前密码验证
            // 不再无限制速（口令复用场景的在线猜测面收敛）
            state.check_auth_cooldown()?;
            let key_data = load_key_file(&key_file_path)?;
            let enabled: Result<(), String> = (|| {
                let mut guard = lock_vault(state)?;
                let vault = guard.as_mut().ok_or("保险柜未打开")?;
                // L2（审计修复）：响应**后端自算** —— 旧实现信任 IPC 提供的任意
                // 20 字节，攻击者可用自选响应启用二因子，把「口令泄露」升级为
                //「排他锁出」（主人拿真钥匙永久打不开）。现由后端对在位钥匙
                // 现场挑战（设备不在位 = 明确报错，启用二因子必须持有实体钥匙）。
                let salt = vault.yubikey_challenge_salt().map_err(|e| e.to_string())?;
                let yk = compute_yk_response(&salt)?;
                vault
                    .enable_yubikey_2fa(&confirm_password, key_data.as_deref(), &yk)
                    .map_err(|e| e.to_string())
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            enabled
        })();
        confirm_password.as_mut_str().zeroize();
        result
    })
    .await
}

/// 3.0.0：解除当前分区的硬件密钥二因子（需验证响应证明持有钥匙）。
#[tauri::command]
pub async fn disable_yubikey_2fa(
    app: AppHandle,
    mut confirm_password: String,
    key_file_path: Option<String>,
) -> Result<(), String> {
    run_blocking(&app, "disable_yubikey_2fa", move |state| {
        let result: Result<(), String> = (|| {
            // 3.0.0（L-11 审计修复）：与 open_vault 同款认证冷却 —— 当前密码验证
            // 不再无限制速（口令复用场景的在线猜测面收敛）
            state.check_auth_cooldown()?;
            let key_data = load_key_file(&key_file_path)?;
            let disabled: Result<(), String> = (|| {
                let mut guard = lock_vault(state)?;
                let vault = guard.as_mut().ok_or("保险柜未打开")?;
                // L2（审计修复）：解除同样后端自算响应 —— 持有实体钥匙是
                //「启用」与「解除」的同一必要条件
                let salt = vault.yubikey_challenge_salt().map_err(|e| e.to_string())?;
                let yk = compute_yk_response(&salt)?;
                vault
                    .disable_yubikey_2fa(&confirm_password, key_data.as_deref(), &yk)
                    .map_err(|e| e.to_string())
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            disabled
        })();
        confirm_password.as_mut_str().zeroize();
        result
    })
    .await
}

/// 3.0.0：硬件密钥状态（当前分区是否启用 + 设备是否在位）。
/// 设备探测失败不阻塞（返回 present=false），仅在 UI 展示。
#[tauri::command]
pub async fn yubikey_status(app: AppHandle) -> Result<serde_json::Value, String> {
    run_blocking(&app, "yubikey_status", move |state| {
        let guard = lock_vault(state)?;
        let enabled = match guard.as_ref() {
            Some(v) => v.is_yubikey_2fa_active().unwrap_or(false),
            None => false,
        };
        let present = crate::yubikey::probe().unwrap_or(false);
        Ok(serde_json::json!({
            "enabled": enabled,
            "present": present,
        }))
    })
    .await
}

// 3.0.1（F2 修复）：**已删除 `yubikey_challenge` 命令** —— 旧命令把 20 字节
// 硬件响应原文交给 WebView，且无认证、无限速、不消费（CWE-306/294）：
// 被攻陷的 WebView 可对任意本地 `.lyt` 路径无限次取响应，使第二因子退化为
// 对文件快照静态可重放的秘密，同时构成不限速硬件 oracle 与文件存在性探测。
// 响应现在只在 open_vault / change_password / 胁迫命令 / 启用解除二因子的
// 后端路径内由 `compute_yk_response` / `session_yk_response` 现场挑战获得。

/// 2.8.0：移动文件/文件夹到目标目录（跨目录移动只改索引，不重加密）。
/// 2.8.1（性能）：走 vault-core 批量 API —— 单次 load/save，N 项一次索引落盘
///（旧实现每项一次完整保存：9 次 fsync + 8×索引体积写放大）。
/// 返回 { ok, fail, errors }。
#[tauri::command]
pub async fn move_items(
    app: AppHandle,
    vpaths: Vec<String>,
    dest_folder: String,
) -> Result<serde_json::Value, String> {
    run_blocking(&app, "move_items", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let dest_norm = vault_core::Index::normalize_vpath(&dest_folder)
            .filter(|p| vault_core::Index::validate_vpath(p))
            .ok_or_else(|| "目标目录非法".to_string())?;
        let mut mgr = vault.get_index_manager().map_err(|e| e.to_string())?;
        let (ok, fail, errors) = mgr
            .move_items(&vpaths, &dest_norm)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "ok": ok, "fail": fail, "errors": errors }))
    })
    .await
}

/// 2.8.0：列出当前分区全部文件夹（移动选择器用）。
#[tauri::command]
pub async fn list_all_folders(app: AppHandle) -> Result<Vec<String>, String> {
    run_blocking(&app, "list_all_folders", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.list_all_folders().map_err(|e| e.to_string())
    })
    .await
}

/// 2.8.0：按文件名 / vpath 搜索（大小写不敏感子串，文件夹在前）。
#[tauri::command]
pub async fn search_files(
    app: AppHandle,
    query: String,
    limit: Option<u32>,
) -> Result<Vec<vault_core::SearchHit>, String> {
    run_blocking(&app, "search_files", move |state| {
        // 2.8.2（L11）：查询长度上限 —— 无界查询随每次击键对全索引做
        // 大小写折叠扫描，超长串白白消耗 CPU
        if query.chars().count() > 256 {
            return Err("搜索词过长（上限 256 字符）".into());
        }
        // 2.8.1：search_files 改为 &self 借用缓存（免 clone），只读守卫即可
        let guard = lock_vault(state)?;
        let vault = guard.as_ref().ok_or("保险柜未打开")?;
        let limit = limit.unwrap_or(200).clamp(1, 1000) as usize;
        Ok(vault.search_files(&query, limit))
    })
    .await
}

/// 2.8.0：读取保险柜内部审计日志（链式 HMAC 保护，倒序，最新在前）。
#[tauri::command]
pub async fn get_audit_log(
    app: AppHandle,
    limit: Option<u32>,
) -> Result<Vec<serde_json::Value>, String> {
    run_blocking(&app, "get_audit_log", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let limit = limit.unwrap_or(500).clamp(1, 5000) as usize;
        let entries = vault.get_audit_entries();
        Ok(entries
            .iter()
            .rev()
            .take(limit)
            .map(|e| serde_json::json!({ "ts": e.ts, "event": e.event }))
            .collect())
    })
    .await
}

/// 2.8.0：全库完整性体检 —— 逐文件解密校验 GCM 认证标签（只读）。
/// 过程经 `integrity-progress` 事件向前端汇报进度。
#[tauri::command]
pub async fn verify_vault_integrity(app: AppHandle) -> Result<serde_json::Value, String> {
    let app2 = app.clone();
    run_blocking(&app, "verify_vault_integrity", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 2.8.1（性能）：进度事件按时间节流（≥100ms 一个）—— 旧实现每文件
        // 一个 IPC 事件，10k 文件 = 1 万事件轰炸 WebView 造成秒级卡顿。
        // Cell 保证闭包仍是 Fn（verify_integrity 的进度回调约束）。
        let last_emit = std::cell::Cell::new(Instant::now() - Duration::from_millis(200));
        let (total, broken) = vault
            .verify_integrity(Some(move |done: usize, total: usize, current: &str| {
                if last_emit.get().elapsed() >= Duration::from_millis(100) {
                    last_emit.set(Instant::now());
                    let _ = app2.emit(
                        "integrity-progress",
                        serde_json::json!({ "done": done, "total": total, "current": current }),
                    );
                }
            }))
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "total": total, "broken": broken }))
    })
    .await
}

/// 2.8.0：读取保险柜头部锁定区的失败尝试计数（开锁前提示用，无需密码）。
/// 2.8.2：async 化（同 check_vault_file —— 文件 I/O 不进主线程）。
#[tauri::command]
pub async fn get_lock_info(path: String) -> Result<serde_json::Value, String> {
    // 3.0.0（M-1）：UNC / 设备路径守卫（读取头部也是文件打开）
    ensure_local_path(&path)?;
    // 3.0.1（F9 修复）：扩展名门 + 失败统一泛化 —— 旧实现对任意本地路径
    // 区分「BadMagic / 版本不支持 / 成功」三类结果，是被攻陷 WebView 的
    // 免认证本地文件类型探测原语
    let lower = path.to_ascii_lowercase();
    if !lower.ends_with(".lyt") && !lower.ends_with(".vault") {
        return Err("无法读取保险柜信息".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        catch("get_lock_info", || {
            let info = vault_core::read_lock_info(Path::new(&path))
                .map_err(|_| "无法读取保险柜信息".to_string())?;
            Ok(serde_json::json!({
                "failedCount": info.failed_count,
                "locked": info.locked,
                "lockUntilEpoch": info.lock_until_epoch,
            }))
        })
    })
    .await
    .map_err(|e| format!("后台任务失败: {}", e))?
}

/// 2.8.0：读取当前设置（enabled=false 表示未启用持久化，settings 字段为默认值）。
/// 2.8.2：async 化（文件 I/O 不进主线程）。
#[tauri::command]
pub async fn get_settings() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        catch("get_settings", || match crate::settings::load_active() {
            // 3.0.1（F9 修复）：不再返回配置文件绝对路径 —— 它泄露安装/
            // 配置目录布局，且前端无功能性依赖
            Some((_, s)) => Ok(serde_json::json!({
                "enabled": true,
                "settings": serde_json::to_value(&s).map_err(|e| e.to_string())?,
            })),
            None => Ok(serde_json::json!({
                "enabled": false,
                "settings": serde_json::to_value(crate::settings::Settings::default())
                    .map_err(|e| e.to_string())?,
            })),
        })
    })
    .await
    .map_err(|e| format!("后台任务失败: {}", e))?
}

/// 2.8.0：启用设置持久化（写入用户选择的位置；已启用时保留现有值迁移到新位置）。
/// 2.8.2：async 化。
#[tauri::command]
pub async fn enable_persistence(app: AppHandle, location: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        catch("enable_persistence", || {
            let loc = match location.as_str() {
                "portable" => crate::settings::ConfigLocation::Portable,
                "appdata" => crate::settings::ConfigLocation::AppData,
                _ => return Err("未知的配置位置".into()),
            };
            // 3.0.0：全新配置（此前未持久化）的窗口尺寸按主显示器自适应写入 ——
            // 与「还原默认」/ 启动兜底 / 前端 adaptiveWindowSize 同一公式；
            // 已有配置迁移到新位置时保留用户既有尺寸
            let existing = crate::settings::load_active();
            let mut s = existing
                .as_ref()
                .map(|(_, s)| s.clone())
                .unwrap_or_default();
            if existing.is_none() {
                if let Ok(Some(m)) = app.primary_monitor() {
                    let scale = m.scale_factor();
                    let (w, h) = crate::settings::adaptive_window_size(
                        m.size().width as f64 / scale,
                        m.size().height as f64 / scale,
                    );
                    s.window_width = w;
                    s.window_height = h;
                }
            }
            let path = crate::settings::save_to(loc, &s)?;
            Ok(path.to_string_lossy().to_string())
        })
    })
    .await
    .map_err(|e| format!("后台任务失败: {}", e))?
}

/// 2.8.0：关闭持久化（删除当前生效的配置文件）。
/// 2.8.2：async 化。
#[tauri::command]
pub async fn disable_persistence(app: AppHandle) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        catch("disable_persistence", || {
            let path = crate::settings::delete_active()?;
            // 3.0.0：关闭持久化即整体回到默认态 —— 防截屏（默认开启）由后端立即
            // 恢复；主题 / 窗口尺寸 / 自动锁定由前端在成功返回后即时应用
            if !crate::apply_anti_screenshot(&app, true) {
                log::warn!("关闭持久化后恢复防截屏默认开启失败（重启后仍会按默认值生效）");
            }
            Ok(path.to_string_lossy().to_string())
        })
    })
    .await
    .map_err(|e| format!("后台任务失败: {}", e))?
}

/// 2.8.0：保存设置（要求已启用持久化）。防截屏开关即时生效。
#[tauri::command]
pub async fn save_settings(app: AppHandle, settings: serde_json::Value) -> Result<(), String> {
    let app2 = app.clone();
    run_blocking(&app, "save_settings", move |_state| {
        let s: crate::settings::Settings =
            serde_json::from_value(settings).map_err(|e| format!("设置格式无效: {}", e))?;
        let s = s.sanitized();
        let path = crate::settings::active_config_path()
            .ok_or("未启用持久化，请先在设置中启用后再修改")?;
        crate::settings::save_at(&path, &s)?;
        // 防截屏开关即时生效（主题 / 自动锁定时长由前端即时应用）。
        // 2.8.1：应用失败向上传播 —— 旧实现静默吞掉，用户切开关失败也显示成功
        if !crate::apply_anti_screenshot(&app2, s.anti_screenshot) {
            return Err(
                "设置已写入，但防截屏开关应用失败（系统可能不支持，重启后仍以保存值为准）".into(),
            );
        }
        Ok(())
    })
    .await
}

/// 2.8.0：系统锁屏 / 睡眠 / 注销触发的自动关闭（system_events 调用）。
/// 关闭会话 + 停止剪贴板保护 + 通知前端回到启动弹窗。
/// 仅 Windows 的 system_events 模块调用，非 Windows 平台静默保留。
#[cfg_attr(not(windows), allow(dead_code))]
pub fn system_lock_vault(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    catch("system_lock_vault", || {
        let mut guard = lock_vault(&state)?;
        if let Some(v) = guard.as_mut() {
            v.close();
        }
        *guard = None;
        // 3.0.1（F16）：锁定同样是会话结束点 —— 媒体令牌一并作废
        clear_media_tokens();
        Ok(())
    })?;
    crate::clipboard_guard::stop();
    let _ = app.emit("vault-locked", ());
    Ok(())
}

// ───────────────── 启动检测：扫描目录下的保险柜文件 ─────────────────

/// 扫描指定目录下（非递归）的 .lyt / .vault 文件，返回文件名列表（按修改时间倒序）。
/// 用于启动时的快速打开弹窗。
///
/// `dir` 参数只支持 Tauri 路径变量占位符：`$DESKTOP` / `$DOCUMENT` /
/// `$DOWNLOAD` / `$HOME`，由后端解析为实际目录。
/// 3.0.1（F11 整理）：删除「绝对路径：直接使用」的过时说明 —— 该分支已在
/// 3.0.0 L1 审计修复中移除（任意目录扫描是保险柜清单枚举原语）。
///
/// 2.4.1（P0-1）：目录扫描移入阻塞线程池（网络驱动器/大目录不会冻结 UI）。
#[tauri::command]
pub async fn scan_vault_files(
    app: AppHandle,
    dir: String,
) -> Result<Vec<serde_json::Value>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        catch("scan_vault_files", || {
            // 解析 Tauri 路径变量占位符。
            // 3.0.0（M-1 审计修复）：占位符白名单 —— 任意目录参数等于给攻陷方一张
            //「磁盘上有哪些保险柜」的完整清单（路径 + mtime + 大小）—— 只放行
            // 四个既定扫描位置。L1（审计修复）：删除绝对路径分支 —— 该分支无
            // 前端调用方（「打开其他保险柜」走前端系统对话框），是被攻陷
            // WebView 的任意目录保险柜清单枚举原语，属纯攻击面死代码。
            // 3.0.0（Tauri 2）：api::path → AppHandle::path()（Result 语义，失败视为目录不存在）
            let resolved_dir = match dir.as_str() {
                "$DESKTOP" => app.path().desktop_dir().ok(),
                "$DOCUMENT" => app.path().document_dir().ok(),
                "$DOWNLOAD" => app.path().download_dir().ok(),
                "$HOME" => app.path().home_dir().ok(),
                _ => return Err("不支持的扫描目录（仅允许系统常用位置）".into()),
            };
            let dir_path = match resolved_dir {
                Some(p) => p,
                None => return Ok(Vec::new()),
            };
            if !dir_path.is_dir() {
                return Ok(Vec::new());
            }
            let mut entries: Vec<(std::path::PathBuf, std::time::SystemTime, u64)> = Vec::new();
            for entry in std::fs::read_dir(&dir_path).map_err(|e| e.to_string())? {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let path = entry.path();
                // 仅扫描普通文件，跳过符号链接防止被利用
                let meta = match std::fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if meta.file_type().is_symlink() {
                    continue;
                }
                if !meta.file_type().is_file() {
                    continue;
                }
                // 后缀检查：.lyt 或 .vault（兼容旧版）
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                if ext != "lyt" && ext != "vault" {
                    continue;
                }
                // N6 修复：验证 magic bytes，避免误识别其他工具的同后缀文件
                // （如 HashiCorp Vault、1Password 等）
                if !vault_core::is_vault_file(&path) {
                    continue;
                }
                let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                entries.push((path, mtime, meta.len()));
            }
            // 按修改时间倒序（最新在前）
            entries.sort_by_key(|e| std::cmp::Reverse(e.1)); // 2.8.1：修改时间倒序
            let result = entries
                .into_iter()
                .map(|(p, mtime, size)| {
                    let name = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();
                    let mtime_secs = mtime
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    serde_json::json!({
                        "path": p.to_string_lossy().to_string(),
                        "name": name,
                        "mtime": mtime_secs,
                        "size": size,
                    })
                })
                .collect();
            Ok(result)
        })
    })
    .await
    .map_err(|e| format!("后台任务失败: {}", e))?
}

// ───────────────── 提取全部文件 ─────────────────

/// 检查提取全部文件时目标子文件夹是否已存在（供前端预检覆盖提示）。
/// 2.4.1（P1-16）：返回结构化对象 { exists, dest_name, dest_path }
/// 2.8.2（H2）：两段式流程的预检 —— 核验令牌但**不消费**（最终提取才焚）。
#[tauri::command]
pub async fn check_extract_all_dest(
    app: AppHandle,
    dest_parent_folder: String,
    token: Option<String>,
) -> Result<serde_json::Value, String> {
    run_blocking(&app, "check_extract_all_dest", move |state| {
        let guard = lock_vault(state)?;
        let vault = guard.as_ref().ok_or("保险柜未打开")?;
        let vault_path = vault.get_path().ok_or("保险柜未打开或路径不可用")?;
        let safe_stem = export_stem(vault_path);

        // 2.8.2（H2）：预检不焚令牌（peek）；2.8.2（M7）：保护目录拒绝
        let token = token.ok_or("缺少对话框令牌（请通过「提取全部」对话框选择目标）")?;
        peek_dialog_paths(&token)?;
        reject_protected_dest(Path::new(&dest_parent_folder))?;

        let dest_parent = Path::new(&dest_parent_folder);
        let dest_root = dest_parent.join(&safe_stem);
        let exists = dest_root.exists();
        Ok(serde_json::json!({
            "exists": exists,
            "dest_name": safe_stem,
            "dest_path": dest_root.to_string_lossy(),
        }))
    })
    .await
}

/// 提取保险柜内所有文件到指定父目录下。
/// 会自动创建一个与保险柜文件同名（去掉 .lyt/.vault 后缀）的子文件夹作为容器。
/// 2.4.1（P1-16）：返回结构化对象 { ok, fail, dest } 供前端显示结果。
/// 2.8.2（H2/M7）：目标目录必须来自后端对话框令牌 + 保护目录拒绝。
#[tauri::command]
pub async fn extract_all_files(
    app: AppHandle,
    dest_parent_folder: String,
    token: Option<String>,
) -> Result<serde_json::Value, String> {
    let app_progress = app.clone();
    run_blocking(&app, "extract_all_files", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;

        let vault_path = vault.get_path().ok_or("保险柜未打开或路径不可用")?;
        let safe_stem = export_stem(vault_path);

        // 2.8.2（H2）：最终提取消费令牌；2.8.2（M7）：保护目录拒绝
        let token = token.ok_or("缺少对话框令牌（请通过「提取全部」对话框选择目标）")?;
        verify_dialog_paths(&token, std::slice::from_ref(&dest_parent_folder))?;
        reject_protected_dest(Path::new(&dest_parent_folder))?;

        let dest_parent = Path::new(&dest_parent_folder);
        std::fs::create_dir_all(dest_parent).map_err(|e| e.to_string())?;
        let dest_parent_abs =
            std::fs::canonicalize(dest_parent).map_err(|_| "目标目录无法访问".to_string())?;
        let dest_root = dest_parent_abs.join(&safe_stem);

        // 校验 dest_root 在 dest_parent_abs 下（防路径遍历）— 先校验再创建
        if !dest_root.starts_with(&dest_parent_abs) {
            return Err("目标路径非法".into());
        }
        std::fs::create_dir_all(&dest_root).map_err(|e| e.to_string())?;

        // 委托给 vault-core：单次 load_index，避免 O(n²) 重复加载
        // 2.4.1（P0-5）：overwrite=true —— 前端已通过 check_extract_all_dest 预检
        // 并向用户确认覆盖；旧实现确认「覆盖」后仍用 create_new 拒绝，大批失败
        let (ok, fail, errors) = vault
            .extract_all_files(
                &dest_root,
                true,
                Some(&make_progress_fn(
                    app_progress,
                    "extract-progress",
                    "filesDone",
                    "filesTotal",
                )),
                None,
            )
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "ok": ok,
            "fail": fail,
            "dest": dest_root.to_string_lossy(),
            "errors": errors,
        }))
    })
    .await
}

// ───────────────── 文件类型图标（Windows 系统图标） ─────────────────
// 对齐 1.3.4 的 QFileIconProvider 行为：按扩展名读取系统注册的文件类型图标。
// 仅 Windows 实现；其他平台返回空串，前端 fallback 到 emoji 图标。
//
// 2.3.0 防卡死注意点：
// - 用 SHGFI_USEFILEATTRIBUTES + 伪文件名 "dummy.ext" 查询，**不访问真实文件**
//   （不走磁盘/网络，网络驱动器也不会挂起）；
// - 命令为 async + spawn_blocking：Shell/GDI 调用在阻塞线程池执行，
//   不占用 Tauri 主线程（UI 线程），大量文件渲染时界面不会冻结。
#[tauri::command]
pub async fn get_file_icon(ext: String) -> Result<String, String> {
    // 清洗扩展名：去前导点、转小写、截断长度
    let ext = ext.trim_start_matches('.').to_lowercase();
    if ext.is_empty()
        || ext.len() > 32
        || !ext
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Ok(String::new());
    }
    #[cfg(windows)]
    {
        let ext_clone = ext.clone();
        match tauri::async_runtime::spawn_blocking(move || read_windows_file_icon(&ext_clone)).await
        {
            Ok(Ok(b64)) => Ok(b64),
            Ok(Err(e)) => {
                log::warn!("get_file_icon 失败 ({}): {}", ext, e);
                Ok(String::new())
            }
            Err(e) => {
                log::warn!("get_file_icon 任务失败: {}", e);
                Ok(String::new())
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = ext;
        Ok(String::new())
    }
}

#[cfg(windows)]
fn read_windows_file_icon(ext: &str) -> Result<String, String> {
    // 注：HICON/DestroyIcon/DeleteDC/HDC 在模块级导入（IconGuard/DcGuard 需要），
    // 此处只导入本函数内使用的项。
    use base64::{engine::general_purpose::STANDARD, Engine};
    use windows::Win32::Graphics::Gdi::{
        GetDIBits, SelectObject, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS,
    };
    use windows::Win32::UI::Shell::{
        SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_SMALLICON, SHGFI_USEFILEATTRIBUTES,
    };
    use windows::Win32::UI::WindowsAndMessaging::{GetIconInfo, ICONINFO};

    // 构造伪文件名 "dummy.ext" 让 Shell 按扩展名查图标
    let filename: Vec<u16> = format!("dummy.{}\0", ext).encode_utf16().collect();

    let mut shfi = SHFILEINFOW::default();
    let flags = SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES;
    let hinst = unsafe {
        SHGetFileInfoW(
            windows::core::PCWSTR(filename.as_ptr()),
            // FILE_ATTRIBUTE_NORMAL 位于 Win32::Storage::FileSystem（windows 0.57）
            windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
            Some(&mut shfi),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            flags,
        )
    };
    // windows 0.57 中 SHGetFileInfoW 返回 usize（成功时非 0，失败为 0）；
    // SHFILEINFOW.hIcon 是 HICON（非 Option）。
    // 3.0.0（i686 修复）：SHFILEINFOW 在 32 位目标上是 packed 结构 —— 对字段
    // 创建引用（is_invalid() 需要 &self）是未对齐引用（E0793 硬错误）；
    // 按值拷贝到局部变量（编译器生成 unaligned read）后再判断。
    let hicon: HICON = shfi.hIcon;
    if hinst == 0 || hicon.is_invalid() {
        return Err("SHGetFileInfoW 未返回图标".into());
    }

    // 取图标位图信息
    let mut icon_info = ICONINFO::default();
    let ok = unsafe { GetIconInfo(hicon, &mut icon_info) };
    let _guard = IconGuard(hicon); // 确保最后 DestroyIcon

    if ok.is_err() {
        return Err("GetIconInfo 失败".into());
    }
    // 2.8.1：RAII 接管两个位图，覆盖本函数所有早退路径
    let _bm_color = BitmapGuard(icon_info.hbmColor);
    let _bm_mask = BitmapGuard(icon_info.hbmMask);

    // 优先用 color bitmap
    let hbm = icon_info.hbmColor;
    if hbm.is_invalid() {
        return Err("图标无 color bitmap".into());
    }

    // 创建兼容 DC 并选入位图
    let hdc = unsafe { windows::Win32::Graphics::Gdi::CreateCompatibleDC(None) };
    if hdc.is_invalid() {
        return Err("CreateCompatibleDC 失败".into());
    }
    let _dc_guard = DcGuard(hdc);
    let old_bm = unsafe { SelectObject(hdc, hbm) };

    // 准备 BITMAPINFO 请求 RGBA。
    // 注意（2.3.0 修复）：尺寸查询（lpvBits=NULL）时 biBitCount 必须为 0，
    // 否则 GetDIBits 返回 0 + ERROR_INVALID_PARAMETER(87)，图标读取失败。
    let mut bi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: 0,
            biHeight: 0,
            biPlanes: 1,
            biBitCount: 0,
            biCompression: 0, // BI_RGB
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        bmiColors: [Default::default()],
    };

    // 第一次调用取尺寸
    let n = unsafe { GetDIBits(hdc, hbm, 0, 0, None, &mut bi, DIB_RGB_COLORS) };
    if n == 0 {
        return Err("GetDIBits 取尺寸失败".into());
    }
    let w = bi.bmiHeader.biWidth;
    let h = bi.bmiHeader.biHeight; // 正数表示 bottom-up
    if w <= 0 || h == 0 {
        return Err("图标尺寸无效".into());
    }
    let abs_h = h.unsigned_abs();
    // 3.0.1（F14）：尺寸来自 Windows 图标缓存而非攻击者字节，但
    // overflow-checks=true 下无界乘法仍是 panic 面 —— checked + 合理上限。
    let img_size: usize = (w as usize)
        .checked_mul(abs_h as usize)
        .and_then(|v| v.checked_mul(4))
        .filter(|v| *v <= 512 * 1024 * 1024)
        .ok_or("图标尺寸异常")?;
    let mut pixels: Vec<u8> = vec![0u8; img_size];

    // 第二次调用取像素
    let n2 = unsafe {
        GetDIBits(
            hdc,
            hbm,
            0,
            abs_h,
            Some(pixels.as_mut_ptr() as *mut _),
            &mut bi,
            DIB_RGB_COLORS,
        )
    };
    if n2 == 0 {
        return Err("GetDIBits 取像素失败".into());
    }

    // 恢复 DC 旧对象
    unsafe {
        SelectObject(hdc, old_bm);
    }

    // BGRA → RGBA，并处理 bottom-up / top-down
    let bottom_up = h > 0;
    let mut rgba: Vec<u8> = Vec::with_capacity(pixels.len());
    if bottom_up {
        // 行序反转
        let row = (w as usize) * 4;
        for y in (0..abs_h as usize).rev() {
            let off = y * row;
            for px in pixels[off..off + row].chunks_exact(4) {
                rgba.push(px[2]); // R
                rgba.push(px[1]); // G
                rgba.push(px[0]); // B
                rgba.push(px[3]); // A
            }
        }
    } else {
        for px in pixels.chunks_exact(4) {
            rgba.push(px[2]);
            rgba.push(px[1]);
            rgba.push(px[0]);
            rgba.push(px[3]);
        }
    }

    // PNG 编码
    let img =
        image::RgbaImage::from_raw(w as u32, abs_h as u32, rgba).ok_or("构造 RgbaImage 失败")?;
    let mut png_buf = std::io::Cursor::new(Vec::with_capacity(4096));
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut png_buf, image::ImageFormat::Png)
        .map_err(|e| format!("PNG 编码失败: {}", e))?;

    Ok(format!(
        "data:image/png;base64,{}",
        STANDARD.encode(png_buf.into_inner())
    ))
}

// windows 0.57：HICON 位于 Win32::UI::WindowsAndMessaging（0.58+ 才移到 Foundation），
// 模块级导入供下方 RAII guard 使用
#[cfg(windows)]
use windows::Win32::Graphics::Gdi::{DeleteDC, DeleteObject, HBITMAP, HDC};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, HICON};

/// 2.8.1：GetIconInfo 返回的 hbmColor / hbmMask 都必须 DeleteObject ——
/// 旧实现两者都不释放（每次查询新扩展名泄漏 2 个 GDI 句柄）。
#[cfg(windows)]
struct BitmapGuard(HBITMAP);
#[cfg(windows)]
impl Drop for BitmapGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteObject(windows::Win32::Graphics::Gdi::HGDIOBJ(self.0 .0));
        }
    }
}

#[cfg(windows)]
struct IconGuard(HICON);
#[cfg(windows)]
impl Drop for IconGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = DestroyIcon(self.0);
        }
    }
}

#[cfg(windows)]
struct DcGuard(HDC);
#[cfg(windows)]
impl Drop for DcGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteDC(self.0);
        }
    }
}

// State 引用保留（run_blocking 内部经由 Manager::state 获取，此导入防止误删告警）
#[allow(unused)]
fn _state_type_check(_: State<AppState>) {}
