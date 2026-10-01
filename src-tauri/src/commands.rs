use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager, State};
use vault_core::Vault;
use zeroize::Zeroize;

// ───────────────── 全局状态 ─────────────────

/// 全局状态：保险柜实例 + 认证频率限制
pub struct AppState {
    vault: Mutex<Option<Vault>>,
    last_auth_attempt: Mutex<Option<Instant>>,
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

fn lock_cooldown<'a>(state: &'a AppState) -> Result<std::sync::MutexGuard<'a, Option<Instant>>, String> {
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
            eprintln!("[LynVault] PANIC in {}: {}", label, msg);
            Err(format!("内部错误 ({}): {}", label, msg))
        }
    }
}

/// 2.4.1 新增（P0-1）：把重 I/O 命令丢到阻塞线程池执行，避免冻结 UI 主线程。
/// 闭包在阻塞线程中拿到 AppState 引用（锁语义与旧同步命令完全一致）。
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
) -> Result<(), String> {
    run_blocking(&app, "create_vault", move |state| {
        state.check_auth_cooldown()?;
        // 2.3.0 修复：密码 / 密钥文件在所有路径（含 load_key_file 失败、操作失败）上都零化，
        // 旧实现 `?` 提前返回会跳过零化。
        let result: Result<(), String> = (|| {
            let key_data = load_key_file(&key_file_path)?;
            let created: Result<(), String> = (|| {
                // 2.4.1（P2-20）：Vault::create 成功即进入已解锁会话
                // （旧流程 create 后再 open_and_authenticate 要重复 8 次 Argon2id）
                let mut vault = Vault::default();
                vault.create(Path::new(&path), &password, key_data.as_deref())
                    .map_err(|e| e.to_string())?;
                let mut guard = lock_vault(state)?;
                *guard = Some(vault);
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

#[tauri::command]
pub async fn open_vault(
    app: AppHandle,
    path: String,
    mut password: String,
    key_file_path: Option<String>,
) -> Result<usize, String> {
    run_blocking(&app, "open_vault", move |state| {
        state.check_auth_cooldown()?;
        let result: Result<usize, String> = (|| {
            let key_data = load_key_file(&key_file_path)?;
            let opened: Result<usize, String> = (|| {
                let mut vault = Vault::default();
                let idx = vault.open_and_authenticate(Path::new(&path), &password, key_data.as_deref())
                    .map_err(|e| e.to_string())?;
                let mut guard = lock_vault(state)?;
                *guard = Some(vault);
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
        Ok(())
    })
    .await
}

// ───────────────── 文件浏览 ─────────────────

/// 2.4.1（P1-16）：返回结构化数组而非手工序列化的 JSON 字符串，
/// 免去前端 JSON.parse；数组语义与旧版一致。
#[tauri::command]
pub async fn list_folder(app: AppHandle, folder: String) -> Result<Vec<serde_json::Value>, String> {
    run_blocking(&app, "list_folder", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let index = vault.load_index().map_err(|e| e.to_string())?;

        // 2.3.0 修复：归一化目录参数（去掉结尾 '/'，根目录保持 "/"），
        // 避免用户在路径框输入 "dir/" 时返回空列表
        // 2.5.1 修复：改用 Index::normalize_vpath 统一归一化 —— 旧实现只去掉
        // 结尾 '/'，路径框输入 "foo//bar"、"///" 等仍会因不匹配返回空列表，
        // 与其他模块（导入/删除/提取）的归一化规则不一致
        let folder_norm = vault_core::Index::normalize_vpath(&folder)
            .filter(|p| vault_core::Index::validate_vpath(p))
            .ok_or_else(|| "无效的目录路径".to_string())?;

        let mut items: Vec<serde_json::Value> = Vec::new();

        for (vpath, _) in &index.folders {
            if vpath.is_empty() || *vpath == "/" { continue; }
            let parent = vpath.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            let display_parent = if parent.is_empty() { "/" } else { parent };
            if display_parent == folder_norm {
                let name = vpath.rsplit_once('/').map(|(_, n)| n).unwrap_or(vpath);
                if !name.is_empty() {
                    items.push(serde_json::json!({
                        "name": name, "vpath": vpath, "type": "folder"
                    }));
                }
            }
        }

        for (vpath, meta) in &index.files {
            let dir = vpath.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            let display_dir = if dir.is_empty() { "/" } else { dir };
            if display_dir == folder_norm {
                items.push(serde_json::json!({
                    "name": meta.name, "vpath": vpath, "type": "file", "size": meta.size
                }));
            }
        }

        items.sort_by(|a, b| {
            let ta = a["type"].as_str().unwrap_or("");
            let tb = b["type"].as_str().unwrap_or("");
            if ta == tb {
                a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or(""))
            } else if ta == "folder" { std::cmp::Ordering::Less }
            else { std::cmp::Ordering::Greater }
        });

        Ok(items)
    })
    .await
}

// ───────────────── 文件导入 ─────────────────

#[tauri::command]
pub async fn import_file(
    app: AppHandle,
    src_path: String,
    dest_vpath: String,
) -> Result<(), String> {
    run_blocking(&app, "import_file", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let src = Path::new(&src_path);
        // 由文件名 + 目标目录构造完整虚拟路径，使文件放入当前浏览的目录
        let filename = src.file_name()
            .ok_or_else(|| "无法获取文件名".to_string())?
            .to_string_lossy().to_string();
        let full_vpath = format!("{}/{}", dest_vpath.trim_end_matches('/'), filename);
        vault.import_file(src, &full_vpath).map_err(|e| e.to_string())
    })
    .await
}

/// 2.4.1 新增（P0-2）：批量导入文件。
/// 单次索引加密落盘替代 N 次（旧版前端循环 import_file 时每个文件都全量重写索引 + 10 次 fsync）。
/// 返回 { ok, fail } 供前端展示结果。
#[tauri::command]
pub async fn import_files_batch(
    app: AppHandle,
    src_paths: Vec<String>,
    dest_base: String,
) -> Result<serde_json::Value, String> {
    run_blocking(&app, "import_files_batch", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let (ok, fail) = vault.import_files_batch(&src_paths, &dest_base)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "ok": ok, "fail": fail }))
    })
    .await
}

#[tauri::command]
pub async fn import_folder(
    app: AppHandle,
    src_folder: String,
    dest_base: String,
) -> Result<(), String> {
    run_blocking(&app, "import_folder", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.import_folder(Path::new(&src_folder), &dest_base).map_err(|e| e.to_string())
    })
    .await
}

/// 拖放导入：自动判断路径是文件还是文件夹，批量导入到 dest_base 下
/// 2.4.1（P1-16）：返回结构化对象 { summary, files, folders, errors? } 供前端提示安全删除源文件
#[tauri::command]
pub async fn import_dropped_paths(
    app: AppHandle,
    paths: Vec<String>,
    dest_base: String,
) -> Result<serde_json::Value, String> {
    run_blocking(&app, "import_dropped_paths", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;

        let mut imported_files: Vec<String> = Vec::new();
        let mut imported_folders: Vec<String> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        // 2.4.1 新功能：拖入的 .lyt/.vault 是保险柜文件而非待加密文件 —— 分流处理，
        // 由前端走「打开保险柜」流程，这里直接跳过（不导入、不报错）。
        let (vault_files, normal_paths): (Vec<String>, Vec<String>) = paths
            .into_iter()
            .partition(|p| {
                let path = Path::new(p);
                let ext = path.extension()
                    .and_then(|e| e.to_str())
                    .map(|s| s.eq_ignore_ascii_case("lyt") || s.eq_ignore_ascii_case("vault"))
                    .unwrap_or(false);
                ext && vault_core::is_vault_file(path)
            });

        for p in &normal_paths {
            let path = Path::new(p);
            if path.is_dir() {
                match vault.import_folder(path, &dest_base) {
                    Ok(_) => imported_folders.push(p.clone()),
                    Err(e) => errors.push(format!("文件夹 '{}': {}", p, e)),
                }
            } else if path.is_file() {
                let filename = path.file_name()
                    .unwrap_or_default().to_string_lossy().to_string();
                let full_vpath = format!("{}/{}", dest_base.trim_end_matches('/'), filename);
                match vault.import_file(path, &full_vpath) {
                    Ok(_) => imported_files.push(p.clone()),
                    Err(e) => errors.push(format!("文件 '{}': {}", p, e)),
                }
            } else {
                errors.push(format!("跳过 '{}': 不是有效文件或目录", p));
            }
        }

        let mut parts = Vec::new();
        if !imported_files.is_empty() { parts.push(format!("{} 个文件", imported_files.len())); }
        if !imported_folders.is_empty() { parts.push(format!("{} 个文件夹", imported_folders.len())); }
        let summary = if parts.is_empty() { "未导入任何内容".into() }
                      else { format!("拖放导入完成：{}", parts.join("，")) };

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
            result["summary"] = serde_json::json!(
                format!("{}\n以下项目导入失败：\n{}", summary, errors.join("\n"))
            );
        }
        Ok(result)
    })
    .await
}

// ───────────────── 文件提取 ─────────────────

#[tauri::command]
pub async fn extract_file(
    app: AppHandle,
    vpath: String,
    dest_folder: String,
) -> Result<(), String> {
    run_blocking(&app, "extract_file", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 2.4.1（P0-5）：overwrite=true 显式覆盖（旧实现固定 create_new，
        // 重复提取同名文件会报错；语义改为「最后提取的生效」）
        vault.extract_file(&vpath, Path::new(&dest_folder), true).map_err(|e| e.to_string())
    })
    .await
}

#[tauri::command]
pub async fn extract_files(
    app: AppHandle,
    vpaths: Vec<String>,
    dest_folder: String,
) -> Result<usize, String> {
    run_blocking(&app, "extract_files", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 2.3.0 修复：委托给 vault-core 批量提取（单次 load_index + extract_file_inner，
        // 避免对每个文件重复 load_index 的 O(n²) 退化）
        let (ok, _fail) = vault.extract_files_batch(&vpaths, Path::new(&dest_folder))
            .map_err(|e| e.to_string())?;
        Ok(ok)
    })
    .await
}

// ───────────────── 文件/文件夹删除 ─────────────────

/// 2.4.1：vault-core 的批量删除现在同时展开文件夹并返回 (文件数, 文件夹数)，
/// 结构化返回 { files, folders } 供 UI 精确反馈。
#[tauri::command]
pub async fn delete_files(app: AppHandle, vpaths: Vec<String>) -> Result<serde_json::Value, String> {
    run_blocking(&app, "delete_files", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 委托给 vault-core 的批量删除方法：一次 load + 批量 DoD 7-pass 擦除 + 一次 save
        let (files, folders) = vault.secure_delete_files_batch(&vpaths)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "files": files, "folders": folders }))
    })
    .await
}

#[tauri::command]
pub async fn delete_folder(app: AppHandle, vpath: String) -> Result<(), String> {
    run_blocking(&app, "delete_folder", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.delete_folder(&vpath).map_err(|e| e.to_string())
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
        if is_folder { im.rename_folder(&old_vpath, &new_name) }
        else { im.rename_file(&old_vpath, &new_name) }
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
        if !alias.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ' ') {
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
                vault.add_partition(&alias, &password, key_data.as_deref()).map_err(|e| e.to_string())
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
        let parts: Vec<serde_json::Value> = vault.get_partitions().iter().enumerate().map(|(i, p)| {
            serde_json::json!({ "index": i, "alias": p.alias })
        }).collect();
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
        vault.defragment_vault(None::<fn(usize)>).map_err(|e| e.to_string())?;
        Ok("碎片整理完成".into())
    })
    .await
}

#[tauri::command]
pub async fn destroy_vault(app: AppHandle) -> Result<(), String> {
    run_blocking(&app, "destroy_vault", move |state| {
        let mut guard = lock_vault(state)?;
        let vault_path = guard.as_ref()
            .and_then(|v| v.get_path().map(|p| p.to_path_buf()))
            .ok_or("保险柜未打开或路径不可用")?;

        // 2.5.1 修复（TOCTOU，关键）：旧实现是「symlink_metadata 检查 → 打开验证
        // → 立刻 drop → 关闭会话 → 按路径重新打开擦除」，检查与擦除之间存在
        // 竞态窗口：同用户目录写权限的攻击者可在窗口内把保险柜文件替换为指向
        // 受害者文件的硬链接/符号链接，使 7-pass 覆写作用于受害者文件。
        //
        // 现在整个销毁流程锚定在**一次打开、全程持有**的句柄上：
        // 1. 以 FILE_FLAG_OPEN_REPARSE_POINT / O_NOFOLLOW 打开（句柄必然指向
        //    文件自身而非重解析目标）；
        // 2. 通过**句柄**元数据原子性地确认非符号链接（不再依赖按路径的
        //    symlink_metadata 检查）；
        // 3. 关闭保险柜会话（drop Vault 自身持有的句柄）；
        // 4. 擦除与删除全部经由该句柄（Windows 下 delete-on-close 不经路径）。
        #[cfg(windows)]
        let file = {
            use std::os::windows::fs::OpenOptionsExt;
            // 0x00200000 = FILE_FLAG_OPEN_REPARSE_POINT
            std::fs::OpenOptions::new().write(true).read(true)
                .custom_flags(0x00200000)
                .open(&vault_path)
                .map_err(|e| format!("无法打开保险柜文件: {}", e))?
        };
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new().write(true).read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&vault_path)
                .map_err(|e| format!("无法打开保险柜文件: {}", e))?
        };
        // 非 Windows / Unix 平台（未官方支持）退化为普通打开
        #[cfg(not(any(windows, unix)))]
        let file = std::fs::OpenOptions::new().write(true).read(true)
            .open(&vault_path)
            .map_err(|e| format!("无法打开保险柜文件: {}", e))?;
        // 句柄级符号链接验证（Unix 上 O_NOFOLLOW 已在打开时拒绝，无需重复）
        #[cfg(windows)]
        {
            let ftype = file.metadata()
                .map_err(|e| format!("无法读取保险柜文件元数据: {}", e))?
                .file_type();
            if ftype.is_symlink() {
                return Err("拒绝销毁符号链接".into());
            }
        }

        // 关闭会话（drop Vault 内部持有的文件句柄，落盘审计）
        if let Some(v) = guard.as_mut() {
            v.close();
        }
        drop(guard);

        // 基于已持有句柄完成 DoD 7-pass 擦除 + 删除（全程不按路径重开）
        vault_core::wipe::dod_erase_handle(file, &vault_path).map_err(|e| e.to_string())
    })
    .await
}

// ───────────────── 文件信息与预览 ─────────────────

/// 2.4.1（P1-16）：返回结构化对象
#[tauri::command]
pub async fn get_file_info(app: AppHandle, vpath: String) -> Result<serde_json::Value, String> {
    run_blocking(&app, "get_file_info", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let index = vault.load_index().map_err(|e| e.to_string())?;
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
            index.files.get(&vpath)
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
pub async fn preview_office_file(app: AppHandle, vpath: String) -> Result<String, String> {
    run_blocking(&app, "preview_office_file", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 2.5.1 修复（OOM）：旧实现直接 load_file_data（内部上限 256 MiB），
        // 而 load_file_content 的预览路径有 64 MiB 上限 —— 同为「预览」，
        // Office 路径却允许整读 256 MiB 再做解压解析，恶意/超大文件可瞬间
        // 占用数百 MB 内存。现与预览路径统一 64 MiB 上限。
        let size = {
            let index = vault.load_index().map_err(|e| e.to_string())?;
            index.files.get(&vpath)
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
        let text = vault_core::office::extract_office_text(&data, filename);
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
        let data = base64::engine::general_purpose::STANDARD
            .decode(content_b64.as_bytes())
            .map_err(|e| format!("内容编码无效: {}", e))?;
        if data.len() as u64 > MAX_PREVIEW_SIZE {
            vault_core::wipe::secure_wipe_vec(data);
            return Err("内容过大：文本编辑上限 64 MB".into());
        }
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let result = vault.update_file_content(&vpath, &data).map_err(|e| e.to_string());
        vault_core::wipe::secure_wipe_vec(data);
        result
    })
    .await
}

// ───────────────── 辅助函数 ─────────────────

fn load_key_file(path: &Option<String>) -> Result<Option<Vec<u8>>, String> {
    match path {
        Some(p) => {
            let data = std::fs::read(p).map_err(|e| e.to_string())?;
            Ok(Some(data))
        }
        None => Ok(None),
    }
}

// ───────────────── .lyt 文件自动识别（2.4.1 新功能） ─────────────────

/// 检查一个路径是否为 LynVault 保险柜文件（扩展名 + magic bytes 双重校验）。
/// 供前端拖放 .lyt 到窗口时自动识别并直接进入密码输入流程，
/// 避免把保险柜文件本身误当作待加密文件导入另一个保险柜。
#[tauri::command]
pub fn check_vault_file(path: String) -> Result<bool, String> {
    catch("check_vault_file", || {
        let p = Path::new(&path);
        let ext = p.extension()
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

// ───────────────── 启动检测：扫描目录下的保险柜文件 ─────────────────

/// 扫描指定目录下（非递归）的 .lyt / .vault 文件，返回文件名列表（按修改时间倒序）。
/// 用于启动时的快速打开弹窗。
///
/// `dir` 参数支持两种形式：
///   1. Tauri 路径变量占位符：`$DESKTOP` / `$DOCUMENT` / `$DOWNLOAD` / `$HOME`
///      由后端解析为实际路径
///   2. 绝对路径：直接使用
///
/// 2.4.1（P0-1）：目录扫描移入阻塞线程池（网络驱动器/大目录不会冻结 UI）。
#[tauri::command]
pub async fn scan_vault_files(dir: String) -> Result<Vec<serde_json::Value>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        catch("scan_vault_files", || {
            // 解析 Tauri 路径变量占位符
            let resolved_dir = match dir.as_str() {
                "$DESKTOP" => tauri::api::path::desktop_dir(),
                "$DOCUMENT" => tauri::api::path::document_dir(),
                "$DOWNLOAD" => tauri::api::path::download_dir(),
                "$HOME" => tauri::api::path::home_dir(),
                _ => Some(std::path::PathBuf::from(&dir)),
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
                let entry = match entry { Ok(e) => e, Err(_) => continue };
                let path = entry.path();
                // 仅扫描普通文件，跳过符号链接防止被利用
                let meta = match std::fs::symlink_metadata(&path) { Ok(m) => m, Err(_) => continue };
                if meta.file_type().is_symlink() { continue; }
                if !meta.file_type().is_file() { continue; }
                // 后缀检查：.lyt 或 .vault（兼容旧版）
                let ext = path.extension()
                    .and_then(|e| e.to_str())
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                if ext != "lyt" && ext != "vault" { continue; }
                // N6 修复：验证 magic bytes，避免误识别其他工具的同后缀文件
                // （如 HashiCorp Vault、1Password 等）
                if !vault_core::is_vault_file(&path) { continue; }
                let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                entries.push((path, mtime, meta.len()));
            }
            // 按修改时间倒序（最新在前）
            entries.sort_by(|a, b| b.1.cmp(&a.1));
            let result = entries.into_iter().map(|(p, mtime, size)| {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                let mtime_secs = mtime.duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                serde_json::json!({
                    "path": p.to_string_lossy().to_string(),
                    "name": name,
                    "mtime": mtime_secs,
                    "size": size,
                })
            }).collect();
            Ok(result)
        })
    })
    .await
    .map_err(|e| format!("后台任务失败: {}", e))?
}

// ───────────────── 提取全部文件 ─────────────────

/// 检查提取全部文件时目标子文件夹是否已存在（供前端预检覆盖提示）。
/// 2.4.1（P1-16）：返回结构化对象 { exists, dest_name, dest_path }
#[tauri::command]
pub async fn check_extract_all_dest(
    app: AppHandle,
    dest_parent_folder: String,
) -> Result<serde_json::Value, String> {
    run_blocking(&app, "check_extract_all_dest", move |state| {
        let guard = lock_vault(state)?;
        let vault = guard.as_ref().ok_or("保险柜未打开")?;
        let vault_path = vault.get_path().ok_or("保险柜未打开或路径不可用")?;
        let stem = vault_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("LynVault_Export")
            .to_string();
        let safe_stem: String = stem.chars()
            .filter(|c| !matches!(c, '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
            .collect();
        let safe_stem = if safe_stem.trim().is_empty() { "LynVault_Export".to_string() } else { safe_stem };

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
#[tauri::command]
pub async fn extract_all_files(
    app: AppHandle,
    dest_parent_folder: String,
) -> Result<serde_json::Value, String> {
    run_blocking(&app, "extract_all_files", move |state| {
        let mut guard = lock_vault(state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;

        // 解析保险柜文件名（去掉后缀）作为根文件夹名
        let vault_path = vault.get_path().ok_or("保险柜未打开或路径不可用")?;
        let stem = vault_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("LynVault_Export")
            .to_string();

        // 安全化文件夹名：禁止路径分隔符与控制字符
        let safe_stem: String = stem.chars()
            .filter(|c| !matches!(c, '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
            .collect();
        let safe_stem = if safe_stem.trim().is_empty() { "LynVault_Export".to_string() } else { safe_stem };

        let dest_parent = Path::new(&dest_parent_folder);
        std::fs::create_dir_all(dest_parent).map_err(|e| e.to_string())?;
        let dest_parent_abs = std::fs::canonicalize(dest_parent)
            .map_err(|_| "目标目录无法访问".to_string())?;
        let dest_root = dest_parent_abs.join(&safe_stem);

        // 校验 dest_root 在 dest_parent_abs 下（防路径遍历）— 先校验再创建
        if !dest_root.starts_with(&dest_parent_abs) {
            return Err("目标路径非法".into());
        }
        std::fs::create_dir_all(&dest_root).map_err(|e| e.to_string())?;

        // 委托给 vault-core：单次 load_index，避免 O(n²) 重复加载
        // 2.4.1（P0-5）：overwrite=true —— 前端已通过 check_extract_all_dest 预检
        // 并向用户确认覆盖；旧实现确认「覆盖」后仍用 create_new 拒绝，大批失败
        let (ok, fail) = vault.extract_all_files(&dest_root, true).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "ok": ok,
            "fail": fail,
            "dest": dest_root.to_string_lossy(),
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
    if ext.is_empty() || ext.len() > 32 || !ext.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Ok(String::new());
    }
    #[cfg(windows)]
    {
        let ext_clone = ext.clone();
        match tauri::async_runtime::spawn_blocking(move || read_windows_file_icon(&ext_clone)).await {
            Ok(Ok(b64)) => Ok(b64),
            Ok(Err(e)) => {
                eprintln!("[LynVault] get_file_icon 失败 ({}): {}", ext, e);
                Ok(String::new())
            }
            Err(e) => {
                eprintln!("[LynVault] get_file_icon 任务失败: {}", e);
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
    use windows::Win32::Graphics::Gdi::{
        GetDIBits, SelectObject, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS,
    };
    use windows::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_SMALLICON, SHGFI_USEFILEATTRIBUTES};
    use windows::Win32::UI::WindowsAndMessaging::{GetIconInfo, ICONINFO};
    use base64::{engine::general_purpose::STANDARD, Engine};

    // 构造伪文件名 "dummy.ext" 让 Shell 按扩展名查图标
    let filename: Vec<u16> = format!("dummy.{}\0", ext)
        .encode_utf16()
        .collect();

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
    // SHFILEINFOW.hIcon 是 HICON（非 Option），用 is_invalid() 判断
    if hinst == 0 || shfi.hIcon.is_invalid() {
        return Err("SHGetFileInfoW 未返回图标".into());
    }
    let hicon: HICON = shfi.hIcon;

    // 取图标位图信息
    let mut icon_info = ICONINFO::default();
    let ok = unsafe { GetIconInfo(hicon, &mut icon_info) };
    let _guard = IconGuard(hicon); // 确保最后 DestroyIcon

    if ok.is_err() {
        return Err("GetIconInfo 失败".into());
    }

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
    let n = unsafe {
        GetDIBits(hdc, hbm, 0, 0, None, &mut bi, DIB_RGB_COLORS)
    };
    if n == 0 {
        return Err("GetDIBits 取尺寸失败".into());
    }
    let w = bi.bmiHeader.biWidth;
    let h = bi.bmiHeader.biHeight; // 正数表示 bottom-up
    if w <= 0 || h == 0 {
        return Err("图标尺寸无效".into());
    }
    let abs_h = h.unsigned_abs();
    let img_size = (w as usize) * (abs_h as usize) * 4;
    let mut pixels: Vec<u8> = vec![0u8; img_size];

    // 第二次调用取像素
    let n2 = unsafe {
        GetDIBits(hdc, hbm, 0, abs_h, Some(pixels.as_mut_ptr() as *mut _), &mut bi, DIB_RGB_COLORS)
    };
    if n2 == 0 {
        return Err("GetDIBits 取像素失败".into());
    }

    // 恢复 DC 旧对象
    unsafe { SelectObject(hdc, old_bm); }

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
    let img = image::RgbaImage::from_raw(w as u32, abs_h as u32, rgba)
        .ok_or("构造 RgbaImage 失败")?;
    let mut png_buf = std::io::Cursor::new(Vec::with_capacity(4096));
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut png_buf, image::ImageFormat::Png)
        .map_err(|e| format!("PNG 编码失败: {}", e))?;

    Ok(format!("data:image/png;base64,{}", STANDARD.encode(png_buf.into_inner())))
}

// windows 0.57：HICON 位于 Win32::UI::WindowsAndMessaging（0.58+ 才移到 Foundation），
// 模块级导入供下方 RAII guard 使用
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, HICON};
#[cfg(windows)]
use windows::Win32::Graphics::Gdi::{DeleteDC, HDC};

#[cfg(windows)]
struct IconGuard(HICON);
#[cfg(windows)]
impl Drop for IconGuard {
    fn drop(&mut self) {
        unsafe { let _ = DestroyIcon(self.0); }
    }
}

#[cfg(windows)]
struct DcGuard(HDC);
#[cfg(windows)]
impl Drop for DcGuard {
    fn drop(&mut self) {
        unsafe { let _ = DeleteDC(self.0); }
    }
}

// State 引用保留（run_blocking 内部经由 Manager::state 获取，此导入防止误删告警）
#[allow(unused)]
fn _state_type_check(_: State<AppState>) {}
