use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::State;
use vault_core::Vault;
use zeroize::Zeroize;

/// 全局状态：保险柜实例 + 认证频率限制
pub struct AppState {
    vault: Mutex<Option<Vault>>,
    last_auth_attempt: Mutex<Option<Instant>>,
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

// ───────────────── 保险柜生命周期 ─────────────────

#[tauri::command]
pub fn create_vault(
    state: State<AppState>,
    path: String,
    mut password: String,
    key_file_path: Option<String>,
) -> Result<String, String> {
    catch("create_vault", || {
        state.check_auth_cooldown()?;
        // 2.3.0 修复：密码 / 密钥文件在所有路径（含 load_key_file 失败、操作失败）上都零化，
        // 旧实现 `?` 提前返回会跳过零化。
        let result: Result<String, String> = (|| {
            let key_data = load_key_file(&key_file_path)?;
            let created: Result<(), String> = (|| {
                Vault::create(Path::new(&path), &password, key_data.as_deref())
                    .map_err(|e| e.to_string())?;
                let mut vault = Vault::default();
                vault.open_and_authenticate(Path::new(&path), &password, key_data.as_deref())
                    .map_err(|e| e.to_string())?;
                let mut guard = lock_vault(&state)?;
                *guard = Some(vault);
                Ok(())
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            created.map(|_| "保险柜创建成功".into())
        })();
        password.as_mut_str().zeroize();
        result
    })
}

#[tauri::command]
pub fn open_vault(
    state: State<AppState>,
    path: String,
    mut password: String,
    key_file_path: Option<String>,
) -> Result<usize, String> {
    catch("open_vault", || {
        state.check_auth_cooldown()?;
        let result: Result<usize, String> = (|| {
            let key_data = load_key_file(&key_file_path)?;
            let opened: Result<usize, String> = (|| {
                let mut vault = Vault::default();
                let idx = vault.open_and_authenticate(Path::new(&path), &password, key_data.as_deref())
                    .map_err(|e| e.to_string())?;
                let mut guard = lock_vault(&state)?;
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
}

#[tauri::command]
pub fn close_vault(state: State<AppState>) -> Result<(), String> {
    catch("close_vault", || {
        let mut guard = lock_vault(&state)?;
        *guard = None;
        Ok(())
    })
}

// ───────────────── 文件浏览 ─────────────────

#[tauri::command]
pub fn list_folder(state: State<AppState>, folder: String) -> Result<String, String> {
    catch("list_folder", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let index = vault.load_index().map_err(|e| e.to_string())?;

        // 2.3.0 修复：归一化目录参数（去掉结尾 '/'，根目录保持 "/"），
        // 避免用户在路径框输入 "dir/" 时返回空列表
        let folder_norm = if folder == "/" { folder.clone() } else { folder.trim_end_matches('/').to_string() };

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

        serde_json::to_string(&items).map_err(|e| e.to_string())
    })
}

// ───────────────── 文件导入 ─────────────────

#[tauri::command]
pub fn import_file(state: State<AppState>, src_path: String, dest_vpath: String) -> Result<(), String> {
    catch("import_file", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let src = Path::new(&src_path);
        // 由文件名 + 目标目录构造完整虚拟路径，使文件放入当前浏览的目录
        let filename = src.file_name()
            .ok_or_else(|| "无法获取文件名".to_string())?
            .to_string_lossy().to_string();
        let full_vpath = format!("{}/{}", dest_vpath.trim_end_matches('/'), filename);
        vault.import_file(src, &full_vpath).map_err(|e| e.to_string())
    })
}

#[tauri::command]
pub fn import_folder(state: State<AppState>, src_folder: String, dest_base: String) -> Result<(), String> {
    catch("import_folder", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.import_folder(Path::new(&src_folder), &dest_base).map_err(|e| e.to_string())
    })
}

/// 拖放导入：自动判断路径是文件还是文件夹，批量导入到 dest_base 下
/// 返回 JSON：{ summary, files:[], folders:[] } 供前端提示安全删除源文件
#[tauri::command]
pub fn import_dropped_paths(
    state: State<AppState>,
    paths: Vec<String>,
    dest_base: String,
) -> Result<String, String> {
    catch("import_dropped_paths", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;

        let mut imported_files: Vec<String> = Vec::new();
        let mut imported_folders: Vec<String> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        for p in &paths {
            let path = std::path::Path::new(p);
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

        let result = serde_json::json!({
            "summary": summary,
            "files": imported_files,
            "folders": imported_folders,
        });

        if !errors.is_empty() {
            let mut full = result.clone();
            full["errors"] = serde_json::json!(errors);
            full["summary"] = serde_json::json!(
                format!("{}\n以下项目导入失败：\n{}", summary, errors.join("\n"))
            );
            Ok(full.to_string())
        } else {
            Ok(result.to_string())
        }
    })
}

// ───────────────── 文件提取 ─────────────────

#[tauri::command]
pub fn extract_file(state: State<AppState>, vpath: String, dest_folder: String) -> Result<(), String> {
    catch("extract_file", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.extract_file(&vpath, Path::new(&dest_folder)).map_err(|e| e.to_string())
    })
}

#[tauri::command]
pub fn extract_files(state: State<AppState>, vpaths: Vec<String>, dest_folder: String) -> Result<usize, String> {
    catch("extract_files", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 2.3.0 修复：委托给 vault-core 批量提取（单次 load_index + extract_file_inner，
        // 避免对每个文件重复 load_index 的 O(n²) 退化）
        let (ok, _fail) = vault.extract_files_batch(&vpaths, Path::new(&dest_folder))
            .map_err(|e| e.to_string())?;
        Ok(ok)
    })
}

// ───────────────── 文件/文件夹删除 ─────────────────

#[tauri::command]
pub fn delete_files(state: State<AppState>, vpaths: Vec<String>) -> Result<usize, String> {
    catch("delete_files", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        // 委托给 vault-core 的批量删除方法：一次 load + 批量 DoD 7-pass 擦除 + 一次 save
        vault.secure_delete_files_batch(&vpaths).map_err(|e| e.to_string())
    })
}

#[tauri::command]
pub fn delete_folder(state: State<AppState>, vpath: String) -> Result<(), String> {
    catch("delete_folder", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.delete_folder(&vpath).map_err(|e| e.to_string())
    })
}

// ───────────────── 新建文件夹 ─────────────────

#[tauri::command]
pub fn new_folder(state: State<AppState>, vpath: String) -> Result<(), String> {
    catch("new_folder", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let mut im = vault.get_index_manager().map_err(|e| e.to_string())?;
        im.add_folder(&vpath).map_err(|e| e.to_string())
    })
}

// ───────────────── 重命名 ─────────────────

#[tauri::command]
pub fn rename_item(state: State<AppState>, old_vpath: String, new_name: String, is_folder: bool) -> Result<(), String> {
    catch("rename_item", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let mut im = vault.get_index_manager().map_err(|e| e.to_string())?;
        if is_folder { im.rename_folder(&old_vpath, &new_name) }
        else { im.rename_file(&old_vpath, &new_name) }
        .map_err(|e| e.to_string())
    })
}

// ───────────────── 分区管理 ─────────────────

#[tauri::command]
pub fn add_partition(state: State<AppState>, alias: String, mut password: String, key_file_path: Option<String>) -> Result<(), String> {
    catch("add_partition", || {
        // 分区别名校验：只允许安全字符，防止 XSS
        if !alias.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == ' ') {
            return Err("分区别名只能包含字母、数字、下划线、短横线和空格".into());
        }
        if alias.trim().is_empty() || alias.len() > 16 {
            return Err("分区别名长度需在 1-16 字符之间".into());
        }
        // 2.3.0 修复：密码 / 密钥文件在所有路径上零化（旧实现 `?` 提前返回会跳过）
        let result: Result<(), String> = (|| {
            let key_data = load_key_file(&key_file_path)?;
            let added: Result<(), String> = (|| {
                let mut guard = lock_vault(&state)?;
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
}

#[tauri::command]
pub fn remove_partition(state: State<AppState>, alias: String) -> Result<(), String> {
    catch("remove_partition", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.remove_partition(&alias).map_err(|e| e.to_string())
    })
}

#[tauri::command]
pub fn list_partitions(state: State<AppState>) -> Result<String, String> {
    catch("list_partitions", || {
        let guard = lock_vault(&state)?;
        let vault = guard.as_ref().ok_or("保险柜未打开")?;
        let parts: Vec<serde_json::Value> = vault.get_partitions().iter().enumerate().map(|(i, p)| {
            serde_json::json!({ "index": i, "alias": p.alias })
        }).collect();
        serde_json::to_string(&parts).map_err(|e| e.to_string())
    })
}

// ───────────────── 碎片整理 ─────────────────

#[tauri::command]
pub fn defragment_vault(state: State<AppState>) -> Result<String, String> {
    catch("defragment_vault", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.defragment_vault(None::<fn(usize)>).map_err(|e| e.to_string())?;
        Ok("碎片整理完成".into())
    })
}

// ───────────────── 销毁保险柜 ─────────────────

#[tauri::command]
pub fn destroy_vault(state: State<AppState>) -> Result<(), String> {
    catch("destroy_vault", || {
        let mut guard = lock_vault(&state)?;
        let vault_path = guard.as_ref()
            .and_then(|v| v.get_path().map(|p| p.to_path_buf()))
            .ok_or("保险柜未打开或路径不可用")?;

        // C8 修复：所有平台都检查符号链接，防止销毁操作跟随符号链接删除系统文件
        let meta = std::fs::symlink_metadata(&vault_path)
            .map_err(|e| format!("无法访问保险柜文件: {}", e))?;
        if meta.file_type().is_symlink() {
            return Err("拒绝销毁符号链接".into());
        }

        // 在释放 guard 前先打开文件，缩小 TOCTOU 窗口
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let _fd = std::fs::OpenOptions::new().write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&vault_path)
                .map_err(|_| "目标文件已被符号链接替换")?;
            drop(_fd);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // 0x00200000 = FILE_FLAG_OPEN_REPARSE_POINT
            let _fd = std::fs::OpenOptions::new().write(true)
                .custom_flags(0x00200000)
                .open(&vault_path)
                .map_err(|_| "目标文件已被重解析点替换")?;
            drop(_fd);
        }
        *guard = None;
        vault_core::wipe::dod_erase(&vault_path, None).map_err(|e| e.to_string())?;

        Ok(())
    })
}

// ───────────────── 文件信息 ─────────────────

#[tauri::command]
pub fn get_file_info(state: State<AppState>, vpath: String) -> Result<String, String> {
    catch("get_file_info", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let index = vault.load_index().map_err(|e| e.to_string())?;
        if let Some(meta) = index.files.get(&vpath) {
            serde_json::to_string(&serde_json::json!({
                "name": meta.name, "size": meta.size, "vpath": vpath,
            })).map_err(|e| e.to_string())
        } else {
            Err("文件不存在".into())
        }
    })
}

// ───────────────── 加载文件内容（安全查看用） ─────────────────

#[tauri::command]
pub fn load_file_content(state: State<AppState>, vpath: String) -> Result<Vec<u8>, String> {
    catch("load_file_content", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.load_file_data(&vpath).map_err(|e| e.to_string())
    })
}

// ───────────────── Office 文档预览 ─────────────────

#[tauri::command]
pub fn preview_office_file(state: State<AppState>, vpath: String) -> Result<String, String> {
    catch("preview_office_file", || {
        let mut guard = lock_vault(&state)?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let data = vault.load_file_data(&vpath).map_err(|e| e.to_string())?;
        let filename = vpath.rsplit('/').next().unwrap_or(&vpath);
        vault_core::office::extract_office_text(&data, filename)
    })
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

// ───────────────── 启动检测：扫描目录下的保险柜文件 ─────────────────

/// 扫描指定目录下（非递归）的 .lyt / .vault 文件，返回文件名列表（按修改时间倒序）。
/// 用于启动时的快速打开弹窗。
///
/// `dir` 参数支持两种形式：
///   1. Tauri 路径变量占位符：`$DESKTOP` / `$DOCUMENT` / `$DOWNLOAD` / `$HOME`
///      由后端解析为实际路径
///   2. 绝对路径：直接使用
#[tauri::command]
pub fn scan_vault_files(dir: String) -> Result<Vec<serde_json::Value>, String> {
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
}

// ───────────────── 提取全部文件 ─────────────────

/// 检查提取全部文件时目标子文件夹是否已存在（供前端预检覆盖提示）。
/// 返回 JSON：{ exists, dest_name, dest_path }
#[tauri::command]
pub fn check_extract_all_dest(
    state: State<AppState>,
    dest_parent_folder: String,
) -> Result<String, String> {
    catch("check_extract_all_dest", || {
        let guard = lock_vault(&state)?;
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
        let result = serde_json::json!({
            "exists": exists,
            "dest_name": safe_stem,
            "dest_path": dest_root.to_string_lossy(),
        });
        Ok(result.to_string())
    })
}

/// 提取保险柜内所有文件到指定父目录下。
/// 会自动创建一个与保险柜文件同名（去掉 .lyt/.vault 后缀）的子文件夹作为容器。
/// 返回 JSON：{ ok, fail, dest } 供前端显示结果。
#[tauri::command]
pub fn extract_all_files(
    state: State<AppState>,
    dest_parent_folder: String,
) -> Result<String, String> {
    catch("extract_all_files", || {
        let mut guard = lock_vault(&state)?;
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
        let (ok, fail) = vault.extract_all_files(&dest_root).map_err(|e| e.to_string())?;
        let result = serde_json::json!({
            "ok": ok,
            "fail": fail,
            "dest": dest_root.to_string_lossy(),
        });
        Ok(result.to_string())
    })
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
