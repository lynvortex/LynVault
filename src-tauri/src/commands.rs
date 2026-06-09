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

impl AppState {
    pub fn new() -> Self {
        Self {
            vault: Mutex::new(None),
            last_auth_attempt: Mutex::new(None),
        }
    }

    /// 检查认证冷却（防止暴力破解绕过 per-instance 限制）
    fn check_auth_cooldown(&self) -> Result<(), String> {
        let mut guard = self.last_auth_attempt.lock().map_err(|_| "内部错误".to_string())?;
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
        let key_data = load_key_file(&key_file_path)?;
        Vault::create(Path::new(&path), &password, key_data.as_deref())
            .map_err(|e| e.to_string())?;

        let mut vault = Vault::default();
        vault.open_and_authenticate(Path::new(&path), &password, key_data.as_deref())
            .map_err(|e| e.to_string())?;
        if let Some(kd) = key_data {
            vault_core::wipe::secure_wipe_vec(kd);
        }
        // 零化密码堆内存
        password.as_mut_str().zeroize();
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        *guard = Some(vault);
        Ok("保险柜创建成功".into())
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
        let key_data = load_key_file(&key_file_path)?;
        let mut vault = Vault::default();
        let idx = vault.open_and_authenticate(Path::new(&path), &password, key_data.as_deref())
            .map_err(|e| e.to_string())?;
        if let Some(kd) = key_data {
            vault_core::wipe::secure_wipe_vec(kd);
        }
        password.as_mut_str().zeroize();
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        *guard = Some(vault);
        Ok(idx)
    })
}

#[tauri::command]
pub fn close_vault(state: State<AppState>) -> Result<(), String> {
    catch("close_vault", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        *guard = None;
        Ok(())
    })
}

// ───────────────── 文件浏览 ─────────────────

#[tauri::command]
pub fn list_folder(state: State<AppState>, folder: String) -> Result<String, String> {
    catch("list_folder", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let index = vault.load_index().map_err(|e| e.to_string())?;

        let mut items: Vec<serde_json::Value> = Vec::new();

        for (vpath, _) in &index.folders {
            if vpath.is_empty() || *vpath == "/" { continue; }
            let parent = vpath.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            let display_parent = if parent.is_empty() { "/" } else { parent };
            if display_parent == folder {
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
            if display_dir == folder {
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
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
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
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
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
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
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
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.extract_file(&vpath, Path::new(&dest_folder)).map_err(|e| e.to_string())
    })
}

#[tauri::command]
pub fn extract_files(state: State<AppState>, vpaths: Vec<String>, dest_folder: String) -> Result<usize, String> {
    catch("extract_files", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let dest = Path::new(&dest_folder);

        let index = vault.load_index().map_err(|e| e.to_string())?;

        // 展开 vpaths：文件直接加入，文件夹递归展开为其下所有文件
        let mut file_vpaths = Vec::new();
        for vp in &vpaths {
            if index.files.contains_key(vp) {
                file_vpaths.push(vp.clone());
            } else if index.folders.contains_key(vp) {
                let prefix = format!("{}/", vp.trim_end_matches('/'));
                for fv in index.files.keys() {
                    if fv.starts_with(&prefix) || fv == vp {
                        file_vpaths.push(fv.clone());
                    }
                }
            }
        }

        let mut count = 0;
        for vp in &file_vpaths {
            vault.extract_file(vp, dest).map_err(|e| e.to_string())?;
            count += 1;
        }
        Ok(count)
    })
}

// ───────────────── 文件/文件夹删除 ─────────────────

#[tauri::command]
pub fn delete_files(state: State<AppState>, vpaths: Vec<String>) -> Result<usize, String> {
    catch("delete_files", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let mut count = 0;
        for vp in &vpaths {
            vault.secure_delete_file(vp).map_err(|e| e.to_string())?;
            count += 1;
        }
        Ok(count)
    })
}

#[tauri::command]
pub fn delete_folder(state: State<AppState>, vpath: String) -> Result<(), String> {
    catch("delete_folder", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.delete_folder(&vpath).map_err(|e| e.to_string())
    })
}

// ───────────────── 新建文件夹 ─────────────────

#[tauri::command]
pub fn new_folder(state: State<AppState>, vpath: String) -> Result<(), String> {
    catch("new_folder", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let mut im = vault.get_index_manager().map_err(|e| e.to_string())?;
        im.add_folder(&vpath).map_err(|e| e.to_string())
    })
}

// ───────────────── 重命名 ─────────────────

#[tauri::command]
pub fn rename_item(state: State<AppState>, old_vpath: String, new_name: String, is_folder: bool) -> Result<(), String> {
    catch("rename_item", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
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
        let key_data = load_key_file(&key_file_path)?;
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        let result = vault.add_partition(&alias, &password, key_data.as_deref()).map_err(|e| e.to_string());
        if let Some(kd) = key_data {
            vault_core::wipe::secure_wipe_vec(kd);
        }
        password.as_mut_str().zeroize();
        result
    })
}

#[tauri::command]
pub fn remove_partition(state: State<AppState>, alias: String) -> Result<(), String> {
    catch("remove_partition", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.remove_partition(&alias).map_err(|e| e.to_string())
    })
}

#[tauri::command]
pub fn list_partitions(state: State<AppState>) -> Result<String, String> {
    catch("list_partitions", || {
        let guard = state.vault.lock().map_err(|e| e.to_string())?;
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
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.defragment_vault(None::<fn(usize)>).map_err(|e| e.to_string())?;
        Ok("碎片整理完成".into())
    })
}

// ───────────────── 审计日志 ─────────────────

#[tauri::command]
pub fn get_audit_log(state: State<AppState>) -> Result<String, String> {
    catch("get_audit_log", || {
        let guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_ref().ok_or("保险柜未打开")?;
        let entries = vault.get_audit_entries();
        serde_json::to_string(&entries).map_err(|e| e.to_string())
    })
}

// ───────────────── 销毁保险柜 ─────────────────

#[tauri::command]
pub fn destroy_vault(state: State<AppState>) -> Result<(), String> {
    catch("destroy_vault", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault_path = guard.as_ref()
            .and_then(|v| v.get_path().map(|p| p.to_path_buf()))
            .ok_or("保险柜未打开或路径不可用")?;
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
        *guard = None;
        vault_core::wipe::dod_erase(&vault_path, None).map_err(|e| e.to_string())?;
        Ok(())
    })
}

// ───────────────── 文件信息 ─────────────────

#[tauri::command]
pub fn get_file_info(state: State<AppState>, vpath: String) -> Result<String, String> {
    catch("get_file_info", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
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

// ───────────────── 安全删除源文件（导入后使用） ─────────────────

#[tauri::command]
pub fn secure_delete_source_files(
    paths: Vec<String>,
) -> Result<String, String> {
    catch("secure_delete_source_files", || {
        // 拒绝符号链接
        for p in &paths {
            let meta = std::fs::symlink_metadata(p)
                .map_err(|e| format!("无法访问 '{}': {}", p, e))?;
            if meta.file_type().is_symlink() {
                return Err(format!("拒绝删除符号链接: '{}'", p));
            }
        }
        let path_refs: Vec<&Path> = paths.iter().map(|p| Path::new(p.as_str())).collect();
        vault_core::wipe::dod_erase_files(&path_refs, None)
            .map_err(|e| e.to_string())?;
        Ok(format!("已安全删除 {} 个源文件（DoD 7-pass）", paths.len()))
    })
}

#[tauri::command]
pub fn secure_delete_source_folder(
    folder: String,
) -> Result<String, String> {
    catch("secure_delete_source_folder", || {
        let root = Path::new(&folder);
        let root_meta = std::fs::symlink_metadata(root)
            .map_err(|_| "无法访问文件夹".to_string())?;
        if root_meta.file_type().is_symlink() {
            return Err("拒绝删除符号链接".into());
        }
        if !root.is_dir() {
            return Err("不是有效的文件夹".into());
        }
        let files = collect_files_recursive(root).map_err(|e| e.to_string())?;
        if files.is_empty() {
            let _ = std::fs::remove_dir_all(root);
            return Ok("空文件夹已删除".into());
        }
        let path_refs: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
        vault_core::wipe::dod_erase_files(&path_refs, None)
            .map_err(|e| e.to_string())?;
        let _ = std::fs::remove_dir_all(root);
        Ok(format!("已安全删除 {} 个源文件（DoD 7-pass）", files.len()))
    })
}

fn collect_files_recursive(dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if path.is_dir() {
            result.extend(collect_files_recursive(&path)?);
        } else {
            result.push(path);
        }
    }
    Ok(result)
}

// ───────────────── 加载文件内容（安全查看用） ─────────────────

#[tauri::command]
pub fn load_file_content(state: State<AppState>, vpath: String) -> Result<Vec<u8>, String> {
    catch("load_file_content", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.load_file_data(&vpath).map_err(|e| e.to_string())
    })
}

// ───────────────── Office 文档预览 ─────────────────

#[tauri::command]
pub fn preview_office_file(state: State<AppState>, vpath: String) -> Result<String, String> {
    catch("preview_office_file", || {
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
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
