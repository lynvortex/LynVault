use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::sync::Mutex;
use tauri::State;
use vault_core::Vault;

/// 全局状态：保险柜实例
pub struct AppState {
    vault: Mutex<Option<Vault>>,
}

impl AppState {
    pub fn new() -> Self {
        Self { vault: Mutex::new(None) }
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
            Err(format!("操作失败 ({})", label))
        }
    }
}

// ───────────────── 保险柜生命周期 ─────────────────

#[tauri::command]
pub fn create_vault(
    state: State<AppState>,
    path: String,
    password: String,
    key_file_path: Option<String>,
) -> Result<String, String> {
    catch("create_vault", || {
        let key_data = load_key_file(&key_file_path)?;
        Vault::create(Path::new(&path), &password, key_data.as_deref())
            .map_err(|e| e.to_string())?;

        // 创建后自动打开
        let mut vault = Vault::default();
        vault.open_and_authenticate(Path::new(&path), &password, key_data.as_deref())
            .map_err(|e| e.to_string())?;
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        *guard = Some(vault);
        Ok("保险柜创建成功".into())
    })
}

#[tauri::command]
pub fn open_vault(
    state: State<AppState>,
    path: String,
    password: String,
    key_file_path: Option<String>,
) -> Result<usize, String> {
    catch("open_vault", || {
        let key_data = load_key_file(&key_file_path)?;
        let mut vault = Vault::default();
        let idx = vault.open_and_authenticate(Path::new(&path), &password, key_data.as_deref())
            .map_err(|e| e.to_string())?;
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
        vault.import_file(Path::new(&src_path), &dest_vpath).map_err(|e| e.to_string())
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
        let mut count = 0;
        for vp in &vpaths {
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
pub fn add_partition(state: State<AppState>, alias: String, password: String, key_file_path: Option<String>) -> Result<(), String> {
    catch("add_partition", || {
        let key_data = load_key_file(&key_file_path)?;
        let mut guard = state.vault.lock().map_err(|e| e.to_string())?;
        let vault = guard.as_mut().ok_or("保险柜未打开")?;
        vault.add_partition(&alias, &password, key_data.as_deref()).map_err(|e| e.to_string())
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
        if !root.is_dir() {
            return Err("不是有效的文件夹".into());
        }
        // 递归收集所有文件
        let files = collect_files_recursive(root).map_err(|e| e.to_string())?;
        if files.is_empty() {
            let _ = std::fs::remove_dir_all(root);
            return Ok("空文件夹已删除".into());
        }
        let path_refs: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
        vault_core::wipe::dod_erase_files(&path_refs, None)
            .map_err(|e| e.to_string())?;
        // 删除空目录结构
        let _ = std::fs::remove_dir_all(root);
        Ok(format!("已安全删除 {} 个源文件（DoD 7-pass）", files.len()))
    })
}

fn collect_files_recursive(dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
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
        Some(p) => Ok(Some(std::fs::read(p).map_err(|e| e.to_string())?)),
        None => Ok(None),
    }
}
