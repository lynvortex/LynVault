// ───────────────── 3.1.0 新增：备用 GUI（egui 版）─────────────────
//
// 背景：主界面前端运行在系统 WebView（Windows WebView2 / Linux webkit2gtk）
// 之上，WebView Runtime 损坏 / 缺失 / 数据目录故障时主窗口无法创建，
// 用户的保险柜明明完好却完全无法访问。本模块提供一套**不依赖 WebView**
// 的完整备用前端（egui 直接 GPU 渲染），两种触发方式：
//
// 1. `LynVault.exe --gui` —— 显式使用备用界面（日常可用）；
// 2. 主窗口创建全部降级重试失败后自动切换（main.rs）。
//
// 架构差异（相对 Tauri 主界面）：
// - 同一进程内直接调用 vault-core，**无 IPC 层** —— 主界面 commands.rs 中
//   防御被攻陷 WebView 的机制（认证冷却、对话框令牌表、拖放载荷核验、
//   错误信息泛化）在此**有意省略**：egui 是进程内可信 UI，不存在不可信
//   调用方；口令安全依靠「用后即清 + 不落日志」与主界面同一水位。
// - 功能按分期交付：一期为文件管理主链路（开柜/浏览/导入/提取/预览/编辑）；
//   3.1.1 补齐管理面（修改密码 / 分区增删 / 操作记录 / 完整性体检 / 整理 /
//   销毁）；胁迫密码、YubiKey 开关与设置持久化的图形化编辑仍待补齐
//   （与主界面功能对齐表见设计讨论）。
// - 主界面启动检测弹窗提供「GUI启动」入口：拉起 `--gui` 子进程后主窗口退出
//   （commands::launch_gui_mode），两条前端路径共用同一份 vault-core 逻辑。
//
// 借用规则：vault 会话放在 `Arc<Mutex<Option<Vault>>>` 中，**只有后台
// 工作线程持锁**，UI 线程每帧仅 `try_lock` 探测存在性 —— 避免阻塞渲染。

pub mod app;
pub mod theme;

use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use vault_core::Vault;
use zeroize::Zeroize;

/// 预览加载上限（与主界面 MAX_PREVIEW_SIZE 一致：64 MiB）
pub const PREVIEW_MAX: u64 = 64 * 1024 * 1024;
/// 文本编辑上限（与主界面一致：4 MB，超过只读）
pub const EDIT_MAX: usize = 4 * 1024 * 1024;

/// 共享保险柜会话 —— 只被后台操作线程持有/修改
pub type SharedVault = Arc<Mutex<Option<Vault>>>;

// ───────────────── 数据类型 ─────────────────

/// 文件列表条目（与主界面 ListItem 对齐）
#[derive(Clone, Debug)]
pub struct Item {
    pub name: String,
    pub vpath: String,
    pub is_folder: bool,
    pub size: Option<u64>,
}

/// 启动扫描命中（与主界面 scan_vault_files 对齐）
#[derive(Clone, Debug)]
pub struct ScannedVault {
    pub path: String,
    pub name: String,
    pub mtime: i64,
    pub size: u64,
}

/// 预览载荷（后台线程解码/解密，UI 线程只做渲染）
pub enum PreviewData {
    /// 已解码 RGBA（在线程内完成解码，避免 UI 线程卡顿）
    Image {
        name: String,
        rgba: Vec<u8>,
        size: [usize; 2],
    },
    Text {
        name: String,
        vpath: String,
        content: String,
        /// false = 非 UTF-8 / 超过编辑上限，仅可读
        editable: bool,
        note: Option<String>,
    },
    Office {
        name: String,
        text: String,
    },
    /// 无法内置预览的类型（音视频 / 压缩包 / 可执行文件等）—— 只给提示
    Notice {
        name: String,
        text: String,
    },
}

/// 分区条目（管理窗口用）
#[derive(Clone, Debug)]
pub struct PartitionRow {
    pub alias: String,
    /// 是否为当前会话所在分区（不可删除）
    pub active: bool,
    /// 是否为主分区（不可删除）
    pub primary: bool,
}

/// 操作记录条目（ts 为 epoch 秒）
#[derive(Clone, Debug)]
pub struct AuditRow {
    pub ts: f64,
    pub event: String,
}

/// 设置视图（GUI 设置窗口用；不含窗口尺寸等主界面专属项）
#[derive(Clone, Debug)]
pub struct SettingsView {
    pub autolock_minutes: u32,
    pub enabled: bool,
    pub location: Option<String>,
}

/// 后台操作完成后的结构化载荷
pub enum OpPayload {
    Summary(String),
    Listing(Vec<Item>),
    Search(Vec<vault_core::SearchHit>),
    Preview(PreviewData),
    Partitions(Vec<PartitionRow>),
    Audit(Vec<AuditRow>),
    /// 完整性体检结果（只读）
    Verify {
        total: usize,
        broken: usize,
    },
    /// 当前分区全部文件夹（移动目标选择用）
    Folders(Vec<String>),
    /// 保险柜头部锁定信息（开锁前提示）
    LockInfo {
        failed: u32,
        locked: bool,
        until: f64,
    },
    /// 硬件密钥二因子状态：(是否启用, 设备是否在位)
    Yubikey {
        enabled: bool,
        present: bool,
    },
    Settings(SettingsView),
}

/// UI 每帧轮询的操作消息
pub enum OpMsg {
    /// 文件级进度（第 done 个 / 共 total 个）
    Progress(usize, usize),
    /// 字节级进度（分块流水线）
    Bytes(u64, u64),
    Finished(Result<OpPayload, String>),
}

/// 操作类别 —— Finished 后 UI 按此路由结果处理
#[derive(Clone, Copy, PartialEq)]
pub enum OpKind {
    Open,
    Create,
    Close,
    List,
    Search,
    Import,
    NewFolder,
    Rename,
    Delete,
    Extract,
    Preview,
    SaveText,
    // 3.1.1：管理功能（改密 / 分区 / 整理 / 销毁 / 记录 / 体检）
    ChangePassword,
    ListPartitions,
    AddPartition,
    RemovePartition,
    Defrag,
    Destroy,
    Audit,
    Verify,
    // 3.1.2：补齐常用功能（移动 / 锁定提示 / 硬件密钥 / 设置）
    Move,
    ListFolders,
    LockInfo,
    YkEnable,
    YkDisable,
    YkStatus,
    SettingsLoad,
    SettingsSave,
}

/// 进行中的后台操作句柄（UI 每帧 poll）
pub struct BusyOp {
    pub kind: OpKind,
    pub label: String,
    pub rx: Receiver<OpMsg>,
}

/// 把闭包丢到后台线程执行（UI 不阻塞；进度/结果经 channel 回传）
pub fn spawn_busy<F>(kind: OpKind, label: &str, f: F) -> BusyOp
where
    F: FnOnce(Sender<OpMsg>) + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || f(tx));
    BusyOp {
        kind,
        label: label.to_string(),
        rx,
    }
}

// ───────────────── 错误映射 ─────────────────

/// VaultError → 用户可读消息。备用 GUI 是进程内可信 UI，非口令类错误
/// 直接展示细节（主界面的泛化是防被攻陷 WebView 的枚举 oracle，此处无该威胁面）。
pub fn vault_err(e: &vault_core::VaultError) -> String {
    match e {
        vault_core::VaultError::AuthFailed => "密码或密钥文件不正确".to_string(),
        vault_core::VaultError::Locked => {
            "保险柜已锁定（连续失败次数过多），请稍后再试".to_string()
        }
        vault_core::VaultError::AlreadyOpen => "保险柜已打开".to_string(),
        other => format!("操作失败：{}", other),
    }
}

// ───────────────── 启动扫描 ─────────────────

/// 常见目录（桌面/文档/下载/用户主目录）。Windows 用 SHGetKnownFolderPath
/// 拿真实路径（可能是本地化的「桌面」），其他平台用 home + 固定英文目录名启发式。
pub fn scan_candidate_dirs() -> Vec<PathBufAlias> {
    let mut dirs = Vec::new();
    #[cfg(windows)]
    {
        use windows::Win32::System::Com::CoTaskMemFree;
        use windows::Win32::UI::Shell::{
            FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_Profile,
            SHGetKnownFolderPath, KNOWN_FOLDER_FLAG,
        };
        for fid in [
            &FOLDERID_Desktop,
            &FOLDERID_Documents,
            &FOLDERID_Downloads,
            &FOLDERID_Profile,
        ] {
            // windows 0.57：三参签名，成功返回 Result<PWSTR>（调用方负责 CoTaskMemFree）
            unsafe {
                if let Ok(pwstr) = SHGetKnownFolderPath(fid, KNOWN_FOLDER_FLAG(0), None) {
                    let s = pwstr.to_string().unwrap_or_default();
                    CoTaskMemFree(Some(pwstr.as_ptr() as _));
                    if !s.is_empty() {
                        dirs.push(PathBufAlias(std::path::PathBuf::from(s)));
                    }
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            let home = std::path::PathBuf::from(home);
            for sub in ["Desktop", "Documents", "Downloads", ""] {
                let d = if sub.is_empty() {
                    home.clone()
                } else {
                    home.join(sub)
                };
                dirs.push(PathBufAlias(d));
            }
        }
    }
    dirs
}

/// PathBuf 的薄包装（仅为让上面的函数签名简洁）
pub struct PathBufAlias(pub std::path::PathBuf);

/// 扫描目录下的 .lyt / .vault 文件（magic bytes 校验，过滤其他工具的同后缀文件）。
/// 与主界面 scan_vault_files 同语义：仅普通文件、跳过符号链接、修改时间倒序。
pub fn scan_vaults_in(dir: &Path) -> Vec<ScannedVault> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        if ext != "lyt" && ext != "vault" {
            continue;
        }
        if !vault_core::is_vault_file(&path) {
            continue;
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        out.push(ScannedVault {
            path: path.to_string_lossy().into_owned(),
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string(),
            mtime,
            size: meta.len(),
        });
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.mtime));
    out
}

// ───────────────── 后台操作（一期：文件管理主链路）─────────────────

/// 打开保险柜（密码 + 可选密钥文件 + 可选 YubiKey 二因子）。
/// 逻辑与 commands::open_vault 一致（去 IPC 冷却/令牌层）。
pub fn op_open(
    shared: SharedVault,
    path: String,
    password: String,
    key_file: Option<String>,
    use_yubikey: bool,
) -> BusyOp {
    spawn_busy(OpKind::Open, "正在打开保险柜", move |tx| {
        let result = (|| -> Result<usize, String> {
            crate::commands::ensure_local_path(&path)?;
            let lower = path.to_ascii_lowercase();
            if !lower.ends_with(".lyt") && !lower.ends_with(".vault") {
                return Err("请选择 .lyt / .vault 保险柜文件".into());
            }
            let key_data = crate::commands::load_key_file(&key_file)?;
            // 二因子：响应只在后端现场挑战硬件（与主界面 F2 修复同语义）
            let yk = if use_yubikey {
                vault_core::read_vault_yk_salt(Path::new(&path))
                    .ok()
                    .and_then(|salt| crate::commands::compute_yk_response(&salt).ok())
            } else {
                None
            };
            let mut vault = Vault::default();
            match vault.open_and_authenticate(
                Path::new(&path),
                &password,
                key_data.as_deref(),
                yk.as_ref(),
            ) {
                Ok(idx) => {
                    *shared.lock().unwrap_or_else(|p| p.into_inner()) = Some(vault);
                    Ok(idx)
                }
                Err(e) => Err(vault_err(&e)),
            }
        })();
        let _ = tx.send(OpMsg::Finished(
            result.map(|_| OpPayload::Summary("保险柜已打开".into())),
        ));
    })
}

/// 新建保险柜（Vault::create 成功即建立会话，无需再次认证）
pub fn op_create(
    shared: SharedVault,
    path: String,
    password: String,
    key_file: Option<String>,
) -> BusyOp {
    spawn_busy(OpKind::Create, "正在创建保险柜", move |tx| {
        let result = (|| -> Result<(), String> {
            crate::commands::ensure_local_path(&path)?;
            if !path.to_ascii_lowercase().ends_with(".lyt") {
                return Err("新保险柜请使用 .lyt 后缀".into());
            }
            let key_data = crate::commands::load_key_file(&key_file)?;
            let mut vault = Vault::default();
            match vault.create(Path::new(&path), &password, key_data.as_deref()) {
                Ok(()) => {
                    *shared.lock().unwrap_or_else(|p| p.into_inner()) = Some(vault);
                    Ok(())
                }
                Err(e) => Err(vault_err(&e)),
            }
        })();
        let _ = tx.send(OpMsg::Finished(
            result.map(|_| OpPayload::Summary("保险柜已创建".into())),
        ));
    })
}

/// 关闭保险柜（审计补落盘 + 密钥清零）
pub fn op_close(shared: SharedVault) -> BusyOp {
    spawn_busy(OpKind::Close, "正在关闭保险柜", move |tx| {
        {
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(v) = guard.as_mut() {
                v.close();
            }
            *guard = None;
        }
        let _ = tx.send(OpMsg::Finished(Ok(OpPayload::Summary(
            "保险柜已关闭".into(),
        ))));
    })
}

/// 列出目录内容（与 commands::list_folder 同逻辑：文件夹在前，同名典排序）
pub fn op_list(shared: SharedVault, cwd: String) -> BusyOp {
    spawn_busy(OpKind::List, "正在读取目录", move |tx| {
        let result = (|| -> Result<Vec<Item>, String> {
            let guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_ref().ok_or("保险柜未打开")?;
            let folder = vault_core::Index::normalize_vpath(&cwd)
                .filter(|p| vault_core::Index::validate_vpath(p))
                .ok_or("无效的目录路径")?;
            let index = vault.index_ref().map_err(|e| vault_err(&e))?;
            let mut items: Vec<Item> = Vec::new();
            for vpath in index.folders.keys() {
                if vpath.is_empty() || vpath == "/" {
                    continue;
                }
                let parent = vpath.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                let display_parent = if parent.is_empty() { "/" } else { parent };
                if display_parent == folder {
                    let name = vpath.rsplit_once('/').map(|(_, n)| n).unwrap_or(vpath);
                    if !name.is_empty() {
                        items.push(Item {
                            name: name.to_string(),
                            vpath: vpath.clone(),
                            is_folder: true,
                            size: None,
                        });
                    }
                }
            }
            for (vpath, meta) in &index.files {
                let dir = vpath.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                let display_dir = if dir.is_empty() { "/" } else { dir };
                if display_dir == folder {
                    items.push(Item {
                        name: meta.name.clone(),
                        vpath: vpath.clone(),
                        is_folder: false,
                        size: Some(meta.size),
                    });
                }
            }
            items.sort_by(|a, b| {
                if a.is_folder != b.is_folder {
                    // 文件夹在前（is_folder=true 排前）
                    b.is_folder.cmp(&a.is_folder)
                } else {
                    a.name.to_lowercase().cmp(&b.name.to_lowercase())
                }
            });
            Ok(items)
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Listing)));
    })
}

/// 全库文件名搜索（大小写不敏感子串，与 commands::search_files 同语义）
pub fn op_search(shared: SharedVault, query: String) -> BusyOp {
    spawn_busy(OpKind::Search, "正在搜索", move |tx| {
        let result = (|| -> Result<Vec<vault_core::SearchHit>, String> {
            if query.chars().count() > 256 {
                return Err("搜索词过长（上限 256 字符）".into());
            }
            let guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_ref().ok_or("保险柜未打开")?;
            Ok(vault.search_files(&query, 200))
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Search)));
    })
}

/// 批量导入文件到当前目录
pub fn op_import_files(shared: SharedVault, cwd: String, paths: Vec<String>) -> BusyOp {
    spawn_busy(OpKind::Import, "正在导入文件", move |tx| {
        let result = (|| -> Result<String, String> {
            let base = vault_core::Index::normalize_vpath(&cwd)
                .filter(|p| vault_core::Index::validate_vpath(p))
                .ok_or("无效的目录路径")?;
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            let file_cb = |done: usize, total: usize| {
                let _ = tx.send(OpMsg::Progress(done, total));
            };
            let chunk_cb = |done: u64, total: u64| {
                let _ = tx.send(OpMsg::Bytes(done, total));
            };
            let (ok, fail, errors) = vault
                .import_files_batch(&paths, &base, Some(&file_cb), Some(&chunk_cb))
                .map_err(|e| vault_err(&e))?;
            let mut msg = format!("导入完成：成功 {} 个，失败 {} 个", ok, fail);
            if !errors.is_empty() {
                msg.push_str("\n失败明细：\n");
                msg.push_str(&errors.join("\n"));
            }
            Ok(msg)
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Summary)));
    })
}

/// 递归导入文件夹到当前目录
pub fn op_import_folder(shared: SharedVault, cwd: String, src: String) -> BusyOp {
    spawn_busy(OpKind::Import, "正在导入文件夹", move |tx| {
        let result = (|| -> Result<String, String> {
            let base = vault_core::Index::normalize_vpath(&cwd)
                .filter(|p| vault_core::Index::validate_vpath(p))
                .ok_or("无效的目录路径")?;
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            let file_cb = |done: usize, total: usize| {
                let _ = tx.send(OpMsg::Progress(done, total));
            };
            let (files, dirs, skipped) = vault
                .import_folder(Path::new(&src), &base, Some(&file_cb))
                .map_err(|e| vault_err(&e))?;
            Ok(format!(
                "文件夹导入完成：{} 个文件，{} 个文件夹，跳过 {} 项",
                files, dirs, skipped
            ))
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Summary)));
    })
}

/// 新建文件夹
pub fn op_new_folder(shared: SharedVault, cwd: String, name: String) -> BusyOp {
    spawn_busy(OpKind::NewFolder, "正在创建文件夹", move |tx| {
        let result = (|| -> Result<(), String> {
            let base = vault_core::Index::normalize_vpath(&cwd)
                .filter(|p| vault_core::Index::validate_vpath(p))
                .ok_or("无效的目录路径")?;
            let vpath = if base == "/" {
                format!("/{}", name)
            } else {
                format!("{}/{}", base, name)
            };
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            let mut im = vault.get_index_manager().map_err(|e| vault_err(&e))?;
            im.add_folder(&vpath).map_err(|e| vault_err(&e))
        })();
        let _ = tx.send(OpMsg::Finished(
            result.map(|_| OpPayload::Summary("文件夹已创建".into())),
        ));
    })
}

/// 重命名文件 / 文件夹（只改索引，不重加密）
pub fn op_rename(shared: SharedVault, vpath: String, new_name: String, is_folder: bool) -> BusyOp {
    spawn_busy(OpKind::Rename, "正在重命名", move |tx| {
        let result = (|| -> Result<(), String> {
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            let mut im = vault.get_index_manager().map_err(|e| vault_err(&e))?;
            let r = if is_folder {
                im.rename_folder(&vpath, &new_name)
            } else {
                im.rename_file(&vpath, &new_name)
            };
            r.map_err(|e| vault_err(&e))
        })();
        let _ = tx.send(OpMsg::Finished(
            result.map(|_| OpPayload::Summary("重命名完成".into())),
        ));
    })
}

/// 批量安全删除（先索引落盘再 DoD 7-pass 覆写；文件夹自动展开去重）
pub fn op_delete(shared: SharedVault, vpaths: Vec<String>) -> BusyOp {
    spawn_busy(OpKind::Delete, "正在安全删除", move |tx| {
        let result = (|| -> Result<String, String> {
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            let (files, folders, reclaimed) = vault
                .secure_delete_files_batch(&vpaths)
                .map_err(|e| vault_err(&e))?;
            let mut msg = format!("删除完成：{} 个文件，{} 个文件夹", files, folders);
            if let Some(bytes) = reclaimed {
                msg.push_str(&format!("，自动整理回收 {}", human_size(bytes)));
            }
            Ok(msg)
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Summary)));
    })
}

/// 批量提取选中项（同名文件默认拒绝覆盖，与主界面提取一致）
pub fn op_extract(shared: SharedVault, vpaths: Vec<String>, dest: String) -> BusyOp {
    spawn_busy(OpKind::Extract, "正在提取", move |tx| {
        let result = (|| -> Result<String, String> {
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            let file_cb = |done: usize, total: usize| {
                let _ = tx.send(OpMsg::Progress(done, total));
            };
            let chunk_cb = |done: u64, total: u64| {
                let _ = tx.send(OpMsg::Bytes(done, total));
            };
            let (ok, fail, errors) = vault
                .extract_files_batch(&vpaths, Path::new(&dest), Some(&file_cb), Some(&chunk_cb))
                .map_err(|e| vault_err(&e))?;
            let mut msg = format!("提取完成：成功 {} 个，失败 {} 个", ok, fail);
            if !errors.is_empty() {
                msg.push_str("\n失败明细（同名文件默认拒绝覆盖）：\n");
                msg.push_str(&errors.join("\n"));
            }
            Ok(msg)
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Summary)));
    })
}

/// 提取全部（目标父目录下自动创建「保险柜文件名」子文件夹，保留内部结构）
pub fn op_extract_all(shared: SharedVault, dest_parent: String, overwrite: bool) -> BusyOp {
    spawn_busy(OpKind::Extract, "正在提取全部文件", move |tx| {
        let result = (|| -> Result<String, String> {
            let vault_path = {
                let guard = shared.lock().unwrap_or_else(|p| p.into_inner());
                let vault = guard.as_ref().ok_or("保险柜未打开")?;
                vault
                    .get_path()
                    .map(|p| p.to_path_buf())
                    .ok_or("保险柜路径不可用")?
            };
            let dest = Path::new(&dest_parent).join(export_stem(&vault_path));
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            let file_cb = |done: usize, total: usize| {
                let _ = tx.send(OpMsg::Progress(done, total));
            };
            let chunk_cb = |done: u64, total: u64| {
                let _ = tx.send(OpMsg::Bytes(done, total));
            };
            let (ok, fail, errors) = vault
                .extract_all_files(&dest, overwrite, Some(&file_cb), Some(&chunk_cb))
                .map_err(|e| vault_err(&e))?;
            let mut msg = format!(
                "提取完成（{}）：成功 {} 个，失败 {} 个",
                dest.display(),
                ok,
                fail
            );
            if !errors.is_empty() {
                msg.push_str("\n失败明细：\n");
                msg.push_str(&errors.join("\n"));
            }
            Ok(msg)
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Summary)));
    })
}

/// 安全预览：图片（解码为 RGBA）/ 文本（UTF-8 校验 + 编辑上限）/ Office 文本。
/// 数据全程在内存，不落盘。
pub fn op_preview(shared: SharedVault, vpath: String, office_password: Option<String>) -> BusyOp {
    spawn_busy(OpKind::Preview, "正在加载预览", move |tx| {
        let result = (|| -> Result<PreviewData, String> {
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            let size = {
                let index = vault.index_ref().map_err(|e| vault_err(&e))?;
                let meta = index.files.get(&vpath).ok_or("文件不存在")?;
                meta.size
            };
            if size > PREVIEW_MAX {
                return Err(format!(
                    "文件过大（{}），预览上限 64 MB，请提取后查看",
                    human_size(size)
                ));
            }
            let data = vault.load_file_data(&vpath).map_err(|e| vault_err(&e))?;
            let filename = vpath.rsplit('/').next().unwrap_or(&vpath).to_string();
            let ext = filename
                .rsplit('.')
                .next()
                .map(|e| e.to_ascii_lowercase())
                .unwrap_or_default();

            let preview = if is_image_ext(&ext) {
                let decoded = decode_image(&data, &filename);
                vault_core::wipe::secure_wipe_vec(data);
                decoded?
            } else if matches!(ext.as_str(), "docx" | "xlsx" | "xls" | "doc") {
                let r = vault_core::office::extract_office_text(
                    &data,
                    &filename,
                    office_password.as_deref(),
                );
                vault_core::wipe::secure_wipe_vec(data);
                let text = r.map_err(|e| {
                    if e == "OFFICE_ENCRYPTED" {
                        "OFFICE_ENCRYPTED".to_string()
                    } else {
                        e
                    }
                })?;
                PreviewData::Office {
                    name: filename,
                    text,
                }
            } else if is_media_ext(&ext) || is_binary_ext(&ext) {
                // 音视频 / 压缩包 / 可执行文件：不解码也不按文本展示（避免乱码噪音）
                vault_core::wipe::secure_wipe_vec(data);
                let what = if is_media_ext(&ext) {
                    "音视频"
                } else if matches!(ext.as_str(), "zip" | "rar" | "7z" | "tar" | "gz") {
                    "压缩包"
                } else {
                    "该二进制文件"
                };
                PreviewData::Notice {
                    name: filename,
                    text: format!(
                        "{} 不支持内置预览。\n\n如需查看，请选中后「提取…」到本地，再用系统程序打开。\n（预览全程在内存解密，不落盘）",
                        what
                    ),
                }
            } else {
                // 其余一律按文本处理（与主界面一致的宽容语义）
                let (content, editable, note) = match String::from_utf8(data.clone()) {
                    Ok(s) => {
                        let over = s.len() > EDIT_MAX;
                        let size_note = human_size(s.len() as u64);
                        if over {
                            (
                                s,
                                false,
                                Some(format!(
                                    "文件超过编辑上限（4 MB），只读预览。当前 {}",
                                    size_note
                                )),
                            )
                        } else {
                            (s, true, None)
                        }
                    }
                    Err(_) => (
                        String::from_utf8_lossy(&data).into_owned(),
                        false,
                        Some("非 UTF-8 编码文本（如 GBK），只读展示可能乱码；如需编辑请先在应用外转换编码".to_string()),
                    ),
                };
                vault_core::wipe::secure_wipe_vec(data);
                PreviewData::Text {
                    name: filename,
                    vpath,
                    content,
                    editable,
                    note,
                }
            };
            Ok(preview)
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Preview)));
    })
}

/// 文本编辑保存（加密追加 → 索引先落盘 → DoD 7-pass 覆写旧密文）
pub fn op_save_text(shared: SharedVault, vpath: String, content: String) -> BusyOp {
    spawn_busy(OpKind::SaveText, "正在保存", move |tx| {
        let result = (|| -> Result<(), String> {
            if content.len() > EDIT_MAX {
                return Err("内容过大：文本编辑上限 4 MB".into());
            }
            let data = content.into_bytes();
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            let r = vault
                .update_file_content(&vpath, &data)
                .map_err(|e| vault_err(&e));
            vault_core::wipe::secure_wipe_vec(data);
            r
        })();
        let _ = tx.send(OpMsg::Finished(
            result.map(|_| OpPayload::Summary("已保存到保险柜".into())),
        ));
    })
}

// ───────────────── 3.1.1：管理功能（改密 / 分区 / 整理 / 销毁 / 记录 / 体检）─────────────────

/// 会话内二因子响应：当前分区启用硬件密钥时现场挑战硬件，普通分区返回 None。
/// 与 commands::session_yk_response 同语义（egui 为进程内可信 UI，无 IPC 层）。
fn session_yk_response(vault: &Vault) -> Result<Option<[u8; 20]>, String> {
    if vault.is_yubikey_2fa_active().map_err(|e| vault_err(&e))? {
        let salt = vault.yubikey_challenge_salt().map_err(|e| vault_err(&e))?;
        Ok(Some(crate::commands::compute_yk_response(&salt)?))
    } else {
        Ok(None)
    }
}

/// 修改当前分区密码（v5/v6 头部级秒完成；v4 一次性升级为 v6 全库重加密）。
/// 必须验证当前密码，防止他人在已解锁的机器上改密锁死主人；口令用后即清。
pub fn op_change_password(
    shared: SharedVault,
    mut current: String,
    mut new: String,
    key_file: Option<String>,
) -> BusyOp {
    spawn_busy(OpKind::ChangePassword, "正在修改密码", move |tx| {
        let result = (|| -> Result<(), String> {
            let key_data = crate::commands::load_key_file(&key_file)?;
            let changed: Result<(), String> = (|| {
                let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
                let vault = guard.as_mut().ok_or("保险柜未打开")?;
                // 二因子分区的验证响应由后台现场挑战硬件
                let yk = session_yk_response(vault)?;
                vault
                    .change_password(
                        &current,
                        &new,
                        key_data.as_deref(),
                        None::<fn(usize)>,
                        yk.as_ref(),
                    )
                    .map_err(|e| vault_err(&e))
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            changed
        })();
        current.zeroize();
        new.zeroize();
        let _ = tx.send(OpMsg::Finished(
            result.map(|_| OpPayload::Summary("密码已修改".into())),
        ));
    })
}

/// 列出全部分区（标记当前分区）
pub fn op_list_partitions(shared: SharedVault) -> BusyOp {
    spawn_busy(OpKind::ListPartitions, "正在读取分区", move |tx| {
        let result = (|| -> Result<Vec<PartitionRow>, String> {
            let guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_ref().ok_or("保险柜未打开")?;
            let active = vault.get_active_partition().map(|p| p.alias.clone());
            Ok(vault
                .get_partitions()
                .iter()
                .enumerate()
                .map(|(i, p)| PartitionRow {
                    alias: p.alias.clone(),
                    active: active.as_deref() == Some(p.alias.as_str()),
                    primary: i == 0,
                })
                .collect())
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Partitions)));
    })
}

/// 添加伪装分区（别名与口令强度校验与主界面一致）
pub fn op_add_partition(
    shared: SharedVault,
    alias: String,
    mut password: String,
    key_file: Option<String>,
) -> BusyOp {
    spawn_busy(OpKind::AddPartition, "正在添加分区", move |tx| {
        let result = (|| -> Result<(), String> {
            if alias.is_empty()
                || alias.chars().count() > 16
                || !alias
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ' ')
            {
                return Err(
                    "分区别名只能包含 ASCII 字母、数字、下划线、短横线和空格，长度 1-16 字符"
                        .into(),
                );
            }
            if password.chars().count() < 12 {
                return Err("分区密码长度至少 12 位".into());
            }
            let key_data = crate::commands::load_key_file(&key_file)?;
            let added: Result<(), String> = (|| {
                let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
                let vault = guard.as_mut().ok_or("保险柜未打开")?;
                vault
                    .add_partition(&alias, &password, key_data.as_deref())
                    .map_err(|e| vault_err(&e))
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            added
        })();
        password.zeroize();
        let _ =
            tx.send(OpMsg::Finished(result.map(|_| {
                OpPayload::Summary(format!("分区 '{}' 已添加", alias))
            })));
    })
}

/// 删除非活跃、非主分区
pub fn op_remove_partition(shared: SharedVault, alias: String) -> BusyOp {
    spawn_busy(OpKind::RemovePartition, "正在删除分区", move |tx| {
        let result = (|| -> Result<(), String> {
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            vault.remove_partition(&alias).map_err(|e| vault_err(&e))
        })();
        let _ =
            tx.send(OpMsg::Finished(result.map(|_| {
                OpPayload::Summary(format!("分区 '{}' 已删除", alias))
            })));
    })
}

/// 碎片整理（后台线程执行，进度按百分比回传）
pub fn op_defragment(shared: SharedVault) -> BusyOp {
    spawn_busy(OpKind::Defrag, "正在整理保险柜", move |tx| {
        let result = (|| -> Result<(), String> {
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            vault
                .defragment_vault(Some(|p: usize| {
                    let _ = tx.send(OpMsg::Progress(p, 100));
                }))
                .map_err(|e| vault_err(&e))
        })();
        let _ = tx.send(OpMsg::Finished(
            result.map(|_| OpPayload::Summary("碎片整理完成".into())),
        ));
    })
}

/// 销毁保险柜（不可恢复；成功后会话清空）
pub fn op_destroy(shared: SharedVault) -> BusyOp {
    spawn_busy(OpKind::Destroy, "正在销毁保险柜", move |tx| {
        let result = (|| -> Result<(), String> {
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            vault.destroy().map_err(|e| vault_err(&e))?;
            *guard = None;
            Ok(())
        })();
        let _ = tx.send(OpMsg::Finished(
            result.map(|_| OpPayload::Summary("保险柜已销毁".into())),
        ));
    })
}

/// 读取操作记录（最新在前）
pub fn op_audit(shared: SharedVault, limit: usize) -> BusyOp {
    spawn_busy(OpKind::Audit, "正在读取操作记录", move |tx| {
        let result = (|| -> Result<Vec<AuditRow>, String> {
            let guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_ref().ok_or("保险柜未打开")?;
            let limit = limit.clamp(1, 5000);
            Ok(vault
                .get_audit_entries()
                .iter()
                .rev()
                .take(limit)
                .map(|e| AuditRow {
                    ts: e.ts,
                    event: e.event.clone(),
                })
                .collect())
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Audit)));
    })
}

/// 全库完整性体检（只读，逐文件校验 GCM 认证标签）
pub fn op_verify(shared: SharedVault) -> BusyOp {
    spawn_busy(OpKind::Verify, "正在完整性体检", move |tx| {
        let result = (|| -> Result<(usize, usize), String> {
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            let (total, broken) = vault
                .verify_integrity(Some(|done: usize, total: usize, _current: &str| {
                    let _ = tx.send(OpMsg::Progress(done, total));
                }))
                .map_err(|e| vault_err(&e))?;
            Ok((total, broken.len()))
        })();
        let _ = tx.send(OpMsg::Finished(
            result.map(|(total, broken)| OpPayload::Verify { total, broken }),
        ));
    })
}

// ───────────────── 3.1.2：移动 / 锁定提示 / 硬件密钥 / 设置 ─────────────────

/// 移动文件/文件夹到目标目录（只改索引，不重加密）
pub fn op_move(shared: SharedVault, vpaths: Vec<String>, dest: String) -> BusyOp {
    spawn_busy(OpKind::Move, "正在移动", move |tx| {
        let result = (|| -> Result<String, String> {
            let dest_norm = vault_core::Index::normalize_vpath(&dest)
                .filter(|p| vault_core::Index::validate_vpath(p))
                .ok_or("目标目录非法")?;
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().ok_or("保险柜未打开")?;
            let mut mgr = vault.get_index_manager().map_err(|e| vault_err(&e))?;
            let (ok, fail, errors) = mgr
                .move_items(&vpaths, &dest_norm)
                .map_err(|e| vault_err(&e))?;
            let mut msg = format!("移动完成：成功 {} 个，失败 {} 个", ok, fail);
            if !errors.is_empty() {
                msg.push_str("\n失败明细：\n");
                msg.push_str(&errors.join("\n"));
            }
            Ok(msg)
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Summary)));
    })
}

/// 列出当前分区全部文件夹（移动目标选择）
pub fn op_list_folders(shared: SharedVault) -> BusyOp {
    spawn_busy(OpKind::ListFolders, "正在读取文件夹", move |tx| {
        let result = (|| -> Result<Vec<String>, String> {
            let guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_ref().ok_or("保险柜未打开")?;
            vault.list_all_folders().map_err(|e| vault_err(&e))
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Folders)));
    })
}

/// 读取保险柜头部锁定信息（无需密码；用于解锁页提示失败次数 / 锁定到期）
pub fn op_lock_info(path: String) -> BusyOp {
    spawn_busy(OpKind::LockInfo, "正在读取锁定信息", move |tx| {
        let result = (|| -> Result<(u32, bool, f64), String> {
            crate::commands::ensure_local_path(&path)?;
            let info = vault_core::read_lock_info(Path::new(&path))
                .map_err(|_| "无法读取保险柜信息".to_string())?;
            Ok((info.failed_count as u32, info.locked, info.lock_until_epoch))
        })();
        let _ = tx.send(OpMsg::Finished(result.map(|(failed, locked, until)| {
            OpPayload::LockInfo {
                failed,
                locked,
                until,
            }
        })));
    })
}

/// 读取硬件密钥状态（是否启用 + 设备是否在位）
pub fn op_yk_status(shared: SharedVault) -> BusyOp {
    spawn_busy(
        OpKind::YkStatus,
        "正在读取硬件密钥状态",
        move |tx| {
            let result = (|| -> Result<(bool, bool), String> {
                let enabled = {
                    let guard = shared.lock().unwrap_or_else(|p| p.into_inner());
                    let vault = guard.as_ref().ok_or("保险柜未打开")?;
                    vault.is_yubikey_2fa_active().map_err(|e| vault_err(&e))?
                };
                Ok((enabled, crate::yubikey::probe().unwrap_or(false)))
            })();
            let _ =
                tx.send(OpMsg::Finished(result.map(|(enabled, present)| {
                    OpPayload::Yubikey { enabled, present }
                })));
        },
    )
}

/// 启用 / 解除当前分区的硬件密钥二因子（现场挑战硬件，口令用后即清）
pub fn op_yk_set(
    shared: SharedVault,
    enable: bool,
    mut password: String,
    key_file: Option<String>,
) -> BusyOp {
    let (kind, label) = if enable {
        (OpKind::YkEnable, "正在启用硬件密钥二因子")
    } else {
        (OpKind::YkDisable, "正在解除硬件密钥二因子")
    };
    spawn_busy(kind, label, move |tx| {
        let result = (|| -> Result<(), String> {
            if password.is_empty() {
                return Err("请输入当前分区密码".into());
            }
            let key_data = crate::commands::load_key_file(&key_file)?;
            let changed: Result<(), String> = (|| {
                let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
                let vault = guard.as_mut().ok_or("保险柜未打开")?;
                let salt = vault.yubikey_challenge_salt().map_err(|e| vault_err(&e))?;
                let yk = crate::commands::compute_yk_response(&salt)?;
                let r = if enable {
                    vault.enable_yubikey_2fa(&password, key_data.as_deref(), &yk)
                } else {
                    vault.disable_yubikey_2fa(&password, key_data.as_deref(), &yk)
                };
                r.map_err(|e| vault_err(&e))
            })();
            if let Some(kd) = key_data {
                vault_core::wipe::secure_wipe_vec(kd);
            }
            changed
        })();
        password.zeroize();
        let msg = if enable {
            "二因子已启用"
        } else {
            "二因子已解除"
        };
        let _ = tx.send(OpMsg::Finished(
            result.map(|_| OpPayload::Summary(msg.into())),
        ));
    })
}

/// 读取设置（自动锁定 + 持久化状态）
pub fn op_settings_load() -> BusyOp {
    spawn_busy(OpKind::SettingsLoad, "正在读取设置", move |tx| {
        // 3.1.1：去掉「定义后立即调用」的零捕获闭包（clippy::redundant_closure_call）
        let result: Result<SettingsView, String> = match crate::settings::load_active() {
            Some((path, s)) => {
                let portable = crate::settings::portable_config_path()
                    .map(|p| p == path)
                    .unwrap_or(false);
                Ok(SettingsView {
                    autolock_minutes: s.autolock_minutes,
                    enabled: true,
                    location: Some(if portable {
                        "便携模式（程序所在目录）".into()
                    } else {
                        "固定安装（用户配置目录）".into()
                    }),
                })
            }
            None => Ok(SettingsView {
                autolock_minutes: 2,
                enabled: false,
                location: None,
            }),
        };
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Settings)));
    })
}

/// 保存设置。`enable_at` 非空表示同时启用持久化（首次保存必填）。
pub fn op_settings_save(
    autolock_minutes: u32,
    enable_at: Option<crate::settings::ConfigLocation>,
) -> BusyOp {
    spawn_busy(OpKind::SettingsSave, "正在保存设置", move |tx| {
        let result = (|| -> Result<SettingsView, String> {
            let mut s = crate::settings::load_active()
                .map(|(_, s)| s)
                .unwrap_or_default();
            s.autolock_minutes = autolock_minutes.min(240);
            let s = s.sanitized();
            match enable_at {
                Some(loc) => {
                    crate::settings::save_to(loc, &s)?;
                }
                None => {
                    let path = crate::settings::active_config_path()
                        .ok_or("未启用持久化，请先选择保存位置")?;
                    crate::settings::save_at(&path, &s)?;
                }
            }
            let view = match crate::settings::load_active() {
                Some((path, saved)) => {
                    let portable = crate::settings::portable_config_path()
                        .map(|p| p == path)
                        .unwrap_or(false);
                    SettingsView {
                        autolock_minutes: saved.autolock_minutes,
                        enabled: true,
                        location: Some(if portable {
                            "便携模式（程序所在目录）".into()
                        } else {
                            "固定安装（用户配置目录）".into()
                        }),
                    }
                }
                None => SettingsView {
                    autolock_minutes: s.autolock_minutes,
                    enabled: false,
                    location: None,
                },
            };
            Ok(view)
        })();
        let _ = tx.send(OpMsg::Finished(result.map(OpPayload::Settings)));
    })
}

// ───────────────── 辅助 ─────────────────

pub fn is_image_ext(ext: &str) -> bool {
    matches!(
        ext,
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "tiff" | "tif"
    )
}

/// 音视频（GUI 不内置解码播放，提示提取后播放）
pub fn is_media_ext(ext: &str) -> bool {
    matches!(
        ext,
        "mp4" | "webm" | "mkv" | "mov" | "avi" | "mp3" | "ogg" | "wav" | "flac" | "m4a" | "aac"
    )
}

/// 无法按文本展示的二进制类型（压缩包 / 可执行文件 / 镜像等）
pub fn is_binary_ext(ext: &str) -> bool {
    matches!(
        ext,
        "zip" | "rar" | "7z" | "tar" | "gz" | "exe" | "dll" | "bin" | "iso" | "apk" | "msi" | "pdf"
    )
}

/// 解码图片为 RGBA（image crate，已启用 png/jpeg/gif/bmp/webp/tiff feature）
fn decode_image(data: &[u8], name: &str) -> Result<PreviewData, String> {
    let reader = image::ImageReader::new(std::io::Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| format!("图片格式识别失败（{}）：{}", name, e))?;
    let img = reader
        .decode()
        .map_err(|e| format!("图片解码失败（{}）：{}", name, e))?;
    let rgba = img.to_rgba8();
    let size = [rgba.width() as usize, rgba.height() as usize];
    Ok(PreviewData::Image {
        name: name.to_string(),
        rgba: rgba.into_raw(),
        size,
    })
}

/// 与 commands::export_stem 同逻辑：保险柜文件名 → 安全的导出子文件夹名
pub fn export_stem(vault_path: &Path) -> String {
    let stem = vault_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("LynVault_Export")
        .to_string();
    let safe: String = stem
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
            )
        })
        .collect();
    if safe.trim().is_empty() {
        "LynVault_Export".to_string()
    } else {
        safe
    }
}

pub fn human_size(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if n >= GB {
        format!("{:.2} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1} KB", n as f64 / KB as f64)
    } else {
        format!("{} B", n)
    }
}

/// 文件类型标签（内置图标兜底，与主界面 Linux 行为一致）
#[allow(dead_code)]
pub fn type_tag(item: &Item) -> String {
    if item.is_folder {
        return "[目录]".into();
    }
    let ext = item
        .name
        .rsplit('.')
        .next()
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    if is_image_ext(&ext) {
        "[图片]".into()
    } else if matches!(ext.as_str(), "docx" | "xlsx" | "xls" | "doc") {
        "[文档]".into()
    } else if matches!(
        ext.as_str(),
        "mp4" | "webm" | "mkv" | "mov" | "mp3" | "ogg" | "wav" | "flac" | "m4a"
    ) {
        "[音视频]".into()
    } else if matches!(
        ext.as_str(),
        "txt"
            | "md"
            | "json"
            | "csv"
            | "xml"
            | "ini"
            | "yaml"
            | "yml"
            | "log"
            | "rs"
            | "js"
            | "ts"
            | "go"
            | "py"
            | "c"
            | "cpp"
            | "h"
            | "java"
            | "sh"
            | "bat"
            | "ps1"
            | "toml"
            | "html"
            | "css"
    ) {
        "[文本]".into()
    } else if ext == "lyt" || ext == "vault" {
        "[保险柜]".into()
    } else {
        "[文件]".into()
    }
}

// ───────────────── 字体 ─────────────────

/// 安装 CJK 字体 —— egui 默认字库不含中日韩字形，直接用会满屏豆腐块。
/// 策略：运行时加载系统字体（Windows 微软雅黑 / 宋体，Linux Noto CJK /
/// 文泉驿，macOS 苹方），追加为 fallback（拉丁仍用 egui 默认字库）。
/// 找不到 CJK 字体时不阻塞启动（界面退化为豆腐块 + 可用）。
fn install_cjk_fonts(ctx: egui::Context) {
    let candidates: &[&str] = &[
        // Windows
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\simsun.ttc",
        "C:\\Windows\\Fonts\\simhei.ttf",
        "C:\\Windows\\Fonts\\Deng.ttf",
        // Linux
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        // macOS
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
    ];
    for p in candidates {
        if let Ok(bytes) = std::fs::read(p) {
            let mut fonts = egui::FontDefinitions::default();
            fonts
                .font_data
                .insert("cjk_fallback".to_owned(), egui::FontData::from_owned(bytes));
            // 3.1.1：中文字体放首位 —— 微软雅黑 / Noto Sans CJK 自带西文字形，
            // 与原版 Segoe UI 观感一致（egui 默认拉丁字体明显偏细偏窄）
            if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                fam.insert(0, "cjk_fallback".to_owned());
            }
            if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                fam.push("cjk_fallback".to_owned());
            }
            // 等宽西文优先 Consolas（Windows），命中不到时沿用默认等宽
            for mono in [
                "C:\\Windows\\Fonts\\consola.ttf",
                "C:\\Windows\\Fonts\\consolab.ttf",
            ] {
                if let Ok(mbytes) = std::fs::read(mono) {
                    fonts
                        .font_data
                        .insert("mono_latin".to_owned(), egui::FontData::from_owned(mbytes));
                    if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                        fam.insert(0, "mono_latin".to_owned());
                    }
                    break;
                }
            }
            ctx.set_fonts(fonts);
            log::info!("备用界面已加载系统 CJK 字体");
            return;
        }
    }
    log::warn!("未找到系统 CJK 字体，备用界面中文可能显示为方块");
}

// ───────────────── 入口 ─────────────────

/// 启动备用 GUI（阻塞至窗口关闭）。
/// `launch_vault`：命令行传入的 .lyt 路径（双击关联 / --gui <路径>），直达解锁页。
pub fn run(launch_vault: Option<String>) -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("LynVault")
            .with_inner_size([1024.0, 660.0])
            .with_min_inner_size([720.0, 460.0])
            // 3.1.1：与原版一致的无边框窗口 —— 标题栏与窗口按钮由 egui 自绘
            .with_decorations(false)
            .with_resizable(true),
        ..Default::default()
    };
    eframe::run_native(
        "LynVault",
        options,
        // eframe 0.29 起 AppCreator 返回 Result<Box<dyn App>, _>
        Box::new(move |cc| {
            install_cjk_fonts(cc.egui_ctx.clone());
            // 与 ui/styles.css（theme-blue）对齐的配色 / 圆角 / 字号 / 控件视觉
            theme::apply(&cc.egui_ctx);
            Ok(Box::new(app::LynVaultApp::new(cc, launch_vault)))
        }),
    )
    .map_err(|e| e.to_string())
}
