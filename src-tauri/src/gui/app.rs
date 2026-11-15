// ───────────────── 备用 GUI：eframe App ─────────────────
//
// 界面状态机：Launcher（启动扫描）→ Unlock（解锁/新建）→ Main（文件管理主界面）。
// 所有 vault 操作走 gui::op_*（后台线程 + channel 回传），UI 线程每帧轮询，
// 渲染永不阻塞。长任务期间工具栏禁用（busy），模态框期间全局入口禁用（modal）。

use std::collections::HashSet;
use std::sync::mpsc::TryRecvError;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use super::theme;
use super::{
    human_size, op_add_partition, op_audit, op_change_password, op_close, op_create, op_defragment,
    op_delete, op_destroy, op_extract, op_extract_all, op_import_files, op_import_folder, op_list,
    op_list_folders, op_list_partitions, op_lock_info, op_move, op_new_folder, op_open, op_preview,
    op_remove_partition, op_rename, op_save_text, op_search, op_settings_load, op_settings_save,
    op_verify, op_yk_set, op_yk_status, scan_candidate_dirs, scan_vaults_in, AuditRow, BusyOp,
    Item, OpKind, OpMsg, OpPayload, PartitionRow, PreviewData, ScannedVault, SharedVault,
};

// ───────────────── 界面状态 ─────────────────

#[derive(PartialEq, Clone, Copy)]
enum Screen {
    Launcher,
    Unlock,
    Main,
}

enum PreviewKind {
    Image {
        handle: Option<egui::TextureHandle>,
        size: [usize; 2],
    },
    Text {
        editing: bool,
        editable: bool,
        dirty: bool,
        note: Option<String>,
    },
    Office,
    /// 无法内置预览（音视频 / 压缩包 / 二进制）—— 只显示提示
    Notice,
}

struct PreviewUi {
    vpath: String,
    name: String,
    open: bool,
    /// 文本内容 / 编辑缓冲（Office 与图片为空）
    text: String,
    kind: PreviewKind,
}

enum Modal {
    NewFolder(String),
    Rename {
        vpath: String,
        name: String,
        is_folder: bool,
    },
    ConfirmDelete(Vec<String>),
    ConfirmOverwriteAll {
        dest_parent: String,
    },
    OfficePw {
        vpath: String,
        name: String,
        password: String,
    },
    // 3.1.1：管理功能的确认框
    ConfirmRemovePartition(String),
    ConfirmDefrag,
    /// 销毁为两步确认（stage 1 → 2 才真正执行）
    ConfirmDestroy {
        stage: u8,
    },
    /// 移动选中项到目标目录（dest 可编辑，folders 来自全库列表）
    MoveTo {
        vpaths: Vec<String>,
        dest: String,
    },
}

/// 保险柜管理窗口状态（口令仅存内存，关闭窗口即丢弃）
struct AdminUi {
    open: bool,
    partitions: Vec<PartitionRow>,
    // 修改密码
    cur_pw: String,
    new_pw: String,
    new_pw2: String,
    keyfile: Option<String>,
    // 添加分区
    new_alias: String,
    new_alias_pw: String,
    // 硬件密钥二因子
    yk: Option<(bool, bool)>,
    yk_requested: bool,
    yk_pw: String,
    /// 体检结果：是否通过 + 文案
    verify: Option<(bool, String)>,
    error: Option<String>,
    notice: Option<String>,
}

impl AdminUi {
    fn new() -> Self {
        Self {
            open: true,
            partitions: Vec::new(),
            cur_pw: String::new(),
            new_pw: String::new(),
            new_pw2: String::new(),
            keyfile: None,
            new_alias: String::new(),
            new_alias_pw: String::new(),
            yk: None,
            yk_requested: false,
            yk_pw: String::new(),
            verify: None,
            error: None,
            notice: None,
        }
    }
}

/// 设置窗口状态
struct SettingsUi {
    open: bool,
    autolock: u32,
    enabled: bool,
    location: Option<String>,
    loaded: bool,
    requested: bool,
    notice: Option<String>,
    error: Option<String>,
}

impl SettingsUi {
    fn new() -> Self {
        Self {
            open: true,
            autolock: 2,
            enabled: false,
            location: None,
            loaded: false,
            requested: false,
            notice: None,
            error: None,
        }
    }
}

/// 操作记录窗口状态
struct AuditUi {
    open: bool,
    entries: Vec<AuditRow>,
}

pub struct LynVaultApp {
    shared: SharedVault,
    screen: Screen,

    // 启动扫描
    scan_rx: Option<mpsc::Receiver<Vec<ScannedVault>>>,
    scanned: Vec<ScannedVault>,

    // 解锁 / 新建
    unlock_path: String,
    unlock_is_new: bool,
    password: String,
    password2: String,
    keyfile: Option<String>,
    use_yk: bool,
    unlock_error: Option<String>,

    // 命令行直达的解锁目标（进入解锁页时消费）
    launch_pending: Option<String>,

    // 主界面
    cwd: String,
    items: Vec<Item>,
    search_mode: bool,
    search_input: String,
    path_input: String,
    selected: HashSet<String>,
    vault_title: String,

    // 操作与反馈
    busy: Option<BusyOp>,
    progress: Option<(usize, usize)>,
    bytes_progress: Option<(u64, u64)>,
    status: String,
    modal: Option<Modal>,
    admin: Option<AdminUi>,
    audit: Option<AuditUi>,
    settings: Option<SettingsUi>,
    /// 解锁页锁定提示：(失败次数, 是否锁定, 锁定到期 epoch)
    lock_info: Option<(u32, bool, f64)>,
    /// 移动目标选择用的全部分区文件夹
    folders: Vec<String>,
    /// Ctrl+F 请求聚焦搜索框（下一帧消费）
    focus_search: bool,
    preview: Option<PreviewUi>,
    /// 当前正在请求预览的 vpath（图片载荷不含 vpath，靠它配对）
    pending_preview_vpath: Option<String>,

    // 空闲自动锁定（后端设置持久化；未启用时默认 2 分钟）
    autolock_minutes: u64,
    last_active: Instant,

    /// 关闭请求已处理标志 —— eframe 0.29 没有 App::on_close_event，
    /// 在 update 里拦截 close_requested：先安全关柜（审计落盘 + 密钥清零）
    /// 再主动发送 Close 命令放行退出
    close_confirmed: bool,
}

impl LynVaultApp {
    pub fn new(_cc: &eframe::CreationContext<'_>, launch_vault: Option<String>) -> Self {
        // 空闲锁定时长：与主界面同一份设置（未启用持久化 → 默认 2 分钟）
        let autolock_minutes = crate::settings::load_active()
            .map(|(_, s)| s.autolock_minutes as u64)
            .unwrap_or(2);
        let mut app = Self {
            shared: Arc::new(Mutex::new(None)),
            screen: Screen::Launcher,
            scan_rx: None,
            scanned: Vec::new(),
            unlock_path: String::new(),
            unlock_is_new: false,
            password: String::new(),
            password2: String::new(),
            keyfile: None,
            use_yk: false,
            unlock_error: None,
            launch_pending: launch_vault,
            cwd: "/".to_string(),
            items: Vec::new(),
            search_mode: false,
            search_input: String::new(),
            path_input: "/".to_string(),
            selected: HashSet::new(),
            vault_title: String::new(),
            busy: None,
            progress: None,
            bytes_progress: None,
            status: String::new(),
            modal: None,
            admin: None,
            audit: None,
            settings: None,
            lock_info: None,
            folders: Vec::new(),
            focus_search: false,
            preview: None,
            pending_preview_vpath: None,
            autolock_minutes,
            last_active: Instant::now(),
            close_confirmed: false,
        };
        if app.launch_pending.is_some() {
            app.consume_launch_target();
        } else {
            app.start_scan();
        }
        app
    }

    fn consume_launch_target(&mut self) {
        if let Some(p) = self.launch_pending.take() {
            let is_new = false;
            self.goto_unlock(p, is_new);
        }
    }

    fn start_scan(&mut self) {
        if self.scan_rx.is_none() {
            let (tx, rx) = mpsc::channel();
            self.scan_rx = Some(rx);
            self.scanned.clear();
            std::thread::spawn(move || {
                let mut found = Vec::new();
                for d in scan_candidate_dirs() {
                    found.extend(scan_vaults_in(&d.0));
                }
                found.sort_by_key(|s| std::cmp::Reverse(s.mtime));
                found.dedup_by(|a, b| a.path == b.path);
                let _ = tx.send(found);
            });
        }
    }

    fn goto_unlock(&mut self, path: String, is_new: bool) {
        self.unlock_path = path.clone();
        self.unlock_is_new = is_new;
        self.password.clear();
        self.password2.clear();
        self.keyfile = None;
        self.use_yk = false;
        self.unlock_error = None;
        self.lock_info = None;
        self.screen = Screen::Unlock;
        // 开锁前提示：该文件已被试错多少次 / 是否处于锁定冷却
        if !is_new {
            self.busy = Some(op_lock_info(path));
            self.progress = None;
            self.bytes_progress = None;
        }
    }

    fn vault_is_open(&self) -> bool {
        // 只 try_lock：后台长任务（导入/整理/体检）全程持锁，若在此阻塞等待，
        // UI 线程会整段卡死（进度条不刷新、按钮无响应）—— 与模块设计一致。
        // WouldBlock 说明有任务正在使用会话 → 保险柜必然处于打开状态。
        match self.shared.try_lock() {
            Ok(guard) => guard.is_some(),
            Err(std::sync::TryLockError::WouldBlock) => true,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner().is_some(),
        }
    }

    /// 全局入口闸门：后台任务进行中或模态框打开时，禁用一切新操作
    fn idle(&self) -> bool {
        self.busy.is_none() && self.modal.is_none()
    }

    fn navigate(&mut self, folder: &str) {
        match vault_core::Index::normalize_vpath(folder)
            .filter(|p| vault_core::Index::validate_vpath(p))
        {
            Some(norm) => {
                self.cwd = norm.clone();
                self.path_input = norm;
                self.selected.clear();
                self.search_mode = false;
                self.search_input.clear();
                self.launch_list();
            }
            None => self.status = "无效的目录路径".into(),
        }
    }

    fn launch_list(&mut self) {
        self.busy = Some(op_list(self.shared.clone(), self.cwd.clone()));
        self.progress = None;
        self.bytes_progress = None;
    }

    fn refresh(&mut self) {
        if self.search_mode {
            self.busy = Some(op_search(self.shared.clone(), self.search_input.clone()));
        } else {
            self.busy = Some(op_list(self.shared.clone(), self.cwd.clone()));
        }
        self.progress = None;
        self.bytes_progress = None;
    }

    // ───────────────── 每帧驱动 ─────────────────

    fn track_activity(&mut self, ctx: &egui::Context) {
        let active = ctx.input(|i| !i.raw.events.is_empty());
        if active {
            self.last_active = Instant::now();
        }
    }

    fn check_autolock(&mut self) {
        if self.screen != Screen::Main || !self.vault_is_open() || !self.idle() {
            return;
        }
        if self.autolock_minutes == 0 {
            return;
        }
        if self.last_active.elapsed() >= Duration::from_secs(self.autolock_minutes * 60) {
            // 与主界面同策略：未点「保存」的编辑缓冲直接丢弃（保险柜内容
            // 仍是旧版本，不存在半写损坏）；预览与模态全部关闭
            self.preview = None;
            self.modal = None;
            self.admin = None;
            self.audit = None;
            self.selected.clear();
            self.busy = Some(op_close(self.shared.clone()));
            self.status = format!("空闲超过 {} 分钟，保险柜已自动关闭", self.autolock_minutes);
            self.screen = Screen::Launcher;
            self.vault_title.clear();
            self.items.clear();
            self.start_scan();
        }
    }

    fn poll_busy(&mut self, ctx: &egui::Context) {
        // 启动扫描结果
        if self.screen == Screen::Launcher {
            if let Some(rx) = &self.scan_rx {
                match rx.try_recv() {
                    Ok(list) => {
                        self.scanned = list;
                        self.scan_rx = None;
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => self.scan_rx = None,
                }
            }
        }
        // take 出来轮询（避免 &mut self.busy 悬在循环里与 apply_finished 的
        // &mut self 冲突）；未收到 Finished 时放回
        let Some(busy) = self.busy.take() else {
            return;
        };
        let kind = busy.kind;
        let label = busy.label.clone();
        let mut finished: Option<Result<OpPayload, String>> = None;
        loop {
            match busy.rx.try_recv() {
                Ok(OpMsg::Progress(done, total)) => self.progress = Some((done, total)),
                Ok(OpMsg::Bytes(done, total)) => self.bytes_progress = Some((done, total)),
                Ok(OpMsg::Finished(payload)) => {
                    finished = Some(payload);
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.progress = None;
                    self.bytes_progress = None;
                    self.status = format!("{}：后台任务异常退出", label);
                    return;
                }
            }
        }
        match finished {
            Some(payload) => {
                self.progress = None;
                self.bytes_progress = None;
                self.apply_finished(kind, &label, payload, ctx);
            }
            None => {
                // 长任务期间保持重绘（进度条动起来）
                self.busy = Some(busy);
                ctx.request_repaint_after(Duration::from_millis(80));
            }
        }
    }

    fn apply_finished(
        &mut self,
        kind: OpKind,
        label: &str,
        payload: Result<OpPayload, String>,
        ctx: &egui::Context,
    ) {
        match payload {
            Err(e) => {
                if e == "OFFICE_ENCRYPTED" {
                    // 加密 Office 文档：弹出口令输入后重新预览
                    let vpath = self.pending_preview_vpath.take().unwrap_or_default();
                    self.preview = None;
                    self.modal = Some(Modal::OfficePw {
                        vpath,
                        name: String::new(),
                        password: String::new(),
                    });
                    return;
                }
                self.status = e;
                if kind == OpKind::Open || kind == OpKind::Create {
                    // 解锁失败：留在解锁页，错误已写入状态栏
                    self.screen = Screen::Unlock;
                }
                // 管理类操作：错误同时落在管理窗口内，避免只看状态栏漏掉
                if matches!(
                    kind,
                    OpKind::ChangePassword
                        | OpKind::AddPartition
                        | OpKind::RemovePartition
                        | OpKind::Defrag
                        | OpKind::Destroy
                        | OpKind::Verify
                        | OpKind::Audit
                        | OpKind::ListPartitions
                        | OpKind::Move
                        | OpKind::ListFolders
                        | OpKind::YkEnable
                        | OpKind::YkDisable
                        | OpKind::YkStatus
                ) {
                    if let Some(a) = &mut self.admin {
                        a.error = Some(self.status.clone());
                    }
                }
                if matches!(kind, OpKind::SettingsLoad | OpKind::SettingsSave) {
                    if let Some(s) = &mut self.settings {
                        s.loaded = true;
                        s.error = Some(self.status.clone());
                    }
                }
            }
            Ok(OpPayload::Summary(s)) => {
                self.status = s;
                match kind {
                    // 开柜 / 建柜成功：进入文件管理主界面并加载根目录
                    //（此前漏掉这一步 —— 状态栏显示「保险柜已打开」但画面停在解锁页）
                    OpKind::Open | OpKind::Create => {
                        self.screen = Screen::Main;
                        self.cwd = "/".to_string();
                        self.path_input = "/".to_string();
                        self.search_mode = false;
                        self.search_input.clear();
                        self.selected.clear();
                        self.preview = None;
                        self.modal = None;
                        self.admin = None;
                        self.audit = None;
                        self.items.clear();
                        self.vault_title = std::path::Path::new(&self.unlock_path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("LynVault")
                            .to_string();
                        self.last_active = Instant::now();
                        self.launch_list();
                    }
                    OpKind::Close => {
                        self.screen = Screen::Launcher;
                        self.vault_title.clear();
                        self.items.clear();
                        self.preview = None;
                        self.admin = None;
                        self.audit = None;
                        self.start_scan();
                    }
                    OpKind::NewFolder
                    | OpKind::Rename
                    | OpKind::Delete
                    | OpKind::Import
                    | OpKind::Extract => self.refresh(),
                    OpKind::SaveText => {
                        // 编辑基线已在窗口内更新（dirty=false），无需刷新列表
                    }
                    OpKind::ChangePassword => {
                        if let Some(a) = &mut self.admin {
                            a.cur_pw.clear();
                            a.new_pw.clear();
                            a.new_pw2.clear();
                            a.error = None;
                            a.notice = Some("密码已修改".into());
                        }
                    }
                    OpKind::AddPartition => {
                        if let Some(a) = &mut self.admin {
                            a.new_alias.clear();
                            a.new_alias_pw.clear();
                            a.error = None;
                            a.notice = Some("分区已添加".into());
                        }
                        self.busy = Some(op_list_partitions(self.shared.clone()));
                    }
                    OpKind::RemovePartition => {
                        if let Some(a) = &mut self.admin {
                            a.error = None;
                            a.notice = Some("分区已删除".into());
                        }
                        self.busy = Some(op_list_partitions(self.shared.clone()));
                    }
                    OpKind::Defrag => {
                        if let Some(a) = &mut self.admin {
                            a.error = None;
                            a.notice = Some("碎片整理完成".into());
                        }
                        self.refresh();
                    }
                    OpKind::Destroy => {
                        self.screen = Screen::Launcher;
                        self.vault_title.clear();
                        self.items.clear();
                        self.preview = None;
                        self.admin = None;
                        self.audit = None;
                        self.start_scan();
                    }
                    OpKind::Move => {
                        if let Some(a) = &mut self.admin {
                            a.error = None;
                        }
                        self.refresh();
                    }
                    OpKind::YkEnable | OpKind::YkDisable => {
                        let msg = self.status.clone();
                        if let Some(a) = &mut self.admin {
                            a.error = None;
                            a.notice = Some(msg);
                        }
                        self.busy = Some(op_yk_status(self.shared.clone()));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                    _ => {}
                }
            }
            Ok(OpPayload::Partitions(list)) => {
                if let Some(a) = &mut self.admin {
                    a.partitions = list;
                }
            }
            Ok(OpPayload::Audit(rows)) => {
                let n = rows.len();
                if let Some(a) = &mut self.audit {
                    a.entries = rows;
                }
                self.status = format!("操作记录：{} 条", n);
            }
            Ok(OpPayload::Folders(list)) => {
                let mut list = list;
                if !list.iter().any(|f| f == "/") {
                    list.insert(0, "/".to_string());
                }
                self.folders = list;
            }
            Ok(OpPayload::LockInfo {
                failed,
                locked,
                until,
            }) => {
                self.lock_info = Some((failed, locked, until));
            }
            Ok(OpPayload::Yubikey { enabled, present }) => {
                if let Some(a) = &mut self.admin {
                    a.yk = Some((enabled, present));
                    a.yk_requested = true;
                }
            }
            Ok(OpPayload::Settings(v)) => {
                self.autolock_minutes = v.autolock_minutes as u64;
                if let Some(s) = &mut self.settings {
                    s.autolock = v.autolock_minutes;
                    s.enabled = v.enabled;
                    s.location = v.location;
                    s.loaded = true;
                    s.notice = Some("设置已保存".into());
                    s.error = None;
                }
            }
            Ok(OpPayload::Verify { total, broken }) => {
                let (ok, msg) = if broken == 0 {
                    (true, format!("全部 {} 个文件校验通过，未发现损坏", total))
                } else {
                    (
                        false,
                        format!(
                            "发现 {} / {} 个文件异常，建议从外部备份重新导入（请勿删除保险柜文件）",
                            broken, total
                        ),
                    )
                };
                self.status = msg.clone();
                if let Some(a) = &mut self.admin {
                    a.verify = Some((ok, msg));
                    a.error = None;
                }
            }
            Ok(OpPayload::Listing(items)) => {
                self.items = items;
                self.status.clear();
            }
            Ok(OpPayload::Search(hits)) => {
                let n = hits.len();
                self.items = hits
                    .into_iter()
                    .map(|h| Item {
                        name: h.name,
                        vpath: h.vpath,
                        is_folder: h.is_dir,
                        size: if h.is_dir { None } else { Some(h.size) },
                    })
                    .collect();
                self.status = format!("搜索完成：{} 项", n);
            }
            Ok(OpPayload::Preview(data)) => match data {
                PreviewData::Image { name, rgba, size } => {
                    let handle = ctx.load_texture(
                        "preview_image",
                        egui::ColorImage::from_rgba_unmultiplied([size[0], size[1]], &rgba),
                        egui::TextureOptions::default(),
                    );
                    self.preview = Some(PreviewUi {
                        vpath: self.pending_preview_vpath.take().unwrap_or_default(),
                        name,
                        open: true,
                        text: String::new(),
                        kind: PreviewKind::Image {
                            handle: Some(handle),
                            size,
                        },
                    });
                    self.status.clear();
                }
                PreviewData::Text {
                    name,
                    vpath,
                    content,
                    editable,
                    note,
                } => {
                    self.preview = Some(PreviewUi {
                        vpath,
                        name,
                        open: true,
                        text: content,
                        kind: PreviewKind::Text {
                            editing: false,
                            editable,
                            dirty: false,
                            note,
                        },
                    });
                    self.status.clear();
                }
                PreviewData::Office { name, text } => {
                    self.preview = Some(PreviewUi {
                        vpath: String::new(),
                        name,
                        open: true,
                        text,
                        kind: PreviewKind::Office,
                    });
                    self.status.clear();
                }
                PreviewData::Notice { name, text } => {
                    self.preview = Some(PreviewUi {
                        vpath: String::new(),
                        name,
                        open: true,
                        text,
                        kind: PreviewKind::Notice,
                    });
                    self.status.clear();
                }
            },
        }
        let _ = label;
    }

    fn handle_drops(&mut self, ctx: &egui::Context) {
        if !self.idle() {
            return;
        }
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if dropped.is_empty() {
            return;
        }
        let paths: Vec<String> = dropped
            .iter()
            .filter_map(|f| f.path.as_ref().map(|p| p.to_string_lossy().into_owned()))
            .collect();
        if paths.is_empty() {
            return;
        }
        // 单个 .lyt / .vault：视为「打开保险柜」（与主界面拖放识别同语义）
        if paths.len() == 1 {
            let p = std::path::Path::new(&paths[0]);
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
                .unwrap_or_default();
            if (ext == "lyt" || ext == "vault") && vault_core::is_vault_file(p) {
                self.goto_unlock(paths[0].clone(), false);
                return;
            }
        }
        // 主界面：当作批量导入
        if self.screen == Screen::Main && self.vault_is_open() {
            self.busy = Some(op_import_files(
                self.shared.clone(),
                self.cwd.clone(),
                paths,
            ));
            self.progress = None;
            self.bytes_progress = None;
        }
    }

    // ───────────────── 渲染 ─────────────────

    /// 顶部标题栏（无边框窗口自绘）：品牌 + 当前保险柜 + 窗口控制按钮
    fn show_title_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("title_bar")
            .frame(
                egui::Frame::none()
                    .fill(theme::TITLEBAR_BG)
                    .inner_margin(egui::Margin {
                        left: 14.0,
                        right: 0.0,
                        top: 0.0,
                        bottom: 0.0,
                    }),
            )
            .exact_height(36.0)
            .show(ctx, |ui| {
                let panel = ui.max_rect();
                // 拖拽区：控制按钮以左的部分（双击切换最大化）
                let drag_rect = egui::Rect::from_min_max(
                    panel.min,
                    egui::pos2((panel.right() - 132.0).max(panel.left()), panel.bottom()),
                );
                let drag = ui.interact(
                    drag_rect,
                    ui.id().with("title_drag"),
                    egui::Sense::click_and_drag(),
                );
                if drag.dragged() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }
                if drag.double_clicked() {
                    let max = ctx.input(|i| i.viewport().maximized).unwrap_or(false);
                    ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!max));
                }
                ui.horizontal_centered(|ui| {
                    ui.label(
                        egui::RichText::new("LynVault")
                            .size(12.0)
                            .strong()
                            .color(theme::BRAND),
                    );
                    ui.label(
                        egui::RichText::new(concat!("v", env!("CARGO_PKG_VERSION")))
                            .size(10.0)
                            .color(theme::MUTED_LIGHT),
                    );
                    if !self.vault_title.is_empty() {
                        ui.label(
                            egui::RichText::new("·")
                                .size(10.0)
                                .color(theme::MUTED_LIGHT),
                        );
                        ui.label(
                            egui::RichText::new(&self.vault_title)
                                .size(11.0)
                                .color(theme::MUTED),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::window_control(ui, "×", true).clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        if theme::window_control(ui, "□", false).clicked() {
                            let max = ctx.input(|i| i.viewport().maximized).unwrap_or(false);
                            ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!max));
                        }
                        if theme::window_control(ui, "−", false).clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                        }
                    });
                });
            });
    }

    /// 底部状态栏
    fn show_status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar")
            .frame(
                egui::Frame::none()
                    .fill(theme::TITLEBAR_BG)
                    .inner_margin(egui::Margin::symmetric(14.0, 6.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if self.busy.is_some() {
                        ui.spinner();
                        if let Some((done, total)) = self.progress {
                            let frac = if total > 0 {
                                done as f32 / total as f32
                            } else {
                                0.0
                            };
                            ui.add(
                                egui::ProgressBar::new(frac)
                                    .show_percentage()
                                    .desired_width(180.0),
                            );
                            ui.label(
                                egui::RichText::new(format!("{}/{}", done, total))
                                    .size(11.0)
                                    .color(theme::MUTED),
                            );
                        } else if let Some((done, total)) = self.bytes_progress {
                            let frac = if total > 0 {
                                done as f32 / total as f32
                            } else {
                                0.0
                            };
                            ui.add(
                                egui::ProgressBar::new(frac)
                                    .show_percentage()
                                    .desired_width(180.0),
                            );
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}/{}",
                                    human_size(done),
                                    human_size(total)
                                ))
                                .size(11.0)
                                .color(theme::MUTED),
                            );
                        }
                    }
                    let text = if self.status.is_empty() {
                        format!("©绘萤者 LynVault {}", env!("CARGO_PKG_VERSION"))
                    } else {
                        self.status.clone()
                    };
                    ui.label(egui::RichText::new(text).size(11.0).color(theme::MUTED));
                    if self.screen == Screen::Main && self.modal.is_none() {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                egui::RichText::new(
                                    "双击进入目录 / 预览　·　右键更多操作　·　Ctrl+点击多选",
                                )
                                .size(10.5)
                                .color(theme::MUTED_LIGHT),
                            );
                        });
                    }
                });
            });
    }

    fn show_launcher(&mut self, ui: &mut egui::Ui) {
        theme::centered_card(ui, 560.0, 476.0, |ui| {
            ui.label(
                egui::RichText::new("🔐  检测到附近的保险柜")
                    .size(16.0)
                    .strong()
                    .color(theme::INK),
            );
            ui.label(
                egui::RichText::new("选择保险柜打开，或新建一个。也可以把 .lyt 文件拖入本窗口。")
                    .size(11.5)
                    .color(theme::MUTED),
            );
            ui.add_space(10.0);

            let footer = 50.0;
            let list_h = (ui.available_height() - footer).max(90.0);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(list_h)
                .show(ui, |ui| {
                    if self.scan_rx.is_some() {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(
                                egui::RichText::new("正在扫描常用目录…")
                                    .size(12.0)
                                    .color(theme::MUTED),
                            );
                        });
                    } else if self.scanned.is_empty() {
                        ui.add_space(22.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new(
                                    "未在常用目录（桌面 / 文档 / 下载 / 主目录）发现保险柜",
                                )
                                .size(12.0)
                                .color(theme::MUTED_LIGHT),
                            );
                        });
                        ui.add_space(22.0);
                    } else {
                        let scanned = self.scanned.clone();
                        for sv in &scanned {
                            let meta =
                                format!("{}　·　{}", epoch_str(sv.mtime), human_size(sv.size));
                            if theme::vault_row(ui, &sv.name, &meta).clicked() {
                                self.goto_unlock(sv.path.clone(), false);
                            }
                            ui.add_space(3.0);
                        }
                    }
                });

            ui.add_space(8.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let idle = self.idle();
                if theme::primary_button(ui, "新建保险柜", idle).clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("LynVault 保险柜", &["lyt"])
                        .set_file_name("新建保险柜.lyt")
                        .save_file()
                    {
                        self.goto_unlock(p.to_string_lossy().into_owned(), true);
                    }
                }
                if ui
                    .add_enabled(idle, egui::Button::new("打开其他保险柜"))
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("LynVault 保险柜", &["lyt", "vault"])
                        .pick_file()
                    {
                        self.goto_unlock(p.to_string_lossy().into_owned(), false);
                    }
                }
                if ui
                    .add_enabled(idle, egui::Button::new("重新扫描"))
                    .clicked()
                {
                    self.scan_rx = None;
                    self.start_scan();
                }
            });
        });
    }

    fn show_unlock(&mut self, ui: &mut egui::Ui) {
        let is_new = self.unlock_is_new;
        theme::centered_card(ui, 500.0, 430.0, |ui| {
            ui.label(
                egui::RichText::new(if is_new {
                    "新建保险柜"
                } else {
                    "打开保险柜"
                })
                .size(16.0)
                .strong()
                .color(theme::INK),
            );
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new("保险柜文件")
                    .size(11.0)
                    .color(theme::MUTED_LIGHT),
            );
            ui.add(
                egui::Label::new(
                    egui::RichText::new(&self.unlock_path)
                        .monospace()
                        .size(11.5)
                        .color(theme::INK_SOFT),
                )
                .wrap(),
            );
            // 开锁前提示：他人试错痕迹 / 临时锁定冷却
            if let Some((failed, locked, until)) = self.lock_info {
                if locked {
                    ui.label(
                        egui::RichText::new(format!(
                            "已临时锁定至 {}（请稍后再试）",
                            epoch_str(until as i64)
                        ))
                        .size(11.5)
                        .color(theme::DANGER),
                    );
                } else if failed > 0 {
                    ui.label(
                        egui::RichText::new(format!(
                            "该文件已被试错 {} 次（成功开柜后清零）",
                            failed
                        ))
                        .size(11.5)
                        .color(theme::DANGER),
                    );
                }
            }
            ui.add_space(10.0);

            // 回车提交在 Grid 闭包内置位（pw_resp 作用域仅限闭包内）
            let mut enter_submit = false;
            egui::Grid::new("unlock_grid")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("密码")
                            .size(12.0)
                            .color(theme::INK_SOFT),
                    );
                    let pw_resp = ui.add(
                        egui::TextEdit::singleline(&mut self.password)
                            .password(true)
                            .desired_width(300.0)
                            .hint_text(if is_new {
                                "至少 12 位"
                            } else {
                                "输入密码"
                            }),
                    );
                    if pw_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        enter_submit = true;
                    }
                    ui.end_row();

                    if is_new {
                        ui.label(
                            egui::RichText::new("确认密码")
                                .size(12.0)
                                .color(theme::INK_SOFT),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.password2)
                                .password(true)
                                .desired_width(300.0),
                        );
                        ui.end_row();
                    }

                    ui.label(
                        egui::RichText::new("密钥文件")
                            .size(12.0)
                            .color(theme::INK_SOFT),
                    );
                    ui.horizontal(|ui| {
                        let kf_display = self
                            .keyfile
                            .clone()
                            .unwrap_or_else(|| "（可选，双重认证）".into());
                        ui.label(
                            egui::RichText::new(kf_display)
                                .monospace()
                                .size(11.0)
                                .color(theme::MUTED),
                        );
                        if ui.small_button("选择…").clicked() {
                            if let Some(p) = rfd::FileDialog::new().pick_file() {
                                self.keyfile = Some(p.to_string_lossy().into_owned());
                            }
                        }
                        if self.keyfile.is_some() && ui.small_button("清除").clicked() {
                            self.keyfile = None;
                        }
                    });
                    ui.end_row();

                    if !is_new {
                        ui.label(
                            egui::RichText::new("硬件密钥")
                                .size(12.0)
                                .color(theme::INK_SOFT),
                        );
                        ui.checkbox(&mut self.use_yk, "使用 YubiKey 二因子解锁");
                        ui.end_row();
                    }
                });

            if let Some(err) = &self.unlock_error {
                ui.add_space(6.0);
                ui.label(egui::RichText::new(err).size(11.5).color(theme::DANGER));
            }

            ui.add_space(12.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let submit = theme::primary_button(
                    ui,
                    if is_new { "创建保险柜" } else { "解锁" },
                    self.idle(),
                )
                .clicked()
                    || enter_submit;
                if submit {
                    self.submit_unlock();
                }
                if ui
                    .add_enabled(self.idle(), egui::Button::new("返回"))
                    .clicked()
                {
                    // 口令不残留
                    self.password.clear();
                    self.password2.clear();
                    self.screen = Screen::Launcher;
                    self.start_scan();
                }
            });
        });
    }

    fn submit_unlock(&mut self) {
        if !self.idle() {
            return;
        }
        if self.unlock_is_new {
            if self.password.chars().count() < 12 {
                self.unlock_error = Some("密码长度至少 12 位".into());
                return;
            }
            if self.password != self.password2 {
                self.unlock_error = Some("两次输入的密码不一致".into());
                return;
            }
            self.unlock_error = None;
            let path = self.unlock_path.clone();
            let pw = std::mem::take(&mut self.password);
            let kf = self.keyfile.clone();
            self.busy = Some(op_create(self.shared.clone(), path, pw, kf));
            self.password.clear();
            self.password2.clear();
        } else {
            self.unlock_error = None;
            let path = self.unlock_path.clone();
            let pw = std::mem::take(&mut self.password);
            let kf = self.keyfile.clone();
            let yk = self.use_yk;
            self.busy = Some(op_open(self.shared.clone(), path, pw, kf, yk));
            self.password.clear();
        }
        self.progress = None;
        self.bytes_progress = None;
    }

    fn show_main(&mut self, ui: &mut egui::Ui) {
        // ── 导航带（↑ / 路径 / 刷新 / 搜索）──
        egui::Frame::none()
            .fill(theme::NAV_BG)
            .inner_margin(egui::Margin {
                left: 14.0,
                right: 14.0,
                top: 8.0,
                bottom: 10.0,
            })
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let idle = self.idle();
                    if ui
                        .add_enabled(idle && self.cwd != "/", egui::Button::new("↑"))
                        .on_hover_text("返回上级目录")
                        .clicked()
                    {
                        let parent = self
                            .cwd
                            .rsplit_once('/')
                            .map(|(p, _)| p.to_string())
                            .unwrap_or_else(|| "/".to_string());
                        self.navigate(&parent);
                    }
                    let path_w = (ui.available_width() - 360.0).max(140.0);
                    let path_resp = ui.add(
                        egui::TextEdit::singleline(&mut self.path_input)
                            .desired_width(path_w)
                            .hint_text("输入路径跳转，如 /docs"),
                    );
                    if path_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        let target = self.path_input.clone();
                        self.navigate(&target);
                    }
                    if ui.add_enabled(idle, egui::Button::new("刷新")).clicked() {
                        self.refresh();
                    }
                    let s_resp = ui.add(
                        egui::TextEdit::singleline(&mut self.search_input)
                            .desired_width(200.0)
                            .hint_text("🔍 搜索文件名…"),
                    );
                    if self.focus_search {
                        s_resp.request_focus();
                        self.focus_search = false;
                    }
                    if s_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        let q = self.search_input.trim().to_string();
                        if !q.is_empty() {
                            self.search_mode = true;
                            self.selected.clear();
                            self.busy = Some(op_search(self.shared.clone(), q));
                            self.progress = None;
                            self.bytes_progress = None;
                        }
                    }
                    if self.search_mode && ui.small_button("✕").on_hover_text("清除搜索").clicked()
                    {
                        self.search_mode = false;
                        self.search_input.clear();
                        self.selected.clear();
                        self.launch_list();
                    }
                });
            });

        // ── 工具栏带 ──
        egui::Frame::none()
            .fill(theme::TOOLBAR_BG)
            .inner_margin(egui::Margin {
                left: 14.0,
                right: 14.0,
                top: 8.0,
                bottom: 8.0,
            })
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let idle = self.idle();
                    let has_sel = !self.selected.is_empty();
                    if ui
                        .add_enabled(idle, egui::Button::new("导入文件"))
                        .clicked()
                    {
                        if let Some(paths) = rfd::FileDialog::new().pick_files() {
                            let strs: Vec<String> = paths
                                .iter()
                                .map(|p| p.to_string_lossy().into_owned())
                                .collect();
                            if !strs.is_empty() {
                                self.busy = Some(op_import_files(
                                    self.shared.clone(),
                                    self.cwd.clone(),
                                    strs,
                                ));
                                self.progress = None;
                                self.bytes_progress = None;
                            }
                        }
                    }
                    if ui
                        .add_enabled(idle, egui::Button::new("导入文件夹"))
                        .clicked()
                    {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            self.busy = Some(op_import_folder(
                                self.shared.clone(),
                                self.cwd.clone(),
                                p.to_string_lossy().into_owned(),
                            ));
                            self.progress = None;
                            self.bytes_progress = None;
                        }
                    }
                    if ui
                        .add_enabled(idle, egui::Button::new("新建文件夹"))
                        .clicked()
                    {
                        self.modal = Some(Modal::NewFolder(String::new()));
                    }
                    if ui
                        .add_enabled(
                            idle && has_sel && self.selected.len() == 1,
                            egui::Button::new("重命名"),
                        )
                        .clicked()
                    {
                        if let Some(vpath) = self.selected.iter().next().cloned() {
                            if let Some(item) = self.items.iter().find(|i| i.vpath == vpath) {
                                self.modal = Some(Modal::Rename {
                                    vpath: vpath.clone(),
                                    name: item.name.clone(),
                                    is_folder: item.is_folder,
                                });
                            }
                        }
                    }
                    if ui
                        .add_enabled(idle && has_sel, egui::Button::new("删除"))
                        .clicked()
                    {
                        self.modal = Some(Modal::ConfirmDelete(
                            self.selected.iter().cloned().collect(),
                        ));
                    }
                    if ui
                        .add_enabled(idle && has_sel, egui::Button::new("移动到…"))
                        .clicked()
                    {
                        self.folders.clear();
                        self.busy = Some(op_list_folders(self.shared.clone()));
                        self.progress = None;
                        self.bytes_progress = None;
                        self.modal = Some(Modal::MoveTo {
                            vpaths: self.selected.iter().cloned().collect(),
                            dest: self.cwd.clone(),
                        });
                    }
                    if ui
                        .add_enabled(idle && has_sel, egui::Button::new("提取选中…"))
                        .clicked()
                    {
                        let targets: Vec<String> = self.selected.iter().cloned().collect();
                        if let Some(dest) = rfd::FileDialog::new()
                            .set_title("选择提取目标目录")
                            .pick_folder()
                        {
                            self.busy = Some(op_extract(
                                self.shared.clone(),
                                targets,
                                dest.to_string_lossy().into_owned(),
                            ));
                            self.progress = None;
                            self.bytes_progress = None;
                        }
                    }
                    if ui
                        .add_enabled(idle, egui::Button::new("提取全部…"))
                        .clicked()
                    {
                        if let Some(dest) = rfd::FileDialog::new()
                            .set_title("选择提取目标父目录")
                            .pick_folder()
                        {
                            let dest_parent = dest.to_string_lossy().into_owned();
                            // 与主界面一致：提取全部在「父目录/保险柜文件名」子文件夹中进行，
                            // 已存在时确认覆盖
                            let stem = {
                                let guard = self.shared.lock().unwrap_or_else(|p| p.into_inner());
                                guard
                                    .as_ref()
                                    .and_then(|v| v.get_path().map(super::export_stem))
                                    .unwrap_or_else(|| "LynVault_Export".into())
                            };
                            let dest_dir = std::path::Path::new(&dest_parent).join(&stem);
                            if dest_dir.exists() {
                                self.modal = Some(Modal::ConfirmOverwriteAll { dest_parent });
                            } else {
                                self.busy =
                                    Some(op_extract_all(self.shared.clone(), dest_parent, false));
                                self.progress = None;
                                self.bytes_progress = None;
                            }
                        }
                    }
                    theme::toolbar_sep(ui);
                    if ui
                        .add_enabled(idle, egui::Button::new("保险柜管理…"))
                        .clicked()
                    {
                        self.admin = Some(AdminUi::new());
                        self.busy = Some(op_list_partitions(self.shared.clone()));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                    if ui
                        .add_enabled(idle, egui::Button::new("操作记录"))
                        .clicked()
                    {
                        self.audit = Some(AuditUi {
                            open: true,
                            entries: Vec::new(),
                        });
                        self.busy = Some(op_audit(self.shared.clone(), 500));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                    if ui.add_enabled(idle, egui::Button::new("设置")).clicked() {
                        // 读取动作由设置窗口首次渲染时发起（避免重复请求）
                        self.settings = Some(SettingsUi::new());
                    }
                    theme::toolbar_sep(ui);
                    if ui
                        .add_enabled(idle, egui::Button::new("关闭保险柜"))
                        .clicked()
                    {
                        self.preview = None;
                        self.modal = None;
                        self.admin = None;
                        self.audit = None;
                        self.selected.clear();
                        self.busy = Some(op_close(self.shared.clone()));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                });
            });

        // ── 文件列表卡片 ──
        egui::Frame::none()
            .inner_margin(egui::Margin {
                left: 10.0,
                right: 10.0,
                top: 0.0,
                bottom: 10.0,
            })
            .show(ui, |ui| {
                theme::list_frame().show(ui, |ui| {
                    if self.search_mode {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!(
                                    "搜索结果（全库，当前目录：{}）",
                                    self.cwd
                                ))
                                .size(11.0)
                                .color(theme::MUTED),
                            );
                        });
                        ui.separator();
                    }

                    let mut action: Option<RowAction> = None;
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            if self.items.is_empty() {
                                let h = (ui.available_height() / 2.0 - 30.0).max(20.0);
                                ui.add_space(h);
                                ui.vertical_centered(|ui| {
                                    ui.label(
                                        egui::RichText::new("📄")
                                            .size(28.0)
                                            .color(theme::MUTED_LIGHT),
                                    );
                                    ui.add_space(4.0);
                                    ui.label(
                                        egui::RichText::new(if self.search_mode {
                                            "没有匹配的文件"
                                        } else {
                                            "将文件拖放至此，或用上方按钮导入"
                                        })
                                        .size(12.0)
                                        .color(theme::MUTED_LIGHT),
                                    );
                                });
                                return;
                            }
                            for idx in 0..self.items.len() {
                                let it = self.items[idx].clone();
                                let is_sel = self.selected.contains(&it.vpath);
                                let size_str = if it.is_folder {
                                    None
                                } else {
                                    Some(human_size(it.size.unwrap_or(0)))
                                };
                                let resp = theme::file_row(
                                    ui,
                                    theme::file_icon(&it.name, it.is_folder),
                                    &it.name,
                                    size_str.as_deref(),
                                    is_sel,
                                );
                                if resp.clicked() {
                                    let additive = ui.input(|i| {
                                        i.modifiers.command || i.modifiers.ctrl || i.modifiers.shift
                                    });
                                    if additive {
                                        if is_sel {
                                            self.selected.remove(&it.vpath);
                                        } else {
                                            self.selected.insert(it.vpath.clone());
                                        }
                                    } else {
                                        self.selected.clear();
                                        self.selected.insert(it.vpath.clone());
                                    }
                                }
                                if resp.double_clicked() {
                                    if it.is_folder {
                                        action = Some(RowAction::Enter(it.vpath.clone()));
                                    } else {
                                        action = Some(RowAction::Preview(it.vpath.clone()));
                                    }
                                }
                                resp.context_menu(|ui| {
                                    if it.is_folder && ui.button("进入").clicked() {
                                        action = Some(RowAction::Enter(it.vpath.clone()));
                                        ui.close_menu();
                                    }
                                    if !it.is_folder && ui.button("预览").clicked() {
                                        action = Some(RowAction::Preview(it.vpath.clone()));
                                        ui.close_menu();
                                    }
                                    if ui.button("重命名").clicked() {
                                        action = Some(RowAction::Rename(
                                            it.vpath.clone(),
                                            it.name.clone(),
                                            it.is_folder,
                                        ));
                                        ui.close_menu();
                                    }
                                    if ui.button("删除").clicked() {
                                        action = Some(RowAction::Delete(vec![it.vpath.clone()]));
                                        ui.close_menu();
                                    }
                                    if ui.button("提取…").clicked() {
                                        action = Some(RowAction::Extract(vec![it.vpath.clone()]));
                                        ui.close_menu();
                                    }
                                    if ui.button("移动到…").clicked() {
                                        action = Some(RowAction::Move(vec![it.vpath.clone()]));
                                        ui.close_menu();
                                    }
                                });
                            }
                        });

                    match action {
                        Some(RowAction::Enter(v)) => self.navigate(&v),
                        Some(RowAction::Preview(v)) => self.start_preview(v),
                        Some(RowAction::Rename(v, n, f)) => {
                            self.modal = Some(Modal::Rename {
                                vpath: v,
                                name: n,
                                is_folder: f,
                            });
                        }
                        Some(RowAction::Delete(vs)) => {
                            self.modal = Some(Modal::ConfirmDelete(vs));
                        }
                        Some(RowAction::Extract(vs)) => {
                            if let Some(dest) = rfd::FileDialog::new()
                                .set_title("选择提取目标目录")
                                .pick_folder()
                            {
                                self.busy = Some(op_extract(
                                    self.shared.clone(),
                                    vs,
                                    dest.to_string_lossy().into_owned(),
                                ));
                                self.progress = None;
                                self.bytes_progress = None;
                            }
                        }
                        Some(RowAction::Move(vs)) => {
                            self.folders.clear();
                            self.busy = Some(op_list_folders(self.shared.clone()));
                            self.progress = None;
                            self.bytes_progress = None;
                            self.modal = Some(Modal::MoveTo {
                                vpaths: vs,
                                dest: self.cwd.clone(),
                            });
                        }
                        None => {}
                    }
                });
            });
    }

    fn start_preview(&mut self, vpath: String) {
        if !self.idle() {
            return;
        }
        self.pending_preview_vpath = Some(vpath.clone());
        self.busy = Some(op_preview(self.shared.clone(), vpath, None));
        self.progress = None;
        self.bytes_progress = None;
    }

    // ───────────────── 管理窗口（分区 / 改密 / 体检 / 整理 / 销毁）─────────────────

    fn show_admin(&mut self, ctx: &egui::Context) {
        let Some(mut admin) = self.admin.take() else {
            return;
        };
        let mut open = admin.open;
        egui::Window::new("保险柜管理")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .vscroll(true)
            .default_width(540.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                let idle = self.idle();

                if let Some(n) = &admin.notice {
                    ui.colored_label(theme::SUCCESS, n);
                }
                if let Some(e) = &admin.error {
                    ui.colored_label(theme::DANGER, e);
                }

                // ── 分区 ──
                ui.heading("分区");
                ui.horizontal(|ui| {
                    if ui.add_enabled(idle, egui::Button::new("刷新")).clicked() {
                        self.busy = Some(op_list_partitions(self.shared.clone()));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                    ui.weak("当前分区与主分区不可删除");
                });
                if admin.partitions.is_empty() {
                    ui.weak("（未读取到分区信息）");
                } else {
                    for p in &admin.partitions {
                        ui.horizontal(|ui| {
                            let mut label = p.alias.clone();
                            if p.primary {
                                label.push_str("（主分区）");
                            }
                            if p.active {
                                label.push_str("（当前）");
                            }
                            ui.label(label);
                            let deletable = !p.primary && !p.active;
                            if ui
                                .add_enabled(
                                    idle && deletable,
                                    egui::Button::new(
                                        egui::RichText::new("删除").color(theme::DANGER).small(),
                                    ),
                                )
                                .clicked()
                            {
                                self.modal = Some(Modal::ConfirmRemovePartition(p.alias.clone()));
                            }
                        });
                    }
                }
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("新分区别名");
                    ui.add(egui::TextEdit::singleline(&mut admin.new_alias).desired_width(150.0));
                });
                ui.horizontal(|ui| {
                    ui.label("分区密码");
                    ui.add(
                        egui::TextEdit::singleline(&mut admin.new_alias_pw)
                            .password(true)
                            .desired_width(220.0)
                            .hint_text("至少 12 位"),
                    );
                    if ui
                        .add_enabled(idle, egui::Button::new("添加分区"))
                        .clicked()
                    {
                        let alias = admin.new_alias.trim().to_string();
                        if alias.is_empty() {
                            admin.error = Some("分区别名不能为空".into());
                        } else if admin.new_alias_pw.chars().count() < 12 {
                            admin.error = Some("分区密码长度至少 12 位".into());
                        } else {
                            let pw = std::mem::take(&mut admin.new_alias_pw);
                            admin.error = None;
                            self.busy =
                                Some(op_add_partition(self.shared.clone(), alias, pw, None));
                            self.progress = None;
                            self.bytes_progress = None;
                        }
                    }
                });

                ui.separator();

                // ── 修改密码 ──
                ui.heading("修改密码");
                egui::Grid::new("admin_pw_grid")
                    .num_columns(2)
                    .spacing([10.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("当前密码");
                        ui.add(
                            egui::TextEdit::singleline(&mut admin.cur_pw)
                                .password(true)
                                .desired_width(280.0),
                        );
                        ui.end_row();
                        ui.label("新密码");
                        ui.add(
                            egui::TextEdit::singleline(&mut admin.new_pw)
                                .password(true)
                                .desired_width(280.0)
                                .hint_text("至少 12 位"),
                        );
                        ui.end_row();
                        ui.label("确认新密码");
                        ui.add(
                            egui::TextEdit::singleline(&mut admin.new_pw2)
                                .password(true)
                                .desired_width(280.0),
                        );
                        ui.end_row();
                        ui.label("密钥文件");
                        ui.horizontal(|ui| {
                            let disp = admin
                                .keyfile
                                .clone()
                                .unwrap_or_else(|| "（可选，与开柜时一致）".into());
                            ui.monospace(disp);
                            if ui.small_button("选择…").clicked() {
                                if let Some(p) = rfd::FileDialog::new().pick_file() {
                                    admin.keyfile = Some(p.to_string_lossy().into_owned());
                                }
                            }
                            if admin.keyfile.is_some() && ui.small_button("清除").clicked() {
                                admin.keyfile = None;
                            }
                        });
                        ui.end_row();
                    });
                if ui
                    .add_enabled(idle, egui::Button::new("修改密码"))
                    .clicked()
                {
                    if admin.new_pw.chars().count() < 12 {
                        admin.error = Some("新密码长度至少 12 位".into());
                    } else if admin.new_pw != admin.new_pw2 {
                        admin.error = Some("两次输入的新密码不一致".into());
                    } else {
                        let cur = std::mem::take(&mut admin.cur_pw);
                        let new = std::mem::take(&mut admin.new_pw);
                        admin.new_pw2.clear();
                        admin.error = None;
                        self.busy = Some(op_change_password(
                            self.shared.clone(),
                            cur,
                            new,
                            admin.keyfile.clone(),
                        ));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                }

                ui.separator();

                // ── 硬件密钥二因子 ──
                ui.heading("硬件密钥（YubiKey）");
                if admin.yk.is_none() {
                    if !admin.yk_requested && self.busy.is_none() {
                        admin.yk_requested = true;
                        self.busy = Some(op_yk_status(self.shared.clone()));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                    ui.weak(if admin.yk_requested && self.busy.is_none() {
                        "状态未知（可点击下方「刷新」重试）"
                    } else {
                        "正在读取状态…"
                    });
                } else if let Some((enabled, present)) = admin.yk {
                    ui.label(if enabled {
                        "二因子：已启用（开柜需插入钥匙并触摸）"
                    } else {
                        "二因子：未启用"
                    });
                    ui.weak(if present {
                        "设备：已在位"
                    } else {
                        "设备：未检测到（启用 / 解除都需要实体钥匙在位）"
                    });
                }
                ui.horizontal(|ui| {
                    ui.label("当前密码");
                    ui.add(
                        egui::TextEdit::singleline(&mut admin.yk_pw)
                            .password(true)
                            .desired_width(200.0),
                    );
                    if ui.add_enabled(idle, egui::Button::new("刷新")).clicked() {
                        admin.yk = None;
                        admin.yk_requested = true;
                        self.busy = Some(op_yk_status(self.shared.clone()));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                });
                let yk_enabled = admin.yk.map(|(e, _)| e).unwrap_or(false);
                if ui
                    .add_enabled(
                        idle && !admin.yk_pw.is_empty(),
                        egui::Button::new(if yk_enabled {
                            "解除二因子（需触摸钥匙）"
                        } else {
                            "启用二因子（需触摸钥匙）"
                        }),
                    )
                    .clicked()
                {
                    let pw = std::mem::take(&mut admin.yk_pw);
                    admin.error = None;
                    admin.notice = None;
                    self.busy = Some(op_yk_set(
                        self.shared.clone(),
                        !yk_enabled,
                        pw,
                        admin.keyfile.clone(),
                    ));
                    self.progress = None;
                    self.bytes_progress = None;
                }

                ui.separator();

                // ── 维护 ──
                ui.heading("维护");
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(idle, egui::Button::new("完整性体检"))
                        .clicked()
                    {
                        admin.verify = None;
                        self.busy = Some(op_verify(self.shared.clone()));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                    if ui
                        .add_enabled(idle, egui::Button::new("整理保险柜…"))
                        .clicked()
                    {
                        self.modal = Some(Modal::ConfirmDefrag);
                    }
                });
                if let Some((ok, msg)) = &admin.verify {
                    ui.colored_label(if *ok { theme::SUCCESS } else { theme::DANGER }, msg);
                }
                ui.weak("体检为只读；整理会重建文件并擦除旧数据区，期间请勿中断。");

                ui.separator();

                // ── 危险操作 ──
                ui.heading("危险操作");
                if ui
                    .add_enabled(
                        idle,
                        egui::Button::new(egui::RichText::new("销毁保险箱…").color(theme::DANGER)),
                    )
                    .clicked()
                {
                    self.modal = Some(Modal::ConfirmDestroy { stage: 1 });
                }
                ui.weak("销毁将不可逆地擦除整个保险柜文件。");
            });
        admin.open = open;
        if admin.open {
            self.admin = Some(admin);
        }
    }

    fn show_audit(&mut self, ctx: &egui::Context) {
        let Some(mut audit) = self.audit.take() else {
            return;
        };
        let mut open = audit.open;
        let mut reload = false;
        egui::Window::new("操作记录（最近 500 条，最新在前）")
            .open(&mut open)
            .collapsible(false)
            .default_width(640.0)
            .default_height(420.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.idle(), egui::Button::new("刷新"))
                        .clicked()
                    {
                        reload = true;
                    }
                    ui.weak("记录由链式 HMAC 保护：任何篡改都会被检测并截断。");
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if audit.entries.is_empty() {
                            ui.weak("暂无记录");
                        }
                        for e in &audit.entries {
                            ui.horizontal(|ui| {
                                ui.monospace(epoch_str(e.ts as i64));
                                ui.label(&e.event);
                            });
                        }
                    });
            });
        if reload {
            self.busy = Some(op_audit(self.shared.clone(), 500));
            self.progress = None;
            self.bytes_progress = None;
        }
        audit.open = open;
        if audit.open {
            self.audit = Some(audit);
        }
    }

    // ───────────────── 模态框 ─────────────────

    fn show_modal(&mut self, ctx: &egui::Context) {
        // 注意：`open` 被 .open(&mut open) 独占借用，闭包内不能直接写 open ——
        // 闭包只置位 close/submit 标志，借用结束后统一回收（egui 借用规则）
        let Some(mut modal) = self.modal.take() else {
            return;
        };
        let mut reopen: Option<Modal> = None;
        match &mut modal {
            Modal::NewFolder(name) => {
                let mut open = true;
                let mut close = false;
                let mut submit = false;
                egui::Window::new("新建文件夹")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label("文件夹名称");
                        let r = ui.add(egui::TextEdit::singleline(name).desired_width(280.0));
                        submit = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("创建").clicked() {
                                submit = true;
                            }
                            if ui.button("取消").clicked() {
                                close = true;
                            }
                        });
                    });
                if close {
                    open = false;
                }
                if submit {
                    let name = name.trim().to_string();
                    if name.is_empty() {
                        reopen = Some(Modal::NewFolder(name));
                        self.status = "文件夹名称不能为空".into();
                    } else {
                        self.busy =
                            Some(op_new_folder(self.shared.clone(), self.cwd.clone(), name));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                } else if open {
                    reopen = Some(modal);
                }
            }
            Modal::Rename {
                vpath,
                name,
                is_folder,
            } => {
                let mut open = true;
                let mut close = false;
                let mut submit = false;
                // 闭包内只读展示用克隆（&mut String 会被闭包按值捕获导致后续无法使用）
                let vpath_disp = vpath.clone();
                egui::Window::new("重命名")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.monospace(&vpath_disp);
                        ui.add_space(4.0);
                        ui.label("新名称");
                        let r = ui.add(egui::TextEdit::singleline(name).desired_width(280.0));
                        submit = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("确定").clicked() {
                                submit = true;
                            }
                            if ui.button("取消").clicked() {
                                close = true;
                            }
                        });
                    });
                if close {
                    open = false;
                }
                if submit {
                    let new_name = name.trim().to_string();
                    if new_name.is_empty() {
                        reopen = Some(Modal::Rename {
                            vpath: vpath.clone(),
                            name: new_name,
                            is_folder: *is_folder,
                        });
                        self.status = "名称不能为空".into();
                    } else {
                        self.busy = Some(op_rename(
                            self.shared.clone(),
                            vpath.clone(),
                            new_name,
                            *is_folder,
                        ));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                } else if open {
                    reopen = Some(modal);
                }
            }
            Modal::ConfirmDelete(vpaths) => {
                let mut open = true;
                let mut close = false;
                let mut confirm = false;
                egui::Window::new("确认安全删除")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.colored_label(
                            theme::DANGER,
                            format!("将安全删除 {} 个选中项（文件夹会整体展开）。", vpaths.len()),
                        );
                        ui.weak(
                            "删除顺序：索引先落盘，再对密文区域 DoD 7-pass 覆写。此操作不可恢复。",
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui
                                .button(egui::RichText::new("确认删除").color(theme::DANGER))
                                .clicked()
                            {
                                confirm = true;
                            }
                            if ui.button("取消").clicked() {
                                close = true;
                            }
                        });
                    });
                if close {
                    open = false;
                }
                if confirm {
                    self.busy = Some(op_delete(self.shared.clone(), vpaths.clone()));
                    self.progress = None;
                    self.bytes_progress = None;
                } else if open {
                    reopen = Some(modal);
                }
            }
            Modal::ConfirmOverwriteAll { dest_parent } => {
                let mut open = true;
                let mut close = false;
                let mut overwrite = false;
                egui::Window::new("目标文件夹已存在")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label("提取目标子文件夹已存在。覆盖合并，还是取消？");
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("覆盖提取").clicked() {
                                overwrite = true;
                            }
                            if ui.button("取消").clicked() {
                                close = true;
                            }
                        });
                    });
                if close {
                    open = false;
                }
                if overwrite {
                    self.busy = Some(op_extract_all(
                        self.shared.clone(),
                        dest_parent.clone(),
                        true,
                    ));
                    self.progress = None;
                    self.bytes_progress = None;
                } else if open {
                    reopen = Some(modal);
                }
            }
            Modal::OfficePw {
                vpath,
                name,
                password,
            } => {
                let mut open = true;
                let mut close = false;
                let mut submit = false;
                let vpath_disp = vpath.clone();
                let name_disp = if name.is_empty() {
                    "该 Office 文档设置了打开密码，请输入口令预览（纯内存解密，不落盘）".to_string()
                } else {
                    name.clone()
                };
                egui::Window::new("加密文档")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.monospace(&vpath_disp);
                        ui.label(name_disp.as_str());
                        let r = ui.add(
                            egui::TextEdit::singleline(password)
                                .password(true)
                                .desired_width(280.0),
                        );
                        submit = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("解密预览").clicked() {
                                submit = true;
                            }
                            if ui.button("取消").clicked() {
                                close = true;
                            }
                        });
                    });
                if close {
                    open = false;
                }
                if submit {
                    let pw = std::mem::take(password);
                    let vpath = vpath.clone();
                    self.pending_preview_vpath = Some(vpath.clone());
                    self.busy = Some(op_preview(self.shared.clone(), vpath, Some(pw)));
                    self.progress = None;
                    self.bytes_progress = None;
                } else if open {
                    reopen = Some(modal);
                }
            }
            Modal::ConfirmRemovePartition(alias) => {
                let mut open = true;
                let mut close = false;
                let mut confirm = false;
                let alias_disp = alias.clone();
                egui::Window::new("删除分区")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label(format!("将从头部移除分区「{}」的条目并擦除其索引区。", alias_disp));
                        ui.weak(
                            "该分区的文件密文因无分区密码无法定位，会原地残留（保险柜整体销毁时一并擦除）。",
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui
                                .button(
                                    egui::RichText::new("确认删除")
                                        .color(theme::DANGER),
                                )
                                .clicked()
                            {
                                confirm = true;
                            }
                            if ui.button("取消").clicked() {
                                close = true;
                            }
                        });
                    });
                if close {
                    open = false;
                }
                if confirm {
                    self.busy = Some(op_remove_partition(self.shared.clone(), alias.clone()));
                    self.progress = None;
                    self.bytes_progress = None;
                } else if open {
                    reopen = Some(modal);
                }
            }
            Modal::ConfirmDefrag => {
                let mut open = true;
                let mut close = false;
                let mut confirm = false;
                egui::Window::new("整理保险柜")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label("整理会重建保险柜文件，并对旧数据区做 DoD 7-pass 覆写。");
                        ui.weak("大保险柜需要一些时间，期间请勿关闭窗口或中断电源。");
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("开始整理").clicked() {
                                confirm = true;
                            }
                            if ui.button("取消").clicked() {
                                close = true;
                            }
                        });
                    });
                if close {
                    open = false;
                }
                if confirm {
                    self.busy = Some(op_defragment(self.shared.clone()));
                    self.progress = None;
                    self.bytes_progress = None;
                } else if open {
                    reopen = Some(modal);
                }
            }
            Modal::ConfirmDestroy { stage } => {
                let mut open = true;
                let mut close = false;
                let mut next = false;
                let mut destroy = false;
                egui::Window::new(if *stage <= 1 {
                    "销毁保险箱"
                } else {
                    "最终确认"
                })
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    if *stage <= 1 {
                        ui.colored_label(
                            theme::DANGER,
                            "此操作将不可逆地销毁当前保险柜及其所有数据！",
                        );
                    } else {
                        ui.colored_label(theme::DANGER, "再次确认：销毁整个保险柜？");
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui
                            .button(if *stage <= 1 {
                                "继续"
                            } else {
                                "确认销毁"
                            })
                            .clicked()
                        {
                            if *stage <= 1 {
                                next = true;
                            } else {
                                destroy = true;
                            }
                        }
                        if ui.button("取消").clicked() {
                            close = true;
                        }
                    });
                });
                if close {
                    open = false;
                }
                if next {
                    reopen = Some(Modal::ConfirmDestroy { stage: 2 });
                } else if destroy {
                    self.busy = Some(op_destroy(self.shared.clone()));
                    self.progress = None;
                    self.bytes_progress = None;
                } else if open {
                    reopen = Some(modal);
                }
            }
            Modal::MoveTo { vpaths, dest } => {
                let mut open = true;
                let mut close = false;
                let mut confirm = false;
                let count = vpaths.len();
                egui::Window::new("移动到…")
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(true)
                    .default_width(460.0)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label(format!("将移动 {} 个选中项到：", count));
                        ui.add(
                            egui::TextEdit::singleline(dest)
                                .desired_width(380.0)
                                .hint_text("/目标目录"),
                        );
                        ui.add_space(4.0);
                        ui.separator();
                        egui::ScrollArea::vertical()
                            .max_height(210.0)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                if self.folders.is_empty() {
                                    ui.weak("正在读取文件夹列表…");
                                }
                                for f in &self.folders {
                                    let label = if f == "/" {
                                        "根目录 /".to_string()
                                    } else {
                                        f.clone()
                                    };
                                    if ui.selectable_label(dest == f, label).clicked() {
                                        *dest = f.clone();
                                    }
                                }
                            });
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("移动").clicked() {
                                confirm = true;
                            }
                            if ui.button("取消").clicked() {
                                close = true;
                            }
                        });
                    });
                if close {
                    open = false;
                }
                if confirm {
                    self.busy = Some(op_move(
                        self.shared.clone(),
                        vpaths.clone(),
                        dest.trim().to_string(),
                    ));
                    self.progress = None;
                    self.bytes_progress = None;
                } else if open {
                    reopen = Some(modal);
                }
            }
        }
        self.modal = reopen;
    }

    // ───────────────── 设置窗口 ─────────────────

    fn show_settings(&mut self, ctx: &egui::Context) {
        let Some(mut s) = self.settings.take() else {
            return;
        };
        if !s.requested {
            s.requested = true;
            self.busy = Some(op_settings_load());
            self.progress = None;
            self.bytes_progress = None;
        }
        let mut open = s.open;
        egui::Window::new("设置")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(420.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                let idle = self.idle();
                if let Some(n) = &s.notice {
                    ui.colored_label(theme::ACCENT_A, n);
                }
                if let Some(e) = &s.error {
                    ui.colored_label(theme::DANGER, e);
                }

                ui.heading("自动锁定");
                ui.horizontal(|ui| {
                    ui.label("空闲超过");
                    ui.add(
                        egui::DragValue::new(&mut s.autolock)
                            .range(0..=240)
                            .speed(0.2)
                            .suffix(" 分钟"),
                    );
                    ui.weak("0 = 禁用（不推荐）");
                });
                ui.weak("长时间无键鼠输入后自动关闭保险柜（密钥清零 + 审计落盘）。");

                ui.separator();
                ui.heading("配置持久化");
                match &s.location {
                    Some(loc) if s.enabled => {
                        ui.label(egui::RichText::new(format!("已启用：{}", loc)).size(12.0));
                        ui.weak("主题 / 自动锁定 / 窗口尺寸等设置会随程序保存。");
                    }
                    _ => {
                        ui.label("当前未启用持久化，设置仅在本次运行内有效。");
                        ui.weak("请选择保存位置（便携模式可用 U 盘携带）。");
                    }
                }

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if theme::primary_button(ui, "保存设置", idle).clicked() {
                        s.notice = None;
                        s.error = None;
                        self.busy = Some(op_settings_save(s.autolock, None));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                    if ui
                        .add_enabled(idle, egui::Button::new("启用为便携模式"))
                        .on_hover_text("配置文件写在程序所在目录，可随 U 盘携带")
                        .clicked()
                    {
                        s.notice = None;
                        s.error = None;
                        self.busy = Some(op_settings_save(
                            s.autolock,
                            Some(crate::settings::ConfigLocation::Portable),
                        ));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                    if ui
                        .add_enabled(idle, egui::Button::new("启用为固定安装"))
                        .on_hover_text("配置文件写到用户配置目录，适合安装到只读位置")
                        .clicked()
                    {
                        s.notice = None;
                        s.error = None;
                        self.busy = Some(op_settings_save(
                            s.autolock,
                            Some(crate::settings::ConfigLocation::AppData),
                        ));
                        self.progress = None;
                        self.bytes_progress = None;
                    }
                });

                ui.separator();
                ui.weak(format!("LynVault {} · GUI 版", env!("CARGO_PKG_VERSION")));
            });
        s.open = open;
        if s.open {
            self.settings = Some(s);
        }
    }

    /// 主界面快捷键：F5 刷新 / Ctrl+F 搜索 / Delete 删除 / Enter 打开 / Backspace 上级
    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        if self.screen != Screen::Main {
            return;
        }
        let typing = ctx.memory(|m| m.focused().is_some());
        let (f5, ctrl_f, del, enter, back) = ctx.input(|i| {
            (
                i.key_pressed(egui::Key::F5),
                i.modifiers.command && i.key_pressed(egui::Key::F),
                i.key_pressed(egui::Key::Delete),
                i.key_pressed(egui::Key::Enter),
                i.key_pressed(egui::Key::Backspace),
            )
        });
        if f5 && self.idle() {
            self.refresh();
        }
        if ctrl_f {
            self.focus_search = true;
        }
        if typing {
            return; // 其余单键快捷键在输入框内不触发
        }
        // 预览 / 管理 / 记录 / 设置窗口打开时，避免快捷键穿透到列表上
        if self.preview.is_some()
            || self.admin.is_some()
            || self.audit.is_some()
            || self.settings.is_some()
        {
            return;
        }
        if del && !self.selected.is_empty() && self.idle() {
            self.modal = Some(Modal::ConfirmDelete(
                self.selected.iter().cloned().collect(),
            ));
        }
        if enter && self.selected.len() == 1 && self.idle() {
            if let Some(vpath) = self.selected.iter().next().cloned() {
                if let Some(item) = self.items.iter().find(|i| i.vpath == vpath) {
                    if item.is_folder {
                        self.navigate(&vpath);
                    } else {
                        self.start_preview(vpath);
                    }
                }
            }
        }
        if back && self.cwd != "/" && self.idle() {
            let parent = self
                .cwd
                .rsplit_once('/')
                .map(|(p, _)| p.to_string())
                .unwrap_or_else(|| "/".to_string());
            self.navigate(&parent);
        }
    }

    // ───────────────── 预览窗口 ─────────────────

    fn show_preview(&mut self, ctx: &egui::Context) {
        let Some(mut preview) = self.preview.take() else {
            return;
        };
        let open = &mut preview.open;
        // 闭包内只置位标志，self / preview 的变动统一放到闭包外（借用规则）
        let mut save_requested = false;
        let mut discard_requested = false;
        egui::Window::new(format!("预览：{}", preview.name))
            .open(open)
            .collapsible(false)
            .default_width(640.0)
            .default_height(480.0)
            .show(ctx, |ui| match &mut preview.kind {
                PreviewKind::Image { handle, size } => match handle {
                    Some(h) => {
                        // 按窗口宽度自适应缩放
                        let avail = ui.available_width();
                        let scale = (avail / size[0].max(1) as f32).min(3.0);
                        let disp = egui::vec2(size[0] as f32 * scale, size[1] as f32 * scale);
                        // egui 0.29：Ui::image 单参数，尺寸经 SizedTexture 携带
                        ui.image(egui::load::SizedTexture::new(h.id(), disp));
                        ui.weak(format!("{} × {} 像素", size[0], size[1]));
                    }
                    None => {
                        ui.spinner();
                    }
                },
                PreviewKind::Office => {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.monospace(&preview.text);
                        });
                }
                PreviewKind::Notice => {
                    ui.vertical_centered(|ui| {
                        ui.add_space(28.0);
                        ui.label(
                            egui::RichText::new("📦")
                                .size(34.0)
                                .color(theme::MUTED_LIGHT),
                        );
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new(&preview.text)
                                .size(12.5)
                                .color(theme::MUTED),
                        );
                    });
                }
                PreviewKind::Text {
                    editing,
                    editable,
                    dirty,
                    note,
                } => {
                    if let Some(n) = note {
                        ui.colored_label(theme::WARNING, n);
                    }
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut preview.text)
                                    .desired_rows(18)
                                    .desired_width(f32::INFINITY)
                                    .code_editor()
                                    .interactive(*editable || *editing),
                            );
                        });
                    if *editable && *editing {
                        // 编辑态：文本变化即标脏（保留修改历史在 preview.text 中）
                        // 简化实现：进入编辑后一律视为可能有修改，以保存时内容比对为准
                        *dirty = true;
                    }
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if *editable {
                            if *editing {
                                if ui.button("保存到保险柜").clicked() {
                                    save_requested = true;
                                }
                                if ui.button("放弃修改").clicked() {
                                    discard_requested = true;
                                }
                                ui.weak(if *dirty {
                                    "有未保存的修改"
                                } else {
                                    "无修改"
                                });
                            } else if ui.button("编辑").clicked() {
                                *editing = true;
                            }
                        }
                    });
                }
            });
        if save_requested {
            let vpath = preview.vpath.clone();
            let content = preview.text.clone();
            if let PreviewKind::Text { dirty, .. } = &mut preview.kind {
                *dirty = false;
            }
            self.preview = Some(preview);
            self.busy = Some(op_save_text(self.shared.clone(), vpath, content));
            self.progress = None;
            self.bytes_progress = None;
        } else if discard_requested {
            // 回滚到保险柜内内容：关闭当前窗口并重新预览（载荷到达后重建窗口）
            let vpath = preview.vpath.clone();
            self.start_preview(vpath);
        } else if preview.open {
            self.preview = Some(preview);
        }
    }
}

enum RowAction {
    Enter(String),
    Preview(String),
    Rename(String, String, bool),
    Delete(Vec<String>),
    Extract(Vec<String>),
    Move(Vec<String>),
}

impl eframe::App for LynVaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 关闭请求拦截（eframe 0.29 无 App::on_close_event）：窗口关闭时保险柜
        // 仍打开 → 先走正常 close（审计补落盘 + 密钥清零）再放行退出，
        // 避免 Vault::Drop 只清密钥不落盘丢失审计
        if !self.close_confirmed && ctx.input(|i| i.viewport().close_requested()) {
            let mut guard = self.shared.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(v) = guard.as_mut() {
                v.close();
            }
            *guard = None;
            self.close_confirmed = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        self.track_activity(ctx);
        self.poll_busy(ctx);
        self.handle_drops(ctx);
        self.check_autolock();
        self.handle_shortcuts(ctx);

        // 无边框窗口：自行处理边缘缩放 + 渐变背景
        theme::handle_edge_resize(ctx);
        theme::paint_background(ctx);

        self.show_title_bar(ctx);
        self.show_status_bar(ctx);

        egui::CentralPanel::default()
            .frame(egui::Frame::none())
            .show(ctx, |ui| match self.screen {
                Screen::Launcher => self.show_launcher(ui),
                Screen::Unlock => self.show_unlock(ui),
                Screen::Main => self.show_main(ui),
            });

        self.show_modal(ctx);
        self.show_admin(ctx);
        self.show_audit(ctx);
        self.show_settings(ctx);
        self.show_preview(ctx);
    }
}

/// epoch 秒 → 本地可读时间（不引入 chrono，直接 civil-from-days 算法）
fn epoch_str(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60
    )
}

/// Howard Hinnant 的 days→(y,m,d)（公历）
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe / 4 - yoe / 100 + yoe / 400);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
