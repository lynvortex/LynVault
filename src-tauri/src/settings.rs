//! 2.8.0：轻量设置持久化（主题 / 自动锁定时长 / 窗口尺寸 / 防截屏开关）。
//!
//! 设计要点：
//! - **配置文件不含任何敏感信息**（无密码、无路径、无保险柜历史），明文 JSON
//!   存放不会造成抗取证死角；
//! - 位置二选一，由用户在设置界面显式启用：
//!   - **便携模式**：exe 同目录（settings.json 跟随 exe，适配 U 盘）；
//!   - **固定安装**：%APPDATA%\LynVault（适配 Program Files 等只读安装位置）；
//! - 启动时 exe 目录优先、其次用户目录；两处都没有 = 未启用持久化（全部用默认值）；
//! - 同时存在两处配置时 exe 目录优先（界面会显示当前生效路径，避免歧义）。

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const CONFIG_FILE_NAME: &str = "settings.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// 主题：vivid（默认，3.0.0 图标配色）/ blue / purple / gold / cyan
    #[serde(default = "default_theme")]
    pub theme: String,
    /// 空闲自动锁定时长（分钟，0 = 禁用）
    #[serde(default = "default_autolock")]
    pub autolock_minutes: u32,
    #[serde(default = "default_width")]
    pub window_width: f64,
    #[serde(default = "default_height")]
    pub window_height: f64,
    /// 防截屏（SetWindowDisplayAffinity）开关，默认开启
    #[serde(default = "default_true")]
    pub anti_screenshot: bool,
}

fn default_theme() -> String {
    "vivid".into()
}
fn default_autolock() -> u32 {
    2
}
fn default_width() -> f64 {
    // 3.0.0：仅作 serde 缺字段兜底；全新配置 / 启动兜底的窗口尺寸一律走
    // adaptive_window_size（主显示器自适应），与前端「还原默认」同一语义
    1024.0
}
fn default_height() -> f64 {
    675.0
}

/// 3.0.0：默认窗口尺寸的自适应公式 —— 与前端 app.js 的 adaptiveWindowSize()
/// 逐字节同语义（入参为主显示器**逻辑**尺寸）：宽 = min(屏宽 60%, 1024)，
/// 高 = min(宽 66%, 屏高 80%)，高度受限时按 3:2 反推宽度。
/// 两端必须同步修改，否则「启用持久化后窗口尺寸跳变」会复发。
pub fn adaptive_window_size(monitor_w: f64, monitor_h: f64) -> (f64, f64) {
    let mut width = (monitor_w * 0.6).min(1024.0).floor();
    let height = (width * 0.66).min(monitor_h * 0.8).floor();
    if height < (width * 0.66).floor() {
        width = (height * 1.5).floor();
    }
    (width, height)
}
fn default_true() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            autolock_minutes: default_autolock(),
            window_width: default_width(),
            window_height: default_height(),
            anti_screenshot: default_true(),
        }
    }
}

impl Settings {
    /// 约束非法取值（窗口尺寸过小 / 时长越界 / 未知主题名一律回退默认）
    pub fn sanitized(mut self) -> Self {
        if !matches!(
            self.theme.as_str(),
            "blue" | "purple" | "gold" | "cyan" | "vivid"
        ) {
            self.theme = "vivid".into();
        }
        if self.autolock_minutes > 240 {
            self.autolock_minutes = 240;
        }
        self.window_width = self.window_width.clamp(480.0, 3840.0);
        self.window_height = self.window_height.clamp(360.0, 2160.0);
        self
    }
}

/// 配置写入位置（设置界面二选一）
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigLocation {
    /// exe 同目录（便携 / U 盘）
    Portable,
    /// 用户目录（%APPDATA%\LynVault）
    AppData,
}

/// exe 同目录的配置文件路径（取不到 exe 路径时 None）
pub fn portable_config_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    Some(dir.join(CONFIG_FILE_NAME))
}

/// 用户目录的配置文件路径
pub fn appdata_config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    base.map(|b| b.join("LynVault"))
        .map(|d| d.join(CONFIG_FILE_NAME))
}

/// 当前生效的配置路径（便携优先；都不存在时 None = 未启用持久化）。
/// 只认「真实存在的文件」—— 这样 disable（删除文件）后自然回到未启用态。
pub fn active_config_path() -> Option<PathBuf> {
    if let Some(p) = portable_config_path() {
        if p.is_file() {
            return Some(p);
        }
    }
    if let Some(p) = appdata_config_path() {
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// 读取当前生效配置；未启用或解析失败返回 None（调用方回退默认值）
pub fn load_active() -> Option<(PathBuf, Settings)> {
    let path = active_config_path()?;
    let text = std::fs::read_to_string(&path).ok()?;
    let settings: Settings = serde_json::from_str(&text).ok()?;
    Some((path, settings.sanitized()))
}

/// 把配置写入指定位置（目录不存在则创建）。返回写入路径。
pub fn save_to(location: ConfigLocation, settings: &Settings) -> Result<PathBuf, String> {
    let path = match location {
        ConfigLocation::Portable => {
            portable_config_path().ok_or_else(|| "无法确定程序所在目录".to_string())?
        }
        ConfigLocation::AppData => {
            let dir = appdata_config_path().ok_or_else(|| "无法确定用户配置目录".to_string())?;
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("创建配置目录失败: {}", e))?;
            }
            dir
        }
    };
    save_at(&path, settings)?;
    Ok(path)
}

/// 3.0.0（L-9）：临时文件加固打开 —— 不跟随符号链接 + 句柄级校验
/// 「非重解析点 + 硬链接数为 1」，校验失败放弃写入（防链接注入受害者文件）。
#[cfg(windows)]
fn open_tmp_secure(tmp: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(tmp)?;
    // 句柄级确认（与 main.rs 日志写入同一套检查）
    {
        use std::os::windows::fs::MetadataExt;
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        let ok =
            unsafe { GetFileInformationByHandle(HANDLE(f.as_raw_handle() as isize), &mut info) }
                .map(|_| info.nNumberOfLinks == 1)
                .unwrap_or(false);
        let attrs = f.metadata().map(|m| m.file_attributes()).unwrap_or(0xFFFF);
        if !ok || attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "配置临时文件校验失败（疑似符号链接/硬链接注入）",
            ));
        }
    }
    Ok(f)
}

#[cfg(not(windows))]
fn open_tmp_secure(tmp: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NOFOLLOW：拒绝指向已有符号链接的目标
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(tmp)?;
    // 3.0.1（F23 修复）：与 Windows 分支对称 —— O_NOFOLLOW 挡符号链接但
    // 挡不住在固定可预测名（settings.json.tmp）上预置的**硬链接**；
    // 句柄级校验硬链接数为 1
    {
        use std::os::unix::fs::MetadataExt;
        if f.metadata()?.nlink() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "配置临时文件校验失败（疑似硬链接注入）",
            ));
        }
    }
    Ok(f)
}

/// 把配置写到指定路径（save_settings 更新现有配置时使用）
/// 2.8.2：原子写入（临时文件 + rename）—— 旧实现 fs::write 非原子且无 fsync，
/// 写入中途掉电/被杀会留下截断的 settings.json，load_active 解析失败静默回
/// 默认值，用户设置无提示丢失。
pub fn save_at(path: &std::path::Path, settings: &Settings) -> Result<(), String> {
    use std::io::Write;
    let sanitized = settings.clone().sanitized();
    let json =
        serde_json::to_string_pretty(&sanitized).map_err(|e| format!("序列化配置失败: {}", e))?;
    let tmp = path.with_extension("json.tmp");
    {
        // 3.0.0（L-9 审计修复）：临时文件改为「不跟随符号链接」打开 + 句柄级校验
        // 「非重解析点 + 硬链接数为 1」—— 与日志文件（main.rs M5）同一威胁模型：
        // 预置符号链接/硬链接把配置写入（或 rename 覆盖）指向受害者文件。
        // 固定名 + File::create（跟随链接）正是 M5 修过的原语。
        let mut f = open_tmp_secure(&tmp).map_err(|e| {
            format!(
                "配置目录不可写（{}）。便携模式请把程序放到可写位置，或改用用户目录",
                e
            )
        })?;
        f.write_all(json.as_bytes())
            .map_err(|e| format!("配置写入失败: {}", e))?;
        f.sync_all().map_err(|e| format!("配置落盘失败: {}", e))?;
    }
    // Windows 上 std::fs::rename 使用 MOVEFILE_REPLACE_EXISTING，可覆盖已存在目标
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!(
            "配置写入失败（{}）。便携模式请把程序放到可写位置，或改用用户目录",
            e
        )
    })
}

/// 删除当前生效的配置文件（关闭持久化）。返回被删除的路径。
pub fn delete_active() -> Result<PathBuf, String> {
    let path = active_config_path().ok_or_else(|| "未启用持久化".to_string())?;
    std::fs::remove_file(&path).map_err(|e| format!("删除配置文件失败: {}", e))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_clamps_and_defaults() {
        let s = Settings {
            theme: "hot-pink".into(),
            autolock_minutes: 9999,
            window_width: 10.0,
            window_height: 99999.0,
            anti_screenshot: false,
        }
        .sanitized();
        assert_eq!(s.theme, "vivid");
        assert_eq!(s.autolock_minutes, 240);
        assert_eq!(s.window_width, 480.0);
        assert_eq!(s.window_height, 2160.0);

        let s2 = Settings::default().sanitized();
        assert_eq!(s2.autolock_minutes, 2);
        assert!(s2.anti_screenshot);
    }

    #[test]
    fn roundtrip_json() {
        let s = Settings::default();
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.theme, "vivid");
        assert_eq!(back.window_width, 1024.0);
        assert_eq!(back.window_height, 675.0);
    }
}
