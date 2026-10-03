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
    /// 主题：blue（默认）/ purple / gold / cyan
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
    "blue".into()
}
fn default_autolock() -> u32 {
    2
}
fn default_width() -> f64 {
    960.0
}
fn default_height() -> f64 {
    620.0
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
        if !matches!(self.theme.as_str(), "blue" | "purple" | "gold" | "cyan") {
            self.theme = "blue".into();
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
    base.map(|b| b.join("LynVault")).map(|d| d.join(CONFIG_FILE_NAME))
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
        ConfigLocation::Portable => portable_config_path()
            .ok_or_else(|| "无法确定程序所在目录".to_string())?,
        ConfigLocation::AppData => {
            let dir = appdata_config_path()
                .ok_or_else(|| "无法确定用户配置目录".to_string())?;
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("创建配置目录失败: {}", e))?;
            }
            dir
        }
    };
    save_at(&path, settings)?;
    Ok(path)
}

/// 把配置写到指定路径（save_settings 更新现有配置时使用）
pub fn save_at(path: &std::path::Path, settings: &Settings) -> Result<(), String> {
    let sanitized = settings.clone().sanitized();
    let json = serde_json::to_string_pretty(&sanitized)
        .map_err(|e| format!("序列化配置失败: {}", e))?;
    std::fs::write(path, json.as_bytes())
        .map_err(|e| format!("配置目录不可写（{}）。便携模式请把程序放到可写位置，或改用用户目录", e))
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
        assert_eq!(s.theme, "blue");
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
        assert_eq!(back.theme, "blue");
        assert_eq!(back.window_width, 960.0);
    }
}
