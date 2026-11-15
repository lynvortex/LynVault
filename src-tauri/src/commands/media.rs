//! 媒体流式预览（`lynvault-media://` 协议）—— 3.1.1 从 commands.rs 拆出。
//!
//! 拆出动机（审计 R2）：媒体令牌表 / 并发闸 / Range 解析 / 协议处理原本与 45 个
//! 命令挤在同一个 2700 行文件里 —— 协议层无法单测，review 面也无法收敛。
//! 本模块只依赖 `super` 的会话状态与 vault-core，不反向依赖任何命令。

use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::AppHandle;

use super::{catch, ct_eq_str, lock_vault, run_blocking, AppState};

/// 3.0.0（优化2）：媒体流式预览令牌表 —— (token, vpath, 签发时刻)。
/// 非一次性（播放/拖动进度条会对同一 URL 发多次 Range 请求），随会话
/// 生命周期：开柜时签发、关柜/锁定/销毁即全部作废。被攻陷的 WebView
/// 最多流式读取「已由用户点开预览的那个文件」—— 与 load_file_content
/// 的既有信任模型一致，且受扩展名白名单与分块布局双重约束。
/// 3.0.1（#14 修复）：条目带签发时刻（15 分钟闲置过期）+ 按 vpath 去重
///（重签发不挤出其他在播令牌）。
static MEDIA_TOKENS: Mutex<Vec<(String, String, Instant)>> = Mutex::new(Vec::new());

/// 3.0.1（#14 修复）：媒体令牌**闲置**过期 —— 距上次使用的时长超过该值即失效。
///
/// 3.1.1（审计修复）：判定改为滑动窗口（命中即刷新时间戳）。旧实现按「签发
/// 时刻」判过期，任何超过 15 分钟的音视频播放都会在中途 404，而播放器不会
/// 自动重新 mint —— 长文件预览（v6 流式的主要卖点）必然失败。
const MEDIA_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

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
        // 3.0.1（#13 修复）：锁中毒恢复（与命令层 into_inner() 纪律一致）——
        // 一次 panic 后预览静默死亡到重启的路径就此关闭
        let mut guard = match MEDIA_INFLIGHT.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
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
        // 签发（按 vpath 去重：重签发替换同 vpath 旧令牌，不挤出其他在播
        // 令牌；先清理过期条目；上限 64 超出才淘汰最旧）。
        // 3.0.1（#14 修复）：锁失败显式报错（旧实现静默签发未注册令牌 ——
        // 前端拿到一个必然 404 的死令牌）
        use rand::RngCore;
        let mut tb = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut tb);
        let token: String = tb.iter().map(|b| format!("{:02x}", b)).collect();
        {
            let mut guard = match MEDIA_TOKENS.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.retain(|(_, vp, issued)| vp != &vpath && issued.elapsed() < MEDIA_TOKEN_TTL);
            if guard.len() >= 64 {
                guard.remove(0);
            }
            guard.push((token.clone(), vpath, Instant::now()));
        }
        let _ = mime; // MIME 在协议层按扩展名再取（路径在此不含用户可控部分）
        Ok(token)
    })
    .await
}

/// 3.0.1（#14 修复）：校验 URL 中的 b64url(vpath) 段与登记的 vpath 一致
///（URL 安全 base64：`-`→`+`、`_`→`/`，补齐 padding 后按标准字母表解码，
/// 与前端 _b64url 的编码方式互逆）。
fn media_b64_matches(encoded: &str, vpath: &str) -> bool {
    use base64::Engine;
    let std_alpha = encoded.replace('-', "+").replace('_', "/");
    let padded = match std_alpha.len() % 4 {
        2 => format!("{}==", std_alpha),
        3 => format!("{}=", std_alpha),
        0 => std_alpha,
        _ => return false, // 长度 %4 == 1 恒非法
    };
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .map(|b| b == vpath.as_bytes())
        .unwrap_or(false)
}

/// 3.0.0（优化2）：媒体流式请求处理 —— 自定义协议 `lynvault-media://` 的
/// Rust 侧。URL 路径 = `/<token>/<b64url(vpath)>`（两者均为 URL 安全字符集，
/// 无需百分号编解码）；Range 请求映射到分块解密，明文内存占用 = 请求窗口。
/// 安全：令牌随会话签发/作废（3.0.1 起带闲置过期）；扩展名白名单；分块布局
/// 校验；响应 no-store（禁止 WebView 磁盘缓存，维持「明文不落盘」承诺）。
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

/// 3.1.1（审计修复）：解析 `Range: bytes=...` 并夹取窗口 —— 纯函数，便于单测。
///
/// `None` = 区间非法（调用方回 416）。语义与旧内联实现逐条一致：
/// - 缺省 / 无 `bytes=` 前缀 → 视为 `0-`；
/// - `bytes=-N` → 末尾 N 字节；
/// - `bytes=A-B` → `[A, B]`（B 为闭区间，`+1` 后转半开）；
/// - 解析失败的部分按默认值降级（`A` → 0，`B` → EOF）；
/// - 最终窗口长度不超过 `window`（旧实现用未检查的 `start + WINDOW`，
///   现改 `saturating_add`，行为一致且无溢出面）。
fn parse_byte_range(range: Option<&str>, file_size: u64, window: u64) -> Option<(u64, u64)> {
    let range = range.and_then(|h| h.strip_prefix("bytes=")).unwrap_or("0-");
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
    end = end.min(start.saturating_add(window)).max(start);
    if start >= end {
        return None;
    }
    Some((start, end))
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
    // 解析路径：<token>/<b64url(vpath)> —— vpath 以令牌登记为准（不信任 URL）。
    // 3.0.1（#14 修复）：b64 段不再是死参数 —— 必须与登记 vpath 一致。
    let path = request.uri().path().trim_start_matches('/');
    let Some((token, b64_segment)) = path.split_once('/') else {
        return not_found();
    };
    let vpath = {
        let mut guard = match MEDIA_TOKENS.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // 3.0.1（#14 修复）：过期令牌移除并 404（闲置过期）。
        // 3.1.1：命中即刷新时间戳（滑动窗口）—— 长音视频播放期间持续续期。
        match guard.iter_mut().position(|(t, _, _)| ct_eq_str(t, token)) {
            Some(pos) => {
                if guard[pos].2.elapsed() >= MEDIA_TOKEN_TTL {
                    guard.remove(pos);
                    return not_found();
                }
                guard[pos].2 = Instant::now();
                guard[pos].1.clone()
            }
            None => return not_found(),
        }
    };
    // 3.0.1（#14 修复）：URL 中的 b64url(vpath) 段与登记 vpath 严格比对
    if !media_b64_matches(b64_segment, &vpath) {
        return not_found();
    }
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
    // 3.0.1（#13 修复）：锁中毒恢复 —— 与命令层 into_inner() 纪律一致
    let mut guard = match state.vault.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
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
    const WINDOW: u64 = 16 * 1024 * 1024;
    let range_header = request.headers().get("range").and_then(|h| h.to_str().ok());
    let Some((start, end)) = parse_byte_range(range_header, file_size, WINDOW) else {
        return Ok(tauri::http::Response::builder()
            .status(416)
            .header("Content-Range", format!("bytes */{}", file_size))
            .body(Vec::new())
            .unwrap());
    };

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

#[cfg(test)]
mod tests {
    //! 3.1.1（审计修复）：协议层的两个纯判定函数此前零覆盖 —— Range 解析
    //! 的边界（越界 / 反向区间 / 窗口夹取）与 b64 段比对是唯一的输入校验点。

    use super::*;

    #[test]
    fn parse_range_defaults_and_suffix() {
        // 缺省 / 无前缀 → 视为 0-，并按窗口夹取
        assert_eq!(parse_byte_range(None, 1000, 16), Some((0, 16)));
        assert_eq!(parse_byte_range(Some("bytes=0-"), 1000, 16), Some((0, 16)));
        assert_eq!(parse_byte_range(Some("0-"), 1000, 16), Some((0, 16)));
        // 末尾 N 字节
        assert_eq!(
            parse_byte_range(Some("bytes=-100"), 1000, 16),
            Some((900, 916))
        );
        // 末尾请求超过文件大小 → 夹到起点 0
        assert_eq!(
            parse_byte_range(Some("bytes=-5000"), 1000, 4096),
            Some((0, 1000))
        );
    }

    #[test]
    fn parse_range_interval_and_clamping() {
        // 闭区间端点 B → 半开 +1
        assert_eq!(
            parse_byte_range(Some("bytes=100-199"), 1000, 4096),
            Some((100, 200))
        );
        // B 超过 EOF → 夹到 EOF
        assert_eq!(
            parse_byte_range(Some("bytes=990-99999"), 1000, 4096),
            Some((990, 1000))
        );
        // 起点越界 / 反向区间 → None（调用方回 416）
        assert_eq!(parse_byte_range(Some("bytes=2000-"), 1000, 16), None);
        assert_eq!(parse_byte_range(Some("bytes=500-100"), 1000, 4096), None);
        // 窗口为 0 → 空区间
        assert_eq!(parse_byte_range(Some("bytes=0-99"), 1000, 0), None);
        // 窗口小于剩余长度 → 截断到窗口
        assert_eq!(parse_byte_range(Some("bytes=0-"), 1000, 64), Some((0, 64)));
        // 非法数字 → 降级为 A=0 / B=EOF（不 panic）
        assert_eq!(
            parse_byte_range(Some("bytes=x-y"), 1000, 4096),
            Some((0, 1000))
        );
        // 极端值不得溢出（旧实现用未检查的 start + window）
        assert_eq!(
            parse_byte_range(Some("bytes=0-"), u64::MAX, u64::MAX),
            Some((0, u64::MAX))
        );
    }

    #[test]
    fn b64_segment_must_match_registered_vpath() {
        use base64::Engine;
        let vp = "/音乐/album 1/song.mp3";
        let enc = base64::engine::general_purpose::STANDARD
            .encode(vp.as_bytes())
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string();
        assert!(
            media_b64_matches(&enc, vp),
            "同一 vpath 的 b64url 段必须匹配"
        );
        assert!(!media_b64_matches(&enc, "/other/song.mp3"), "不符必须拒绝");
        assert!(!media_b64_matches("!!!", vp), "非法 base64 必须拒绝");
        assert!(!media_b64_matches("A", vp), "长度 %4 == 1 必须拒绝");
    }
}
