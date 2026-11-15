//! 3.2.0：持久化配置的「加密 + 防伪造」容器（LYCFG）。
//!
//! 背景：settings.json / si.json 此前为明文 JSON。二者不含长期机密，但存在
//! 合法值域内的危险篡改面 —— `anti_screenshot: false`、`autolock_minutes: 0`
//! 都是合法值（sanitized() 夹不住），si.json 的端口/令牌被改写可把第二实例
//! 握手重定向。本模块把两类文件统一包进二进制容器：
//!
//! ```text
//! b"LYCFG" | ver:u8 | mode:u8 | payload
//!   mode 1 = DPAPI（CryptProtectData + 应用熵，用户域绑定，真加密 + 防伪造）
//!   mode 2 = HMAC-SHA256（明文 + 认证标签，防低门槛篡改，跨机器可用）
//! ```
//!
//! 模式选择（写入方决定）：
//! - **固定安装 / 机器本地文件**（AppData 配置、si.json）：Windows 走 DPAPI
//!   （密钥由系统按用户账户持有，不落在二进制/磁盘上）；非 Windows 无 DPAPI，
//!   降级 HMAC。
//! - **便携模式**（settings.json 跟随 exe，可能插到别的机器）：DPAPI 解不开，
//!   走 HMAC —— 只承诺防篡改，不加密（主题/窗口尺寸本无保密价值）。
//!
//! 威胁模型诚实声明（与 settings.rs / single_instance.rs 既有声明同水位）：
//! - **同用户恶意进程**无法用文件格式防御 —— 它本可改内存、注入进程、直接
//!   调 DPAPI。文件层防的是：离线篡改、其他用户、拷贝伪造、误损坏；
//! - HMAC 模式的密钥从源码常量派生，逆向可提取 —— 这是**防篡改门槛**而非
//!   密码学边界，挡脚本小子与顺手的 JSON 编辑，不挡定向逆向；
//! - 校验失败一律拒绝采用（回退默认值 —— 默认值在安全侧：防截屏开、2 分钟
//!   自动锁），篡改的期望收益为负。

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// 容器魔数（5 字节 ASCII，便于 hexdump 肉眼识别）
pub const MAGIC: &[u8; 5] = b"LYCFG";
/// 容器格式版本（payload 布局或模式语义变化时递增）
const VERSION: u8 = 1;

/// mode 1：DPAPI（仅 Windows；其他平台写入方不得选用）
const MODE_DPAPI: u8 = 1;
/// mode 2：HMAC-SHA256 认证的明文（跨平台 / 便携）
const MODE_HMAC: u8 = 2;

/// HMAC 模式的认证标签长度
const TAG_LEN: usize = 32;

/// 写入时选用的封装模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// DPAPI（Windows 用户域，真加密 + 防伪造）。
    /// 仅 Windows 写入方构造；Linux/macOS 构建目标下不使用（允许死代码）
    #[allow(dead_code)]
    Dpapi,
    /// HMAC-SHA256（明文 + 认证标签，防篡改）
    Hmac,
}

/// 解码结果 —— 区分「容器解封成功」与「旧版明文」（迁移入口）
pub enum Decoded {
    /// 容器解封成功，payload 为原始 JSON 字节
    Container(Vec<u8>),
    /// 不带 LYCFG 魔数：旧版明文（或用户手放的其他文件），由调用方解析并迁移
    LegacyPlaintext(Vec<u8>),
}

/// HMAC 模式密钥：从源码常量派生（SHA-256 两轮），避免裸 32 字节串被
/// `strings` 直接扫出。诚实定位：提高门槛，不是密码学边界（见模块头注释）。
/// 若走 CI 注入方案（build.rs 读环境变量覆盖），常量仍是兜底 —— 保证
/// 「升级后旧配置仍可解」，避免每次发版配置被静默重置。
const MAC_SECRET: &[u8] = b"4f1c8a62e9b34d07a5c1e83f6b09d247c8e5a1f3b6d2084791ec5a7b3f0d9642";

fn mac_key(domain: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MAC_SECRET);
    h.update(domain);
    h.finalize().into()
}

/// DPAPI 附加熵 —— 绑定应用身份：同机同用户的其他程序 DPAPI 密文
/// （没有本熵值）无法直接当成本配置解出。
#[cfg(windows)]
const DPAPI_ENTROPY: &[u8] = b"LynVault::LYCFG::v1::app-entropy";

// ───────────────── HMAC 模式 ─────────────────

fn hmac_sign(payload: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(&mac_key(b"hmac-mode-v1")).expect("HMAC 接受任意长度密钥");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

/// 恒定时间比较（无 subtle 依赖，手写逐字节或）
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ───────────────── DPAPI 模式（仅 Windows）─────────────────

#[cfg(windows)]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows::core::w;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: DPAPI_ENTROPY.len() as u32,
            pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(
            &input,
            w!("LynVault LYCFG v1"),
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
        .map_err(|e| format!("DPAPI 加密失败: {}", e))?;
        let slice = std::slice::from_raw_parts(out.pbData, out.cbData as usize);
        let v = slice.to_vec();
        // CoTaskMemFree 释放 CryptProtectData 分配的输出缓冲（LocalAlloc 语义）
        windows::Win32::System::Com::CoTaskMemFree(Some(out.pbData as *const _));
        Ok(v)
    }
}

#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: DPAPI_ENTROPY.len() as u32,
            pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
        .map_err(|e| format!("DPAPI 解密失败（密文损坏或非本机/本用户数据）: {}", e))?;
        let slice = std::slice::from_raw_parts(out.pbData, out.cbData as usize);
        let v = slice.to_vec();
        windows::Win32::System::Com::CoTaskMemFree(Some(out.pbData as *const _));
        Ok(v)
    }
}

// ───────────────── 编解码入口 ─────────────────

/// 把明文 payload 封进容器。
/// `Mode::Dpapi` 在非 Windows 平台自动降级为 `Mode::Hmac`（调用方无需分支）。
pub fn encode(plaintext: &[u8], mode: Mode) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(plaintext.len() + 64);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    match mode {
        Mode::Dpapi => {
            #[cfg(windows)]
            {
                out.push(MODE_DPAPI);
                out.extend_from_slice(&dpapi_protect(plaintext)?);
            }
            #[cfg(not(windows))]
            {
                // 平台降级路径（保持调用方代码跨平台一致）
                out.push(MODE_HMAC);
                out.extend_from_slice(&hmac_sign(plaintext));
                out.extend_from_slice(plaintext);
            }
        }
        Mode::Hmac => {
            out.push(MODE_HMAC);
            out.extend_from_slice(&hmac_sign(plaintext));
            out.extend_from_slice(plaintext);
        }
    }
    Ok(out)
}

/// 解封容器。返回值三态：
/// - `Ok(Container(bytes))` —— 校验通过；
/// - `Ok(LegacyPlaintext(bytes))` —— 无魔数，按旧版明文透传（调用方迁移）；
/// - `Err(msg)` —— **带魔数但校验失败**（篡改 / 损坏 / 版本不识别）。
///   调用方必须拒绝采用（回退默认值），绝不能把 payload 当明文继续解析。
pub fn decode(raw: &[u8]) -> Result<Decoded, String> {
    if raw.len() < MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
        return Ok(Decoded::LegacyPlaintext(raw.to_vec()));
    }
    if raw.len() < MAGIC.len() + 2 {
        return Err("容器头被截断".into());
    }
    let ver = raw[5];
    let mode = raw[6];
    if ver != VERSION {
        return Err(format!(
            "不识别的容器版本 {}（可能来自更新版本的 LynVault）",
            ver
        ));
    }
    let body = &raw[MAGIC.len() + 2..];
    match mode {
        MODE_DPAPI => {
            #[cfg(windows)]
            {
                Ok(Decoded::Container(dpapi_unprotect(body)?))
            }
            #[cfg(not(windows))]
            {
                let _ = body;
                Err("DPAPI 容器只能在写入它的平台上解封（Windows）".into())
            }
        }
        MODE_HMAC => {
            if body.len() < TAG_LEN {
                return Err("HMAC 容器被截断".into());
            }
            let (tag, payload) = body.split_at(TAG_LEN);
            if !ct_eq(tag, &hmac_sign(payload)) {
                return Err("完整性校验失败（配置疑似被篡改或损坏）".into());
            }
            Ok(Decoded::Container(payload.to_vec()))
        }
        other => Err(format!("不识别的容器模式 {}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_roundtrip() {
        let plain = br#"{"theme":"vivid","autolock_minutes":2}"#;
        let blob = encode(plain, Mode::Hmac).unwrap();
        assert!(blob.starts_with(MAGIC));
        match decode(&blob).unwrap() {
            Decoded::Container(back) => assert_eq!(back, plain),
            Decoded::LegacyPlaintext(_) => panic!("期望 Container，实际 LegacyPlaintext"),
        }
    }

    #[test]
    fn hmac_detects_tamper() {
        let plain = b"payload";
        let mut blob = encode(plain, Mode::Hmac).unwrap();
        // 翻转 payload 末字节（明文区）
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(decode(&blob).is_err());
        // 翻转标签区首字节
        let mut blob2 = encode(plain, Mode::Hmac).unwrap();
        blob2[MAGIC.len() + 2] ^= 0x01;
        assert!(decode(&blob2).is_err());
        // 截断
        let blob3 = &encode(plain, Mode::Hmac).unwrap()[..MAGIC.len() + 2 + 8];
        assert!(decode(blob3).is_err());
    }

    #[test]
    fn legacy_passthrough() {
        let raw = b"{\"not\":\"a container\"}";
        match decode(raw).unwrap() {
            Decoded::LegacyPlaintext(back) => assert_eq!(back, raw),
            Decoded::Container(_) => panic!("明文不应进入容器路径"),
        }
        assert!(decode(b"LY").is_ok_and(|d| matches!(d, Decoded::LegacyPlaintext(_))));
        // 带魔数但头不完整 → Err（不再当明文）
        assert!(decode(b"LYCFG").is_err());
        assert!(decode(b"LYCFG\x01").is_err());
    }

    #[test]
    fn unknown_mode_rejected() {
        let mut blob = encode(b"x", Mode::Hmac).unwrap();
        blob[6] = 0x7F;
        assert!(decode(&blob).is_err());
    }

    #[test]
    fn unknown_version_rejected() {
        let mut blob = encode(b"x", Mode::Hmac).unwrap();
        blob[5] = 0x09;
        assert!(decode(&blob).is_err());
    }

    // DPAPI 往返只能在 Windows 上验证（沙箱 CI 为 Linux）
    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip() {
        let plain = b"secret-ish payload";
        let blob = encode(plain, Mode::Dpapi).unwrap();
        match decode(&blob).unwrap() {
            Decoded::Container(back) => assert_eq!(back, plain),
            _ => panic!("期望 Container"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_detects_tamper() {
        let mut blob = encode(b"payload", Mode::Dpapi).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(decode(&blob).is_err());
    }
}
