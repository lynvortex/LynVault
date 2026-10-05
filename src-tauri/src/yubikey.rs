//! 硬件密钥设备层（3.0.0，可选二因子）—— YubiKey HMAC-SHA1 挑战-响应。
//!
//! 走 PC/SC（CCID）协议，直连 Yubico OTP 应用（零重依赖；`pcsc` 仅封装
//! 系统智能卡服务：Windows winscard / Linux pcsc-lite）：
//! 1. SELECT AID `A000000527 2001`（YubiKey OTP 应用，Global Platform 选择）；
//! 2. 挑战命令 INS=0x01、P1=SLOT_CHAL_HMAC2(0x38，槽 2 —— 与 KeePassXC
//!    挑战-响应同一约定；槽 1 常被占用为一次性密码/静态口令)；
//! 3. 响应 = rAPDU 中 SW 9000 之前的最后 20 字节（HMAC-SHA1）。
//!
//! 本模块不做任何密钥持久化 —— 私钥在 YubiKey 内部不可导出；挑战由
//! vault-core 从公开的保险柜盐派生（crypto::derive_yubikey_challenge）。
//!
//! 前置条件（用户操作，UI 提示）：YubiKey 槽 2 需配置为 HMAC-SHA1
//! 挑战-响应凭证（yubikey个人化工具或 `ykman otp chresp -H 2`）。

use pcsc::{Card, Context, Protocols, ShareMode};

/// YubiKey OTP 应用 AID（RID A000000527 + PIX 2001）
const APDU_SELECT: [u8; 12] = [
    0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01,
];
/// 挑战-响应：INS=0x01，P1 = 槽位操作码，P2 = 0x00
const INS_YK2_REQ: u8 = 0x01;
/// SLOT_CHAL_HMAC2（ykdef.h）：槽 2 的 HMAC-SHA1 挑战操作码
const SLOT_CHAL_HMAC2: u8 = 0x38;
const SW_OK: [u8; 2] = [0x90, 0x00];
const HMAC_LEN: usize = 20;
/// 挑战上限（YubiKey HMAC-SHA1 最大 64 字节）
const MAX_CHALLENGE: usize = 64;

/// 建立上下文并返回第一个「名称含 YubiKey」的读卡器 + 已连接卡片
fn connect_first_yubikey() -> Result<(Context, Card), String> {
    let ctx = Context::establish(pcsc::Scope::User)
        .map_err(|e| format!("智能卡服务不可用（{}）—— 检查 YubiKey 是否插入", e))?;
    let readers = ctx
        .list_readers_owned()
        .map_err(|e| format!("枚举读卡器失败（{}）", e))?;
    for reader in &readers {
        let name = reader.to_string_lossy().to_ascii_lowercase();
        if !name.contains("yubikey") {
            continue;
        }
        if let Ok(card) = ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
            return Ok((ctx, card));
        }
    }
    Err("未检测到 YubiKey（请插入硬件密钥后重试）".into())
}

/// 发送 APDU 并校验 SW 9000，返回负载
fn transmit_checked(card: &Card, apdu: &[u8]) -> Result<Vec<u8>, String> {
    let mut rapdu_buf = [0u8; 261]; // 最大 rAPDU：255 + SW
    let rapdu = card
        .transmit(apdu, &mut rapdu_buf)
        .map_err(|e| format!("与 YubiKey 通信失败（{}）", e))?;
    if rapdu.len() < 2 {
        return Err("YubiKey 响应异常（过短）".into());
    }
    let (payload, sw) = rapdu.split_at(rapdu.len() - 2);
    if sw != SW_OK {
        return Err(format!(
            "YubiKey 拒绝请求（状态字 {:02X}{:02X}）—— 若为未配置槽位，请先为槽 2 配置 HMAC-SHA1 挑战-响应凭证",
            sw[0], sw[1]
        ));
    }
    Ok(payload.to_vec())
}

/// 探测 YubiKey 是否在位（SELECT OTP 应用成功 = 在位）。
/// 探测失败一律返回 Ok(false)（设备缺失不构成错误，二因子为可选功能）。
pub fn probe() -> Result<bool, String> {
    let probe_result = (|| -> Result<bool, String> {
        let (_ctx, card) = connect_first_yubikey()?;
        transmit_checked(&card, &APDU_SELECT)?;
        Ok(true)
    })();
    match probe_result {
        Ok(ok) => Ok(ok),
        // 服务不可用 / 无读卡器 / 无卡片：视为不在位，不向上报错
        Err(_) => Ok(false),
    }
}

/// 对槽 2 执行 HMAC-SHA1 挑战-响应，返回 20 字节响应。
/// `challenge` 类型即 64 字节（YubiKey 协议上限）—— 3.0.1（F15）：删除
/// 对 `&[u8; 64]` 永假的长度检查。
pub fn challenge_response(challenge: &[u8; 64]) -> Result<[u8; HMAC_LEN], String> {
    let (_ctx, card) = connect_first_yubikey()?;
    transmit_checked(&card, &APDU_SELECT)?;

    let mut apdu = Vec::with_capacity(5 + MAX_CHALLENGE);
    apdu.extend_from_slice(&[
        0x00,
        INS_YK2_REQ,
        SLOT_CHAL_HMAC2,
        0x00,
        challenge.len() as u8,
    ]);
    apdu.extend_from_slice(challenge);
    let payload = transmit_checked(&card, &apdu)?;

    // 兼容两种响应形态：20 字节裸 HMAC（YK4+），或前置 2 字节状态的
    // 22 字节旧形态（论坛实测样例）—— 一律取 SW 之前的最后 20 字节
    if payload.len() < HMAC_LEN {
        return Err("YubiKey 响应负载过短".into());
    }
    let mut out = [0u8; HMAC_LEN];
    out.copy_from_slice(&payload[payload.len() - HMAC_LEN..]);
    Ok(out)
}
