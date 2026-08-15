//! 密码学原语封装

/// 头部签名相关常量（与 vault.rs 保持一致）
const SIGNED_LENGTH: usize = 887;
const SIGNATURE_OFFSET: usize = 960;
const SIGNATURE_SIZE: usize = 64;

use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::KeyInit as AesKeyInit;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::VaultError;

/// 锁定区 MAC 密钥（公开派生，与密码无关）。
///
/// 2.3.0 修复（关键）：旧实现用「密码 + 密钥文件」经 Argon2id 派生锁定密钥，
/// 导致两个致命问题：
/// 1. 任何错误密码都过不了锁定区 HMAC 校验，`record_failure` 永远不会执行，
///    防暴力破解锁定（5 次错误锁 30 分钟）形同虚设；
/// 2. 锁定区只认主密码，诱饵分区（独立密码）永远无法打开。
///
/// 现改为从 salt 独立派生的公开密钥（HKDF-SHA256，无需密码）：
/// - 任意一次打开尝试（无论密码对错）都能校验锁定区，错误密码会真正递增
///   `lock_count` 并触发锁定；
/// - 任何分区的合法密码都能打开保险柜并重置锁定；
/// - 局限（已文档化）：拥有文件写权限的攻击者可伪造「未锁定」记录，这与
///   其直接破坏文件的能力同级；离线复制文件暴力破解不受锁定影响（所有密码库皆然）。
pub fn derive_lock_mac_key(salt: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, salt);
    let mut key = [0u8; 32];
    hkdf.expand(b"lynvault-lock-mac-v4", &mut key)
        .expect("HKDF expand 失败");
    key
}

/// 旧版（<2.3.0）锁定密钥派生 —— 仅用于打开旧保险柜时校验锁定区并自动迁移。
///
/// 保留旧的 `password + key_file` 裸拼接格式（无长度前缀）以兼容旧文件格式，
/// 该拼接歧义是旧格式的固有缺陷，不能在此修复（会破坏旧文件兼容性）；
/// 新保险柜一律使用 `derive_lock_mac_key`，不涉及密码拼接。
pub fn derive_legacy_lock_key(
    salt: &[u8; 32],
    password: &str,
    key_file_data: Option<&[u8]>,
) -> [u8; 32] {
    // 复刻旧实现：先对 salt 做域分离异或，再 Argon2id + HKDF-SHA256。
    // 任何一步与旧版不同都会导致旧保险柜锁定区校验失败。
    let mut lock_salt = [0u8; 32];
    lock_salt.copy_from_slice(salt);
    const DOMAIN_SEP: [u8; 32] = *b"LYNVAULT-LOCK-DOMAIN-SEP-V3-----";
    for i in 0..32 {
        lock_salt[i] ^= DOMAIN_SEP[i];
    }

    // 2.4.1 修复：精确预留容量，避免多次 realloc 在堆上留下含密码的旧副本
    let kf_len = key_file_data.map_or(0, |kf| kf.len());
    let mut combined = Vec::with_capacity(password.as_bytes().len() + kf_len);
    combined.extend_from_slice(password.as_bytes());
    if let Some(kf) = key_file_data {
        combined.extend_from_slice(kf);
    }

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .expect("Argon2 参数合法");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master = [0u8; 32];
    argon2
        .hash_password_into(&combined, &lock_salt, &mut master)
        .expect("Argon2id 派生 legacy lock_key 失败");

    let hkdf = Hkdf::<Sha256>::new(None, &master);
    let mut key = [0u8; 32];
    hkdf.expand(b"pyvault4-lock-key-v3", &mut key)
        .expect("HKDF expand 失败");

    combined.zeroize();
    master.zeroize();
    lock_salt.zeroize();
    key
}

/// 输出密钥类型
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    pub enc_key: [u8; 32],
    pub auth_key: [u8; 32],
    pub sign_key: [u8; 32],
}

/// Argon2id 参数：64 MB 内存，3 轮迭代
const ARGON2_M_COST: u32 = 65536; // 64 MB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// 从主密码 + 可选密钥文件 + 盐 派生出三个密钥（Argon2id → HKDF-SHA512）
///
/// 安全性：使用长度前缀 + 分隔符避免拼接歧义。
/// 旧实现 `password + key_file` 会让 `("abc","def")` 与 `("abcd","ef")` 派生相同密钥。
/// 现在格式为：`u64_le(password_len) || password || u64_le(keyfile_len) || key_file`，
/// 任意一方长度变化都会改变前缀字节，从根本上消除歧义。
pub fn derive_keys(
    password: &str,
    key_file_data: Option<&[u8]>,
    salt: &[u8],
) -> Result<KeyMaterial, VaultError> {
    let pwd_bytes = password.as_bytes();
    // 2.4.1 修复：按最终长度精确预留，避免 extend 触发 realloc，
    // 旧缓冲区（含密码/密钥文件字节）未经 zeroize 残留在堆上
    let kf_len = key_file_data.map_or(0, |kf| kf.len());
    let mut combined = Vec::with_capacity(8 + pwd_bytes.len() + 8 + kf_len);
    // 长度前缀（小端 u64），消除拼接歧义
    combined.extend_from_slice(&(pwd_bytes.len() as u64).to_le_bytes());
    combined.extend_from_slice(pwd_bytes);
    if let Some(kf) = key_file_data {
        combined.extend_from_slice(&(kf.len() as u64).to_le_bytes());
        combined.extend_from_slice(kf);
    } else {
        combined.extend_from_slice(&0u64.to_le_bytes());
    }

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| VaultError::Other(format!("Argon2 参数错误: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master = [0u8; 32];
    argon2.hash_password_into(&combined, salt, &mut master)
        .map_err(|e| VaultError::Other(format!("Argon2id 派生失败: {}", e)))?;

    let hkdf = Hkdf::<Sha512>::new(None, &master);
    let mut derived = vec![0u8; 96];
    hkdf.expand(b"pyvault4-keys", &mut derived)
        .map_err(|_| VaultError::Other("HKDF 派生失败".into()))?;

    let mut keys = KeyMaterial {
        enc_key: [0u8; 32],
        auth_key: [0u8; 32],
        sign_key: [0u8; 32],
    };
    keys.enc_key.copy_from_slice(&derived[..32]);
    keys.auth_key.copy_from_slice(&derived[32..64]);
    keys.sign_key.copy_from_slice(&derived[64..96]);

    // 擦除中间量
    combined.zeroize();
    master.zeroize();
    derived.zeroize();

    Ok(keys)
}

/// AES-256-GCM 加密，返回 nonce(12) || ciphertext
/// `aad`：关联认证数据（绑定的上下文），解密时必须传入相同值
pub fn encrypt_gcm(key: &[u8; 32], plaintext: &[u8], aad: &[u8], nonce: Option<&[u8]>) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("invalid AES key");
    let nonce = match nonce {
        Some(n) => Nonce::from_slice(n).to_owned(),
        None => {
            let mut n = [0u8; 12];
            OsRng.fill_bytes(&mut n);
            Nonce::from(n)
        }
    };
    let payload = Payload { msg: plaintext, aad };
    let ciphertext = cipher.encrypt(&nonce, payload).map_err(|_| VaultError::EncryptFailed)?;
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// AES-256-GCM 解密，输入 nonce(12) || ciphertext，失败返回 None
/// `aad` 必须与加密时传入的值一致
pub fn decrypt_gcm(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    let (nonce, ct) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).expect("invalid AES key");
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload { msg: ct, aad };
    cipher.decrypt(nonce, payload).ok()
}

/// 生成认证标签（HMAC-SHA256 of b"AUTH_OK"）
pub fn create_auth_tag(auth_key: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(auth_key).unwrap();
    mac.update(b"AUTH_OK");
    mac.finalize().into_bytes().into()
}

/// 验证认证标签（恒定时间比较）
pub fn verify_auth_tag(auth_key: &[u8], tag: &[u8]) -> bool {
    if tag.len() < 32 { return false; }
    let expected = create_auth_tag(auth_key);
    // 恒定时间比较，防止计时攻击
    use subtle::ConstantTimeEq;
    expected.ct_eq(&tag[..32]).into()
}

/// 计算头部签名（HMAC-SHA512 over first 887 bytes of header）
pub fn compute_header_signature(payload: &[u8], sign_key: &[u8]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(sign_key).unwrap();
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

/// 验证头部签名（恒定时间）
pub fn verify_header_signature(header: &[u8], sign_key: &[u8]) -> bool {
    if header.len() < 1024 {
        return false;
    }
    let payload = &header[..SIGNED_LENGTH];
    let stored_sig = &header[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE];
    let computed = compute_header_signature(payload, sign_key);
    use subtle::ConstantTimeEq;
    computed.ct_eq(stored_sig).into()
}
