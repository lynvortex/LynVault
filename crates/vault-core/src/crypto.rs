//! 密码学原语封装

/// 头部签名相关常量（与 vault.rs 保持一致）
const SIGNED_LENGTH: usize = 968;
const SIGNATURE_OFFSET: usize = 960;
const SIGNATURE_SIZE: usize = 64;

use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit as AesKeyInit;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::VaultError;

/// 输出密钥类型
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    pub enc_key: [u8; 32],
    pub auth_key: [u8; 32],
    pub sign_key: [u8; 32],
}

/// 从主密码 + 可选密钥文件 + 盐 派生出三个密钥
pub fn derive_keys(
    password: &str,
    key_file_data: Option<&[u8]>,
    salt: &[u8],
) -> Result<KeyMaterial, VaultError> {
    let mut combined = Vec::new();
    combined.extend_from_slice(password.as_bytes());
    if let Some(kf) = key_file_data {
        combined.extend_from_slice(kf);
    }

    let mut master = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(&combined, salt, 1_000_000, &mut master);

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
pub fn encrypt_gcm(key: &[u8; 32], plaintext: &[u8], nonce: Option<&[u8]>) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("invalid AES key");
    let nonce = match nonce {
        Some(n) => Nonce::from_slice(n).to_owned(),
        None => {
            let mut n = [0u8; 12];
            OsRng.fill_bytes(&mut n);
            Nonce::from(n)
        }
    };
    let ciphertext = cipher.encrypt(&nonce, plaintext).expect("encryption failure");
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result
}

/// AES-256-GCM 解密，输入 nonce(12) || ciphertext，失败返回 None
pub fn decrypt_gcm(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    let (nonce, ct) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).expect("invalid AES key");
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ct).ok()
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
