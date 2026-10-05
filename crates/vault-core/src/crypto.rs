//! 密码学原语封装

/// 头部签名相关常量（单一来源：vault.rs 侧一律从本模块导入，
/// 不再各自维护一份靠注释提醒保持一致）
pub const SIGNED_LENGTH: usize = 887;
pub const SIGNATURE_OFFSET: usize = 960;
pub const SIGNATURE_SIZE: usize = 64;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::KeyInit as AesKeyInit;
use aes_gcm::{Aes256Gcm, Nonce};
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
///
/// 2.5.1 修复：Argon2id 派生失败（如内存分配失败）原先直接 `expect` panic，
/// 现改为错误传播；失败时同样保证中间量被清零。
pub fn derive_legacy_lock_key(
    salt: &[u8; 32],
    password: &str,
    key_file_data: Option<&[u8]>,
) -> Result<[u8; 32], VaultError> {
    // 复刻旧实现：先对 salt 做域分离异或，再 Argon2id + HKDF-SHA256。
    // 任何一步与旧版不同都会导致旧保险柜锁定区校验失败。
    let mut lock_salt = [0u8; 32];
    lock_salt.copy_from_slice(salt);
    const DOMAIN_SEP: [u8; 32] = *b"LYNVAULT-LOCK-DOMAIN-SEP-V3-----";
    for i in 0..32 {
        lock_salt[i] ^= DOMAIN_SEP[i];
    }

    // 2.7.1 修复：参数校验前置 —— 旧实现在口令已拼进 combined 之后再
    // `Params::new(...)?`，该错误路径会跳过下方 zeroize，留下含口令的堆残留
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| VaultError::Other(format!("Argon2 参数错误: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // 2.4.1 修复：精确预留容量，避免多次 realloc 在堆上留下含密码的旧副本
    let kf_len = key_file_data.map_or(0, |kf| kf.len());
    let mut combined = Vec::with_capacity(password.len() + kf_len);
    combined.extend_from_slice(password.as_bytes());
    if let Some(kf) = key_file_data {
        combined.extend_from_slice(kf);
    }

    let mut master = [0u8; 32];
    if let Err(e) = argon2.hash_password_into(&combined, &lock_salt, &mut master) {
        combined.zeroize();
        lock_salt.zeroize();
        return Err(VaultError::Other(format!(
            "Argon2id 派生 legacy lock_key 失败: {}",
            e
        )));
    }

    let hkdf = Hkdf::<Sha256>::new(None, &master);
    let mut key = [0u8; 32];
    // HKDF-SHA256 expand 32 字节恒在合法范围（上限 255×32），此处不可失败
    hkdf.expand(b"pyvault4-lock-key-v3", &mut key)
        .expect("HKDF expand 失败");

    combined.zeroize();
    master.zeroize();
    lock_salt.zeroize();
    Ok(key)
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

/// Argon2id 主派生（v4/v5 共用）：口令 + 可选密钥文件（长度前缀）+ 盐 → 32 字节。
///
/// 安全性：使用长度前缀 + 分隔符避免拼接歧义。
/// 旧实现 `password + key_file` 会让 `("abc","def")` 与 `("abcd","ef")` 派生相同密钥。
/// 现在格式为：`u64_le(password_len) || password || u64_le(keyfile_len) || key_file`，
/// 任意一方长度变化都会改变前缀字节，从根本上消除歧义。
fn argon2_master(
    password: &str,
    key_file_data: Option<&[u8]>,
    salt: &[u8],
) -> Result<[u8; 32], VaultError> {
    // 2.7.1 修复：参数校验前置（与 derive_legacy_lock_key 同一问题）——
    // 口令已拼进 combined 之后再 `?` 会跳过零化
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| VaultError::Other(format!("Argon2 参数错误: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

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

    // 2.7.0 修复：与 derive_legacy_lock_key 一致，所有错误路径都先 zeroize
    // combined（含主密码字节）再返回，不允许 `?` 提前返回跳过零化
    let mut master = [0u8; 32];
    if let Err(e) = argon2.hash_password_into(&combined, salt, &mut master) {
        combined.zeroize();
        return Err(VaultError::Other(format!("Argon2id 派生失败: {}", e)));
    }
    combined.zeroize();
    Ok(master)
}

/// 从主密码 + 可选密钥文件 + 盐 派生出三个密钥（Argon2id → HKDF-SHA512）
pub fn derive_keys(
    password: &str,
    key_file_data: Option<&[u8]>,
    salt: &[u8],
) -> Result<KeyMaterial, VaultError> {
    let mut master = argon2_master(password, key_file_data, salt)?;
    let keys = match expand_keys(&master) {
        Ok(k) => k,
        Err(e) => {
            master.zeroize();
            return Err(e);
        }
    };
    master.zeroize();
    Ok(keys)
}

/// 2.8.0（v5 信封加密）：从 32 字节 data_key 派生三把会话密钥。
///
/// 与 v4 的「master → HKDF 扩展」完全同构（v4 中 master 直接由口令派生），
/// v5 中 master 换成随机 data_key —— 文件/索引密文的 GCM 布局与 AAD 约定
/// 因此完全不变，v4→v5 升级只需重加密数据本身。
pub fn expand_keys(data_key: &[u8; 32]) -> Result<KeyMaterial, VaultError> {
    let hkdf = Hkdf::<Sha512>::new(None, data_key);
    let mut derived = vec![0u8; 96];
    if hkdf.expand(b"pyvault4-keys", &mut derived).is_err() {
        return Err(VaultError::Other("HKDF 派生失败".into()));
    }

    let mut keys = KeyMaterial {
        enc_key: [0u8; 32],
        auth_key: [0u8; 32],
        sign_key: [0u8; 32],
    };
    keys.enc_key.copy_from_slice(&derived[..32]);
    keys.auth_key.copy_from_slice(&derived[32..64]);
    keys.sign_key.copy_from_slice(&derived[64..96]);

    derived.zeroize();
    Ok(keys)
}

/// 2.8.0（v5 信封加密）：从口令 + 可选密钥文件 + 盐 派生 KEK（密钥包裹密钥）。
///
/// Argon2id 参数与 `derive_keys` 完全一致（相同的内存硬度 = 相同的暴力破解成本），
/// 仅 HKDF 扩展的 info 域分离（`pyvault5-kek`），与 data_key → 会话密钥的扩展
/// 互不混淆。口令只负责「包裹」随机 data_key，因此修改口令无需重加密数据。
pub fn derive_kek(
    password: &str,
    key_file_data: Option<&[u8]>,
    salt: &[u8],
) -> Result<[u8; 32], VaultError> {
    let mut master = argon2_master(password, key_file_data, salt)?;
    let hkdf = Hkdf::<Sha512>::new(None, &master);
    let mut kek = [0u8; 32];
    if hkdf.expand(b"pyvault5-kek", &mut kek).is_err() {
        master.zeroize();
        return Err(VaultError::Other("HKDF 派生失败".into()));
    }
    master.zeroize();
    Ok(kek)
}

/// AES-256-GCM 加密，返回 nonce(12) || ciphertext
/// `aad`：关联认证数据（绑定的上下文），解密时必须传入相同值
pub fn encrypt_gcm(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>, VaultError> {
    // 2.5.1 修复：expect 改为错误传播（32 字节密钥实际恒有效，但保持加密
    // 关键路径零 panic 的纪律，避免任何上游重构引入长度错误时直接崩进程）
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::EncryptFailed)?;
    let nonce = match nonce {
        Some(n) => Nonce::from_slice(n).to_owned(),
        None => {
            let mut n = [0u8; 12];
            OsRng.fill_bytes(&mut n);
            Nonce::from(n)
        }
    };
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| VaultError::EncryptFailed)?;
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
    // 2.5.1 修复：同 encrypt_gcm，expect 改为返回 None（解密失败语义）
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload { msg: ct, aad };
    cipher.decrypt(nonce, payload).ok()
}

/// 2.8.0（v5 信封加密）：用 KEK 解包 data_key（输入 60 字节 nonce12||ct32||tag16）。
///
/// 返回 None = 口令错误或包裹体被篡改（GCM 认证失败）。这是 v5 打开流程中
/// 「口令是否正确」的判定点 —— 口令正确性由 AES-GCM 认证标签保证。
/// 2.8.1：解出的明文 data_key 清零后才丢弃 —— 这是保护全部文件数据的密钥，
/// 任何路径都不允许明文残留堆内存。
pub fn unwrap_data_key(kek: &[u8; 32], wrapped: &[u8], aad: &[u8]) -> Option<[u8; 32]> {
    if wrapped.len() != 60 {
        return None;
    }
    let mut plain = decrypt_gcm(kek, wrapped, aad)?;
    if plain.len() != 32 {
        plain.zeroize();
        return None;
    }
    let mut dk = [0u8; 32];
    dk.copy_from_slice(&plain);
    plain.zeroize();
    Some(dk)
}

/// 2.8.1：就地解密 —— 消费 `nonce(12) || ciphertext || tag(16)` 布局的缓冲区，
/// 解密直接发生在原缓冲上，返回明文（缓冲复用，避免大文件场景的多份全尺寸分配）。
/// 输出与 `decrypt_gcm` 完全一致的明文；认证失败返回 None（缓冲内容不再可信）。
pub fn decrypt_into(key: &[u8; 32], mut data: Vec<u8>, aad: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::AeadInPlace;
    use zeroize::Zeroize;
    if data.len() < 12 + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let (nonce, rest) = data.split_at_mut(12);
    let (ct, tag_bytes) = rest.split_at_mut(rest.len() - 16);
    let tag = aes_gcm::Tag::from_slice(tag_bytes);
    let nonce_arr: [u8; 12] = nonce.try_into().expect("nonce 长度已在上方检查为 12");
    // L5（审计修复）：aes-gcm 先经 CTR 变换再验标签 —— 认证失败时缓冲**已含
    // 明文等价的 keystream 输出**，直接 drop 会残留；就地清零后再返回 None
    //（这恰是最该干净的路径：密文被篡改 / 密钥错误）。
    if cipher
        .decrypt_in_place_detached((&nonce_arr).into(), aad, ct, tag)
        .is_err()
    {
        data.zeroize();
        return None;
    }
    // 就地收缩为明文：截掉尾部 tag、移除头部 nonce（一次前移拷贝）
    let plain_len = ct.len();
    data.truncate(12 + plain_len);
    data.drain(..12);
    Some(data)
}

/// 2.8.1：消费明文缓冲就地加密，输出 `nonce(12) || ciphertext || tag(16)` ——
/// 与 `encrypt_gcm` 的线格式逐字节一致（AAD/密钥相同时可互换），
/// 但省去一次全尺寸密文拷贝（明文缓冲被移动复用）。
pub fn encrypt_into(key: &[u8; 32], mut plain: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, VaultError> {
    use aes_gcm::aead::AeadInPlace;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::EncryptFailed)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let tag = cipher
        .encrypt_in_place_detached((&nonce).into(), aad, &mut plain)
        .map_err(|_| VaultError::EncryptFailed)?;
    let mut out = Vec::with_capacity(12 + plain.len() + 16);
    out.extend_from_slice(&nonce);
    out.append(&mut plain);
    out.extend_from_slice(tag.as_slice());
    Ok(out)
}

/// 生成认证标签（HMAC-SHA256 of b"AUTH_OK"）—— **旧格式**。
///
/// 2.6.1 起新保险柜改用 [`create_auth_tag_bound`]（绑定头部）；本函数仅用于
/// 兼容打开 2.6.1 之前创建的保险柜，并在首次成功打开时自动迁移。
pub fn create_auth_tag(auth_key: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(auth_key)
        .expect("HMAC-SHA256 接受任意长度密钥，构造不可失败");
    mac.update(b"AUTH_OK");
    mac.finalize().into_bytes().into()
}

/// 验证旧格式认证标签（恒定时间比较）
pub fn verify_auth_tag(auth_key: &[u8], tag: &[u8]) -> bool {
    if tag.len() < 32 {
        return false;
    }
    let expected = create_auth_tag(auth_key);
    // 恒定时间比较，防止计时攻击
    use subtle::ConstantTimeEq;
    expected.ct_eq(&tag[..32]).into()
}

/// 头部绑定认证标签的域分隔符（避免与旧格式标签的计算域混淆）
const DOMAIN_AUTH_TAG_BOUND: &[u8] = b"LYNVAULT-AUTH-TAG-BOUND-V5";

/// 2.6.1 新增：生成本分区**绑定头部**的认证标签。
///
/// 旧实现的分区认证标签 `HMAC(auth_key, "AUTH_OK")` 与头部内容完全无关，头部完整性
/// 只能由一个**全局**头部签名兜底；而该签名又因「多分区保险柜的头部可能由其他分区
/// （不同密码）签名」被 `real_count >= 2` 条件整体跳过 —— 该条件取自攻击者可控的
/// 头部内容：只要塞入一个带合法别名的伪条目，就能把单分区保险柜**降级**为
/// 「不校验头部签名」的状态（零知识降级）。
///
/// 现改为：每个分区的认证标签直接绑定头部中**该分区自身且不可变**的部分 ——
/// 头部前缀（magic / version / 保留区 / 保险柜 salt）+ 本条目别名字段(16B)
/// + 本条目 salt(32B)。由此：
/// - 无论分区有多少，篡改上述任一字节都会使**该分区的 auth_tag 匹配失败 → 认证
///   直接失败**，头部完整性校验不再依赖任何攻击者可控的分区计数；
/// - 每个分区只绑定自己的条目与全局前缀（不含 `index_offset` / `index_length`
///   与其他分区条目），因此任一分区更新头部都不会让其他分区的标签失效；
/// - `index_offset` / `index_length` 由索引的 AES-GCM 认证标签单独保护。
pub fn create_auth_tag_bound(
    auth_key: &[u8],
    header_prefix: &[u8],
    entry_alias: &[u8],
    entry_salt: &[u8],
) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(auth_key)
        .expect("HMAC-SHA256 接受任意长度密钥，构造不可失败");
    mac.update(DOMAIN_AUTH_TAG_BOUND);
    mac.update(header_prefix);
    mac.update(entry_alias);
    mac.update(entry_salt);
    mac.finalize().into_bytes().into()
}

/// 恒定时间校验分区认证标签：同时比较「头部绑定」（新）与「AUTH_OK」（旧）两种
/// 标签，任一匹配即通过。两种标签都完整计算、都用 `ct_eq` 比较（不短路），
/// 保证每次认证的工作量恒定，与真实分区数量无关。
///
/// 3.0.1（F27）：**仅 v4 打开路径**允许本函数 —— legacy 标签不绑定任何头部
/// 字段，接受它意味着「篡改被接受后被无条件重打 bound 标签洗白」。v5/v6
/// 信封路径一律用 [`verify_auth_tag_bound_only`]（所有 v5/v6 写入方都发
/// bound 标签，legacy 分支按构造不可达）。
pub fn verify_auth_tag_bound(
    auth_key: &[u8],
    header_prefix: &[u8],
    entry_alias: &[u8],
    entry_salt: &[u8],
    tag: &[u8],
) -> bool {
    if tag.len() < 32 {
        return false;
    }
    use subtle::ConstantTimeEq;
    let bound = create_auth_tag_bound(auth_key, header_prefix, entry_alias, entry_salt);
    let legacy = create_auth_tag(auth_key);
    let stored = &tag[..32];
    let ok_bound = bound.ct_eq(stored);
    let ok_legacy = legacy.ct_eq(stored);
    (ok_bound | ok_legacy).into()
}

/// 3.0.1（F27 修复）：恒定时间校验「头部绑定」认证标签（仅 bound 形态）。
/// v5/v6 信封路径专用。
pub fn verify_auth_tag_bound_only(
    auth_key: &[u8],
    header_prefix: &[u8],
    entry_alias: &[u8],
    entry_salt: &[u8],
    tag: &[u8],
) -> bool {
    if tag.len() < 32 {
        return false;
    }
    use subtle::ConstantTimeEq;
    let bound = create_auth_tag_bound(auth_key, header_prefix, entry_alias, entry_salt);
    bound.ct_eq(&tag[..32]).into()
}

/// 计算头部签名（HMAC-SHA512 over first 887 bytes of header）
pub fn compute_header_signature(payload: &[u8], sign_key: &[u8]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(sign_key)
        .expect("HMAC-SHA512 接受任意长度密钥，构造不可失败");
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

/// 3.0.0（v6 流式布局）：分块密文的 AAD ——
/// 域分隔 || 冻结 vpath（导入时的 aad_tag）|| 块序号 u64_le || 总块数 u64_le。
///
/// v6 的每个文件按 [`crate::vault`] 的 CHUNK_SIZE_V6 分块，每块独立
/// `nonce(12) || ct || tag(16)`。把块序号与总块数纳入 AAD 后：
/// - 删除/截断任一块 → 解密该块后校验总块数与序号仍通过，但最终长度不匹配
///   会失败（总块数参与每块 AAD，篡改任一块的计数都需要重写整文件全部标签）；
/// - 块交换/块拼接（把 A 文件的块挪进 B 文件）→ 冻结 vpath 不匹配必然认证失败；
/// - 与 Legacy 布局（整段 GCM，AAD = 冻结 vpath）域分离，两种布局互不可互换。
pub fn chunk_aad(frozen_vpath: &str, chunk_index: u64, chunk_count: u64) -> Vec<u8> {
    const DOMAIN: &[u8] = b"LYNVAULT-CHUNK-V6";
    let mut aad = Vec::with_capacity(DOMAIN.len() + frozen_vpath.len() + 16);
    aad.extend_from_slice(DOMAIN);
    aad.extend_from_slice(frozen_vpath.as_bytes());
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.extend_from_slice(&chunk_count.to_le_bytes());
    aad
}

// ─────────────── 3.0.0（可选硬件密钥二因子）───────────────
//
// 设计（零格式变更）：
// - 挑战不落盘 —— 从公开的保险柜盐 HKDF 派生（[`derive_yubikey_challenge`]），
//   安全性完全落在「响应只有物理钥匙能算」（HMAC-SHA1 密钥存于 YubiKey 内部）；
// - 响应不落盘 —— 启用二因子的分区，其 data_key 的包裹密钥在 KEK 之上再与
//   响应混合（[`mix_kek_with_response`]，HKDF 域分离），即「双重包裹」的
//   等效形态，头部条目结构不变；
// - 打开时对每个条目先试「混合 KEK」（若提供了响应）再试「普通 KEK」——
//   两次 GCM 解包开销可忽略，普通分区与二因子分区共存，无需任何标志位。

/// 派生 YubiKey 挑战（64 字节 —— YubiKey HMAC-SHA1 挑战-响应的最大挑战长度）。
/// 挑战由公开的保险柜盐确定派生：同一保险柜每次开柜挑战一致，响应由钥匙计算。
pub fn derive_yubikey_challenge(vault_salt: &[u8; 32]) -> [u8; 64] {
    let hkdf = Hkdf::<Sha256>::new(None, vault_salt);
    let mut challenge = [0u8; 64];
    hkdf.expand(b"lynvault-yubikey-challenge-v1", &mut challenge)
        .expect("HKDF expand 64 字节恒在合法范围");
    challenge
}

/// 把 YubiKey 响应（20 字节 HMAC-SHA1）混合进 KEK —— 启用二因子的分区
/// 用混合后的 KEK 包裹 data_key。域分离确保与普通 KEK 派生不可混淆。
pub fn mix_kek_with_response(kek: &[u8; 32], response: &[u8; 20]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha512>::new(None, kek);
    // 响应拼入 info 域（域分隔 || 响应），与普通 KEK 扩展不可混淆
    let mut info = Vec::with_capacity(23 + 20);
    info.extend_from_slice(b"lynvault-yk-kek-mix-v1");
    info.extend_from_slice(response);
    let mut mixed = [0u8; 32];
    hkdf.expand(&info, &mut mixed)
        .expect("HKDF expand 32 字节恒在合法范围");
    mixed
}
