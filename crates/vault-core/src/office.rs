//! Office 文档文本提取（docx / doc / xlsx / xls / csv）
//!
//! - `.docx`：解压 ZIP → 解析 word/document.xml → 提取 <w:t> 文本节点
//! - `.doc`：OLE 复合文档 → 扫描 UTF-16LE 文本流
//! - `.xlsx/.xls`：通过 calamine 读取所有工作表
//! - `.csv`：直接作为 UTF-8 文本返回
//! - 加密 OOXML（docx/xlsx，Office 2010+ 的 Agile Encryption）：纯内存解密后解析，
//!   支持口令派生（SHA-1/256/384/512 + AES-128/256-CBC），全程不落盘

use calamine::Reader as CalReader;
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::io::{self, Cursor, Read};

/// 还原 quick-xml 0.41 拆分出的实体引用事件（GeneralRef）为实际字符。
///
/// 0.41 起 reader 不再把 `&amp;` 之类的实体并入 Text 事件，而是单独发出
/// `Event::GeneralRef`（内容为不含 `&`/`;` 的实体名，如 `amp`、`#x4E2D`）。
/// 这里解析预定义实体与数字字符引用；未知实体保留原始 `&name;` 形式。
fn resolve_general_ref(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('#') {
        let code = if let Some(hex) = rest.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            rest.parse::<u32>().ok()
        };
        if let Some(c) = code.and_then(char::from_u32) {
            return c.to_string();
        }
    }
    if let Some(s) = resolve_xml_entity(name) {
        return s.to_string();
    }
    format!("&{};", name)
}

// ───────────────── 公共接口 ─────────────────

/// 预览文本总量上限（64 MiB）。2.3.0 修复：docx/pptx 是 ZIP 容器，
/// 恶意构造的「压缩炸弹」解压后可占用巨量内存导致 OOM，此处对每个条目、
/// 条目数量与最终文本总量统一设限。
const MAX_OFFICE_TEXT: usize = 64 * 1024 * 1024;

/// 2.5.1 新增：ZIP 容器条目数量上限。恶意 zip 可在中央目录声明海量条目，
/// zip crate 解析时为每个条目分配元数据，旧实现不检查条目数导致内存耗尽。
const MAX_ZIP_ENTRIES: usize = 10_000;

/// 2.5.1 新增：工作表数量上限。恶意 xlsx 可声明海量（空）工作表，
/// 每个表头行不计入文本总量上限，旧实现可被堆到千万级。
const MAX_SHEETS: usize = 1_000;

/// 2.5.1 新增：单表行数处理上限，超出即拒绝预览（防恶意大表）。
const MAX_ROWS_PER_SHEET: usize = 1_000_000;

/// 从 ZIP 归档中读取单个条目，限制解压后大小（防压缩炸弹）。
fn read_zip_entry_limited<R: Read + io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    name: &str,
) -> io::Result<Vec<u8>> {
    let f = archive
        .by_name(name)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, format!("{} 不存在", name)))?;
    if f.size() > MAX_OFFICE_TEXT as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("条目 '{}' 解压尺寸超过预览上限（可能为压缩炸弹）", name),
        ));
    }
    let mut buf = Vec::with_capacity(f.size() as usize);
    f.take((MAX_OFFICE_TEXT as u64) + 1).read_to_end(&mut buf)?;
    if buf.len() > MAX_OFFICE_TEXT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("条目 '{}' 解压后超过预览上限", name),
        ));
    }
    Ok(buf)
}

// ───────────────── 加密 OOXML 解密（Agile / Standard） ─────────────────
//
// Office 对 docx/xlsx 设置「打开密码」后遵循 MS-OFFCRYPTO：文件变为 OLE 复合文档，
// 内含 EncryptionInfo（参数）与 EncryptedPackage（密文载荷，即原始 OOXML ZIP）。
// 解密全程仅在内存中进行，不落盘。算法细节逐字核对自参考实现 msoffcrypto-tool 6.0.0：
// - Agile（EncryptionInfo 版本 4.4，Office 2010+）：
//   口令派生 H0 = H(salt ‖ UTF-16LE(口令))，Hn = H(u32_le(i) ‖ Hn-1)，i ∈ [0, spinCount)
//   （注意是迭代器前缀拼接，而非早期草稿的 Hn-1 XOR H0 方案）；各用途密钥 =
//   H(Hn ‖ blockKey) 截断至 keyBits/8；载荷 4096 字节/段，第 i 段 IV = H(keyData.salt ‖ u32_le(i)) 前 16 字节
// - Standard（版本 2/3.2，Office 2007）：SHA-1 迭代 50000 次后做 0x36/0x5c 双散列扩展；
//   校验器与载荷均为 AES-**ECB**（无 IV），载荷首 4 字节为 u32 明文总长

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use base64::Engine;
use sha1::Sha1;
use sha2::digest::DynDigest;
use sha2::Digest;
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroize;

use crate::wipe::secure_wipe_vec;

const BLK_KEY_VERIFIER_HASH_INPUT: [u8; 8] = [0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79];
const BLK_KEY_VERIFIER_HASH_VALUE: [u8; 8] = [0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E];
const BLK_KEY_KEY_VALUE: [u8; 8] = [0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6];

/// spinCount 上限：Office 默认值为 10 万。恶意 XML 声称超大值（如 10⁷）会让
/// 口令派生的迭代散列在预览路径上消耗大量 CPU —— 超出即按参数异常拒绝
const MAX_SPIN_COUNT: u32 = 100_000;

#[derive(Clone, Copy)]
enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

fn hash_alg_by_name(name: &str) -> Option<HashAlg> {
    match name.to_ascii_uppercase().as_str() {
        "SHA1" | "SHA-1" => Some(HashAlg::Sha1),
        "SHA256" | "SHA-256" => Some(HashAlg::Sha256),
        "SHA384" | "SHA-384" => Some(HashAlg::Sha384),
        "SHA512" | "SHA-512" => Some(HashAlg::Sha512),
        _ => None,
    }
}

fn new_hasher(alg: HashAlg) -> Box<dyn DynDigest> {
    match alg {
        HashAlg::Sha1 => Box::new(Sha1::new()),
        HashAlg::Sha256 => Box::new(Sha256::new()),
        HashAlg::Sha384 => Box::new(Sha384::new()),
        HashAlg::Sha512 => Box::new(Sha512::new()),
    }
}

/// 各散列算法的摘要长度（EncryptionInfo 参数校验用）
fn hash_digest_len(alg: HashAlg) -> usize {
    match alg {
        HashAlg::Sha1 => 20,
        HashAlg::Sha256 => 32,
        HashAlg::Sha384 => 48,
        HashAlg::Sha512 => 64,
    }
}

fn hash_bytes(alg: HashAlg, data: &[u8]) -> Vec<u8> {
    let mut h = new_hasher(alg);
    h.update(data);
    h.finalize().to_vec()
}

enum AesKey {
    K128(Aes128),
    K192(Aes192),
    K256(Aes256),
}

fn new_aes(key: &[u8]) -> Option<AesKey> {
    match key.len() {
        16 => Some(AesKey::K128(Aes128::new_from_slice(key).ok()?)),
        24 => Some(AesKey::K192(Aes192::new_from_slice(key).ok()?)),
        32 => Some(AesKey::K256(Aes256::new_from_slice(key).ok()?)),
        _ => None,
    }
}

/// AES-CBC 解密（手写 CBC：逐块 ECB 解密后与前一块密文异或，避免引入 cbc crate）
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(16) || iv.len() < 16 {
        return None;
    }
    let cipher = new_aes(key)?;
    let mut out = data.to_vec();
    let mut prev: [u8; 16] = iv[..16].try_into().ok()?;
    for chunk in out.chunks_exact_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        let cipher_block = *block;
        match &cipher {
            AesKey::K128(c) => c.decrypt_block(block),
            AesKey::K192(c) => c.decrypt_block(block),
            AesKey::K256(c) => c.decrypt_block(block),
        }
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        prev = cipher_block.into();
    }
    Some(out)
}

/// 口令迭代散列（MS-OFFCRYPTO 2.3.4.11）
fn derive_iterated_hash(password_utf16: &[u8], salt: &[u8], alg: HashAlg, spin: u32) -> Vec<u8> {
    let mut buf = salt.to_vec();
    buf.extend_from_slice(password_utf16);
    let mut h = hash_bytes(alg, &buf);
    // 2.7.1：含口令字节的中间量用后即清零，不允许随作用域结束残留
    buf.zeroize();
    let mut tmp = Vec::with_capacity(4 + h.len());
    for i in 0u32..spin {
        tmp.clear();
        tmp.extend_from_slice(&i.to_le_bytes());
        tmp.extend_from_slice(&h);
        let next = hash_bytes(alg, &tmp);
        h.zeroize();
        h = next;
    }
    tmp.zeroize();
    h
}

fn derive_key(h_digest: &[u8], block_key: &[u8], alg: HashAlg, key_bits: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(h_digest.len() + block_key.len());
    buf.extend_from_slice(h_digest);
    buf.extend_from_slice(block_key);
    let out = hash_bytes(alg, &buf);
    // 2.8.2（L1）：拼接缓冲含密钥派生材料，用后即清零
    buf.zeroize();
    out[..key_bits / 8].to_vec()
}

struct AgileParams {
    spin_count: u32,
    enc_key_bits: usize,
    enc_hash: HashAlg,
    enc_salt: Vec<u8>,
    verifier_hash_input: Vec<u8>,
    verifier_hash_value: Vec<u8>,
    key_value: Vec<u8>,
    data_key_bits: usize,
    data_hash: HashAlg,
    data_salt: Vec<u8>,
}

/// 解析 EncryptionInfo：8 字节版本头（agile = 4.4）+ UTF-8 参数 XML
fn parse_encryption_info(info: &[u8]) -> Result<AgileParams, String> {
    if info.len() < 8 || info[0] != 4 || info[1] != 0 || info[2] != 4 || info[3] != 0 {
        return Err("不支持的 Office 加密格式（仅支持 Office 2010 及以上版本的 AES 加密）".into());
    }
    let xml =
        std::str::from_utf8(&info[8..]).map_err(|_| "EncryptionInfo 不是有效 UTF-8".to_string())?;

    use std::collections::HashMap;
    let mut key_data: HashMap<String, String> = HashMap::new();
    let mut enc_key: HashMap<String, String> = HashMap::new();
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e)) => {
                let qname = e.name();
                let name = qname.as_ref();
                let target = if name.ends_with(b"keyData") {
                    Some(&mut key_data)
                } else if name.ends_with(b"encryptedKey") {
                    Some(&mut enc_key)
                } else {
                    None
                };
                if let Some(map) = target {
                    for attr in e.attributes().with_checks(false) {
                        let attr = attr.map_err(|_| "EncryptionInfo 属性解析失败".to_string())?;
                        // 字段值均为 base64/数字，无 XML 转义，直接按原始字节取用
                        map.insert(
                            String::from_utf8_lossy(attr.key.as_ref()).to_string(),
                            String::from_utf8_lossy(&attr.value).to_string(),
                        );
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err("EncryptionInfo XML 解析失败".into()),
            _ => {}
        }
        buf.clear();
    }

    let get = |map: &HashMap<String, String>, k: &str| -> Result<String, String> {
        map.get(k)
            .cloned()
            .ok_or_else(|| format!("EncryptionInfo 缺少字段 {}", k))
    };
    let b64 = |v: &str| -> Result<Vec<u8>, String> {
        base64::engine::general_purpose::STANDARD
            .decode(v)
            .map_err(|_| "EncryptionInfo 字段 base64 无效".to_string())
    };

    for map in [&key_data, &enc_key] {
        let cipher = get(map, "cipherAlgorithm")?;
        let chaining = map
            .get("cipherChaining")
            .map(String::as_str)
            .unwrap_or("ChainingModeCBC");
        if !cipher.eq_ignore_ascii_case("AES") || chaining != "ChainingModeCBC" {
            return Err("不支持的 Office 加密格式（仅支持 AES-CBC）".into());
        }
    }
    let spin_count: u32 = get(&enc_key, "spinCount")?
        .parse()
        .map_err(|_| "spinCount 无效".to_string())?;
    if spin_count == 0 || spin_count > MAX_SPIN_COUNT {
        return Err("加密参数异常（spinCount 超出安全范围）".into());
    }
    let enc_key_bits: usize = get(&enc_key, "keyBits")?
        .parse()
        .map_err(|_| "keyBits 无效".to_string())?;
    let data_key_bits: usize = get(&key_data, "keyBits")?
        .parse()
        .map_err(|_| "keyBits 无效".to_string())?;
    if !matches!(enc_key_bits, 128 | 192 | 256) || !matches!(data_key_bits, 128 | 192 | 256) {
        return Err("不支持的密钥长度".into());
    }
    let enc_hash = hash_alg_by_name(&get(&enc_key, "hashAlgorithm")?)
        .ok_or_else(|| "不支持的散列算法".to_string())?;
    let data_hash = hash_alg_by_name(&get(&key_data, "hashAlgorithm")?)
        .ok_or_else(|| "不支持的散列算法".to_string())?;
    // 2.7.1 修复（恶意文档 panic）：Agile EncryptionInfo 声明 SHA-1 + AES-192/256 时，
    // derive_key 会按 keyBits 截断散列输出 → 越界切片 panic。解析阶段校验
    // 「摘要长度 ≥ 密钥长度」，超出即按参数异常拒绝。
    if hash_digest_len(enc_hash) < enc_key_bits / 8
        || hash_digest_len(data_hash) < data_key_bits / 8
    {
        return Err("加密参数异常（散列长度小于密钥长度）".into());
    }

    Ok(AgileParams {
        spin_count,
        enc_key_bits,
        enc_hash,
        enc_salt: b64(&get(&enc_key, "saltValue")?)?,
        verifier_hash_input: b64(&get(&enc_key, "encryptedVerifierHashInput")?)?,
        verifier_hash_value: b64(&get(&enc_key, "encryptedVerifierHashValue")?)?,
        key_value: b64(&get(&enc_key, "encryptedKeyValue")?)?,
        data_key_bits,
        data_hash,
        data_salt: b64(&get(&key_data, "saltValue")?)?,
    })
}

fn read_stream_limited<R: Read + io::Seek>(
    cfb: &mut cfb::CompoundFile<R>,
    name: &str,
    cap: u64,
) -> Result<Vec<u8>, String> {
    let stream = cfb
        .open_stream(name)
        .map_err(|_| format!("缺少流 {}", name))?;
    let mut out = Vec::new();
    stream
        .take(cap)
        .read_to_end(&mut out)
        .map_err(|e| format!("读取 {} 失败: {}", name, e))?;
    Ok(out)
}

/// 解密加密 OOXML 载荷，返回原始 OOXML ZIP 字节。
/// 按 EncryptionInfo 版本头分发：Agile（4.4，Office 2010+）或 Standard（2/3.2，Office 2007）。
/// 两种格式的密文流名都是 EncryptedPackage（注意不是 EncryptionPackage）。
fn decrypt_encrypted_package(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut cfb = cfb::CompoundFile::open(Cursor::new(data))
        .map_err(|e| format!("OLE 容器解析失败: {}", e))?;
    let info = read_stream_limited(&mut cfb, "/EncryptionInfo", 1024 * 1024)?;
    let package = read_stream_limited(&mut cfb, "/EncryptedPackage", (MAX_OFFICE_TEXT as u64) + 1)?;
    drop(cfb);

    if info.len() >= 4 && info[0] == 4 && info[1] == 0 && info[2] == 4 && info[3] == 0 {
        decrypt_agile_package(&info, &package, password)
    } else if info.len() >= 4 && info[1] == 0 && info[2] == 2 && matches!(info[0], 2..=4) {
        decrypt_standard_package(&info, &package, password)
    } else {
        Err(format!(
            "不支持的 Office 加密格式（EncryptionInfo 版本 {}.{}, 仅支持 Office 2007+ 的 AES 加密）",
            info.first().copied().unwrap_or(0),
            info.get(2).copied().unwrap_or(0)
        ))
    }
}

/// 口令校验：解密 verifierHashInput 取散列，与解密后的 verifierHashValue 比较
fn password_ok(p: &AgileParams, password_key: &dyn Fn(&[u8]) -> Vec<u8>) -> bool {
    use subtle::ConstantTimeEq;
    let key1 = password_key(&BLK_KEY_VERIFIER_HASH_INPUT);
    let verifier_input = match aes_cbc_decrypt(&key1, &p.enc_salt, &p.verifier_hash_input) {
        Some(v) => v,
        None => {
            secure_wipe_vec(key1);
            return false;
        }
    };
    let key2 = password_key(&BLK_KEY_VERIFIER_HASH_VALUE);
    let mut expected = match aes_cbc_decrypt(&key2, &p.enc_salt, &p.verifier_hash_value) {
        Some(v) => v,
        None => {
            secure_wipe_vec(key1);
            secure_wipe_vec(key2);
            secure_wipe_vec(verifier_input);
            return false;
        }
    };
    // 2.7.1：两把临时密钥与 verifier_input 用后即清零
    secure_wipe_vec(key1);
    secure_wipe_vec(key2);
    let mut actual = hash_bytes(p.enc_hash, &verifier_input);
    secure_wipe_vec(verifier_input);
    // Office 对非块对齐的散列会零填充到块大小，只比较 digest 长度的前缀；
    // 2.7.1：比较改为恒定时间（与 vault 侧认证纪律一致，防止计时侧信道）
    let ok =
        expected.len() >= actual.len() && bool::from(expected[..actual.len()].ct_eq(&actual[..]));
    // 2.8.2（L1）：expected（解密出的校验散列）与 actual 用后清零
    expected.zeroize();
    actual.zeroize();
    ok
}

/// 解密 Agile Encryption 载荷，返回原始 OOXML ZIP 字节
fn decrypt_agile_package(info: &[u8], package: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let p = parse_encryption_info(info)?;

    // 口令 → 迭代散列 → 三把用途密钥
    let mut pwd16: Vec<u8> = Vec::with_capacity(password.len() * 2 + 2);
    for unit in password.encode_utf16() {
        pwd16.extend_from_slice(&unit.to_le_bytes());
    }
    let h = derive_iterated_hash(&pwd16, &p.enc_salt, p.enc_hash, p.spin_count);
    pwd16.zeroize();

    let derive = |block_key: &[u8]| derive_key(&h, block_key, p.enc_hash, p.enc_key_bits);
    let ok = password_ok(&p, &derive);
    // 中间密钥（secretKey）也要从 h 派生 —— 必须在零化 h 之前完成
    let mut key3 = derive(&BLK_KEY_KEY_VALUE);
    let mut h = h;
    h.zeroize();
    if !ok {
        key3.zeroize();
        return Err("密码错误或文档已损坏".into());
    }

    // 中间密钥（secretKey）：解密 encryptedKeyValue
    let mut secret = aes_cbc_decrypt(&key3, &p.enc_salt, &p.key_value).ok_or("文档已损坏")?;
    key3.zeroize();
    if secret.len() != p.data_key_bits / 8 {
        secret.zeroize();
        return Err("文档加密参数异常".into());
    }

    // 载荷：首 8 字节 u64 明文总长，4096 字节/段
    if package.len() < 8 {
        secret.zeroize();
        return Err("文档已损坏".into());
    }
    let total_size_u64 = u64::from_le_bytes(package[..8].try_into().unwrap());
    // 2.8.2（I8）：先做上限检查再转 usize —— 32 位目标上 u64→usize 会回绕，
    // 旧实现 `as usize` 在前会绕过 MAX_OFFICE_TEXT 检查
    if total_size_u64 > MAX_OFFICE_TEXT as u64 {
        secret.zeroize();
        return Err(format!(
            "文档解密后超过预览上限（{} 字节）",
            MAX_OFFICE_TEXT
        ));
    }
    let total_size = total_size_u64 as usize;
    let mut plain: Vec<u8> = Vec::with_capacity(total_size);
    let mut remaining = total_size;
    for (i, chunk) in package[8..].chunks(4096).enumerate() {
        if remaining == 0 {
            break;
        }
        let mut iv_input = p.data_salt.clone();
        iv_input.extend_from_slice(&(i as u32).to_le_bytes());
        let iv = hash_bytes(p.data_hash, &iv_input);
        let dec = match aes_cbc_decrypt(&secret, &iv, chunk) {
            Some(d) => d,
            None => {
                secret.zeroize();
                plain.zeroize();
                return Err("文档已损坏".into());
            }
        };
        let take = dec.len().min(remaining);
        plain.extend_from_slice(&dec[..take]);
        remaining -= take;
    }
    secret.zeroize();
    // 2.8.2（I8）：截断包拒绝 —— 声明的明文长度未消费完说明载荷被截断，
    // 旧实现会带着残缺 ZIP 继续解析
    if remaining != 0 {
        plain.zeroize();
        return Err("文档已损坏（载荷被截断）".into());
    }

    if plain.starts_with(b"PK") {
        Ok(plain)
    } else {
        plain.zeroize();
        Err("密码错误或文档已损坏".into())
    }
}

// ───────────────── Standard Encryption（Office 2007，EncryptionInfo 版本 2/3.2） ─────────────────
//
// 算法核对自 msoffcrypto-tool 6.0.0（method/ecma376_standard.py + format/common.py）：
// - 口令派生：h = SHA1(salt ‖ UTF-16LE(口令))，迭代 50000 次 hn = SHA1(u32_le(i) ‖ hn-1)，
//   hfinal = SHA1(h ‖ u32_le(0))，再做 0x36/0x5c 双散列扩展，取前 keySize/8 字节
// - 密钥校验：AES-**ECB** 解密 encryptedVerifier（16B）取 SHA1，与解密后的
//   encryptedVerifierHash（32B）前 20 字节比较
// - 载荷：EncryptedPackage 流首 4 字节 u32 明文总长（跳过 8 字节），AES-ECB 整体解密后截断

struct StandardParams {
    key_bits: usize,
    salt: [u8; 16],
    encrypted_verifier: [u8; 16],
    encrypted_verifier_hash: Vec<u8>,
}

fn parse_standard_encryption_info(info: &[u8]) -> Result<StandardParams, String> {
    const ERR_SHORT: &str = "Standard EncryptionInfo 结构不完整";
    // 真实布局（Word 2007 4.2 实测）：
    //   [0..4]   版本 (major, minor)
    //   [4..8]   flags（0x24 = fCryptoAPI | fAES）
    //   [8..12]  headerSize（其后的 EncryptionHeader 长度，含 UTF-16 CSP 名称）
    //   [12..12+headerSize]  dd925430 EncryptionHeader：Flags/SizeExtra/algId/algIdHash/
    //                        keySize/providerType/reserved×2 + cspName
    //   之后                  dd910568 DecryptionVerifier（72 字节）
    if info.len() < 12 {
        return Err(ERR_SHORT.into());
    }
    let header_size = u32::from_le_bytes(info[8..12].try_into().unwrap()) as usize;
    let header_start: usize = 12;
    let header_end = header_start.checked_add(header_size).ok_or(ERR_SHORT)?;
    if header_size < 32 || info.len() < header_end + 4 + 16 + 16 + 4 + 32 {
        return Err(ERR_SHORT.into());
    }
    let header = &info[header_start..header_end];
    let alg_id = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let key_size = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    if alg_id & 0xFF00 != 0x6600 {
        return Err("不支持的 Office 加密算法（仅支持 AES，不支持 RC4 等）".into());
    }
    if !matches!(key_size, 128 | 192 | 256) {
        return Err("不支持的密钥长度".into());
    }
    // 校验器（dd910568）：saltSize(4)/salt(16)/encryptedVerifier(16)/verifierHashSize(4)/encryptedVerifierHash(32)
    let v = &info[header_end..];
    let salt_size = u32::from_le_bytes(v[0..4].try_into().unwrap());
    if salt_size != 16 {
        return Err("不支持的盐长度".into());
    }
    Ok(StandardParams {
        key_bits: key_size,
        salt: v[4..20].try_into().unwrap(),
        encrypted_verifier: v[20..36].try_into().unwrap(),
        encrypted_verifier_hash: v[40..72].to_vec(),
    })
}

/// Standard Encryption 的 0x36/0x5c 双散列密钥扩展
fn derive_standard_key(h_final: &[u8], key_bits: usize) -> Vec<u8> {
    const CB_HASH: usize = 20; // SHA-1
    let mut buf1 = [0x36u8; 64];
    let mut buf2 = [0x5cu8; 64];
    for i in 0..CB_HASH {
        buf1[i] ^= h_final[i];
        buf2[i] ^= h_final[i];
    }
    let mut x3 = hash_bytes(HashAlg::Sha1, &buf1);
    let x2 = hash_bytes(HashAlg::Sha1, &buf2);
    // 2.7.1：扩展缓冲含密钥材料，用后即清零
    buf1.zeroize();
    buf2.zeroize();
    x3.extend_from_slice(&x2);
    let mut x2 = x2;
    x2.zeroize();
    let key = x3[..key_bits / 8].to_vec();
    x3.zeroize();
    key
}

/// AES-ECB 解密（Standard Encryption 的校验器与数据段不使用 IV）
fn aes_ecb_decrypt(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return None;
    }
    let cipher = new_aes(key)?;
    let mut out = data.to_vec();
    for chunk in out.chunks_exact_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        match &cipher {
            AesKey::K128(c) => c.decrypt_block(block),
            AesKey::K192(c) => c.decrypt_block(block),
            AesKey::K256(c) => c.decrypt_block(block),
        }
    }
    Some(out)
}

/// Standard Encryption 口令派生（MS-OFFCRYPTO 2.3.5.2 / dd925430）
fn derive_standard_key_from_password(password: &str, salt: &[u8], key_bits: usize) -> Vec<u8> {
    let mut pwd16: Vec<u8> = Vec::with_capacity(password.len() * 2 + 2);
    for unit in password.encode_utf16() {
        pwd16.extend_from_slice(&unit.to_le_bytes());
    }
    // h = SHA1(salt ‖ pwd)；迭代 50000 次 hn = SHA1(u32_le(i) ‖ hn-1)；hfinal = SHA1(h ‖ 0)
    let mut buf = salt.to_vec();
    buf.extend_from_slice(&pwd16);
    // 2.7.1：全部中间量（pwd16/buf/h/tmp/h_final）用后即清零
    pwd16.zeroize();
    let mut h = hash_bytes(HashAlg::Sha1, &buf);
    buf.zeroize();
    for i in 0u32..50_000 {
        let mut tmp = i.to_le_bytes().to_vec();
        tmp.extend_from_slice(&h);
        let next = hash_bytes(HashAlg::Sha1, &tmp);
        tmp.zeroize();
        h.zeroize();
        h = next;
    }
    h.extend_from_slice(&0u32.to_le_bytes());
    let mut h_final = hash_bytes(HashAlg::Sha1, &h);
    h.zeroize();
    let key = derive_standard_key(&h_final, key_bits);
    h_final.zeroize();
    key
}

fn decrypt_standard_package(
    info: &[u8],
    package: &[u8],
    password: &str,
) -> Result<Vec<u8>, String> {
    let p = parse_standard_encryption_info(info)?;
    let key = derive_standard_key_from_password(password, &p.salt, p.key_bits);

    // 口令校验（AES-ECB）。
    // 2.8.1：verifier 比对改为恒定时间（与 Agile 路径的 ct_eq 纪律一致），
    // 并给 verifier_hash 解密失败的早退路径补上 key 清零（旧实现 key 以明文 drop）
    let mut verifier = aes_ecb_decrypt(&key, &p.encrypted_verifier).ok_or_else(|| {
        let mut k = key.clone();
        k.zeroize();
        "文档已损坏".to_string()
    })?;
    let expected = hash_bytes(HashAlg::Sha1, &verifier);
    let verifier_hash = aes_ecb_decrypt(&key, &p.encrypted_verifier_hash).ok_or_else(|| {
        let mut k = key.clone();
        k.zeroize();
        "文档已损坏".to_string()
    })?;
    use subtle::ConstantTimeEq;
    let ok = verifier_hash.len() >= expected.len()
        && bool::from(verifier_hash.as_slice()[..expected.len()].ct_eq(&expected[..]));
    verifier.zeroize();
    // 2.8.2（L1）：expected / verifier_hash 含校验材料，比较后清零
    let mut expected = expected;
    expected.zeroize();
    let mut verifier_hash = verifier_hash;
    verifier_hash.zeroize();
    if !ok {
        let mut key = key;
        key.zeroize();
        return Err("密码错误或文档已损坏".into());
    }

    // 载荷：首 4 字节 u32 明文总长，跳过 8 字节，AES-ECB 整体解密后截断
    if package.len() < 8 {
        let mut key = key;
        key.zeroize();
        return Err("文档已损坏".into());
    }
    let total_size = u32::from_le_bytes(package[..4].try_into().unwrap()) as usize;
    if total_size > MAX_OFFICE_TEXT {
        let mut key = key;
        key.zeroize();
        return Err(format!(
            "文档解密后超过预览上限（{} 字节）",
            MAX_OFFICE_TEXT
        ));
    }
    if package.len() - 8 == 0 || !(package.len() - 8).is_multiple_of(16) {
        let mut key = key;
        key.zeroize();
        return Err("文档已损坏".into());
    }
    let mut plain = match aes_ecb_decrypt(&key, &package[8..]) {
        Some(d) => d,
        None => {
            let mut key = key;
            key.zeroize();
            return Err("文档已损坏".into());
        }
    };
    let mut key = key;
    key.zeroize();
    if plain.len() < total_size {
        plain.zeroize();
        return Err("文档已损坏".into());
    }
    plain.truncate(total_size);
    if plain.starts_with(b"PK") {
        Ok(plain)
    } else {
        plain.zeroize();
        Err("密码错误或文档已损坏".into())
    }
}

enum EncryptedKind {
    Docx,
    Xlsx,
}

/// 加密 OOXML 预览入口：无口令返回 OFFICE_ENCRYPTED 哨兵，有口令则纯内存解密后复用解析器
fn extract_encrypted_ooxml(
    data: &[u8],
    password: Option<&str>,
    kind: EncryptedKind,
) -> Result<String, String> {
    let Some(password) = password else {
        return Err("OFFICE_ENCRYPTED".into());
    };
    let plain = decrypt_encrypted_package(data, password)?;
    let text = match kind {
        EncryptedKind::Docx => extract_docx_text(&plain).map_err(|e| e.to_string()),
        EncryptedKind::Xlsx => extract_xlsx_text(&plain).map_err(|e| e.to_string()),
    };
    secure_wipe_vec(plain);
    text
}

/// 自动检测格式并提取 Office 文档文本
///
/// `password`：加密 OOXML 文档（Agile Encryption）的打开口令；未提供口令而文档
/// 已加密时返回 `Err("OFFICE_ENCRYPTED")`（前端据此弹出口令输入框）。
pub fn extract_office_text(
    data: &[u8],
    filename: &str,
    password: Option<&str>,
) -> Result<String, String> {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();

    match ext.as_str() {
        "docx" => {
            if is_ole_compound(data) {
                return extract_encrypted_ooxml(data, password, EncryptedKind::Docx);
            }
            extract_docx_text(data).map_err(|e| e.to_string())
        }
        "xlsx" => {
            if is_ole_compound(data) {
                return extract_encrypted_ooxml(data, password, EncryptedKind::Xlsx);
            }
            extract_xlsx_text(data).map_err(|e| e.to_string())
        }
        "doc" => {
            if is_ole_compound(data) {
                extract_doc_text(data).map_err(|e| e.to_string())
            } else {
                Err(".doc 文件格式无效".into())
            }
        }
        "xls" => {
            if is_ole_compound(data) {
                extract_xls_ole_text(data).map_err(|e| e.to_string())
            } else {
                extract_xlsx_text(data).map_err(|e| e.to_string())
            }
        }
        "csv" => extract_csv_text(data).map_err(|e| e.to_string()),
        _ => Err(format!("不支持的 Office 格式: .{}", ext)),
    }
}

// ───────────────── 格式检测 ─────────────────

/// 检测是否为 OLE 复合文档
fn is_ole_compound(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    data[..4] == [0xD0, 0xCF, 0x11, 0xE0]
}

// ───────────────── DOC 提取（旧版 Word OLE） ─────────────────

/// 从 OLE 复合文档中提取 .doc 文本
///
/// 先用 `cfb` crate 解析 OLE 结构，读取 "WordDocument" stream，
/// 再从此 stream 中扫描 UTF-16LE 文本（而非扫描全量文件，大幅降低误报）
fn extract_doc_text(data: &[u8]) -> io::Result<String> {
    use cfb::CompoundFile;

    let cursor = Cursor::new(data);

    // 打开 OLE 复合文档（F: Read + Seek）
    let mut cfb = CompoundFile::open(cursor)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("OLE 解析失败: {}", e)))?;

    // 读取 WordDocument stream（.doc 文件的主文档流，路径以 '/' 开头），限制大小防异常
    let mut stream_data = Vec::new();
    {
        let stream = cfb.open_stream("/WordDocument").map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "未找到 WordDocument stream（可能不是有效的 .doc 文件）",
            )
        })?;
        stream
            .take((MAX_OFFICE_TEXT as u64) + 1)
            .read_to_end(&mut stream_data)?;
    }

    if stream_data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WordDocument stream 为空",
        ));
    }
    if stream_data.len() > MAX_OFFICE_TEXT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WordDocument stream 超过预览上限",
        ));
    }

    // 从 FIB（File Information Block）之后开始扫描
    // FIB 通常占据前 1024-2048 字节，文本从 offset 0x0400 附近开始
    let scan_start = if stream_data.len() > 0x0800 {
        0x0400
    } else {
        0
    };
    let scan_end = stream_data.len() - (stream_data.len() % 2);

    let mut texts = Vec::new();
    let mut current = String::new();

    let mut i = scan_start;
    while i + 1 < scan_end {
        let lo = stream_data[i];
        let hi = stream_data[i + 1];
        let ch = u16::from_le_bytes([lo, hi]);

        // 2.4.1 修复（P2-23）：处理 UTF-16 代理对（CJK 扩展 B 等增补平面字符）。
        // 旧实现把高/低代理分别当独立 u16 转 char，from_u32 失败全部变 '?'。
        if (0xD800..=0xDBFF).contains(&ch) && i + 3 < scan_end {
            let lo2 = stream_data[i + 2];
            let hi2 = stream_data[i + 3];
            let low_pair = u16::from_le_bytes([lo2, hi2]);
            if (0xDC00..=0xDFFF).contains(&low_pair) {
                let c = ((((ch as u32) - 0xD800) << 10) | ((low_pair as u32) - 0xDC00)) + 0x10000;
                current.push(char::from_u32(c).unwrap_or('?'));
                i += 4;
                continue;
            }
        }

        if is_word_text_char(ch) {
            current.push(char::from_u32(ch as u32).unwrap_or('?'));
        } else if current.len() >= 4 {
            let trimmed = current.trim();
            if !trimmed.is_empty() && trimmed.chars().any(|c| c.is_alphabetic()) {
                texts.push(trimmed.to_string());
            }
            current.clear();
        } else {
            current.clear();
        }
        i += 2;
    }

    // 处理最后一段
    if current.len() >= 4 {
        let trimmed = current.trim();
        if !trimmed.is_empty() && trimmed.chars().any(|c| c.is_alphabetic()) {
            texts.push(trimmed.to_string());
        }
    }

    if texts.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "无法从 .doc 文件中提取文本（可能是加密或格式不支持）",
        ));
    }

    Ok(texts.join("\n"))
}

/// 判断是否为 Word 文本中常见的字符
fn is_word_text_char(ch: u16) -> bool {
    match ch {
        // ASCII 可打印字符
        0x20..=0x7E => true,
        // 中文 CJK 基本区
        0x4E00..=0x9FFF => true,
        // 中文 CJK 扩展 A
        0x3400..=0x4DBF => true,
        // 中文标点
        0x3000..=0x303F => true,
        // 全角 ASCII
        0xFF01..=0xFF5E => true,
        // 日文假名
        0x3040..=0x309F => true,
        0x30A0..=0x30FF => true,
        // 韩文
        0xAC00..=0xD7AF => true,
        // 常见拉丁扩展
        0x00C0..=0x024F => true,
        // Tab / CR / LF
        0x09 | 0x0D | 0x0A => true,
        _ => false,
    }
}

// ───────────────── 2.8.2（H3/H4/H5/M2/M3）：解析前预扫描 ─────────────────
//
// 根因在 calamine 0.36.1 上游 —— Range::from_sparse 按单元格坐标包围盒一次性
// 稠密分配 cols×rows（~32B/格）；sharedStrings 的 uniqueCount 直接 reserve(n)；
// xls 的 BIFF 0x0200 Dimensions 记录同样无界 reserve 且 end < start 时 u32 下溢。
// 几 KB 的恶意文件即可要求数百 GiB 分配，Rust 分配失败走 handle_alloc_error →
// **abort**，catch_unwind 无法拦截，整个进程静默死亡。原有限制
// （MAX_ROWS_PER_SHEET 等）都在物化之后检查，形同虚设。
//
// 预扫描在交给 calamine 之前按普通错误拒绝一切资源耗尽向量：
// - xlsx：ZIP 条目数 / 逐条目实测解压尺寸 / 全部条目解压总量（M3 压缩炸弹）；
//   sharedStrings 的 uniqueCount 与实际 <si> 计数（H4）；worksheet 的 dimension
//   与每个单元格坐标解析 + 包围盒面积（H3）。
// - xls：OLE 打开 /Workbook（或 /Book）流 → 逐条 BIFF 记录扫描 Dimensions
//   （H5 下溢 / 行列极限）与真实单元格记录的包围盒（M2）。
// 上限取 400 万格（而非审计建议的 100 万），为真实大型表格留兼容余量
// （≈128 MB 稠密内存，仍远低于 abort 阈值）。

/// worksheet 包围盒面积上限（4,000,000 格 ≈ 128 MB 稠密内存）
const MAX_CELLS_BBOX: u64 = 4_000_000;
/// Excel 规格极限：行 ≤ 1,048,576 / 列 ≤ 16,384，坐标越界直接拒绝
const MAX_EXCEL_ROWS: u32 = 1_048_576;
const MAX_EXCEL_COLS: u32 = 16_384;
/// sharedStrings 的 uniqueCount / 实际 <si> 计数上限（H4）
const MAX_SHARED_STRING_COUNT: usize = 2_000_000;
/// xlsx ZIP 条目数上限（与 docx 路径的 MAX_ZIP_ENTRIES 同值）
const MAX_XLSX_ZIP_ENTRIES: usize = 10_000;
/// xlsx 单条目实测解压尺寸上限（M3）
const MAX_XLSX_ENTRY_UNCOMPRESSED: u64 = 64 * 1024 * 1024;
/// xlsx 全部条目解压总量上限（M3）
const MAX_XLSX_TOTAL_UNCOMPRESSED: u64 = 256 * 1024 * 1024;
/// xls 的 Workbook/Book 流读取上限（防 OLE 流声明无界）
const MAX_XLS_WORKBOOK_STREAM: u64 = 256 * 1024 * 1024;

/// 解析 xlsx 单元格坐标（"A1" / "XFD1048576"）→ (row, col)，均 1-based。
/// 非法形式返回 None。列段最多 3 个字母（XFD 已是 Excel 极限）。
fn parse_cell_ref(s: &str) -> Option<(u32, u32)> {
    if s.is_empty() {
        return None;
    }
    let split = s.char_indices().find(|(_, c)| c.is_ascii_digit())?;
    let (col_part, row_part) = s.split_at(split.0);
    if col_part.is_empty() || col_part.len() > 3 {
        return None;
    }
    if !col_part.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    if row_part.is_empty() || !row_part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut col: u32 = 0;
    for b in col_part.bytes() {
        let v = (b.to_ascii_uppercase() - b'A') as u32 + 1;
        col = col.checked_mul(26)?.checked_add(v)?;
    }
    let row: u32 = row_part.parse().ok()?;
    Some((row, col))
}

/// 包围盒追踪器（预扫描共用）：维护坐标包围盒 + 单元格计数，
/// 超过 Excel 规格极限或包围盒面积上限即报错。坐标一律 1-based。
struct BboxTracker {
    min_r: u32,
    min_c: u32,
    max_r: u32,
    max_c: u32,
    cells: u64,
}

impl BboxTracker {
    fn new() -> Self {
        Self {
            min_r: u32::MAX,
            min_c: u32::MAX,
            max_r: 0,
            max_c: 0,
            cells: 0,
        }
    }

    /// 3.0.0（LM-1）：仅计数（无 r 属性单元格 —— 坐标按行内顺序推断，
    /// 上界即单元格总数；不参与包围盒）
    fn count_cell(&mut self) -> Result<(), String> {
        self.cells += 1;
        if self.cells > MAX_CELLS_BBOX {
            return Err(format!(
                "工作表单元格数量超过安全上限（{}）",
                MAX_CELLS_BBOX
            ));
        }
        Ok(())
    }

    /// 记录一个坐标（1-based，已做 Excel 规格极限校验）
    fn track(&mut self, r: u32, c: u32) -> Result<(), String> {
        if r == 0 || r > MAX_EXCEL_ROWS || c == 0 || c > MAX_EXCEL_COLS {
            return Err(format!(
                "单元格坐标超出 Excel 规格极限（row={}, col={}）",
                r, c
            ));
        }
        self.merge(r, c);
        self.cells += 1;
        if self.cells > MAX_CELLS_BBOX {
            return Err(format!(
                "工作表单元格数量超过安全上限（{}）",
                MAX_CELLS_BBOX
            ));
        }
        Ok(())
    }

    /// 合并一个已通过外部校验的坐标（不计数，供 Dimensions 声明并入包围盒）
    fn merge(&mut self, r: u32, c: u32) {
        self.min_r = self.min_r.min(r);
        self.min_c = self.min_c.min(c);
        self.max_r = self.max_r.max(r);
        self.max_c = self.max_c.max(c);
    }

    /// 包围盒面积超限检查（空表直接通过）
    fn check_area(&self) -> Result<(), String> {
        if self.cells == 0 && self.max_r == 0 {
            return Ok(());
        }
        let rows = (self.max_r.saturating_sub(self.min_r) + 1) as u64;
        let cols = (self.max_c.saturating_sub(self.min_c) + 1) as u64;
        let area = rows.saturating_mul(cols);
        if area > MAX_CELLS_BBOX {
            return Err(format!(
                "工作表包围盒（{}×{} = {} 格）超过安全上限（{} 格）",
                rows, cols, area, MAX_CELLS_BBOX
            ));
        }
        Ok(())
    }
}

/// H4：sharedStrings 预扫描 —— uniqueCount 声明与实际 <si> 计数同限。
/// calamine 对 uniqueCount 直接 reserve(n)，几 KB 文件即可要求 TB 级分配。
fn count_shared_strings(xml: &[u8]) -> Result<(), String> {
    let text =
        std::str::from_utf8(xml).map_err(|_| "sharedStrings.xml 不是有效 UTF-8".to_string())?;
    let mut reader = Reader::from_str(text);
    let mut buf = Vec::new();
    let mut si_count: usize = 0;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let name = e.name();
                let local = name.as_ref();
                if local == b"si" {
                    si_count += 1;
                    if si_count > MAX_SHARED_STRING_COUNT {
                        return Err(format!(
                            "sharedStrings 条目数超过安全上限（{}）",
                            MAX_SHARED_STRING_COUNT
                        ));
                    }
                } else if local == b"sst" {
                    for attr in e.attributes().with_checks(false) {
                        let attr = attr.map_err(|_| "sharedStrings 属性解析失败".to_string())?;
                        if attr.key.as_ref() == b"uniqueCount" {
                            if let Ok(v) = std::str::from_utf8(&attr.value) {
                                if let Ok(n) = v.parse::<usize>() {
                                    if n > MAX_SHARED_STRING_COUNT {
                                        return Err(format!(
                                            "sharedStrings uniqueCount={} 超过安全上限（{}）",
                                            n, MAX_SHARED_STRING_COUNT
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("sharedStrings.xml 解析失败: {}", e)),
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

/// H3：worksheet 预扫描 —— 解析 <dimension ref> 与每个 <c r> 坐标，
/// 坐标超出 Excel 规格极限直接拒绝；包围盒（dimension 与实际单元格的并集）
/// 面积超限拒绝。
fn prescan_worksheet_xml(xml: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(xml).map_err(|_| "worksheet XML 不是有效 UTF-8".to_string())?;
    let mut reader = Reader::from_str(text);
    let mut buf = Vec::new();
    let mut bbox = BboxTracker::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let name = e.name();
                let local = name.as_ref();
                if local == b"dimension" {
                    for attr in e.attributes().with_checks(false) {
                        let attr = attr.map_err(|_| "worksheet 属性解析失败".to_string())?;
                        if attr.key.as_ref() == b"ref" {
                            if let Ok(v) = std::str::from_utf8(&attr.value) {
                                // 可能是范围 "A1:C5" 或单格 "A1"；两端都参与包围盒
                                for part in v.split(':') {
                                    let (r, c) = parse_cell_ref(part).ok_or_else(|| {
                                        format!("dimension 引用坐标非法: {}", part)
                                    })?;
                                    bbox.track(r, c)?;
                                }
                            }
                        }
                    }
                } else if local == b"c" {
                    // 3.0.0（LM-1 审计修复）：无 r 属性的单元格也计数 —— OOXML
                    // 允许省略 r（坐标按行内顺序推断，calamine 同样按此解析），
                    // 旧实现完全不计入 → ≤64 MiB 的恶意 xlsx 可隐含千万级单元格
                    // 绕过 MAX_CELLS_BBOX。顺序推断坐标的上界就是单元格总数，
                    // 对无 r 单元格按出现次数累加即可封住该盲区（有 r 的仍走
                    // 精确坐标包围盒）。
                    let mut has_r = false;
                    for attr in e.attributes().with_checks(false) {
                        let attr = attr.map_err(|_| "worksheet 属性解析失败".to_string())?;
                        if attr.key.as_ref() == b"r" {
                            has_r = true;
                            let v = std::str::from_utf8(&attr.value)
                                .map_err(|_| "单元格坐标非 UTF-8".to_string())?;
                            let (r, c) = parse_cell_ref(v)
                                .ok_or_else(|| format!("单元格坐标非法: {}", v))?;
                            bbox.track(r, c)?;
                        }
                    }
                    if !has_r {
                        bbox.count_cell()?;
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("worksheet XML 解析失败: {}", e)),
            _ => {}
        }
        buf.clear();
    }
    bbox.check_area()
}

/// xlsx 预扫描入口：交给 calamine 之前拒绝一切资源耗尽向量。
fn prescan_xlsx(data: &[u8]) -> Result<(), String> {
    let cursor = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| format!("ZIP 解析失败: {}", e))?;
    if archive.len() > MAX_XLSX_ZIP_ENTRIES {
        return Err(format!(
            "ZIP 条目数量过多（{} 个，上限 {}）",
            archive.len(),
            MAX_XLSX_ZIP_ENTRIES
        ));
    }
    let names: Vec<String> = archive.file_names().map(|s| s.to_string()).collect();

    // 第一遍：逐条目**实测**解压尺寸（中央目录声明可撒谎，必须真解压计量）
    let mut total_uncompressed: u64 = 0;
    for name in &names {
        let mut f = archive
            .by_name(name)
            .map_err(|e| format!("ZIP 条目读取失败（{}）: {}", name, e))?;
        let mut entry_total: u64 = 0;
        let mut buf = [0u8; 65536];
        loop {
            let n = f
                .read(&mut buf)
                .map_err(|e| format!("ZIP 条目解压失败（{}）: {}", name, e))?;
            if n == 0 {
                break;
            }
            entry_total += n as u64;
            if entry_total > MAX_XLSX_ENTRY_UNCOMPRESSED {
                return Err(format!(
                    "ZIP 条目 '{}' 解压尺寸超过上限（64 MiB）—— 可能为压缩炸弹",
                    name
                ));
            }
        }
        total_uncompressed += entry_total;
        if total_uncompressed > MAX_XLSX_TOTAL_UNCOMPRESSED {
            return Err("ZIP 解压总量超过上限（256 MiB）—— 可能为压缩炸弹".to_string());
        }
    }

    // 第二遍：sharedStrings（H4）与各 worksheet（H3）
    if names.iter().any(|n| n == "xl/sharedStrings.xml") {
        let mut f = archive
            .by_name("xl/sharedStrings.xml")
            .map_err(|e| format!("读取 sharedStrings.xml 失败: {}", e))?;
        let mut xml = Vec::with_capacity(f.size().min(MAX_XLSX_ENTRY_UNCOMPRESSED) as usize);
        f.read_to_end(&mut xml)
            .map_err(|e| format!("读取 sharedStrings.xml 失败: {}", e))?;
        count_shared_strings(&xml)?;
    }
    for name in &names {
        if !name.starts_with("xl/worksheets/") || !name.ends_with(".xml") {
            continue;
        }
        let mut f = archive
            .by_name(name)
            .map_err(|e| format!("读取工作表（{}）失败: {}", name, e))?;
        let mut xml = Vec::with_capacity(f.size().min(MAX_XLSX_ENTRY_UNCOMPRESSED) as usize);
        f.read_to_end(&mut xml)
            .map_err(|e| format!("读取工作表（{}）失败: {}", name, e))?;
        prescan_worksheet_xml(&xml).map_err(|e| format!("工作表 {} 预扫描失败: {}", name, e))?;
    }
    Ok(())
}

/// H5/M2：xls BIFF 记录预扫描 —— Dimensions（0x0200）的下溢与行列极限 +
/// 真实单元格记录统计包围盒。
///
/// Dimensions 布局按记录长度区分：≥16 字节 = BIFF3/4（4×u32），10 字节 =
/// BIFF5/8（4×u16，rwMac/colMac 为 0-based 闭区间端点）。行 ≤ 65536、
/// 列 ≤ 256（BIFF8 极限）。单元格记录：row/col 位于载荷头部 u16×2；
/// MULRK(0x00BD)/MULBLANK(0x00BE) 的列区间为 colFirst（头部）与 colLast（尾部）。
fn prescan_biff_records(workbook: &[u8]) -> Result<(), String> {
    let rd16 = |p: &[u8], off: usize| -> u32 { u16::from_le_bytes([p[off], p[off + 1]]) as u32 };
    let rd32 = |p: &[u8], off: usize| -> u32 {
        u32::from_le_bytes([p[off], p[off + 1], p[off + 2], p[off + 3]])
    };
    let mut bbox = BboxTracker::new();

    let mut off = 0usize;
    while off + 4 <= workbook.len() {
        let opcode = u16::from_le_bytes([workbook[off], workbook[off + 1]]);
        let len = u16::from_le_bytes([workbook[off + 2], workbook[off + 3]]) as usize;
        let payload_start = off + 4;
        if payload_start + len > workbook.len() {
            // 截断流：结构问题交由 calamine 报具体错误
            break;
        }
        let p = &workbook[payload_start..payload_start + len];
        match opcode {
            0x0200 if len >= 16 => {
                // BIFF3/4：4×u32
                let (sr, er, sc, ec) = (rd32(p, 0), rd32(p, 4), rd32(p, 8), rd32(p, 12));
                if er < sr || ec < sc {
                    return Err("Dimensions 记录 end < start（下溢攻击）".to_string());
                }
                if (er.saturating_sub(sr) as u64) + 1 > 65536
                    || (ec.saturating_sub(sc) as u64) + 1 > 256
                {
                    return Err(format!(
                        "Dimensions 包围盒超出 BIFF 极限（{} 行 × {} 列）",
                        (er - sr) as u64 + 1,
                        (ec - sc) as u64 + 1
                    ));
                }
                // 0-based 闭区间端点 → 1-based 并入包围盒（不经 track 计数）
                bbox.merge(er.saturating_add(1), ec.saturating_add(1));
                bbox.merge(sr.saturating_add(1), sc.saturating_add(1));
            }
            0x0200 if len >= 8 => {
                // BIFF5/8：4×u16（闭区间端点，0-based）
                let (sr, er, sc, ec) = (rd16(p, 0), rd16(p, 2), rd16(p, 4), rd16(p, 6));
                if er < sr || ec < sc {
                    return Err("Dimensions 记录 end < start（下溢攻击）".to_string());
                }
                if (er - sr) + 1 > 65536 || (ec - sc) + 1 > 256 {
                    return Err(format!(
                        "Dimensions 包围盒超出 BIFF 极限（{} 行 × {} 列）",
                        (er - sr) as u64 + 1,
                        (ec - sc) as u64 + 1
                    ));
                }
                bbox.merge(er + 1, ec + 1);
                bbox.merge(sr + 1, sc + 1);
            }
            // 单元格记录：FORMULA / LABELSST / NUMBER / LABEL / BOOLERR / RK / RSTRING / BLANK
            0x0006 | 0x00FD | 0x0201 | 0x0203 | 0x0204 | 0x0205 | 0x027E | 0x00D6 if len >= 4 => {
                let (r, c) = (rd16(p, 0), rd16(p, 2));
                if r >= 65536 || c >= 256 {
                    return Err(format!("单元格坐标超出 BIFF 极限（row={}, col={}）", r, c));
                }
                bbox.track(r + 1, c + 1)?;
            }
            // MULRK / MULBLANK：row(2) colFirst(2) ... colLast(2)
            0x00BD | 0x00BE if len >= 6 => {
                let r = rd16(p, 0);
                let cf = rd16(p, 2);
                let cl = rd16(p, len - 2);
                if cl < cf {
                    return Err("MULRK/MULBLANK 列区间 end < start".to_string());
                }
                if r >= 65536 || cl >= 256 {
                    return Err(format!("单元格坐标超出 BIFF 极限（row={}, col={}）", r, cl));
                }
                for c in cf..=cl {
                    bbox.track(r + 1, c + 1)?;
                }
            }
            _ => {}
        }
        off = payload_start + len;
    }

    bbox.check_area()
}

/// xls 预扫描入口：OLE 打开 Workbook/Book 流 → BIFF 记录扫描 → 再交 calamine。
/// 流缺失/截断等结构问题不拦截（交由 calamine 报具体错误），
/// 只拦截确定的资源耗尽向量。
fn prescan_xls_ole(data: &[u8]) -> Result<(), String> {
    use cfb::CompoundFile;
    let cursor = Cursor::new(data);
    let mut cfb = CompoundFile::open(cursor).map_err(|e| format!("OLE 解析失败: {}", e))?;
    let stream_name = if cfb.exists("/Workbook") {
        "/Workbook"
    } else if cfb.exists("/Book") {
        "/Book"
    } else {
        return Ok(()); // 交由 calamine 报错
    };
    let mut workbook = Vec::new();
    {
        let s = cfb
            .open_stream(stream_name)
            .map_err(|e| format!("读取 {} 流失败: {}", stream_name, e))?;
        let claimed = s.len();
        if claimed > MAX_XLS_WORKBOOK_STREAM {
            return Err(format!("{} 流超过安全上限（256 MiB）", stream_name));
        }
        s.take(MAX_XLS_WORKBOOK_STREAM + 1)
            .read_to_end(&mut workbook)
            .map_err(|e| format!("读取 {} 流失败: {}", stream_name, e))?;
    }
    if workbook.len() as u64 > MAX_XLS_WORKBOOK_STREAM {
        return Err(format!("{} 流超过安全上限（256 MiB）", stream_name));
    }
    prescan_biff_records(&workbook)
}

// ───────────────── XLS / XLSX 通用提取 ─────────────────

/// 通用 calamine 工作表提取（消除 Xlsx 和 Xls 的重复逻辑）
fn extract_calamine_sheets<R, RS>(workbook: &mut R) -> io::Result<String>
where
    R: calamine::Reader<RS>,
    RS: std::io::Read + std::io::Seek,
    R::Error: std::fmt::Display,
{
    let mut output = Vec::new();
    let mut total = 0usize;

    let sheet_names = workbook.sheet_names().to_owned();
    // 2.5.1 修复：限制工作表数量（表头行不计入文本总量，需单独设限）
    if sheet_names.len() > MAX_SHEETS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "工作表数量过多（{} 个，上限 {}），已拒绝预览",
                sheet_names.len(),
                MAX_SHEETS
            ),
        ));
    }

    for sheet_name in sheet_names {
        output.push(format!("── {} ──", sheet_name));

        match workbook.worksheet_range(&sheet_name) {
            Ok(range) => {
                let mut rows_seen = 0usize;
                for row in range.rows() {
                    // 2.5.1 修复：单表行数上限
                    rows_seen += 1;
                    if rows_seen > MAX_ROWS_PER_SHEET {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "工作表 '{}' 行数超过预览上限（{} 行）",
                                sheet_name, MAX_ROWS_PER_SHEET
                            ),
                        ));
                    }
                    let cells: Vec<String> = row.iter().map(cell_to_string).collect();
                    let line = cells.join("\t");
                    if !line.trim().is_empty() {
                        // 2.3.0 修复：限制预览文本总量，防止超大数据集拖垮内存
                        total += line.len() + 1;
                        if total > MAX_OFFICE_TEXT {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "表格内容超过预览上限（64 MiB）",
                            ));
                        }
                        output.push(line);
                    }
                }
            }
            Err(e) => {
                output.push(format!("[读取错误: {}]", e));
            }
        }
        output.push(String::new());
    }

    Ok(output.join("\n"))
}

/// 从 OLE 复合文档中提取 .xls 文本（旧版 Excel）
/// 2.8.2：入口顺序为 OLE 解析 → BIFF 预扫描 → Xls::new（资源耗尽向量在
/// 交给 calamine 之前拒绝）
fn extract_xls_ole_text(data: &[u8]) -> io::Result<String> {
    use calamine::Xls;
    prescan_xls_ole(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let cursor = Cursor::new(data);
    let mut workbook: Xls<Cursor<&[u8]>> =
        Xls::new(cursor).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    extract_calamine_sheets(&mut workbook)
}

// ───────────────── DOCX 提取 ─────────────────

fn extract_docx_text(data: &[u8]) -> io::Result<String> {
    let cursor = Cursor::new(data);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // 2.5.1 修复：中央目录条目数上限（zip crate 为每个条目分配元数据）
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "ZIP 条目数量过多（{} 个，上限 {}）",
                archive.len(),
                MAX_ZIP_ENTRIES
            ),
        ));
    }

    let mut xml_buf = read_zip_entry_limited(&mut archive, "word/document.xml")?;
    let xml = String::from_utf8_lossy(&xml_buf);
    let parsed = parse_docx_xml(&xml);
    // L5（审计修复）：文档明文缓冲用后即清零（提取文本本身经 IPC 返回，
    // 属既有信任模型；缓冲生命周期更长的堆残留则不应留）
    drop(xml);
    xml_buf.zeroize();
    parsed
}

fn parse_docx_xml(xml: &str) -> io::Result<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut paragraphs: Vec<String> = Vec::new();
    let mut current_para = String::new();
    let mut in_para = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = e.name();
                let local = name.as_ref();
                if local == b"w:p" {
                    in_para = true;
                    current_para.clear();
                }
            }
            Ok(Event::Empty(ref e)) => {
                let name = e.name();
                let local = name.as_ref();
                if in_para && (local == b"w:br" || local == b"w:cr") {
                    current_para.push('\n');
                } else if in_para && local == b"w:tab" {
                    current_para.push('\t');
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_para {
                    if let Ok(text) = e.xml10_content() {
                        current_para.push_str(&text);
                    }
                }
            }
            Ok(Event::GeneralRef(ref e)) => {
                if in_para {
                    if let Ok(name) = e.decode() {
                        current_para.push_str(&resolve_general_ref(&name));
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name = e.name();
                let local = name.as_ref();
                if local == b"w:p" {
                    let trimmed = current_para.trim();
                    if !trimmed.is_empty() {
                        paragraphs.push(trimmed.to_string());
                    }
                    in_para = false;
                    current_para.clear();
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(paragraphs.join("\n"))
}

// ───────────────── XLSX 提取 ─────────────────

fn extract_xlsx_text(data: &[u8]) -> io::Result<String> {
    use calamine::Xlsx;
    // 2.8.2（H3/H4/M3）：解析前预扫描 —— 压缩炸弹 / uniqueCount / 包围盒
    // 攻击在交给 calamine 之前按普通错误拒绝（加密 xlsx 解密后同样覆盖）
    prescan_xlsx(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let cursor = Cursor::new(data);
    let mut workbook: Xlsx<Cursor<&[u8]>> =
        Xlsx::new(cursor).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    extract_calamine_sheets(&mut workbook)
}

fn cell_to_string(cell: &calamine::Data) -> String {
    match cell {
        calamine::Data::Empty => String::new(),
        calamine::Data::String(s) => s.clone(),
        calamine::Data::Float(f) => {
            if f.fract() == 0.0 && f.abs() < i64::MAX as f64 {
                format!("{}", *f as i64)
            } else {
                format!("{}", f)
            }
        }
        calamine::Data::Int(i) => format!("{}", i),
        calamine::Data::Bool(b) => {
            if *b {
                "TRUE".into()
            } else {
                "FALSE".into()
            }
        }
        calamine::Data::Error(e) => format!("#ERR:{:?}", e),
        calamine::Data::DateTime(d) => format!("{}", d),
        _ => String::new(),
    }
}

// ───────────────── CSV 提取 ─────────────────

fn extract_csv_text(data: &[u8]) -> io::Result<String> {
    // 2.3.0 修复：限制 CSV 预览大小，防止超大文件整串进 UI 拖垮内存
    if data.len() > MAX_OFFICE_TEXT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CSV 文件超过预览上限（64 MiB），请提取后查看",
        ));
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))?;
    Ok(text.to_string())
}

// ───────────────── 测试 ─────────────────

#[cfg(test)]
mod tests {
    use super::*;
    // BlockEncrypt 仅测试内的加密辅助（aes_cbc_encrypt）使用：
    // 留在顶层会在非测试构建报 unused import，收进测试模块
    use aes::cipher::BlockEncrypt;

    // ───────── 2.8.2（H3/H4/H5/M2/M3）：预扫描测试 ─────────

    #[test]
    fn cell_ref_parsing() {
        assert_eq!(parse_cell_ref("A1"), Some((1, 1)));
        assert_eq!(parse_cell_ref("XFD1048576"), Some((1_048_576, 16_384)));
        assert_eq!(parse_cell_ref("a5"), Some((5, 1)));
        assert!(parse_cell_ref("1A").is_none());
        assert!(parse_cell_ref("A").is_none());
        assert!(parse_cell_ref("").is_none());
        assert!(parse_cell_ref("XFE1").is_some()); // 列数本身合法，越界判定交给上限
        assert_eq!(parse_cell_ref("XFE1").map(|(_, c)| c), Some(16_385));
    }

    fn worksheet_xml(dim: &str, cells: &[&str]) -> Vec<u8> {
        let cell_xml: String = cells.iter().map(|c| format!(r#"<c r="{}"/>"#, c)).collect();
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><worksheet><dimension ref="{}"/><sheetData><row>{}</row></sheetData></worksheet>"#,
            dim, cell_xml
        )
        .into_bytes()
    }

    #[test]
    fn prescan_worksheet_rejects_attacks() {
        // dimension 全范围引用 A1:XFD1048576 → 包围盒 171 亿格，拒绝
        assert!(prescan_worksheet_xml(&worksheet_xml("A1:XFD1048576", &[])).is_err());
        // 稀疏单元格包围盒：A1 与 XFD1048576 两个格 → 包围盒超限，拒绝
        assert!(prescan_worksheet_xml(&worksheet_xml("", &["A1", "XFD1048576"])).is_err());
        // 越界坐标（行 > 1,048,576）
        assert!(prescan_worksheet_xml(&worksheet_xml("", &["A1048577"])).is_err());
        // 越界坐标（列 > 16,384）
        assert!(prescan_worksheet_xml(&worksheet_xml("", &["XFE1"])).is_err());
        // 非法坐标
        assert!(prescan_worksheet_xml(&worksheet_xml("", &["1A"])).is_err());
    }

    #[test]
    fn prescan_worksheet_allows_legal_sheet() {
        // 完整最小合法 worksheet 照常通过（防误伤回归）
        assert!(prescan_worksheet_xml(&worksheet_xml("A1:C3", &["A1", "B2", "C3"])).is_ok());
        // 大但合法：400 万格恰好在上限内（dimension 2000×2000）
        // 2000×2000 = 4,000,000 格恰好在上限内（列 2000 = BXX）
        assert!(prescan_worksheet_xml(&worksheet_xml("A1:BXX2000", &["A1"])).is_ok());
        // 超过 400 万格的 dimension（2000×2001）拒绝
        // 2000×2001 = 4,002,000 格超过上限
        assert!(prescan_worksheet_xml(&worksheet_xml("A1:BXX2001", &["A1"])).is_err());
    }

    #[test]
    fn prescan_xlsx_rejects_huge_unique_count() {
        // H4：uniqueCount 声明超大 → 拒绝（calamine 会按它 reserve）
        let xml = br#"<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" uniqueCount="99999999"><si><t>a</t></si></sst>"#;
        assert!(count_shared_strings(xml).is_err());
        // 合法声明 + 合法实际计数 → 通过
        let ok = br#"<?xml version="1.0"?><sst uniqueCount="1"><si><t>a</t></si></sst>"#;
        assert!(count_shared_strings(ok).is_ok());
        // 声明合法但实际 <si> 计数超限 → 拒绝（声明可撒谎，实测为准）
        let mut lying = String::from("<?xml version=\"1.0\"?><sst uniqueCount=\"1\">");
        for _ in 0..(MAX_SHARED_STRING_COUNT + 1) {
            lying.push_str("<si><t>x</t></si>");
        }
        lying.push_str("</sst>");
        assert!(count_shared_strings(lying.as_bytes()).is_err());
    }

    #[test]
    fn prescan_xlsx_allows_minimal_legal_xlsx() {
        // 完整最小合法 xlsx 照常通过预扫描（防误伤回归）
        use std::io::Write;
        let mut zw = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zw.start_file(
            "xl/worksheets/sheet1.xml",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zw.write_all(&worksheet_xml("A1:B2", &["A1", "B2"]))
            .unwrap();
        zw.start_file(
            "xl/sharedStrings.xml",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zw.write_all(br#"<?xml version="1.0"?><sst uniqueCount="1"><si><t>ok</t></si></sst>"#)
            .unwrap();
        let data = zw.finish().unwrap().into_inner();
        assert!(prescan_xlsx(&data).is_ok());
    }

    #[test]
    fn prescan_biff_rejects_attacks() {
        let le = |v: u32| v.to_le_bytes();
        // H5：伪造 Dimensions（0xFFFFFFFF 行，u32 布局）→ 拒绝
        let mut data = Vec::new();
        data.extend_from_slice(&0x0200u16.to_le_bytes());
        data.extend_from_slice(&16u16.to_le_bytes());
        data.extend_from_slice(&le(0));
        data.extend_from_slice(&le(0xFFFFFFFF));
        data.extend_from_slice(&le(0));
        data.extend_from_slice(&le(255));
        assert!(prescan_biff_records(&data).is_err());
        // H5：end < start 下溢 → 拒绝
        let mut data = Vec::new();
        data.extend_from_slice(&0x0200u16.to_le_bytes());
        data.extend_from_slice(&16u16.to_le_bytes());
        data.extend_from_slice(&le(100));
        data.extend_from_slice(&le(99));
        data.extend_from_slice(&le(0));
        data.extend_from_slice(&le(255));
        assert!(prescan_biff_records(&data).is_err());
        // M2：稀疏单元格包围盒（row 0 col 0 与 row 65535 col 255）→ 65536×256 超限
        let rec = |op: u16, payload: &[u8]| {
            let mut d = Vec::new();
            d.extend_from_slice(&op.to_le_bytes());
            d.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            d.extend_from_slice(payload);
            d
        };
        let mut data = Vec::new();
        data.extend_from_slice(&rec(0x027E, &{
            let mut p = Vec::new();
            p.extend_from_slice(&0u16.to_le_bytes());
            p.extend_from_slice(&0u16.to_le_bytes());
            p.extend_from_slice(&0u32.to_le_bytes());
            p
        }));
        data.extend_from_slice(&rec(0x027E, &{
            let mut p = Vec::new();
            p.extend_from_slice(&65535u16.to_le_bytes());
            p.extend_from_slice(&255u16.to_le_bytes());
            p.extend_from_slice(&0u32.to_le_bytes());
            p
        }));
        assert!(prescan_biff_records(&data).is_err());
        // MULRK 列区间 end < start → 拒绝
        let mut data = Vec::new();
        let mut p = Vec::new();
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&5u16.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&rec(0x00BD, &p));
        assert!(prescan_biff_records(&data).is_err());
    }

    #[test]
    fn prescan_biff_allows_legal_dimensions() {
        // BIFF8 布局（4×u16）小表 + 若干单元格照常通过（防误伤回归）
        let rec = |op: u16, payload: &[u8]| {
            let mut d = Vec::new();
            d.extend_from_slice(&op.to_le_bytes());
            d.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            d.extend_from_slice(payload);
            d
        };
        let mut data = Vec::new();
        let mut dims = Vec::new();
        dims.extend_from_slice(&0u16.to_le_bytes());
        dims.extend_from_slice(&99u16.to_le_bytes());
        dims.extend_from_slice(&0u16.to_le_bytes());
        dims.extend_from_slice(&20u16.to_le_bytes());
        dims.extend_from_slice(&0u16.to_le_bytes()); // reserved
        data.extend_from_slice(&rec(0x0200, &dims));
        let mut cell = Vec::new();
        cell.extend_from_slice(&0u16.to_le_bytes());
        cell.extend_from_slice(&0u16.to_le_bytes());
        cell.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&rec(0x027E, &cell));
        assert!(prescan_biff_records(&data).is_ok());
    }

    // 规范向量一（与 msoffcrypto-tool 6.0.0 doctest 一致，源自 Word 实际生成的文件）：
    // 口令派生 + encryptedKeyValue 解密必须得到固定的中间密钥
    const VEC_PASSWORD: &str = "Password1234_";
    const VEC_SALT: &[u8] = b"Lr]E\xdca\x0f\x93\x94\x12\xa0M\xa7\x91\x04f";
    const VEC_ENC_KEY_VALUE: &[u8] =
        b"\xa1l\xd5\x16Zz\xb9\xd2q\x11>\xd3\x86\xa7\x8c\xf4\x96\x92\xe8\xe5'\xb0\xc5\xfc\x00U\xed\x08\x0b|\xb9K";
    const VEC_SECRET_KEY: &[u8] =
        b"@ f\t\xd9\xfa\xad\xf2K\x07j\xeb\xf2\xc45\xb7B\x92\xc8\xb8\xa7\xaa\x81\xbcg\x9b\xe8\x97\x11\xb0*\xc2";

    #[test]
    fn kdf_matches_spec_vector() {
        let mut pwd16 = Vec::new();
        for unit in VEC_PASSWORD.encode_utf16() {
            pwd16.extend_from_slice(&unit.to_le_bytes());
        }
        let h = derive_iterated_hash(&pwd16, VEC_SALT, HashAlg::Sha512, 100_000);
        let key3 = derive_key(&h, &BLK_KEY_KEY_VALUE, HashAlg::Sha512, 256);
        let skey = aes_cbc_decrypt(&key3, VEC_SALT, VEC_ENC_KEY_VALUE).expect("CBC 解密失败");
        assert_eq!(skey, VEC_SECRET_KEY, "中间密钥应与规范向量一致");
    }

    // 规范向量二：口令校验（verify_password → True）
    const VEC2_SALT: &[u8] = b"\xcb\xca\x1c\x99\x93C\xfb\xad\x92\x07V4\x15\x004\xb0";
    const VEC2_ENC_VHI: &[u8] = b"9\xee\xa5N&\xe5\x14y\x8c(K\xc7qM8\xac";
    const VEC2_ENC_VHV: &[u8] = b"\x147mm\x81s4\xe6\xb0\xffO\xd8\"\x1a|g\x8e]\x8axN\x8f\x99\x9fL\x18\x890\xc3jK)\xc5\xb33`[\\\xd4\x03\xb0P\x03\xad\xcf\x18\xcc\xa8\xcb\xab\x8d\xeb\xe3s\xc6V\x04\xa0\xbe\xcf\xae\\\n\xd0";

    fn params_for_verify() -> AgileParams {
        AgileParams {
            spin_count: 100_000,
            enc_key_bits: 256,
            enc_hash: HashAlg::Sha512,
            enc_salt: VEC2_SALT.to_vec(),
            verifier_hash_input: VEC2_ENC_VHI.to_vec(),
            verifier_hash_value: VEC2_ENC_VHV.to_vec(),
            key_value: vec![0; 32],
            data_key_bits: 256,
            data_hash: HashAlg::Sha512,
            data_salt: vec![0; 16],
        }
    }

    #[test]
    fn verifier_matches_spec_vector() {
        let p = params_for_verify();
        let mut pwd16 = Vec::new();
        for unit in VEC_PASSWORD.encode_utf16() {
            pwd16.extend_from_slice(&unit.to_le_bytes());
        }
        let h = derive_iterated_hash(&pwd16, VEC2_SALT, HashAlg::Sha512, 100_000);
        let derive = |bk: &[u8]| derive_key(&h, bk, HashAlg::Sha512, 256);
        assert!(password_ok(&p, &derive), "正确口令应通过校验");
        let h_bad = derive_iterated_hash(b"wrong-password", VEC2_SALT, HashAlg::Sha512, 100_000);
        let derive_bad = |bk: &[u8]| derive_key(&h_bad, bk, HashAlg::Sha512, 256);
        assert!(!password_ok(&p, &derive_bad), "错误口令不应通过");
    }

    // 规范向量三（ECMA-376 Standard，Office 2007）：msoffcrypto-tool 6.0.0 doctest
    const VEC3_SALT: &[u8] = b"\xe8\x82fI\x0c[\xd1\xee\xbd+C\x94\xe3\xf80\xef";
    const VEC3_KEY: &[u8] = b"@\xb1:q\xf9\x0b\x96n7T\x08\xf2\xd1\x81\xa1\xaa";

    #[test]
    fn standard_kdf_matches_spec_vector() {
        let key = derive_standard_key_from_password(VEC_PASSWORD, VEC3_SALT, 128);
        assert_eq!(key, VEC3_KEY, "Standard 派生密钥应与规范向量一致");
    }

    // 加密往返：内存构造最小 docx → 测试内按 Agile 规范加密 → OLE 容器封装 → 解密预览
    #[test]
    fn encrypted_docx_roundtrip() {
        let docx = build_minimal_docx("机密测试内容");
        let ole = agile_encrypt_for_test(&docx, "口令Password123", 2000);

        // 无口令 → 哨兵错误
        assert_eq!(
            extract_office_text(&ole, "t.docx", None).unwrap_err(),
            "OFFICE_ENCRYPTED"
        );
        // 错误口令
        assert!(extract_office_text(&ole, "t.docx", Some("wrong-password"))
            .unwrap_err()
            .contains("密码错误"));
        // 正确口令
        let text = extract_office_text(&ole, "t.docx", Some("口令Password123")).unwrap();
        assert!(
            text.contains("机密测试内容"),
            "解密后应能提取文本: {}",
            text
        );
    }

    // 2.7.1 回归：spinCount 超过上限（10 万，Office 默认值）必须在解析阶段按
    // 参数异常拒绝，不再允许 10⁷ 次迭代散列的预览路径 DoS
    #[test]
    fn spin_count_above_cap_is_rejected() {
        let docx = build_minimal_docx("spin");
        let ole = agile_encrypt_for_test(&docx, "Password1234_", MAX_SPIN_COUNT + 1);
        let err = extract_office_text(&ole, "t.docx", Some("Password1234_")).unwrap_err();
        assert!(
            err.contains("spinCount"),
            "应报 spinCount 参数异常: {}",
            err
        );
    }

    fn build_minimal_docx(text: &str) -> Vec<u8> {
        use std::io::Write;
        let mut zw = zip::ZipWriter::new(Cursor::new(Vec::new()));
        // zip 8：FileOptions 带泛型参数，SimpleFileOptions 是无额外选项的别名
        zw.start_file(
            "word/document.xml",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zw.write_all(
            format!(
                "<w:document><w:body><w:p><w:r><w:t>{}</w:t></w:r></w:p></w:body></w:document>",
                text
            )
            .as_bytes(),
        )
        .unwrap();
        zw.finish().unwrap().into_inner()
    }

    fn b64s(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        if iv.len() < 16 {
            return None;
        }
        let cipher = new_aes(key)?;
        let mut padded = data.to_vec();
        if !padded.len().is_multiple_of(16) {
            padded.resize((padded.len() / 16 + 1) * 16, 0);
        }
        let mut prev: [u8; 16] = iv[..16].try_into().ok()?;
        for chunk in padded.chunks_exact_mut(16) {
            let block = GenericArray::from_mut_slice(chunk);
            for (b, p) in block.iter_mut().zip(prev.iter()) {
                *b ^= *p;
            }
            match &cipher {
                AesKey::K128(c) => c.encrypt_block(block),
                AesKey::K192(c) => c.encrypt_block(block),
                AesKey::K256(c) => c.encrypt_block(block),
            }
            prev.copy_from_slice(block.as_slice());
        }
        Some(padded)
    }

    fn agile_encrypt_for_test(payload: &[u8], password: &str, spin: u32) -> Vec<u8> {
        use rand::{rngs::OsRng, RngCore};
        use std::io::Write;

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut kd_salt = [0u8; 16];
        OsRng.fill_bytes(&mut kd_salt);
        let mut verifier_input = [0u8; 16];
        OsRng.fill_bytes(&mut verifier_input);

        let mut pwd16 = Vec::new();
        for unit in password.encode_utf16() {
            pwd16.extend_from_slice(&unit.to_le_bytes());
        }
        let h = derive_iterated_hash(&pwd16, &salt, HashAlg::Sha512, spin);
        let enc = |bk: &[u8]| derive_key(&h, bk, HashAlg::Sha512, 256);

        let enc_vhi =
            aes_cbc_encrypt(&enc(&BLK_KEY_VERIFIER_HASH_INPUT), &salt, &verifier_input).unwrap();
        let vhv = hash_bytes(HashAlg::Sha512, &verifier_input);
        let enc_vhv = aes_cbc_encrypt(&enc(&BLK_KEY_VERIFIER_HASH_VALUE), &salt, &vhv).unwrap();
        let mut secret16 = [0u8; 16];
        OsRng.fill_bytes(&mut secret16);
        let mut secret32 = secret16.to_vec();
        secret32.resize(32, 0x36);
        let enc_kv = aes_cbc_encrypt(&enc(&BLK_KEY_KEY_VALUE), &salt, &secret32).unwrap();

        let mut package = Vec::new();
        package.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        for (i, chunk) in payload.chunks(4096).enumerate() {
            let mut iv_input = kd_salt.to_vec();
            iv_input.extend_from_slice(&(i as u32).to_le_bytes());
            let iv = hash_bytes(HashAlg::Sha512, &iv_input);
            package.extend_from_slice(&aes_cbc_encrypt(&secret32, &iv, chunk).unwrap());
        }

        let info_xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
             <encryption><keyData saltSize=\"16\" blockSize=\"16\" keyBits=\"256\" hashSize=\"64\" \
             cipherAlgorithm=\"AES\" cipherChaining=\"ChainingModeCBC\" hashAlgorithm=\"SHA512\" \
             saltValue=\"{}\" /><keyEncryptors><keyEncryptor uri=\"x\">\
             <p:encryptedKey spinCount=\"{}\" saltSize=\"16\" blockSize=\"16\" keyBits=\"256\" \
             hashSize=\"64\" cipherAlgorithm=\"AES\" cipherChaining=\"ChainingModeCBC\" \
             hashAlgorithm=\"SHA512\" saltValue=\"{}\" encryptedVerifierHashInput=\"{}\" \
             encryptedVerifierHashValue=\"{}\" encryptedKeyValue=\"{}\" />\
             </keyEncryptor></keyEncryptors></encryption>",
            b64s(&kd_salt),
            spin,
            b64s(&salt),
            b64s(&enc_vhi),
            b64s(&enc_vhv),
            b64s(&enc_kv)
        );
        let mut info = vec![4, 0, 4, 0, 0x40, 0, 0, 0];
        info.extend_from_slice(info_xml.as_bytes());

        let mut cfb = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        {
            let mut s = cfb.create_stream("/EncryptionInfo").unwrap();
            s.write_all(&info).unwrap();
        }
        {
            let mut s = cfb.create_stream("/EncryptedPackage").unwrap();
            s.write_all(&package).unwrap();
        }
        cfb.into_inner().into_inner()
    }
}
