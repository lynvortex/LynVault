use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use serde_json;
use zeroize::Zeroize;

use crate::audit::AuditLog;
use crate::crypto::*;
use crate::error::VaultError;
use crate::index::{FileMeta, Index, IndexManager};
use crate::lock::LockState;
use crate::wipe::{dod_erase, dod_overwrite_range, secure_wipe_vec};

// --- 常量 ---
const MAGIC: &[u8; 8] = b"PYVAULT4";
const VERSION: u8 = 4;
const HEADER_SIZE: usize = 1024;
const MAX_PARTITIONS: usize = 8;
const PARTITION_ENTRY_SIZE: usize = 96;

/// LynVault 文件 magic bytes（8 字节），用于启动扫描时识别真正的保险柜文件
pub const VAULT_MAGIC: &[u8; 8] = MAGIC;

/// 快速检查文件是否为 LynVault 保险柜（仅读取并比对头部 8 字节 magic）。
/// 任何 I/O 错误或 magic 不匹配都返回 false（不暴露具体错误）。
pub fn is_vault_file(path: &Path) -> bool {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = [0u8; 8];
    match f.read_exact(&mut buf) {
        Ok(_) => &buf == VAULT_MAGIC,
        Err(_) => false,
    }
}

const LOCK_OFFSET: usize = 887;
// 签名范围仅到 lock_offset 之前；锁定区（887-927）由自身 HMAC 保护，
// 每次认证失败都会修改锁定区，若包含在签名中会导致后续认证因签名不匹配而失败
const SIGNED_LENGTH: usize = 887;
const SIGNATURE_OFFSET: usize = 960;
const SIGNATURE_SIZE: usize = 64;

const DEFAULT_PARTITION: &str = "Main";

/// 单次操作中内存缓冲区的上限（256 MiB）。
/// 超过此大小的文件改用流式读写，避免 OOM（M1 修复）。
const MAX_INMEM_BUFFER: usize = 256 * 1024 * 1024;
const MAX_IMPORT_DEPTH: usize = 64;
const MAX_IMPORT_ENTRIES: usize = 100_000;

// ─────────── 自由函数：避免 &mut self 借用冲突 ───────────

/// 从文件读取并解密索引
fn load_index_from_file(
    file: &mut File,
    enc_key: &[u8; 32],
    offset: u64,
    length: u64,
) -> Result<Index, VaultError> {
    // 2.3.0 修复：索引长度上限校验，防止恶意头部（溢出绕过边界检查后）触发超大分配
    if length > MAX_INMEM_BUFFER as u64 {
        return Err(VaultError::Other(format!(
            "索引数据过大（{} 字节），超过单次加载上限", length
        )));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut enc = vec![0u8; length as usize];
    file.read_exact(&mut enc)?;
    let plain = decrypt_gcm(enc_key, &enc, b"index").ok_or(VaultError::DecryptFailed)?;
    let index: Index = serde_json::from_slice(&plain)?;
    secure_wipe_vec(plain);
    Ok(index)
}

/// 加密索引并追加写入，返回 (new_offset, new_length)。
///
/// C3 修复（关键）：旧实现的写入顺序是
///   1. 写新索引到末尾
///   2. 用随机数据覆写旧索引
///   3. （save_index 调用 update_header）更新头部偏移
/// 在第 2 步与第 3 步之间崩溃，头部仍指向已被随机数据覆盖的旧索引位置，
/// 下次打开会因 DecryptFailed 永久锁定。
///
/// 新顺序：
///   1. 写新索引到末尾
///   2. 更新头部偏移指向新索引（旧索引位置暂存）
///   3. 擦除旧索引（此时即使崩溃，新索引已可由头部定位，旧索引只是垃圾）
/// 由于头部更新在本函数内无法完成（需要 &mut self 全字段），
/// 此处返回 new_off/new_len + 旧位置信息，由 save_index 协调顺序。
fn save_index_to_file(
    file: &mut File,
    enc_key: &[u8; 32],
    index: &Index,
    old_offset: u64,
    old_length: u64,
) -> Result<(u64, u64), VaultError> {
    let plain = serde_json::to_vec(index)?;
    let encrypted = encrypt_gcm(enc_key, &plain, b"index", None)?;

    // 步骤 1：新索引写入文件末尾
    let new_offset = file.seek(SeekFrom::End(0))?;
    file.write_all(&encrypted)?;
    file.flush()?;
    file.sync_all()?;

    // 注意：旧索引的擦除推迟到 save_index 完成 update_header 之后，
    // 以保证头部偏移先于旧索引擦除被持久化（C3 修复）。
    let _ = (old_offset, old_length);

    secure_wipe_vec(plain);
    Ok((new_offset, encrypted.len() as u64))
}

/// 在头部已更新后擦除旧索引区段。
/// 即使此步失败，新索引已可由头部偏移定位，不影响正确性。
fn wipe_old_index_range(file: &mut File, old_offset: u64, old_length: u64) {
    if old_length == 0 {
        return;
    }
    // 用 DoD 7-pass 擦除（C7 修复：旧索引含明文 size/路径元数据）
    if let Err(e) = dod_overwrite_range(file, old_offset, old_length) {
        log::warn!("擦除旧索引失败（不影响正确性）: {}", e);
    }
    let _ = file.flush();
}

/// 跨文件流式拷贝（2.4.1 碎片整理紧凑迁移用）。
/// 源/目标为不同文件，天然无单文件自拷贝的重叠破坏风险。
fn copy_between(
    src: &mut File,
    dst: &mut File,
    src_off: u64,
    dst_off: u64,
    len: u64,
) -> std::io::Result<()> {
    const CHUNK: usize = 1024 * 1024;
    let mut buf = vec![0u8; CHUNK];
    let mut remaining = len;
    let mut s = src_off;
    let mut d = dst_off;
    while remaining > 0 {
        let n = remaining.min(CHUNK as u64) as usize;
        src.seek(SeekFrom::Start(s))?;
        src.read_exact(&mut buf[..n])?;
        dst.seek(SeekFrom::Start(d))?;
        dst.write_all(&buf[..n])?;
        s += n as u64;
        d += n as u64;
        remaining -= n as u64;
    }
    Ok(())
}

/// 同步父目录，确保重命名持久化。Windows 上无法用 File::open 打开目录，
/// 需 FILE_FLAG_BACKUP_SEMANTICS；失败时仅记录日志（尽力而为）。
fn sync_parent_dir(path: &Path) {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return,
    };
    #[cfg(unix)]
    {
        let _ = File::open(parent).and_then(|d| d.sync_all());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // 0x02000000 = FILE_FLAG_BACKUP_SEMANTICS（允许以目录句柄打开）
        if let Ok(d) = OpenOptions::new().read(true).custom_flags(0x02000000).open(parent) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = File::open(parent).and_then(|d| d.sync_all());
    }
}

/// 写入完整头部（含签名）
fn write_header_to_file(
    file: &mut File,
    lock_state: &LockState,
    salt: &[u8; 32],
    partitions: &[PartitionInfo],
    sign_key: &[u8; 32],
) -> Result<(), VaultError> {
    let mut header = [0u8; HEADER_SIZE];

    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION;
    // bytes 9..40 reserved
    // bytes 41..73: was lock_key (plaintext) — now zeroed (lock_key is derived from salt)
    header[73..105].copy_from_slice(salt);
    // num_partitions always MAX_PARTITIONS to hide real count
    header[105] = MAX_PARTITIONS as u8;

    let mut off = 106;
    for i in 0..MAX_PARTITIONS {
        if let Some(p) = partitions.get(i) {
            // M7 修复：按字符截断而非字节，避免切断多字节字符产生无效 UTF-8
            let alias_bytes: Vec<u8> = p.alias.chars().take(16).collect::<String>().into_bytes();
            let copy_len = alias_bytes.len().min(16);
            header[off..off + copy_len].copy_from_slice(&alias_bytes[..copy_len]);
            off += 16;
            header[off..off + 32].copy_from_slice(&p.salt);
            off += 32;
            header[off..off + 32].copy_from_slice(&p.auth_tag);
            off += 32;
            header[off..off + 8].copy_from_slice(&p.index_offset.to_le_bytes());
            off += 8;
            header[off..off + 8].copy_from_slice(&p.index_length.to_le_bytes());
            off += 8;
        } else {
            // 2.3.0 修复（防元数据泄露）：未使用的条目**整体**填充随机数据（含别名），
            // 不再以「别名首字节 0」作标记 —— 旧标记使读取者可数出真实分区数量。
            // 打开时会对全部 8 个条目做恒定次数的认证尝试，伪条目认证必然失败。
            let mut rand_buf = [0u8; PARTITION_ENTRY_SIZE];
            OsRng.fill_bytes(&mut rand_buf);
            header[off..off + PARTITION_ENTRY_SIZE].copy_from_slice(&rand_buf);
            off += PARTITION_ENTRY_SIZE;
        }
    }

    header[LOCK_OFFSET] = lock_state.lock_count;
    header[LOCK_OFFSET + 1..LOCK_OFFSET + 9]
        .copy_from_slice(&lock_state.lock_until.to_le_bytes());
    // 2.3.0 修复：锁定区 HMAC 使用从 salt 独立派生的公开密钥，
    // 任意密码的打开尝试都能校验并递增计数（详见 crypto::derive_lock_mac_key）
    let mac_key = derive_lock_mac_key(salt);
    let hmac = lock_state.compute_hmac(&mac_key);
    header[LOCK_OFFSET + 9..LOCK_OFFSET + 9 + 32].copy_from_slice(&hmac);

    let sig = compute_header_signature(&header[..SIGNED_LENGTH], sign_key);
    header[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE].copy_from_slice(&sig);

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

/// 从保险柜文件读取并解密原始数据
/// `aad` 必须与加密时使用的值一致（通常为文件虚拟路径）
fn read_decrypt_file_data(
    file: &mut File,
    enc_key: &[u8; 32],
    offset: u64,
    length: u64,
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let file_len = file.metadata()?.len();
    let end = offset.checked_add(length)
        .ok_or_else(|| VaultError::Other("文件数据范围溢出".into()))?;
    if end > file_len || length > MAX_INMEM_BUFFER as u64 {
        return Err(VaultError::Other("文件数据超出安全读取范围".into()));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut enc_data = vec![0u8; length as usize];
    file.read_exact(&mut enc_data)?;
    decrypt_gcm(enc_key, &enc_data, aad).ok_or(VaultError::DecryptFailed)
}

/// 安全文件名清理
/// 2.4.1 变更：由「白名单」改为「黑名单」策略 —— 仅剔除路径危险字符与控制字符，
/// 保留 Unicode 字符与常见符号（!@#$%^& 等）。旧白名单会把 `report#1.txt`
/// 静默改名为 `report1.txt`，批量提取时引发大量「目标已存在」失败。
/// 仍然处理：结尾 '.'/' '（Windows 规范化）、保留设备名（CON/NUL/COM1..）。
fn sanitize_filename(name: &str) -> String {
    let mut safe: String = name
        .chars()
        .filter(|c| {
            let cu = *c as u32;
            // 控制字符与 DEL 剔除；路径分隔符与 Windows 保留字符剔除
            cu >= 0x20 && cu != 0x7f
                && !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
        .collect();
    while safe.ends_with('.') || safe.ends_with(' ') {
        safe.pop();
    }
    let upper = safe.to_uppercase();
    // Windows 保留设备名检查：主名（去掉最后一个扩展名）匹配即视为保留。
    // 旧实现只比对完整名，`CON.txt` 不会被加前缀，提取到 Windows 即创建失败。
    let stem = match upper.rfind('.') {
        Some(pos) => &upper[..pos],
        None => upper.as_str(),
    };
    if matches!(stem,
        "CON" | "PRN" | "AUX" | "NUL"
        | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
        | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9")
    {
        safe.insert(0, '_');
    }
    if safe.is_empty() { "extracted_file".to_string() } else { safe }
}

/// 校验分区别名（与 commands.rs 前端校验保持一致，供库级 API 直接调用时防护）。
fn is_valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && !alias.trim().is_empty()
        && alias.len() <= 16
        && alias.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == ' ')
}

// ─────────────────────────────────────────────────────────────

/// 保险柜主体
pub struct Vault {
    pub(crate) path: Option<PathBuf>,
    pub(crate) file: Option<File>,

    pub(crate) enc_key: Option<[u8; 32]>,
    pub(crate) auth_key: Option<[u8; 32]>,
    pub(crate) sign_key: Option<[u8; 32]>,

    pub(crate) salt: [u8; 32],
    pub(crate) lock_state: LockState,

    pub(crate) partitions: Vec<PartitionInfo>,
    pub(crate) active_partition: Option<usize>,

    pub(crate) audit: Option<AuditLog>,

    /// 2.4.1 新增：解密后的索引内存缓存（P0-2 优化核心）。
    /// 旧实现每次操作都要「读磁盘 → AES-GCM 解密 → JSON 反序列化」，
    /// 批量导入 1000 个文件 = 2000+ 次全量解密加载。
    /// 现在打开保险柜后索引常驻内存，save_index 成功后同步刷新缓存。
    /// 注意：缓存与磁盘一致性由「所有索引变更必须走 save_index」这一约定保证。
    pub(crate) cached_index: Option<Index>,

    /// 2.4.1 新增：审计条目有未落盘的变更（关闭时才需要补一次 save_index，
    /// 避免旧实现 close() 无条件全量重写索引 + 7-pass 擦旧索引的开销）。
    pub(crate) audit_dirty: bool,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            path: None,
            file: None,
            enc_key: None,
            auth_key: None,
            sign_key: None,
            salt: [0u8; 32],
            lock_state: LockState::new(),
            partitions: Vec::new(),
            active_partition: None,
            audit: None,
            cached_index: None,
            audit_dirty: false,
        }
    }
}

#[derive(Debug, Clone, Zeroize)]
pub struct PartitionInfo {
    pub alias: String,
    pub salt: [u8; 32],
    pub auth_tag: [u8; 32],
    pub index_offset: u64,
    pub index_length: u64,
}

impl Vault {
    /// 2.4.1 新增：写审计并置脏标记（统一入口）。
    /// 旧实现审计在各处手动 add，close() 无条件全量重写索引以持久化审计；
    /// 现在只有 audit_dirty=true 时 close() 才补一次 save_index。
    pub(crate) fn log_event(&mut self, msg: &str) {
        if let Some(ref mut audit) = self.audit {
            audit.add(msg);
        }
        self.audit_dirty = true;
    }

    // ═══════════════ 创建 ═══════════════

    /// 2.4.1 变更：创建后直接建立会话（P2-20 优化）。
    /// 旧流程「create → 立刻 open_and_authenticate」要对刚写完的文件
    /// 再跑 8 次 Argon2id（约 1 秒）。现在 create 成功即进入已解锁状态，
    /// 全程只派生 1 组密钥。返回后调用方无需再次认证。
    pub fn create(
        &mut self,
        path: &Path,
        password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<(), VaultError> {
        // 2.4.1 修复：按字符数而非字节数校验（旧实现 4 个汉字即通过）
        if password.chars().count() < 12 {
            return Err(VaultError::Other("密码长度至少 12 位".into()));
        }
        if self.is_open() {
            return Err(VaultError::AlreadyOpen);
        }

        let mut file = OpenOptions::new()
            .read(true).write(true).create(true).truncate(true).open(path)?;
        file.write_all(&[0u8; HEADER_SIZE])?;
        file.flush()?;

        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        let mut keys = derive_keys(password, key_file_data, &salt)?;
        let auth_tag = create_auth_tag(&keys.auth_key);

        let empty_index = Index::new();
        let index_json = serde_json::to_vec(&empty_index)?;
        let enc_index = encrypt_gcm(&keys.enc_key, &index_json, b"index", None)?;

        let index_offset = file.seek(SeekFrom::End(0))?;
        let index_length = enc_index.len() as u64;
        file.write_all(&enc_index)?;
        file.flush()?;
        file.sync_all()?;

        let partition = PartitionInfo {
            alias: DEFAULT_PARTITION.into(),
            salt,
            auth_tag,
            index_offset,
            index_length,
        };

        // 2.3.0：锁定区 HMAC 由 write_header_to_file 用公开密钥计算（见 crypto::derive_lock_mac_key），
        // 不再绑定主密码 —— 旧实现导致错误密码无法递增计数（锁定永不生效）且诱饵分区无法打开。
        let lock_state = LockState::new();
        write_header_to_file(&mut file, &lock_state, &salt, &[partition.clone()], &keys.sign_key)?;

        // ── P2-20：直接建立会话（不再二次认证） ──
        let mut audit = AuditLog::new(keys.auth_key);
        audit.add("保险柜已创建并解锁");
        let mut cached = empty_index;
        cached.audit = audit.to_vec();

        self.file = Some(file);
        self.path = Some(path.to_path_buf());
        self.salt = salt;
        self.enc_key = Some(keys.enc_key);
        self.auth_key = Some(keys.auth_key);
        self.sign_key = Some(keys.sign_key);
        self.lock_state = lock_state;
        self.partitions = vec![partition];
        self.active_partition = Some(0);
        self.audit = Some(audit);
        self.cached_index = Some(cached);
        self.audit_dirty = true; // 审计尚未随索引落盘，close() 时补写

        keys.zeroize(); // 各密钥副本已存入 self，此处清理临时结构
        secure_wipe_vec(index_json);
        Ok(())
    }

    // ═══════════════ 打开认证 ═══════════════

    pub fn open_and_authenticate(
        &mut self,
        path: &Path,
        password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<usize, VaultError> {
        if self.is_open() {
            return Err(VaultError::AlreadyOpen);
        }
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header)?;

        let (magic, version, salt) = Self::parse_header(&header)?;
        if &magic != MAGIC || version != VERSION {
            return Err(VaultError::BadMagic);
        }

        let lock_count = header[LOCK_OFFSET];
        let lock_until = f64::from_le_bytes(header[LOCK_OFFSET+1..LOCK_OFFSET+9].try_into().unwrap());

        // 2.3.0 修复（关键）：锁定区 HMAC 使用从 salt 独立派生的**公开**密钥，
        // 与密码无关。因此：
        // - 错误密码能通过锁定区校验并进入分区认证 → 认证失败会真正递增 lock_count（锁定生效）；
        // - 诱饵分区（独立密码）也能通过锁定区校验并打开。
        // 旧版（<2.3.0）锁定区用密码派生密钥签名，此处做兼容校验并在后续写入时自动迁移。
        let mac_key = derive_lock_mac_key(&salt);
        let mut lock_state = LockState { lock_count, lock_until, lock_until_monotonic: None };
        let stored_hmac: [u8; 32] = header[LOCK_OFFSET+9..LOCK_OFFSET+9+32].try_into().unwrap();
        let verified = if lock_state.verify_hmac(&mac_key, &stored_hmac) {
            true
        } else {
            // 旧版锁定区：用密码派生密钥（旧格式）再试一次；仅用于旧保险柜打开时校验。
            let legacy_key = derive_legacy_lock_key(&salt, password, key_file_data);
            lock_state.verify_hmac(&legacy_key, &stored_hmac)
        };
        if !verified {
            // 新密钥与旧派生方式都无法校验 → 锁定区确实被篡改（或密码与密钥文件不匹配的旧保险柜）
            return Err(VaultError::Other("头部锁定区被篡改".into()));
        }
        if lock_state.is_locked() {
            return Err(VaultError::Locked);
        }

        // 解析分区表：始终扫描 MAX_PARTITIONS 个条目（2.3.0 起伪条目整体随机填充，
        // 不再有「别名首字节 0」标记，因此不再跳过任何条目 —— 全部参与认证以保证恒定时间）
        let mut parsed: Vec<PartitionInfo> = Vec::new();
        let mut off = 106;
        for _ in 0..MAX_PARTITIONS {
            if off + PARTITION_ENTRY_SIZE > HEADER_SIZE { break; }
            let alias_len = header[off..off+16].iter().position(|&b| b == 0).unwrap_or(16);
            let alias = String::from_utf8_lossy(&header[off..off+alias_len]).to_string();
            let mut p_salt = [0u8; 32];
            p_salt.copy_from_slice(&header[off+16..off+48]);
            let mut auth_tag = [0u8; 32];
            auth_tag.copy_from_slice(&header[off+48..off+80]);
            let index_offset = u64::from_le_bytes(header[off+80..off+88].try_into().unwrap());
            let index_length = u64::from_le_bytes(header[off+88..off+96].try_into().unwrap());
            parsed.push(PartitionInfo { alias, salt: p_salt, auth_tag, index_offset, index_length });
            off += PARTITION_ENTRY_SIZE;
        }

        // C9 修复 + 2.3.0 + 2.4.1：始终对**全部 8 个条目**执行完整 Argon2id 派生
        // （即使中途匹配），消除计时侧信道 —— 总派生工作量恒定，与真实分区数量无关。
        //
        // 2.4.1 优化（P1-6）：8 组密钥改为分块并行派生（块大小 = min(CPU 逻辑核数, 4)），
        // 串行约 1s 降至约 0.25-0.5s。并行只是调度优化：8 次派生仍 100% 完成后
        // 才进入认证比较，恒定时间语义不变；并行度上限 4 同时把瞬时内存峰值
        // 控制在 4×64MB，低配机器按核数自动降为 1（退化为旧行为）。
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let parallel = cpus.min(4).max(1);
        let mut keys_list: Vec<KeyMaterial> = Vec::with_capacity(parsed.len());
        for chunk in parsed.chunks(parallel) {
            let results: Vec<Result<KeyMaterial, VaultError>> = std::thread::scope(|s| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|p| s.spawn(move || derive_keys(password, key_file_data, &p.salt)))
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join()
                            .unwrap_or_else(|_| Err(VaultError::Other("密钥派生线程失败".into())))
                    })
                    .collect()
            });
            for r in results {
                keys_list.push(r?);
            }
        }

        // 认证比较阶段（此时重计算已完成，循环本身极轻）
        let mut matched_idx: Option<usize> = None;
        let mut matched_index: Option<Index> = None;
        let mut matched_keys: Option<([u8; 32], [u8; 32], [u8; 32])> = None;
        for (idx, keys) in keys_list.iter_mut().enumerate() {
            let p = &parsed[idx];
            if matched_idx.is_none() && verify_auth_tag(&keys.auth_key, &p.auth_tag) {
                match Self::try_authenticate_partition(&mut file, &header, &parsed, idx, keys) {
                    Ok(index) => {
                        matched_idx = Some(idx);
                        matched_index = Some(index);
                        matched_keys = Some((keys.enc_key, keys.auth_key, keys.sign_key));
                    }
                    Err(e) => {
                        // 匹配分区但头部/索引校验失败 → 视为篡改，中止并清理全部密钥
                        for k in keys_list.iter_mut() { k.zeroize(); }
                        return Err(e);
                    }
                }
            }
            // 不 return，继续遍历剩余条目（恒定时间语义由 8 次派生保证）
        }

        // 全部密钥材料统一清理（匹配项的副本已随 matched_keys 带出）
        for k in keys_list.iter_mut() { k.zeroize(); }

        if let (Some(idx), Some(index), Some((enc_key, auth_key, sign_key))) =
            (matched_idx, matched_index, matched_keys)
        {
            // 过滤出真实分区（别名合法的条目；伪条目随机数据几乎不可能通过校验）
            let real_partitions: Vec<PartitionInfo> = parsed.iter()
                .filter(|p| is_valid_alias(&p.alias))
                .cloned()
                .collect();
            let matched_salt = parsed[idx].salt;
            let matched_tag = parsed[idx].auth_tag;
            let active = real_partitions.iter()
                .position(|p| p.salt == matched_salt && p.auth_tag == matched_tag)
                .ok_or_else(|| VaultError::Other("内部错误：匹配分区丢失".into()))?;

            lock_state.reset();
            self.lock_state = lock_state;
            self.salt = salt;
            self.partitions = real_partitions;
            self.active_partition = Some(active);

            self.enc_key = Some(enc_key);
            self.auth_key = Some(auth_key);
            self.sign_key = Some(sign_key);

            let mut audit = AuditLog::from_entries(index.audit.clone(), auth_key);
            audit.add("保险柜已解锁");
            self.audit = Some(audit);

            self.file = Some(file);
            self.path = Some(path.to_path_buf());
            // 2.4.1：成功打开后把索引放入内存缓存，后续操作不再重复解密加载
            self.cached_index = Some(index);
            self.audit_dirty = true; // "已解锁"审计尚未落盘

            // 成功打开：重置锁定区并重新签名头部（旧保险柜在此完成锁定区格式迁移）
            self.update_header()?;

            return Ok(active);
        }

        // 全部失败：2.3.0 起真正递增锁定计数（公开密钥可计算 HMAC，无需正确密码）。
        // 5 次错误 → 锁定 30 分钟；锁定期间 is_locked() 直接拒绝（包括正确密码）。
        lock_state.record_failure();
        let mut lock_buf = [0u8; 41];
        lock_buf[0] = lock_state.lock_count;
        lock_buf[1..9].copy_from_slice(&lock_state.lock_until.to_le_bytes());
        let hmac = lock_state.compute_hmac(&mac_key);
        lock_buf[9..41].copy_from_slice(&hmac);
        file.seek(SeekFrom::Start(LOCK_OFFSET as u64))?;
        file.write_all(&lock_buf)?;
        file.flush()?;
        file.sync_all()?;

        Err(VaultError::AuthFailed)
    }

    /// 2.4.1 新增（从 open_and_authenticate 抽取）：对已通过 auth_tag 校验的分区
    /// 做头部签名校验 + 索引边界检查 + 读取解密。密钥由调用方持有并负责清理。
    fn try_authenticate_partition(
        file: &mut File,
        header: &[u8; HEADER_SIZE],
        parsed: &[PartitionInfo],
        idx: usize,
        keys: &KeyMaterial,
    ) -> Result<Index, VaultError> {
        let p = &parsed[idx];
        // 头部签名校验（2.3.0 语义调整）：
        // - 单分区保险柜：签名必须与当前分区密钥匹配，否则视为篡改；
        // - 多分区保险柜：头部可能由其他分区（不同密码）的持有者签名，
        //   签名不匹配不代表篡改（篡改仍会被分区认证失败 / GCM 认证失败捕获），
        //   打开成功后 update_header 会用当前分区密钥重新签名。
        let real_count = parsed.iter().filter(|pp| is_valid_alias(&pp.alias)).count();
        if !verify_header_signature(header, &keys.sign_key) && real_count <= 1 {
            return Err(VaultError::Other("保险柜头部已被篡改".into()));
        }

        // 2.3.0 修复：索引边界检查使用 checked_add 防 u64 溢出回绕，
        // 并对索引长度设上限，防止恶意头部触发超大内存分配（进程被杀）
        let file_size = file.metadata()?.len();
        match p.index_offset.checked_add(p.index_length) {
            None => return Err(VaultError::Other("索引超出文件范围".into())),
            Some(end) if end > file_size => {
                return Err(VaultError::Other("索引超出文件范围".into()));
            }
            _ => {}
        }
        if p.index_length > MAX_INMEM_BUFFER as u64 {
            return Err(VaultError::Other(format!(
                "索引过大（{} 字节），超过单次加载上限", p.index_length
            )));
        }

        file.seek(SeekFrom::Start(p.index_offset))?;
        let mut enc_index = vec![0u8; p.index_length as usize];
        file.read_exact(&mut enc_index)?;
        let index_json = match decrypt_gcm(&keys.enc_key, &enc_index, b"index") {
            Some(j) => j,
            None => {
                secure_wipe_vec(enc_index);
                return Err(VaultError::DecryptFailed);
            }
        };
        let index: Index = serde_json::from_slice(&index_json)?;
        secure_wipe_vec(enc_index);
        secure_wipe_vec(index_json);
        Ok(index)
    }

    // ═══════════════ 索引操作 ═══════════════

    pub fn get_index_manager(&mut self) -> Result<IndexManager<'_>, VaultError> {
        if self.enc_key.is_none() || self.file.is_none() {
            return Err(VaultError::NotOpen);
        }
        Ok(IndexManager::new(self))
    }

    /// 2.4.1 优化（P0-2）：索引加载走内存缓存。
    /// 旧实现每次操作都「读磁盘 → AES-GCM 解密 → JSON 反序列化」；
    /// 现在首次加载后常驻缓存，save_index 成功后同步刷新。
    pub fn load_index(&mut self) -> Result<Index, VaultError> {
        if let Some(idx) = &self.cached_index {
            return Ok(idx.clone());
        }
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let (offset, length) = {
            let p = &self.partitions[active];
            (p.index_offset, p.index_length)
        };
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let index = load_index_from_file(file, enc_key, offset, length)?;
        self.cached_index = Some(index.clone());
        Ok(index)
    }

    pub fn save_index(&mut self, index: &Index) -> Result<(), VaultError> {
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let (old_off, old_len) = {
            let p = &self.partitions[active];
            (p.index_offset, p.index_length)
        };

        let mut idx = index.clone();
        if let Some(audit) = &self.audit {
            idx.audit = audit.to_vec();
        }

        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        // 步骤 1：写新索引到末尾（不擦旧索引）
        let (new_off, new_len) = save_index_to_file(file, enc_key, &idx, old_off, old_len)?;

        // 步骤 2：更新内存中的分区信息
        self.partitions[active].index_offset = new_off;
        self.partitions[active].index_length = new_len;

        // 步骤 3：更新头部偏移（持久化指向新索引）
        self.update_header()?;

        // 步骤 4：头部已落盘，现在安全擦除旧索引（C3 修复关键点）
        // 即使此步失败/崩溃，新索引已可由头部定位，旧索引只是垃圾数据
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        wipe_old_index_range(file, old_off, old_len);

        // 2.4.1：磁盘写入成功后刷新内存缓存（一致性由「变更必须走 save_index」保证）
        self.cached_index = Some(idx);
        self.audit_dirty = false;
        Ok(())
    }

    // ═══════════════ 头部更新 ═══════════════

    fn update_header(&mut self) -> Result<(), VaultError> {
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let sign_key = self.sign_key.as_ref().ok_or(VaultError::NotOpen)?;
        write_header_to_file(
            file, &self.lock_state,
            &self.salt, &self.partitions, sign_key,
        )
    }

    fn parse_header(header: &[u8; HEADER_SIZE])
        -> Result<([u8; 8], u8, [u8; 32]), VaultError>
    {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&header[..8]);
        let version = header[8];
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&header[73..105]);
        Ok((magic, version, salt))
    }

    // ═══════════════ 分区管理 ═══════════════

    pub fn add_partition(&mut self, alias: &str, fake_password: &str, key_file_data: Option<&[u8]>) -> Result<(), VaultError> {
        if self.file.is_none() { return Err(VaultError::NotOpen); }
        // 2.3.0：库级 API 也校验分区别名（此前仅 Tauri 命令层校验，
        // 非法别名可能导致重开后分区不可见）
        if !is_valid_alias(alias) {
            return Err(VaultError::Other("分区别名只能包含字母、数字、下划线、短横线和空格，长度 1-16 字符".into()));
        }
        // 2.4.1 修复（P2-19）：分区密码同样按字符数校验（旧实现无任何强度校验）
        if fake_password.chars().count() < 12 {
            return Err(VaultError::Other("分区密码长度至少 12 位".into()));
        }
        if self.partitions.len() >= MAX_PARTITIONS { return Err(VaultError::TooManyPartitions); }

        let mut part_salt = [0u8; 32];
        OsRng.fill_bytes(&mut part_salt);
        let mut keys = derive_keys(fake_password, key_file_data, &part_salt)?;
        let auth_tag = create_auth_tag(&keys.auth_key);

        let empty_index = Index::new();
        let plain = serde_json::to_vec(&empty_index)?;
        let enc = encrypt_gcm(&keys.enc_key, &plain, b"index", None)?;

        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(&enc)?;
        file.flush()?;
        file.sync_all()?;

        self.partitions.push(PartitionInfo {
            alias: alias.into(),
            salt: part_salt,
            auth_tag,
            index_offset: offset,
            index_length: enc.len() as u64,
        });

        self.log_event(&format!("添加伪装分区 '{}'", alias));
        self.update_header()?;
        keys.zeroize();
        secure_wipe_vec(plain);
        Ok(())
    }

    pub fn remove_partition(&mut self, alias: &str) -> Result<(), VaultError> {
        if self.file.is_none() { return Err(VaultError::NotOpen); }
        let pos = self.partitions.iter().position(|p| p.alias == alias)
            .ok_or(VaultError::PartitionNotFound)?;
        if pos == 0 { return Err(VaultError::Other("不能删除主分区".into())); }
        if self.active_partition == Some(pos) {
            return Err(VaultError::Other("不能删除当前使用的分区".into()));
        }

        // 2.3.0 顺序修正：先持久化「分区已删除」（update_header），再擦除旧索引区。
        // 旧实现先擦后更新头部，擦除后崩溃会让头部仍指向已被覆盖的索引 → 永久损坏。
        let p = self.partitions[pos].clone();
        self.partitions.remove(pos);
        // 调整活跃分区索引：如果删除的位置在当前活跃分区之前，活跃索引需要减 1
        if let Some(active) = self.active_partition {
            if pos < active {
                self.active_partition = Some(active - 1);
            }
        }
        self.log_event(&format!("删除分区 '{}'", alias));
        self.update_header()?;

        // 擦除旧索引区（尽力而为）。已知限制：该分区的文件密文因无分区密码无法定位，
        // 无法一并擦除（README「已知限制」已说明）；保险柜整体销毁时会一并擦除。
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = dod_overwrite_range(file, p.index_offset, p.index_length) {
                log::warn!("擦除已删除分区的索引失败（不影响正确性）: {}", e);
            }
            let _ = file.flush();
            let _ = file.sync_all();
        }
        Ok(())
    }

    // ═══════════════ 文件导入 ═══════════════

    /// 导入单个文件（独立命令路径：加载缓存索引 → 写入 → 单次 save_index）。
    pub fn import_file(&mut self, src_path: &Path, vpath: &str) -> Result<(), VaultError> {
        let mut index = self.load_index()?;
        self.import_file_into_index(&mut index, src_path, vpath)?;
        self.save_index(&index)
    }

    /// 2.4.1 新增：批量导入多个文件（P0-2 优化核心）。
    /// 单次 load_index（缓存）+ 内存更新 + **一次** save_index。
    /// 旧实现（前端循环调用 import_file）N 个文件 = N 次全量索引重写
    /// + N×10 次 fsync；现在批量路径只有 1 次。
    /// 返回 (成功数, 失败数)。单个文件失败记录日志后继续。
    pub fn import_files_batch(
        &mut self,
        src_paths: &[String],
        dest_base: &str,
    ) -> Result<(usize, usize), VaultError> {
        let mut index = self.load_index()?;
        let base_clean = dest_base.trim_end_matches('/');
        let mut ok = 0usize;
        let mut fail = 0usize;
        for p in src_paths {
            let src = std::path::Path::new(p);
            let name = src.file_name().unwrap_or_default().to_string_lossy().to_string();
            let vpath = format!("{}/{}", base_clean, name);
            match self.import_file_into_index(&mut index, src, &vpath) {
                Ok(()) => ok += 1,
                Err(e) => {
                    fail += 1;
                    log::warn!("导入 '{}' 失败: {}", src.display(), e);
                }
            }
        }
        // 2.4.1（P1-14）：批量操作记一条摘要审计，不再逐文件刷审计链
        if ok > 0 || fail > 0 {
            self.log_event(&format!("批量导入：成功 {} 个，失败 {} 个", ok, fail));
        }
        if ok > 0 {
            self.save_index(&index)?;
        }
        Ok((ok, fail))
    }

    /// 2.4.1 新增（从 import_file 抽取）：把一个文件加密追加到保险柜并更新**内存中的**索引。
    /// 不写盘、不审计 —— 由调用方决定单文件（import_file：逐次落盘）
    /// 或批量（import_files_batch / import_folder：最后一次落盘）策略。
    fn import_file_into_index(
        &mut self,
        index: &mut Index,
        src_path: &Path,
        vpath: &str,
    ) -> Result<(), VaultError> {
        // M5 修复：归一化 + 校验虚拟路径
        let vpath = Index::normalize_vpath(vpath)
            .filter(|p| Index::validate_vpath(p))
            .ok_or_else(|| VaultError::Other("无效的虚拟路径".into()))?;

        // C5 修复：检查重名，避免静默覆盖
        if index.files.contains_key(&vpath) {
            return Err(VaultError::Other(format!("目标路径已存在: {}", vpath)));
        }

        // 2.3.0 修复：先查文件大小，超过内存上限直接拒绝，避免整文件读入导致 OOM
        let src_meta = fs::metadata(src_path)?;
        if src_meta.len() > MAX_INMEM_BUFFER as u64 {
            return Err(VaultError::Other(format!(
                "文件过大（{} 字节），超过单次导入上限 {} 字节",
                src_meta.len(), MAX_INMEM_BUFFER
            )));
        }
        let data = fs::read(src_path)?;
        let size = data.len() as u64;
        let name = src_path.file_name()
            .unwrap_or_default().to_string_lossy().to_string();

        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let encrypted = encrypt_gcm(enc_key, &data, vpath.as_bytes(), None)?;

        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(&encrypted)?;
        file.flush()?;
        file.sync_all()?;

        // 直接更新内存索引（与 IndexManager::add_file 相同语义），
        // 由调用方统一 save_index
        index.files.insert(
            vpath.clone(),
            FileMeta { name, size, offset, length: encrypted.len() as u64 },
        );
        if let Some(pos) = vpath.rfind('/') {
            if pos > 0 {
                index.folders.insert(vpath[..pos].to_string(), true);
            }
        }
        secure_wipe_vec(data);
        Ok(())
    }

    /// 2.4.1 重写（P0-2）：文件夹导入改为两阶段 ——
    /// 阶段 1 纯文件系统遍历收集 (源路径, 目标虚拟路径)；
    /// 阶段 2 用**单份内存索引**逐文件加密追加，最后一次性 save_index。
    /// 旧实现每导入一个文件都 load_index ×2 + save_index 全量重写一次，
    /// 1000 个文件 ≈ 2000 次解密加载 + 1000 次全量索引写 + 7000+ 次 fsync。
    pub fn import_folder(&mut self, src: &Path, base: &str) -> Result<(), VaultError> {
        let source_meta = fs::symlink_metadata(src)?;
        if source_meta.file_type().is_symlink() || !source_meta.is_dir() {
            return Err(VaultError::Other("导入源必须是非链接目录".into()));
        }
        let base_name = src.file_name()
            .unwrap_or_default().to_string_lossy().to_string();
        let base_clean = base.trim_end_matches('/');

        // 阶段 1：收集（无 self 借用，纯遍历）
        let mut collected: Vec<(PathBuf, String)> = Vec::new();
        let mut entries_seen = 0usize;
        Self::collect_import_files(
            src,
            &format!("{}/{}", base_clean, base_name),
            0,
            &mut entries_seen,
            &mut collected,
        )?;
        if collected.is_empty() {
            return Ok(());
        }

        // 阶段 2：单份索引逐文件导入，最后一次落盘
        let mut index = self.load_index()?;
        let mut ok = 0usize;
        let mut fail = 0usize;
        for (src_path, dest_vpath) in collected {
            match self.import_file_into_index(&mut index, &src_path, &dest_vpath) {
                Ok(()) => ok += 1,
                Err(e) => {
                    fail += 1;
                    log::warn!("导入 '{}' 失败: {}", src_path.display(), e);
                }
            }
        }
        self.log_event(&format!(
            "导入文件夹 '{}'：成功 {} 个文件，失败 {} 个",
            base_name, ok, fail
        ));
        if ok > 0 {
            self.save_index(&index)?;
        }
        Ok(())
    }

    /// 2.4.1 新增：递归收集待导入文件（原 walk_import 的遍历部分，去掉了 self 依赖）。
    fn collect_import_files(
        current: &Path,
        dest_root: &str,
        depth: usize,
        entries_seen: &mut usize,
        out: &mut Vec<(PathBuf, String)>,
    ) -> Result<(), VaultError> {
        if depth > MAX_IMPORT_DEPTH {
            return Err(VaultError::Other("导入目录层级超过安全上限".into()));
        }
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            *entries_seen += 1;
            if *entries_seen > MAX_IMPORT_ENTRIES {
                return Err(VaultError::Other("导入项目数量超过安全上限".into()));
            }
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.file_type().is_symlink() {
                log::warn!("跳过符号链接 '{}'", path.display());
                continue;
            }
            let name = path.file_name()
                .unwrap_or_default().to_string_lossy().to_string();
            let dest_path = format!("{}/{}", dest_root, name);
            if meta.is_dir() {
                Self::collect_import_files(&path, &dest_path, depth + 1, entries_seen, out)?;
            } else if meta.is_file() {
                out.push((path, dest_path));
            }
        }
        Ok(())
    }

    // ═══════════════ 文件提取 ═══════════════

    /// 2.4.1 新增（P1-12）：批量提取前的目标根目录准备（创建 + 规范化，只做一次）。
    /// 旧实现在 extract_file_inner 里对**每个文件**做 canonicalize，
    /// 批量提取 1000 个文件 = 2000 次冗余系统调用。
    fn prepare_dest_root(dest_folder: &Path) -> Result<PathBuf, VaultError> {
        fs::create_dir_all(dest_folder)?;
        fs::canonicalize(dest_folder)
            .map_err(|_| VaultError::Other("目标目录无法访问".into()))
    }

    /// 提取单个文件。2.4.1：`overwrite` 参数显式控制覆盖语义
    /// （true = 覆盖已存在文件；false = 拒绝并报错，与旧行为一致）。
    pub fn extract_file(
        &mut self,
        vpath: &str,
        dest_folder: &Path,
        overwrite: bool,
    ) -> Result<(), VaultError> {
        // 单次 load_index：获取文件名和密文位置
        let (rel_dir, file_name, offset, length) = {
            let index = self.load_index()?;
            let meta = index.files.get(vpath)
                .ok_or_else(|| VaultError::Other("文件不存在".into()))?;

            let vpath_trimmed = vpath.trim_matches('/');
            let rel_dir = match vpath_trimmed.rfind('/') {
                Some(pos) => &vpath_trimmed[..pos],
                None => "",
            };
            (rel_dir.to_string(), meta.name.clone(), meta.offset, meta.length)
        };
        let dest_abs = Self::prepare_dest_root(dest_folder)?;
        // 委托给内部实现（不重复 load_index / canonicalize）
        self.extract_file_inner(vpath, &rel_dir, &file_name, offset, length, &dest_abs, overwrite)?;
        // 2.4.1（P1-14）：审计移到调用方 —— 批量提取只记一条摘要
        self.log_event(&format!("提取文件 '{}'", vpath));
        Ok(())
    }

    /// 内部提取实现：已从索引中取出元数据，不再重复 load_index。
    /// 2.4.1 变更：
    /// - `dest_abs` 由调用方提前规范化和校验（P1-12），此处只对非空相对子目录
    ///   做符号链接防御；
    /// - `overwrite` 控制覆盖语义（P0-5）：旧实现固定 create_new 拒绝覆盖，
    ///   与前端「继续提取将覆盖同名文件」确认文案矛盾 —— 用户确认后反而大批失败；
    /// - 成功审计移至调用方（P1-14）。
    fn extract_file_inner(
        &mut self,
        vpath: &str,
        rel_dir: &str,
        file_name: &str,
        offset: u64,
        length: u64,
        dest_abs: &Path,
        overwrite: bool,
    ) -> Result<(), VaultError> {

        // 解密文件数据
        let data = {
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
            read_decrypt_file_data(file, enc_key, offset, length, vpath.as_bytes())?
        };

        let safe_name = sanitize_filename(&file_name);

        let rel_path: PathBuf = rel_dir
            .split('/')
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
            .map(sanitize_filename)
            .collect();

        let output_dir = if rel_path.components().count() > 0 {
            dest_abs.join(&rel_path)
        } else {
            dest_abs.to_path_buf()
        };
        fs::create_dir_all(&output_dir)?;
        // 仅当存在相对子目录时才需要 canonicalize 防符号链接逃逸；
        // 目标根目录已由 prepare_dest_root 规范化（P1-12）
        let output_dir_abs = if rel_path.components().count() > 0 {
            let abs = fs::canonicalize(&output_dir)
                .map_err(|_| VaultError::Other("输出目录无法访问".into()))?;
            if !abs.starts_with(dest_abs) {
                secure_wipe_vec(data);
                return Err(VaultError::Other("输出目录包含符号链接".into()));
            }
            abs
        } else {
            output_dir
        };

        let dest_path = output_dir_abs.join(&safe_name);

        // 路径遍历防护：验证最终路径在目标目录下
        if !dest_path.starts_with(dest_abs) {
            self.log_event(&format!("拦截路径遍历攻击: '{}'", vpath));
            secure_wipe_vec(data);
            return Err(VaultError::Other("路径遍历攻击已拦截".into()));
        }

        // C8 修复（强化）：使用 O_NOFOLLOW 打开目标文件，防止 TOCTOU 符号链接竞态。
        // 旧实现在 Windows 上仅检查-再-write，存在时间窗口。
        // 现在两端都使用 NO_FOLLOW 等价标志打开，并写入后验证仍是普通文件。
        // 2.4.1（P0-5）：overwrite=true 时用 create+truncate（仍带 NO_FOLLOW），
        // 让「提取全部」的覆盖确认框名副其实。
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = OpenOptions::new();
            opts.write(true).custom_flags(libc::O_NOFOLLOW);
            if overwrite {
                opts.create(true).truncate(true);
            } else {
                opts.create_new(true);
            }
            let mut f = opts
                .open(&dest_path)
                .map_err(|_| VaultError::Other("目标文件已存在或路径异常（符号链接？）".into()))?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            // FILE_FLAG_OPEN_REPARSE_POINT prevents following a final reparse point.
            use std::os::windows::fs::OpenOptionsExt;
            let mut opts = OpenOptions::new();
            opts.write(true).custom_flags(0x00200000 | 0x08000000);
            if overwrite {
                opts.create(true).truncate(true);
            } else {
                opts.create_new(true);
            }
            let mut f = opts
                .open(&dest_path)
                .map_err(|_| VaultError::Other("目标文件已存在或路径异常（重解析点？）".into()))?;
            f.write_all(&data)?;
            f.sync_all()?;
        }

        secure_wipe_vec(data);
        Ok(())
    }

    // ═══════════════ 文件删除 ═══════════════

    pub fn secure_delete_file(&mut self, vpath: &str) -> Result<(), VaultError> {
        // 2.3.0 顺序修正：先更新索引并 save_index（标记已删除），再覆写密文。
        // 旧实现先擦密文后存索引，中途崩溃会让索引仍指向已损坏的密文 → GCM 认证失败 → 永久损坏。
        // 与 secure_delete_files_batch 的「先存索引再擦密文」策略保持一致。
        let mut index = self.load_index()?;
        let meta = index.files.get(vpath)
            .ok_or_else(|| VaultError::Other("文件不存在".into()))?
            .clone();
        index.files.remove(vpath);
        self.log_event(&format!("安全删除文件 '{}'", vpath));
        self.save_index(&index)?;

        // 覆写密文（尽力而为：失败时密文残留无害，索引已不指向）
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = dod_overwrite_range(file, meta.offset, meta.length) {
                log::warn!("覆写密文失败（残留无害）: {}", e);
            }
            let _ = file.flush();
            let _ = file.sync_all();
        }
        Ok(())
    }

    pub fn delete_folder(&mut self, vpath: &str) -> Result<(), VaultError> {
        let prefix = format!("{}/", vpath);

        // 1. 一次性加载索引，收集所有需要移除的条目
        let mut index = self.load_index()?;

        let files_to_wipe: Vec<(String, u64, u64)> = index.files.iter()
            .filter(|(k, _)| k.starts_with(&prefix) || **k == vpath)
            .map(|(k, m)| (k.clone(), m.offset, m.length))
            .collect();

        // 2. 先从索引中批量移除（一次 save_index；与 secure_delete_files_batch 同策略）
        for (vpath_key, _, _) in &files_to_wipe {
            index.files.remove(vpath_key);
        }

        let dirs_to_delete: Vec<String> = index.folders.keys()
            .filter(|d| d.starts_with(&prefix))
            .cloned()
            .collect();
        for d in dirs_to_delete {
            index.folders.remove(&d);
        }
        if vpath != "/" {
            index.folders.remove(vpath);
        }

        self.log_event(&format!("删除文件夹 '{}'（含 {} 个文件）", vpath, files_to_wipe.len()));
        self.save_index(&index)?;

        // 3. 索引已安全落盘后再批量覆写密文（失败残留无害）
        for (_, offset, length) in &files_to_wipe {
            if let Some(file) = self.file.as_mut() {
                if let Err(e) = dod_overwrite_range(file, *offset, *length) {
                    log::warn!("覆写密文失败（残留无害）: {}", e);
                }
            }
        }
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
            let _ = file.sync_all();
        }
        Ok(())
    }

    /// 批量安全删除多个文件/文件夹（DoD 7-pass 覆写密文 + 索引移除）。
    ///
    /// 关键安全顺序：**先更新索引 + save_index（标记为已删除），再覆写密文**。
    /// 这样即使覆写过程中磁盘满/断电，索引已安全落盘：
    /// - 已被覆写的文件：索引已删除，不可达，碎片整理可清理
    /// - 未被覆写的文件：索引已删除，不可达，密文残留不影响功能
    /// 旧实现先覆写后 save_index，覆写中途失败会导致索引仍指向已损坏密文 → GCM 认证失败 → 永久损坏。
    ///
    /// 2.4.1 变更：
    /// - P1-11：旧实现对**每个**选中的文件夹都全表扫描一遍索引（选 m 个文件夹
    ///   = O(n×m)）；现在先分类一次（直接文件集合 + 文件夹前缀集合），再**单遍**
    ///   扫描索引判断归属，复杂度 O(n+m)。
    /// - P1-14：逐文件审计改为一条摘要审计（旧实现删 1000 个文件会追加 2000+ 条
    ///   审计，索引与 HMAC 链同步膨胀）。
    /// - 返回 (删除文件数, 删除文件夹数)，供 UI 精确反馈。
    pub fn secure_delete_files_batch(
        &mut self,
        vpaths: &[String],
    ) -> Result<(usize, usize), VaultError> {
        let mut index = self.load_index()?;

        // 1. 分类：直接文件 → 集合；文件夹 → 前缀（含自身匹配）
        let mut direct_files: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut folder_prefixes: Vec<String> = Vec::new();
        let mut folder_self: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for vp in vpaths {
            let vp_norm = vp.trim_end_matches('/');
            if vp_norm.is_empty() || vp_norm == "/" {
                continue;
            }
            if index.files.contains_key(vp_norm) {
                direct_files.insert(vp_norm);
            } else if index.folders.contains_key(vp_norm) {
                folder_prefixes.push(format!("{}/", vp_norm));
                folder_self.insert(vp_norm);
            }
            // 既不是文件也不是文件夹的 vpath 静默跳过（防御性）
        }
        if direct_files.is_empty() && folder_prefixes.is_empty() {
            return Ok((0, 0));
        }

        // 2. 单遍扫描索引：命中「直接文件」或「任一文件夹前缀」即收集
        //    R6：HashSet 去重，防嵌套选中（/a + /a/b）重复收集
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut to_wipe: Vec<(String, u64, u64)> = Vec::new();
        for (k, m) in &index.files {
            let hit = direct_files.contains(k.as_str())
                || folder_prefixes.iter().any(|p| k.starts_with(p.as_str()));
            if hit && seen.insert(k.clone()) {
                to_wipe.push((k.clone(), m.offset, m.length));
            }
        }
        let mut folders_to_delete: Vec<String> = Vec::new();
        for d in index.folders.keys() {
            let hit = folder_self.contains(d.as_str())
                || folder_prefixes.iter().any(|p| d.starts_with(p.as_str()));
            if hit && seen.insert(d.clone()) {
                folders_to_delete.push(d.clone());
            }
        }

        if to_wipe.is_empty() && folders_to_delete.is_empty() {
            return Ok((0, 0));
        }

        // 3. 先从索引移除所有文件和文件夹（一次 save_index）+ 摘要审计（P1-14）
        for (vp, _, _) in &to_wipe {
            index.files.remove(vp);
        }
        for d in &folders_to_delete {
            index.folders.remove(d);
        }
        self.log_event(&format!(
            "批量安全删除：{} 个文件，{} 个文件夹",
            to_wipe.len(),
            folders_to_delete.len()
        ));
        self.save_index(&index)?;

        // 4. 索引已安全落盘后再批量 DoD 7-pass 覆写密文
        //    此时即使覆写失败，索引已不指向这些 offset，不会导致数据损坏
        for (_, offset, length) in &to_wipe {
            if let Some(file) = self.file.as_mut() {
                // 单个覆写失败不影响整体，密文残留无害（索引已删除）
                if let Err(e) = dod_overwrite_range(file, *offset, *length) {
                    log::warn!("覆写密文失败（残留无害）: {}", e);
                }
            }
        }
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
            let _ = file.sync_all();
        }

        Ok((to_wipe.len(), folders_to_delete.len()))
    }

    // ═══════════════ 文件读取 ═══════════════

    pub fn load_file_data(&mut self, vpath: &str) -> Result<Vec<u8>, VaultError> {
        let (offset, length) = {
            let index = self.load_index()?;
            let meta = index.files.get(vpath)
                .ok_or_else(|| VaultError::Other("文件不存在".into()))?;
            (meta.offset, meta.length)
        };
        // M1 修复：超大文件拒绝全量加载（避免 OOM + Tauri IPC 膨胀）
        if length as usize > MAX_INMEM_BUFFER {
            return Err(VaultError::Other(format!(
                "文件过大（{} 字节），超过单次加载上限 {} 字节，请使用提取功能导出后查看",
                length, MAX_INMEM_BUFFER
            )));
        }
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        read_decrypt_file_data(file, enc_key, offset, length, vpath.as_bytes())
    }

    // ═══════════════ 碎片整理 ═══════════════

    pub fn defragment_vault<F: Fn(usize)>(&mut self, progress: Option<F>) -> Result<(), VaultError> {
        let active_enc_key = *self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let sign_key = *self.sign_key.as_ref().ok_or(VaultError::NotOpen)?;
        let vault_path = self.path.as_ref().ok_or(VaultError::NotOpen)?.clone();

        // 2.4.1（P0-3）：记录活跃分区旧布局（旧索引位置 + 全部旧文件数据位置），
        // 整理成功后对这些区域做 DoD 7-pass 擦除。
        // 旧实现把活跃分区数据复制到文件末尾后**不擦旧位置**，导致每整理一次
        // 文件反而膨胀一份活跃分区数据 —— 与「碎片整理释放空间」的语义完全相反。
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let old_part = self.partitions[active].clone();
        let (old_idx_off, old_idx_len) = (old_part.index_offset, old_part.index_length);
        let old_file_ranges: Vec<(u64, u64)> = {
            let index = self.load_index()?;
            index.files.values().map(|m| (m.offset, m.length)).collect()
        };
        // 整理前文件长度：新数据全部追加在 [orig_len, ...) —— 旧数据区与
        // 新数据区天然不相交（blob 均追加写入，互不重叠），擦除旧区不会伤及新数据
        let orig_len = std::fs::metadata(&vault_path)?.len();

        // 随机临时文件名，防止符号链接攻击
        let mut rand_suffix = [0u8; 16];
        OsRng.fill_bytes(&mut rand_suffix);
        let temp_name = format!("{}.tmp.{}", vault_path.display(), hex::encode(rand_suffix));
        let temp_path = PathBuf::from(&temp_name);
        let backup_name = format!("{}.bak.{}", vault_path.display(), hex::encode(rand_suffix));
        let backup_path = PathBuf::from(&backup_name);

        // C2 修复（关键）：旧实现只迁移活跃分区的文件和索引，
        // fs::rename 后其他分区的索引和文件密文全部丢失。
        // 新实现：遍历所有分区，将每个分区的索引（不解密，直接复制密文）
        // 迁移到临时文件，并更新对应分区的 offset/length。
        // 文件密文也整体复制（按活跃分区的索引定位）。
        // 由于其他分区无密码无法解密索引，我们只能整体复制 vault 文件中
        // 除头部外的所有数据，再重写活跃分区的索引使其紧凑。
        // 简化且正确的做法：复制整个原文件到临时文件，然后在临时文件上
        // 对活跃分区做碎片整理（重写文件数据 + 索引），其他分区数据原样保留。

        // Create unique backup and temporary files exclusively so pre-existing links cannot be followed.
        let mut backup_file = OpenOptions::new().write(true).create_new(true).open(&backup_path)?;
        let mut original = File::open(&vault_path)?;
        std::io::copy(&mut original, &mut backup_file)?;
        backup_file.sync_all()?;
        drop(backup_file);

        // 2.4.1：闭包返回整理后的最终索引（供成功分支刷新内存缓存）
        let result = (|| -> Result<Index, VaultError> {
            // 2.4.1（P0-3 增强）：单分区（绝大多数用户的常态）走「紧凑整理」——
            // 新临时文件只包含「头部 + 迁移数据 + 新索引」，旧数据区根本不会
            // 出现在新文件里，物理长度直接缩小，真正回收磁盘空间。
            // 多分区时维持旧行为：整体复制原文件（其他分区数据位置未知，不能丢弃），
            // 旧数据区在成功路径末尾统一 DoD 擦除。
            let single_partition = self.partitions.len() == 1;

            // 步骤 1：准备临时文件
            let mut tmp_file = {
                let mut tmp_file = OpenOptions::new()
                    .read(true).write(true).create_new(true)
                    .open(&temp_path)?;
                if !single_partition {
                    // 多分区：整体复制原文件，保留所有分区数据
                    let src_file = File::open(&vault_path)?;
                    std::io::copy(&mut &src_file, &mut tmp_file)?;
                    tmp_file.flush()?;
                    tmp_file.sync_all()?;
                } else {
                    // 单分区：头部占位（步骤 6 重写为最终内容）
                    tmp_file.write_all(&[0u8; HEADER_SIZE])?;
                    tmp_file.flush()?;
                    tmp_file.sync_all()?;
                }
                tmp_file
            };

            // 步骤 2：加载活跃分区索引（直接从原文件读取，原文件此刻未被修改）
            let mut index = {
                let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
                let active = self.active_partition.ok_or(VaultError::NotOpen)?;
                let p = &self.partitions[active];
                load_index_from_file(file, &active_enc_key, p.index_offset, p.index_length)?
            };

            // 步骤 3：迁移活跃分区的文件数据（紧凑排列，流式拷贝防 OOM）
            let files_snapshot: Vec<(String, u64, u64)> = index.files.iter()
                .map(|(k, m)| (k.clone(), m.offset, m.length))
                .collect();
            let total = files_snapshot.len();

            // 迁移源一律是原文件（读取与写入分离到两个句柄，
            // 避免单文件自拷贝在区间重叠时的数据破坏风险）
            let mut src_file = File::open(&vault_path)?;
            let mut write_cursor = if single_partition {
                HEADER_SIZE as u64
            } else {
                tmp_file.seek(SeekFrom::End(0))?
            };
            for (i, (vpath, old_off, old_len)) in files_snapshot.iter().enumerate() {
                copy_between(&mut src_file, &mut tmp_file, *old_off, write_cursor, *old_len)?;
                index.files.get_mut(vpath)
                    .ok_or_else(|| VaultError::Other("defragment: 文件不在索引中".to_string()))?
                    .offset = write_cursor;
                write_cursor += *old_len;
                if let Some(ref cb) = progress {
                    cb((i + 1) * 50 / total.max(1));
                }
            }
            drop(src_file);

            // 步骤 4：写入活跃分区的新索引
            let mut idx_for_write = index.clone();
            if let Some(ref audit) = self.audit {
                idx_for_write.audit = audit.to_vec();
            }
            let idx_json = serde_json::to_vec(&idx_for_write)?;
            let enc_idx = encrypt_gcm(&active_enc_key, &idx_json, b"index", None)?;
            tmp_file.seek(SeekFrom::Start(write_cursor))?;
            tmp_file.write_all(&enc_idx)?;
            tmp_file.flush()?;
            tmp_file.sync_all()?;

            let new_idx_offset = write_cursor;
            let new_idx_length = enc_idx.len() as u64;

            // 步骤 5：空间回收说明
            // - 单分区：临时文件从未写入旧数据（见步骤 1/3），文件本身就是紧凑
            //   布局，无需截断，物理空间已直接回收；
            // - 多分区：不截断文件（其他分区数据位于原文件中部，无密码无法定位
            //   其边界，截断会永久破坏它们）。空间回收靠成功路径末尾对活跃分区
            //   旧数据区/旧索引的 DoD 7-pass 擦除（P0-3）—— 逻辑空间被释放，
            //   物理文件长度保持不变（见 README「已知限制」）。

            let active = self.active_partition.ok_or(VaultError::NotOpen)?;
            self.partitions[active].index_offset = new_idx_offset;
            self.partitions[active].index_length = new_idx_length;

            // 步骤 6：写入头部（含所有分区的新偏移）
            let lock_state = &self.lock_state;
            let salt = &self.salt;
            let partitions = &self.partitions;
            write_header_to_file(&mut tmp_file, lock_state, salt, partitions, &sign_key)?;
            tmp_file.flush()?;
            tmp_file.sync_all()?;
            drop(tmp_file);

            // 步骤 7：原子替换
            fs::rename(&temp_path, &vault_path)?;
            sync_parent_dir(&vault_path);

            // 2.3.0 修复：备份是保险柜的完整副本，直接删除会在磁盘上留下抗取证死角。
            // 先 DoD 7-pass 擦除再删除；失败仅记日志（备份残留不影响主文件正确性）。
            if let Err(e) = dod_erase(&backup_path, None) {
                log::warn!("擦除碎片整理备份失败（请手动删除 {}）: {}", backup_path.display(), e);
            }
            secure_wipe_vec(idx_json);
            Ok(idx_for_write)
        })();

        match result {
            Ok(final_index) => {
                let file = OpenOptions::new().read(true).write(true).open(&vault_path)?;
                self.file = Some(file);
                // P0-3：擦除活跃分区旧数据区与旧索引（逻辑空间回收）。
                // 仅多分区路径需要：新文件是原文件的完整副本，旧区仍在新文件内。
                // 单分区紧凑整理的新文件从未包含旧数据区，此处擦除反而会毁掉
                // 迁移后的新数据 —— 必须跳过。
                let single_partition = self.partitions.len() == 1;
                // 新数据全部位于 [orig_len, ...)，与旧区不相交；此步失败仅意味着
                // 残留垃圾数据（无害），不影响正确性。
                // 防御性校验：若不变量被破坏（旧区越界进入新区），跳过擦除只留垃圾。
                let wipe_safe = !single_partition
                    && old_idx_off.saturating_add(old_idx_len) <= orig_len
                    && old_file_ranges.iter().all(|&(o, l)| o.saturating_add(l) <= orig_len);
                if single_partition {
                    log::debug!("单分区紧凑整理：旧数据区未进入新文件，无需擦除");
                } else if !wipe_safe {
                    log::warn!("碎片整理布局校验未通过，跳过旧数据擦除（残留垃圾，无害）");
                }
                if wipe_safe {
                    let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
                    let mut wiped = true;
                    if old_idx_len > 0 {
                        if let Err(e) = dod_overwrite_range(file, old_idx_off, old_idx_len) {
                            wiped = false;
                            log::warn!("整理后擦除旧索引失败（残留垃圾，无害）: {}", e);
                        }
                    }
                    for (off, len) in &old_file_ranges {
                        if *len == 0 { continue; }
                        if let Err(e) = dod_overwrite_range(file, *off, *len) {
                            wiped = false;
                            log::warn!("整理后擦除旧数据失败（残留垃圾，无害）: {}", e);
                        }
                    }
                    if wiped {
                        let _ = file.flush();
                        let _ = file.sync_all();
                    }
                }
                // 2.4.1：刷新索引缓存到整理后的布局（偏移已全部更新）
                self.cached_index = Some(final_index);
                self.log_event("执行保险柜碎片整理");
                if let Some(ref cb) = progress {
                    cb(100);
                }
                Ok(())
            }
            Err(e) => {
                let _ = fs::remove_file(&temp_path);
                if backup_path.exists() {
                    let _ = fs::rename(&backup_path, &vault_path);
                    // 2.4.1 修复：闭包内可能已把 self.partitions[active] 指向**新**偏移，
                    // 而恢复回来的原文件仍是旧布局 —— 不回滚会导致后续读写错位。
                    // （旧实现在此存在状态不一致缺陷）
                    if let Some(active) = self.active_partition {
                        self.partitions[active] = old_part;
                    }
                    let file = OpenOptions::new().read(true).write(true).open(&vault_path).ok();
                    self.file = file;
                }
                Err(e)
            }
        }
    }

    // ═══════════════ 查询 ═══════════════

    pub fn get_audit_entries(&self) -> Vec<crate::audit::AuditEntry> {
        self.audit.as_ref().map(|a| a.to_vec()).unwrap_or_default()
    }

    /// 提取保险柜内所有文件到指定目录，保留 vpath 目录结构。
    /// R3 修复：真正单次 load_index，循环调用 extract_file_inner（不再重复 load）。
    /// 2.4.1 变更：目标目录只校验/规范化一次（P1-12）；新增 overwrite 参数（P0-5，
    /// 由前端确认框传入 —— 旧实现确认「覆盖」后实际用 create_new 拒绝覆盖，大批失败）。
    /// 返回 (成功数, 失败数)。
    pub fn extract_all_files(
        &mut self,
        dest_folder: &Path,
        overwrite: bool,
    ) -> Result<(usize, usize), VaultError> {
        let dest_abs = Self::prepare_dest_root(dest_folder)?;
        // 单次 load_index，收集所有文件的元数据
        let file_infos: Vec<(String, String, String, u64, u64)> = {
            let index = self.load_index()?;
            index.files.iter().map(|(vpath, meta)| {
                let vpath_trimmed = vpath.trim_matches('/');
                let rel_dir = match vpath_trimmed.rfind('/') {
                    Some(pos) => vpath_trimmed[..pos].to_string(),
                    None => "".to_string(),
                };
                (vpath.clone(), rel_dir, meta.name.clone(), meta.offset, meta.length)
            }).collect()
        };
        let mut ok = 0usize;
        let mut fail = 0usize;
        for (vpath, rel_dir, file_name, offset, length) in &file_infos {
            match self.extract_file_inner(vpath, rel_dir, file_name, *offset, *length, &dest_abs, overwrite) {
                Ok(_) => ok += 1,
                Err(e) => {
                    fail += 1;
                    log::warn!("提取全部：'{}' 失败: {}", vpath, e);
                }
            }
        }
        self.log_event(&format!(
            "提取全部文件到 '{}'（成功 {}，失败 {}）",
            dest_folder.display(), ok, fail
        ));
        Ok((ok, fail))
    }

    /// 批量提取指定文件/文件夹到目标目录（单次 load_index，避免 O(n²) 重复加载）。
    /// 文件夹自动展开为其下所有文件；返回 (成功数, 失败数)。
    /// 2.3.0 修复：`extract_files` 命令原先对每个文件重复 load_index，大数据量下退化 O(n²)。
    /// 2.4.1：目标目录只校验一次（P1-12）+ 摘要审计（P1-14）。
    pub fn extract_files_batch(&mut self, vpaths: &[String], dest_folder: &Path) -> Result<(usize, usize), VaultError> {
        let dest_abs = Self::prepare_dest_root(dest_folder)?;
        let index = self.load_index()?;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut targets: Vec<(String, String, String, u64, u64)> = Vec::new();
        for vp in vpaths {
            let vp_norm = vp.trim_end_matches('/');
            if vp_norm.is_empty() || vp_norm == "/" {
                continue;
            }
            if index.files.contains_key(vp_norm) {
                if seen.insert(vp_norm.to_string()) {
                    let m = index.files.get(vp_norm).unwrap();
                    let vpath_trimmed = vp_norm.trim_matches('/');
                    let rel_dir = match vpath_trimmed.rfind('/') {
                        Some(pos) => vpath_trimmed[..pos].to_string(),
                        None => String::new(),
                    };
                    targets.push((vp_norm.to_string(), rel_dir, m.name.clone(), m.offset, m.length));
                }
            } else if index.folders.contains_key(vp_norm) {
                let prefix = format!("{}/", vp_norm);
                for (fv, m) in &index.files {
                    if (fv.starts_with(&prefix) || fv == vp_norm) && seen.insert(fv.clone()) {
                        let vpath_trimmed = fv.trim_matches('/');
                        let rel_dir = match vpath_trimmed.rfind('/') {
                            Some(pos) => vpath_trimmed[..pos].to_string(),
                            None => String::new(),
                        };
                        targets.push((fv.clone(), rel_dir, m.name.clone(), m.offset, m.length));
                    }
                }
            }
        }

        let mut ok = 0usize;
        let mut fail = 0usize;
        for (vpath, rel_dir, file_name, offset, length) in &targets {
            // 批量提取保持「拒绝覆盖」的安全默认；需要覆盖语义时走提取全部（P0-5）
            match self.extract_file_inner(vpath, rel_dir, file_name, *offset, *length, &dest_abs, false) {
                Ok(_) => ok += 1,
                Err(e) => {
                    fail += 1;
                    log::warn!("批量提取：'{}' 失败: {}", vpath, e);
                }
            }
        }
        self.log_event(&format!("批量提取：成功 {} 个文件，失败 {} 个", ok, fail));
        Ok((ok, fail))
    }

    /// 追加一条审计日志。如果审计日志未初始化则什么都不做。
    pub fn add_audit_entry(&mut self, msg: &str) {
        self.log_event(msg);
    }

    pub fn get_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn get_active_partition(&self) -> Option<&PartitionInfo> {
        self.active_partition.and_then(|i| self.partitions.get(i))
    }

    pub fn get_partitions(&self) -> &[PartitionInfo] {
        &self.partitions
    }

    pub fn is_open(&self) -> bool {
        self.enc_key.is_some() && self.file.is_some()
    }

    // ═══════════════ 关闭 ═══════════════

    /// 2.4.1 变更（P1-15）：只在审计有未落盘变更时才补一次 save_index。
    /// 旧实现 close() 无条件 load+save（全量索引重写 + 7-pass 擦旧索引，
    /// 10 次 fsync）—— 而大多数时候索引内容早已随上一次操作落盘，
    /// 这次写入的唯一目的是把「保险柜已关闭」审计条目刷进索引。
    pub fn close(&mut self) {
        if self.audit.is_some() {
            if let Some(ref mut audit) = self.audit {
                audit.add("保险柜已关闭");
            }
            self.audit_dirty = true;
        }
        // M8 修复：close 失败不应掩盖原错误，但 Drop 中无法返回错误，
        // 失败时只记日志
        if self.enc_key.is_some() && self.file.is_some() && self.audit_dirty {
            if let Err(e) = self.load_index().and_then(|idx| self.save_index(&idx)) {
                log::error!("关闭保险柜时保存索引失败: {}", e);
            }
        }
        self.file = None;
        self.path = None;
        // 2.4.1：清理索引缓存（含明文审计字符串），避免敏感数据残留在堆上
        if let Some(mut idx) = self.cached_index.take() {
            idx.files.clear();
            idx.folders.clear();
            idx.audit.clear();
        }
        if let Some(mut key) = self.enc_key.take() { key.zeroize(); }
        if let Some(mut key) = self.auth_key.take() { key.zeroize(); }
        if let Some(mut key) = self.sign_key.take() { key.zeroize(); }
        self.active_partition = None;
        self.audit = None;
        self.audit_dirty = false;
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        // M8 修复：避免在 Drop 中做可能 panic 的 I/O；close 已做错误处理
        // 仅清理密钥，不强制 save_index（防止 Drop 中二次失败）
        self.file = None;
        self.path = None;
        // 2.4.1：同样清理索引缓存中的明文内容（含审计条目）
        if let Some(mut idx) = self.cached_index.take() {
            idx.files.clear();
            idx.folders.clear();
            idx.audit.clear();
        }
        if let Some(mut key) = self.enc_key.take() { key.zeroize(); }
        if let Some(mut key) = self.auth_key.take() { key.zeroize(); }
        if let Some(mut key) = self.sign_key.take() { key.zeroize(); }
    }
}
