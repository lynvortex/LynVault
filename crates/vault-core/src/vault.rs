use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use serde_json;
use zeroize::Zeroize;

use crate::audit::AuditLog;
use crate::crypto::*;
use crate::error::VaultError;
use crate::index::{Index, IndexManager};
use crate::lock::LockState;
use crate::wipe::secure_wipe_vec;

// --- 常量 ---
const MAGIC: &[u8; 8] = b"PYVAULT4";
const VERSION: u8 = 4;
const HEADER_SIZE: usize = 1024;
const MAX_PARTITIONS: usize = 8;
const PARTITION_ENTRY_SIZE: usize = 96;

const LOCK_OFFSET: usize = 887;
const SIGNED_LENGTH: usize = 968;
const SIGNATURE_OFFSET: usize = 960;
const SIGNATURE_SIZE: usize = 64;

const PBKDF2_ITERATIONS: u32 = 1_000_000;
const DEFAULT_PARTITION: &str = "Main";

// ─────────── 自由函数：避免 &mut self 借用冲突 ───────────

/// 从文件读取并解密索引
fn load_index_from_file(
    file: &mut File,
    enc_key: &[u8; 32],
    offset: u64,
    length: u64,
) -> Result<Index, VaultError> {
    file.seek(SeekFrom::Start(offset))?;
    let mut enc = vec![0u8; length as usize];
    file.read_exact(&mut enc)?;
    let plain = decrypt_gcm(enc_key, &enc).ok_or(VaultError::DecryptFailed)?;
    let index: Index = serde_json::from_slice(&plain)?;
    secure_wipe_vec(plain);
    Ok(index)
}

/// 加密索引并追加写入，返回 (new_offset, new_length)
fn save_index_to_file(
    file: &mut File,
    enc_key: &[u8; 32],
    index: &Index,
    old_offset: u64,
    old_length: u64,
) -> Result<(u64, u64), VaultError> {
    let plain = serde_json::to_vec(index)?;
    let encrypted = encrypt_gcm(enc_key, &plain, None);

    // 覆写旧索引区段为随机数据
    let mut rand_data = vec![0u8; old_length as usize];
    OsRng.fill_bytes(&mut rand_data);
    file.seek(SeekFrom::Start(old_offset))?;
    file.write_all(&rand_data)?;

    let new_offset = file.seek(SeekFrom::End(0))?;
    file.write_all(&encrypted)?;
    file.flush()?;

    secure_wipe_vec(plain);
    Ok((new_offset, encrypted.len() as u64))
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
    // bytes 9..17 reserved (nonce_counter removed, always zero)
    header[41..73].copy_from_slice(&lock_state.lock_key);
    header[73..105].copy_from_slice(salt);

    header[105] = partitions.len() as u8;
    let mut off = 106;
    for p in partitions {
        let alias_bytes = p.alias.as_bytes();
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
    }

    header[LOCK_OFFSET] = lock_state.lock_count;
    header[LOCK_OFFSET + 1..LOCK_OFFSET + 9]
        .copy_from_slice(&lock_state.lock_until.to_le_bytes());
    let hmac = lock_state.compute_hmac();
    header[LOCK_OFFSET + 9..LOCK_OFFSET + 9 + 32].copy_from_slice(&hmac);

    let sig = compute_header_signature(&header[..SIGNED_LENGTH], sign_key);
    header[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE].copy_from_slice(&sig);

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header)?;
    file.flush()?;
    Ok(())
}

/// 从保险柜文件读取并解密原始数据
fn read_decrypt_file_data(
    file: &mut File,
    enc_key: &[u8; 32],
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, VaultError> {
    file.seek(SeekFrom::Start(offset))?;
    let mut enc_data = vec![0u8; length as usize];
    file.read_exact(&mut enc_data)?;
    decrypt_gcm(enc_key, &enc_data).ok_or(VaultError::DecryptFailed)
}

/// 安全文件名清理
fn sanitize_filename(name: &str) -> String {
    let safe: String = name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>();
    if safe.is_empty() { "extracted_file".to_string() } else { safe }
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
    pub(crate) last_attempt: Option<Instant>,
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
            lock_state: LockState::new([0u8; 32]),
            partitions: Vec::new(),
            active_partition: None,
            audit: None,
            last_attempt: None,
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
    // ═══════════════ 创建 ═══════════════

    pub fn create(
        path: &Path,
        password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<(), VaultError> {
        if password.len() < 12 {
            return Err(VaultError::Other("密码长度至少 12 位".into()));
        }

        let mut file = OpenOptions::new()
            .read(true).write(true).create(true).truncate(true).open(path)?;
        file.write_all(&[0u8; HEADER_SIZE])?;
        file.flush()?;

        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let mut lock_key = [0u8; 32];
        OsRng.fill_bytes(&mut lock_key);

        let mut keys = derive_keys(password, key_file_data, &salt)?;
        let auth_tag = create_auth_tag(&keys.auth_key);

        let empty_index = Index::new();
        let index_json = serde_json::to_vec(&empty_index)?;
        let enc_index = encrypt_gcm(&keys.enc_key, &index_json, None);

        let index_offset = file.seek(SeekFrom::End(0))?;
        let index_length = enc_index.len() as u64;
        file.write_all(&enc_index)?;
        file.flush()?;

        let partition = PartitionInfo {
            alias: DEFAULT_PARTITION.into(),
            salt,
            auth_tag,
            index_offset,
            index_length,
        };

        let lock_state = LockState::new(lock_key);
        write_header_to_file(&mut file, &lock_state, &salt, &[partition], &keys.sign_key)?;

        keys.zeroize();
        Ok(())
    }

    // ═══════════════ 打开认证 ═══════════════

    pub fn open_and_authenticate(
        &mut self,
        path: &Path,
        password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<usize, VaultError> {
        if let Some(last) = self.last_attempt {
            if last.elapsed() < Duration::from_secs(3) {
                return Err(VaultError::Other("请稍后再试（冷却中）".into()));
            }
        }
        self.last_attempt = Some(Instant::now());

        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header)?;

        let (magic, version, lock_key, salt) = Self::parse_header(&header)?;
        if &magic != MAGIC || version != VERSION {
            return Err(VaultError::BadMagic);
        }

        let lock_count = header[LOCK_OFFSET];
        let lock_until = f64::from_le_bytes(header[LOCK_OFFSET+1..LOCK_OFFSET+9].try_into().unwrap());
        let mut lock_state = LockState { lock_count, lock_until, lock_key };

        let stored_hmac: [u8; 32] = header[LOCK_OFFSET+9..LOCK_OFFSET+9+32].try_into().unwrap();
        if !lock_state.verify_hmac(&stored_hmac) {
            return Err(VaultError::Other("头部锁定区被篡改".into()));
        }
        if lock_state.is_locked() {
            return Err(VaultError::Locked);
        }

        // 解析分区表
        let num_partitions = header[105] as usize;
        let mut partitions = Vec::new();
        let mut off = 106;
        for _ in 0..num_partitions.min(MAX_PARTITIONS) {
            if off + PARTITION_ENTRY_SIZE > HEADER_SIZE { break; }
            let alias_len = header[off..off+16].iter().position(|&b| b == 0).unwrap_or(16);
            let alias = String::from_utf8_lossy(&header[off..off+alias_len]).to_string();
            let mut p_salt = [0u8; 32];
            p_salt.copy_from_slice(&header[off+16..off+48]);
            let mut auth_tag = [0u8; 32];
            auth_tag.copy_from_slice(&header[off+48..off+80]);
            let index_offset = u64::from_le_bytes(header[off+80..off+88].try_into().unwrap());
            let index_length = u64::from_le_bytes(header[off+88..off+96].try_into().unwrap());
            partitions.push(PartitionInfo { alias, salt: p_salt, auth_tag, index_offset, index_length });
            off += PARTITION_ENTRY_SIZE;
        }

        // 尝试每个分区
        for (idx, p) in partitions.iter().enumerate() {
            let mut keys = derive_keys(password, key_file_data, &p.salt)?;
            if verify_auth_tag(&keys.auth_key, &p.auth_tag) {
                let enc_index = {
                    file.seek(SeekFrom::Start(p.index_offset))?;
                    let mut buf = vec![0u8; p.index_length as usize];
                    file.read_exact(&mut buf)?;
                    buf
                };
                let index_json = decrypt_gcm(&keys.enc_key, &enc_index)
                    .ok_or(VaultError::DecryptFailed)?;
                let index: Index = serde_json::from_slice(&index_json)?;

                lock_state.reset();
                self.lock_state = lock_state;
                self.salt = salt;
                self.partitions = partitions;
                self.active_partition = Some(idx);

                self.enc_key = Some(keys.enc_key);
                self.auth_key = Some(keys.auth_key);
                self.sign_key = Some(keys.sign_key);

                let mut audit = AuditLog::from_entries(index.audit.clone(), keys.auth_key);
                audit.add("保险柜已解锁");
                self.audit = Some(audit);

                self.file = Some(file);
                self.path = Some(path.to_path_buf());

                self.update_header()?;

                keys.zeroize();
                secure_wipe_vec(index_json);
                secure_wipe_vec(enc_index);
                return Ok(idx);
            }
            keys.zeroize();
        }

        // 全部失败
        lock_state.record_failure();
        let mut lock_buf = [0u8; 41];
        lock_buf[0] = lock_state.lock_count;
        lock_buf[1..9].copy_from_slice(&lock_state.lock_until.to_le_bytes());
        let hmac = lock_state.compute_hmac();
        lock_buf[9..41].copy_from_slice(&hmac);
        file.seek(SeekFrom::Start(LOCK_OFFSET as u64))?;
        file.write_all(&lock_buf)?;
        file.flush()?;

        Err(VaultError::AuthFailed)
    }

    // ═══════════════ 索引操作 ═══════════════

    pub fn get_index_manager(&mut self) -> Result<IndexManager<'_>, VaultError> {
        if self.enc_key.is_none() || self.file.is_none() {
            return Err(VaultError::NotOpen);
        }
        Ok(IndexManager::new(self))
    }

    pub fn load_index(&mut self) -> Result<Index, VaultError> {
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let (offset, length) = {
            let p = &self.partitions[active];
            (p.index_offset, p.index_length)
        };
        let file = self.file.as_mut().unwrap();
        let enc_key = self.enc_key.as_ref().unwrap();
        load_index_from_file(file, enc_key, offset, length)
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

        let file = self.file.as_mut().unwrap();
        let enc_key = self.enc_key.as_ref().unwrap();
        let (new_off, new_len) = save_index_to_file(file, enc_key, &idx, old_off, old_len)?;

        self.partitions[active].index_offset = new_off;
        self.partitions[active].index_length = new_len;
        self.update_header()?;
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
        -> Result<([u8; 8], u8, [u8; 32], [u8; 32]), VaultError>
    {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&header[..8]);
        let version = header[8];
        // bytes 9..17 reserved (was nonce_counter)
        let mut lock_key = [0u8; 32];
        lock_key.copy_from_slice(&header[41..73]);
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&header[73..105]);
        Ok((magic, version, lock_key, salt))
    }

    // ═══════════════ 分区管理 ═══════════════

    pub fn add_partition(&mut self, alias: &str, fake_password: &str, key_file_data: Option<&[u8]>) -> Result<(), VaultError> {
        if self.file.is_none() { return Err(VaultError::NotOpen); }
        if self.partitions.len() >= MAX_PARTITIONS { return Err(VaultError::TooManyPartitions); }

        let mut part_salt = [0u8; 32];
        OsRng.fill_bytes(&mut part_salt);
        let mut keys = derive_keys(fake_password, key_file_data, &part_salt)?;
        let auth_tag = create_auth_tag(&keys.auth_key);

        let empty_index = Index::new();
        let plain = serde_json::to_vec(&empty_index)?;
        let enc = encrypt_gcm(&keys.enc_key, &plain, None);

        let file = self.file.as_mut().unwrap();
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(&enc)?;
        file.flush()?;

        self.partitions.push(PartitionInfo {
            alias: alias.into(),
            salt: part_salt,
            auth_tag,
            index_offset: offset,
            index_length: enc.len() as u64,
        });

        if let Some(ref mut audit) = self.audit {
            audit.add(&format!("添加伪装分区 '{}'", alias));
        }
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

        let p = &self.partitions[pos];
        let mut rand_data = vec![0u8; p.index_length as usize];
        OsRng.fill_bytes(&mut rand_data);
        let file = self.file.as_mut().unwrap();
        file.seek(SeekFrom::Start(p.index_offset))?;
        file.write_all(&rand_data)?;
        file.flush()?;

        self.partitions.remove(pos);
        if let Some(ref mut audit) = self.audit {
            audit.add(&format!("删除分区 '{}'", alias));
        }
        self.update_header()?;
        Ok(())
    }

    // ═══════════════ 文件导入 ═══════════════

    pub fn import_file(&mut self, src_path: &Path, vpath: &str) -> Result<(), VaultError> {
        if !Index::validate_vpath(vpath) {
            return Err(VaultError::Other("无效的虚拟路径".into()));
        }
        let data = fs::read(src_path)?;
        let size = data.len() as u64;
        let name = src_path.file_name()
            .unwrap_or_default().to_string_lossy().to_string();

        let enc_key = self.enc_key.as_ref().unwrap();
        let encrypted = encrypt_gcm(enc_key, &data, None);

        let file = self.file.as_mut().unwrap();
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(&encrypted)?;
        file.flush()?;

        let mut im = IndexManager::new(self);
        im.add_file(vpath, &name, size, offset, encrypted.len() as u64)?;
        secure_wipe_vec(data);
        Ok(())
    }

    pub fn import_folder(&mut self, src: &Path, base: &str) -> Result<(), VaultError> {
        let base_name = src.file_name()
            .unwrap_or_default().to_string_lossy().to_string();
        let base_clean = base.trim_end_matches('/');
        self.walk_import(src, &format!("{}/{}", base_clean, base_name))
    }

    fn walk_import(&mut self, current: &Path, dest_root: &str) -> Result<(), VaultError> {
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let name = path.file_name()
                .unwrap_or_default().to_string_lossy().to_string();
            let dest_path = format!("{}/{}", dest_root, name);
            if path.is_dir() {
                self.walk_import(&path, &dest_path)?;
            } else {
                self.import_file(&path, &dest_path)?;
            }
        }
        Ok(())
    }

    // ═══════════════ 文件提取 ═══════════════

    pub fn extract_file(&mut self, vpath: &str, dest_folder: &Path) -> Result<(), VaultError> {
        // 先获取文件元数据
        let file_name = {
            let index = self.load_index()?;
            let meta = index.files.get(vpath)
                .ok_or(VaultError::Other("文件不存在".into()))?;
            meta.name.clone()
        };

        // 读取并解密
        let data = {
            let index = self.load_index()?;
            let meta = index.files.get(vpath).unwrap();
            let file = self.file.as_mut().unwrap();
            let enc_key = self.enc_key.as_ref().unwrap();
            read_decrypt_file_data(file, enc_key, meta.offset, meta.length)?
        };

        let safe_name = sanitize_filename(&file_name);
        let dest_path = dest_folder.join(&safe_name);

        // 路径遍历检查：先 canonicalize 目标目录，再检查最终路径
        let dest_abs = fs::canonicalize(dest_folder)
            .map_err(|_| VaultError::Other("目标目录不存在".into()))?;
        // 统一用 '/' 比较，消除平台差异
        let dest_str = dest_abs.to_string_lossy().replace('\\', "/");
        let final_str = dest_path.to_string_lossy().replace('\\', "/");
        if !final_str.starts_with(&dest_str) {
            if let Some(ref mut audit) = self.audit {
                audit.add(&format!("拦截路径遍历攻击: '{}'", file_name));
            }
            secure_wipe_vec(data);
            return Err(VaultError::Other("路径遍历攻击已拦截".into()));
        }

        fs::create_dir_all(dest_folder)?;
        fs::write(&dest_path, &data)?;

        if let Some(ref mut audit) = self.audit {
            audit.add(&format!("提取文件 '{}'", vpath));
        }
        secure_wipe_vec(data);
        Ok(())
    }

    // ═══════════════ 文件删除 ═══════════════

    pub fn secure_delete_file(&mut self, vpath: &str) -> Result<(), VaultError> {
        let meta = {
            let index = self.load_index()?;
            index.files.get(vpath)
                .ok_or(VaultError::Other("文件不存在".into()))?
                .clone()
        };

        // 用随机数据覆写
        let mut rand_data = vec![0u8; meta.length as usize];
        OsRng.fill_bytes(&mut rand_data);
        let file = self.file.as_mut().unwrap();
        file.seek(SeekFrom::Start(meta.offset))?;
        file.write_all(&rand_data)?;
        file.flush()?;

        let mut index = self.load_index()?;
        index.files.remove(vpath);
        if let Some(ref mut audit) = self.audit {
            audit.add(&format!("安全删除文件 '{}'", vpath));
        }
        self.save_index(&index)?;
        Ok(())
    }

    pub fn delete_folder(&mut self, vpath: &str) -> Result<(), VaultError> {
        let files_to_delete: Vec<String> = {
            let index = self.load_index()?;
            let prefix = format!("{}/", vpath);
            index.files.keys()
                .filter(|f| f.starts_with(&prefix) || *f == vpath)
                .cloned()
                .collect()
        };

        for f in &files_to_delete {
            self.secure_delete_file(f)?;
        }

        let prefix = format!("{}/", vpath);
        let mut index = self.load_index()?;
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
        if let Some(ref mut audit) = self.audit {
            audit.add(&format!("删除文件夹 '{}'", vpath));
        }
        self.save_index(&index)?;
        Ok(())
    }

    // ═══════════════ 文件读取 ═══════════════

    pub fn load_file_data(&mut self, vpath: &str) -> Result<Vec<u8>, VaultError> {
        let (offset, length) = {
            let index = self.load_index()?;
            let meta = index.files.get(vpath)
                .ok_or(VaultError::Other("文件不存在".into()))?;
            (meta.offset, meta.length)
        };
        let file = self.file.as_mut().unwrap();
        let enc_key = self.enc_key.as_ref().unwrap();
        read_decrypt_file_data(file, enc_key, offset, length)
    }

    // ═══════════════ 碎片整理 ═══════════════

    pub fn defragment_vault<F: Fn(usize)>(&mut self, progress: Option<F>) -> Result<(), VaultError> {
        let enc_key = *self.enc_key.as_ref().unwrap();
        let sign_key = *self.sign_key.as_ref().unwrap();
        let vault_path = self.path.as_ref().ok_or(VaultError::NotOpen)?.clone();

        // 随机临时文件名，防止符号链接攻击
        let mut rand_suffix = [0u8; 16];
        OsRng.fill_bytes(&mut rand_suffix);
        let temp_name = format!("{}.tmp.{}", vault_path.display(), hex::encode(rand_suffix));
        let temp_path = PathBuf::from(&temp_name);
        let backup_path = vault_path.with_extension("vault.bak");

        let mut index = self.load_index()?;

        // 备份原文件
        fs::copy(&vault_path, &backup_path)?;

        let result = (|| -> Result<(), VaultError> {
            let mut tmp_file = OpenOptions::new()
                .read(true).write(true).create(true).truncate(true)
                .open(&temp_path)?;
            tmp_file.write_all(&[0u8; HEADER_SIZE])?;

            // 迁移所有文件数据
            let files_snapshot: Vec<(String, u64, u64)> = index.files.iter()
                .map(|(k, m)| (k.clone(), m.offset, m.length))
                .collect();
            let total = files_snapshot.len();

            for (i, (vpath, old_off, old_len)) in files_snapshot.iter().enumerate() {
                let enc_data = {
                    let file = self.file.as_mut().unwrap();
                    file.seek(SeekFrom::Start(*old_off))?;
                    let mut buf = vec![0u8; *old_len as usize];
                    file.read_exact(&mut buf)?;
                    buf
                };

                let new_offset = tmp_file.seek(SeekFrom::End(0))?;
                tmp_file.write_all(&enc_data)?;
                index.files.get_mut(vpath).unwrap().offset = new_offset;

                if let Some(ref cb) = progress {
                    cb((i + 1) * 50 / total.max(1));
                }
            }

            // 写入加密索引
            let idx_json = serde_json::to_vec(&index)?;
            let enc_idx = encrypt_gcm(&enc_key, &idx_json, None);
            let idx_offset = tmp_file.seek(SeekFrom::End(0))?;
            tmp_file.write_all(&enc_idx)?;
            tmp_file.flush()?;

            let active = self.active_partition.unwrap();
            self.partitions[active].index_offset = idx_offset;
            self.partitions[active].index_length = enc_idx.len() as u64;

            // 写入头部
            let lock_state = &self.lock_state;
            let salt = &self.salt;
            let partitions = &self.partitions;
            write_header_to_file(&mut tmp_file, lock_state, salt, partitions, &sign_key)?;
            tmp_file.flush()?;
            tmp_file.sync_all()?; // fsync 确保数据落盘
            drop(tmp_file);

            // 原子替换：rename 临时文件到原路径
            fs::rename(&temp_path, &vault_path)?;

            // fsync 目录确保 rename 落盘
            if let Some(parent) = vault_path.parent() {
                let _ = File::open(parent).and_then(|d| d.sync_all());
            }

            // 清理备份
            let _ = fs::remove_file(&backup_path);

            secure_wipe_vec(idx_json);
            Ok(())
        })();

        match result {
            Ok(()) => {
                let file = OpenOptions::new().read(true).write(true).open(&vault_path)?;
                self.file = Some(file);
                if let Some(ref mut audit) = self.audit {
                    audit.add("执行保险柜碎片整理");
                }
                self.save_index(&index)?;
                if let Some(ref cb) = progress {
                    cb(100);
                }
                Ok(())
            }
            Err(e) => {
                // 失败时恢复备份
                let _ = fs::remove_file(&temp_path);
                if backup_path.exists() {
                    let _ = fs::rename(&backup_path, &vault_path);
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

    pub fn close(&mut self) {
        if let Some(ref mut audit) = self.audit {
            audit.add("保险柜已关闭");
        }
        if self.enc_key.is_some() && self.file.is_some() {
            let _ = self.load_index().and_then(|idx| self.save_index(&idx));
        }
        self.file = None;
        self.path = None;
        if let Some(mut key) = self.enc_key.take() { key.zeroize(); }
        if let Some(mut key) = self.auth_key.take() { key.zeroize(); }
        if let Some(mut key) = self.sign_key.take() { key.zeroize(); }
        self.active_partition = None;
    }
}

impl Drop for Vault {
    fn drop(&mut self) { self.close(); }
}