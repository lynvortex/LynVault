//! 会话生命周期 —— 创建 / 打开认证（v4/v5 恒定时间分区遍历）/ 索引加载保存 / 头部更新。
//! 3.0.0 拆分自 vault.rs，逻辑逐字节不变。
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::audit::AuditLog;
use crate::crypto::*;
use crate::error::VaultError;
use crate::index::{Index, IndexManager};
use crate::lock::LockState;
use crate::wipe::secure_wipe_vec;

use super::consts::*;
use super::fs_util::*;
use super::header::*;
use super::locked_key::LockedKey;
use super::{PartitionInfo, Vault};

/// 信封开柜的匹配结果元组（session.rs 双路径解包用）
type EnvelopeMatch = (usize, Index, KeyMaterial, Zeroizing<[u8; 32]>, bool);

impl Vault {
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

        // 2.7.1 修复（检查-再清零竞态）：旧实现先 is_vault_file 检查再以 create+truncate
        // 打开，两步之间目标文件可能被替换 —— 检查失效时直接把另一个保险柜清零且
        // 不可恢复。现改为 **create_new 优先**：目标已存在时不会被清零；确认
        // 「已存在且非保险柜」（用户已在保存对话框确认覆盖普通文件）后才以
        // create+truncate 重开。
        let mut file = match open_vault_create_new(path) {
            Ok(f) => f,
            Err(e) => {
                // create_new 失败：区分「已存在」与目录 / 权限等
                if let Ok(meta) = fs::metadata(path) {
                    if meta.is_dir() {
                        return Err(VaultError::Other("目标路径是目录，无法创建保险柜".into()));
                    }
                }
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(e.into());
                }
                if is_vault_file(path) {
                    return Err(VaultError::Other(
                        "目标路径已存在一个保险柜文件，拒绝覆盖（请选择其他位置或先手动删除）"
                            .into(),
                    ));
                }
                // 已存在且非保险柜的普通文件：UI 保存对话框已让用户显式确认覆盖。
                // 2.8.1（TOCTOU 收口）：旧实现 create+truncate 重开，「确认-重开」
                // 窗口内目标仍可能被换成保险柜文件而被清零。现在以**不截断**方式
                // 打开，用**同一句柄**验证 magic 后才 set_len(0) —— 打开与确认
                // 锚定同一文件对象，窗口关闭（句柄打开即锚定，无路径重开）。
                #[allow(clippy::suspicious_open_options)] // 截断延迟到 magic 验证后，见上
                {
                    let mut opts = OpenOptions::new();
                    opts.read(true).write(true).create(true);
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::OpenOptionsExt;
                        const FILE_SHARE_READ: u32 = 0x0000_0001;
                        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                        opts.share_mode(FILE_SHARE_READ)
                            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        opts.custom_flags(libc::O_NOFOLLOW);
                    }
                    opts.open(path)?
                }
            }
        };
        // 2.8.1：覆盖路径用同一句柄验证目标确实不是保险柜后才截断清零
        //（create_new 成功的新文件此处读到 EOF，直接放行）
        {
            use std::io::Read;
            let file_len = file.metadata()?.len();
            if file_len >= 8 {
                file.seek(SeekFrom::Start(0))?;
                let mut magic = [0u8; 8];
                file.read_exact(&mut magic)?;
                if &magic == MAGIC {
                    return Err(VaultError::Other(
                        "目标路径已存在一个保险柜文件，拒绝覆盖（请选择其他位置或先手动删除）"
                            .into(),
                    ));
                }
            }
            // 2.8.2：硬链接别名防护 —— 句柄锚定防住了「确认后被换成保险柜」，
            // 但防不住「普通文件是受害者文件的硬链接」：set_len(0) + 后续写入
            // 作用在共享 inode 上，会把用户从未同意覆盖的另一个链接目标清零。
            #[cfg(windows)]
            {
                use std::os::windows::io::AsRawHandle;
                use windows::Win32::Foundation::HANDLE;
                use windows::Win32::Storage::FileSystem::{
                    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
                };
                let mut info = BY_HANDLE_FILE_INFORMATION::default();
                // L8（审计修复）：API 失败时 fail-closed（旧实现放行继续截断）
                let ok = unsafe {
                    GetFileInformationByHandle(HANDLE(file.as_raw_handle() as isize), &mut info)
                };
                if ok.is_err() || info.nNumberOfLinks > 1 {
                    return Err(VaultError::Other(
                        "无法确认目标文件硬链接状态（或存在多个硬链接），拒绝覆盖 —— 请先删除其他链接或选择其他位置".into(),
                    ));
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if file.metadata()?.nlink() > 1 {
                    return Err(VaultError::Other(
                        "目标文件存在多个硬链接，拒绝覆盖（请先删除其他链接或选择其他位置）".into(),
                    ));
                }
            }
            file.set_len(0)?;
            file.seek(SeekFrom::End(0))?;
        }
        // 2.6.1：创建即为独占会话，避免与另一实例并发写同一文件
        lock_vault_exclusive(&file)
            .map_err(|_| VaultError::Other("保险柜文件已被另一个实例占用".into()))?;
        file.write_all(&[0u8; HEADER_SIZE_V5])?;
        file.flush()?;

        // ── 2.8.0（v5 信封加密）──
        // 随机 data_key 承担真正的加密职责；口令只负责「包裹」它存进头部。
        // 修改口令 = 换盐重新包裹 + 重写头部，数据一个字节不动。
        // 2.8.1：data_key/kek 用 Zeroizing —— expand_keys 派生失败的 `?` 早退
        // 路径上随机 data_key 不再以明文残留（数组没有 Drop，旧实现靠不到）。
        let mut vault_salt = [0u8; 32];
        OsRng.fill_bytes(&mut vault_salt);
        let mut dk_buf = [0u8; 32];
        OsRng.fill_bytes(&mut dk_buf);
        let data_key = Zeroizing::new(dk_buf);
        let mut keys = expand_keys(&data_key)?;

        let mut part_salt = [0u8; 32];
        OsRng.fill_bytes(&mut part_salt);
        let kek = Zeroizing::new(derive_kek(password, key_file_data, &part_salt)?);
        let alias_field = alias_field16(DEFAULT_PARTITION);
        let wrap_aad = key_wrap_aad(
            &auth_tag_header_prefix(&vault_salt, VERSION_V6),
            &alias_field,
            &part_salt,
        );
        let wrapped_v = encrypt_gcm(&kek, &data_key[..], &wrap_aad, None)?;
        let mut wrapped = [0u8; WRAPPED_KEY_SIZE];
        wrapped.copy_from_slice(&wrapped_v);
        drop(kek);
        secure_wipe_vec(wrapped_v);

        // 2.6.1：认证标签绑定头部（含保险柜 salt 与本条目别名字段），
        // 消除多分区场景下头部完整性被整体跳过的降级（详见 crypto::create_auth_tag_bound）。
        let auth_tag = bound_auth_tag(
            &keys.auth_key,
            &vault_salt,
            VERSION_V6,
            &alias_field,
            &part_salt,
        );

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
            salt: part_salt,
            auth_tag,
            index_offset,
            index_length,
            wrapped_key: Some(wrapped),
            audit_count: 0,
        };

        // 2.3.0：锁定区 HMAC 由 write_header_to_file 用公开密钥计算（见 crypto::derive_lock_mac_key），
        // 不再绑定主密码 —— 旧实现导致错误密码无法递增计数（锁定永不生效）且诱饵分区无法打开。
        let lock_state = LockState::new();
        // 3.0.0（M-2）：新建柜即生成随机挑战盐
        let mut yk_salt = [0u8; 32];
        OsRng.fill_bytes(&mut yk_salt);
        write_header_to_file(
            &mut file,
            VERSION_V6,
            &lock_state,
            &vault_salt,
            std::slice::from_ref(&partition),
            &keys.sign_key,
            &yk_salt,
        )?;

        // ── P2-20：直接建立会话（不再二次认证） ──
        let mut audit = AuditLog::new(keys.auth_key);
        audit.add("保险柜已创建并解锁");
        let mut cached = empty_index;
        cached.audit = audit.to_vec();

        self.file = Some(file);
        self.path = Some(path.to_path_buf());
        self.format_version = VERSION_V6;
        self.data_key = Some(LockedKey::new(*data_key)); // Zeroizing 解包 → 装箱驻留
        self.salt = vault_salt;
        self.enc_key = Some(LockedKey::new(keys.enc_key));
        self.auth_key = Some(LockedKey::new(keys.auth_key));
        self.sign_key = Some(LockedKey::new(keys.sign_key));
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

    /// 仅供集成测试构造 v4 旧格式夹具（v4 兼容 / 升级路径的回归测试需要）。
    /// 逻辑为 2.7.1 `create` 的原样复刻（含「库盐即分区盐」的历史行为）。
    #[doc(hidden)]
    pub fn create_v4_for_tests(
        &mut self,
        path: &Path,
        password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<(), VaultError> {
        if password.chars().count() < 12 {
            return Err(VaultError::Other("密码长度至少 12 位".into()));
        }
        if self.is_open() {
            return Err(VaultError::AlreadyOpen);
        }
        let mut file = open_vault_create_new(path)?;
        lock_vault_exclusive(&file)
            .map_err(|_| VaultError::Other("保险柜文件已被另一个实例占用".into()))?;
        file.write_all(&[0u8; HEADER_SIZE_V4])?;
        file.flush()?;

        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let mut keys = derive_keys(password, key_file_data, &salt)?;
        let auth_tag = bound_auth_tag(
            &keys.auth_key,
            &salt,
            VERSION_V4,
            &alias_field16(DEFAULT_PARTITION),
            &salt,
        );

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
            wrapped_key: None,
            audit_count: 0,
        };
        let lock_state = LockState::new();
        write_header_to_file(
            &mut file,
            VERSION_V4,
            &lock_state,
            &salt,
            std::slice::from_ref(&partition),
            &keys.sign_key,
            &[0u8; 32],
        )?;

        let mut audit = AuditLog::new(keys.auth_key);
        audit.add("保险柜已创建并解锁");
        let mut cached = empty_index;
        cached.audit = audit.to_vec();

        self.file = Some(file);
        self.path = Some(path.to_path_buf());
        self.format_version = VERSION_V4;
        self.data_key = None;
        self.salt = salt;
        self.enc_key = Some(LockedKey::new(keys.enc_key));
        self.auth_key = Some(LockedKey::new(keys.auth_key));
        self.sign_key = Some(LockedKey::new(keys.sign_key));
        self.lock_state = lock_state;
        self.partitions = vec![partition];
        self.active_partition = Some(0);
        self.audit = Some(audit);
        self.cached_index = Some(cached);
        self.audit_dirty = true;

        keys.zeroize();
        secure_wipe_vec(index_json);
        Ok(())
    }

    /// 仅供集成测试构造 v5/v6 信封格式夹具（兼容性回归测试需要）。
    /// 与 `create` 的差异：省去安全创建前奏（create_new 竞态防护等，
    /// 测试夹具不涉及不可信目标路径），并接受显式版本参数（5 或 6）。
    #[doc(hidden)]
    pub fn create_envelope_for_tests(
        &mut self,
        path: &Path,
        password: &str,
        key_file_data: Option<&[u8]>,
        version: u8,
    ) -> Result<(), VaultError> {
        debug_assert!(matches!(version, VERSION_V5 | VERSION_V6));
        if password.chars().count() < 12 {
            return Err(VaultError::Other("密码长度至少 12 位".into()));
        }
        if self.is_open() {
            return Err(VaultError::AlreadyOpen);
        }
        let mut file = open_vault_create_new(path)?;
        lock_vault_exclusive(&file)
            .map_err(|_| VaultError::Other("保险柜文件已被另一个实例占用".into()))?;
        file.write_all(&[0u8; HEADER_SIZE_V5])?;
        file.flush()?;

        let mut vault_salt = [0u8; 32];
        OsRng.fill_bytes(&mut vault_salt);
        let mut dk_buf = [0u8; 32];
        OsRng.fill_bytes(&mut dk_buf);
        let data_key = Zeroizing::new(dk_buf);
        let mut keys = expand_keys(&data_key)?;

        let mut part_salt = [0u8; 32];
        OsRng.fill_bytes(&mut part_salt);
        let kek = Zeroizing::new(derive_kek(password, key_file_data, &part_salt)?);
        let alias_field = alias_field16(DEFAULT_PARTITION);
        let wrap_aad = key_wrap_aad(
            &auth_tag_header_prefix(&vault_salt, version),
            &alias_field,
            &part_salt,
        );
        let wrapped_v = encrypt_gcm(&kek, &data_key[..], &wrap_aad, None)?;
        let mut wrapped = [0u8; WRAPPED_KEY_SIZE];
        wrapped.copy_from_slice(&wrapped_v);
        drop(kek);
        secure_wipe_vec(wrapped_v);

        let auth_tag = bound_auth_tag(
            &keys.auth_key,
            &vault_salt,
            version,
            &alias_field,
            &part_salt,
        );

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
            salt: part_salt,
            auth_tag,
            index_offset,
            index_length,
            wrapped_key: Some(wrapped),
            audit_count: 0,
        };
        let lock_state = LockState::new();
        let mut yk_salt = [0u8; 32];
        OsRng.fill_bytes(&mut yk_salt);
        write_header_to_file(
            &mut file,
            version,
            &lock_state,
            &vault_salt,
            std::slice::from_ref(&partition),
            &keys.sign_key,
            &yk_salt,
        )?;

        let mut audit = AuditLog::new(keys.auth_key);
        audit.add("保险柜已创建并解锁");
        let mut cached = empty_index;
        cached.audit = audit.to_vec();

        self.file = Some(file);
        self.path = Some(path.to_path_buf());
        self.format_version = version;
        self.data_key = Some(LockedKey::new(*data_key));
        self.salt = vault_salt;
        self.enc_key = Some(LockedKey::new(keys.enc_key));
        self.auth_key = Some(LockedKey::new(keys.auth_key));
        self.sign_key = Some(LockedKey::new(keys.sign_key));
        self.lock_state = lock_state;
        self.partitions = vec![partition];
        self.active_partition = Some(0);
        self.audit = Some(audit);
        self.cached_index = Some(cached);
        self.audit_dirty = true;

        keys.zeroize();
        secure_wipe_vec(index_json);
        Ok(())
    }

    // ═══════════════ 打开认证 ═══════════════

    /// 3.0.0：新增 `yk_response` —— 硬件密钥（YubiKey HMAC-SHA1 挑战-响应）。
    /// None = 不使用（现有行为逐字节一致）；Some = 对每个条目先试「响应混合
    /// KEK」再试普通 KEK 解包，两种分区共存。v4 无包裹层，响应被忽略。
    pub fn open_and_authenticate(
        &mut self,
        path: &Path,
        password: &str,
        key_file_data: Option<&[u8]>,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<usize, VaultError> {
        if self.is_open() {
            return Err(VaultError::AlreadyOpen);
        }
        let mut file = open_vault_rw(path, false)?;
        // 2.6.1：独占打开 —— 第二个实例（或同进程重复打开）必须失败而非并发写入
        lock_vault_exclusive(&file)
            .map_err(|_| VaultError::Other("保险柜文件已被另一个实例占用".into()))?;
        // 2.8.0：先嗅探 magic + 版本字节，再按格式读取对应大小的头部
        // （v4 文件总长可能不足 2048 字节，不能直接按 v5 头部大小读取）
        // 3.0.0（M-2）：嗅探扩展到 41 字节 —— 顺手读出头部保留区的挑战盐
        //（9..41）作为会话初始值；每次成功开柜后轮换（见下方成功路径）。
        let mut sniff = [0u8; 41];
        file.read_exact(&mut sniff)?;
        if &sniff[..8] != MAGIC {
            return Err(VaultError::BadMagic);
        }
        let mut yk_challenge_salt = [0u8; 32];
        yk_challenge_salt.copy_from_slice(&sniff[9..41]);
        self.yk_challenge_salt = yk_challenge_salt;
        match sniff[8] {
            VERSION_V4 => self.open_and_authenticate_v4(path, file, password, key_file_data),
            // 3.0.0：v6 与 v5 头部同布局、认证/包裹 AAD 按版本字节绑定 —— 同一信封路径
            v @ (VERSION_V5 | VERSION_V6) => self.open_and_authenticate_envelope(
                path,
                file,
                password,
                key_file_data,
                v,
                yk_response,
            ),
            v => Err(VaultError::Other(format!(
                "不支持的保险柜格式版本 {}（文件可能来自更新版本的 LynVault，请升级软件后重试）",
                v
            ))),
        }
    }

    /// v4 旧格式打开（2.8.0 起仅为兼容保留；新建保险柜一律 v5）。
    /// 认证逻辑与 2.7.1 的 open_and_authenticate 完全一致。
    fn open_and_authenticate_v4(
        &mut self,
        path: &Path,
        mut file: File,
        password: &str,
        key_file_data: Option<&[u8]>,
    ) -> Result<usize, VaultError> {
        file.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; HEADER_SIZE_V4];
        file.read_exact(&mut header)?;

        let (magic, version, salt) = Self::parse_header(&header)?;
        if &magic != MAGIC || version != VERSION_V4 {
            return Err(VaultError::BadMagic);
        }

        let lock_count = header[LOCK_OFFSET_V4];
        let mut lock_until = f64::from_le_bytes(
            header[LOCK_OFFSET_V4 + 1..LOCK_OFFSET_V4 + 9]
                .try_into()
                .unwrap(),
        );
        // 2.8.1：拒绝非有限值 —— NaN 恒判未锁定、+inf 恒判锁定，均属异常头部
        if !lock_until.is_finite() {
            lock_until = 0.0;
        }

        // 2.3.0 修复（关键）：锁定区 HMAC 使用从 salt 独立派生的**公开**密钥，
        // 与密码无关。因此：
        // - 错误密码能通过锁定区校验并进入分区认证 → 认证失败会真正递增 lock_count（锁定生效）；
        // - 诱饵分区（独立密码）也能通过锁定区校验并打开。
        // 旧版（<2.3.0）锁定区用密码派生密钥签名，此处做兼容校验并在后续写入时自动迁移。
        let mac_key = derive_lock_mac_key(&salt);
        let mut lock_state = LockState {
            lock_count,
            lock_until,
            lock_until_monotonic: None,
        };
        let stored_hmac: [u8; 32] = header[LOCK_OFFSET_V4 + 9..LOCK_OFFSET_V4 + 9 + 32]
            .try_into()
            .unwrap();
        let verified = if lock_state.verify_hmac(&mac_key, &stored_hmac) {
            true
        } else {
            // 旧版锁定区：用密码派生密钥（旧格式）再试一次；仅用于旧保险柜打开时校验。
            // 2.5.1：derive_legacy_lock_key 改为返回 Result（不再 panic），
            // 派生失败（如 Argon2id 内存分配失败）按校验失败处理。
            match derive_legacy_lock_key(&salt, password, key_file_data) {
                Ok(legacy_key) => lock_state.verify_hmac(&legacy_key, &stored_hmac),
                Err(_) => false,
            }
        };
        if !verified {
            // 2.7.1 修复：<2.3.0 的旧格式保险柜锁定区用密码派生密钥校验，输错密码
            // 同样走到该分支 —— 旧文案「头部锁定区被篡改」会诱导用户误以为文件
            // 被破坏而丢弃重要保险柜。现明确告知旧版保险柜通常只是密码或密钥
            // 文件不正确。
            return Err(VaultError::Other(
                "头部锁定区校验失败。若是 2.3.0 之前创建的旧版保险柜，这通常只是密码或密钥文件不正确，请确认后重试（文件并未损坏，请勿删除）；新版保险柜出现该错误则说明头部可能被篡改".into(),
            ));
        }
        if lock_state.is_locked() {
            return Err(VaultError::Locked);
        }

        // 解析分区表：始终扫描 MAX_PARTITIONS 个条目（2.3.0 起伪条目整体随机填充，
        // 不再有「别名首字节 0」标记，因此不再跳过任何条目 —— 全部参与认证以保证恒定时间）
        let mut parsed: Vec<PartitionInfo> = Vec::new();
        let mut off = 106;
        for _ in 0..MAX_PARTITIONS {
            if off + PARTITION_ENTRY_SIZE_V4 > HEADER_SIZE_V4 {
                break;
            }
            let alias_len = header[off..off + 16]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(16);
            let alias = String::from_utf8_lossy(&header[off..off + alias_len]).to_string();
            let mut p_salt = [0u8; 32];
            p_salt.copy_from_slice(&header[off + 16..off + 48]);
            let mut auth_tag = [0u8; 32];
            auth_tag.copy_from_slice(&header[off + 48..off + 80]);
            let index_offset = u64::from_le_bytes(header[off + 80..off + 88].try_into().unwrap());
            let index_length = u64::from_le_bytes(header[off + 88..off + 96].try_into().unwrap());
            parsed.push(PartitionInfo {
                alias,
                salt: p_salt,
                auth_tag,
                index_offset,
                index_length,
                wrapped_key: None,
                audit_count: 0,
            });
            off += PARTITION_ENTRY_SIZE_V4;
        }

        // C9 修复 + 2.3.0 + 2.4.1：始终对**全部 8 个条目**执行完整 Argon2id 派生
        // （即使中途匹配），消除计时侧信道 —— 总派生工作量恒定，与真实分区数量无关。
        //
        // 2.4.1 优化（P1-6）：8 组密钥改为分块并行派生（块大小 = min(CPU 逻辑核数, 4)），
        // 串行约 1s 降至约 0.25-0.5s。并行只是调度优化：8 次派生仍 100% 完成后
        // 才进入认证比较，恒定时间语义不变；并行度上限 4 同时把瞬时内存峰值
        // 控制在 4×64MB，低配机器按核数自动降为 1（退化为旧行为）。
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        // 3.0.0：并行上限 4 → 8 —— 8 核以上机器开柜约减半（8×Argon2id 各 64MB，
        // 瞬时内存峰值 512MB，桌面场景可接受；低配机器按核数自动回落）
        let parallel = cpus.clamp(1, 8);
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
            // 2.6.1：用「绑定头部」的认证标签校验 —— 头部前缀 + 本条目别名字段 + salt
            // 都被纳入 HMAC，因此篡改头部必然使该分区匹配失败（不再依赖分区计数）。
            let eoff = 106 + idx * PARTITION_ENTRY_SIZE_V4;
            let tag_ok = verify_auth_tag_bound(
                &keys.auth_key,
                &header[..105],
                &header[eoff..eoff + 16],
                &header[eoff + 16..eoff + 48],
                &p.auth_tag,
            );
            if matched_idx.is_none() && tag_ok {
                match Self::try_authenticate_partition(&mut file, &parsed, idx, keys) {
                    Ok(index) => {
                        matched_idx = Some(idx);
                        matched_index = Some(index);
                        matched_keys = Some((keys.enc_key, keys.auth_key, keys.sign_key));
                    }
                    Err(e) => {
                        // 匹配分区但头部/索引校验失败 → 视为篡改，中止并清理全部密钥
                        // 2.7.1 诊断：先以头部 HMAC 签名（此前只写不校验）取证，
                        // 再统一清零全部密钥
                        let sig_ok = verify_header_signature(&header, &keys.sign_key);
                        for k in keys_list.iter_mut() {
                            k.zeroize();
                        }
                        // 2.7.1 修复：分区密码正确但索引解不出来时，旧实现只抛
                        // 「Invalid ciphertext or corrupted data」，与「密码错误」
                        // 不可区分，也没有下一步指引。现明确告知「分区密码正确」。
                        return Err(VaultError::Other(format!(
                            "分区密码正确，但该分区数据校验失败（{}）。头部签名{}。为避免进一步损坏，请勿再向此保险柜写入任何数据，并改用更早时间点的副本（用其他分区密码打开不受影响）",
                            e,
                            if sig_ok {
                                "校验通过 —— 头部未被篡改，损坏位于索引数据区"
                            } else {
                                "校验失败 —— 头部可能也被篡改"
                            }
                        )));
                    }
                }
            }
            // 不 return，继续遍历剩余条目（恒定时间语义由 8 次派生保证）
        }

        // 全部密钥材料统一清理（匹配项的副本已随 matched_keys 带出）
        for k in keys_list.iter_mut() {
            k.zeroize();
        }

        if let (Some(idx), Some(index), Some((enc_key, auth_key, sign_key))) =
            (matched_idx, matched_index, matched_keys)
        {
            // 过滤出真实分区（别名合理的条目；伪条目随机数据几乎不可能通过校验）
            let real_partitions: Vec<PartitionInfo> = parsed
                .iter()
                .filter(|p| is_plausible_alias(&p.alias))
                .cloned()
                .collect();
            let matched_salt = parsed[idx].salt;
            let matched_tag = parsed[idx].auth_tag;
            // 恒定时间比较：避免按字节短路泄露「salt/tag 前多少字节匹配」的时序信息
            let active = real_partitions.iter()
                .position(|p| {
                    use subtle::ConstantTimeEq;
                    bool::from(p.salt.ct_eq(&matched_salt) & p.auth_tag.ct_eq(&matched_tag))
                })
                .ok_or_else(|| VaultError::Other(
                    "头部与数据不匹配：找不到对应的分区（文件可能被篡改、损坏或与其他保险柜混用）".into(),
                ))?;

            lock_state.reset();
            self.lock_state = lock_state;
            self.salt = salt;
            // 2.8.0：会话元数据 —— v4 格式无包裹层，data_key 为 None
            self.format_version = VERSION_V4;
            self.data_key = None;
            self.partitions = real_partitions;
            self.active_partition = Some(active);

            // 2.6.1：旧格式（未绑定头部）认证标签 → 首次成功打开即就地迁移为绑定格式，
            // 之后头部完整性由 auth_tag 无条件保证。仅迁移当前分区（其他分区的
            // auth_key 未知，待其各自被打开时迁移），由随后的 update_header 落盘。
            let moff = 106 + idx * PARTITION_ENTRY_SIZE_V4;
            let migrated_tag = create_auth_tag_bound(
                &auth_key,
                &auth_tag_header_prefix(&salt, VERSION_V4),
                &header[moff..moff + 16],
                &header[moff + 16..moff + 48],
            );
            if self.partitions[active].auth_tag != migrated_tag {
                self.partitions[active].auth_tag = migrated_tag;
            }

            self.enc_key = Some(LockedKey::new(enc_key));
            self.auth_key = Some(LockedKey::new(auth_key));
            self.sign_key = Some(LockedKey::new(sign_key));

            let mut audit = AuditLog::from_entries(index.audit.clone(), auth_key);
            // 2.8.2：恢复时丢弃过尾部条目 → 显式写入告警（不再静默截断）
            if audit.is_truncated() {
                audit.add("警告：审计链存在无法校验的条目，部分历史记录可能被篡改或损坏");
            }
            audit.add("保险柜已解锁");
            self.audit = Some(audit);

            self.file = Some(file);
            self.path = Some(path.to_path_buf());
            // 2.4.1：成功打开后把索引放入内存缓存，后续操作不再重复解密加载
            self.cached_index = Some(index);
            self.audit_dirty = true; // "已解锁"审计尚未落盘

            // 成功打开：重置锁定区并重新签名头部（旧保险柜在此完成锁定区格式迁移）。
            // 3.0.0（M-2）：每次成功开柜轮换硬件密钥挑战盐 —— 响应一次性。
            //（v4 头部不写盐，此处轮换仅为会话语义一致）
            OsRng.fill_bytes(&mut self.yk_challenge_salt);
            // 3.0.0（L-2）：后置步骤失败时显式放弃会话，不再外泄「Err + 半开会话」
            if let Err(e) = self.update_header() {
                self.abandon_session();
                return Err(e);
            }

            // 3.0.0（胁迫密码）：带标记的分区开柜成功 → 销毁其他分区条目
            //（fail-closed：触发失败即开柜失败，见 duress 模块文档）
            if let Err(e) = self.check_and_trigger_duress() {
                self.abandon_session();
                return Err(e);
            }

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
        file.seek(SeekFrom::Start(LOCK_OFFSET_V4 as u64))?;
        file.write_all(&lock_buf)?;
        file.flush()?;
        file.sync_all()?;

        Err(VaultError::AuthFailed)
    }

    /// 2.8.0（v5）起信封加密打开认证。3.0.0：版本参数化（v5/v6 头部同布局）。
    ///
    /// 与 v4 的恒定时间结构一致：先对全部 8 个条目并行完成 Argon2id（KEK 派生，
    /// 绝对主导成本），再进入逐条目「解包 data_key → 派生会话密钥 → 验证绑定
    /// 认证标签」的轻量比较阶段 —— 每个条目都完整尝试，不因中途匹配而短路。
    /// 口令正确 ⇔ 该条目的 GCM 解包成功（错误口令解包必然失败）。
    #[allow(clippy::too_many_arguments)]
    fn open_and_authenticate_envelope(
        &mut self,
        path: &Path,
        mut file: File,
        password: &str,
        key_file_data: Option<&[u8]>,
        envelope_version: u8,
        yk_response: Option<&[u8; 20]>,
    ) -> Result<usize, VaultError> {
        debug_assert!(matches!(envelope_version, VERSION_V5 | VERSION_V6));
        file.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; HEADER_SIZE_V5];
        file.read_exact(&mut header)?;

        let (magic, version, salt) = Self::parse_header(&header)?;
        if &magic != MAGIC || version != envelope_version {
            return Err(VaultError::BadMagic);
        }

        let lock_count = header[LOCK_OFFSET_V5];
        let mut lock_until = f64::from_le_bytes(
            header[LOCK_OFFSET_V5 + 1..LOCK_OFFSET_V5 + 9]
                .try_into()
                .unwrap(),
        );
        // 2.8.1：拒绝非有限值 —— NaN 恒判未锁定、+inf 恒判锁定，均属异常头部
        if !lock_until.is_finite() {
            lock_until = 0.0;
        }

        // 锁定区校验（公开密钥，与 v4 同一机制；v5 为新格式，无 legacy 回退）
        let mac_key = derive_lock_mac_key(&salt);
        let mut lock_state = LockState {
            lock_count,
            lock_until,
            lock_until_monotonic: None,
        };
        let stored_hmac: [u8; 32] = header[LOCK_OFFSET_V5 + 9..LOCK_OFFSET_V5 + 9 + 32]
            .try_into()
            .unwrap();
        if !lock_state.verify_hmac(&mac_key, &stored_hmac) {
            return Err(VaultError::Other(
                "头部锁定区校验失败 —— 头部可能被篡改".into(),
            ));
        }
        if lock_state.is_locked() {
            return Err(VaultError::Locked);
        }

        // 解析 8 个 192 字节条目（含 60 字节包裹密钥；伪条目为随机字节，认证必然失败）
        let mut parsed: Vec<PartitionInfo> = Vec::new();
        let mut off = 106;
        for _ in 0..MAX_PARTITIONS {
            let alias_len = header[off..off + 16]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(16);
            let alias = String::from_utf8_lossy(&header[off..off + alias_len]).to_string();
            let mut p_salt = [0u8; 32];
            p_salt.copy_from_slice(&header[off + 16..off + 48]);
            let mut auth_tag = [0u8; 32];
            auth_tag.copy_from_slice(&header[off + 48..off + 80]);
            let index_offset = u64::from_le_bytes(header[off + 80..off + 88].try_into().unwrap());
            let index_length = u64::from_le_bytes(header[off + 88..off + 96].try_into().unwrap());
            let mut wrapped = [0u8; WRAPPED_KEY_SIZE];
            wrapped.copy_from_slice(&header[off + 96..off + 96 + WRAPPED_KEY_SIZE]);
            // 3.0.0（审计锚点）：同时读出本槽的审计计数
            let audit_count = u32::from_le_bytes(
                header[AUDIT_COUNT_OFFSET + 4 * parsed.len()
                    ..AUDIT_COUNT_OFFSET + 4 * (parsed.len() + 1)]
                    .try_into()
                    .unwrap(),
            );
            parsed.push(PartitionInfo {
                alias,
                salt: p_salt,
                auth_tag,
                index_offset,
                index_length,
                wrapped_key: Some(wrapped),
                audit_count,
            });
            off += PARTITION_ENTRY_SIZE_V5;
        }

        // 阶段 1：8 × Argon2id（KEK 派生），分块并行（与 v4 相同的调度优化）。
        // 2.8.1：KEK 用 Zeroizing 包裹 —— `?` 提前返回（派生失败）时已派生的
        // KEK 不再以明文形式残留在堆上（数组没有 Drop，旧实现靠不到）
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        // 3.0.0：并行上限 4 → 8 —— 8 核以上机器开柜约减半（8×Argon2id 各 64MB，
        // 瞬时内存峰值 512MB，桌面场景可接受；低配机器按核数自动回落）
        let parallel = cpus.clamp(1, 8);
        let mut kek_list: Vec<Zeroizing<[u8; 32]>> = Vec::with_capacity(parsed.len());
        for chunk in parsed.chunks(parallel) {
            let results: Vec<Result<[u8; 32], VaultError>> = std::thread::scope(|s| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|p| s.spawn(move || derive_kek(password, key_file_data, &p.salt)))
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join()
                            .unwrap_or_else(|_| Err(VaultError::Other("密钥派生线程失败".into())))
                    })
                    .collect()
            });
            // 2.8.2：`?` 早退时 results 中尚未 push 的 KEK 是裸 [u8;32] 数组
            // （Copy，drop 是空操作），会以明文残留堆内存 —— 改为先全部收进
            // Zeroizing 容器再决定成败，任何路径 drop 即清零。
            let mut chunk_keks: Vec<Zeroizing<[u8; 32]>> = Vec::with_capacity(results.len());
            let mut first_err: Option<VaultError> = None;
            for r in results {
                match r {
                    Ok(k) => chunk_keks.push(Zeroizing::new(k)),
                    Err(e) => {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    }
                }
            }
            if let Some(e) = first_err {
                // chunk_keks 是 Zeroizing，drop 即清零
                return Err(e);
            }
            kek_list.extend(chunk_keks);
        }

        // 阶段 2：逐条目解包 + 认证标签校验（轻量，全部尝试保持恒定时间语义）。
        // candidate 的 data_key 同样用 Zeroizing：无论走哪条分支（存入会话 /
        // 篡改中止 / 多余候选），drop 时都会清零。
        let prefix = auth_tag_header_prefix(&salt, envelope_version);
        // 匹配结果：(条目序号, 索引, 会话密钥, data_key, 是否经硬件密钥混合路径命中)
        let mut matched: Option<EnvelopeMatch> = None;
        for (idx, kek) in kek_list.iter().enumerate() {
            let p = &parsed[idx];
            let eoff = 106 + idx * PARTITION_ENTRY_SIZE_V5;
            let alias_field = &header[eoff..eoff + 16];
            let wrap_aad = key_wrap_aad(&prefix, alias_field, &p.salt);
            let stored_wrapped = p.wrapped_key.unwrap_or([0u8; WRAPPED_KEY_SIZE]);
            // 3.0.0：双路径解包 —— 提供响应时先试「混合 KEK」（二因子分区），
            // 未命中再试普通 KEK（普通分区）。两次 GCM 开销可忽略；不提供响应
            // 时只走普通路径（行为与历史一致）。
            // L-1（审计修复）：候选一律以 Zeroizing 持有 —— [u8;32] 是 Copy，
            // `if let Some(dk) = dk_opt` 取出的是副本，原值按普通 drop 释放会残留
            // 明文 data_key（认证标签失配分支正是最该干净的场景）。
            let mut dk_opt: Option<Zeroizing<[u8; 32]>> = None;
            let mut via_yk = false;
            if let Some(resp) = yk_response {
                let mixed = Zeroizing::new(mix_kek_with_response(kek, resp));
                if let Some(dk) = unwrap_data_key(&mixed, &stored_wrapped, &wrap_aad) {
                    dk_opt = Some(Zeroizing::new(dk));
                    via_yk = true;
                }
            }
            if dk_opt.is_none() {
                dk_opt = unwrap_data_key(kek, &stored_wrapped, &wrap_aad).map(Zeroizing::new);
            }
            let mut candidate_via_yk = false;
            let mut candidate: Option<(KeyMaterial, Zeroizing<[u8; 32]>)> = None;
            if let Some(dk) = dk_opt {
                // dk 是 Zeroizing：所有失败分支随 drop 自动清零，不再手工复制清零
                if let Ok(keys) = expand_keys(&dk) {
                    if verify_auth_tag_bound(
                        &keys.auth_key,
                        &prefix,
                        alias_field,
                        &p.salt,
                        &p.auth_tag,
                    ) {
                        candidate = Some((keys, dk));
                        candidate_via_yk = via_yk;
                    }
                }
            }
            if matched.is_none() {
                if let Some((keys, dk)) = candidate {
                    match Self::try_authenticate_partition(&mut file, &parsed, idx, &keys) {
                        Ok(index) => matched = Some((idx, index, keys, dk, candidate_via_yk)),
                        Err(e) => {
                            // 匹配分区但头部/索引校验失败 → 视为篡改，中止并清理全部密钥
                            //（candidate 的 dk 是 Zeroizing，drop 时自动清零）
                            let sig_ok = verify_header_signature_v5(&header, &keys.sign_key);
                            // keys 是 ZeroizeOnDrop，dk 是 Zeroizing —— 出作用域即清零
                            for k in kek_list.iter_mut() {
                                k.zeroize();
                            }
                            return Err(VaultError::Other(format!(
                                "分区密码正确，但该分区数据校验失败（{}）。头部签名{}。为避免进一步损坏，请勿再向此保险柜写入任何数据，并改用更早时间点的副本",
                                e,
                                if sig_ok {
                                    "校验通过 —— 头部未被篡改，损坏位于索引数据区"
                                } else {
                                    "校验失败 —— 头部可能也被篡改"
                                }
                            )));
                        }
                    }
                }
            } else if let Some((_, dk)) = candidate {
                // 防御分支：理论上至多一个条目能通过认证，多余的密钥立即清零
                drop(dk);
            }
            let _ = candidate_via_yk;
        }
        for k in kek_list.iter_mut() {
            k.zeroize();
        }

        if let Some((idx, index, keys, data_key, via_yk)) = matched {
            // 2.8.2（M1）→ 2.8.2.1（兼容性修正）：头部签名**校验但不再硬拒**。
            // index_offset/index_length 不在 auth_tag AAD、key_wrap AAD、锁区
            // HMAC 的任何覆盖范围内 —— 验签仍执行，但签名不一致时不再拒绝打开：
            // 多分区保险柜的头部由「最后打开的分区」签名（跨分区打开必然
            // 不一致）、云同步回写/写入中断/历史版本签名形态差异也会造成
            // 良性不一致 —— 硬拒把合法存量柜全部挡在门外（发布当日即回归）。
            // 现改为：写入审计告警 + 下方 update_header 按当前分区密钥重签
            // （迁移到规范形）。已知取舍（3.0.0 M-3 复核）：全文件级回滚（攻击者
            // 持旧版本完整副本，云同步/备份回灌场景）无法用头部内状态根治 ——
            // index_offset/length 不在 auth_tag/包裹 AAD/锁区 HMAC 覆盖范围内，
            // 头部签名又因多分区跨签名不能硬拒；v6 头部与 v5 逐字节同布局，
            // 曾设想的 generation 计数器未引入，README「已知限制」已如实声明
            // 该窗口，不得再以「v6 根治」误导后续审计。
            let legacy_signature = !verify_header_signature_v5(&header, &keys.sign_key);
            // 过滤出真实分区（伪条目随机数据几乎不可能通过认证）
            let real_partitions: Vec<PartitionInfo> = parsed
                .iter()
                .filter(|p| is_plausible_alias(&p.alias))
                .cloned()
                .collect();
            let matched_salt = parsed[idx].salt;
            let matched_tag = parsed[idx].auth_tag;
            // 恒定时间比较（与 v4 相同）
            let active = real_partitions.iter()
                .position(|p| {
                    use subtle::ConstantTimeEq;
                    bool::from(p.salt.ct_eq(&matched_salt) & p.auth_tag.ct_eq(&matched_tag))
                })
                .ok_or_else(|| VaultError::Other(
                    "头部与数据不匹配：找不到对应的分区（文件可能被篡改、损坏或与其他保险柜混用）".into(),
                ))?;

            lock_state.reset();
            self.lock_state = lock_state;
            self.salt = salt;
            self.format_version = envelope_version;
            self.partitions = real_partitions;
            self.active_partition = Some(active);

            self.enc_key = Some(LockedKey::new(keys.enc_key));
            self.auth_key = Some(LockedKey::new(keys.auth_key));
            self.sign_key = Some(LockedKey::new(keys.sign_key));
            self.data_key = Some(LockedKey::new(*data_key)); // Zeroizing 解包 → 装箱驻留
            self.yubikey_wrapped = via_yk;

            // 3.0.0（审计锚点）：头部计数 vs 索引实际条目数 —— 尾部截断
            //（HMAC 链无法自查）或索引回滚在此显式检出。计数 0 = 无锚点
            //（v4 分区 / 3.0.0 之前落盘的存量分区），跳过并在首次落盘后生效。
            let stored_count = parsed[idx].audit_count;
            let anchor_mismatch = stored_count != 0 && index.audit.len() != stored_count as usize;
            let mut audit = AuditLog::from_entries(index.audit.clone(), keys.auth_key);
            if anchor_mismatch {
                audit.mark_truncated();
            }
            // 2.8.2：恢复时丢弃过尾部条目 → 显式写入告警（不再静默截断）
            if audit.is_truncated() {
                audit.add("警告：审计链存在无法校验的条目，部分历史记录可能被篡改或损坏");
            }
            if anchor_mismatch {
                audit.add(&format!(
                    "警告：审计记录数量与头部锚点不符（索引 {} 条，锚点 {}）—— 历史记录可能被截断或回滚",
                    index.audit.len(),
                    stored_count
                ));
            }
            // 锚点以磁盘索引为准刷新（会话内新增条目由 save_index 同步）
            self.partitions[active].audit_count = index.audit.len() as u32;
            // 2.8.2.1：签名与当前分区密钥不一致（多分区跨签名/历史遗留/头部曾被改动）
            // → 审计留痕，随后 update_header 按当前分区密钥重签迁移
            if legacy_signature {
                audit.add("提示：头部签名与当前分区密钥不一致（多分区跨签名或历史版本遗留），已重新签名迁移");
            }
            audit.add("保险柜已解锁");
            self.audit = Some(audit);

            self.file = Some(file);
            self.path = Some(path.to_path_buf());
            self.cached_index = Some(index);
            self.audit_dirty = true;

            // 成功打开：重置锁定区并重新签名头部。
            // 3.0.0（M-2）：每次成功开柜轮换硬件密钥挑战盐 —— 响应一次性
            //（旧响应在本次开柜后立即失效，下次开柜需重新触摸钥匙）。
            OsRng.fill_bytes(&mut self.yk_challenge_salt);
            // 3.0.0（L-2）：后置步骤失败时显式放弃会话
            if let Err(e) = self.update_header() {
                self.abandon_session();
                return Err(e);
            }

            // 3.0.0（胁迫密码）：同 v4 —— 带标记分区开柜成功即销毁其他分区条目
            if let Err(e) = self.check_and_trigger_duress() {
                self.abandon_session();
                return Err(e);
            }

            return Ok(active);
        }

        // 全部失败：递增锁定计数（v5 偏移）
        lock_state.record_failure();
        let mut lock_buf = [0u8; 41];
        lock_buf[0] = lock_state.lock_count;
        lock_buf[1..9].copy_from_slice(&lock_state.lock_until.to_le_bytes());
        let hmac = lock_state.compute_hmac(&mac_key);
        lock_buf[9..41].copy_from_slice(&hmac);
        file.seek(SeekFrom::Start(LOCK_OFFSET_V5 as u64))?;
        file.write_all(&lock_buf)?;
        file.flush()?;
        file.sync_all()?;

        Err(VaultError::AuthFailed)
    }
    /// 2.4.1 新增（从 open_and_authenticate 抽取）：对已通过 auth_tag（头部绑定）校验的
    /// 分区做索引边界检查 + 读取解密。密钥由调用方持有并负责清理。
    /// 头部完整性已由调用方在 auth_tag 校验阶段无条件保证。
    fn try_authenticate_partition(
        file: &mut File,
        parsed: &[PartitionInfo],
        idx: usize,
        keys: &KeyMaterial,
    ) -> Result<Index, VaultError> {
        let p = &parsed[idx];
        // 头部完整性（2.6.1 重构，消除零知识降级）：
        // 旧实现在此按 `real_count = 头部中别名合法的条目数` 决定是否校验头部签名 ——
        // 该计数完全取自攻击者可控的头部：向单分区保险柜塞入一个带合法别名的伪条目，
        // 即可把签名校验整体跳过。现改为：头部完整性由调用方已验证的**头部绑定
        // auth_tag** 无条件保证（篡改 magic/version/保险柜 salt/本条目别名/salt 都会
        // 导致认证失败，见 crypto::create_auth_tag_bound），不再依赖任何分区计数，
        // 因此这里不再做「按分区数条件跳过」的签名校验。
        //
        // 全局头部签名（HMAC-SHA512）仍按旧格式写入以保持头部结构兼容；它能覆盖的
        // 字段已被 auth_tag（身份/全局字段）与索引 GCM 标签（index_offset/length）
        // 分别保护，其无法覆盖的多分区交叉签名场景也不再是安全缺口。

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
                "索引过大（{} 字节），超过单次加载上限",
                p.index_length
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

    /// 2.8.1：改为接管索引所有权 —— 旧实现 `index.clone()` 每次保存都深拷贝
    /// 整个 files/folders HashMap（10k 文件 ≈ 数 MB 分配 ×2，含 audit Vec 再克隆一次），
    /// 所有调用方本就在 save 后不再使用索引，直接移动即可。
    /// 2.8.1：只读借用内存索引缓存（list_folder / get_file_info 等只读路径
    /// 免去 load_index 的整索引克隆）
    pub fn index_ref(&self) -> Result<&Index, VaultError> {
        self.cached_index.as_ref().ok_or(VaultError::NotOpen)
    }

    pub fn save_index(&mut self, mut index: Index) -> Result<(), VaultError> {
        let active = self.active_partition.ok_or(VaultError::NotOpen)?;
        let (old_off, old_len) = {
            let p = &self.partitions[active];
            (p.index_offset, p.index_length)
        };

        if let Some(audit) = &self.audit {
            index.audit = audit.to_vec();
        }
        // 3.0.0（审计锚点）：计数与本次落盘的索引内容一致 —— 头部与索引的
        // 写入顺序（先索引后头部）保证任意崩溃点两者自洽
        self.partitions[active].audit_count = index.audit.len() as u32;
        let idx = index;

        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        // 步骤 1：写新索引到末尾（不擦旧索引）
        let (new_off, new_len) = save_index_to_file(file, enc_key, &idx)?;

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

    pub(crate) fn update_header(&mut self) -> Result<(), VaultError> {
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let sign_key = self.sign_key.as_ref().ok_or(VaultError::NotOpen)?;
        let yk_salt = self.yk_challenge_salt;
        write_header_to_file(
            file,
            self.format_version,
            &self.lock_state,
            &self.salt,
            &self.partitions,
            sign_key,
            &yk_salt,
        )
    }

    /// 头部前缀解析（magic / 版本 / 保险柜 salt）—— 三个字段在 v4/v5 布局中位置一致。
    fn parse_header(header: &[u8]) -> Result<([u8; 8], u8, [u8; 32]), VaultError> {
        if header.len() < 105 {
            return Err(VaultError::BadMagic);
        }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&header[..8]);
        let version = header[8];
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&header[73..105]);
        Ok((magic, version, salt))
    }
}
