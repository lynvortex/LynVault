//! 文件写入 —— 导入 / 批量导入 / 文件夹导入 / 文本编辑保存。
//! 3.0.0：v6 会话按 CHUNK_SIZE_V6 分块流式导入（恒定内存），v4/v5 会话行为不变。
use std::fs::{self};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{chunk_aad, encrypt_gcm};
use crate::error::VaultError;
use crate::index::{ChunkLayout, FileMeta, Index};
use crate::wipe::{dod_overwrite_range, secure_wipe_vec};
use zeroize::Zeroize;

use super::consts::*;
use super::fs_util::*;

use super::Vault;

impl Vault {
    // ═══════════════ 文件导入 ═══════════════

    /// 导入单个文件（独立命令路径：加载缓存索引 → 写入 → 单次 save_index）。
    pub fn import_file(&mut self, src_path: &Path, vpath: &str) -> Result<(), VaultError> {
        let mut index = self.load_index()?;
        self.import_file_into_index(&mut index, src_path, vpath, true, None)?;
        self.save_index(index)
    }

    /// 2.4.1 新增：批量导入多个文件（P0-2 优化核心）。
    /// 单次 load_index（缓存）+ 内存更新 + **一次** save_index。
    /// 旧实现（前端循环调用 import_file）N 个文件 = N 次全量索引重写
    /// + N×10 次 fsync；现在批量路径只有 1 次。
    ///
    /// 返回 (成功数, 失败数, 失败明细)。单个文件失败记录日志后继续。
    /// 2.8.2：新增条目数上限与失败明细返回 —— 旧实现只返回计数，注释声称
    /// 「明细已反馈前端」但根本没有明细出口。
    /// 3.0.0（优化1）：`file_progress`（第 done 个 / 共 total 个）与
    /// `chunk_progress`（当前文件已加密字节 / 总字节，仅 v6 分块路径）回调。
    pub fn import_files_batch(
        &mut self,
        src_paths: &[String],
        dest_base: &str,
        file_progress: Option<&dyn Fn(usize, usize)>,
        chunk_progress: Option<&dyn Fn(u64, u64)>,
    ) -> Result<(usize, usize, Vec<String>), VaultError> {
        if src_paths.len() > MAX_IMPORT_ENTRIES {
            return Err(VaultError::Other(format!(
                "单次导入条目数超过安全上限（{}）",
                MAX_IMPORT_ENTRIES
            )));
        }
        let mut index = self.load_index()?;
        let base_clean = dest_base.trim_end_matches('/');
        let mut ok = 0usize;
        let mut fail = 0usize;
        let mut errors: Vec<String> = Vec::new();
        for p in src_paths {
            let src = std::path::Path::new(p);
            let name = src
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let vpath = format!("{}/{}", base_clean, name);
            match self.import_file_into_index(&mut index, src, &vpath, false, chunk_progress) {
                Ok(()) => ok += 1,
                Err(e) => {
                    fail += 1;
                    errors.push(format!("{}: {}", name, e));
                    // 2.8.1：不再把含 vpath 的错误写入明文日志（违反 2.6.1 自定规则），
                    // 失败明细经返回值反馈给前端逐项展示
                    log::warn!("批量导入有失败项（明细已随返回值反馈）");
                }
            }
        }
        if let Some(cb) = file_progress {
            cb(src_paths.len(), src_paths.len());
        }
        // 2.4.1（P1-14）：批量操作记一条摘要审计，不再逐文件刷审计链
        if ok > 0 || fail > 0 {
            self.log_event(&format!("批量导入：成功 {} 个，失败 {} 个", ok, fail));
        }
        if ok > 0 {
            // 2.8.2：批量路径的密文写入省掉了逐文件 fsync —— save_index 的
            // sync_all 作用于同一句柄，会连带刷出全部已写密文，崩溃安全不变
            self.save_index(index)?;
        }
        Ok((ok, fail, errors))
    }

    /// 2.4.1 新增（从 import_file 抽取）：把一个文件加密追加到保险柜并更新**内存中的**索引。
    /// 不写盘、不审计 —— 由调用方决定单文件（import_file：逐次落盘）
    /// 或批量（import_files_batch / import_folder：最后一次落盘）策略。
    /// 2.8.2：`sync_each` 控制是否逐文件 fsync —— 批量路径传 false，由调用方在
    /// save_index 时统一 sync_all（同句柄 sync_all 会连带刷出全部已写密文），
    /// 千文件批量导入从 N 次 fsync 降为 1 次。
    #[allow(clippy::too_many_arguments)]
    fn import_file_into_index(
        &mut self,
        index: &mut Index,
        src_path: &Path,
        vpath: &str,
        sync_each: bool,
        chunk_progress: Option<&dyn Fn(u64, u64)>,
    ) -> Result<(), VaultError> {
        // M5 修复：归一化 + 校验虚拟路径（2.8.2：收敛到 clean_vpath 单一来源）
        let vpath =
            Index::clean_vpath(vpath).ok_or_else(|| VaultError::Other("无效的虚拟路径".into()))?;

        // C5 修复：检查重名，避免静默覆盖
        // 2.8.1：同时检查文件夹命名空间 —— file/folder 同名碰撞会让
        // rename/delete/move 的语义变得含混（两套删除实现对同一 vpath 行为不同）
        if index.files.contains_key(&vpath) {
            return Err(VaultError::Other(format!("目标路径已存在: {}", vpath)));
        }
        if index.folders.contains_key(&vpath) {
            return Err(VaultError::Other(format!(
                "目标路径已存在同名文件夹，无法导入为文件: {}",
                vpath
            )));
        }

        // 3.0.0（v6）：单文件上限 —— v6 分块流式导入提升为 MAX_VAULT_FILE（1 TiB）；
        // v4/v5 保持 MAX_INMEM_BUFFER（Legacy 整段布局的内存固有限制）
        let legacy_session = self.format_version != VERSION_V6;
        let size_limit: u64 = if legacy_session {
            MAX_INMEM_BUFFER as u64
        } else {
            MAX_VAULT_FILE
        };

        // 2.7.0 修复（TOCTOU）：句柄化读取 —— 按元数据快照封顶读取总量，
        // 源文件中途膨胀不会触发无上界分配；v6 分块路径按快照大小**定长**读取，
        // 中途增长只会读到快照前缀，中途收缩 read_exact 失败拒绝（残留密文无害）。
        let src_file = open_import_source(src_path)?;
        let src_meta = src_file.metadata()?;
        if src_meta.len() > size_limit {
            return Err(VaultError::Other(format!(
                "文件过大（{} 字节），超过单次导入上限 {} 字节",
                src_meta.len(),
                size_limit
            )));
        }
        let size = src_meta.len();
        let name = src_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // 冻结导入时的 vpath 作为 AAD，此后重命名不再影响解密
        let frozen_aad = vpath.clone();

        // ── 3.0.0（v6）：分块流式导入 —— 恒定 4 MiB 明文缓冲，内存占用与文件大小无关 ──
        // 空文件走 Legacy（0 字节无分块收益，nonce+tag 纯开销）。
        let (offset, total_cipher_len, layout) = if !legacy_session && size > 0 {
            let chunk_size = CHUNK_SIZE_V6;
            let chunk_count = size.div_ceil(chunk_size);
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            let offset = file.seek(SeekFrom::End(0))?;
            let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
            // 3.0.0（优化1）：读/加密流水线 —— 后台线程预读下一块，
            // sync_channel(1) 有界通道限制在途 ≤ 2 块（约 8 MiB）；
            // 磁盘读取与加密/写盘重叠，AES-NI 下吞吐提升明显
            let (tx, rx) = std::sync::mpsc::sync_channel::<Result<Vec<u8>, std::io::Error>>(1);
            let src_ref = &src_file;
            // scope 返回写入的密文总长（内部错误经 `?` 传播）
            let written = std::thread::scope(|s| {
                s.spawn(move || {
                    let mut pos = 0u64;
                    loop {
                        if pos >= size {
                            break;
                        }
                        let n = std::cmp::min(chunk_size, size - pos) as usize;
                        let mut b = vec![0u8; n];
                        match (&*src_ref).read_exact(&mut b) {
                            Ok(()) => {
                                pos += n as u64;
                                // send 失败 = 主线程已退出（出错路径）：通道另一端
                                // 已断开，缓冲不可能被消费 —— 清零后丢弃
                                if tx.send(Ok(b)).is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                // 部分读取的 b 同样含源明文（L5：失败路径不留残留）
                                b.zeroize();
                                let _ = tx.send(Err(e));
                                break;
                            }
                        }
                    }
                });
                let mut written = 0u64;
                let mut done_plain = 0u64;
                for received in rx {
                    let mut plain = match received {
                        Ok(b) => b,
                        Err(e) => return Err(e.into()),
                    };
                    let i = done_plain.div_ceil(chunk_size);
                    let enc = encrypt_gcm(
                        enc_key,
                        &plain,
                        &chunk_aad(&frozen_aad, i, chunk_count),
                        None,
                    );
                    done_plain += plain.len() as u64;
                    plain.zeroize();
                    let enc = enc?;
                    file.write_all(&enc)?;
                    written += enc.len() as u64;
                    if let Some(cb) = chunk_progress {
                        cb(done_plain.min(size), size);
                    }
                }
                Ok::<u64, VaultError>(written)
            })?;
            if sync_each {
                file.flush()?;
                file.sync_all()?;
            }
            (
                offset,
                written,
                ChunkLayout::Chunked {
                    chunk_size,
                    chunk_count,
                },
            )
        } else {
            // ── Legacy 整段导入（v4/v5 会话；v6 的空文件）——与历史行为逐字节一致 ──
            let mut data = Vec::with_capacity(std::cmp::min(size as usize, MAX_INMEM_BUFFER));
            if let Err(e) = (&src_file)
                .take((MAX_INMEM_BUFFER as u64) + 1)
                .read_to_end(&mut data)
            {
                secure_wipe_vec(data); // 读到一半失败的明文也一并零化
                return Err(e.into());
            }
            drop(src_file);
            if data.len() > MAX_INMEM_BUFFER {
                secure_wipe_vec(data);
                return Err(VaultError::Other(format!(
                    "文件过大（读取时超过 {} 字节），超过单次导入上限",
                    MAX_INMEM_BUFFER
                )));
            }
            let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
            let encrypted = encrypt_gcm(enc_key, &data, frozen_aad.as_bytes(), None)?;
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            let offset = file.seek(SeekFrom::End(0))?;
            file.write_all(&encrypted)?;
            if sync_each {
                file.flush()?;
                file.sync_all()?;
            }
            let len = encrypted.len() as u64;
            secure_wipe_vec(data);
            (offset, len, ChunkLayout::Legacy)
        };
        let _ = layout.is_legacy(); // 布局信息已随条目落索引（仅消除 lint 歧义）

        // 直接更新内存索引（与 IndexManager::add_file 相同语义），
        // 由调用方统一 save_index
        index.files.insert(
            vpath.clone(),
            FileMeta {
                name,
                size,
                offset,
                length: total_cipher_len,
                aad_tag: Some(frozen_aad),
                layout,
            },
        );
        if let Some(pos) = vpath.rfind('/') {
            if pos > 0 {
                index.folders.insert(vpath[..pos].to_string(), true);
            }
        }
        Ok(())
    }

    /// 2.5.1 新增：原地更新文件内容（TXT 编辑保存路径）。
    ///
    /// 安全顺序与 secure_delete_file 一致：
    /// 1. 加密新内容追加到文件末尾；
    /// 2. 更新索引指向新密文位置并 save_index（先落盘）；
    /// 3. DoD 7-pass 覆写旧密文区段（失败时残留无害 —— 索引已指向新位置）。
    ///
    /// 任何时点崩溃，索引要么仍指向旧密文（内容未变），要么已指向新密文，
    /// 不会出现索引指向半损坏密文的永久损坏。
    pub fn update_file_content(&mut self, vpath: &str, data: &[u8]) -> Result<(), VaultError> {
        let vpath = Index::normalize_vpath(vpath)
            .filter(|p| Index::validate_vpath(p))
            .ok_or_else(|| VaultError::Other("无效的虚拟路径".into()))?;

        // 防御性上限（调用方 commands.rs 已按 64MB 预检，此处兜底）
        if data.len() > MAX_INMEM_BUFFER {
            return Err(VaultError::Other(format!(
                "内容过大（{} 字节），超过单次写入上限",
                data.len()
            )));
        }

        let mut index = self.load_index()?;
        let meta = index
            .files
            .get(&vpath)
            .ok_or_else(|| VaultError::Other("文件不存在".into()))?
            .clone();

        // 加密新内容：AAD 用导入时冻结的标识（旧索引回退到当前 vpath）。
        // 这里刻意不用当前 vpath —— 否则「重命名后再保存」会把 AAD 悄悄改成新路径，
        // 看起来自愈，实际是又一次把 AAD 绑回可变标识。
        let frozen_aad = meta.aad_tag.clone().unwrap_or_else(|| vpath.clone());
        // 3.0.0（v6）：v6 会话把新内容按分块布局写入（编辑上限 4 MB → 至多 1 块；
        // 空内容走 Legacy）——旧密文区段随后整体擦除，布局切换无兼容负担
        let (offset, total_cipher_len, new_layout) = if self.format_version == VERSION_V6 {
            let chunk_size = CHUNK_SIZE_V6;
            let size = data.len() as u64;
            if size == 0 {
                let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
                let encrypted = encrypt_gcm(enc_key, data, frozen_aad.as_bytes(), None)?;
                let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
                let offset = file.seek(SeekFrom::End(0))?;
                let len = encrypted.len() as u64;
                file.write_all(&encrypted)?;
                (offset, len, ChunkLayout::Legacy)
            } else {
                let chunk_count = size.div_ceil(chunk_size);
                let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
                let offset = file.seek(SeekFrom::End(0))?;
                let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
                let mut written = 0u64;
                for (i, chunk) in data.chunks(chunk_size as usize).enumerate() {
                    let enc = encrypt_gcm(
                        enc_key,
                        chunk,
                        &chunk_aad(&frozen_aad, i as u64, chunk_count),
                        None,
                    )?;
                    file.write_all(&enc)?;
                    written += enc.len() as u64;
                }
                (
                    offset,
                    written,
                    ChunkLayout::Chunked {
                        chunk_size,
                        chunk_count,
                    },
                )
            }
        } else {
            let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
            let encrypted = encrypt_gcm(enc_key, data, frozen_aad.as_bytes(), None)?;
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            let offset = file.seek(SeekFrom::End(0))?;
            let len = encrypted.len() as u64;
            file.write_all(&encrypted)?;
            (offset, len, ChunkLayout::Legacy)
        };
        {
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            file.flush()?;
            file.sync_all()?;
        }

        // 索引改指向新密文（保留原文件名）
        index.files.insert(
            vpath.clone(),
            FileMeta {
                name: meta.name,
                size: data.len() as u64,
                offset,
                length: total_cipher_len,
                // 沿用原有冻结标识（旧索引为 None），不因保存内容而重新绑定
                aad_tag: meta.aad_tag,
                layout: new_layout,
            },
        );

        self.log_event(&format!("更新文件内容 '{}'", vpath));
        self.save_index(index)?;

        // 索引已安全落盘，覆写旧密文（失败残留无害）
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = dod_overwrite_range(file, meta.offset, meta.length) {
                log::warn!("覆写旧密文失败（残留无害）: {}", e);
            }
            let _ = file.flush();
            let _ = file.sync_all();
        }
        Ok(())
    }

    /// 2.4.1 重写（P0-2）：文件夹导入改为两阶段 ——
    /// 阶段 1 纯文件系统遍历收集 (源路径, 目标虚拟路径)；
    /// 阶段 2 用**单份内存索引**逐文件加密追加，最后一次性 save_index。
    /// 旧实现每导入一个文件都 load_index ×2 + save_index 全量重写一次，
    /// 1000 个文件 ≈ 2000 次解密加载 + 1000 次全量索引写 + 7000+ 次 fsync。
    /// 返回 (成功数, 失败数, 跳过的符号链接数)。
    /// 2.8.2 修复两点：① 空目录（或全部内容都是符号链接）也会登记文件夹
    /// 条目 —— 旧实现静默丢弃，用户以为导入成功却什么都没有；② 符号链接
    /// 跳过数真实计入返回值（旧日志谎称「已计入失败计数」）。
    /// 3.0.0（优化1）：`file_progress`（第 done 个 / 共 total 个文件）。
    pub fn import_folder(
        &mut self,
        src: &Path,
        base: &str,
        file_progress: Option<&dyn Fn(usize, usize)>,
    ) -> Result<(usize, usize, usize), VaultError> {
        let source_meta = fs::symlink_metadata(src)?;
        if source_meta.file_type().is_symlink() || !source_meta.is_dir() {
            return Err(VaultError::Other("导入源必须是非链接目录".into()));
        }
        let base_name = src
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let base_clean = base.trim_end_matches('/');

        // 阶段 1：收集（无 self 借用，纯遍历；条目 = (源路径, 目标 vpath, is_dir)）
        let mut collected: Vec<(PathBuf, String, bool)> = Vec::new();
        let mut entries_seen = 0usize;
        let mut skipped_symlinks = 0usize;
        Self::collect_import_files(
            src,
            &format!("{}/{}", base_clean, base_name),
            0,
            &mut entries_seen,
            &mut collected,
            &mut skipped_symlinks,
        )?;

        // 阶段 2：单份索引逐文件导入，最后一次落盘
        let mut index = self.load_index()?;

        // 2.8.2：根文件夹条目先登记（空目录也要有）；若同名**文件**已存在
        // 则是命名空间碰撞，明确拒绝
        let root_vpath = Index::clean_vpath(&format!("{}/{}", base_clean, base_name))
            .ok_or_else(|| VaultError::Other("无效的目标路径".into()))?;
        if index.files.contains_key(&root_vpath) {
            return Err(VaultError::Other(format!(
                "目标路径已存在同名文件，无法导入为文件夹: {}",
                root_vpath
            )));
        }
        let root_folder_new = !index.folders.contains_key(&root_vpath);
        if root_folder_new {
            index.folders.insert(root_vpath, true);
        }

        if collected.is_empty() {
            // 空目录：仅登记文件夹本身
            self.log_event(&format!(
                "导入空文件夹 '{}'（含 0 个文件，跳过 {} 个符号链接）",
                base_name, skipped_symlinks
            ));
            self.save_index(index)?;
            return Ok((0, 0, skipped_symlinks));
        }

        let mut ok = 0usize;
        let mut fail = 0usize;
        let mut errors: Vec<String> = Vec::new();
        // 3.0.0（L-6）：目录条目先登记（含空子目录；已有同名文件则命名空间碰撞拒绝）
        for (_src_path, dest_vpath, is_dir) in collected.iter() {
            if *is_dir {
                if index.files.contains_key(dest_vpath) {
                    return Err(VaultError::Other(format!(
                        "目标路径已存在同名文件，无法导入为文件夹: {}",
                        dest_vpath
                    )));
                }
                index.folders.entry(dest_vpath.clone()).or_insert(true);
            }
        }
        let total_files = collected.iter().filter(|(_, _, d)| !*d).count();
        let mut done_files = 0usize;
        for (src_path, dest_vpath, is_dir) in collected {
            if is_dir {
                continue; // 目录条目已在上方登记
            }
            match self.import_file_into_index(&mut index, &src_path, &dest_vpath, false, None) {
                Ok(()) => ok += 1,
                Err(e) => {
                    fail += 1;
                    errors.push(format!(
                        "{}: {}",
                        dest_vpath.rsplit('/').next().unwrap_or(""),
                        e
                    ));
                    // 2.8.1：不再把含 vpath 的错误写入明文日志（违反 2.6.1 自定规则），
                    // 失败明细经返回值反馈给前端逐项展示
                    log::warn!("批量导入有失败项（明细已随返回值反馈）");
                }
            }
            done_files += 1;
            if let Some(cb) = file_progress {
                cb(done_files, total_files);
            }
        }
        self.log_event(&format!(
            "导入文件夹 '{}'：成功 {} 个文件，失败 {} 个，跳过 {} 个符号链接",
            base_name, ok, fail, skipped_symlinks
        ));
        // 2.8.2：失败但根文件夹是新登记时也要落盘（保持「文件夹已导入」语义）
        if ok > 0 || root_folder_new {
            if ok > 0 {
                let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
                file.flush()?;
                file.sync_all()?;
            }
            self.save_index(index)?;
        }
        Ok((ok, fail, skipped_symlinks))
    }

    /// 2.4.1 新增：递归收集待导入文件（原 walk_import 的遍历部分，去掉了 self 依赖）。
    /// 2.8.2：`skipped_symlinks` 真实统计跳过的符号链接数。
    /// 3.0.0（L-6）：条目带 is_dir 标记 —— 目录也登记（空子目录不再丢失）。
    fn collect_import_files(
        current: &Path,
        dest_root: &str,
        depth: usize,
        entries_seen: &mut usize,
        out: &mut Vec<(PathBuf, String, bool)>,
        skipped_symlinks: &mut usize,
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
                *skipped_symlinks += 1;
                log::warn!("跳过符号链接（未计入失败项，已随返回值反馈）");
                continue;
            }
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let dest_path = format!("{}/{}", dest_root, name);
            if meta.is_dir() {
                // 3.0.0（L-6 审计修复）：子目录也登记为文件夹条目 —— 旧实现只递归
                // 不登记，子目录里的文件会经 import_file_into_index 自动补父目录，
                // 但**空的子目录**被静默丢弃（2.8.2 只修了「空根目录」这一层，
                // 与其注释「空目录也要有」的意图不一致）
                out.push((path.clone(), dest_path.clone(), true));
                Self::collect_import_files(
                    &path,
                    &dest_path,
                    depth + 1,
                    entries_seen,
                    out,
                    skipped_symlinks,
                )?;
            } else if meta.is_file() {
                out.push((path, dest_path, false));
            }
        }
        Ok(())
    }
}
