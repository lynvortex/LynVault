//! 文件读取与提取 —— 单文件 / 批量 / 全部提取、内存加载。
//! 3.0.0：Chunked 布局分块流式提取（恒定内存）；Legacy 行为不变。
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::VaultError;
use crate::index::ChunkLayout;
use crate::wipe::secure_wipe_vec;

use super::consts::*;
use super::fs_util::*;

use super::Vault;

/// 3.0.0：提取目标的元数据快照（vpath, rel_dir, 文件名, offset, length, 冻结 AAD, 布局）
type ExtractTarget = (
    String,
    String,
    String,
    u64,
    u64,
    u64,
    Option<String>,
    ChunkLayout,
);

impl Vault {
    /// 2.4.1 新增（P1-12）：批量提取前的目标根目录准备（创建 + 规范化，只做一次）。
    /// 旧实现在 extract_file_inner 里对**每个文件**做 canonicalize，
    /// 批量提取 1000 个文件 = 2000 次冗余系统调用。
    fn prepare_dest_root(dest_folder: &Path) -> Result<PathBuf, VaultError> {
        fs::create_dir_all(dest_folder)?;
        fs::canonicalize(dest_folder).map_err(|_| VaultError::Other("目标目录无法访问".into()))
    }

    /// 提取单个文件。2.4.1：`overwrite` 参数显式控制覆盖语义
    /// （true = 覆盖已存在文件；false = 拒绝并报错，与旧行为一致）。
    ///
    /// 2.5.1 变更：单文件提取**直接放入目标目录**，不再重建其在保险柜内的
    /// 上级目录结构 —— 旧行为提取 /docs/readme.txt 到 D:\out 会生成
    /// D:\out\docs\readme.txt，只提取一个文件也要套一层同名文件夹；
    /// 现在结果为 D:\out\readme.txt。多选批量提取与「提取全部」仍保留完整
    /// 目录结构（避免不同子目录的同名文件在目标根冲突）。
    pub fn extract_file(
        &mut self,
        vpath: &str,
        dest_folder: &Path,
        overwrite: bool,
    ) -> Result<(), VaultError> {
        // 单次 load_index：获取文件名、密文位置、冻结的 AAD 标识与块布局
        let (file_name, offset, length, aad_tag, layout) = {
            let index = self.load_index()?;
            let meta = index
                .files
                .get(vpath)
                .ok_or_else(|| VaultError::Other("文件不存在".into()))?;
            (
                meta.name.clone(),
                meta.offset,
                meta.length,
                meta.aad_tag.clone(),
                meta.layout.clone(),
            )
        };
        let dest_abs = Self::prepare_dest_root(dest_folder)?;
        let aad = aad_bytes(aad_tag.as_deref(), vpath);
        // 委托给内部实现（rel_dir 传空 = 直接放入目标目录，见上方 2.5.1 说明）
        self.extract_file_inner(
            vpath, "", &file_name, offset, length, aad, &layout, &dest_abs, overwrite, None,
        )?;
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
    /// - 成功审计移至调用方（P1-14）；
    /// - `aad` 由调用方用 `aad_bytes` 求值后传入（优先索引里冻结的 aad_tag），
    ///   不能再拿 vpath 现算 —— vpath 可能已被重命名。
    #[allow(clippy::too_many_arguments)] // 2.8.1：历史稳定内部 API，拆参数结构收益为负
    #[allow(clippy::too_many_arguments)]
    fn extract_file_inner(
        &mut self,
        vpath: &str,
        rel_dir: &str,
        file_name: &str,
        offset: u64,
        length: u64,
        aad: &[u8],
        layout: &ChunkLayout,
        dest_abs: &Path,
        overwrite: bool,
        chunk_progress: Option<&dyn Fn(u64, u64)>,
    ) -> Result<(), VaultError> {
        let safe_name = sanitize_filename(file_name);

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
            if !path_within(&abs, dest_abs) {
                return Err(VaultError::Other("输出目录包含符号链接".into()));
            }
            abs
        } else {
            output_dir
        };

        let dest_path = output_dir_abs.join(&safe_name);

        // 路径遍历防护：验证最终路径在目标目录下
        if !path_within(&dest_path, dest_abs) {
            self.log_event(&format!("拦截路径遍历攻击: '{}'", vpath));
            return Err(VaultError::Other("路径遍历攻击已拦截".into()));
        }

        // C8 修复（强化）：使用 O_NOFOLLOW 打开目标文件，防止 TOCTOU 符号链接竞态。
        // 旧实现在 Windows 上仅检查-再-write，存在时间窗口。
        // 现在两端都使用 NO_FOLLOW 等价标志打开。
        // 2.4.1（P0-5）：overwrite=true 时用 create+truncate（仍带 NO_FOLLOW），
        // 让「提取全部」的覆盖确认框名副其实。
        // 2.8.2：删除「写入后验证仍是普通文件」的不实注释 —— 实现从未做该验证，
        // 防护依赖打开标志本身（重解析点在打开时即被拒绝或以本体形式打开）。
        // 3.0.0：Legacy 先解密后打开（解密失败不残留目标文件，与历史一致）；
        // Chunked 打开后分块流式写入（恒定内存；中途解密失败会留下部分写入的
        // 目标文件 —— 与磁盘满等写失败的既有语义一致）。
        #[cfg(unix)]
        fn open_dest(dest_path: &Path, overwrite: bool) -> std::io::Result<std::fs::File> {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = OpenOptions::new();
            opts.write(true).custom_flags(libc::O_NOFOLLOW);
            if overwrite {
                opts.create(true).truncate(true);
            } else {
                opts.create_new(true);
            }
            opts.open(dest_path)
        }
        #[cfg(not(unix))]
        fn open_dest(dest_path: &Path, overwrite: bool) -> std::io::Result<std::fs::File> {
            // FILE_FLAG_OPEN_REPARSE_POINT prevents following a final reparse point.
            use std::os::windows::fs::OpenOptionsExt;
            let mut opts = OpenOptions::new();
            opts.write(true).custom_flags(0x00200000 | 0x08000000);
            if overwrite {
                opts.create(true).truncate(true);
            } else {
                opts.create_new(true);
            }
            opts.open(dest_path)
        }

        if matches!(layout, ChunkLayout::Legacy) {
            // ── Legacy：整段解密 → 写入（与历史行为逐字节一致）──
            let data = {
                let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
                let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
                read_decrypt_file_data(file, enc_key, offset, length, aad)?
            };
            let mut f = open_dest(&dest_path, overwrite).map_err(|_| {
                VaultError::Other("目标文件已存在或路径异常（重解析点/符号链接？）".into())
            })?;
            f.write_all(&data)?;
            f.sync_all()?;
            drop(f);
            secure_wipe_vec(data);
            Ok(())
        } else {
            // ── Chunked（v6）：分块流式提取 —— 明文任何时刻至多 4 MiB 在内存 ──
            let (chunk_size, chunk_count) = match layout {
                ChunkLayout::Chunked {
                    chunk_size,
                    chunk_count,
                } => (*chunk_size, *chunk_count),
                _ => unreachable!(),
            };
            let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
            let mut f = open_dest(&dest_path, overwrite).map_err(|_| {
                VaultError::Other("目标文件已存在或路径异常（重解析点/符号链接？）".into())
            })?;
            // L7：同 Legacy 分支 —— 打开后回验中间目录未被替换为 junction
            let recheck = fs::canonicalize(&dest_path)
                .map_err(|_| VaultError::Other("目标路径无法解析".into()))?;
            if !path_within(&recheck, dest_abs) {
                return Err(VaultError::Other("输出目录包含符号链接".into()));
            }
            let result = stream_decrypt_to_writer(
                file,
                self.enc_key.as_ref().ok_or(VaultError::NotOpen)?,
                offset,
                length,
                chunk_size,
                chunk_count,
                std::str::from_utf8(aad)
                    .map_err(|_| VaultError::Other("冻结 AAD 标识非 UTF-8".into()))?,
                &mut f,
                chunk_progress,
            );
            match result {
                Ok(()) => {
                    f.sync_all()?;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }

    // ═══════════════ 文件读取 ═══════════════

    /// 3.0.0（优化2）：媒体流式预览的文件信息 —— (明文大小, 是否分块布局)。
    /// 仅 Chunked 布局支持流式（分块独立解密 = 随机访问）；Legacy 整段布局
    /// 维持「提取后查看」。
    pub fn media_file_info(&self, vpath: &str) -> Result<(u64, bool), VaultError> {
        let index = self.cached_index.as_ref().ok_or(VaultError::NotOpen)?;
        let meta = index
            .files
            .get(vpath)
            .ok_or_else(|| VaultError::Other("文件不存在".into()))?;
        let streamable = matches!(meta.layout, ChunkLayout::Chunked { .. }) && meta.size > 0;
        Ok((meta.size, streamable))
    }

    /// 3.0.0（优化2）：媒体流式预览的字节区间读取 —— 解密覆盖 [start, end)
    /// 的若干块并拼接切片，明文内存占用 = 请求窗口大小（调用方封顶）。
    /// 仅 Chunked 布局；块密文位置 = 数据区起点 + 块序号 × (块大小 + 28)
    ///（非末块定长，AAD 绑定块序号防重排）。
    pub fn read_media_range(
        &mut self,
        vpath: &str,
        start: u64,
        end_excl: u64,
    ) -> Result<Vec<u8>, VaultError> {
        use crate::crypto::{chunk_aad, decrypt_into};
        use std::io::{Read, Seek, SeekFrom};
        use zeroize::Zeroize;

        let (offset, aad_tag, layout, size, length) = {
            let index = self.cached_index.as_ref().ok_or(VaultError::NotOpen)?;
            let meta = index
                .files
                .get(vpath)
                .ok_or_else(|| VaultError::Other("文件不存在".into()))?;
            (
                meta.offset,
                meta.aad_tag.clone(),
                meta.layout.clone(),
                meta.size,
                meta.length,
            )
        };
        let (chunk_size, chunk_count) = match layout {
            ChunkLayout::Chunked {
                chunk_size,
                chunk_count,
            } => (chunk_size, chunk_count),
            ChunkLayout::Legacy => {
                return Err(VaultError::Other(
                    "旧版整段布局不支持流式预览，请提取后查看".into(),
                ))
            }
        };
        // 边界与窗口上限（双保险：协议层也已限制）
        const MAX_WINDOW: u64 = 64 * 1024 * 1024;
        if start >= size || end_excl <= start {
            return Err(VaultError::Other("请求区间越界".into()));
        }
        let end = end_excl.min(size);
        if end - start > MAX_WINDOW {
            return Err(VaultError::Other("单次请求窗口过大".into()));
        }

        // 3.0.1（F3）：统一布局解析（chunk_size 上限 + 末块校验 + 全 checked）
        let plan = resolve_chunk_plan(length, chunk_size, chunk_count)?;

        let first = start / plan.chunk_size;
        let last = (end - 1) / plan.chunk_size;
        if last >= plan.chunk_count {
            return Err(VaultError::Other("请求区间越界".into()));
        }
        let frozen = aad_tag.unwrap_or_else(|| vpath.to_string());
        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;

        let mut out = Vec::with_capacity((end - start) as usize);
        // 3.0.1（F4）：偏移算术全 checked —— 旧实现 `offset + first * full_ct`
        // 未检查，溢出在 release（overflow-checks=true）下 panic
        let mut pos = offset
            .checked_add(
                first
                    .checked_mul(plan.full_ct)
                    .ok_or_else(|| VaultError::Other("媒体区间算术溢出".into()))?,
            )
            .ok_or_else(|| VaultError::Other("媒体区间算术溢出".into()))?;
        for i in first..=last {
            let ct_len = plan.ct_len(i);
            file.seek(SeekFrom::Start(pos))?;
            let mut enc = vec![0u8; ct_len as usize];
            file.read_exact(&mut enc)?;
            let mut plain = decrypt_into(enc_key, enc, &chunk_aad(&frozen, i, plan.chunk_count))
                .ok_or(VaultError::DecryptFailed)?;
            // 本块明文区间 [i*cs, i*cs+plain_n) 与请求区间 [start, end) 的交集。
            // 3.0.1（F4）：切片前显式 sanity —— 旧实现索引谎报 size 时
            // `lo > hi` 直接 `panic: slice index starts at ... but ends at ...`
            //（普通切片越界不受 overflow-checks 保护，每请求一次 DoS）
            let chunk_plain_lo = i
                .checked_mul(plan.chunk_size)
                .ok_or_else(|| VaultError::Other("媒体区间算术溢出".into()))?;
            let lo = start.saturating_sub(chunk_plain_lo);
            let hi = end.saturating_sub(chunk_plain_lo).min(plan.plain_len(i));
            if lo > hi || hi as usize > plain.len() {
                return Err(VaultError::Other(
                    "媒体区间与分块布局不一致（索引可能被篡改）".into(),
                ));
            }
            out.extend_from_slice(&plain[lo as usize..hi as usize]);
            plain.zeroize();
            pos = pos
                .checked_add(ct_len)
                .ok_or_else(|| VaultError::Other("媒体区间算术溢出".into()))?;
        }
        Ok(out)
    }

    pub fn load_file_data(&mut self, vpath: &str) -> Result<Vec<u8>, VaultError> {
        let (offset, length, aad_tag, layout) = {
            let index = self.load_index()?;
            let meta = index
                .files
                .get(vpath)
                .ok_or_else(|| VaultError::Other("文件不存在".into()))?;
            (
                meta.offset,
                meta.length,
                meta.aad_tag.clone(),
                meta.layout.clone(),
            )
        };
        // M1 修复：超大文件拒绝全量加载（避免 OOM + Tauri IPC 膨胀）
        // 2.8.2：改用 u64 比较 —— 旧写法 `length as usize` 在 32 位目标上会
        // 回绕（大 u64 变小 usize）使该检查失效（真正的防线在
        // read_decrypt_file_data 内，这里属于纵深防御，因此修正而非删除）
        if length > MAX_INMEM_BUFFER as u64 {
            return Err(VaultError::Other(format!(
                "文件过大（{} 字节），超过单次加载上限 {} 字节，请使用提取功能导出后查看",
                length, MAX_INMEM_BUFFER
            )));
        }
        let file = self.file.as_mut().ok_or(VaultError::NotOpen)?;
        let enc_key = self.enc_key.as_ref().ok_or(VaultError::NotOpen)?;
        read_decrypt_file_data_layout(
            file,
            enc_key,
            offset,
            length,
            aad_tag.as_deref(),
            vpath,
            &layout,
        )
    }

    /// 提取保险柜内所有文件到指定目录，保留 vpath 目录结构。
    /// R3 修复：真正单次 load_index，循环调用 extract_file_inner（不再重复 load）。
    /// 2.4.1 变更：目标目录只校验/规范化一次（P1-12）；新增 overwrite 参数（P0-5，
    /// 由前端确认框传入 —— 旧实现确认「覆盖」后实际用 create_new 拒绝覆盖，大批失败）。
    /// 返回 (成功数, 失败数, 失败明细)。
    /// 3.0.0（优化1）：`file_progress`（第 done 个 / 共 total 个文件）与
    /// `chunk_progress`（累计已解密字节 / 总字节，跨文件累计）。
    pub fn extract_all_files(
        &mut self,
        dest_folder: &Path,
        overwrite: bool,
        file_progress: Option<&dyn Fn(usize, usize)>,
        chunk_progress: Option<&dyn Fn(u64, u64)>,
    ) -> Result<(usize, usize, Vec<String>), VaultError> {
        let dest_abs = Self::prepare_dest_root(dest_folder)?;
        // 单次 load_index，收集所有文件的元数据
        let file_infos: Vec<ExtractTarget> = {
            let index = self.index_ref()?;
            index
                .files
                .iter()
                .map(|(vpath, meta)| {
                    let vpath_trimmed = vpath.trim_matches('/');
                    let rel_dir = match vpath_trimmed.rfind('/') {
                        Some(pos) => vpath_trimmed[..pos].to_string(),
                        None => "".to_string(),
                    };
                    (
                        vpath.clone(),
                        rel_dir,
                        meta.name.clone(),
                        meta.offset,
                        meta.length,
                        meta.size,
                        meta.aad_tag.clone(),
                        meta.layout.clone(),
                    )
                })
                .collect()
        };
        // 3.0.1（F5）：累计改 checked —— 旧 `sum()` 在 overflow-checks 下遇
        // u64 溢出必然 panic（两条 size = u64::MAX/2+1 的索引条目即可在提取
        // 开始前炸掉进程）；索引交叉校验（Index::validate）落地后正常文件
        // 不会到这里溢出，本检查属于纵深防御。
        let total_bytes: u64 = file_infos
            .iter()
            .map(|f| f.5)
            .try_fold(0u64, |acc, s| acc.checked_add(s))
            .ok_or_else(|| VaultError::Other("文件总大小累计溢出（索引可能被篡改）".into()))?;
        let mut done_bytes: u64 = 0;
        let mut ok = 0usize;
        let mut fail = 0usize;
        let mut errors: Vec<String> = Vec::new();
        let mut done_files = 0usize;
        for (vpath, rel_dir, file_name, offset, length, size, aad_tag, layout) in &file_infos {
            let aad = aad_bytes(aad_tag.as_deref(), vpath);
            // 分块进度换算为跨文件累计：闭包捕获本文件的完成字节基数
            let wrapped;
            let per_file: Option<&dyn Fn(u64, u64)> = match (chunk_progress, layout) {
                (Some(outer), ChunkLayout::Chunked { .. }) if *size > 0 => {
                    let base = done_bytes;
                    let total = total_bytes;
                    wrapped = move |done: u64, _total: u64| outer(base.saturating_add(done), total);
                    Some(&wrapped)
                }
                _ => None,
            };
            match self.extract_file_inner(
                vpath, rel_dir, file_name, *offset, *length, aad, layout, &dest_abs, overwrite,
                per_file,
            ) {
                Ok(_) => {
                    done_bytes = done_bytes.saturating_add(*size);
                    ok += 1;
                }
                Err(e) => {
                    fail += 1;
                    errors.push(format!("{}: {}", vpath, e));
                    // 2.8.1：错误串含 vpath，不再落明文日志（明细经返回值反馈前端）
                    log::warn!("提取全部有失败项（明细已随返回值反馈）");
                }
            }
            done_files += 1;
            if let Some(cb) = file_progress {
                cb(done_files, file_infos.len());
            }
        }
        // 2.8.1：审计串不再携带真实文件系统路径（抗取证：审计在加密索引内，
        // 但备份/内存转储场景下目的路径属于用户敏感信息）
        self.log_event(&format!("提取全部文件（成功 {}，失败 {}）", ok, fail));
        Ok((ok, fail, errors))
    }

    /// 批量提取指定文件/文件夹到目标目录（单次 load_index，避免 O(n²) 重复加载）。
    /// 文件夹自动展开为其下所有文件；返回 (成功数, 失败数, 失败明细)。
    /// 2.3.0 修复：`extract_files` 命令原先对每个文件重复 load_index，大数据量下退化 O(n²)。
    /// 2.4.1：目标目录只校验一次（P1-12）+ 摘要审计（P1-14）。
    /// 3.0.0（优化1）：回调语义同 extract_all_files。
    pub fn extract_files_batch(
        &mut self,
        vpaths: &[String],
        dest_folder: &Path,
        file_progress: Option<&dyn Fn(usize, usize)>,
        chunk_progress: Option<&dyn Fn(u64, u64)>,
    ) -> Result<(usize, usize, Vec<String>), VaultError> {
        let dest_abs = Self::prepare_dest_root(dest_folder)?;
        let targets: Vec<ExtractTarget> = {
            let index = self.index_ref()?;
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut targets: Vec<ExtractTarget> = Vec::new();
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
                        targets.push((
                            vp_norm.to_string(),
                            rel_dir,
                            m.name.clone(),
                            m.offset,
                            m.length,
                            m.size,
                            m.aad_tag.clone(),
                            m.layout.clone(),
                        ));
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
                            targets.push((
                                fv.clone(),
                                rel_dir,
                                m.name.clone(),
                                m.offset,
                                m.length,
                                m.size,
                                m.aad_tag.clone(),
                                m.layout.clone(),
                            ));
                        }
                    }
                }
            }
            targets
        };

        let mut ok = 0usize;
        let mut fail = 0usize;
        let mut errors: Vec<String> = Vec::new();
        // 3.0.1（F5）：同 extract_all_files —— 累计改 checked，杜绝 panic
        let total_bytes: u64 = targets
            .iter()
            .map(|t| t.5)
            .try_fold(0u64, |acc, s| acc.checked_add(s))
            .ok_or_else(|| VaultError::Other("文件总大小累计溢出（索引可能被篡改）".into()))?;
        let mut done_bytes: u64 = 0;
        let mut done_files = 0usize;
        for (vpath, rel_dir, file_name, offset, length, size, aad_tag, layout) in &targets {
            let aad = aad_bytes(aad_tag.as_deref(), vpath);
            let wrapped;
            let per_file: Option<&dyn Fn(u64, u64)> = match (chunk_progress, layout) {
                (Some(outer), ChunkLayout::Chunked { .. }) if *size > 0 => {
                    let base = done_bytes;
                    let total = total_bytes;
                    wrapped = move |done: u64, _total: u64| outer(base.saturating_add(done), total);
                    Some(&wrapped)
                }
                _ => None,
            };
            // 批量提取保持「拒绝覆盖」的安全默认；需要覆盖语义时走提取全部（P0-5）
            match self.extract_file_inner(
                vpath, rel_dir, file_name, *offset, *length, aad, layout, &dest_abs, false,
                per_file,
            ) {
                Ok(_) => {
                    done_bytes = done_bytes.saturating_add(*size);
                    ok += 1;
                }
                Err(e) => {
                    fail += 1;
                    errors.push(format!("{}: {}", vpath, e));
                    log::warn!("批量提取有失败项（明细已随返回值反馈）");
                }
            }
            done_files += 1;
            if let Some(cb) = file_progress {
                cb(done_files, targets.len());
            }
        }
        self.log_event(&format!("批量提取：成功 {} 个文件，失败 {} 个", ok, fail));
        Ok((ok, fail, errors))
    }
}

/// 3.0.0（v6）：分块流式解密到任意写入器 —— 逐块「读取密文 → 解密 → 写出」，
/// 明文任何时刻至多一块（CHUNK_SIZE_V6）在内存。长度一致性校验统一走
/// `resolve_chunk_plan`（3.0.1 F3：含 chunk_size 上限）。
#[allow(clippy::too_many_arguments)]
fn stream_decrypt_to_writer<W: std::io::Write>(
    file: &mut std::fs::File,
    enc_key: &[u8; 32],
    offset: u64,
    length: u64,
    chunk_size: u64,
    chunk_count: u64,
    frozen: &str,
    writer: &mut W,
    chunk_progress: Option<&dyn Fn(u64, u64)>,
) -> Result<(), VaultError> {
    use std::io::{Read, Seek, SeekFrom};

    use crate::crypto::decrypt_into;
    use zeroize::Zeroize;

    // 3.0.1（F3）：统一布局解析 —— chunk_size 上限 / 末块校验 / 全 checked。
    // 旧实现唯一检查是「非零」，chunk_count=1 时 2^40 的块尺寸直达
    // vec![0u8; N] → alloc-abort 整个进程。
    let plan = resolve_chunk_plan(length, chunk_size, chunk_count)?;
    offset
        .checked_add(length)
        .ok_or_else(|| VaultError::Other("分块密文范围溢出（索引可能被篡改）".into()))?;

    // 3.0.0（优化1）：读/解密流水线 —— 后台线程预读下一块密文
    //（密文非敏感，无需零化；sync_channel(1) 限制在途 ≤ 2 块）
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(usize, Vec<u8>), std::io::Error>>(1);
    let file_ref = &file;
    std::thread::scope(|s| {
        s.spawn(move || {
            let mut pos = offset;
            for i in 0..plan.chunk_count {
                let ct_len = plan.ct_len(i);
                let mut enc = vec![0u8; ct_len as usize];
                // &File 同样实现 Read/Seek —— 与会话句柄共享游标但受互斥锁保护，
                // 读线程独占本请求期间的位置语义
                let mut rf = &**file_ref;
                if let Err(e) = rf
                    .seek(SeekFrom::Start(pos))
                    .and_then(|_| rf.read_exact(&mut enc))
                {
                    let _ = tx.send(Err(e));
                    return;
                }
                pos = match pos.checked_add(ct_len) {
                    Some(p) => p,
                    None => {
                        let _ = tx.send(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "分块密文位置溢出",
                        )));
                        return;
                    }
                };
                if tx.send(Ok((i as usize, enc))).is_err() {
                    return; // 主线程已退出
                }
            }
        });
        let mut done: u64 = 0;
        let total: u64 = plan.plaintext_total();
        for received in rx {
            let (i, enc) = match received {
                Ok(v) => v,
                Err(e) => return Err(e.into()),
            };
            let mut plain = decrypt_into(
                enc_key,
                enc,
                &crate::crypto::chunk_aad(frozen, i as u64, plan.chunk_count),
            )
            .ok_or(VaultError::DecryptFailed)?;
            writer.write_all(&plain)?;
            done = done.saturating_add(plain.len() as u64);
            plain.zeroize();
            if let Some(cb) = chunk_progress {
                cb(done.min(total), total);
            }
        }
        Ok::<(), VaultError>(())
    })
}
