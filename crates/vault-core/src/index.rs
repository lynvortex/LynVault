use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use crate::audit::AuditEntry;
use crate::VaultError;

/// 文件元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    pub name: String,
    pub size: u64,
    pub offset: u64,
    pub length: u64,
    /// 导入时冻结的 AAD 标识。
    ///
    /// 文件密文的 AAD 原先直接绑定 vpath，而 vpath 是可变的 —— 一旦重命名，
    /// 索引 key 变了但密文没重加密，GCM 认证随即失败（内容永久不可读）。
    /// 现在改为：导入时把当时的 vpath 冻结在这里，此后读写一律以它为准，
    /// 重命名只改索引 key、不再影响 AAD。
    ///
    /// 旧索引没有该字段 → `None`，读取时回退到当前 vpath（与历史行为一致）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad_tag: Option<String>,
}

/// 索引结构（序列化为 JSON 后加密存储）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub files: HashMap<String, FileMeta>,     // vpath -> meta
    pub folders: HashMap<String, bool>,       // vpath -> true
    pub audit: Vec<AuditEntry>,
}

impl Index {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            folders: HashMap::new(),
            audit: Vec::new(),
        }
    }

    /// 验证虚拟路径是否安全。
    ///
    /// 规则（M5 修复）：
    /// - 必须以 '/' 开头
    /// - 禁止 '..' 段（防止路径遍历）
    /// - 禁止反斜杠
    /// - 禁止空字节 / 控制字符
    /// - 不允许连续 '/'，不允许以 '/' 结尾（根 '/' 除外）
    /// - 每段不允许为空
    pub fn validate_vpath(vpath: &str) -> bool {
        if !vpath.starts_with('/') {
            return false;
        }
        if vpath == "/" {
            return true;
        }
        if vpath.contains('\\') || vpath.contains('\0') {
            return false;
        }
        if vpath.ends_with('/') {
            return false;
        }
        // 拆段检查。注意："/foo".split('/') 会产生 ["", "foo"]，
        // 第一个空段来自开头的 '/'，必须跳过。
        for seg in vpath.split('/').skip(1) {
            if seg.is_empty() {
                // 连续 '/' 产生空段
                return false;
            }
            if seg == "." || seg == ".." {
                return false;
            }
            // 禁止控制字符
            if seg.chars().any(|c| (c as u32) < 0x20) {
                return false;
            }
        }
        true
    }

    /// 归一化虚拟路径：去掉多余的 '/'、结尾 '/'、'.' 段。
    /// 不允许 '..' 段：**越过根的 '..'（如 "/../a"）直接返回 None 而非静默
    /// 重定向到根内路径**（2.8.2 收紧 —— 旧行为把遍历尝试悄悄变成合法路径，
    /// 语义出人意料；段内的 ".."（如 "/foo/../bar"）仍正常折叠）。
    pub fn normalize_vpath(vpath: &str) -> Option<String> {
        if vpath.contains('\\') || vpath.contains('\0') {
            return None;
        }
        let mut parts: Vec<&str> = Vec::new();
        for seg in vpath.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                // 不允许跳出根：越界即拒绝（2.8.2 收紧）
                if parts.pop().is_none() {
                    return None;
                }
                continue;
            }
            if seg.chars().any(|c| (c as u32) < 0x20) {
                return None;
            }
            parts.push(seg);
        }
        if parts.is_empty() {
            return Some("/".to_string());
        }
        Some(format!("/{}", parts.join("/")))
    }

    /// 2.8.2：归一化 + 校验一步完成（vault.rs 各入口的
    /// `normalize_vpath(..).filter(validate_vpath)` 组合的单一来源）。
    pub fn clean_vpath(vpath: &str) -> Option<String> {
        Self::normalize_vpath(vpath).filter(|p| Self::validate_vpath(p))
    }
}

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

/// 索引管理器（提供便捷的增删改查方法，内部调用 Vault 的 load/save）
pub struct IndexManager<'a> {
    vault: &'a mut crate::Vault,
}

impl<'a> IndexManager<'a> {
    pub fn new(vault: &'a mut crate::Vault) -> Self {
        Self { vault }
    }

    pub fn add_file(&mut self, vpath: &str, name: &str, size: u64, offset: u64, length: u64) -> Result<(), VaultError> {
        let vpath = Index::normalize_vpath(vpath)
            .filter(|p| Index::validate_vpath(p))
            .ok_or_else(|| VaultError::Other("无效的虚拟路径".into()))?;
        let mut index = self.vault.load_index()?;
        // C5 修复：重名直接覆盖会丢失旧文件元数据（其密文残留无法清理）。
        // 改为冲突时报错，让调用方决定是覆盖、重命名还是取消。
        // 2.8.1：同时检查文件夹命名空间 —— file/folder 同名碰撞会让
        // rename/delete/move 语义含混（两套删除实现对同一 vpath 行为不同）。
        if index.files.contains_key(&vpath) {
            return Err(VaultError::Other(format!("目标路径已存在: {}", vpath)));
        }
        if index.folders.contains_key(&vpath) {
            return Err(VaultError::Other(format!(
                "目标路径已存在同名文件夹，无法创建为文件: {}", vpath
            )));
        }
        index.files.insert(vpath.clone(), FileMeta {
            name: name.into(),
            size,
            offset,
            length,
            // 约定：调用方加密文件数据时以 vpath 为 AAD（见 read_decrypt_file_data 文档），
            // 此处把该 vpath 冻结下来，此后重命名不会再影响解密
            aad_tag: Some(vpath.clone()),
        });
        // 自动创建父文件夹
        if let Some(parent) = vpath.rfind('/') {
            if parent > 0 {
                let parent = &vpath[..parent];
                index.folders.insert(parent.into(), true);
            }
        }
        self.vault.log_event(&format!("添加文件 '{}'", vpath));
        self.vault.save_index(index)?;
        Ok(())
    }

    pub fn remove_file(&mut self, vpath: &str) -> Result<(), VaultError> {
        let mut index = self.vault.load_index()?;
        if let Some(meta) = index.files.remove(vpath) {
            let (off, len) = (meta.offset, meta.length);
            self.vault.log_event(&format!("删除文件 '{}'", vpath));
            self.vault.save_index(index)?;
            // 2.8.2：与 secure_delete_file 同一安全顺序 —— 索引落盘后再 DoD
            // 覆写密文。旧实现只动索引不擦密文，库级调用方会拿到一套
            // 「不擦除的删除」语义（与命令层的宣传承诺不一致）。
            if let Some(file) = self.vault.file.as_mut() {
                if let Err(e) = crate::wipe::dod_overwrite_range(file, off, len) {
                    log::warn!("覆写密文失败（残留无害）: {}", e);
                }
                let _ = file.flush();
                let _ = file.sync_all();
            }
        }
        Ok(())
    }

    pub fn add_folder(&mut self, vpath: &str) -> Result<(), VaultError> {
        let vpath = Index::normalize_vpath(vpath)
            .filter(|p| Index::validate_vpath(p))
            .ok_or_else(|| VaultError::Other("无效的虚拟路径".into()))?;
        if vpath == "/" {
            return Err(VaultError::Other("不能创建根目录".into()));
        }
        let mut index = self.vault.load_index()?;
        if index.folders.contains_key(&vpath) {
            return Err(VaultError::Other(format!("文件夹已存在: {}", vpath)));
        }
        // 2.8.1：交叉命名空间碰撞防护（同 add_file）
        if index.files.contains_key(&vpath) {
            return Err(VaultError::Other(format!(
                "目标路径已存在同名文件，无法创建为文件夹: {}", vpath
            )));
        }
        index.folders.insert(vpath.clone(), true);
        self.vault.log_event(&format!("创建文件夹 '{}'", vpath));
        self.vault.save_index(index)?;
        Ok(())
    }

    pub fn remove_folder(&mut self, vpath: &str) -> Result<(), VaultError> {
        let mut index = self.vault.load_index()?;
        // 删除文件夹及其下所有文件和子文件夹
        let prefix = format!("{}/", vpath);
        let files_to_remove: Vec<String> = index.files.keys()
            .filter(|f| f.starts_with(&prefix))
            .cloned()
            .collect();
        // 2.8.2：先收集密文区间（save_index 会消耗 index）
        let mut wiped_ranges: Vec<(u64, u64)> = Vec::with_capacity(files_to_remove.len());
        for f in &files_to_remove {
            if let Some(meta) = index.files.remove(f) {
                wiped_ranges.push((meta.offset, meta.length));
            }
        }
        let dirs_to_remove: Vec<String> = index.folders.keys()
            .filter(|d| d.starts_with(&prefix))
            .cloned()
            .collect();
        for d in dirs_to_remove {
            index.folders.remove(&d);
        }
        index.folders.remove(vpath);

        self.vault.log_event(&format!("删除文件夹 '{}'", vpath));
        self.vault.save_index(index)?;

        // 2.8.2：索引落盘后覆写密文（与 remove_file 同一收口）
        if !wiped_ranges.is_empty() {
            if let Some(file) = self.vault.file.as_mut() {
                for (off, len) in &wiped_ranges {
                    if let Err(e) = crate::wipe::dod_overwrite_range(file, *off, *len) {
                        log::warn!("覆写密文失败（残留无害）: {}", e);
                    }
                }
                let _ = file.flush();
                let _ = file.sync_all();
            }
        }
        Ok(())
    }

    pub fn rename_file(&mut self, old_vpath: &str, new_name: &str) -> Result<(), VaultError> {
        // 校验新文件名
        if new_name.is_empty()
            || new_name.contains('/')
            || new_name.contains('\\')
            || new_name.contains('\0')
            || new_name == "."
            || new_name == ".."
            || new_name.chars().any(|c| (c as u32) < 0x20)
        {
            return Err(VaultError::Other("新文件名非法".into()));
        }
        let mut index = self.vault.load_index()?;
        let mut meta = index.files.remove(old_vpath)
            .ok_or(VaultError::Other("文件不存在".into()))?;
        // AAD 冻结：旧索引（导入早于该修复）没有 aad_tag，而密文是用「重命名前的
        // vpath」做 AAD 加密的 —— 必须在改 key 之前把它固定下来，否则改完 key
        // 密文的 AAD 再也对不上，文件内容会永久不可读。
        if meta.aad_tag.is_none() {
            meta.aad_tag = Some(old_vpath.to_string());
        }
        let parent = old_vpath.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        let new_vpath = format!("{}/{}", parent, new_name);
        if !Index::validate_vpath(&new_vpath) {
            // 回滚：把元数据放回去
            index.files.insert(old_vpath.to_string(), meta);
            return Err(VaultError::Other("新路径非法".into()));
        }
        // C5 修复：目标已存在时拒绝覆盖
        // 2.8.2：同时检查文件夹命名空间（与 add_file / rename_folder 对称）——
        // 旧实现只查 files，把文件改名成已有文件夹的名字会制造 file/folder
        // 同键碰撞（两套删除实现对同一 vpath 行为不同）
        if index.files.contains_key(&new_vpath) || index.folders.contains_key(&new_vpath) {
            index.files.insert(old_vpath.to_string(), meta);
            return Err(VaultError::Other(format!("目标路径已存在: {}", new_vpath)));
        }
        index.files.insert(new_vpath.clone(), FileMeta {
            name: new_name.into(),
            ..meta
        });
        self.vault.log_event(&format!("重命名 '{}' -> '{}'", old_vpath, new_vpath));
        self.vault.save_index(index)?;
        Ok(())
    }

    pub fn rename_folder(&mut self, old_vpath: &str, new_name: &str) -> Result<(), VaultError> {
        if new_name.is_empty()
            || new_name.contains('/')
            || new_name.contains('\\')
            || new_name.contains('\0')
            || new_name == "."
            || new_name == ".."
            || new_name.chars().any(|c| (c as u32) < 0x20)
        {
            return Err(VaultError::Other("新文件夹名非法".into()));
        }
        let mut index = self.vault.load_index()?;
        if !index.folders.contains_key(old_vpath) {
            return Err(VaultError::Other("文件夹不存在".into()));
        }
        let parent = old_vpath.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        let new_vpath = format!("{}/{}", parent, new_name);
        if !Index::validate_vpath(&new_vpath) {
            return Err(VaultError::Other("新路径非法".into()));
        }
        // C5 修复：目标已存在时拒绝覆盖
        if index.folders.contains_key(&new_vpath) || index.files.contains_key(&new_vpath) {
            return Err(VaultError::Other(format!("目标路径已存在: {}", new_vpath)));
        }

        // 2.8.2：子树改写收敛到共享纯函数（含子树键冲突检测）
        let (new_files, new_folders) =
            rewrite_folder_keys(&index.files, &index.folders, old_vpath, &new_vpath)?;
        index.files = new_files;
        index.folders = new_folders;

        self.vault.log_event(&format!("重命名文件夹 '{}' -> '{}'", old_vpath, new_vpath));
        self.vault.save_index(index)?;
        Ok(())
    }

    /// 2.8.0：移动文件到目标目录（跨目录移动 = 索引 key 前缀改写，密文不动 ——
    /// AAD 绑定的是导入时冻结的 aad_tag，与重命名同一语义）。
    pub fn move_file(&mut self, old_vpath: &str, dest_dir: &str) -> Result<(), VaultError> {
        let mut index = self.vault.load_index()?;
        move_file_in_index(&mut index, old_vpath, dest_dir)?;
        self.vault.log_event(&format!("移动 '{}'（文件）", old_vpath));
        self.vault.save_index(index)?;
        Ok(())
    }

    /// 2.8.0：移动文件夹（含全部子树）到目标目录。
    /// 拒绝移入自身或自身的子目录；子树 key 前缀改写并逐个冻结 aad_tag。
    pub fn move_folder(&mut self, old_vpath: &str, dest_dir: &str) -> Result<(), VaultError> {
        let mut index = self.vault.load_index()?;
        move_folder_in_index(&mut index, old_vpath, dest_dir)?;
        self.vault.log_event(&format!("移动文件夹 '{}'（含子树）", old_vpath));
        self.vault.save_index(index)?;
        Ok(())
    }

    /// 2.8.1（性能）：批量移动 —— 单次 load_index，N 项在内存中依次变换，
    /// **一次** save_index。旧实现每项一次完整「加密落盘 + 头部重写 + 旧索引
    /// DoD 7-pass 擦除」（约 9 次 fsync + 8× 索引体积写入），100 项 × 10k 文件
    /// 索引 ≈ 1.6GB 写放大；批量化后与 import_files_batch 同一成本模型。
    /// 返回 (成功数, 失败数, 失败明细)。
    pub fn move_items(
        &mut self,
        vpaths: &[String],
        dest_dir: &str,
    ) -> Result<(usize, usize, Vec<String>), VaultError> {
        let mut index = self.vault.load_index()?;
        let mut ok = 0usize;
        let mut fail = 0usize;
        let mut errors: Vec<String> = Vec::new();
        for vp in vpaths {
            let vp_norm = vp.trim_end_matches('/');
            if vp_norm.is_empty() || vp_norm == "/" {
                fail += 1;
                errors.push(format!("{}: 非法路径", vp));
                continue;
            }
            let is_dir = index.folders.contains_key(vp_norm);
            let is_file = index.files.contains_key(vp_norm);
            if !is_dir && !is_file {
                fail += 1;
                errors.push(format!("{}: 不存在", vp));
                continue;
            }
            let r = if is_dir {
                move_folder_in_index(&mut index, vp_norm, dest_dir)
            } else {
                move_file_in_index(&mut index, vp_norm, dest_dir)
            };
            match r {
                Ok(()) => ok += 1,
                Err(e) => {
                    fail += 1;
                    errors.push(format!("{}: {}", vp_norm, e));
                }
            }
        }
        if ok > 0 {
            self.vault
                .log_event(&format!("批量移动 {} 项（失败 {} 项）", ok, fail));
            self.vault.save_index(index)?;
        }
        Ok((ok, fail, errors))
    }
}

/// 2.8.1：移动文件的纯索引变换（不做 load/save，单项与批量路径共用）。
fn move_file_in_index(index: &mut Index, old_vpath: &str, dest_dir: &str) -> Result<(), VaultError> {
    let dest_dir = Index::normalize_vpath(dest_dir)
        .filter(|p| Index::validate_vpath(p))
        .ok_or_else(|| VaultError::Other("目标目录非法".into()))?;
    // 2.8.1 修复：存在性检查前移 —— 旧实现 no-op 短路在存在性检查之前，
    // 「移动不存在的文件到原地」会误报成功
    if !index.files.contains_key(old_vpath) {
        return Err(VaultError::Other("文件不存在".into()));
    }
    if dest_dir != "/" && !index.folders.contains_key(&dest_dir) {
        return Err(VaultError::Other(format!("目标文件夹不存在: {}", dest_dir)));
    }
    let name = old_vpath
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| VaultError::Other("源路径非法".into()))?;
    let new_vpath = if dest_dir == "/" {
        format!("/{}", name)
    } else {
        format!("{}/{}", dest_dir, name)
    };
    if !Index::validate_vpath(&new_vpath) {
        return Err(VaultError::Other("目标路径非法".into()));
    }
    if new_vpath == old_vpath {
        return Ok(()); // 移动到当前所在目录：无操作（源已确认存在）
    }
    let mut meta = index
        .files
        .remove(old_vpath)
        .ok_or(VaultError::Other("文件不存在".into()))?;
    // AAD 冻结（与 rename_file 相同：旧索引可能没有 aad_tag）
    if meta.aad_tag.is_none() {
        meta.aad_tag = Some(old_vpath.to_string());
    }
    if index.folders.contains_key(&new_vpath) || index.files.contains_key(&new_vpath) {
        index.files.insert(old_vpath.to_string(), meta);
        return Err(VaultError::Other(format!("目标路径已存在: {}", new_vpath)));
    }
    // 2.8.2：同时检查文件夹命名空间（与 move_folder 对称）—— 旧实现只查 files，
    // 把文件移动成已有文件夹的名字会制造 file/folder 同键碰撞
    if index.folders.contains_key(&new_vpath) {
        index.files.insert(old_vpath.to_string(), meta);
        return Err(VaultError::Other(format!(
            "目标路径已存在同名文件夹，无法移动为文件: {}", new_vpath
        )));
    }
    index.files.insert(new_vpath, meta);
    Ok(())
}

/// 2.8.1：移动文件夹的纯索引变换（不做 load/save，单项与批量路径共用）。
fn move_folder_in_index(index: &mut Index, old_vpath: &str, dest_dir: &str) -> Result<(), VaultError> {
    let dest_dir = Index::normalize_vpath(dest_dir)
        .filter(|p| Index::validate_vpath(p))
        .ok_or_else(|| VaultError::Other("目标目录非法".into()))?;
    if !index.folders.contains_key(old_vpath) {
        return Err(VaultError::Other("文件夹不存在".into()));
    }
    if dest_dir != "/" && !index.folders.contains_key(&dest_dir) {
        return Err(VaultError::Other(format!("目标文件夹不存在: {}", dest_dir)));
    }
    let name = old_vpath
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| VaultError::Other("源路径非法".into()))?;
    let new_vpath = if dest_dir == "/" {
        format!("/{}", name)
    } else {
        format!("{}/{}", dest_dir, name)
    };
    if !Index::validate_vpath(&new_vpath) {
        return Err(VaultError::Other("目标路径非法".into()));
    }
    if new_vpath == old_vpath {
        return Ok(()); // 原地：无操作（源已确认存在）
    }
    // 不能移入自身 / 自身子目录（否则 key 改写会产生环）
    if new_vpath.starts_with(&format!("{}/", old_vpath)) {
        return Err(VaultError::Other("不能把文件夹移动到它自身或其子目录内".into()));
    }
    if index.folders.contains_key(&new_vpath) || index.files.contains_key(&new_vpath) {
        return Err(VaultError::Other(format!("目标路径已存在: {}", new_vpath)));
    }

    // 2.8.2：子树改写收敛到共享纯函数（含子树键冲突检测）
    let (new_files, new_folders) =
        rewrite_folder_keys(&index.files, &index.folders, old_vpath, &new_vpath)?;
    index.files = new_files;
    index.folders = new_folders;
    Ok(())
}

/// 2.8.2：文件夹子树键改写的共享纯函数（rename_folder 与 move_folder_in_index
/// 原本各自复制一份，现收敛到此处），内含**子树键冲突检测** ——
/// 顶层 new_vpath 的存在性检查由调用方负责，子项改写后的键仍可能撞上既有键
/// （folders 记录缺失的遗留索引状态）。HashMap 的 insert 会**静默覆盖**旧元数据
/// （原文件密文变孤儿、内容丢失），因此用「键数量不变」作为冲突锚点：
/// 任何一次碰撞都会让 map 变小。
fn rewrite_folder_keys(
    files: &HashMap<String, FileMeta>,
    folders: &HashMap<String, bool>,
    old_vpath: &str,
    new_vpath: &str,
) -> Result<(HashMap<String, FileMeta>, HashMap<String, bool>), VaultError> {
    let mut new_files = HashMap::new();
    let mut new_folders = HashMap::new();
    let old_prefix = format!("{}/", old_vpath);
    let new_prefix = format!("{}/", new_vpath);

    for (k, v) in files {
        if k.starts_with(&old_prefix) || k == old_vpath {
            // AAD 冻结：密文用「重命名前的 vpath」做 AAD，必须在改 key 之前
            // 逐个固定下来，否则整个子树改完 key 后密文全部失配（内容永久不可读）
            let mut meta = v.clone();
            if meta.aad_tag.is_none() {
                meta.aad_tag = Some(k.clone());
            }
            let new_key = if k == old_vpath {
                new_vpath.to_string()
            } else {
                new_prefix.to_string() + &k[old_prefix.len()..]
            };
            new_files.insert(new_key, meta);
        } else {
            new_files.insert(k.clone(), v.clone());
        }
    }
    for k in folders.keys() {
        if k.starts_with(&old_prefix) {
            new_folders.insert(new_prefix.to_string() + &k[old_prefix.len()..], true);
        } else if k == old_vpath {
            new_folders.insert(new_vpath.to_string(), true);
        } else {
            new_folders.insert(k.clone(), true);
        }
    }

    if new_files.len() != files.len() || new_folders.len() != folders.len() {
        return Err(VaultError::Other(
            "目标路径与现有文件/文件夹冲突（子项重名），已中止操作".into(),
        ));
    }
    Ok((new_files, new_folders))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_vpath() {
        assert!(Index::validate_vpath("/"));
        assert!(Index::validate_vpath("/foo"));
        assert!(Index::validate_vpath("/foo/bar"));
        assert!(!Index::validate_vpath("foo"));
        assert!(!Index::validate_vpath("/foo/"));
        assert!(!Index::validate_vpath("/foo//bar"));
        assert!(!Index::validate_vpath("/foo/../bar"));
        assert!(!Index::validate_vpath("/foo\\bar"));
        assert!(!Index::validate_vpath("/foo\0bar"));
    }

    #[test]
    fn test_normalize_vpath() {
        assert_eq!(Index::normalize_vpath("/foo/bar").as_deref(), Some("/foo/bar"));
        assert_eq!(Index::normalize_vpath("/foo//bar").as_deref(), Some("/foo/bar"));
        assert_eq!(Index::normalize_vpath("/foo/./bar").as_deref(), Some("/foo/bar"));
        assert_eq!(Index::normalize_vpath("/foo/bar/").as_deref(), Some("/foo/bar"));
        assert_eq!(Index::normalize_vpath("/").as_deref(), Some("/"));
        assert_eq!(Index::normalize_vpath("///").as_deref(), Some("/"));
        // 2.8.2：越过根的 '..' 拒绝而非静默重定向到根内路径
        assert_eq!(Index::normalize_vpath("/../evil.txt"), None);
        assert_eq!(Index::normalize_vpath("/../.."), None);
        // 段内的 '..' 仍正常折叠
        assert_eq!(Index::normalize_vpath("/foo/../bar").as_deref(), Some("/bar"));
    }

    // 2.8.2：clean_vpath 组合语义
    #[test]
    fn test_clean_vpath() {
        assert_eq!(Index::clean_vpath("/foo//bar/").as_deref(), Some("/foo/bar"));
        assert_eq!(Index::clean_vpath("/foo/../.."), None);
        // 归一化补全前导斜杠是历史行为（"plain.txt" → "/plain.txt"，导入路径兼容）
        assert_eq!(Index::clean_vpath("foo").as_deref(), Some("/foo"));
    }

    // 2.8.2：文件移动的文件夹命名空间碰撞检查（move_file_in_index 纯函数）
    #[test]
    fn test_move_file_rejects_folder_collision() {
        let mut idx = Index::new();
        idx.folders.insert("/x/notes".into(), true);
        idx.files.insert("/notes".into(), FileMeta {
            name: "notes".into(), size: 1, offset: 0, length: 10, aad_tag: None,
        });
        // 把文件 /notes 移入 /x：目标 /x/notes 已是文件夹 → 必须拒绝，
        // 且源条目保持原位（回滚）
        let r = super::move_file_in_index(&mut idx, "/notes", "/x");
        assert!(r.is_err(), "移动成已有文件夹的名字必须被拒绝");
        assert!(idx.files.contains_key("/notes"), "拒绝后源文件不得丢失");
        assert!(!idx.files.contains_key("/x/notes"), "不得产生 file/folder 同键碰撞");
    }

    // 2.8.2：文件夹改名的子树键冲突检测（键数量锚点）
    #[test]
    fn test_rename_folder_subtree_collision_is_rejected() {
        // 构造「folders 缺少 /b 记录」的遗留形态索引：/b/c.txt 存在但没有 /b 文件夹
        let mut idx = Index::new();
        idx.files.insert("/b/c.txt".into(), FileMeta {
            name: "c.txt".into(), size: 1, offset: 0, length: 10, aad_tag: None,
        });
        idx.folders.insert("/a".into(), true);
        idx.files.insert("/a/d.txt".into(), FileMeta {
            name: "d.txt".into(), size: 1, offset: 5, length: 10, aad_tag: None,
        });
        idx.folders.insert("/a/sub".into(), true);
        // /a 改名为 /b：/a/d.txt → /b/d.txt 不冲突，但 /a/sub → /b/sub 与
        // 隐含的 /b 子树无冲突，而 /b/c.txt 保持 —— 顶层 /b 未被 folders 记录，
        // 旧实现顶层检查放行；子树改写键数不变则允许（无碰撞）
        // 这里验证的是「有碰撞时拒绝」：让 /a 下有 /a/c.txt 与既有 /b/c.txt 相撞
        idx.files.insert("/a/c.txt".into(), FileMeta {
            name: "c.txt".into(), size: 2, offset: 99, length: 10, aad_tag: None,
        });
        // 改名 /a → /b：/a/c.txt → /b/c.txt 与既有 /b/c.txt 相撞 → 必须拒绝
        let r = super::rewrite_folder_keys(&idx.files, &idx.folders, "/a", "/b");
        assert!(r.is_err(), "子树键碰撞必须被拒绝（否则静默覆盖丢数据）");
        assert_eq!(idx.files.get("/b/c.txt").unwrap().offset, 0, "既有 /b/c.txt 不得被覆盖");
        assert!(idx.files.contains_key("/a/c.txt"), "源子树保持原状");
        // 无碰撞的改名照常通过
        assert!(super::rewrite_folder_keys(&idx.files, &idx.folders, "/a", "/c").is_ok());
    }

}
