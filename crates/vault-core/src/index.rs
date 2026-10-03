use serde::{Serialize, Deserialize};
use std::collections::HashMap;
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
    /// 不允许 '..' 段（直接返回 None）。
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
                // 不允许跳出根
                parts.pop();
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
        if index.files.contains_key(&vpath) {
            return Err(VaultError::Other(format!("目标路径已存在: {}", vpath)));
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
        self.vault.save_index(&index)?;
        Ok(())
    }

    pub fn remove_file(&mut self, vpath: &str) -> Result<(), VaultError> {
        let mut index = self.vault.load_index()?;
        if index.files.remove(vpath).is_some() {
            self.vault.log_event(&format!("删除文件 '{}'", vpath));
            self.vault.save_index(&index)?;
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
        index.folders.insert(vpath.clone(), true);
        self.vault.log_event(&format!("创建文件夹 '{}'", vpath));
        self.vault.save_index(&index)?;
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
        for f in files_to_remove {
            index.files.remove(&f);
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
        self.vault.save_index(&index)?;
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
        if index.files.contains_key(&new_vpath) {
            index.files.insert(old_vpath.to_string(), meta);
            return Err(VaultError::Other(format!("目标路径已存在: {}", new_vpath)));
        }
        index.files.insert(new_vpath.clone(), FileMeta {
            name: new_name.into(),
            ..meta
        });
        self.vault.log_event(&format!("重命名 '{}' -> '{}'", old_vpath, new_vpath));
        self.vault.save_index(&index)?;
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

        // 移动所有子文件和子文件夹
        let mut new_files = HashMap::new();
        let mut new_folders = HashMap::new();
        let old_prefix = format!("{}/", old_vpath);
        let new_prefix = format!("{}/", new_vpath);

        for (k, v) in &index.files {
            if k.starts_with(&old_prefix) || k == old_vpath {
                // AAD 冻结：密文用「重命名前的 vpath」做 AAD，必须在改 key 之前
                // 逐个固定下来，否则整个子树改完 key 后密文全部失配（内容永久不可读）
                let mut meta = v.clone();
                if meta.aad_tag.is_none() {
                    meta.aad_tag = Some(k.clone());
                }
                let new_key = if k == old_vpath {
                    new_vpath.clone()
                } else {
                    new_prefix.to_string() + &k[old_prefix.len()..]
                };
                new_files.insert(new_key, meta);
            } else {
                new_files.insert(k.clone(), v.clone());
            }
        }
        for k in index.folders.keys() {
            if k.starts_with(&old_prefix) {
                let new_key = new_prefix.to_string() + &k[old_prefix.len()..];
                new_folders.insert(new_key, true);
            } else if k == old_vpath {
                new_folders.insert(new_vpath.clone(), true);
            } else {
                new_folders.insert(k.clone(), true);
            }
        }

        index.files = new_files;
        index.folders = new_folders;

        self.vault.log_event(&format!("重命名文件夹 '{}' -> '{}'", old_vpath, new_vpath));
        self.vault.save_index(&index)?;
        Ok(())
    }

    /// 2.8.0：移动文件到目标目录（跨目录移动 = 索引 key 前缀改写，密文不动 ——
    /// AAD 绑定的是导入时冻结的 aad_tag，与重命名同一语义）。
    pub fn move_file(&mut self, old_vpath: &str, dest_dir: &str) -> Result<(), VaultError> {
        let dest_dir = Index::normalize_vpath(dest_dir)
            .filter(|p| Index::validate_vpath(p))
            .ok_or_else(|| VaultError::Other("目标目录非法".into()))?;
        let mut index = self.vault.load_index()?;
        if dest_dir != "/" && !index.folders.contains_key(&dest_dir) {
            return Err(VaultError::Other(format!("目标文件夹不存在: {}", dest_dir)));
        }
        let name = old_vpath.rsplit('/').next()
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
            return Ok(()); // 移动到当前所在目录：无操作
        }
        let mut meta = index.files.remove(old_vpath)
            .ok_or(VaultError::Other("文件不存在".into()))?;
        // AAD 冻结（与 rename_file 相同：旧索引可能没有 aad_tag）
        if meta.aad_tag.is_none() {
            meta.aad_tag = Some(old_vpath.to_string());
        }
        if index.files.contains_key(&new_vpath) {
            index.files.insert(old_vpath.to_string(), meta);
            return Err(VaultError::Other(format!("目标路径已存在: {}", new_vpath)));
        }
        index.files.insert(new_vpath.clone(), meta);
        self.vault.log_event(&format!("移动 '{}' -> '{}'", old_vpath, new_vpath));
        self.vault.save_index(&index)?;
        Ok(())
    }

    /// 2.8.0：移动文件夹（含全部子树）到目标目录。
    /// 拒绝移入自身或自身的子目录；子树 key 前缀改写并逐个冻结 aad_tag。
    pub fn move_folder(&mut self, old_vpath: &str, dest_dir: &str) -> Result<(), VaultError> {
        let dest_dir = Index::normalize_vpath(dest_dir)
            .filter(|p| Index::validate_vpath(p))
            .ok_or_else(|| VaultError::Other("目标目录非法".into()))?;
        let mut index = self.vault.load_index()?;
        if !index.folders.contains_key(old_vpath) {
            return Err(VaultError::Other("文件夹不存在".into()));
        }
        if dest_dir != "/" && !index.folders.contains_key(&dest_dir) {
            return Err(VaultError::Other(format!("目标文件夹不存在: {}", dest_dir)));
        }
        let name = old_vpath.rsplit('/').next()
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
            return Ok(());
        }
        // 不能移入自身 / 自身子目录（否则 key 改写会产生环）
        if new_vpath == old_vpath || new_vpath.starts_with(&format!("{}/", old_vpath)) {
            return Err(VaultError::Other("不能把文件夹移动到它自身或其子目录内".into()));
        }
        if index.folders.contains_key(&new_vpath) || index.files.contains_key(&new_vpath) {
            return Err(VaultError::Other(format!("目标路径已存在: {}", new_vpath)));
        }

        let mut new_files = HashMap::new();
        let mut new_folders = HashMap::new();
        let old_prefix = format!("{}/", old_vpath);
        let new_prefix = format!("{}/", new_vpath);

        for (k, v) in &index.files {
            if k.starts_with(&old_prefix) || k == old_vpath {
                // AAD 冻结（与 rename_folder 相同）
                let mut meta = v.clone();
                if meta.aad_tag.is_none() {
                    meta.aad_tag = Some(k.clone());
                }
                let new_key = if k == old_vpath {
                    new_vpath.clone()
                } else {
                    new_prefix.to_string() + &k[old_prefix.len()..]
                };
                new_files.insert(new_key, meta);
            } else {
                new_files.insert(k.clone(), v.clone());
            }
        }
        for k in index.folders.keys() {
            if k.starts_with(&old_prefix) {
                new_folders.insert(new_prefix.to_string() + &k[old_prefix.len()..], true);
            } else if k == old_vpath {
                new_folders.insert(new_vpath.clone(), true);
            } else {
                new_folders.insert(k.clone(), true);
            }
        }
        index.files = new_files;
        index.folders = new_folders;

        self.vault.log_event(&format!("移动文件夹 '{}' -> '{}'", old_vpath, new_vpath));
        self.vault.save_index(&index)?;
        Ok(())
    }
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
    }
}
