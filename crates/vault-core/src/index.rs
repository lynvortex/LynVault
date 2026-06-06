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

    /// 验证虚拟路径是否安全
    pub fn validate_vpath(vpath: &str) -> bool {
        vpath.starts_with('/') && !vpath.contains("..") && !vpath.contains('\\')
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
        if !Index::validate_vpath(vpath) {
            return Err(VaultError::Other("无效的虚拟路径".into()));
        }
        let mut index = self.vault.load_index()?;
        index.files.insert(vpath.into(), FileMeta {
            name: name.into(),
            size,
            offset,
            length,
        });
        // 自动创建父文件夹
        if let Some(parent) = vpath.rfind('/') {
            if parent > 0 {
                let parent = &vpath[..parent];
                index.folders.insert(parent.into(), true);
            }
        }
        if let Some(audit) = &mut self.vault.audit {
            audit.add(&format!("添加文件 '{}'", vpath));
        }
        self.vault.save_index(&index)?;
        Ok(())
    }

    pub fn remove_file(&mut self, vpath: &str) -> Result<(), VaultError> {
        let mut index = self.vault.load_index()?;
        if index.files.remove(vpath).is_some() {
            if let Some(audit) = &mut self.vault.audit {
                audit.add(&format!("删除文件 '{}'", vpath));
            }
            self.vault.save_index(&index)?;
        }
        Ok(())
    }

    pub fn add_folder(&mut self, vpath: &str) -> Result<(), VaultError> {
        if !Index::validate_vpath(vpath) {
            return Err(VaultError::Other("无效的虚拟路径".into()));
        }
        let mut index = self.vault.load_index()?;
        index.folders.insert(vpath.into(), true);
        if let Some(audit) = &mut self.vault.audit {
            audit.add(&format!("创建文件夹 '{}'", vpath));
        }
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

        if let Some(audit) = &mut self.vault.audit {
            audit.add(&format!("删除文件夹 '{}'", vpath));
        }
        self.vault.save_index(&index)?;
        Ok(())
    }

    pub fn rename_file(&mut self, old_vpath: &str, new_name: &str) -> Result<(), VaultError> {
        let mut index = self.vault.load_index()?;
        let meta = index.files.remove(old_vpath).ok_or(VaultError::Other("文件不存在".into()))?;
        let parent = old_vpath.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        let new_vpath = format!("{}/{}", parent, new_name);
        if !Index::validate_vpath(&new_vpath) {
            return Err(VaultError::Other("新路径非法".into()));
        }
        index.files.insert(new_vpath.clone(), FileMeta {
            name: new_name.into(),
            ..meta
        });
        if let Some(audit) = &mut self.vault.audit {
            audit.add(&format!("重命名 '{}' -> '{}'", old_vpath, new_vpath));
        }
        self.vault.save_index(&index)?;
        Ok(())
    }

    pub fn rename_folder(&mut self, old_vpath: &str, new_name: &str) -> Result<(), VaultError> {
        let mut index = self.vault.load_index()?;
        if !index.folders.contains_key(old_vpath) {
            return Err(VaultError::Other("文件夹不存在".into()));
        }
        let parent = old_vpath.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        let new_vpath = format!("{}/{}", parent, new_name);
        if !Index::validate_vpath(&new_vpath) {
            return Err(VaultError::Other("新路径非法".into()));
        }

        // 移动所有子文件和子文件夹
        let mut new_files = HashMap::new();
        let mut new_folders = HashMap::new();
        let old_prefix = format!("{}/", old_vpath);
        let new_prefix = format!("{}/", new_vpath);

        for (k, v) in &index.files {
            if k.starts_with(&old_prefix) {
                let new_key = new_prefix.to_string() + &k[old_prefix.len()..];
                new_files.insert(new_key, v.clone());
            } else if k == old_vpath {
                new_files.insert(new_vpath.clone(), v.clone());
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

        if let Some(audit) = &mut self.vault.audit {
            audit.add(&format!("重命名文件夹 '{}' -> '{}'", old_vpath, new_vpath));
        }
        self.vault.save_index(&index)?;
        Ok(())
    }
}