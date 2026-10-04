//! 安全删除 —— 文件 / 文件夹 / 批量删除、死空间估算与自动整理触发。
//! 3.0.0 拆分自 vault.rs，逻辑逐字节不变。
use std::io::Write;

use crate::error::VaultError;
use crate::index::Index;
use crate::wipe::dod_overwrite_range;

use super::consts::*;
use super::header::header_size_of;

use super::Vault;

impl Vault {
    // ═══════════════ 文件删除 ═══════════════

    /// 估算单分区保险柜的死空间(文件中已被安全擦除、但仍占位的空间总量):
    /// 文件长度 − 头部 − 活跃分区索引长度 − 全部有效文件密文长度。
    /// 多分区保险柜无法得知其他分区的死区,返回 None(自动整理跳过)。
    fn estimate_dead_bytes(&self) -> Option<u64> {
        if self.partitions.len() != 1 {
            return None;
        }
        let file_len = self.file.as_ref()?.metadata().ok()?.len();
        let index = self.cached_index.as_ref()?;
        let used = index
            .files
            .values()
            .fold(0u64, |acc, m| acc.saturating_add(m.length));
        let dead = file_len
            .saturating_sub(header_size_of(self.format_version).ok()? as u64)
            .saturating_sub(self.partitions[0].index_length)
            .saturating_sub(used);
        Some(dead)
    }

    /// 2.7.0 新增:删除类操作末尾调用。死空间达到阈值时自动执行一次紧凑整理,
    /// 把已擦除区域从文件中物理移除(抗取证:死区尽快从磁盘上消失)。
    /// 返回 Some(回收字节数) 表示已整理;未达阈值 / 多分区 / 估算失败返回 None。
    fn auto_defragment_if_worthwhile(&mut self) -> Result<Option<u64>, VaultError> {
        let Some(dead) = self.estimate_dead_bytes() else {
            return Ok(None);
        };
        if dead < AUTO_DEFRAG_MIN_DEAD_BYTES {
            return Ok(None);
        }
        let file_len = self
            .file
            .as_ref()
            .ok_or(VaultError::NotOpen)?
            .metadata()?
            .len();
        if dead.saturating_mul(AUTO_DEFRAG_DEAD_RATIO_DEN)
            < file_len.saturating_mul(AUTO_DEFRAG_DEAD_RATIO_NUM)
        {
            return Ok(None); // 死空间占比不足 30%,攒一攒再整理
        }
        self.defragment_vault(None::<fn(usize)>)?;
        self.log_event(&format!("自动整理保险柜:回收约 {} 字节死空间", dead));
        Ok(Some(dead))
    }

    pub fn secure_delete_file(&mut self, vpath: &str) -> Result<Option<u64>, VaultError> {
        // 2.7.1 修复：删除入口统一走 normalize_vpath —— 旧实现只有 delete_folder
        // 去过尾斜杠，`/docs//a.txt`、`/docs/./a.txt` 之类输入会「文件不存在」静默失配
        let vpath = Index::normalize_vpath(vpath)
            .filter(|p| Index::validate_vpath(p))
            .ok_or_else(|| VaultError::Other("无效的虚拟路径".into()))?;
        // 2.3.0 顺序修正：先更新索引并 save_index（标记已删除），再覆写密文。
        // 旧实现先擦密文后存索引，中途崩溃会让索引仍指向已损坏的密文 → GCM 认证失败 → 永久损坏。
        // 与 secure_delete_files_batch 的「先存索引再擦密文」策略保持一致。
        let mut index = self.load_index()?;
        let meta = index
            .files
            .get(&vpath)
            .ok_or_else(|| VaultError::Other("文件不存在".into()))?
            .clone();
        index.files.remove(&vpath);
        self.log_event(&format!("安全删除文件 '{}'", vpath));
        self.save_index(index)?;

        // 覆写密文（尽力而为：失败时密文残留无害，索引已不指向）
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = dod_overwrite_range(file, meta.offset, meta.length) {
                log::warn!("覆写密文失败（残留无害）: {}", e);
            }
            let _ = file.flush();
            let _ = file.sync_all();
        }

        Ok(self.auto_defragment_if_worthwhile().unwrap_or_else(|e| {
            log::warn!("删除后自动整理失败（不影响删除结果）: {}", e);
            None
        }))
    }

    pub fn delete_folder(&mut self, vpath: &str) -> Result<Option<u64>, VaultError> {
        // 2.7.1 修复：带尾斜杠的删除请求 `delete_folder("/a/")` 会得到前缀 "/a//"，
        // 一个文件都没删却返回成功 —— 入口统一按索引键规则归一化；删除根目录
        // 改为明确报错（不再静默全删）
        let vpath = Index::normalize_vpath(vpath)
            .filter(|p| Index::validate_vpath(p))
            .ok_or_else(|| VaultError::Other("无效的虚拟路径".into()))?;
        if vpath == "/" {
            return Err(VaultError::Other("拒绝删除根目录".into()));
        }
        let prefix = format!("{}/", vpath);

        // 1. 一次性加载索引，收集所有需要移除的条目
        let mut index = self.load_index()?;

        let files_to_wipe: Vec<(String, u64, u64)> = index
            .files
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix) || **k == vpath)
            .map(|(k, m)| (k.clone(), m.offset, m.length))
            .collect();

        // 2. 先从索引中批量移除（一次 save_index；与 secure_delete_files_batch 同策略）
        for (vpath_key, _, _) in &files_to_wipe {
            index.files.remove(vpath_key);
        }

        let dirs_to_delete: Vec<String> = index
            .folders
            .keys()
            .filter(|d| d.starts_with(&prefix))
            .cloned()
            .collect();
        for d in dirs_to_delete {
            index.folders.remove(&d);
        }
        if vpath != "/" {
            index.folders.remove(&vpath);
        }

        self.log_event(&format!(
            "删除文件夹 '{}'（含 {} 个文件）",
            vpath,
            files_to_wipe.len()
        ));
        self.save_index(index)?;

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

        Ok(self.auto_defragment_if_worthwhile().unwrap_or_else(|e| {
            log::warn!("删除后自动整理失败（不影响删除结果）: {}", e);
            None
        }))
    }

    /// 批量安全删除多个文件/文件夹（DoD 7-pass 覆写密文 + 索引移除）。
    ///
    /// 关键安全顺序：**先更新索引 + save_index（标记为已删除），再覆写密文**。
    /// 这样即使覆写过程中磁盘满/断电，索引已安全落盘：
    /// - 已被覆写的文件：索引已删除，不可达，碎片整理可清理
    /// - 未被覆写的文件：索引已删除，不可达，密文残留不影响功能
    ///
    /// 旧实现先覆写后 save_index，覆写中途失败会导致索引仍指向已损坏密文 → GCM 认证失败 → 永久损坏。
    ///
    /// 2.4.1 变更：
    /// - P1-11：旧实现对**每个**选中的文件夹都全表扫描一遍索引（选 m 个文件夹
    ///   = O(n×m)）；现在先分类一次（直接文件集合 + 文件夹前缀集合），再**单遍**
    ///   扫描索引判断归属，复杂度 O(n+m)。
    /// - P1-14：逐文件审计改为一条摘要审计（旧实现删 1000 个文件会追加 2000+ 条
    ///   审计，索引与 HMAC 链同步膨胀）。
    /// - 返回 (删除文件数, 删除文件夹数, Some(自动整理回收字节数))，供 UI 精确反馈。
    ///   2.7.0 起：删除完成后若死空间达到自动整理阈值（见 auto_defragment_if_worthwhile），
    ///   会追加一次紧凑整理并物理回收空间。
    pub fn secure_delete_files_batch(
        &mut self,
        vpaths: &[String],
    ) -> Result<(usize, usize, Option<u64>), VaultError> {
        let mut index = self.load_index()?;

        // 1. 分类：直接文件 → 集合；文件夹 → 前缀（含自身匹配）
        let mut direct_files: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut folder_prefixes: Vec<String> = Vec::new();
        let mut folder_self: std::collections::HashSet<&str> = std::collections::HashSet::new();
        // 归一化结果统一落到这里（String），随后的分类只借用
        let mut normalized: Vec<String> = Vec::with_capacity(vpaths.len());
        for vp in vpaths {
            // 2.7.1 修复：入口统一按索引键规则归一化（与 secure_delete_file /
            // delete_folder 一致），`/docs//a.txt` 之类输入不再静默失配
            match Index::normalize_vpath(vp) {
                Some(p) if Index::validate_vpath(&p) && p != "/" => normalized.push(p),
                _ => continue,
            }
        }
        for vp_norm in &normalized {
            if index.files.contains_key(vp_norm.as_str()) {
                direct_files.insert(vp_norm.as_str());
            } else if index.folders.contains_key(vp_norm.as_str()) {
                folder_prefixes.push(format!("{}/", vp_norm));
                folder_self.insert(vp_norm.as_str());
            }
            // 既不是文件也不是文件夹的 vpath 静默跳过（防御性）
        }
        if direct_files.is_empty() && folder_prefixes.is_empty() {
            return Ok((0, 0, None));
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
            return Ok((0, 0, None));
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
        self.save_index(index)?;

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

        let reclaimed = self.auto_defragment_if_worthwhile().unwrap_or_else(|e| {
            log::warn!("删除后自动整理失败（不影响删除结果）: {}", e);
            None
        });

        Ok((to_wipe.len(), folders_to_delete.len(), reclaimed))
    }
}
