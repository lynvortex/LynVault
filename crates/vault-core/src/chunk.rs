//! 3.1.1（审计修复）：分块布局几何的**单一事实来源**（叶子模块）。
//!
//! 3.0.0 引入 v6 分块布局时，同一条恒等式被写了三份：
//! - 写入侧：`ops_import` / `update_file_content` 用 `size.div_ceil(chunk_size)` 推导块数；
//! - 读取侧：`fs_util::resolve_chunk_plan` 由密文长度反推末块长度；
//! - 校验侧：`Index::validate` 又独立重写了一遍（`full_ct_total` / `expected_last` /
//!   `expected_size`）。
//!
//! 三份实现必须逐字节等价，而它们之间**没有任何测试或类型约束**保证这一点 ——
//! 任何一处漂移都会变成「validate 放过、读取侧爆雷」或「正常柜被拒绝打开」。
//! 本模块把解析与恒等式收敛到一处：写入侧只负责产生 `(chunk_size, chunk_count)`，
//! 读取侧与校验侧一律调用 [`resolve_chunk_plan`]。
//!
//! 同时本模块只依赖 [`crate::error`]（无任何 `vault` / `index` 依赖）——
//! `index` 不再需要回引 `vault::consts` / `vault::fs_util` 取分块知识，
//! `index` → `vault` 的一条常量回边就此切断。

use crate::error::VaultError;

/// v6 分块布局的明文块大小（4 MiB）—— 每块独立 nonce + GCM tag，
/// 常量内存流式加解密的单位。
pub const CHUNK_SIZE_V6: u64 = 4 * 1024 * 1024;

/// 分块密文每块开销：nonce(12) + GCM tag(16)
pub const CHUNK_OVERHEAD: u64 = 28;

/// 分块布局解析结果 —— 逐块几何的唯一事实来源。
#[derive(Debug, Clone, Copy)]
pub struct ChunkPlan {
    pub chunk_size: u64,
    pub chunk_count: u64,
    /// 满块密文长度 = chunk_size + CHUNK_OVERHEAD
    pub full_ct: u64,
    /// 末块明文长度 ∈ (0, chunk_size]
    pub expected_last: u64,
}

impl ChunkPlan {
    /// 第 i 块的明文长度（末块 = expected_last，其余 = chunk_size）
    pub fn plain_len(&self, i: u64) -> u64 {
        if i + 1 == self.chunk_count {
            self.expected_last
        } else {
            self.chunk_size
        }
    }

    /// 第 i 块的密文长度
    pub fn ct_len(&self, i: u64) -> u64 {
        self.plain_len(i) + CHUNK_OVERHEAD
    }

    /// 明文总长（= 索引 `size` 字段在写入时的值）。
    ///
    /// saturating：resolve_chunk_plan 的校验已保证真实值不溢出
    ///（(count-1)*full_ct ≤ length），此处 saturate 仅作为纵深防御。
    pub fn plaintext_total(&self) -> u64 {
        (self.chunk_count - 1)
            .saturating_mul(self.chunk_size)
            .saturating_add(self.expected_last)
    }
}

/// 由密文总长 + 索引布局解析分块几何 —— 所有读写/校验路径共用，不得自行演算。
///
/// 校验（3.0.1 F3 起）：
/// - `chunk_size ∈ (0, CHUNK_SIZE_V6]`：唯一曾是「非零」检查 —— chunk_count=1
///   时 `length` 全额通过，`vec![0u8; 2^40]` 直接 alloc-abort 整个进程；
///   写入方恒用 CHUNK_SIZE_V6 分块，超限值必属篡改/损坏；
/// - `chunk_count > 0`，全程 checked 运算（release 档 overflow-checks 开启，
///   但显式报错优于 panic）；
/// - 末块明文 ∈ (0, chunk_size]：密文长度与索引布局矛盾即拒绝（截断/篡改）。
pub fn resolve_chunk_plan(
    length: u64,
    chunk_size: u64,
    chunk_count: u64,
) -> Result<ChunkPlan, VaultError> {
    if chunk_size == 0 || chunk_count == 0 {
        return Err(VaultError::Other("分块布局参数非法".into()));
    }
    if chunk_size > CHUNK_SIZE_V6 {
        return Err(VaultError::Other(format!(
            "分块大小非法（{} 字节，超过上限 {} 字节）",
            chunk_size, CHUNK_SIZE_V6
        )));
    }
    let full_ct = chunk_size
        .checked_add(CHUNK_OVERHEAD)
        .ok_or_else(|| VaultError::Other("分块布局参数非法".into()))?;
    let full_ct_total = full_ct
        .checked_mul(chunk_count - 1)
        .ok_or_else(|| VaultError::Other("分块布局参数非法（块数溢出）".into()))?;
    let expected_last = match length.checked_sub(full_ct_total) {
        Some(v) if v > CHUNK_OVERHEAD && v <= full_ct => v - CHUNK_OVERHEAD,
        _ => {
            return Err(VaultError::Other(
                "分块密文长度与索引布局不一致（密文可能被截断或篡改）".into(),
            ))
        }
    };
    Ok(ChunkPlan {
        chunk_size,
        chunk_count,
        full_ct,
        expected_last,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 块数推导与写入侧恒等式一致（`size.div_ceil(chunk_size)`）
    #[test]
    fn plan_matches_writer_identity() {
        for size in [1u64, 4095, 4096, 4097, 8 * 1024 * 1024 + 1] {
            let count = size.div_ceil(CHUNK_SIZE_V6);
            let length = count * CHUNK_OVERHEAD + size;
            let plan =
                resolve_chunk_plan(length, CHUNK_SIZE_V6, count).expect("合法布局必须可解析");
            assert_eq!(plan.chunk_count, count);
            assert_eq!(plan.plaintext_total(), size, "明文总长必须与写入侧一致");
            // 逐块长度累加 == 密文总长（几何自洽）
            let sum: u64 = (0..count).map(|i| plan.ct_len(i)).sum();
            assert_eq!(sum, length);
        }
    }

    /// 四个边界：块大小 0 / 超上限 / 块数 0 / 末块为 0
    #[test]
    fn rejects_illegal_geometry() {
        assert!(resolve_chunk_plan(100, 0, 1).is_err(), "块大小 0 必须拒绝");
        assert!(
            resolve_chunk_plan(100, CHUNK_SIZE_V6 + 1, 1).is_err(),
            "块大小超过 CHUNK_SIZE_V6 必须拒绝"
        );
        assert!(resolve_chunk_plan(100, 1024, 0).is_err(), "块数 0 必须拒绝");
        // 单块、密文恰为 28 字节（明文 0）→ 末块明文必须 > 0
        assert!(
            resolve_chunk_plan(CHUNK_OVERHEAD, 1024, 1).is_err(),
            "末块明文为 0 必须拒绝"
        );
        // 多块但末块缺失（总长不足 (count-1) 个满块）
        assert!(resolve_chunk_plan(64, 1024, 2).is_err(), "末块缺失必须拒绝");
    }

    /// 块数溢出与块大小溢出不得 panic（release 亦为显式错误）
    #[test]
    fn no_panic_on_extreme_values() {
        assert!(resolve_chunk_plan(u64::MAX, CHUNK_SIZE_V6, u64::MAX).is_err());
        assert!(resolve_chunk_plan(u64::MAX, CHUNK_SIZE_V6, 1 << 20).is_err());
        assert!(resolve_chunk_plan(0, CHUNK_SIZE_V6, 1).is_err());
    }
}
