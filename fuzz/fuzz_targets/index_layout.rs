//! 模糊测试：分块布局解析算术（3.0.1 F18/F25）。
//!
//! 3.0.0 的 fuzz 目标只驱动「反序列化 + 路径清洗」，从未触及提取 / 媒体 /
//! 擦除的算术路径（F3/F4/F5 因此漏网）。本目标把任意 (length, chunk_size,
//! chunk_count) 直接喂给统一布局解析函数，断言：
//! - 任何输入不得 panic（Err 一律干净返回）；
//! - Ok 时字段满足写入方几何不变量（chunk_size ∈ (0, 4 MiB]、末块 ∈
//!   (0, chunk_size]、length ≥ 满块密文总量 + 末块开销）。
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }
    let le = |b: &[u8]| u64::from_le_bytes(b.try_into().expect("8 字节切片"));
    let length = le(&data[0..8]);
    let chunk_size = le(&data[8..16]);
    let chunk_count = le(&data[16..24]);
    match vault_core::resolve_chunk_plan_for_fuzz(length, chunk_size, chunk_count) {
        Ok((cs, cc, full_ct, expected_last)) => {
            assert!(cs > 0 && cs <= 4 * 1024 * 1024, "chunk_size 超上限: {}", cs);
            assert!(cc > 0, "chunk_count 为 0 却返回 Ok");
            assert_eq!(full_ct, cs + 28, "满块密文长度不变量破坏");
            assert!(
                expected_last > 0 && expected_last <= cs,
                "末块明文长度越界: {} (cs={})",
                expected_last,
                cs
            );
            let full_ct_total = full_ct
                .checked_mul(cc - 1)
                .expect("解析成功的 plan 其满块总量不溢出");
            assert!(
                length >= full_ct_total + 28,
                "length 不变量破坏: length={} full_ct_total={}",
                length,
                full_ct_total
            );
        }
        Err(_) => {}
    }
});
