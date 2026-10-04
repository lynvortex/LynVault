//! 模糊测试：加密索引的反序列化与虚拟路径清洗。
//! 目标：恶意 JSON / 布局字段不得 panic（serde 错误一律返回 Err）。
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(index) = serde_json::from_str::<vault_core::Index>(text) {
            // 反序列化成功的索引再喂给路径清洗（对每个键 panic-free）
            for key in index.files.keys() {
                let _ = vault_core::Index::clean_vpath(key);
                let _ = vault_core::Index::validate_vpath(key);
            }
        }
    }
});
