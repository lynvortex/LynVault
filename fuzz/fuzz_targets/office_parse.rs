//! 模糊测试：Office 文档解析（docx/xlsx/doc + 加密 OOXML 分支）。
//! 目标：任意字节输入不得 panic / OOM（资源上限由预扫描与限读逻辑保证）。
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 文件名决定解析分支 —— 三类入口都覆盖
    let _ = vault_core::office::extract_office_text(data, "fuzz.docx", Some("fuzz-password"));
    let _ = vault_core::office::extract_office_text(data, "fuzz.xlsx", Some("fuzz-password"));
    let _ = vault_core::office::extract_office_text(data, "fuzz.doc", None);
    // I10：补 .xls 二进制与 .csv 直读分支
    let _ = vault_core::office::extract_office_text(data, "fuzz.xls", None);
    let _ = vault_core::office::extract_office_text(data, "fuzz.csv", None);
});
