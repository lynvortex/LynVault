//! 模糊测试：保险柜头部公开字段的解析（开锁前提示 / 挑战盐 / magic 识别）。
//! 目标：任意头部字节不得 panic（校验失败一律返回 Err）。
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir().join(format!("lynvault-fuzz-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("probe.lyt");
    if std::fs::write(&path, data).is_ok() {
        let _ = vault_core::read_lock_info(&path);
        let _ = vault_core::read_vault_salt(&path);
        let _ = vault_core::read_vault_yk_salt(&path);
        let _ = vault_core::is_vault_file(&path);
        let _ = std::fs::remove_file(&path);
    }
});
