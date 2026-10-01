//! LynVault vault-core 集成测试（2.4.1）
//!
//! 覆盖本轮改动的高风险路径：
//! - P2-20：创建后免二次认证（create 成功即 is_open）
//! - P0-2：索引内存缓存一致性（save 后缓存刷新 / close 后清理）
//! - P0-2：批量导入 / 批量删除 / 批量提取
//! - P1-3：文件名黑名单化（Unicode 与 # 等符号保留）
//! - P2-19：密码按字符数校验（4 个 12+ 字符汉字可通过，11 个 ASCII 字符拒绝）
//! - is_vault_file：magic bytes 识别（.lyt 自动识别功能的基础）
//! - 碎片整理后数据完整性（P0-3：旧数据擦除 + 布局重写）
//! - 重命名回归：rename_file / rename_folder 后密文仍可解密（AAD 不得绑定可变 vpath）

use std::fs;
use std::path::{Path, PathBuf};
use vault_core::Vault;

const PWD: &str = "correct horse battery staple";

/// 每个测试独立的临时目录（进程退出时由 TempDir 析构清理）
fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lynvault-test-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_src(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let p = dir.join(name);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&p, content).unwrap();
    p
}

fn new_vault(dir: &Path) -> (Vault, PathBuf) {
    let path = dir.join("test.lyt");
    let mut v = Vault::default();
    v.create(&path, PWD, None).expect("创建保险柜失败");
    (v, path)
}

// ───────────────── 生命周期 ─────────────────

#[test]
fn create_opens_session_and_magic_matches() {
    let dir = tempdir("create");
    let (v, path) = new_vault(&dir);

    // P2-20：创建后免二次认证 —— create 成功即已解锁
    assert!(v.is_open(), "create 后应直接进入已解锁会话");

    // magic bytes 识别（启动扫描 / 拖放识别 / 文件关联都依赖它）
    assert!(vault_core::is_vault_file(&path), "is_vault_file 应识别刚创建的保险柜");

    // 同名但非保险柜的文件（magic 不匹配）必须被拒绝
    let fake = write_src(&dir, "fake.lyt", b"not a lynvault file at all....");
    assert!(!vault_core::is_vault_file(&fake), "magic 不匹配的 .lyt 不应被识别");

    // 空文件 / 不存在文件
    assert!(!vault_core::is_vault_file(&dir.join("nonexistent.lyt")));
}

#[test]
fn wrong_password_rejected() {
    let dir = tempdir("wrongpwd");
    let (_, path) = new_vault(&dir);

    let mut v2 = Vault::default();
    let r = v2.open_and_authenticate(&path, "wrong password!!!!!", None);
    assert!(r.is_err(), "错误密码必须被拒绝");
    assert!(!v2.is_open());
}

#[test]
fn password_length_by_char_count() {
    let dir = tempdir("pwdlen");
    let path = dir.join("t.lyt");

    // P2-19：按字符数校验 —— 11 个 ASCII 字符拒绝
    let mut v = Vault::default();
    assert!(v.create(&path, "abcdefghijk", None).is_err(), "11 字符应被拒绝");
    // 12 个 ASCII 字符通过
    v.create(&path, "abcdefghijkl", None).expect("12 字符应通过");
    assert!(v.is_open());

    // 12 个汉字（字节数 36，字符数 12）也必须通过 —— 旧实现按字节算会误放 4 个汉字
    let path2 = dir.join("t2.lyt");
    let mut v2 = Vault::default();
    v2.create(&path2, &"密码密码密码密码密码密码".to_string(), None)
        .expect("12 个汉字（36 字节）应通过字符数校验");
}

// ───────────────── 导入 / 提取 / 数据完整性 ─────────────────

#[test]
fn import_extract_roundtrip() {
    let dir = tempdir("roundtrip");
    let (mut v, _) = new_vault(&dir);

    let data = b"hello lynvault \xe4\xbd\xa0\xe5\xa5\xbd roundtrip payload".to_vec();
    let src = write_src(&dir, "payload.bin", &data);
    v.import_file(&src, "/payload.bin").expect("导入失败");

    let got = v.load_file_data("/payload.bin").expect("读取失败");
    assert_eq!(got, data, "解密内容应与原文一致");

    // 提取到新目录并核对
    let out = dir.join("out");
    v.extract_file("/payload.bin", &out, true).expect("提取失败");
    assert_eq!(fs::read(out.join("payload.bin")).unwrap(), data);
}

#[test]
fn import_files_batch_counts_and_persists() {
    let dir = tempdir("batchimport");
    let (mut v, path) = new_vault(&dir);

    let srcs: Vec<String> = (0..5)
        .map(|i| {
            write_src(&dir, &format!("f{}.txt", i), format!("content-{}", i).as_bytes())
                .to_string_lossy()
                .to_string()
        })
        .collect();
    let (ok, fail) = v.import_files_batch(&srcs, "/").expect("批量导入失败");
    assert_eq!((ok, fail), (5, 0));

    // 不存在的文件计入失败，不影响其余导入
    let mut with_bad = srcs.clone();
    with_bad.push(dir.join("no_such_file.bin").to_string_lossy().to_string());
    let (ok2, fail2) = v
        .import_files_batch(&with_bad, "/dir2")
        .expect("批量导入（含失败项）不应整体失败");
    assert_eq!((ok2, fail2), (5, 1));

    // 重新打开验证持久化（同时验证索引缓存路径与磁盘一致）
    drop(v);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None).expect("重开失败");
    let idx = v2.load_index().unwrap();
    assert_eq!(idx.files.len(), 10, "5 + 5 个文件应全部持久化");
}

#[test]
fn filename_blacklist_keeps_unicode_and_hash() {
    let dir = tempdir("filename");
    let (mut v, _) = new_vault(&dir);

    // P1-3：黑名单策略 —— '#'、'@'、中文、emoji 都应保留原名
    let src = write_src(&dir, "report#1 v2.txt", "x".as_bytes());
    v.import_file(&src, "/report#1 v2.txt").unwrap();
    let idx = v.load_index().unwrap();
    let meta = idx.files.get("/report#1 v2.txt").expect("原 vpath 应存在");
    assert_eq!(meta.name, "report#1 v2.txt", "文件名不应被白名单改名");

    let src2 = write_src(&dir, "中文文件𝄞.txt", "y".as_bytes());
    v.import_file(&src2, "/d/中文文件𝄞.txt").unwrap();
    let idx = v.load_index().unwrap();
    assert!(idx.files.contains_key("/d/中文文件𝄞.txt"), "Unicode 文件名应保留");

    // 提取时 Windows 保留名被加前缀（黑名单策略的例外规则）
    let src3 = write_src(&dir, "CON.txt", "z".as_bytes());
    v.import_file(&src3, "/CON.txt").unwrap();
    let out = dir.join("out2");
    v.extract_file("/CON.txt", &out, true).unwrap();
    assert!(out.join("_CON.txt").exists(), "保留设备名应加下划线前缀");
}

#[test]
fn secure_delete_batch_removes_files_and_folders() {
    let dir = tempdir("batchdel");
    let (mut v, _) = new_vault(&dir);

    let srcs: Vec<String> = (0..3)
        .map(|i| {
            write_src(&dir, &format!("del{}.txt", i), "top secret".as_bytes())
                .to_string_lossy()
                .to_string()
        })
        .collect();
    v.import_files_batch(&srcs, "/sub").unwrap();

    let inner = write_src(&dir, "nested.txt", "n".as_bytes());
    v.import_file(&inner, "/sub2/nested.txt").unwrap();

    // 混合删除：2 个直接文件 + 1 个文件夹（含 1 个文件）
    let targets = vec![
        "/sub/del0.txt".to_string(),
        "/sub/del1.txt".to_string(),
        "/sub2".to_string(),
    ];
    let (files, folders) = v.secure_delete_files_batch(&targets).expect("批量删除失败");
    assert_eq!(files, 3, "2 个直接文件 + 文件夹内 1 个文件");
    assert_eq!(folders, 1);

    let idx = v.load_index().unwrap();
    assert!(!idx.files.contains_key("/sub/del0.txt"));
    assert!(!idx.files.contains_key("/sub/del1.txt"));
    assert!(idx.files.contains_key("/sub/del2.txt"), "未选中的文件保留");
    assert!(!idx.files.contains_key("/sub2/nested.txt"));
}

#[test]
fn index_cache_consistent_after_save_and_close() {
    let dir = tempdir("cachecoherence");
    let (mut v, path) = new_vault(&dir);

    let src = write_src(&dir, "a.txt", "a".as_bytes());
    v.import_file(&src, "/a.txt").unwrap();

    // P0-2：save_index 后内存缓存应刷新 —— 直接改索引再保存，随后 load 应看到变更
    {
        let mut idx = v.load_index().unwrap();
        idx.folders.insert("/made/by/test".to_string(), true);
        v.save_index(&idx).unwrap();
    }
    let idx2 = v.load_index().unwrap();
    assert!(idx2.folders.contains_key("/made/by/test"), "缓存应反映 save 后的索引");

    // close 清理缓存（含明文审计），重开后从磁盘加载仍是新状态
    v.close();
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None).unwrap();
    let idx3 = v2.load_index().unwrap();
    assert!(idx3.folders.contains_key("/made/by/test"));
    assert!(idx3.files.contains_key("/a.txt"));
}

#[test]
fn defragment_preserves_data_and_shrinks_file() {
    let dir = tempdir("defrag");
    let (mut v, path) = new_vault(&dir);

    // 导入 6 个文件
    let srcs: Vec<String> = (0..6)
        .map(|i| {
            write_src(&dir, &format!("d{}.bin", i), &vec![i as u8; 4096])
                .to_string_lossy()
                .to_string()
        })
        .collect();
    v.import_files_batch(&srcs, "/").unwrap();

    // 删掉一半制造空洞
    let del: Vec<String> = (0..3).map(|i| format!("/d{}.bin", i)).collect();
    v.secure_delete_files_batch(&del).unwrap();

    let size_before = fs::metadata(&path).unwrap().len();
    v.defragment_vault(None::<fn(usize)>).expect("碎片整理失败");
    let size_after = fs::metadata(&path).unwrap().len();
    assert!(size_after < size_before, "整理后文件应变小（{} → {}）", size_before, size_after);

    // 整理后剩余文件数据完整（索引偏移已被重写）
    for i in 3..6 {
        let data = v.load_file_data(&format!("/d{}.bin", i)).unwrap();
        assert_eq!(data, vec![i as u8; 4096], "整理后 /d{}.bin 数据损坏", i);
    }

    // 重开验证磁盘上的新布局
    drop(v);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None).unwrap();
    let idx = v2.load_index().unwrap();
    assert_eq!(idx.files.len(), 3);
}

#[test]
fn extract_all_files_counts() {
    let dir = tempdir("extractall");
    let (mut v, _) = new_vault(&dir);

    let srcs: Vec<String> = (0..4)
        .map(|i| {
            write_src(&dir, &format!("e{}.txt", i), "e".as_bytes())
                .to_string_lossy()
                .to_string()
        })
        .collect();
    v.import_files_batch(&srcs, "/x/y").unwrap();

    let out = dir.join("export");
    let (ok, fail) = v.extract_all_files(&out, true).unwrap();
    assert_eq!((ok, fail), (4, 0));
    // vault-name 根目录由 Tauri 命令层负责创建；核心 API 只保留虚拟路径层级
    assert!(out.join("x/y/e0.txt").exists(), "应保留虚拟路径层级 x/y/");
}

// ───────────────── 分区 ─────────────────

#[test]
fn partition_add_remove_and_wrong_partition_password() {
    let dir = tempdir("partition");
    let (mut v, path) = new_vault(&dir);

    v.add_partition("decoy", "decoy password 123", None).expect("添加分区失败");
    assert_eq!(v.get_partitions().len(), 2, "主分区 + 1 伪装分区");

    v.remove_partition("decoy").expect("删除分区失败");
    assert_eq!(v.get_partitions().len(), 1);

    // 重开后用伪装分区密码尝试：只能打开伪装分区（看不到主分区数据）
    drop(v);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, "decoy password 123", None)
        .expect_err("已删除的分区密码不应再有效");
}

// ───────────────── 分区别名（2.6.1 加固回归） ─────────────────

/// 新录入的别名必须是 ASCII-only：Unicode 字母（如全角/汉字）会被拒绝，
/// 防止「视觉同名」的分区别名混淆。合法 ASCII 别名不受影响。
#[test]
fn new_partition_alias_must_be_ascii_only() {
    let dir = tempdir("aliasascii");
    let (mut v, _) = new_vault(&dir);

    for bad in ["分区", "ｄｅｃｏｙ", "Décoy", "a\tb"] {
        assert!(
            v.add_partition(bad, "decoy password 123", None).is_err(),
            "非 ASCII / 控制字符别名应被拒绝: {:?}",
            bad
        );
    }
    // 合法 ASCII（字母/数字/下划线/短横线/空格）仍可通过
    v.add_partition("decoy 2", "decoy password 123", None)
        .expect("合法 ASCII 别名应通过");
    assert!(v.get_partitions().iter().any(|p| p.alias == "decoy 2"));
}

// ───────────────── 头部完整性（2.6.1 回归） ─────────────────

/// 多分区（real_count ≥ 2）下篡改头部条目也必须被捕获。
/// 旧实现以「头部声明的有效分区数 ≤ 1」为条件校验头部签名，多分区时整体跳过，
/// 导致头部可被静默篡改。新实现改用「绑定头部」的分区 auth_tag，无条件捕获。
#[test]
fn header_tamper_detected_even_with_multiple_partitions() {
    let dir = tempdir("headertamper");
    let (mut v, path) = new_vault(&dir);
    v.add_partition("decoy", "decoy password 123", None).expect("添加分区失败");
    drop(v);

    // 篡改主分区条目的别名字段（条目 0 偏移 = 106）。
    // 别名不参与锁定区 HMAC、也不参与密钥派生，旧实现在多分区下无法发现。
    let mut bytes = fs::read(&path).unwrap();
    bytes[106] ^= 0xFF;
    fs::write(&path, &bytes).unwrap();

    let mut v2 = Vault::default();
    assert!(
        v2.open_and_authenticate(&path, PWD, None).is_err(),
        "多分区保险柜的头部篡改必须导致认证失败（不得因分区数 ≥ 2 而跳过校验）"
    );
}

/// 单分区保险柜不得通过「注入带合法别名的伪条目」把头部完整性校验降级跳过。
/// 旧实现中：注入伪条目 → real_count 变为 2 → 头部签名校验被整体跳过 → 篡改可成功。
#[test]
fn fake_partition_cannot_downgrade_header_integrity() {
    let dir = tempdir("fakedowngrade");
    let (_, path) = new_vault(&dir);

    let mut b = fs::read(&path).unwrap();
    // 条目 1 偏移 = 106 + 96 = 202。整段别名先清零，再写入合法别名 "evil"，
    // 使 is_valid_alias 判定为真（把 real_count 抬到 2）。
    b[202..218].copy_from_slice(&[0u8; 16]);
    b[202..206].copy_from_slice(b"evil");
    // 同时篡改主分区别名（让头部与主分区 auth_tag 不再匹配）
    b[106] ^= 0xFF;
    fs::write(&path, &b).unwrap();

    let mut v = Vault::default();
    assert!(
        v.open_and_authenticate(&path, PWD, None).is_err(),
        "注入伪条目不得使头部完整性校验被跳过"
    );
}

// ───────────────── 虚拟路径校验（回归） ─────────────────

#[test]
fn vpath_validation_neutralizes_traversal() {
    let dir = tempdir("vpath");
    let (mut v, _) = new_vault(&dir);

    let src = write_src(&dir, "t.txt", "t".as_bytes());
    // 反斜杠 / 控制字符直接拒绝
    for bad in ["/a\\b.txt", "/a\u{0}b.txt", "/a\u{1}b.txt"] {
        let r = v.import_file(&src, bad);
        assert!(r.is_err(), "非法 vpath 应被拒绝: {:?}", bad);
    }

    // 「..」段被归一化中和到根内（不可能逃逸），落在 /evil.txt
    v.import_file(&src, "/../evil.txt").expect("遍历段应被归一化而非报错");
    let idx = v.load_index().unwrap();
    assert!(idx.files.contains_key("/evil.txt"), ".. 应被中和为根内路径");
    assert!(
        idx.files.keys().all(|k| k.starts_with('/')),
        "所有 vpath 必须以 / 开头"
    );

    // 无前导斜杠会被补齐
    v.import_file(&src, "plain.txt").unwrap();
    assert!(v.load_index().unwrap().files.contains_key("/plain.txt"));

    // 合法路径成功
    assert!(v.import_file(&src, "/ok/t.txt").is_ok());
}

// ───────────────── 重命名（回归） ─────────────────

/// 重命名只改索引 key，密文在原地不动（FileMeta 的 offset/length 被 `..meta` 原样保留）。
/// 因此解密时若拿「当前 vpath」当 AAD，重命名后 GCM 认证必然失败 —— 内容静默不可读。
#[test]
fn rename_file_keeps_content_readable() {
    let dir = tempdir("renamefile");
    let (mut v, path) = new_vault(&dir);

    let data = b"rename me \xe4\xbd\xa0\xe5\xa5\xbd payload".to_vec();
    let src = write_src(&dir, "before.bin", &data);
    v.import_file(&src, "/before.bin").unwrap();

    {
        let mut im = v.get_index_manager().unwrap();
        im.rename_file("/before.bin", "after.bin").expect("重命名失败");
    }

    let idx = v.load_index().unwrap();
    assert!(idx.files.contains_key("/after.bin"), "索引应指向新路径");
    assert!(!idx.files.contains_key("/before.bin"), "旧路径应消失");

    // 关键断言：密文没有被重新加密，重命名后必须仍能解密
    assert_eq!(
        v.load_file_data("/after.bin").expect("重命名后应仍能读取"),
        data
    );

    let out = dir.join("out");
    v.extract_file("/after.bin", &out, true).expect("重命名后应仍能提取");
    assert_eq!(fs::read(out.join("after.bin")).unwrap(), data);

    // 重开验证磁盘状态：排除内存索引缓存掩盖问题的可能
    drop(v);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None).unwrap();
    assert_eq!(
        v2.load_file_data("/after.bin").expect("重开后应仍能读取"),
        data
    );
}

/// rename_folder 会按 new_prefix 批量改写所有子文件的索引 key（index.rs），
/// 所以整个文件夹改名时，里面每个文件都会遭遇同一次 AAD 失配。
#[test]
fn rename_folder_keeps_children_readable() {
    let dir = tempdir("renamefolder");
    let (mut v, path) = new_vault(&dir);

    let a = b"child a".to_vec();
    let b = b"child b".to_vec();
    v.import_file(&write_src(&dir, "a.bin", &a), "/docs/a.bin").unwrap();
    v.import_file(&write_src(&dir, "b.bin", &b), "/docs/sub/b.bin").unwrap();

    {
        let mut im = v.get_index_manager().unwrap();
        im.rename_folder("/docs", "reference").expect("重命名文件夹失败");
    }

    let idx = v.load_index().unwrap();
    assert!(idx.folders.contains_key("/reference"), "文件夹应移到新路径");
    assert!(idx.files.contains_key("/reference/a.bin"), "一级子文件应随之移动");
    assert!(idx.files.contains_key("/reference/sub/b.bin"), "嵌套子文件也应随之移动");

    // 关键断言：一级与嵌套子文件都仍可解密
    assert_eq!(
        v.load_file_data("/reference/a.bin").expect("一级子文件应仍可读"),
        a
    );
    assert_eq!(
        v.load_file_data("/reference/sub/b.bin").expect("嵌套子文件应仍可读"),
        b
    );

    drop(v);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None).unwrap();
    assert_eq!(v2.load_file_data("/reference/sub/b.bin").unwrap(), b);
}

/// 兼容性契约：修复前写入的索引没有 aad_tag（反序列化后为 None），读取必须
/// 回退到当前 vpath —— 存量保险柜不能因为这次修复而读不出来。
/// 同时验证「重命名时才冻结」这条路径：旧条目在首次改名后即获得保护。
#[test]
fn legacy_index_without_aad_tag_still_readable() {
    let dir = tempdir("legacyaad");
    let (mut v, _) = new_vault(&dir);

    let data = b"legacy entry".to_vec();
    v.import_file(&write_src(&dir, "old.bin", &data), "/old.bin").unwrap();

    // 模拟修复前写入的索引条目：把冻结标识抹掉（等价于旧版本序列化出的 JSON）
    {
        let mut idx = v.load_index().unwrap();
        idx.files.get_mut("/old.bin").unwrap().aad_tag = None;
        v.save_index(&idx).unwrap();
    }

    // 回退路径：按当前 vpath 解密，仍应成功
    assert_eq!(
        v.load_file_data("/old.bin").expect("旧索引应回退到当前 vpath"),
        data
    );

    // 重命名时才冻结，冻结后仍可读
    {
        let mut im = v.get_index_manager().unwrap();
        im.rename_file("/old.bin", "renamed.bin").unwrap();
    }
    let idx = v.load_index().unwrap();
    assert_eq!(
        idx.files.get("/renamed.bin").unwrap().aad_tag.as_deref(),
        Some("/old.bin"),
        "重命名应把旧 vpath 冻结为 AAD"
    );
    assert_eq!(
        v.load_file_data("/renamed.bin").expect("冻结后应仍可读"),
        data
    );
}
