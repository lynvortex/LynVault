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
    // Windows：文件名为保留设备名（CON.txt 等）时，普通路径的 fs::write 会被
    // 路径归一化重写到设备本身——「成功」写进控制台/空设备而磁盘上无文件。
    // 一律改用 verbatim（\\?\）路径写入以禁用重写（对普通文件名行为不变）。
    #[cfg(windows)]
    if let Some(s) = p.as_os_str().to_str() {
        if !s.starts_with(r"\\?\") {
            let verbatim = if let Some(rest) = s.strip_prefix(r"\\") {
                format!(r"\\?\UNC\{}", rest)
            } else {
                format!(r"\\?\{}", s)
            };
            fs::write(verbatim, content).unwrap();
            return p;
        }
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
    v2.create(&path2, "密码密码密码密码密码密码", None)
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
    let (files, folders, reclaimed) = v.secure_delete_files_batch(&targets).expect("批量删除失败");
    assert_eq!(files, 3, "2 个直接文件 + 文件夹内 1 个文件");
    assert_eq!(folders, 1);
    assert!(reclaimed.is_none(), "小文件删除的死空间远低于阈值,不应自动整理");

    let idx = v.load_index().unwrap();
    assert!(!idx.files.contains_key("/sub/del0.txt"));
    assert!(!idx.files.contains_key("/sub/del1.txt"));
    assert!(idx.files.contains_key("/sub/del2.txt"), "未选中的文件保留");
    assert!(!idx.files.contains_key("/sub2/nested.txt"));
}

// 真实加密样本回归：Office 2007（COM 生成）的 Standard Encryption 文档，
// 口令 Password1234_。覆盖「Agile 之外的真实文件互通性」与 EncryptedPackage 流名。
#[test]
fn encrypted_office_2007_real_files() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for name in ["enc_test.docx", "enc_test.xlsx"] {
        let data = fs::read(base.join(name)).unwrap_or_else(|_| panic!("缺少测试样本 {}", name));
        // 无口令 → 哨兵错误
        assert_eq!(
            vault_core::office::extract_office_text(&data, name, None).unwrap_err(),
            "OFFICE_ENCRYPTED"
        );
        // 错误口令
        let err = vault_core::office::extract_office_text(&data, name, Some("wrong-password"))
            .unwrap_err();
        assert!(err.contains("密码错误"));
        // 正确口令
        let text = vault_core::office::extract_office_text(&data, name, Some("Password1234_"))
            .unwrap_or_else(|e| panic!("{} 解密失败: {}", name, e));
        assert!(text.contains("机密"), "{} 应解出文本: {}", name, text);
    }
}

#[test]
fn auto_defrag_after_large_delete_shrinks_file() {
    let dir = tempdir("autodefrag");
    let (mut v, vault_path) = new_vault(&dir);

    // 70 MiB 文件:删除后死空间 70 MiB ≥ 64 MiB 阈值,占比 ~100% ≥ 30%
    let big = write_src(&dir, "big.bin", &vec![0xABu8; 70 * 1024 * 1024]);
    v.import_file(&big, "/big.bin").unwrap();
    let len_before = fs::metadata(&vault_path).unwrap().len();

    let (files, folders, reclaimed) = v
        .secure_delete_files_batch(&["/big.bin".to_string()])
        .expect("批量删除失败");
    assert_eq!((files, folders), (1, 0));
    assert!(reclaimed.is_some(), "死空间 70 MiB 应触发自动整理");
    assert!(reclaimed.unwrap() >= 64 * 1024 * 1024);

    let len_after = fs::metadata(&vault_path).unwrap().len();
    assert!(len_after < len_before, "整理后文件应小于整理前");
    assert!(
        len_after < 5 * 1024 * 1024,
        "整理后文件应缩回头部+索引级别(实际 {} 字节)",
        len_after
    );
    assert!(v.load_index().unwrap().files.is_empty());
}

#[test]
fn auto_defrag_skipped_below_threshold() {
    let dir = tempdir("nodefrag");
    let (mut v, vault_path) = new_vault(&dir);

    let src = write_src(&dir, "small.txt", &vec![b'x'; 1024 * 1024]);
    v.import_file(&src, "/small.txt").unwrap();
    let len_before = fs::metadata(&vault_path).unwrap().len();

    let (_, _, reclaimed) = v
        .secure_delete_files_batch(&["/small.txt".to_string()])
        .expect("批量删除失败");
    assert!(reclaimed.is_none(), "死空间未达阈值不应自动整理");

    // 未整理时文件长度只会因追加新索引微涨,不可能缩回(整理会缩到 KB 级)
    let len_after = fs::metadata(&vault_path).unwrap().len();
    assert!(len_after >= len_before, "未达阈值时不应回收空间");
}

#[test]
fn auto_defrag_skipped_for_multi_partition() {
    let dir = tempdir("mpnodefrag");
    let (mut v, _) = new_vault(&dir);
    v.add_partition("Decoy", "decoy-password-123", None).unwrap();

    let big = write_src(&dir, "big2.bin", &vec![0xCDu8; 70 * 1024 * 1024]);
    v.import_file(&big, "/big2.bin").unwrap();

    // 多分区整理不回收空间,自动触发没有收益 —— 应跳过
    let (_, _, reclaimed) = v
        .secure_delete_files_batch(&["/big2.bin".to_string()])
        .expect("批量删除失败");
    assert!(reclaimed.is_none(), "多分区保险柜不应自动整理");
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
        v.save_index(idx).unwrap();
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
    // 2.8.0（v5）：条目 1 偏移 = 106 + 192 = 298。整段别名先清零，再写入合法别名
    // "evil"，使 is_plausible_alias 判定为真（把真实分区数抬到 2）。
    b[298..314].copy_from_slice(&[0u8; 16]);
    b[298..302].copy_from_slice(b"evil");
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
        v.save_index(idx).unwrap();
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

// ───────────────── 2.7.1 回归 ─────────────────

/// 创建保险柜不得覆盖已有保险柜：create_new 优先 —— 目标已存在（即便已被换成
/// 另一个保险柜）时直接拒绝，且拒绝后原件必须完好可用。旧实现「先 is_vault_file
/// 检查再 create+truncate」的两步之间存在竞态，检查失效时会把另一个保险柜清零。
#[test]
fn create_refuses_to_overwrite_existing_vault() {
    let dir = tempdir("noclobber");
    let (mut v, path) = new_vault(&dir);
    let data = b"precious payload".to_vec();
    v.import_file(&write_src(&dir, "p.bin", &data), "/p.bin").unwrap();
    drop(v);

    let mut v2 = Vault::default();
    assert!(
        v2.create(&path, "another password 123", None).is_err(),
        "创建必须拒绝覆盖已有保险柜"
    );
    assert!(!v2.is_open());

    // 拒绝后原件完好：仍可用原密码打开并读出数据
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, PWD, None)
        .expect("拒绝覆盖后原件必须完好");
    assert_eq!(v3.load_file_data("/p.bin").unwrap(), data);
}

/// 三个删除入口（secure_delete_file / secure_delete_files_batch / delete_folder）
/// 统一按索引键规则归一化：`/docs//a.txt`、`/docs/./a.txt`、带尾斜杠的输入都能
/// 命中；删除根目录明确报错。
#[test]
fn delete_entries_normalize_vpath() {
    let dir = tempdir("delnorm");
    let (mut v, _) = new_vault(&dir);
    v.import_file(&write_src(&dir, "a.txt", b"a"), "/docs/a.txt").unwrap();
    v.import_file(&write_src(&dir, "b.txt", b"b"), "/docs/b.txt").unwrap();

    // 批量删除：冗余斜杠输入命中
    let (files, _, _) = v
        .secure_delete_files_batch(&["/docs//b.txt".to_string()])
        .expect("批量删除失败");
    assert_eq!(files, 1, "归一化后应命中 /docs/b.txt");

    // 单文件删除：'.' 段输入命中
    let reclaimed = v.secure_delete_file("/docs/./a.txt").expect("单文件删除失败");
    assert!(reclaimed.is_none(), "小文件删除不应触发自动整理");

    // 文件夹删除：尾斜杠输入命中；根目录明确报错
    v.import_file(&write_src(&dir, "c.txt", b"c"), "/more/c.txt").unwrap();
    assert!(v.delete_folder("/").is_err(), "删除根目录应明确报错");
    let reclaimed = v.delete_folder("/more/").expect("文件夹删除失败");
    assert!(reclaimed.is_none());

    let idx = v.load_index().unwrap();
    assert!(
        idx.files.is_empty(),
        "三种输入形式都应命中删除（仍剩 {} 项）",
        idx.files.len()
    );
}

// ───────────────── 2.8.0：v5 信封加密 / 改密码 / 升级 ─────────────────

/// v4 旧格式夹具（兼容路径回归测试用）
fn new_vault_v4(dir: &Path) -> (Vault, PathBuf) {
    let path = dir.join("test-v4.lyt");
    let mut v = Vault::default();
    v.create_v4_for_tests(&path, PWD, None).expect("创建 v4 保险柜失败");
    (v, path)
}

/// 新建保险柜必须是 v5（信封加密），且头部版本字节 = 5、头部 2048 字节
#[test]
fn v5_create_uses_envelope_format() {
    let dir = tempdir("v5create");
    let (_, path) = new_vault(&dir);
    let b = fs::read(&path).unwrap();
    assert_eq!(&b[..8], b"PYVAULT4", "magic 保持不变（识别路径依赖）");
    assert_eq!(b[8], 5, "新建保险柜应为 v5 格式");
    assert!(b.len() >= 2048, "v5 头部为 2048 字节");
}

/// v4 旧保险柜仍可打开、改名后仍可读（只读兼容）
#[test]
fn v4_vault_opens_and_rename_keeps_readable() {
    let dir = tempdir("v4compat");
    let (mut v, path) = new_vault_v4(&dir);
    let src = write_src(&dir, "a.txt", b"v4 content");
    v.import_file(&src, "/a.txt").unwrap();
    v.get_index_manager().unwrap().rename_file("/a.txt", "b.txt").unwrap();
    let data = v.load_file_data("/b.txt").unwrap();
    assert_eq!(data, b"v4 content");
    drop(v);

    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None).expect("v4 保险柜应能打开");
    let data = v2.load_file_data("/b.txt").unwrap();
    assert_eq!(data, b"v4 content");
}

/// v4 保险柜的锁定区 / 篡改检测在新版本下依旧生效
#[test]
fn v4_tamper_still_detected() {
    let dir = tempdir("v4tamper");
    let (_, path) = new_vault_v4(&dir);
    let mut b = fs::read(&path).unwrap();
    b[106] ^= 0xFF; // 条目 0 别名（v4 布局）
    fs::write(&path, &b).unwrap();
    let mut v = Vault::default();
    assert!(v.open_and_authenticate(&path, PWD, None).is_err(), "v4 头部篡改必须被捕获");
}

/// v5 改密码：头部级操作 —— 文件数据偏移/长度完全不变，新密码可开、旧密码失效
#[test]
fn v5_change_password_is_header_only() {
    let dir = tempdir("v5chg");
    let (mut v, path) = new_vault(&dir);
    let src = write_src(&dir, "doc.txt", b"secret content for change test");
    v.import_file(&src, "/doc.txt").unwrap();
    let before: Vec<(u64, u64)> = v.load_index().unwrap().files.values()
        .map(|m| (m.offset, m.length)).collect();
    let file_len_before = fs::metadata(&path).unwrap().len();

    v.change_password(PWD, "brand new password 123", None, None::<fn(usize)>)
        .expect("v5 改密码失败");
    let after: Vec<(u64, u64)> = v.load_index().unwrap().files.values()
        .map(|m| (m.offset, m.length)).collect();
    assert_eq!(before, after, "v5 改密码不得触碰数据区（偏移应逐字节一致）");
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        file_len_before,
        "v5 改密码不得改变文件长度"
    );
    drop(v);

    // 旧密码失效
    let mut v2 = Vault::default();
    assert!(v2.open_and_authenticate(&path, PWD, None).is_err(), "旧密码应被拒绝");
    // 新密码可开，内容完好
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, "brand new password 123", None)
        .expect("新密码应能打开");
    assert_eq!(v3.load_file_data("/doc.txt").unwrap(), b"secret content for change test");
}

/// v5 改密码必须验证当前密码（防未锁屏时被改密锁死）
#[test]
fn v5_change_password_requires_current_password() {
    let dir = tempdir("v5chgverify");
    let (mut v, _) = new_vault(&dir);
    let r = v.change_password("wrong current password!", "brand new password 123", None, None::<fn(usize)>);
    assert!(r.is_err(), "当前密码错误必须被拒绝");
}

/// v4 → v5 升级（改密码触发）：数据完好、格式变为 v5、旧密码失效、审计链保留
#[test]
fn v4_change_password_upgrades_to_v5() {
    let dir = tempdir("v4upgrade");
    let (mut v, path) = new_vault_v4(&dir);
    let src = write_src(&dir, "doc.txt", b"upgrade me");
    v.import_file(&src, "/doc.txt").unwrap();
    drop(v);

    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None).unwrap();
    v2.change_password(PWD, "upgraded password 456", None, None::<fn(usize)>)
        .expect("v4→v5 升级失败");
    drop(v2);

    let b = fs::read(&path).unwrap();
    assert_eq!(b[8], 5, "升级后应为 v5 格式");
    assert!(b.len() >= 2048, "升级后头部应为 2048 字节");

    // 旧密码失效，新密码可开，内容完好
    let mut v3 = Vault::default();
    assert!(v3.open_and_authenticate(&path, PWD, None).is_err(), "旧密码应被拒绝");
    let mut v4 = Vault::default();
    v4.open_and_authenticate(&path, "upgraded password 456", None)
        .expect("新密码应能打开升级后的保险柜");
    assert_eq!(v4.load_file_data("/doc.txt").unwrap(), b"upgrade me");
}

/// 多分区 v4 保险柜改密码必须明确报错（其余分区口令未知，无法生成包裹密钥）
#[test]
fn v4_multi_partition_change_password_rejected() {
    let dir = tempdir("v4multi");
    let (mut v, _) = new_vault_v4(&dir);
    v.add_partition("decoy", "decoy password 123", None).unwrap();
    let r = v.change_password(PWD, "brand new password 123", None, None::<fn(usize)>);
    assert!(r.is_err(), "多分区 v4 改密码应被拒绝");
}

/// v5 改密码后头部篡改仍能被检出（auth_tag 重新绑定新盐）
#[test]
fn v5_tamper_after_password_change_detected() {
    let dir = tempdir("v5chgtamper");
    let (mut v, path) = new_vault(&dir);
    v.change_password(PWD, "brand new password 123", None, None::<fn(usize)>).unwrap();
    drop(v);
    let mut b = fs::read(&path).unwrap();
    b[106] ^= 0xFF; // 条目 0 别名（v5 布局同样起始于 106）
    fs::write(&path, &b).unwrap();
    let mut v2 = Vault::default();
    assert!(v2.open_and_authenticate(&path, "brand new password 123", None).is_err());
}

// ───────────────── 2.8.0：移动 / 搜索 / 完整性体检 / 锁定信息 ─────────────────

/// 移动文件与文件夹：内容可读、冲突拒绝、移入自身子目录拒绝
#[test]
fn move_file_and_folder_keeps_content_readable() {
    let dir = tempdir("move");
    let (mut v, _) = new_vault(&dir);
    v.get_index_manager().unwrap().add_folder("/docs").unwrap();
    v.get_index_manager().unwrap().add_folder("/docs/sub").unwrap();
    v.get_index_manager().unwrap().add_folder("/archive").unwrap();
    let src = write_src(&dir, "a.txt", b"move me");
    v.import_file(&src, "/a.txt").unwrap();
    v.import_file(&write_src(&dir, "b.txt", b"nested"), "/docs/sub/b.txt").unwrap();

    // 文件移动：根 → /docs
    v.get_index_manager().unwrap().move_file("/a.txt", "/docs").unwrap();
    assert_eq!(v.load_file_data("/docs/a.txt").unwrap(), b"move me");
    assert!(!v.load_index().unwrap().files.contains_key("/a.txt"));

    // 文件夹移动：/docs → /archive（子树整体迁移，内容仍可读）
    v.get_index_manager().unwrap().move_folder("/docs", "/archive").unwrap();
    let idx = v.load_index().unwrap();
    assert!(idx.files.contains_key("/archive/docs/a.txt"), "文件应随子树迁移");
    assert!(idx.files.contains_key("/archive/docs/sub/b.txt"), "子目录文件应随子树迁移");
    assert!(!idx.folders.contains_key("/docs"), "原文件夹条目应消失");
    drop(v);

    // 重开后内容仍可读（持久化正确）
    let (_, path) = ((), dir.join("test.lyt"));
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None).unwrap();
    assert_eq!(v2.load_file_data("/archive/docs/sub/b.txt").unwrap(), b"nested");
}

/// 移动冲突与非法目标
#[test]
fn move_conflicts_rejected() {
    let dir = tempdir("moveconflict");
    let (mut v, _) = new_vault(&dir);
    v.get_index_manager().unwrap().add_folder("/docs").unwrap();
    v.import_file(&write_src(&dir, "a.txt", b"A"), "/a.txt").unwrap();
    v.import_file(&write_src(&dir, "b.txt", b"B"), "/docs/b.txt").unwrap();
    // 在 /docs 下再放一个同名 a.txt，制造真正的同名冲突
    v.import_file(&write_src(&dir, "a2.txt", b"A2"), "/docs/a.txt").unwrap();

    // 同名冲突
    let r = v.get_index_manager().unwrap().move_file("/a.txt", "/docs");
    assert!(r.is_err(), "同名冲突应被拒绝");
    // 目标文件夹不存在
    let r = v.get_index_manager().unwrap().move_file("/a.txt", "/nowhere");
    assert!(r.is_err(), "目标文件夹不存在应被拒绝");
    // 文件夹移入自身子目录
    let r = v.get_index_manager().unwrap().move_folder("/docs", "/docs");
    assert!(r.is_err(), "文件夹移入自身应被拒绝");
    // 数据未被破坏（冲突后原文件仍可读）
    assert_eq!(v.load_file_data("/a.txt").unwrap(), b"A");
    assert_eq!(v.load_file_data("/docs/b.txt").unwrap(), b"B");
}

/// 完整性体检：完好库全部通过；翻转密文字节后能定位损坏文件
#[test]
fn verify_integrity_detects_tampering() {
    let dir = tempdir("verify");
    let (mut v, path) = new_vault(&dir);
    v.import_file(&write_src(&dir, "ok.txt", b"fine"), "/ok.txt").unwrap();
    let (total, broken) = v.verify_integrity(None::<fn(usize, usize, &str)>).unwrap();
    assert_eq!(total, 1);
    assert!(broken.is_empty(), "完好库不应有异常");
    drop(v);

    // 篡改文件密文（数据区从 2048 开始；索引在最前，其后是文件数据）
    let meta_off = {
        let mut v = Vault::default();
        v.open_and_authenticate(&path, PWD, None).unwrap();
        v.load_index().unwrap().files.get("/ok.txt").unwrap().offset
    };
    let mut b = fs::read(&path).unwrap();
    b[meta_off as usize + 20] ^= 0xFF;
    fs::write(&path, &b).unwrap();

    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None).unwrap();
    let (total, broken) = v2.verify_integrity(None::<fn(usize, usize, &str)>).unwrap();
    assert_eq!(total, 1);
    assert_eq!(broken.len(), 1, "篡改必须被检出");
    assert_eq!(broken[0].vpath, "/ok.txt");
}

/// 搜索：文件名与 vpath 大小写不敏感匹配
#[test]
fn search_files_matches_name_and_vpath() {
    let dir = tempdir("search");
    let (mut v, _) = new_vault(&dir);
    v.get_index_manager().unwrap().add_folder("/Reports").unwrap();
    v.import_file(&write_src(&dir, "Q3-Summary.txt", b"x"), "/Reports/Q3-Summary.txt").unwrap();
    v.import_file(&write_src(&dir, "other.txt", b"y"), "/other.txt").unwrap();

    let hits = v.search_files("q3", 50);
    assert_eq!(hits.len(), 1, "应命中 /Reports/Q3-Summary.txt（vpath 包含 q3）");
    assert!(!hits[0].is_dir);
    let hits = v.search_files("reports", 50);
    assert_eq!(hits.len(), 2, "应命中文件夹 /Reports 及其下文件（vpath 包含）");
    assert!(hits[0].is_dir, "文件夹条目应标记 is_dir 且排在前面");
    let hits = v.search_files("summary", 50);
    assert!(hits.iter().any(|h| h.name.contains("Q3-Summary")));
    let hits = v.search_files("zzz-not-exist", 50);
    assert!(hits.is_empty());
}

/// 锁定信息：错误密码尝试后计数递增，UI 可在开锁前展示
#[test]
fn read_lock_info_reports_failed_attempts() {
    let dir = tempdir("lockinfo");
    let (_, path) = new_vault(&dir);
    let info = vault_core::read_lock_info(&path).unwrap();
    assert_eq!(info.failed_count, 0, "新库应为 0 次失败");
    assert!(!info.locked);

    // 一次错误尝试（真实打开路径会写入锁定区）
    let mut v = Vault::default();
    assert!(v.open_and_authenticate(&path, "wrong password 123", None).is_err());
    let info = vault_core::read_lock_info(&path).unwrap();
    assert_eq!(info.failed_count, 1, "失败尝试应被记录");
    assert!(!info.locked, "1 次失败不应触发锁定");
}

/// 2.8.1：file/folder 交叉命名空间碰撞必须被拒绝（防 rename/delete 语义含混）
#[test]
fn file_folder_collision_rejected() {
    let dir = tempdir("collision");
    let (mut v, _) = new_vault(&dir);
    // 先建文件 /docs，再建同名文件夹应被拒绝
    v.import_file(&write_src(&dir, "d.txt", b"D"), "/docs").unwrap();
    assert!(
        v.get_index_manager().unwrap().add_folder("/docs").is_err(),
        "同名文件夹应被拒绝"
    );
    // 反向：先建文件夹 /x，再导入同名文件应被拒绝
    v.get_index_manager().unwrap().add_folder("/x").unwrap();
    assert!(
        v.import_file(&write_src(&dir, "y.txt", b"Y"), "/x").is_err(),
        "同名文件应被拒绝"
    );
    // 拒绝后两命名空间各自完好
    let idx = v.load_index().unwrap();
    assert!(idx.files.contains_key("/docs"));
    assert!(idx.folders.contains_key("/x"));
}

/// 2.8.1：批量移动单次索引落盘 —— 内容可读、计数正确、混合失败正确
#[test]
fn move_items_batch_single_pass() {
    let dir = tempdir("movebatch");
    let (mut v, _) = new_vault(&dir);
    v.get_index_manager().unwrap().add_folder("/dst").unwrap();
    for i in 0..10 {
        let name = format!("f{}.txt", i);
        v.import_file(&write_src(&dir, &name, format!("content-{}", i).as_bytes()), &format!("/f{}.txt", i)).unwrap();
    }
    let count_before = v.load_index().unwrap().files.len();
    let vpaths: Vec<String> = (0..10).map(|i| format!("/f{}.txt", i)).collect();
    let (ok, fail, errors) = v.get_index_manager().unwrap().move_items(&vpaths, "/dst").unwrap();
    assert_eq!(ok, 10);
    assert_eq!(fail, 0);
    assert!(errors.is_empty());
    let idx = v.load_index().unwrap();
    assert_eq!(idx.files.len(), count_before, "移动不增减条目数");
    for i in 0..10 {
        let vp = format!("/dst/f{}.txt", i);
        assert!(idx.files.contains_key(&vp), "{} 应在 /dst 下", vp);
        assert_eq!(
            v.load_file_data(&vp).unwrap(),
            format!("content-{}", i).into_bytes(),
            "移动后内容必须完好"
        );
    }
    // 混合失败：不存在的文件 + 非法的根路径
    let bad: Vec<String> = vec!["/ghost.txt".to_string(), "/".to_string()];
    let (ok2, fail2, _) = v.get_index_manager().unwrap().move_items(&bad, "/dst").unwrap();
    assert_eq!(ok2, 0);
    assert_eq!(fail2, 2);
}
