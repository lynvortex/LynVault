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
    assert!(
        vault_core::is_vault_file(&path),
        "is_vault_file 应识别刚创建的保险柜"
    );

    // 同名但非保险柜的文件（magic 不匹配）必须被拒绝
    let fake = write_src(&dir, "fake.lyt", b"not a lynvault file at all....");
    assert!(
        !vault_core::is_vault_file(&fake),
        "magic 不匹配的 .lyt 不应被识别"
    );

    // 空文件 / 不存在文件
    assert!(!vault_core::is_vault_file(&dir.join("nonexistent.lyt")));
}

#[test]
fn wrong_password_rejected() {
    let dir = tempdir("wrongpwd");
    let (_, path) = new_vault(&dir);

    let mut v2 = Vault::default();
    let r = v2.open_and_authenticate(&path, "wrong password!!!!!", None, None);
    assert!(r.is_err(), "错误密码必须被拒绝");
    assert!(!v2.is_open());
}

#[test]
fn password_length_by_char_count() {
    let dir = tempdir("pwdlen");
    let path = dir.join("t.lyt");

    // P2-19：按字符数校验 —— 11 个 ASCII 字符拒绝
    let mut v = Vault::default();
    assert!(
        v.create(&path, "abcdefghijk", None).is_err(),
        "11 字符应被拒绝"
    );
    // 12 个 ASCII 字符通过
    v.create(&path, "abcdefghijkl", None)
        .expect("12 字符应通过");
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
    v.extract_file("/payload.bin", &out, true)
        .expect("提取失败");
    assert_eq!(fs::read(out.join("payload.bin")).unwrap(), data);
}

#[test]
fn import_files_batch_counts_and_persists() {
    let dir = tempdir("batchimport");
    let (mut v, path) = new_vault(&dir);

    let srcs: Vec<String> = (0..5)
        .map(|i| {
            write_src(
                &dir,
                &format!("f{}.txt", i),
                format!("content-{}", i).as_bytes(),
            )
            .to_string_lossy()
            .to_string()
        })
        .collect();
    let (ok, fail, _errors) = v
        .import_files_batch(&srcs, "/", None, None)
        .expect("批量导入失败");
    assert_eq!((ok, fail), (5, 0));

    // 不存在的文件计入失败，不影响其余导入
    let mut with_bad = srcs.clone();
    with_bad.push(dir.join("no_such_file.bin").to_string_lossy().to_string());
    let (ok2, fail2, errors2) = v
        .import_files_batch(&with_bad, "/dir2", None, None)
        .expect("批量导入（含失败项）不应整体失败");
    assert_eq!((ok2, fail2), (5, 1));
    assert_eq!(errors2.len(), 1, "失败明细应随返回值给出");

    // 重新打开验证持久化（同时验证索引缓存路径与磁盘一致）
    drop(v);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None)
        .expect("重开失败");
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
    assert!(
        idx.files.contains_key("/d/中文文件𝄞.txt"),
        "Unicode 文件名应保留"
    );

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
    v.import_files_batch(&srcs, "/sub", None, None).unwrap();

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
    assert!(
        reclaimed.is_none(),
        "小文件删除的死空间远低于阈值,不应自动整理"
    );

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
    v.add_partition("Decoy", "decoy-password-123", None)
        .unwrap();

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
    assert!(
        idx2.folders.contains_key("/made/by/test"),
        "缓存应反映 save 后的索引"
    );

    // close 清理缓存（含明文审计），重开后从磁盘加载仍是新状态
    v.close();
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
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
    v.import_files_batch(&srcs, "/", None, None).unwrap();

    // 删掉一半制造空洞
    let del: Vec<String> = (0..3).map(|i| format!("/d{}.bin", i)).collect();
    v.secure_delete_files_batch(&del).unwrap();

    let size_before = fs::metadata(&path).unwrap().len();
    v.defragment_vault(None::<fn(usize)>).expect("碎片整理失败");
    let size_after = fs::metadata(&path).unwrap().len();
    assert!(
        size_after < size_before,
        "整理后文件应变小（{} → {}）",
        size_before,
        size_after
    );

    // 整理后剩余文件数据完整（索引偏移已被重写）
    for i in 3..6 {
        let data = v.load_file_data(&format!("/d{}.bin", i)).unwrap();
        assert_eq!(data, vec![i as u8; 4096], "整理后 /d{}.bin 数据损坏", i);
    }

    // 重开验证磁盘上的新布局
    drop(v);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
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
    v.import_files_batch(&srcs, "/x/y", None, None).unwrap();

    let out = dir.join("export");
    let (ok, fail, _errors) = v.extract_all_files(&out, true, None, None).unwrap();
    assert_eq!((ok, fail), (4, 0));
    // vault-name 根目录由 Tauri 命令层负责创建；核心 API 只保留虚拟路径层级
    assert!(out.join("x/y/e0.txt").exists(), "应保留虚拟路径层级 x/y/");
}

// ───────────────── 分区 ─────────────────

#[test]
fn partition_add_remove_and_wrong_partition_password() {
    let dir = tempdir("partition");
    let (mut v, path) = new_vault(&dir);

    v.add_partition("decoy", "decoy password 123", None)
        .expect("添加分区失败");
    assert_eq!(v.get_partitions().len(), 2, "主分区 + 1 伪装分区");

    v.remove_partition("decoy").expect("删除分区失败");
    assert_eq!(v.get_partitions().len(), 1);

    // 重开后用伪装分区密码尝试：只能打开伪装分区（看不到主分区数据）
    drop(v);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, "decoy password 123", None, None)
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
    v.add_partition("decoy", "decoy password 123", None)
        .expect("添加分区失败");
    drop(v);

    // 篡改主分区条目的别名字段（条目 0 偏移 = 106）。
    // 别名不参与锁定区 HMAC、也不参与密钥派生，旧实现在多分区下无法发现。
    let mut bytes = fs::read(&path).unwrap();
    bytes[106] ^= 0xFF;
    fs::write(&path, &bytes).unwrap();

    let mut v2 = Vault::default();
    assert!(
        v2.open_and_authenticate(&path, PWD, None, None).is_err(),
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
        v.open_and_authenticate(&path, PWD, None, None).is_err(),
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

    // 2.8.2：越过根的「..」直接拒绝（旧行为是静默中和到根内路径，语义出人意料）
    let r = v.import_file(&src, "/../evil.txt");
    assert!(r.is_err(), "越过根的 .. 应被拒绝而非静默重定向");
    // 段内的「..」仍正常中和到根内
    v.import_file(&src, "/docs/../evil.txt")
        .expect("段内 .. 应被中和");
    let idx = v.load_index().unwrap();
    assert!(
        idx.files.contains_key("/evil.txt"),
        "段内 .. 应被中和为根内路径"
    );
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
        im.rename_file("/before.bin", "after.bin")
            .expect("重命名失败");
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
    v.extract_file("/after.bin", &out, true)
        .expect("重命名后应仍能提取");
    assert_eq!(fs::read(out.join("after.bin")).unwrap(), data);

    // 重开验证磁盘状态：排除内存索引缓存掩盖问题的可能
    drop(v);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
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
    v.import_file(&write_src(&dir, "a.bin", &a), "/docs/a.bin")
        .unwrap();
    v.import_file(&write_src(&dir, "b.bin", &b), "/docs/sub/b.bin")
        .unwrap();

    {
        let mut im = v.get_index_manager().unwrap();
        im.rename_folder("/docs", "reference")
            .expect("重命名文件夹失败");
    }

    let idx = v.load_index().unwrap();
    assert!(idx.folders.contains_key("/reference"), "文件夹应移到新路径");
    assert!(
        idx.files.contains_key("/reference/a.bin"),
        "一级子文件应随之移动"
    );
    assert!(
        idx.files.contains_key("/reference/sub/b.bin"),
        "嵌套子文件也应随之移动"
    );

    // 关键断言：一级与嵌套子文件都仍可解密
    assert_eq!(
        v.load_file_data("/reference/a.bin")
            .expect("一级子文件应仍可读"),
        a
    );
    assert_eq!(
        v.load_file_data("/reference/sub/b.bin")
            .expect("嵌套子文件应仍可读"),
        b
    );

    drop(v);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
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
    v.import_file(&write_src(&dir, "old.bin", &data), "/old.bin")
        .unwrap();

    // 模拟修复前写入的索引条目：把冻结标识抹掉（等价于旧版本序列化出的 JSON）
    {
        let mut idx = v.load_index().unwrap();
        idx.files.get_mut("/old.bin").unwrap().aad_tag = None;
        v.save_index(idx).unwrap();
    }

    // 回退路径：按当前 vpath 解密，仍应成功
    assert_eq!(
        v.load_file_data("/old.bin")
            .expect("旧索引应回退到当前 vpath"),
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
    v.import_file(&write_src(&dir, "p.bin", &data), "/p.bin")
        .unwrap();
    drop(v);

    let mut v2 = Vault::default();
    assert!(
        v2.create(&path, "another password 123", None).is_err(),
        "创建必须拒绝覆盖已有保险柜"
    );
    assert!(!v2.is_open());

    // 拒绝后原件完好：仍可用原密码打开并读出数据
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, PWD, None, None)
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
    v.import_file(&write_src(&dir, "a.txt", b"a"), "/docs/a.txt")
        .unwrap();
    v.import_file(&write_src(&dir, "b.txt", b"b"), "/docs/b.txt")
        .unwrap();

    // 批量删除：冗余斜杠输入命中
    let (files, _, _) = v
        .secure_delete_files_batch(&["/docs//b.txt".to_string()])
        .expect("批量删除失败");
    assert_eq!(files, 1, "归一化后应命中 /docs/b.txt");

    // 单文件删除：'.' 段输入命中
    let reclaimed = v
        .secure_delete_file("/docs/./a.txt")
        .expect("单文件删除失败");
    assert!(reclaimed.is_none(), "小文件删除不应触发自动整理");

    // 文件夹删除：尾斜杠输入命中；根目录明确报错
    v.import_file(&write_src(&dir, "c.txt", b"c"), "/more/c.txt")
        .unwrap();
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
    v.create_v4_for_tests(&path, PWD, None)
        .expect("创建 v4 保险柜失败");
    (v, path)
}

/// 新建保险柜必须是 v5（信封加密），且头部版本字节 = 5、头部 2048 字节
#[test]
fn v5_create_uses_envelope_format() {
    let dir = tempdir("v5create");
    let (_, path) = new_vault(&dir);
    let b = fs::read(&path).unwrap();
    assert_eq!(&b[..8], b"PYVAULT4", "magic 保持不变（识别路径依赖）");
    assert_eq!(b[8], 6, "3.0.0 起新建保险柜应为 v6 流式格式");
    assert!(b.len() >= 2048, "v6 头部与 v5 同为 2048 字节");
}

/// v4 旧保险柜仍可打开、改名后仍可读（只读兼容）
#[test]
fn v4_vault_opens_and_rename_keeps_readable() {
    let dir = tempdir("v4compat");
    let (mut v, path) = new_vault_v4(&dir);
    let src = write_src(&dir, "a.txt", b"v4 content");
    v.import_file(&src, "/a.txt").unwrap();
    v.get_index_manager()
        .unwrap()
        .rename_file("/a.txt", "b.txt")
        .unwrap();
    let data = v.load_file_data("/b.txt").unwrap();
    assert_eq!(data, b"v4 content");
    drop(v);

    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None)
        .expect("v4 保险柜应能打开");
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
    assert!(
        v.open_and_authenticate(&path, PWD, None, None).is_err(),
        "v4 头部篡改必须被捕获"
    );
}

/// v5 改密码：头部级操作 —— 文件数据偏移/长度完全不变，新密码可开、旧密码失效
#[test]
fn v5_change_password_is_header_only() {
    let dir = tempdir("v5chg");
    let (mut v, path) = new_vault(&dir);
    let src = write_src(&dir, "doc.txt", b"secret content for change test");
    v.import_file(&src, "/doc.txt").unwrap();
    let before: Vec<(u64, u64)> = v
        .load_index()
        .unwrap()
        .files
        .values()
        .map(|m| (m.offset, m.length))
        .collect();
    let file_len_before = fs::metadata(&path).unwrap().len();

    v.change_password(PWD, "brand new password 123", None, None::<fn(usize)>, None)
        .expect("v5 改密码失败");
    let after: Vec<(u64, u64)> = v
        .load_index()
        .unwrap()
        .files
        .values()
        .map(|m| (m.offset, m.length))
        .collect();
    assert_eq!(before, after, "v5 改密码不得触碰数据区（偏移应逐字节一致）");
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        file_len_before,
        "v5 改密码不得改变文件长度"
    );
    drop(v);

    // 旧密码失效
    let mut v2 = Vault::default();
    assert!(
        v2.open_and_authenticate(&path, PWD, None, None).is_err(),
        "旧密码应被拒绝"
    );
    // 新密码可开，内容完好
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, "brand new password 123", None, None)
        .expect("新密码应能打开");
    assert_eq!(
        v3.load_file_data("/doc.txt").unwrap(),
        b"secret content for change test"
    );
}

/// v5 改密码必须验证当前密码（防未锁屏时被改密锁死）
#[test]
fn v5_change_password_requires_current_password() {
    let dir = tempdir("v5chgverify");
    let (mut v, _) = new_vault(&dir);
    let r = v.change_password(
        "wrong current password!",
        "brand new password 123",
        None,
        None::<fn(usize)>,
        None,
    );
    assert!(r.is_err(), "当前密码错误必须被拒绝");
}

/// v4 → v5 升级（改密码触发）：数据完好、格式变为 v5、旧密码失效、审计链保留
#[test]
fn v4_change_password_upgrades_to_v6() {
    let dir = tempdir("v4upgrade");
    let (mut v, path) = new_vault_v4(&dir);
    let src = write_src(&dir, "doc.txt", b"upgrade me");
    v.import_file(&src, "/doc.txt").unwrap();
    drop(v);

    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
    v2.change_password(PWD, "upgraded password 456", None, None::<fn(usize)>, None)
        .expect("v4→v6 升级失败");
    drop(v2);

    let b = fs::read(&path).unwrap();
    assert_eq!(b[8], 6, "3.0.0 起升级后应为 v6 流式格式");
    assert!(b.len() >= 2048, "升级后头部应为 2048 字节");

    // 旧密码失效，新密码可开，内容完好
    let mut v3 = Vault::default();
    assert!(
        v3.open_and_authenticate(&path, PWD, None, None).is_err(),
        "旧密码应被拒绝"
    );
    let mut v4 = Vault::default();
    v4.open_and_authenticate(&path, "upgraded password 456", None, None)
        .expect("新密码应能打开升级后的保险柜");
    assert_eq!(v4.load_file_data("/doc.txt").unwrap(), b"upgrade me");
}

/// 多分区 v4 保险柜改密码必须明确报错（其余分区口令未知，无法生成包裹密钥）
#[test]
fn v4_multi_partition_change_password_rejected() {
    let dir = tempdir("v4multi");
    let (mut v, _) = new_vault_v4(&dir);
    v.add_partition("decoy", "decoy password 123", None)
        .unwrap();
    let r = v.change_password(PWD, "brand new password 123", None, None::<fn(usize)>, None);
    assert!(r.is_err(), "多分区 v4 改密码应被拒绝");
}

/// v5 改密码后头部篡改仍能被检出（auth_tag 重新绑定新盐）
#[test]
fn v5_tamper_after_password_change_detected() {
    let dir = tempdir("v5chgtamper");
    let (mut v, path) = new_vault(&dir);
    v.change_password(PWD, "brand new password 123", None, None::<fn(usize)>, None)
        .unwrap();
    drop(v);
    let mut b = fs::read(&path).unwrap();
    b[106] ^= 0xFF; // 条目 0 别名（v5 布局同样起始于 106）
    fs::write(&path, &b).unwrap();
    let mut v2 = Vault::default();
    assert!(v2
        .open_and_authenticate(&path, "brand new password 123", None, None)
        .is_err());
}

// ───────────────── 2.8.0：移动 / 搜索 / 完整性体检 / 锁定信息 ─────────────────

/// 移动文件与文件夹：内容可读、冲突拒绝、移入自身子目录拒绝
#[test]
fn move_file_and_folder_keeps_content_readable() {
    let dir = tempdir("move");
    let (mut v, _) = new_vault(&dir);
    v.get_index_manager().unwrap().add_folder("/docs").unwrap();
    v.get_index_manager()
        .unwrap()
        .add_folder("/docs/sub")
        .unwrap();
    v.get_index_manager()
        .unwrap()
        .add_folder("/archive")
        .unwrap();
    let src = write_src(&dir, "a.txt", b"move me");
    v.import_file(&src, "/a.txt").unwrap();
    v.import_file(&write_src(&dir, "b.txt", b"nested"), "/docs/sub/b.txt")
        .unwrap();

    // 文件移动：根 → /docs
    v.get_index_manager()
        .unwrap()
        .move_file("/a.txt", "/docs")
        .unwrap();
    assert_eq!(v.load_file_data("/docs/a.txt").unwrap(), b"move me");
    assert!(!v.load_index().unwrap().files.contains_key("/a.txt"));

    // 文件夹移动：/docs → /archive（子树整体迁移，内容仍可读）
    v.get_index_manager()
        .unwrap()
        .move_folder("/docs", "/archive")
        .unwrap();
    let idx = v.load_index().unwrap();
    assert!(
        idx.files.contains_key("/archive/docs/a.txt"),
        "文件应随子树迁移"
    );
    assert!(
        idx.files.contains_key("/archive/docs/sub/b.txt"),
        "子目录文件应随子树迁移"
    );
    assert!(!idx.folders.contains_key("/docs"), "原文件夹条目应消失");
    drop(v);

    // 重开后内容仍可读（持久化正确）
    let (_, path) = ((), dir.join("test.lyt"));
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
    assert_eq!(
        v2.load_file_data("/archive/docs/sub/b.txt").unwrap(),
        b"nested"
    );
}

/// 移动冲突与非法目标
#[test]
fn move_conflicts_rejected() {
    let dir = tempdir("moveconflict");
    let (mut v, _) = new_vault(&dir);
    v.get_index_manager().unwrap().add_folder("/docs").unwrap();
    v.import_file(&write_src(&dir, "a.txt", b"A"), "/a.txt")
        .unwrap();
    v.import_file(&write_src(&dir, "b.txt", b"B"), "/docs/b.txt")
        .unwrap();
    // 在 /docs 下再放一个同名 a.txt，制造真正的同名冲突
    v.import_file(&write_src(&dir, "a2.txt", b"A2"), "/docs/a.txt")
        .unwrap();

    // 同名冲突
    let r = v.get_index_manager().unwrap().move_file("/a.txt", "/docs");
    assert!(r.is_err(), "同名冲突应被拒绝");
    // 目标文件夹不存在
    let r = v
        .get_index_manager()
        .unwrap()
        .move_file("/a.txt", "/nowhere");
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
    v.import_file(&write_src(&dir, "ok.txt", b"fine"), "/ok.txt")
        .unwrap();
    let (total, broken) = v.verify_integrity(None::<fn(usize, usize, &str)>).unwrap();
    assert_eq!(total, 1);
    assert!(broken.is_empty(), "完好库不应有异常");
    drop(v);

    // 篡改文件密文（数据区从 2048 开始；索引在最前，其后是文件数据）
    let meta_off = {
        let mut v = Vault::default();
        v.open_and_authenticate(&path, PWD, None, None).unwrap();
        v.load_index().unwrap().files.get("/ok.txt").unwrap().offset
    };
    let mut b = fs::read(&path).unwrap();
    b[meta_off as usize + 20] ^= 0xFF;
    fs::write(&path, &b).unwrap();

    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
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
    v.get_index_manager()
        .unwrap()
        .add_folder("/Reports")
        .unwrap();
    v.import_file(
        &write_src(&dir, "Q3-Summary.txt", b"x"),
        "/Reports/Q3-Summary.txt",
    )
    .unwrap();
    v.import_file(&write_src(&dir, "other.txt", b"y"), "/other.txt")
        .unwrap();

    let hits = v.search_files("q3", 50);
    assert_eq!(
        hits.len(),
        1,
        "应命中 /Reports/Q3-Summary.txt（vpath 包含 q3）"
    );
    assert!(!hits[0].is_dir);
    let hits = v.search_files("reports", 50);
    assert_eq!(
        hits.len(),
        2,
        "应命中文件夹 /Reports 及其下文件（vpath 包含）"
    );
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
    assert!(v
        .open_and_authenticate(&path, "wrong password 123", None, None)
        .is_err());
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
    v.import_file(&write_src(&dir, "d.txt", b"D"), "/docs")
        .unwrap();
    assert!(
        v.get_index_manager().unwrap().add_folder("/docs").is_err(),
        "同名文件夹应被拒绝"
    );
    // 反向：先建文件夹 /x，再导入同名文件应被拒绝
    v.get_index_manager().unwrap().add_folder("/x").unwrap();
    assert!(
        v.import_file(&write_src(&dir, "y.txt", b"Y"), "/x")
            .is_err(),
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
        v.import_file(
            &write_src(&dir, &name, format!("content-{}", i).as_bytes()),
            &format!("/f{}.txt", i),
        )
        .unwrap();
    }
    let count_before = v.load_index().unwrap().files.len();
    let vpaths: Vec<String> = (0..10).map(|i| format!("/f{}.txt", i)).collect();
    let (ok, fail, errors) = v
        .get_index_manager()
        .unwrap()
        .move_items(&vpaths, "/dst")
        .unwrap();
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
    let (ok2, fail2, _) = v
        .get_index_manager()
        .unwrap()
        .move_items(&bad, "/dst")
        .unwrap();
    assert_eq!(ok2, 0);
    assert_eq!(fail2, 2);
}

// 2.8.2.1（兼容性回归）：头部签名与当前分区密钥不一致时**不再硬拒** ——
// 多分区跨签名 / 历史版本遗留 / 部分写入中断都是良性场景，2.8.2 首版的
// 强制验签硬拒把合法存量柜挡在门外（发布当日实测回归）。现约定：
// 打开成功 + 审计留痕 + 按当前分区密钥重签迁移。
#[test]
fn legacy_signature_mismatch_still_opens_and_resigns() {
    let dir = tempdir("sig-mismatch");
    let path = dir.join("sig.lyt");
    const SIG_PWD: &str = "signature mismatch test";

    // 创建（2.8.2 写入规范形签名）后正常关闭
    let mut v = Vault::default();
    v.create(&path, SIG_PWD, None).expect("创建失败");
    v.close();

    // 模拟历史遗留：签名区（1984..2048）整体覆写为 0xFF
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("打开头部失败");
        f.seek(SeekFrom::Start(1984)).unwrap();
        f.write_all(&[0xFFu8; 64]).unwrap();
        f.sync_all().unwrap();
    }

    // 打开：必须成功（不再报「头部签名校验失败」）
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, SIG_PWD, None, None)
        .expect("签名不一致的存量柜必须能够打开（验签 + 重签迁移）");
    let entries = v2.get_audit_entries();
    assert!(
        entries
            .iter()
            .any(|e| e.event.contains("头部签名与当前分区密钥不一致")),
        "签名不一致必须写入审计留痕"
    );
    // 数据可用性：导入新文件并重开校验
    let src = write_src(&dir, "after.txt", b"after heal");
    v2.import_file(&src, "/after.txt").expect("迁移后写入失败");
    v2.close();

    // 重开：头部已按当前分区密钥重签，审计不再出现新的签名提示
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, SIG_PWD, None, None)
        .expect("重签后的保险柜再次打开失败");
    let idx = v3.load_index().unwrap();
    assert!(
        idx.files.contains_key("/after.txt"),
        "迁移后写入的数据必须可读"
    );
    let entries3 = v3.get_audit_entries();
    // 审计为追加式历史：首次打开的那条提示仍在，但重签后再次打开**不得新增**
    let legacy_notes = |entries: &[vault_core::audit::AuditEntry]| {
        entries
            .iter()
            .filter(|e| e.event.contains("头部签名与当前分区密钥不一致"))
            .count()
    };
    assert_eq!(
        legacy_notes(&entries3),
        legacy_notes(&entries),
        "重签后的再次打开不得再新增签名提示"
    );
    v3.close();
}

// ═══════════════ 3.0.0：v6 流式分块格式 ═══════════════

/// v6 分块导入的确定性内容生成器（PRNG，避免全零特殊化）
fn pattern_bytes(len: usize, seed: u8) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut x = seed as u32 | 1;
    for b in out.iter_mut() {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    out
}

/// v6 多块导入/提取往返：5 MiB（= 4 MiB 整块 + 1 MiB 末块）+ 12 MiB（3 整块），
/// 覆盖非对齐末块与多整块路径；close/reopen 后内容逐字节一致
#[test]
fn v6_chunked_import_extract_roundtrip() {
    let dir = tempdir("v6roundtrip");
    let (mut v, path) = new_vault(&dir);

    let big = pattern_bytes(5 * 1024 * 1024, 7);
    let src1 = write_src(&dir, "big.bin", &big);
    v.import_file(&src1, "/big.bin").unwrap();

    let bigger = pattern_bytes(12 * 1024 * 1024, 11);
    let src2 = write_src(&dir, "bigger.bin", &bigger);
    v.import_file(&src2, "/nested/bigger.bin").unwrap();

    assert_eq!(v.load_file_data("/big.bin").unwrap(), big);
    assert_eq!(v.load_file_data("/nested/bigger.bin").unwrap(), bigger);
    drop(v);

    // 重开持久化
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
    assert_eq!(v2.load_file_data("/big.bin").unwrap(), big);
    assert_eq!(v2.load_file_data("/nested/bigger.bin").unwrap(), bigger);

    // 完整性体检通过（分块逐块校验）
    let (total, broken) = v2.verify_integrity(None::<fn(usize, usize, &str)>).unwrap();
    assert_eq!(total, 2);
    assert!(broken.is_empty(), "体检不应报异常: {:?}", broken);

    // 提取逐字节一致
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    v2.extract_all_files(&out, true, None, None).unwrap();
    assert_eq!(fs::read(out.join("big.bin")).unwrap(), big);
    assert_eq!(fs::read(out.join("nested/bigger.bin")).unwrap(), bigger);
}

/// v6 分块密文被篡改（翻转中部一个字节）→ 解密必须失败（GCM 认证 + 块 AAD）
#[test]
fn v6_chunk_tampering_detected() {
    let dir = tempdir("v6tamper");
    let (mut v, path) = new_vault(&dir);
    let payload = pattern_bytes(9 * 1024 * 1024, 23);
    let src = write_src(&dir, "payload.bin", &payload);
    v.import_file(&src, "/payload.bin").unwrap();
    drop(v);

    // 翻转文件中部一个字节（必然落在 9 MiB 密文的数据区内，远离头部/索引）
    let mut raw = fs::read(&path).unwrap();
    let mid = raw.len() / 2;
    raw[mid] ^= 0x01;
    fs::write(&path, &raw).unwrap();

    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
    assert!(
        v2.load_file_data("/payload.bin").is_err(),
        "篡改分块密文后加载必须失败"
    );
    let (_, broken) = v2.verify_integrity(None::<fn(usize, usize, &str)>).unwrap();
    assert_eq!(broken.len(), 1, "体检必须检出被篡改的文件");
}

/// v6 空文件走 Legacy 布局且可读；小文件编辑保存（v6 单块路径）后内容正确
#[test]
fn v6_empty_file_and_edit_save() {
    let dir = tempdir("v6edit");
    let (mut v, path) = new_vault(&dir);

    let empty = write_src(&dir, "empty.txt", b"");
    v.import_file(&empty, "/empty.txt").unwrap();
    assert_eq!(v.load_file_data("/empty.txt").unwrap(), b"");

    let note = pattern_bytes(300_000, 5);
    let src = write_src(&dir, "note.txt", &note);
    v.import_file(&src, "/note.txt").unwrap();
    v.update_file_content("/note.txt", b"edited content v6")
        .unwrap();
    assert_eq!(v.load_file_data("/note.txt").unwrap(), b"edited content v6");
    drop(v);

    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
    assert_eq!(v2.load_file_data("/empty.txt").unwrap(), b"");
    assert_eq!(
        v2.load_file_data("/note.txt").unwrap(),
        b"edited content v6"
    );
}

/// v6 分块文件删除 + 自动整理 + 碎片整理后其余分块文件完好
#[test]
fn v6_delete_defrag_with_chunked_files() {
    let dir = tempdir("v6defrag");
    let (mut v, path) = new_vault(&dir);
    let keep1 = pattern_bytes(6 * 1024 * 1024, 31);
    let keep2 = pattern_bytes(6 * 1024 * 1024, 37);
    let gone = pattern_bytes(6 * 1024 * 1024, 41);
    let s1 = write_src(&dir, "k1.bin", &keep1);
    let s2 = write_src(&dir, "k2.bin", &keep2);
    let s3 = write_src(&dir, "gone.bin", &gone);
    v.import_file(&s1, "/k1.bin").unwrap();
    v.import_file(&s2, "/k2.bin").unwrap();
    v.import_file(&s3, "/gone.bin").unwrap();
    v.secure_delete_file("/gone.bin").unwrap();
    v.defragment_vault(None::<fn(usize)>).unwrap();
    drop(v);

    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
    assert_eq!(v2.load_file_data("/k1.bin").unwrap(), keep1);
    assert_eq!(v2.load_file_data("/k2.bin").unwrap(), keep2);
    assert!(v2.load_file_data("/gone.bin").is_err());
}

/// v6 突破 Legacy 内存上限：导入 260 MiB（> 256 MiB）并提取比对
/// （内容为确定性伪随机，哈希比对避免 260 MB 级 Vec 相等断言的额外内存）
#[test]
fn v6_import_above_legacy_limit() {
    use std::io::Write as _;
    let dir = tempdir("v6big");
    let (mut v, path) = new_vault(&dir);

    // 分段写入确定性伪随机内容（260 MiB），同时计算参考哈希
    let mut src_path = dir.join("huge.bin");
    #[cfg(windows)]
    {
        let s = src_path.to_str().unwrap().to_string();
        src_path = PathBuf::from(format!(r"\\?\{}", s));
    }
    let mut h = std::collections::hash_map::DefaultHasher::new();
    {
        let mut f = fs::File::create(&src_path).unwrap();
        let mut x: u32 = 0x9E3779B9;
        let mut buf = vec![0u8; 1024 * 1024];
        for _ in 0..260 {
            for b in buf.iter_mut() {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *b = (x >> 24) as u8;
            }
            use std::hash::Hasher;
            h.write(&buf);
            f.write_all(&buf).unwrap();
        }
        f.sync_all().unwrap();
    }
    let expect_hash = {
        use std::hash::Hasher;
        h.finish()
    };

    v.import_file(&src_path, "/huge.bin").unwrap();
    // 单文件提取直接放入目标目录（2.5.1 语义）—— 目标目录不能与源同目录（撞名）
    let out_dir = dir.join("extract-out");
    fs::create_dir_all(&out_dir).unwrap();
    v.extract_file("/huge.bin", &out_dir, false).unwrap();
    drop(v);

    // 提取产物与源内容哈希一致
    let read_path = out_dir.join("huge.bin");
    assert!(read_path.exists(), "提取产物应存在");
    let mut h2 = std::collections::hash_map::DefaultHasher::new();
    {
        let mut f = fs::File::open(&read_path).unwrap();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = std::io::Read::read(&mut f, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            use std::hash::Hasher;
            h2.write(&buf[..n]);
        }
    }
    let got_hash = {
        use std::hash::Hasher;
        h2.finish()
    };
    assert_eq!(expect_hash, got_hash, "260 MiB 大文件往返哈希必须一致");
    let _ = path;
}

// ═══════════════ 3.0.0：跨版本兼容夹具回归 ═══════════════
//
// 「老版本保险柜永远打得开」由提交进仓库的二进制夹具守卫 ——
// 2.8.2 曾因兼容性回归发布补丁（旧柜无法打开），当时的教训是没有
// 任何测试钉住格式兼容性。夹具由 LYNVAULT_GEN_FIXTURES=1 时的一次性
// 测试生成后提交，此后每次 CI 都会重新打开并校验内容。

const FIXTURE_PWD: &str = "Fixture-Vault-2026!";
const FIXTURE_README: &[u8] = b"LynVault compatibility fixture\nkeep this vault openable forever\n";
/// 64 KiB 确定性二进制内容
fn fixture_binary() -> Vec<u8> {
    pattern_bytes(64 * 1024, 99)
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn fixture_assertions(vault_path: &Path) {
    // 3.0.0（审计修复）：夹具文件是只读守卫资产 —— 开柜成功路径会重写头部
    //（锁定区重置 / 挑战盐轮换），直接打开仓库夹具会产生「测试改写受版本
    // 控制文件」的撕裂写风险（并行测试下实测出现过）。一律复制后打开副本。
    let copy_dir = tempdir("fixture-copy");
    let work = copy_dir.join("work.lyt");
    fs::copy(vault_path, &work).unwrap();
    let vault_path = work.as_path();
    let mut v = Vault::default();
    v.open_and_authenticate(vault_path, FIXTURE_PWD, None, None)
        .expect("兼容夹具必须能够打开（格式回归守卫）");
    assert_eq!(
        v.load_file_data("/docs/readme.txt").unwrap(),
        FIXTURE_README
    );
    let expect = fixture_binary();
    assert_eq!(v.load_file_data("/bin/data.bin").unwrap(), expect);
    // 目录结构完整
    assert!(v.index_ref().unwrap().folders.contains_key("/docs"));
    assert!(v.index_ref().unwrap().folders.contains_key("/bin"));
}

/// 一次性夹具生成器：LYNVAULT_GEN_FIXTURES=1 cargo test 时写出 v4/v5 夹具
///（生成后随仓库提交；平时运行自动跳过）
#[test]
fn generate_compatibility_fixtures() {
    if std::env::var("LYNVAULT_GEN_FIXTURES").is_err() {
        return;
    }
    let dir = fixtures_dir();
    fs::create_dir_all(&dir).unwrap();

    let binary = fixture_binary();
    for (fname, version) in [("v4_vault.lyt", 4u8), ("v5_vault.lyt", 5u8)] {
        let fpath = dir.join(fname);
        if fpath.exists() {
            fs::remove_file(&fpath).unwrap();
        }
        let mut v = Vault::default();
        match version {
            4 => v
                .create_v4_for_tests(&fpath, FIXTURE_PWD, None)
                .expect("v4 夹具创建失败"),
            _ => v
                .create_envelope_for_tests(&fpath, FIXTURE_PWD, None, 5)
                .expect("v5 夹具创建失败"),
        }
        let tmp = tempdir("fixture-src");
        let r1 = write_src(&tmp, "readme.txt", FIXTURE_README);
        let r2 = write_src(&tmp, "data.bin", &binary);
        v.import_file(&r1, "/docs/readme.txt").unwrap();
        v.import_file(&r2, "/bin/data.bin").unwrap();
        v.close();
        assert_eq!(
            fs::read(&fpath).unwrap()[8],
            version,
            "夹具版本字节必须正确"
        );
    }
    println!("fixtures written to {}", dir.display());
}

/// v4 夹具（2.x 历史格式）打开 + 内容校验 + 改名后仍可读
#[test]
fn fixture_v4_opens_and_content_matches() {
    let fpath = fixtures_dir().join("v4_vault.lyt");
    assert!(
        fpath.exists(),
        "v4 兼容夹具缺失 —— 见 generate_compatibility_fixtures"
    );
    fixture_assertions(&fpath);

    // 重命名后 AAD 冻结语义在 v4 上同样成立（副本上操作，见 fixture_assertions 注释）
    let dir = tempdir("fixture-v4-rename");
    let work = dir.join("work.lyt");
    fs::copy(&fpath, &work).unwrap();
    let mut v = Vault::default();
    v.open_and_authenticate(&work, FIXTURE_PWD, None, None)
        .unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    v.extract_file("/docs/readme.txt", &out, false).unwrap();
    assert_eq!(fs::read(out.join("readme.txt")).unwrap(), FIXTURE_README);
}

/// v5 夹具（2.8.0 信封格式）打开 + 内容校验
#[test]
fn fixture_v5_opens_and_content_matches() {
    let fpath = fixtures_dir().join("v5_vault.lyt");
    assert!(
        fpath.exists(),
        "v5 兼容夹具缺失 —— 见 generate_compatibility_fixtures"
    );
    fixture_assertions(&fpath);
}

/// v5 夹具改密码 → 自动升级 v6 → 内容完好（升级路径回归守卫）
#[test]
fn fixture_v5_change_password_upgrades_to_v6() {
    let fpath = fixtures_dir().join("v5_vault.lyt");
    assert!(fpath.exists(), "v5 兼容夹具缺失");
    let dir = tempdir("fixture-v5-upgrade");
    let upgraded = dir.join("upgraded.lyt");
    fs::copy(&fpath, &upgraded).unwrap();

    let mut v = Vault::default();
    v.open_and_authenticate(&upgraded, FIXTURE_PWD, None, None)
        .unwrap();
    v.change_password(
        FIXTURE_PWD,
        "brand new password 123",
        None,
        None::<fn(usize)>,
        None,
    )
    .expect("v5→v6 头部级升级失败");
    drop(v);

    assert_eq!(fs::read(&upgraded).unwrap()[8], 6, "升级后应为 v6");
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&upgraded, "brand new password 123", None, None)
        .expect("升级后的 v6 必须能用新密码打开");
    assert_eq!(
        v2.load_file_data("/docs/readme.txt").unwrap(),
        FIXTURE_README
    );
    assert_eq!(
        v2.load_file_data("/bin/data.bin").unwrap(),
        fixture_binary()
    );
}

// ═══════════════ 3.0.0：胁迫密码 ═══════════════

/// 完整触发流程：主分区（真实数据）+ 胁迫分区（诱饵）→ 标记 → 胁迫密码开柜
/// → 主分区永久不可开（密码正确也失败）→ 胁迫分区继续正常可用、审计无痕
#[test]
fn duress_trigger_destroys_other_partitions() {
    let dir = tempdir("duress");
    let path = dir.join("duress.lyt");
    const MAIN_PWD: &str = "main partition password";
    const DURESS_PWD: &str = "duress partition pwd";

    let mut v = Vault::default();
    v.create(&path, MAIN_PWD, None).unwrap();
    let src = write_src(&dir, "secret.txt", b"top secret");
    v.import_file(&src, "/secret.txt").unwrap();
    v.add_partition("Duress", DURESS_PWD, None).unwrap();
    drop(v);

    // 主分区会话直接标记 Duress 分区（跨分区标记，无需先打开它）
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, MAIN_PWD, None, None)
        .unwrap();
    v2.set_duress_mark_on("Duress", DURESS_PWD, None, None)
        .unwrap();
    v2.close();

    // 用胁迫密码开柜 → 触发覆写
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, DURESS_PWD, None, None)
        .expect("胁迫开柜必须成功（诱饵正常呈现）");
    assert!(v3.load_file_data("/secret.txt").is_err());
    // 不写审计：诱饵柜的操作记录必须完全正常
    let entries = v3.get_audit_entries();
    assert!(
        entries.iter().all(|e| !e.event.contains("胁迫")),
        "触发不得写入审计（诱饵柜无痕）"
    );
    // 胁迫分区还能正常写入
    let decoy = write_src(&dir, "decoy.txt", b"decoy content");
    v3.import_file(&decoy, "/decoy.txt").unwrap();
    v3.close();

    // 主分区密码正确也永久打不开
    let mut v4 = Vault::default();
    assert!(
        v4.open_and_authenticate(&path, MAIN_PWD, None, None)
            .is_err(),
        "触发后主分区必须永久不可开"
    );

    // 胁迫分区可继续打开，诱饵数据完好
    let mut v5 = Vault::default();
    v5.open_and_authenticate(&path, DURESS_PWD, None, None)
        .unwrap();
    assert_eq!(v5.load_file_data("/decoy.txt").unwrap(), b"decoy content");
}

/// 标记/解除都必须验证当前分区密码（防他人在已解锁机器上恶意标记）
#[test]
fn duress_mark_requires_password_and_two_partitions() {
    let dir = tempdir("duressguard");
    let (mut v, _path) = new_vault(&dir);
    // 单分区：直接拒绝（没有保护对象）
    assert!(
        v.set_duress_mark_on("Second", "second partition pwd", None, None)
            .is_err(),
        "单分区不得设置胁迫标记"
    );
    v.add_partition("Second", "second partition pwd", None)
        .unwrap();
    // 允许标记当前分区（原地标记是自然流程）：成功
    v.set_duress_mark_on("Main", PWD, None, None).unwrap();
    v.clear_duress_mark_on("Main", PWD, None, None).unwrap();
    // 目标分区密码错误：拒绝
    assert!(v
        .set_duress_mark_on("Second", "totally wrong pwd", None, None)
        .is_err());
    // 正确的目标分区密码：成功
    v.set_duress_mark_on("Second", "second partition pwd", None, None)
        .unwrap();
    // 重复标记：明确报错
    assert!(v
        .set_duress_mark_on("Second", "second partition pwd", None, None)
        .is_err());
    // 错误密码不得解除
    assert!(v
        .clear_duress_mark_on("Second", "totally wrong pwd", None, None)
        .is_err());
    // 正确解除
    v.clear_duress_mark_on("Second", "second partition pwd", None, None)
        .unwrap();
}

/// 演练：副本上验证完整触发，原件零接触、副本用后擦除
#[test]
fn duress_rehearsal_leaves_original_intact() {
    let dir = tempdir("duressdrill");
    let path = dir.join("drill.lyt");
    const MAIN_PWD: &str = "main partition password";
    const DURESS_PWD: &str = "duress partition pwd";

    let mut v = Vault::default();
    v.create(&path, MAIN_PWD, None).unwrap();
    let src = write_src(&dir, "secret.txt", b"top secret");
    v.import_file(&src, "/secret.txt").unwrap();
    v.add_partition("Duress", DURESS_PWD, None).unwrap();
    drop(v);

    // 主分区会话直接标记 Duress 分区
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, MAIN_PWD, None, None)
        .unwrap();
    v2.set_duress_mark_on("Duress", DURESS_PWD, None, None)
        .unwrap();
    v2.close();
    // 演练（胁迫密码打开副本触发）：返回被覆写的其他分区数（=1）
    let mut v2b = Vault::default();
    v2b.open_and_authenticate(&path, MAIN_PWD, None, None)
        .unwrap();
    let wiped = v2b
        .duress_rehearsal(DURESS_PWD, None, None)
        .expect("演练失败");
    assert_eq!(wiped, 1);
    v2b.close();

    // 原件零接触：主分区仍可开、数据完好
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, MAIN_PWD, None, None)
        .expect("演练不得影响原件");
    assert_eq!(v3.load_file_data("/secret.txt").unwrap(), b"top secret");
    drop(v3);

    // 演练副本已被擦除删除（无残留）
    let leftovers: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains("rehearsal"))
        .collect();
    assert!(leftovers.is_empty(), "演练副本必须被删除: {:?}", leftovers);
}

/// 解除标记后开柜不再触发（主分区完好）
#[test]
fn duress_clear_mark_disables_trigger() {
    let dir = tempdir("duressclear");
    let path = dir.join("clear.lyt");
    const MAIN_PWD: &str = "main partition password";
    const DURESS_PWD: &str = "duress partition pwd";

    let mut v = Vault::default();
    v.create(&path, MAIN_PWD, None).unwrap();
    let src = write_src(&dir, "secret.txt", b"top secret");
    v.import_file(&src, "/secret.txt").unwrap();
    v.add_partition("Duress", DURESS_PWD, None).unwrap();
    drop(v);

    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, MAIN_PWD, None, None)
        .unwrap();
    v2.set_duress_mark_on("Duress", DURESS_PWD, None, None)
        .unwrap();
    v2.clear_duress_mark_on("Duress", DURESS_PWD, None, None)
        .unwrap();
    v2.close();

    // 胁迫密码开柜：不触发，主分区完好
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, DURESS_PWD, None, None)
        .unwrap();
    v3.close();
    let mut v4 = Vault::default();
    v4.open_and_authenticate(&path, MAIN_PWD, None, None)
        .expect("解除标记后主分区必须完好");
    assert_eq!(v4.load_file_data("/secret.txt").unwrap(), b"top secret");
}

// ═══════════════ 3.0.0：硬件密钥二因子（响应注入 —— 无需真钥匙）═══════════════

/// 3.0.1（F19 回归修复）：响应必须由**文件中的挑战盐**派生 —— 模拟真实
/// 「钥匙对挑战算响应」的确定性函数（SHA-256 截断模拟 HMAC-SHA1；vault-core
/// 只把响应当不透明 20 字节）。旧测试用固定字面量 RESP，使「开柜轮换盐」
/// 类缺陷完全无法被端到端测试发现（3.0.0 F19 因此漏网）。
fn hardware_response(path: &std::path::Path) -> [u8; 20] {
    use sha2::{Digest, Sha256};
    let salt = vault_core::read_vault_yk_salt(path).expect("读取挑战盐");
    let challenge = vault_core::crypto::derive_yubikey_challenge(&salt);
    let d = Sha256::digest(challenge);
    let mut resp = [0u8; 20];
    resp.copy_from_slice(&d[..20]);
    resp
}

/// 启用 → 无响应拒绝 → 带响应可开 → **连续重开不砖化（F19 回归）** →
/// 改密码保留二因子 → 解除复原
#[test]
fn yubikey_2fa_full_lifecycle() {
    let dir = tempdir("yk2fa");
    let path = dir.join("yk.lyt");
    const PWD2: &str = "hardware key vault pwd";

    let mut v = Vault::default();
    v.create(&path, PWD2, None).unwrap();
    let src = write_src(&dir, "hw.txt", b"hardware protected");
    v.import_file(&src, "/hw.txt").unwrap();
    let resp = hardware_response(&path);
    v.enable_yubikey_2fa(PWD2, None, &resp).unwrap();
    assert!(v.is_yubikey_2fa_active().unwrap());
    v.close();

    // 无响应：密码正确也拒绝
    let mut v2 = Vault::default();
    assert!(
        v2.open_and_authenticate(&path, PWD2, None, None).is_err(),
        "启用二因子后无响应必须拒绝开柜"
    );
    // 错误响应：拒绝
    let mut v2b = Vault::default();
    assert!(
        v2b.open_and_authenticate(&path, PWD2, None, Some(&[0x00u8; 20]))
            .is_err(),
        "错误响应必须被拒绝"
    );
    // 正确响应：开柜成功，内容完好
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, PWD2, None, Some(&resp))
        .unwrap();
    assert_eq!(v3.load_file_data("/hw.txt").unwrap(), b"hardware protected");

    // F19 回归核心：盐恒定 —— 关柜再连续重开两次，每次都必须成功。
    // （3.0.0 的开柜轮换在此处第二次重开即 AuthFailed 且永久不可恢复）
    let resp2 = hardware_response(&path);
    assert_eq!(resp2, resp, "挑战盐在开柜后不得变化（F19）");
    v3.close();
    let mut v3b = Vault::default();
    v3b.open_and_authenticate(&path, PWD2, None, Some(&resp))
        .expect("第二次开柜必须成功（F19 回归）");
    v3b.close();
    let mut v3c = Vault::default();
    v3c.open_and_authenticate(&path, PWD2, None, Some(&resp))
        .expect("第三次开柜必须成功（F19 回归）");

    // 改密码：不带响应明确报错；带响应成功且保留二因子
    assert!(v3c
        .change_password(PWD2, "new hardware pwd 999", None, None::<fn(usize)>, None)
        .is_err());
    v3c.change_password(
        PWD2,
        "new hardware pwd 999",
        None,
        None::<fn(usize)>,
        Some(&resp),
    )
    .unwrap();
    v3c.close();
    let mut v4 = Vault::default();
    v4.open_and_authenticate(&path, "new hardware pwd 999", None, Some(&resp))
        .unwrap();
    assert!(
        v4.is_yubikey_2fa_active().unwrap(),
        "改密码必须保留二因子状态"
    );

    // 解除后无响应可开
    v4.disable_yubikey_2fa("new hardware pwd 999", None, &resp)
        .unwrap();
    v4.close();
    let mut v5 = Vault::default();
    v5.open_and_authenticate(&path, "new hardware pwd 999", None, None)
        .unwrap();
    assert_eq!(v5.load_file_data("/hw.txt").unwrap(), b"hardware protected");
}

/// 普通分区与二因子分区共存：双路径解包互不干扰
#[test]
fn yubikey_2fa_coexists_with_plain_partitions() {
    let dir = tempdir("ykcoexist");
    let path = dir.join("co.lyt");
    const MAIN_PWD: &str = "plain main partition";
    const YK_PWD: &str = "yubikey second part";

    let mut v = Vault::default();
    v.create(&path, MAIN_PWD, None).unwrap();
    let src = write_src(&dir, "plain.txt", b"plain data");
    v.import_file(&src, "/plain.txt").unwrap();
    v.add_partition("Yk", YK_PWD, None).unwrap();
    drop(v);

    // 打开二因子分区并启用
    let resp = hardware_response(&path);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, YK_PWD, None, None).unwrap();
    v2.enable_yubikey_2fa(YK_PWD, None, &resp).unwrap();
    v2.close();

    // 无响应：普通分区可开（双路径普通命中）、二因子分区拒绝
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, MAIN_PWD, None, None)
        .unwrap();
    assert_eq!(v3.load_file_data("/plain.txt").unwrap(), b"plain data");
    v3.close();
    let mut v4 = Vault::default();
    assert!(v4.open_and_authenticate(&path, YK_PWD, None, None).is_err());

    // 带响应：二因子分区可开（混合命中）；普通分区也可开（混合未命中 → 普通命中）
    let mut v5 = Vault::default();
    v5.open_and_authenticate(&path, YK_PWD, None, Some(&resp))
        .unwrap();
    v5.close();
    let mut v6 = Vault::default();
    v6.open_and_authenticate(&path, MAIN_PWD, None, Some(&resp))
        .unwrap();
    assert_eq!(v6.load_file_data("/plain.txt").unwrap(), b"plain data");
    assert!(
        !v6.is_yubikey_2fa_active().unwrap(),
        "普通分区的会话不得误报二因子"
    );
}

/// 二因子分区上的胁迫触发：响应参与验证路径
#[test]
fn yubikey_2fa_partition_duress_flow() {
    let dir = tempdir("ykduress");
    let path = dir.join("ykd.lyt");
    const MAIN_PWD: &str = "plain main partition";
    const YK_PWD: &str = "yubikey duress part";

    let mut v = Vault::default();
    v.create(&path, MAIN_PWD, None).unwrap();
    let src = write_src(&dir, "secret.txt", b"top secret");
    v.import_file(&src, "/secret.txt").unwrap();
    v.add_partition("Yk", YK_PWD, None).unwrap();
    drop(v);

    // 启用二因子（Yk 会话）
    let resp = hardware_response(&path);
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, YK_PWD, None, None).unwrap();
    v2.enable_yubikey_2fa(YK_PWD, None, &resp).unwrap();
    v2.close();
    // 主分区会话跨分区标记二因子分区（验证走混合路径）
    let mut v2b = Vault::default();
    v2b.open_and_authenticate(&path, MAIN_PWD, None, None)
        .unwrap();
    v2b.set_duress_mark_on("Yk", YK_PWD, None, Some(&resp))
        .unwrap();
    v2b.close();

    // 胁迫开柜（带响应）→ 主分区销毁
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, YK_PWD, None, Some(&resp))
        .expect("带响应的胁迫开柜必须成功");
    v3.close();
    let mut v4 = Vault::default();
    assert!(v4
        .open_and_authenticate(&path, MAIN_PWD, None, None)
        .is_err());
}

/// P0-1 回归（3.0.0 审计修复）：v5 多分区保险柜改密码必须明确拒绝 ——
/// 否则升级 v6 后其他分区的包裹体/认证标签仍按 v5 前缀绑定，正确密码也永久锁死
#[test]
fn v5_multi_partition_change_password_is_rejected() {
    let dir = tempdir("p0-1");
    let path = dir.join("multi5.lyt");
    const MAIN_PWD: &str = "main v5 partition pwd";
    const DECOY_PWD: &str = "decoy v5 partition pwd";

    let mut v = Vault::default();
    v.create_envelope_for_tests(&path, MAIN_PWD, None, 5)
        .unwrap();
    let src = write_src(&dir, "data.txt", b"important");
    v.import_file(&src, "/data.txt").unwrap();
    v.add_partition("decoy", DECOY_PWD, None).unwrap();
    drop(v);

    // 改密码：必须明确报错，而不是「升级成功 + 其他分区锁死」
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, MAIN_PWD, None, None)
        .unwrap();
    let err = v2
        .change_password(
            MAIN_PWD,
            "brand new password 123",
            None,
            None::<fn(usize)>,
            None,
        )
        .expect_err("多分区 v5 改密码必须被拒绝");
    assert!(
        err.to_string().contains("暂不支持"),
        "错误信息应说明原因: {}",
        err
    );
    drop(v2);

    // 版本字节必须仍为 5（未发生半吊子升级），两个分区均完好
    assert_eq!(fs::read(&path).unwrap()[8], 5, "拒绝后不得发生版本切换");
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, DECOY_PWD, None, None)
        .expect("拒绝后 decoy 分区必须仍然可开");
    v3.close();
    let mut v4 = Vault::default();
    v4.open_and_authenticate(&path, MAIN_PWD, None, None)
        .unwrap();
    assert_eq!(v4.load_file_data("/data.txt").unwrap(), b"important");
}

/// 审计锚点（3.0.0）：篡改头部计数 → 开柜显式告警；正常重开无告警
#[test]
fn audit_anchor_detects_truncation_and_rollback() {
    let dir = tempdir("anchor");
    let path = dir.join("anchor.lyt");

    // create → close（落盘 2 条审计 + 锚点计数）
    let mut v = Vault::default();
    v.create(&path, PWD, None).unwrap();
    v.close();
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None).unwrap();
    let src = write_src(&dir, "a.txt", b"data");
    v2.import_file(&src, "/a.txt").unwrap();
    // 干净状态：无锚点告警
    let entries = v2.get_audit_entries();
    assert!(
        entries.iter().all(|e| !e.event.contains("锚点不符")),
        "干净开柜不得出现锚点告警: {:?}",
        entries.iter().map(|e| &e.event).collect::<Vec<_>>()
    );
    v2.close();

    // 篡改头部槽 0 计数（41..45）：+5 模拟「索引尾部被截断 / 回滚到旧索引」
    let mut raw = fs::read(&path).unwrap();
    let stored = u32::from_le_bytes(raw[41..45].try_into().unwrap());
    assert!(stored > 0, "落盘过审计后锚点应为正数");
    raw[41..45].copy_from_slice(&(stored + 5).to_le_bytes());
    fs::write(&path, &raw).unwrap();

    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, PWD, None, None)
        .expect("锚点不符应告警而非拒绝（防御纵深，不阻断可用性）");
    let entries3 = v3.get_audit_entries();
    assert!(
        entries3
            .iter()
            .any(|e| e.event.contains("审计记录数量与头部锚点不符")),
        "锚点不符必须显式告警"
    );
    v3.close();

    // 重新落盘后锚点自愈：头部计数 == 索引实际条目数
    //（= v3 会话返回的条目数 + close 追加的「已关闭」1 条，确定性关系）
    let raw = fs::read(&path).unwrap();
    let healed = u32::from_le_bytes(raw[41..45].try_into().unwrap());
    assert_eq!(
        healed,
        entries3.len() as u32 + 1,
        "重新落盘后锚点必须与索引实际条目数一致"
    );

    // 重开：锚点一致 → 不得新增告警（历史告警条目保留，属追加式审计的预期）
    let mut v4 = Vault::default();
    v4.open_and_authenticate(&path, PWD, None, None).unwrap();
    let anchor_notes = |entries: &[vault_core::audit::AuditEntry]| {
        entries
            .iter()
            .filter(|e| e.event.contains("锚点不符"))
            .count()
    };
    assert_eq!(
        anchor_notes(&v4.get_audit_entries()),
        anchor_notes(&entries3),
        "锚点一致的重开不得新增告警"
    );
}

/// 优化1：分块导入的进度回调 —— 单调递增、终值 == 文件大小
#[test]
fn import_chunk_progress_is_monotonic_and_complete() {
    let dir = tempdir("progimp");
    let (mut v, _path) = new_vault(&dir);
    let big = pattern_bytes(5 * 1024 * 1024 + 12345, 61);
    let src = write_src(&dir, "prog.bin", &big);

    let seen: std::sync::Mutex<Vec<(u64, u64)>> = std::sync::Mutex::new(Vec::new());
    let files_seen: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());
    v.import_files_batch(
        &[src.to_string_lossy().into_owned()],
        "/",
        Some(&|d: usize, t: usize| files_seen.lock().unwrap().push((d, t))),
        Some(&|d: u64, t: u64| seen.lock().unwrap().push((d, t))),
    )
    .unwrap();

    let seen = seen.into_inner().unwrap();
    assert_eq!(*seen.last().unwrap(), (big.len() as u64, big.len() as u64));
    for w in seen.windows(2) {
        assert!(w[0].0 <= w[1].0, "进度必须单调: {:?}", w);
    }
    assert_eq!(*files_seen.lock().unwrap().last().unwrap(), (1, 1));
}

/// 优化1：提取进度 —— 文件级与跨文件累计字节级
#[test]
fn extract_progress_is_monotonic_and_complete() {
    let dir = tempdir("progext");
    let (mut v, _path) = new_vault(&dir);
    let f1 = pattern_bytes(3 * 1024 * 1024 + 7, 67);
    let f2 = pattern_bytes(2 * 1024 * 1024 + 99, 71);
    let s1 = write_src(&dir, "p1.bin", &f1);
    let s2 = write_src(&dir, "p2.bin", &f2);
    v.import_files_batch(
        &[
            s1.to_string_lossy().into_owned(),
            s2.to_string_lossy().into_owned(),
        ],
        "/",
        None,
        None,
    )
    .unwrap();

    let seen: std::sync::Mutex<Vec<(u64, u64)>> = std::sync::Mutex::new(Vec::new());
    let files_seen: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    v.extract_all_files(
        &out,
        true,
        Some(&|d: usize, t: usize| files_seen.lock().unwrap().push((d, t))),
        Some(&|d: u64, t: u64| seen.lock().unwrap().push((d, t))),
    )
    .unwrap();

    let seen = seen.into_inner().unwrap();
    let total = (f1.len() + f2.len()) as u64;
    assert_eq!(
        *seen.last().unwrap(),
        (total, total),
        "终值必须等于两文件之和"
    );
    for w in seen.windows(2) {
        assert!(w[0].0 <= w[1].0, "累计进度必须单调: {:?}", w);
    }
    let files_seen = files_seen.into_inner().unwrap();
    assert_eq!(*files_seen.last().unwrap(), (2, 2));
}

/// 优化2：媒体流式区间读取 —— 任意区间与整段内容逐字节一致
#[test]
fn media_range_reads_match_full_content() {
    let dir = tempdir("media");
    let (mut v, _path) = new_vault(&dir);
    let payload = pattern_bytes(10 * 1024 * 1024 + 777, 83);
    let src = write_src(&dir, "movie.bin", &payload);
    v.import_file(&src, "/movie.bin").unwrap();

    let (size, streamable) = v.media_file_info("/movie.bin").unwrap();
    assert_eq!(size, payload.len() as u64);
    assert!(streamable, "分块导入的文件应可流式");

    // 覆盖：块内、跨块、末块尾部、整段、1 字节边界
    for (a, b) in [
        (0u64, 1024u64),
        (4 * 1024 * 1024 - 1, 4 * 1024 * 1024 + 1),
        (8 * 1024 * 1024, size),
        (0, size),
        (size - 1, size),
        (123, 456),
    ] {
        let got = v.read_media_range("/movie.bin", a, b).unwrap();
        assert_eq!(
            got,
            payload[a as usize..b as usize],
            "区间 [{a},{b}) 内容不一致"
        );
    }
    // 越界与空区间拒绝
    assert!(v.read_media_range("/movie.bin", size, size + 1).is_err());
    assert!(v.read_media_range("/movie.bin", 5, 5).is_err());
}

/// 优化2：Legacy 布局拒绝流式（v4 保险柜导入的文件）
#[test]
fn media_range_rejects_legacy_layout() {
    let dir = tempdir("medialeg");
    let path = dir.join("legacy.lyt");
    let mut v = Vault::default();
    v.create_v4_for_tests(&path, PWD, None).unwrap();
    let src = write_src(&dir, "old.bin", b"legacy content");
    v.import_file(&src, "/old.bin").unwrap();
    let (_, streamable) = v.media_file_info("/old.bin").unwrap();
    assert!(!streamable, "Legacy 布局不得标记为可流式");
    assert!(v.read_media_range("/old.bin", 0, 4).is_err());
}

/// UX 重构：跨分区标记 —— 主分区会话直接把 decoy 标记为胁迫分区
///（无需先打开 decoy），decoy 密码开柜即触发，主分区永久锁死
#[test]
fn duress_cross_partition_marking() {
    let dir = tempdir("duressx");
    let path = dir.join("cross.lyt");
    const MAIN_PWD: &str = "main partition password";
    const DECOY_PWD: &str = "decoy partition pwd";

    let mut v = Vault::default();
    v.create(&path, MAIN_PWD, None).unwrap();
    let src = write_src(&dir, "secret.txt", b"top secret");
    v.import_file(&src, "/secret.txt").unwrap();
    v.add_partition("decoy", DECOY_PWD, None).unwrap();

    // 主分区会话内直接标记 decoy（目标分区口令验证）
    v.set_duress_mark_on("decoy", DECOY_PWD, None, None)
        .unwrap();
    // 错误的目标口令必须被拒绝
    v.set_duress_mark_on("decoy", "wrong password 123", None, None)
        .expect_err("错误的目标口令必须拒绝");
    drop(v);

    // decoy 密码开柜 → 触发 → 主分区永久不可开
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, DECOY_PWD, None, None)
        .expect("decoy 开柜必须成功");
    v2.close();
    let mut v3 = Vault::default();
    assert!(
        v3.open_and_authenticate(&path, MAIN_PWD, None, None)
            .is_err(),
        "触发后主分区必须永久不可开"
    );
}

/// 跨分区解除：主分区会话解除 decoy 的标记 → decoy 开柜不触发
#[test]
fn duress_cross_partition_clear() {
    let dir = tempdir("duressxc");
    let path = dir.join("cross2.lyt");
    const MAIN_PWD: &str = "main partition password";
    const DECOY_PWD: &str = "decoy partition pwd";

    let mut v = Vault::default();
    v.create(&path, MAIN_PWD, None).unwrap();
    v.add_partition("decoy", DECOY_PWD, None).unwrap();
    v.set_duress_mark_on("decoy", DECOY_PWD, None, None)
        .unwrap();
    v.clear_duress_mark_on("decoy", DECOY_PWD, None, None)
        .unwrap();
    drop(v);

    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, DECOY_PWD, None, None)
        .unwrap();
    v2.close();
    let mut v3 = Vault::default();
    v3.open_and_authenticate(&path, MAIN_PWD, None, None)
        .expect("解除标记后主分区必须完好");
    v3.close();
}

/// 分区别名查重（审计修复）：重名会破坏所有按别名定位分区的代码路径
#[test]
fn add_partition_rejects_duplicate_alias() {
    let dir = tempdir("dupalias");
    let (mut v, _path) = new_vault(&dir);
    v.add_partition("Alpha", "first partition pwd", None)
        .unwrap();
    assert!(
        v.add_partition("Alpha", "second partition pwd", None)
            .is_err(),
        "重名分区必须被拒绝"
    );
    // 大小写变体不算重名（alias 查找为精确匹配语义，保持一致）
    v.add_partition("alpha", "second partition pwd", None)
        .unwrap();
    // 原分区不受影响（首个 Alpha 的密码仍可打开它——通过分区列表验证数量）
    assert_eq!(v.get_partitions().len(), 3);
}

// ═══════════════ 3.0.1：安全修复回归测试 ═══════════════

/// F1 回归：擦除区间硬边界 —— 越界（含越过 EOF）一律拒绝，文件不得被撑大
#[test]
fn dod_overwrite_range_rejects_out_of_bounds() {
    let dir = tempdir("f1wipe");
    let path = dir.join("w.bin");
    fs::write(&path, vec![0xAAu8; 1024]).unwrap();
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    // 区间完全在文件内：成功
    vault_core::wipe::dod_overwrite_range(&mut f, 0, 512).unwrap();
    // 越过 EOF：拒绝（旧实现会把文件撑大到越界长度再覆写 7 遍）
    assert!(vault_core::wipe::dod_overwrite_range(&mut f, 0, 4096).is_err());
    // offset+length 溢出：拒绝
    assert!(vault_core::wipe::dod_overwrite_range(&mut f, u64::MAX - 1, 10).is_err());
    drop(f);
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        1024,
        "文件不得被越界擦除撑大"
    );
}

/// 3.0.1 回归（F1 假阳性收口）：伪条目是纯随机字节，有概率恰好形成
/// 1-2 字符的「合理别名」+ 随机 index_offset —— 全量范围硬校验曾把这样的
/// 正常保险柜永久拒绝打开（假阳性砖化）。构造该形态：把伪条目的别名字段
/// 写成 "K "（合理）+ 越界偏移，重开必须成功（该条目被按伪条目排除），
/// 且认证命中的真实分区不受影响。
#[test]
fn pseudo_entry_with_plausible_alias_and_random_range_does_not_block_open() {
    use std::io::{Seek, SeekFrom, Write};
    let dir = tempdir("pseudorange");
    let path = dir.join("pseudo.lyt");
    const PWD: &str = "pseudo range test pwd!";
    let mut v = Vault::default();
    v.create(&path, PWD, None).unwrap();
    v.close();

    // 篡改**伪条目 1**（条目 0 = Main 真实分区）：别名字段 → "K" + 零填充，
    // index_offset/length → 接近 u64::MAX 的随机值（条目内偏移 106+192+80/88）
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let base: u64 = 106 + 192;
    f.seek(SeekFrom::Start(base)).unwrap();
    let mut alias = [0u8; 16];
    alias[0] = b'K';
    f.write_all(&alias).unwrap();
    f.seek(SeekFrom::Start(base + 80)).unwrap();
    f.write_all(&(u64::MAX / 2).to_le_bytes()).unwrap();
    f.write_all(&(u64::MAX / 2).to_le_bytes()).unwrap();
    drop(f);

    // 修复前：全量范围硬校验报「分区表校验失败」→ 永久打不开；
    // 修复后：越界伪条目被排除出会话，正常打开
    let mut v2 = Vault::default();
    v2.open_and_authenticate(&path, PWD, None, None)
        .expect("偶然合理的伪条目不得阻断开柜");
    assert_eq!(v2.get_partitions().len(), 1, "越界伪条目不得进入分区表");
    v2.close();
}

/// F1 回归：未认证的头部 index_offset/length 驱动的破坏性擦除必须在打开时
/// 被全分区范围校验拦截（攻击者无需密码：只改文件即可触发旧缺陷）
#[test]
fn tampered_index_range_is_rejected_at_open() {
    let dir = tempdir("f1range");
    let path = dir.join("r.lyt");
    const PWD: &str = "range validation pwd!";
    let mut v = Vault::default();
    v.create(&path, PWD, None).unwrap();
    let src = write_src(&dir, "a.txt", b"data");
    v.import_file(&src, "/a.txt").unwrap();
    v.close();

    // 篡改第一个分区条目（别名 Main 合法）的 index_offset/length
    // —— 条目内偏移：106 + 80（index_offset，8 字节 LE）与 106 + 88（length）
    use std::io::{Seek, SeekFrom, Write};
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    f.seek(SeekFrom::Start(106 + 80)).unwrap();
    f.write_all(&0u64.to_le_bytes()).unwrap();
    f.write_all(&(u64::MAX / 2).to_le_bytes()).unwrap();
    drop(f);

    let mut v2 = Vault::default();
    let err = v2
        .open_and_authenticate(&path, PWD, None, None)
        .expect_err("越界分区表必须被拒绝");
    assert!(
        format!("{}", err).contains("分区表校验失败"),
        "应被分区表范围校验拒绝，实际: {}",
        err
    );
}

/// F3/F4/F5 根治：Index::validate 拒绝与写入方几何矛盾的条目
#[test]
fn index_validate_rejects_inconsistent_layouts() {
    use vault_core::index::ChunkLayout;
    use vault_core::{FileMeta, Index};

    let legacy = |size, offset, length| FileMeta {
        name: "f".into(),
        size,
        offset,
        length,
        aad_tag: None,
        layout: ChunkLayout::Legacy,
    };
    // Legacy：size == length - 28 合法；矛盾拒绝
    let mut idx = Index::new();
    idx.files.insert("/ok".into(), legacy(10, 100, 38));
    assert!(idx.validate(10000).is_ok());
    idx.files.insert("/bad".into(), legacy(999, 200, 38));
    assert!(idx.validate(10000).is_err());
    // 密文范围越过文件边界：拒绝
    let mut oob = Index::new();
    oob.files.insert("/oob".into(), legacy(10, 9000, 1 << 20));
    assert!(oob.validate(10000).is_err());
    // Chunked：chunk_size 超上限（F3 的 2^40 分配路径）拒绝
    let mut big = Index::new();
    big.files.insert(
        "/big".into(),
        FileMeta {
            name: "big".into(),
            size: 100,
            offset: 0,
            length: 128,
            aad_tag: None,
            layout: ChunkLayout::Chunked {
                chunk_size: 1 << 40,
                chunk_count: 1,
            },
        },
    );
    assert!(big.validate(u64::MAX).is_err());
    // Chunked：size 与布局矛盾（F4 的谎报 size → 切片 panic 路径）拒绝
    let mut mis = Index::new();
    mis.files.insert(
        "/mis".into(),
        FileMeta {
            name: "mis".into(),
            size: 200,
            offset: 0,
            length: 100 + 28,
            aad_tag: None,
            layout: ChunkLayout::Chunked {
                chunk_size: 100,
                chunk_count: 1,
            },
        },
    );
    assert!(mis.validate(u64::MAX).is_err());
}

/// F7 回归：审计数组的反序列化上限 —— 硬上限内可解析（兼容历史超限），
/// 超过硬上限拒绝（数百万条目的内存放大 DoS 收口）
#[test]
fn audit_array_deserialization_is_capped() {
    use vault_core::Index;
    let hmac = "00".repeat(32);
    let entry = |i: usize| {
        format!(
            r#"{{"ts":1700000000.0,"event":"e{}","hmac":"{}"}}"#,
            i, hmac
        )
    };
    let build = |n: usize| {
        format!(
            r#"{{"files":{{}},"folders":{{}},"audit":[{}]}}"#,
            (0..n).map(entry).collect::<Vec<_>>().join(",")
        )
    };
    // 运行期上限（1 万）之上、硬上限（10 万）之内：仍可解析
    assert!(serde_json::from_str::<Index>(&build(10_001)).is_ok());
    // 超过硬上限：拒绝
    assert!(serde_json::from_str::<Index>(&build(100_001)).is_err());
}
