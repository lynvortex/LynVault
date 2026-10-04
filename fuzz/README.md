# LynVault Fuzz

cargo-fuzz 模糊测试（3.0.0 优化4）。三个靶子覆盖最不可信的输入面：

- `office_parse` — Office 文档解析（恶意 docx/xlsx/doc，含加密 OOXML 分支）
- `header_probe` — 保险柜头部公开字段解析（read_lock_info / 挑战盐 / magic）
- `index_json` — 加密索引反序列化 + vpath 清洗

## 本地运行

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run office_parse -- -max_total_time=60 -rss_limit_mb=2560
```

## CI

每周定时（.github/workflows/fuzz.yml）+ 手动触发，每靶 60 秒冒烟；
发现崩溃会把 artifact（crash 输入）随 job 产物上传。
