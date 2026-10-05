# LynVault Fuzz

cargo-fuzz 模糊测试。四个靶子覆盖最不可信的输入面：

- `office_parse` — Office 文档解析（恶意 docx/xlsx/doc，含加密 OOXML 分支）
- `header_probe` — 保险柜头部公开字段解析（read_lock_info / 挑战盐 / magic）
- `index_json` — 加密索引反序列化 + vpath 清洗
- `index_layout` — 分块布局解析算术（3.0.1 F18/F25 新增：任意
  (length, chunk_size, chunk_count) 不得 panic，Ok 结果满足写入方几何不变量
  —— 3.0.0 的靶子从未触及提取 / 媒体 / 擦除的算术路径，F3/F4/F5 因此漏网）

种子语料入库于 `fuzz/corpus/<target>/`（cargo-fuzz 运行时自动加载并回填）。

## 本地运行

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run office_parse --fuzz-dir fuzz -- -max_total_time=60 -rss_limit_mb=2560
```

## CI

每周定时（.github/workflows/fuzz.yml）+ 手动触发，每靶 60 秒冒烟；PR 上对
`index_layout` 跑 30 秒算术冒烟。crash 输入随 job 产物上传（3.0.1 修正了
旧配置中 artifact 路径与实际输出不匹配、崩溃输入从未被上传的问题）。
