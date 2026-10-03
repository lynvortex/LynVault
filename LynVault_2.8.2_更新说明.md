# LynVault 2.8.2 更新说明

## 一、高危修复（H1–H5）

### H1. 单实例远程路径守卫绕过 → NTLM 凭据外发（上一轮已完成）

- **位置**：`src-tauri/src/single_instance.rs` `is_remote_or_device_path()`
- **问题**：旧守卫 `t.starts_with(r"\\")` 存在两个绕过：`\\?\UNC\server\share`（剥掉 verbatim 前缀后剩 `UNC\...`）与 `//server/share`（正斜杠被 Win32 规范化为 UNC），均可在**任何用户确认之前**触发对远程 SMB 的文件打开，无提示外发 NTLMv2 凭据。
- **修复**：去首尾引号 → 正斜杠统一为反斜杠 → 剥 `\\?\` 前缀 → 大小写不敏感识别 `UNC\` 前缀 → 剩余以 `\\` 开头（普通 UNC 或 `\\.\` 设备命名空间）即拒绝。`\\?\C:\...` verbatim 本地路径仍放行。函数改为 `pub` 供 `check_vault_file` 复用。
- **测试**：`single_instance::tests` 4 组单测（UNC 变体、设备路径、本地路径不误伤、引号剥离）。

### H2. 导入类命令直接接受 IPC 路径 → 任意用户可读文件窃取

- **位置**：`src-tauri/src/commands.rs`（新增 `dialog_pick_files` / `dialog_pick_folder`、令牌表 `DIALOG_TOKENS`）；`src-tauri/src/main.rs`（命令注册、拖放记录）；`ui/app.js`（前端改调用后端对话框）
- **问题**：Tauri 1.x 自定义命令无能力隔离。被 XSS 攻陷的 WebView 可直接 `invoke('import_files_batch', { src_paths: [...] })` 把任意用户可读文件（如 `.ssh`、浏览器 Cookies）导入已解锁的保险柜再读回外传——等价于「渲染层任意文件读取」。
- **修复**：**对话框令牌化**。
  1. 文件/目录选择改由后端命令弹出原生对话框（`blocking::FileDialogBuilder`，在 `spawn_blocking` 线程调用），所选路径登记进一次性令牌表并签发 128 位随机令牌（`rand::rngs::OsRng`）；
  2. `import_files_batch` / `import_folder` / `extract_files` / `extract_all_files` 必须凭令牌取路径，且要求 IPC 传入路径与对话框登记**逐条完全一致**，令牌用后即焚；`check_extract_all_dest` 为两段式流程做非消费式核验（预检不焚令牌，最终提取焚）；
  3. 拖放导入（`import_dropped_paths`）不再信任 WebView 字符串：main 里通过 `Builder::on_window_event` 捕获 `WindowEvent::FileDrop(Dropped(paths))` 记录主进程侧真实拖放载荷，导入命令要求传入路径与该载荷**排序后完全一致**，否则拒绝。
- **前端适配**：`importFiles` / `importFolder` / `extractSelected` / `extractAllFiles` 改为先 `invoke('dialog_pick_files'|'dialog_pick_folder')` 取 `{token, paths}`，再携带 `token` 调用对应命令。

### H3 + H4 + H5 + M2 + M3. 恶意 Office 文档触发 calamine 无界分配 → 进程 abort

- **位置**：`crates/vault-core/src/office.rs`（新增预扫描体系约 400 行 + 测试）
- **问题**：根因在 calamine 0.36.1 上游——`Range::from_sparse` 按单元格坐标包围盒一次性稠密分配 `cols×rows`（~32B/格）；`sharedStrings` 的 `uniqueCount` 直接 `reserve(n)`；xls 的 BIFF `0x0200` Dimensions 记录同样无界 reserve 且 `end < start` 时 u32 下溢。几 KB 的恶意文件即可要求数百 GiB 分配，Rust 分配失败走 `handle_alloc_error` → **abort**，`catch_unwind` 无法拦截，整个进程静默死亡。原有限制（`MAX_ROWS_PER_SHEET` 等）都在物化之后检查，形同虚设。另外 xlsx 路径缺少 docx 已有的 ZIP 纪律，64 MiB 压缩炸弹可展开至 64 GB。
- **修复**：所有 xlsx/xls 解析入口增加**预扫描**，在交给 calamine 之前按普通错误拒绝：
  - **xlsx（`prescan_xlsx`）**：
    - ZIP 条目数 ≤ 10000；
    - 逐条目**实测**解压尺寸 ≤ 64 MiB（中央目录声明可撒谎，必须真解压计量）+ 全部条目解压总量 ≤ 256 MiB（M3 压缩炸弹失效）；
    - `sharedStrings.xml`：`uniqueCount` ≤ 2,000,000 且实际 `<si>` 计数同限（H4）；
    - 各 worksheet：`<dimension ref>` 与每个 `<c r>` 坐标解析（`parse_cell_ref`），坐标超出 Excel 规格极限（行 > 1,048,576 / 列 > 16,384）直接拒绝；包围盒面积 ≤ 4,000,000 格（H3）。上限取 400 万而非审计建议的 100 万，为真实大型表格留兼容余量（≈128 MB 稠密内存，仍远低于 abort 阈值）。
  - **xls（`prescan_xls_ole`）**：用 cfb 打开 `/Workbook`（或 `/Book`）流，逐条扫描 BIFF 记录：
    - Dimensions（0x0200）：`end < start` 拒绝（H5 u32 下溢）、行 ≤ 65536、列 ≤ 256、包围盒 ≤ 4,000,000；
    - 真实单元格记录（FORMULA/LABELSST/NUMBER/LABEL/BOOLERR/RK/RSTRING/BLANK 及 MULRK/MULBLANK 的列区间）统计包围盒（M2），超限拒绝。
  - 加密 xlsx（Agile 解密后）与非 OLE 的 `.xls`（走 xlsx 解析器）同样被预扫描覆盖。
- **测试**（office.rs 9 个新单测 + 集成回归）：伪造 Dimensions（0xFFFFFFFF 行）、`end < start` 下溢、稀疏单元格包围盒（65536×256）、超大 uniqueCount、越界坐标、dimension 范围引用（`A1:XFD1048576`）均被拒绝；**完整最小合法 xlsx 照常预览**（防误伤回归）。

### H5 补充说明

入口 `extract_xls_ole_text` 现在的顺序为：OLE 解析（cfb）→ BIFF 预扫描 → `Xls::new`。流缺失/截断等结构问题不拦截（交由 calamine 报具体错误），只拦截确定的资源耗尽向量。

---

## 二、中危修复（M1–M8）

### M1. 头部字段无认证保护 → 回滚使已删除条目复活（本轮新完成）

- **位置**：`crates/vault-core/src/vault.rs`（`canonical_signed_bytes_v5`、`write_header_v5`、`verify_header_signature_v5`、`open_and_authenticate_v5`）；`crates/vault-core/src/crypto.rs`（注释修正）
- **问题**：分区条目中的 `index_offset/index_length`（条目内偏移 80..96）不在 auth_tag AAD、key_wrap AAD、锁区 HMAC 任何认证范围内；头部签名仅在失败诊断中校验、成功开柜从不校验。文件写攻击者（OneDrive 版本回滚/备份恢复/卷影拷回）把这两个字段换成旧副本的值，受害者用**正确密码**打开即静默加载旧索引——已删除条目复活、审计链回滚，改密码也无法清除。
- **修复**（签名规范形 + 成功开柜强制验签，无需 v6 格式变更）：
  1. **关键事实**：v5 锁定区（1642..1683，41 字节）位于签名范围（..1984）内，但创建时与会话内锁区恒为零（失败尝试只发生在打开阶段，成功打开即重置锁区并全量重签），因此**历史上所有合法签名都等于「锁区置零的规范形」签名**；
  2. `write_header_v5` 与 `verify_header_signature_v5` 一致改用规范形（锁区字节置零后计算）；
  3. `open_and_authenticate_v5` 在认证成功后、使用索引前**强制验签**，失败报「头部签名校验失败……文件可能已被篡改」并拒绝打开（密钥均为 ZeroizeOnDrop，早退安全）；
  4. 效果：改动签名范围内任何字段（含 M1 攻击目标）即破坏签名 → 正确口令也进不去；失败尝试不再使签名失真（见 L4）。
- **兼容性**：存量 v5 文件签名与规范形逐字节一致，零迁移；v4 签名范围（`SIGNED_LENGTH=887`）本就不含锁区（887=LOCK_OFFSET_V4），未改动。崩溃安全不受影响（save_index 的「写新索引→更新头部→擦旧索引」顺序中，崩溃后旧头部+旧索引+旧签名自洽，照常打开）。
- **文档化残余风险**：全文件级回滚（旧头部+旧签名+旧索引整体一致）无法与「合法的更早版本」区分，根治需 v6 在索引内嵌 generation 计数器——与审计「更快补丁」的边界一致。

### M4. 剪贴板保护/系统事件监听可被一条跨进程消息杀死

- **位置**：`src-tauri/src/clipboard_guard.rs`（重写 Windows 部分）、`src-tauri/src/system_events.rs`
- **问题**：message-only 窗口类名（`LVClip`/`LVSys`）是二进制常量，同会话恶意进程可 `FindWindowExW` 定位后：① 发 `WM_APP+1`（恰与应用 `WM_STOP=0x8001` 同值）当作合法停止；② 发 `WM_CLOSE`，`DefWindowProcW` 销毁窗口，`GetMessageW` 返回 -1 被旧代码 `r.0 <= 0` 当作退出。线程死亡后 `THREAD` 仍持有死句柄，`start()` 永久 no-op——剪贴板防泄露、锁屏/睡眠自动关柜两大防护**全程静默失效**。
- **修复**（两模块同型）：
  1. `WM_STOP` 处理加 `STOP_REQUESTED` 前置条件——外部伪造的 `WM_APP+1` 按普通消息忽略；
  2. `wnd_proc` 拦截 `WM_CLOSE` 返回 0，阻止销毁；
  3. `GetMessageW` 三态区分：-1/0 跳出内层循环，外层**重建监听窗口继续**（sleep 250ms，上限 60 次防风暴，超限 `log::error` 后放弃，下个开柜周期 `start()` 经 `JoinHandle::is_finished()` 重新武装）；
  4. 类名随机化（pid + 启动纳秒 + 序号），退出时 `UnregisterClassW` 防类泄漏；
  5. `start()` 检测死亡线程并重新武装（旧实现 `is_some()` 直接返回）。

### M5. %TEMP% 固定日志路径 → 硬链接注入/覆写用户文件

- **位置**：`src-tauri/src/main.rs`（`init_logging`、`FileLogger::log`）
- **问题**：`%TEMP%\LynVault.log` 公开可预测。攻击者预先建为指向受害者文件的 NTFS 硬链接 → 日志内容注入目标文件；超 1 MiB 轮转时清零覆写直接毁掉目标文件。
- **修复**：日志迁至 `%LOCALAPPDATA%\LynVault\logs\LynVault.log`（不可用回退 `%TEMP%\LynVault\logs\`）；每次写入以 `FILE_FLAG_OPEN_REPARSE_POINT` 打开（符号链接不跟随），并经 `GetFileInformationByHandle` 校验「非重解析点 + 硬链接数为 1」，校验失败放弃本次写入（防注入/防覆写）。

### M6. env::args() 遇非 UTF-8 参数 panic → GUI 进程无声消失

- **位置**：`src-tauri/src/main.rs:main()`
- **修复**：改用 `std::env::args_os()` + `to_string_lossy()`。畸形参数不再 panic（GUI 子系统无控制台，panic 即「双击后什么都没发生」）。

### M7. 解压命令任意目标目录 + 强制覆盖 → 任意写/持久化

- **位置**：`src-tauri/src/commands.rs`（`extract_files` / `extract_all_files` / `reject_protected_dest`）；与 H2 共用令牌体系
- **修复**：① 提取目标目录必须来自后端对话框令牌（同 H2）；② 新增 `reject_protected_dest`：目标（canonicalize 后、剥 `\\?\` 前缀、大小写不敏感带分隔符边界比较）不得位于 Windows 目录、Program Files（含 x86）、ProgramData、用户与全用户开始菜单（覆盖启动文件夹持久化原语）子树；③ 「提取全部」沿用前端覆盖确认 + 令牌贯通（预检非消费、执行消费）。

### M8. check_vault_file 无远程路径守卫（上一轮已完成）

- **位置**：`src-tauri/src/commands.rs:check_vault_file` + `ui/app.js` 拖放候选过滤
- **修复**：后端对远程/设备路径直接返回 `Ok(false)` 不做文件打开（复用 H1 的 `is_remote_or_device_path`）；前端拖放候选先行同样的字符串级过滤。另有本轮补充：`import_dropped_paths` 内部的保险柜魔数探测同样跳过远程路径（探测本身即文件打开）。

---

## 三、低危修复（L1–L13）

| 编号 | 问题 | 修复 | 位置 |
|---|---|---|---|
| **L1** | Office 解密密钥材料清零缺口；aes 未开 zeroize | `aes = { features = ["zeroize"] }`；`derive_key` 的拼接缓冲与完整散列清零；`password_ok` 的 expected/actual 清零；Standard 路径 expected/verifier_hash 清零并重构 key 清零路径（顺带修 I8 的 clone 裸 drop） | `crates/vault-core/Cargo.toml`、`office.rs` |
| **L2** | 单实例端口确定性派生 + 无鉴权 → 路径泄露/启动级 DoS | 端口（20000-39999）与 128 位令牌按安装随机生成并持久化到 `%LOCALAPPDATA%\LynVault\si.json`；转发握手 `HELLO + token`，对端令牌校验失败/超时一律不发送路径并**继续正常启动**；服务端令牌不符直接断开。同用户进程仍可读配置文件（同用户边界内无法根治，文档化残余风险）——攻击门槛从「离线静态计算」提高到「读文件并模仿协议」 | `single_instance.rs`（`SiConfig`、`load_or_create_si_config`、协议两侧） |
| **L4** | v5 失败路径写锁区后不重签 → 诊断永远误报篡改 | **随 M1 根治**：签名规范形使失败尝试不再影响签名；诊断分支「校验失败」现在即真实篡改（文案已相应收紧）。注：审计建议的「写锁区后重签」短期方案不可行（失败路径只有错误口令派生的 sign_key），规范形是等效且正确的实现 | `vault.rs` |
| **L5** | 文件关联注册未转义 exe 路径 | exe 路径含 `"` 时拒绝注册并记日志 | `file_assoc.rs` |
| **L6** | 剪贴板清理无防抖 → WinRT RPC 洪水 | 80ms 防抖：风暴窗口内更新置位 `PENDING_CLEAR` + `SetTimer` 尾沿定时器，WM_TIMER 统一补清；`clear_clipboard` 成功后记录墙钟毫秒 | `clipboard_guard.rs` |
| **L7** | `update_file_content` 先解码后限长 → 解码期 OOM | 按 `len*3/4` 先行拒绝（上一轮已完成） | `commands.rs` |
| **L11** | `search_files` 查询长度无界 | 超过 256 字符拒绝 | `commands.rs` |
| **L12** | 前端 `value=` 插值未转义 | 设置对话框三处数值统一走 `escapeAttr(String(...))` | `ui/app.js` |
| **L13** | 审计日志记录攻击者可控 vpath | 入库前控制字符替换为 `?` + 截断 200 字符 | `vault.rs` |

**L3**（锁区 MAC 密钥派生自公开盐）与 **L8/L9/L10**（scan/check/lock-info 存在性预言机）未修复，见第六节。

---

## 四、信息级修复（I1–I9）

| 编号 | 处置 |
|---|---|
| **I1** | `catch()` 的 panic 载荷改为只写 `log::error`（落新日志文件），对外返回通用文案「内部错误 (label): 操作失败，详情已记录日志」——内部路径等细节不再直达 WebView |
| **I3** | 版本号统一 2.8.2：`main.rs APP_VERSION`、`tauri.conf.json`、`src-tauri/Cargo.toml`、`crates/vault-core/Cargo.toml`（未做构建脚本单一来源注入，四处手改） |
| **I4** | 「内部错误：匹配分区丢失」（v4/v5 两处）改为如实描述：「头部与数据不匹配：找不到对应的分区（文件可能被篡改、损坏或与其他保险柜混用）」 |
| **I8** | Agile 载荷解密后校验 `remaining == 0`（截断包拒绝）；`u64→usize` 转换移到上限检查之后（32 位目标回绕风险）；styles.xml 等非扫描条目的炸弹由 M3 的逐条目实测解压覆盖 |
| **I2 / I5 / I6 / I9** | 未修复（I2 UI 透明度设计；I5 侵入性重构；I6 理论性问题但改 AAD 需迁移；I9 留档事项）——见第六节 |
| **I7** | 审计确认为 FYI（当前 wnd_proc 无 panic 路径），未改动；本轮新增的 `WM_CLOSE` 分支同样无 panic 路径 |

---

## 五、非审计项修复

- **密码框回车确认**（会话早期需求）：`ui/app.js` 新增 `initDialogEnterKey` IIFE——`#dialog` 上统一的 Enter 委托：单行输入框 Enter 触发主按钮（多字段时依次跳字段，最后字段提交；TEXTAREA/组合键/按钮焦点不拦截；异步执行期间按钮禁用自然防重）。覆盖所有走 `showDialog` 的对话框（解锁/创建保险柜、分区密码、加密文档、修改密码、设置等）。此前密码框未包 `<form>` 也未绑 Enter，必须手点「确定」。
---

## 六、第二轮补充审计修复（本轮新完成）

> 本节对应《LynVault_2.8.2_补充审计发现.md》的 53 项新发现；其中多数已在本轮修复，
> 全部改动已落码并通过 `cargo test -p vault-core`（17 lib + 39 集成）、
> `cargo check --release -p LynVault`、`node --check ui/app.js`。

### 高危

| 编号 | 问题 | 修复 | 位置 |
|---|---|---|---|
| **G1** | WTS_SESSION_LOGOFF 常量误写 0x9（实为 REMOTE_CONTROL）→ 注销永不关柜、远程控制会话误触发 | 改为 0x6 并注明 SDK 值；窗口类名随机化 + WM_CLOSE 拦截 + GetMessage 三态重建循环 | `system_events.rs` |
| **G2** | 文件 rename/move 不查文件夹命名空间 → 制造 file/folder 同键碰撞 | 四处（rename_file/rename_folder/move_file/move_folder）命名空间检查对称 | `index.rs` |
| **G3** | 文件夹改名/移动的子树键冲突静默覆盖 → 数据丢失 | 抽取共享纯函数 `rewrite_folder_keys`，以「键数量不变」为冲突锚点，碰撞即拒绝；rename/move 两份重复实现同步收敛（消除屎山） | `index.rs` |

### 中危（摘要）

- **审计链截断告警**：`AuditLog::from_entries` 丢弃尾部条目时置位 `truncated`，开柜路径写入显式告警条目（根治需 v6 条目数锚点，与全文件回滚同级）。
- **空闲自动锁定后端兜底**：新增 `idle_lock_watchdog`（GetLastInputInfo 系统级空闲，5 秒轮询），超过 autolock_minutes 且柜打开 → 与锁屏同一关闭流程；前端 JS 定时器不再是最后一道防线。
- **剪贴板回声竞态**：改为「清空前 S0 / 清空后 S1，仅 S1 == S0+1 才记录回声序列号」，他人抢写不再被误判为自己触发（明文不再漏清）。
- **system_events / single_instance 线程 panic 韧性**：`LOCK_IN_FLIGHT` 改为 catch_unwind 后必复位；单实例连接线程 panic 不再泄漏并发计数；APP 锁中毒恢复。
- **add/remove_partition 崩溃一致性**：先写头部、成功才提交内存（与 change_password_v5 同一纪律），失败不再分叉。
- **批量操作失败明细真实可达**：import_files_batch / import_folder / extract_files_batch / extract_all_files 返回 errors 数组，前端对话框展示（"明细已反馈前端"的假注释删除）；拖放部分失败时成功名单保留，用户可安全删除已导入的源文件。
- **整理后重开失败诚实报错**：defragment 成功路径重开失败 → 「已完成，请重开」语义 + 内存缓存对齐新布局；不再以「整理失败」误导重试。
- **shell.open 白名单锚定**：`^https://github\.com/lynvortex/LynVault/?$`；CSP 移除无用途的 `blob:`。
- **覆盖创建硬链接别名防护**：create() 覆盖路径检查 nNumberOfLinks > 1 即拒绝。
- **open_vault_rw 重解析点防护**：只查 is_symlink() → 检查 FILE_ATTRIBUTE_REPARSE_POINT 位（挂载点/OneDrive 占位等一切 tag 拒绝）。

### 低危 / 屎山 / 性能（摘要）

- normalize_vpath 越过根的 `..` 拒绝（不再静默重定向）；IndexManager::remove_file/remove_folder 补 DoD 密文覆写；空文件夹导入登记条目不再静默丢弃；符号链接跳过数真实统计（假注释修正）；import_files_batch 条目数上限；搜索 Unicode 大小写折叠回归修复（É/К/Σ 重新可命中）；锁定到期后重新获得完整尝试额度；load_file_data 32 位回绕死检查修正；settings.json 原子写入（temp+rename+fsync）；check_vault_file/get_lock_info/settings 三件套 async 化（文件 I/O 不进主线程）；preview_office_file 带口令尝试走 3 秒冷却；日志统一走 log crate（eprintln 清理）；dod_erase 进度逐 pass 真实上报、dod_erase_files 死代码删除；export_stem 重复代码收敛；catch() 的 I1 落实（panic 细节仅日志）；HMAC 构造 unwrap → expect（纪律注释落地）；workspace 增加 `[profile.release]`（thin LTO + strip）；批量导入 N 次 fsync → 1 次（save_index 统一 sync_all）；read_decrypt_file_data 改 decrypt_into（热路径省一份全尺寸分配）；defragment 去掉整索引深拷贝；get_file_info/list_all_folders/verify_integrity 改只读借用；verify_integrity 按物理偏移排序（顺序读）；前端：saveEdit/moveSelected 非破坏性错误、listFolder 序号守卫、工具栏忙态防重入、addPartition onCancel、启动流程 promise 泄漏修复、自动锁失败重挂计时器、escapeAttr 补单引号、三套转义/解包收敛、图标缓存命中同步路径、>4MB 文本单次解码、密码框 autocomplete、Enter 确认（P2-20）。

### 本轮未修复（有意保留，理由如下）

- **索引键大小写敏感**（/A.txt 与 /a.txt 可共存）：修之名删除存量数据，提取路径已有拒绝覆盖默认与失败计数兜底。
- **vpath 允许 `:` 等字符**：收紧会让存量保险柜中含此类字符的条目无法操作（GCM 认证的索引只进不出），提取端 sanitize_filename 已保证落地安全。
- **save_index 每次保存 7-pass 擦旧索引**：抗取证设计核心，不做会话内合并。
- **Tauri IPC 口令明文多副本**：String 在 WebView 堆 / IPC / serde 缓冲的副本无法零化，命令层 zeroize 只清最后一跳 —— 属 Tauri 1.x 架构限制，升级 Tauri 2 + 强类型通道时一并处理。
