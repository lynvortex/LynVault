# LynVault 2.8.2 补充审计发现（第二轮）

> 范围：在《LynVault_2.8.2_更新说明.md》已记录问题（H1–H5 / M1–M8 / L1–L13 / I1–I9）**之外**的新发现。
> 方法：vault-core 全量精读（vault.rs / crypto.rs / index.rs / office.rs / wipe.rs / audit.rs / lock.rs）、commands.rs 全量精读、前端与外围模块并行扫描，关键结论均经人工二次验证并核对行号。

---

## 〇、最高优先级：版本错位 —— 更新说明中的 2.8.2 修复不在本代码快照内

当前 git 工作区干净（仅更新说明 MD 未跟踪），最后一次提交是 2.8.1 发布。逐项核实，MD 声称"已完成"的修复在代码中**全部不存在**：

| MD 声称 | 代码实际情况 |
|---|---|
| M6：`env::args_os()` | `main.rs:262` 仍是 `std::env::args()` |
| M5：日志迁 `%LOCALAPPDATA%` + 硬链接防护 | `main.rs:151` 仍写 `%TEMP%\LynVault.log`，无 reparse/硬链接校验 |
| M4：WM_CLOSE 拦截 / 类名随机化 / 线程重建 | `clipboard_guard.rs:178`（"LVC"）、`system_events.rs:76`（"LVSys"）固定类名，均无 WM_CLOSE 拦截 |
| H2/M7：对话框令牌（`dialog_pick_files` 等） | `commands.rs` 中 grep 计数为 0 |
| H3–H5：calamine 预扫描（`prescan_xlsx` 等） | `office.rs` 中 grep 计数为 0 |
| I3：版本号统一 2.8.2 | 四处均为 2.8.1 |

**含义**：修复代码要么丢失、要么改在另一份工作副本。若按当前快照出 2.8.2，更新说明即为虚假声明，且 H1–H5 全部处于未修复状态。下文所有条目均不再重复这些"已记录未落码"的问题。

---

## 一、高危（新发现）

### 1. WTS_SESSION_LOGOFF 常量写错：注销永不触发关柜（已验证）
- **位置**：`src-tauri/src/system_events.rs:74`
- `WTS_SESSION_LOGOFF` 正确值是 **0x6**，代码写成 `0x9`（实为 `WTS_SESSION_REMOTE_CONTROL`）。后果：① 用户注销时保险柜**不会**自动关闭（安全功能自 2.8.0 起从未生效）；② 远程控制会话开始/结束反而误触发关柜。与 `WM_POWERBROADCAST=0x0218`、`PBT_APMSUSPEND=4` 等全部手抄魔法数直接相关（windows crate 已启用对应 feature，本可用具名常量）。

### 2. 文件改名/移动缺文件夹命名空间碰撞检查（不对称，已验证）
- **位置**：`crates/vault-core/src/index.rs:250`（rename_file）、`index.rs:438`（move_file_in_index）
- `rename_file`/`move_file_in_index` 只查 `index.files` 是否冲突，**不查 `index.folders`**；而 `rename_folder`（:284）和 `move_folder_in_index`（:477）两个命名空间都查。把文件改名为已存在文件夹的名字（如把文件重命名为 `/x/notes`，而 `/x/notes` 是文件夹）会成功，制造 file/folder 同键碰撞——正是 2.8.1 注释里自己承认"语义含混、两套删除实现行为不同"的形态。检查应当四处对称。

### 3. 文件夹重命名/移动的子树键冲突静默覆盖 → 数据丢失
- **位置**：`crates/vault-core/src/index.rs:294-311`（rename_folder）、`index.rs:486-498`（move_folder_in_index）
- 子树重建时对新键 `new_files.insert(new_key, meta)` **无条件插入**，只在校验顶层 `new_vpath` 时查过一次冲突。若索引中存在 `/b/x.txt` 而 `folders` 缺少 `/b` 记录（遗留数据/历史版本索引），把 `/a` 改名/移动为 `/b` 会**静默覆盖 `/b/x.txt` 的元数据**——原文件密文变孤儿、内容从索引中消失，且无任何报错。C5"目标已存在时拒绝覆盖"的目标在子树层面未达成。子树重建应逐键检测冲突或做整体预检。

---

## 二、中危（新发现）

### 4. 审计链对"截断"无防护，恢复时静默接受
- **位置**：`crates/vault-core/src/audit.rs:111-138`（from_entries）
- 逐条校验遇第一条失败即 `break`，之前的合法条目被接受。链式 HMAC 只保证"追加不可篡改"，没有条目数/终点锚点——持有文件写权限的攻击者可以无痕砍掉尾部任意条目（如"密码修改失败""删除文件"记录），下次打开照常加载。与 `rekey`（:71-90）"任何一条失败即报错不静默丢弃"的原则自相矛盾。至少应把条目数写入头部受签名保护。

### 5. 空闲自动锁定主防线在前端 JS 定时器上，后端零兜底
- **位置**：`ui/app.js:1478-1534`；后端 `settings.rs` 仅有分钟数、`commands.rs` 无任何空闲检测
- Rust 侧没有 `GetLastInputInfo` 空闲检测：WebView2 后台计时器节流（最小化时定时器可被拖延数分钟）、渲染进程挂起/崩溃期间，保险柜保持解锁。对以"闲置自动上锁"为卖点的保险柜是结构性缺口——空闲检测应下沉到 Rust 层。

### 6. 剪贴板回声检查竞态 → 他人明文可残留
- **位置**：`src-tauri/src/clipboard_guard.rs:151-163`（已验证）
- `EmptyClipboard()` 之后才读 `GetClipboardSequenceNumber()` 存入 `LAST_CLEARED_SEQ`。若此窗口内其他程序（剪贴板管理器/输入法等高频写入者）抢先写入，存下的是**别人的**序列号，其对应的下一条 `WM_CLIPBOARDUPDATE` 会被误判为"自己触发"而跳过清空——明文残留恰发生在防护最该生效的场景。

### 7. system_events 的 LOCK_IN_FLIGHT / APP 无 panic 韧性 → 自动关柜永久失效
- **位置**：`src-tauri/src/system_events.rs:52-55`（已验证）、:27-29
- 关闭线程无 `catch_unwind`：`system_lock_vault` 内部 catch 之外还有 `clipboard_guard::stop()`（WinRT 调用）与 `emit_all`，任一 panic → 线程 unwind → `LOCK_IN_FLIGHT` 永久为 true → 本会话后续所有锁屏/睡眠自动关柜静默失效。同类：`spawn` 中 `if let Ok(mut guard) = APP.lock()` 在锁中毒时静默跳过，之后所有事件空转。

### 8. add_partition / remove_partition 违反自家崩溃一致性纪律
- **位置**：`crates/vault-core/src/vault.rs:1831-1844`（add）、:1858-1867（remove）
- 两者都是**先改内存 `self.partitions` 再 `update_header()`**，header 写失败时不回滚内存——与 `change_password_v5`（:1966-1979，失败恢复旧条目）的纪律不一致。失败后内存与磁盘分叉：后续任意一次 save_index 会把"失败的添加/删除"持久化；文件尾还会留下孤儿索引密文。

### 9. "失败明细已反馈前端"是假的：批量接口只返回计数
- **位置**：`vault.rs:2370`、`:2582`、`:3380`、`:3441`（注释）；`commands.rs:283`、`:349-357`、`:409-411`
- `import_files_batch` / `import_folder` / `extract_all_files` / `extract_files_batch` 全部只返回 `(ok, fail)` 计数，错误在 `log::warn!("明细已反馈前端")` 处被吞——前端永远无法知道**哪一项**失败。拖放导入在部分失败时把 `imported_files` 整体置空（:355-356），"可安全删除源文件"提示整体丢失：50 个文件哪怕 49 个成功也一个都不敢删。要么实现明细返回，要么改注释。

### 10. 长操作持有全局互斥锁 + 删除后静默自动整理无进度
- **位置**：`src-tauri/src/commands.rs:13`（单一 `Mutex<Option<Vault>>`）；`vault.rs:2806-2827`（auto_defragment_if_worthwhile）
- `verify_vault_integrity` / `defragment_vault` / v4 改密全库重加密期间持有全局锁，**所有其他命令（含列表、搜索、甚至 close_vault）排队阻塞**。更糟的是删除类操作死空间达标时**静默**触发一次完整整理（复制整个保险柜 + 备份 + 7-pass 擦除，GB 级文件可达分钟级），`None::<fn(usize)>` 无进度回调，UI 无任何提示——用户只会觉得"删除之后应用卡死了"。

### 11. defragment 成功分支重开文件失败 → 误导性错误 + 会话半死
- **位置**：`crates/vault-core/src/vault.rs:3253-3256`（已验证）
- 整理已提交（ReplaceFileW 完成、备份已擦）后，`open_vault_rw(...)?` / `lock_vault_exclusive` 失败直接 `?` 上抛：磁盘是新布局，会话 `file=None`（`is_open()=false` 但 enc_key 仍 Some），`cached_index` 仍是**旧偏移**。用户看到"碎片整理失败"会重试（再整理一次）而不是按提示重开。此处应与改密路径一致（:2200-2205 的"已生效、请重开"语义）。

### 12. shell.open 白名单为未锚定前缀匹配
- **位置**：`src-tauri/tauri.conf.json`（`"open": "https://github.com/lynvortex/LynVault"`，已验证）
- Tauri 1.x 将该字符串编译为前缀正则：`https://github.com/lynvortex/LynVault.evil.example/`、`.../LynVault/../../x` 等均放行。应写锚定形式（如 `^https://github\.com/lynvortex/LynVault/?$`）。叠加 CSP `style-src 'unsafe-inline'` 与 `withGlobalTauri: true`（完整 API 挂 `window.__TAURI__`），任何未来 XSS 即刻获得 invoke + 任意前缀 URL 打开能力。

### 13. 密钥派生 `?` 早退路径零化缺口（v4/v5 打开流程）
- **位置**：`crates/vault-core/src/vault.rs:1299-1301`（v4 keys_list）、`:1494-1509`（v5 kek_list）
- `for r in results { keys_list.push(r?) }`：`r?` 早退时——v4 侧 `keys_list` 中已 push 的 KeyMaterial 随 Vec drop **不清零**；v5 侧 `results` 里尚未 push 的裸 `[u8;32]` KEK 同样裸 drop。与 2.8.1 自己声称的"`?` 提前返回路径不残留明文密钥"纪律直接矛盾（create/add_partition/change_password 都修了，唯独打开循环漏了）。

### 14. 覆盖创建路径的硬链接别名残留
- **位置**：`crates/vault-core/src/vault.rs:990-1007`
- 2.8.1 的"同一句柄验证 magic 后再 set_len(0)"修掉了符号链接/替换竞态，但**硬链接别名**仍在：同用户攻击者预先把"普通文件 A"硬链接到受害者文件 B，用户确认覆盖 A 时 `set_len(0)` + 后续写入作用在共享 inode 上——B 被清零。句柄锚定防不住别名共享内容。

---

## 三、低危（新发现）

### 15. `open_vault_rw` 重解析点防护只查 `is_symlink()`
- `vault.rs:157-166`：OneDrive 按需占位文件、挂载点等其他 reparse tag 直接放行（与注释"重解析点一律拒绝"不符）；且 `FILE_FLAG_OPEN_REPARSE_POINT` 打开云占位保险柜可能导致水合失败/读到占位元数据。

### 16. 搜索大小写折叠退化为 ASCII-only —— 检索回归
- `vault.rs:2303`（`make_ascii_lowercase`）：É↔é、К↔к 等非 ASCII 大小写不再命中。注释声称"仅收窄 ß↔SS 这一罕见情形"**不实**——整片拉丁扩展/西里尔/希腊用户全部受影响。

### 17. 空文件夹导入静默丢弃
- `vault.rs:2567-2569`：`collected.is_empty()` 直接 `Ok(())`，且父文件夹只在有文件时登记——拖入空目录既无提示也不产生条目，用户以为导入了。

### 18. 符号链接跳过日志谎报"已计入失败计数"
- `vault.rs:2616`：`log::warn!("……已计入失败计数")`，实际 `continue`，失败计数没加；`import_folder` 的汇总也不体现跳过项。

### 19. 锁定到期后"零宽容"：lock_count 过期不清零
- `lock.rs:62-74`：30 分钟锁定到期后输错 **1 次**立即再锁 30 分钟（count 仍 ≥5，saturating_add 后直接触发）。对密码易错的正常用户等于永封直到一次输对。`LOCKOUT_SECONDS as u64` 也依赖常量恰为整数。

### 20. 32 位截断检查是死代码
- `vault.rs:3041`：`length as usize > MAX_INMEM_BUFFER` 在 32 位目标上会先回绕（大 u64 变小 usize）根本拦不住，真正的防线在 `read_decrypt_file_data`（:635）。同类屎山：`wipe.rs:49` `length > usize::MAX as u64` 恒为 false，永不触发。

### 21. settings.json 非原子写入 + 损坏后静默回默认值
- `settings.rs:153`（`fs::write` 无 temp+rename、无 fsync）：掉电/被杀 → 配置截断 → `load_active` 返回 None（无日志）→ 防截屏关闭状态、主题等静默丢失；再 `enable_persistence` 时 `unwrap_or_default()` 以全默认值**覆盖**旧配置（`commands.rs:956-958`），无提示。

### 22. FileLogger：每条日志重新 open + 多实例交错 + 锁内同步零写
- `main.rs:116-148`：每条日志 `OpenOptions::open` + metadata + seek（不保存句柄）；无跨进程互斥，降级多开时两实例交错写/各自轮转；轮转在锁内同步把 1MiB+ 日志按 8KB 零写（首次超限的写入会被拖住）。

### 23. 单实例协议："." 结束行从未校验、回执先于路径校验
- `single_instance.rs:219-221`（已验证）：`dot` 读入后是死变量；:209 在校验路径之前就回 `"OK\n"`——转发损坏/非法 .lyt 时，第二实例拿到"成功"回执后退出，用户双击后"什么都没发生"。

### 24. 同步命令在主线程做文件 I/O
- `commands.rs:736`（check_vault_file）、`:916`（get_lock_info）、`:929/949/966`（settings 三件套）为非 async 命令——Tauri 1.x 在主线程执行；`check_vault_file` / `get_lock_info` 对网络盘路径会冻结 UI（且本快照无 M8 远程路径守卫）。`scan_vault_files` 反而正确地进了 spawn_blocking——同类操作两种待遇。

### 25. Office 文档口令尝试无任何限速
- `commands.rs:629`（preview_office_file）没有 `check_auth_cooldown`——开柜口令有 3 秒冷却，Office 文档口令可在进程内全速暴力尝试（XSS 或恶意自动化场景下每秒可达数十次）。

### 26. `import_files_batch` 无条目数上限
- `vault.rs:2351-2382`：`src_paths: &[String]` 长度不设限（`MAX_IMPORT_ENTRIES` 只覆盖文件夹遍历）；被攻陷的 WebView 可传入海量路径使保险柜无限膨胀。

### 27. vpath 字符集策略三处不一致
- `index.rs:51-80` validate 只禁控制字符/反斜杠/点段：`:` 可进 vpath、段允许尾点/尾空格；提取时 `sanitize_filename`（vault.rs:649）再剔除——柜内名与提取名静默不一致。`normalize_vpath` 把 `"/../a"` 归一成 `"/a"` 而非拒绝（:93-97，越界尝试被静默重定向）。另外 HashMap 键大小写敏感，`/A.txt` 与 `/a.txt` 可共存，提取到 Windows 大小写不敏感 FS 必冲突其一。

### 28. `IndexManager::remove_file/remove_folder` 不擦密文
- `index.rs:164-219`：库级 API 的删除只动索引，不做 DoD 覆写——与 `secure_delete_file` 形成两套删除语义（后者才是宣传的"安全删除"），任何库调用方都会踩坑。

### 29. 前端：保存失败销毁编辑器丢内容
- `ui/app.js:1046`（代理发现，行号已核对）：`saveEdit` 失败时 `showError` 内部 `showDialog` 用错误内容整体替换 `#dialog-body`，textarea 连同用户未保存的编辑被清空；:1047 注释"保留编辑内容让用户重试"与实际行为相反。磁盘满/保险柜被锁场景下可能丢数千字编辑。

### 30. 前端：listFolder 无序号守卫，慢响应晚到覆盖新状态
- `ui/app.js:674-694`：快速连点目录 A→B，后完成的 A 响应同时决定渲染与 `state.currentFolder`；且 681-683 无条件清搜索框、置 `searchMode=false`，陈旧目录响应能顶掉用户新发起的搜索（`runSearch` 有 `_searchSeq`，listFolder 与之无交叉防护）。

### 31. 前端：工具栏批量操作全部无防重入/忙态
- `ui/app.js:763-875`：`importFiles`/`importFolder`/`extractSelected`/`extractAllFiles`/`deleteSelected`/`defragmentVault` await 期间按钮不禁用——DoD 7-pass 删除进行中再点删除/提取，操作并发打进后端（后端互斥锁会串行化，但两个"删除+整理"叠加的耗时是双倍，且 UI 状态机错乱）；双击"导入"发起两次批量导入。

### 32. 前端：对话框 promise 泄漏与启动软锁
- `ui/app.js:1094-1102`：`addPartition` 的两个 `new Promise(resolve => showInput(...))` 无 onCancel——点遮罩关闭对话框则 resolve 永不调用，async 函数永久挂起（对比 `promptEncryptedOffice:896` 是对的）。`ui/app.js:1963-2005`、`:1878-1892`：`tauriSave/tauriOpen/tauriAsk` 裸 await 无 catch，插件 invoke 一旦 reject，`_startupProcessing` 永久为 true，启动列表全被守卫拦死——软锁到重启。

### 33. 前端：自动锁失败路径不重挂计时器
- `ui/app.js:1498-1534`：`close_vault` 失败走 catch 后 `_idleTimer` 为 null 且无人重建——柜保持打开但**失去自动锁**，直到下次用户活动才恢复；自动保存失败仅状态栏一句话就继续关柜，未保存编辑直接丢。

### 34. 前端：三份转义映射并行漂移 + `escapeAttr` 不转义单引号
- `ui/app.js:413-417`（escapeAttr 无 `'`）、`:1062-1064`（viewFile 手写第三份映射）、`:39-44`（诊断 HTML 未转义插值）。当前各调用点恰好用双引号包属性所以不可利用，属"差一个模板就 XSS"的埋雷。

### 35. 前端：密码输入框无 `autocomplete` 约束
- `ui/app.js:436`、`:1329-1331`：密码框未加 `autocomplete="off"/"new-password"`（搜索框反而加了）；WebView2 表单语境下可能触发保存/自动填充提示。`showInput` 把 `value` 属性拼进 innerHTML（当前恒空串），未来一旦预填密码就会进 HTML 源。

### 36. 擦除进度回调 7 连发 + `dod_erase_files` 死代码带整除 bug
- `wipe.rs:123-127`：进度在 7 pass 全部写完后才连发 7 次（0% 直跳 100%），GB 级擦除全程无反馈。`wipe.rs:203-220` `dod_erase_files` 全仓库无调用者，且 `100 / paths.len()` 整除：3 个文件最高 99%、>100 个恒 0。

---

## 四、屎山 / 一致性

37. **注释与实现不符**：`vault.rs:2738-2743` 承诺"写入后验证仍是普通文件"，`extract_file_inner` 两个平台分支都没有验证步骤；`wipe.rs:39-41` 的函数注释与实际复用关系漂移。
38. **`create_v4_for_tests` 以 `pub` 进入生产库**（`vault.rs:1099`）——测试夹具 API 打进发布二进制，且整个函数是 create() 的复刻粘贴（已是第二份拷贝）。
39. **crypto.rs 的"零 panic 纪律"自相矛盾**：`encrypt_gcm` 的 expect 修成了错误传播（:221 注释还专门强调纪律），但 `create_auth_tag`（:324）、`create_auth_tag_bound`（:363）、`compute_header_signature`（:393）、`derive_lock_mac_key`（crypto.rs:39）、`derive_legacy_lock_key`（:90）及 audit.rs 四处 HMAC `new_from_slice(...).unwrap()` 原样保留（HMAC 任意长度 key 恒成功，实际无险，但纪律是纸面的）。
40. **重复代码温床**：`check_extract_all_dest` 与 `extract_all_files` 的 safe_stem 清洗逐行复制（commands.rs:1097-1104 / 1131-1141）；`rename_folder` 与 `move_folder_in_index`、`rename_file` 与 `move_file_in_index` 四个函数近乎两两复制；`normalize+validate` 三行组合在全库重复 15+ 次。
41. **死变量/死参数**：`single_instance.rs:219`（`dot`）、`app.js` 的 `getIcon(name, isFolder)` 参数从未使用、`_activeBlobUrls` 整套 blob 追踪无生产者（连 CSP `img-src blob:` 都是它的陪葬）。
42. **版本号四处漂移**：main.rs 窗口标题、两个 Cargo.toml、tauri.conf.json 均 2.8.1；app.js 头注释还写着 "LynVault 2.0"；目录名与 MD 是 2.8.2。无单一来源。
43. **windows crate 0.57 feature 集两处手工维护**（src-tauri 与 vault-core 各一份），已落后多个版本的安全修复；workspace 根无 `[profile.release]`（无 LTO/strip/opt 优化，发布二进制 9.9MB）。
44. **Tauri IPC 口令明文传输是诚实的残余风险**：`String` 参数在 WebView JS 堆、IPC JSON、serde 反序列化缓冲里有多份无法零化的副本，命令层的 `password.zeroize()` 只清最后一跳——建议至少在 README 安全模型里如实文档化。

---

## 五、性能优化点

45. **批量导入的 fsync 假优化**：`import_file_into_index` 每文件仍 `flush()+sync_all()`（vault.rs:2450-2452）——"批量只需 1 次保存"只省了索引重写，数据 fsync 仍是 N 次，千文件导入依旧 1000 次 fsync。应在批量路径积累缓冲、末尾一次性 sync。
46. **每次读文件双倍内存**：`read_decrypt_file_data` → `decrypt_gcm` 分配套密文 Vec + 独立明文 Vec（crypto.rs:243-253）；`decrypt_into`/`encrypt_into`（:279-317）已为此而写却只接了 v4 升级一条管线。热路径（预览、提取、体检）全部可换。
47. **defragment 步骤 4 无谓深拷贝**：`vault.rs:3191` `index.clone()` 整索引克隆后立即序列化——先注入 audit 再 `to_vec(&index)` 即可，10k 文件索引省一次数 MB 分配。
48. **`get_file_info` / `list_all_folders` / `verify_integrity` 用 `load_index()`（整索引克隆）**而不是已有的 `index_ref()` 只读借用（commands.rs:581、vault.rs:2329-2334、:2258）——2.8.1 优化只覆盖了 list_folder/search 两处。
49. **文本预览先全量解码后判断门槛**（app.js:977-1004，代理发现）：60MB "txt" 要先 `atob` + 逐字符循环 + 两次 TextDecoder 全部完成，才在 :998 判定"只读预览"。应按 base64 长度提前分流。同类：64MiB 文本经 JSON 字符串过 IPC（office 预览路径无 base64 化）。
50. **`verify_integrity` 逐文件排序后乱序解密**：items 按路径排序但物理偏移乱序，HDD/网络盘上随机跳转；按 offset 排序可顺序读。
51. **`search_files` 每键触发全索引线性扫描**（前端防抖 300ms 后仍全表扫 HashMap + 逐项 ASCII 折叠）——10 万条目下单次 ~ms 级尚可，但 limit 之前仍构造全部命中 Vec；可改为命中 limit 即短路（当前实现 `hits.truncate(limit)` 在扫描完之后）。
52. **文件列表图标二次 DOM 变更**（app.js:568-574）：缓存命中的扩展名也要 await 微任务后替换节点，2000 行列表 ≈ 2000 次跨微任务替换；可挂载前批量预解析。
53. **日志写放大**：`wipe_old_index_range` 每次保存对旧索引做 7-pass 覆写（每次编辑保存 = 7×索引体积写入 + sync）——安全设计如此，但结合"每次 saveEdit 都 save_index"，高频编辑场景可考虑会话内合并擦除。

---

## 附：本次审计方法与置信度说明

- 一、二节全部条目与三节的 15/16/18/19/20/22/23/24/25/26 均由主审计逐行验证（文中行号直接来自源码）。
- 三节的 29-35（前端）与 21 的部分细节来自并行探索代理的精读报告，代理对关键定级做了后端交叉验证；前端行号未逐条复核，修复前请以实际代码为准。
- 已刻意排除更新说明已记录的全部条目（H/M/L/I 系列），包括本快照中"声称已修未修"的部分——那属于第〇节版本错位问题，不重复计分。
