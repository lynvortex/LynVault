# LynVault 2.0.1

抗取证加密保险柜 — 基于 Tauri + Rust 的桌面端加密文件管理系统。

将敏感文件加密存储于单个 `.vault` 文件中，通过密码或密码+密钥文件双重认证解锁，支持多分区隔离、安全擦除、Office 内联预览，以及完整的操作审计日志。

---

## 核心功能

### 1. 加密保险柜

- **加密算法**：AES-256-GCM（认证加密，防篡改 + 防窃听）
- **密钥派生**：PBKDF2-HMAC-SHA256（100 万次迭代）→ HKDF-SHA512 扩展，派生三把独立密钥：
  - `enc_key` — 加解密文件数据
  - `auth_key` — 认证标签验证（防暴力破解）
  - `sign_key` — 头部签名（HMAC-SHA512，防头部篡改）
- **认证方式**：
  - 纯密码模式
  - 密码 + 密钥文件双重认证（密钥文件可存储在 USB 等物理介质）
- **头部结构**：1024 字节固定头部，包含 magic bytes、版本号、salt、nonce counter、分区表、认证标签和签名，所有字段均校验完整性

### 2. 伪装分区（Plausible Deniability）

- 单个保险柜最多支持 **8 个独立分区**，每个分区拥有独立的密码和密钥
- 用不同密码打开保险柜会进入不同分区，**分区之间完全隔离**
- 不存在的分区不会暴露任何元数据（真·隐写术思路）
- 支持动态添加/删除分区，删除分区时安全擦除该分区所有数据

### 3. 文件浏览与管理

- **虚拟文件系统**：所有文件存储在加密保险柜内部，通过虚拟路径 (`vpath`) 访问
- **文件夹导航**：树状目录结构，支持路径输入框直接跳转 + 上级目录返回
- **导入文件**：选择本地文件导入到当前目录，支持多选批量导入
- **导入文件夹**：递归导入整个文件夹，保留目录结构
- **提取文件**：将保险柜内的文件解密导出到本地指定目录
- **批量操作**：支持 Ctrl+多选，批量提取、批量删除
- **新建文件夹**：在当前目录下创建子文件夹
- **重命名**：文件/文件夹重命名（右键菜单或选中后操作）
- **删除**：从保险柜中安全删除选中的文件/文件夹
- **右键菜单**：文件/文件夹右键弹出快捷操作菜单

### 4. 安全查看（零明文泄露）

无需导出即可在应用内预览文件内容，**文件始终不解密到磁盘**：

- **图片预览**：支持 PNG / JPG / GIF / BMP / WebP / TIFF，内置鼠标滚轮缩放
- **文本查看**：支持 TXT / MD / JSON / CSV / XML / INI / YAML 等纯文本格式，以及常见代码文件（.rs / .js / .go / .py / .sh 等）
- **Office 预览**：
  - `.docx` — 解压 ZIP 解析 `word/document.xml` 提取文本
  - `.xlsx/.xls` — 通过 calamine 读取所有工作表
  - `.pptx` — 解析幻灯片 XML
  - `.doc` — OLE 复合文档 UTF-16LE 文本流扫描
  - `.csv` — 直接 UTF-8 渲染
- 不支持的格式会提示导出后查看

### 5. 源文件安全擦除

导入文件后可选择**立即安全擦除源文件**，防止明文残留：

- **擦除标准**：DoD 5220.22-M 7-pass
  - Pass 1: `0xFF`
  - Pass 2: `0x00`
  - Pass 3: 随机数据
  - Pass 4: `0xFF`
  - Pass 5: `0x00`
  - Pass 6: 随机数据
  - Pass 7: 随机数据
- 每次写入后 `fsync` 确保落盘
- 支持单文件擦除和文件夹递归擦除（遍历所有文件后删除空目录结构）
- 支持进度回调

### 6. 保险柜销毁

- 二次确认后执行不可逆销毁
- 先关闭保险柜，再对整个 `.vault` 文件执行 DoD 5220.22-M 7-pass 擦除
- 擦除完成后删除文件

### 7. 碎片整理

- 对保险柜文件执行碎片整理，压缩冗余空间
- 整理后自动重新加载文件列表

### 8. 审计日志

- 记录所有关键操作（创建、打开、导入、提取、删除等）
- 带时间戳，可在界面内查看完整日志

### 9. 内存安全

- 所有密钥材料使用 `zeroize` crate 自动清零（`ZeroizeOnDrop`）
- 加解密中间变量（plaintext、master key、derived key）使用后立即 `zeroize()`
- 保险柜全局状态使用 `Mutex` 保护，panic 时自动 catch 防止闪退

---

## 项目结构

```
LynVault 2.0.0/
├── Cargo.toml                 # Workspace 根配置
├── Cargo.lock
├── src-tauri/                 # Tauri 桌面应用
│   ├── Cargo.toml
│   ├── tauri.conf.json        # Tauri 配置（窗口、权限、打包）
│   ├── build.rs
│   ├── icons/                 # 应用图标
│   └── src/
│       ├── main.rs            # 入口 + 命令注册
│       └── commands.rs        # 24 个 Tauri IPC 命令
├── crates/
│   └── vault-core/            # 核心加密库（纯 Rust，无平台依赖）
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs         # 模块导出
│           ├── vault.rs       # 保险柜生命周期管理
│           ├── crypto.rs      # AES-256-GCM / PBKDF2 / HKDF / HMAC
│           ├── index.rs       # 加密文件索引
│           ├── lock.rs        # 并发锁 + 签名验证
│           ├── audit.rs       # 操作审计日志
│           ├── wipe.rs        # DoD 安全擦除
│           ├── office.rs      # Office 文档文本提取
│           └── error.rs       # 错误类型定义
└── ui/                        # 前端界面（vanilla JS）
    ├── index.html             # 主界面
    ├── styles.css             # 样式（暗色主题）
    └── app.js                 # 交互逻辑
```

## Tauri IPC 命令

| 命令 | 说明 |
|---|---|
| `create_vault` | 创建新保险柜（加密 + 自动打开） |
| `open_vault` | 打开并认证保险柜 |
| `close_vault` | 关闭当前保险柜 |
| `list_folder` | 列出目录内容 |
| `import_file` | 导入单个文件 |
| `import_folder` | 递归导入文件夹 |
| `extract_file` | 提取单个文件 |
| `extract_files` | 批量提取文件 |
| `delete_files` | 安全删除文件（DoD 7-pass） |
| `delete_folder` | 删除文件夹 |
| `new_folder` | 新建文件夹 |
| `rename_item` | 重命名文件/文件夹 |
| `add_partition` | 添加伪装分区 |
| `remove_partition` | 删除伪装分区 |
| `list_partitions` | 列出所有分区 |
| `defragment_vault` | 碎片整理 |
| `get_audit_log` | 获取审计日志 |
| `destroy_vault` | 不可逆销毁保险柜 |
| `get_file_info` | 获取文件元信息 |
| `load_file_content` | 安全加载文件内容 |
| `preview_office_file` | Office 文档预览 |
| `secure_delete_source_files` | 安全删除源文件（导入后） |
| `secure_delete_source_folder` | 安全删除源文件夹（导入后） |

## 技术栈

| 层 | 技术 |
|---|---|
| 前端 | HTML + CSS + JavaScript (vanilla) |
| 框架 | Tauri 1.x |
| 后端 | Rust 2021 Edition |
| 加密 | aes-gcm (AES-256-GCM) / pbkdf2 (1M iterations) / hkdf / hmac / sha2 |
| 内存安全 | zeroize (ZeroizeOnDrop) |
| Office 解析 | calamine (Excel) / quick-xml (DOCX/PPTX) / zip |
| 打包 | Tauri bundler (Windows .exe / .msi) |

## 编译

```bash
# 安装 Tauri CLI
cargo install tauri-cli

# 开发模式（热重载）
cargo tauri dev

# 构建发布版
cargo tauri build
```

## 系统要求

- Rust 工具链 (rustup)
- Tauri 系统依赖：[tauri.app/start/#prerequisites](https://tauri.app/start/#prerequisites)
- Windows：WebView2 Runtime（Win 10 1803+ 通常已预装）
- 构建产物：`src-tauri/target/release/LynVault 2.0.1.exe`

## License

MIT
