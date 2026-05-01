### 概述
**LynVault** 是一个支持**可否认加密**的多分区加密文件柜。  
所有文件被加密存储在单个 `.vault` 容器中，通过**不同密码**可解锁不同的分区（真实分区与伪装分区），并可叠加**密钥文件**增强安全性。

加密算法采用 **PBKDF2 密钥派生 + AES-256-GCM 加密**，元数据由 HMAC-SHA512 保护。  
保险柜内置防篡改审计日志、安全擦除以及暴力破解锁定（5 次错误后锁定 30 分钟）。

### 功能特色
- 🔐 高强度加密：PBKDF2 (100 万次迭代) + AES-256-GCM
- 🎭 可否认性：最多 8 个分区，各自独立密码 / 密钥文件
- 🛡️ 反取证：DoD 7 次覆写安全删除
- 🔒 连续错误自动锁定
- 📜 链式哈希审计日志（防篡改）
- 🖥️ 跨平台图形界面（基于 PySide6）

### 环境要求
- Python 3.9 或更高版本
- PySide6
- cryptography

安装依赖：
```bash
pip install -r requirements.txt
```

### 使用方法
运行程序：
```bash
python main.py
```

**新建保险柜**  
`文件 → 新建保险柜` → 选择保存位置，设置主密码（至少 12 位），可选密钥文件。

**打开保险柜**  
`文件 → 打开保险柜` → 选择 `.vault` 文件，输入对应密码（以及密钥文件）。  
若输入**伪装分区密码**，则会打开对应的隐藏分区。

**导入文件**  
可直接拖拽文件/文件夹到窗口，或通过工具栏按钮导入。

**管理伪装分区**  
`操作 → 添加伪装分区` / `删除伪装分区`

**提取 / 删除**  
右键文件，选择“提取”或“安全删除”。

### 打包为独立 EXE（Windows）
```bash
pyinstaller --onefile --windowed --icon=icon.ico --name LynVault main.py
```
若需要体积较小的启动器（依赖外置），可将 `--onefile` 替换为 `--onedir`。

### 安全须知
- 保险柜**不存储密码**，仅保存认证标签的派生值。
- 请使用**足够复杂的主密码**（12 位以上）并考虑配合密钥文件。
- 审计日志采用链式哈希，任何篡改均会导致链断裂。
- **无后门**，忘记密码将无法恢复数据。

### 开源许可
本项目基于 MIT License 发布。  
© 2025 LynVortex

### Overview
**LynVault** is a local, multi-layer encrypted file container with **plausible deniability**.
It creates a single `.vault` file where you can securely store files.  
The vault supports multiple **hidden partitions**: one real partition and several fake ones, each unlocked by a **different password** (optionally combined with a **key file**).

All data is encrypted with **AES-256-GCM**, and every critical header is integrity-protected with HMAC-SHA512. The vault includes **audit logging**, **anti-tampering** and **brute-force lockout** (after 5 wrong attempts, locked for 30 minutes).

### Features
- 🔐 Strong encryption: PBKDF2 (1 000 000 iterations) + AES-256-GCM
- 🎭 Plausible deniability: up to 8 partitions, each with its own password / key file
- 🛡️ Anti‑forensic: secure deletion with DoD 7‑pass overwrite
- 🔒 Auto‑lock after consecutive failed attempts
- 📜 Chain‑hashed audit log (tamper‑evident)
- 🖥️ Cross‑platform GUI (Windows, Linux, macOS) built with PySide6

### Requirements
- Python 3.9+
- PySide6
- cryptography

Install dependencies:
```bash
pip install -r requirements.txt
```

### Usage
Run the application:
```bash
python main.py
```

**Create a vault**  
`File → New Vault` → choose a location, set a master password (min. 12 chars) and optionally a key file.

**Open a vault**  
`File → Open Vault` → select the `.vault` file, enter the password (and key file if used).  
If you enter a **fake password**, the corresponding hidden partition will open instead.

**Add files**  
Drag & drop files/folders into the window, or use the toolbar buttons.

**Manage hidden partitions**  
`Actions → Add Decoy Partition` / `Remove Decoy Partition`

**Extract / Delete**  
Right‑click a file and choose "Extract" or "Secure Delete".

### Building a standalone EXE (Windows)
```bash
pyinstaller --onefile --windowed --icon=icon.ico --name LynVault main.py
```
For a smaller launcher (using external dependencies), replace `--onefile` with `--onedir`.

### Security Notes
- The vault does **not** store passwords – only a derived authentication tag is saved.
- Use a **strong master password** (> 12 characters) and consider a key file.
- The audit log is chain‑hashed; any tampering will break the chain.
- There is **no backdoor** – lost passwords cannot be recovered.

### License
This project is released under the MIT License.  
© 2025 LynVortex
