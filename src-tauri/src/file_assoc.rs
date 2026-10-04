//! 2.4.1 新功能：.lyt 文件关联自注册（Windows 专属模块，main.rs 中已 cfg 门控）。
//!
//! 目的：让「资源管理器双击 .lyt → 直接弹出 LynVault 密码输入」开箱即用。
//! Tauri 1.x 的 bundle 配置不支持 fileAssociations（Tauri 2.0 才有），
//! 也没有 NSIS installerHooks；因此采用**运行时自注册**方案：
//! - 写 HKCU\Software\Classes（用户级，无需管理员，便携版 exe 同样生效）；
//! - 仅当 `.lyt` 尚无关联或已指向本程序时写入 —— 用户手动设置的
//!   其他关联（如选择了别的编辑器）绝不被覆盖；
//! - 全程 best-effort：任何失败只记日志，绝不影响启动。
//!
//! 注册表布局（与 NSIS 手工注册完全一致）：
//! ```text
//! HKCU\Software\Classes\.lyt                    (默认) = LynVault.Vault
//! HKCU\Software\Classes\LynVault.Vault          (默认) = LynVault 加密保险柜
//! HKCU\Software\Classes\LynVault.Vault\DefaultIcon        = "<exe路径>,0"
//! HKCU\Software\Classes\LynVault.Vault\shell\open\command = ""<exe路径>" "%1""
//! ```
//! 双击 .lyt 时系统执行 `LynVault.exe <文件路径>`，main.rs 解析 argv 后
//! 前端直接进入该保险柜的密码输入（配合单实例端口转发，程序已在运行时
//! 也能正确聚焦并打开）。

const PROG_ID: &str = "LynVault.Vault";
const PROG_DESC: &str = "LynVault 加密保险柜";

/// 入口：尝试注册（若缺失）。应放在后台线程调用，避免拖慢启动。
pub fn register_if_absent() {
    use std::io;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            log::warn!("[LynVault] 无法定位自身路径，跳过 .lyt 关联注册: {}", e);
            return;
        }
    };
    let exe_str = match exe.to_str() {
        Some(s) => s.to_string(),
        None => return, // 非 UTF-8 路径，极罕见，放弃
    };
    // 2.8.2（L5）：exe 路径含双引号时拒绝注册 —— 路径会被拼进注册表命令
    // `"<exe>" "%1"`，未转义的引号可使命令结构被操纵
    if exe_str.contains('"') {
        log::warn!("[LynVault] exe 路径包含双引号，拒绝注册 .lyt 文件关联（防命令结构被操纵）");
        return;
    }

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let classes = match hkcu.open_subkey_with_flags("Software\\Classes", KEY_READ | KEY_WRITE) {
        Ok(k) => k,
        Err(e) => {
            log::warn!(
                "[LynVault] 打开注册表 Classes 失败，跳过 .lyt 关联注册: {}",
                e
            );
            return;
        }
    };

    // 已有关联？
    // 2.7.1 修复：此前只要 .lyt 指向本 ProgId 就会重写全部 4 个键并广播
    // SHCNE_ASSOCCHANGED —— 既无意义，又会被安全软件反复判为「修改文件关联」
    // 的高危行为而弹风险提示。现已注册且 open 命令指向当前 exe 时直接跳过
    //（exe 移动 / 替换后命令不匹配，自然重新注册）。
    if let Ok(dot) = classes.open_subkey_with_flags(".lyt", KEY_READ) {
        if let Ok(existing) = dot.get_value::<String, _>("") {
            if existing.eq_ignore_ascii_case(PROG_ID) {
                if let Ok(cmd_key) = classes
                    .open_subkey_with_flags(format!("{}\\shell\\open\\command", PROG_ID), KEY_READ)
                {
                    if let Ok(cmd) = cmd_key.get_value::<String, _>("") {
                        if cmd == format!("\"{}\" \"%1\"", exe_str) {
                            return;
                        }
                    }
                }
            } else if !existing.is_empty() {
                // 用户已将 .lyt 关联到其他程序 —— 尊重用户选择，不覆盖
                return;
            }
        }
    }

    let write_res: io::Result<()> = (|| {
        // .lyt → ProgId
        let (dot, _) = classes.create_subkey(".lyt")?;
        dot.set_value("", &PROG_ID)?;

        // ProgId 描述 / 图标 / 打开命令
        let (prog, _) = classes.create_subkey(PROG_ID)?;
        prog.set_value("", &PROG_DESC)?;
        let (icon, _) = classes.create_subkey(format!("{}\\DefaultIcon", PROG_ID))?;
        icon.set_value("", &format!("{},0", exe_str))?;
        let (cmd, _) = classes.create_subkey(format!("{}\\shell\\open\\command", PROG_ID))?;
        cmd.set_value("", &format!("\"{}\" \"%1\"", exe_str))?;
        Ok(())
    })();
    if let Err(e) = write_res {
        log::warn!("[LynVault] .lyt 关联自注册失败（不影响其他功能）: {}", e);
        return;
    }

    // 通知 Explorer 刷新关联（失败无妨，重启 Explorer 后自然生效）
    //（2.7.1：日志器只落 Warn 及以上，移除永不记录的 info 日志）
    notify_shell();
}

/// 广播 SHCNE_ASSOCCHANGED，让资源管理器立即刷新图标与关联。
fn notify_shell() {
    use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};
    // windows 0.57 签名：dwitem1/dwitem2 为 Option<*const c_void>（SHCNE_ASSOCCHANGED 不带 item）
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }
}
