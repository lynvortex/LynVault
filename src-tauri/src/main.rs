// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
#[cfg(windows)]
mod file_assoc;
mod single_instance;

fn main() {
    // ── 2.4.1 新功能：.lyt 文件导航到软件后自动识别 ──
    // 场景 1：文件管理器双击 .lyt（程序启动时已自注册用户级文件关联，
    //        见 file_assoc.rs）→ 系统以「LynVault.exe <文件路径>」启动 →
    //        解析 argv 存入全局，前端启动时经 get_launch_vault_arg 读取
    //        并直接进入密码输入。
    // 场景 2：程序已在运行时再次双击 .lyt → 单实例端口被占 → 把路径
    //        转发给已运行实例后本进程立即退出；已运行实例聚焦窗口并
    //        向前端发 vault-file-requested 事件。
    // 场景 3：把 .lyt 拖到窗口（拖放识别在前端 check_vault_file 完成）。
    let argv: Vec<String> = std::env::args().skip(1).collect();
    commands::set_launch_vault_arg(single_instance::extract_vault_arg(argv.iter().cloned()));

    // 单实例竞争：非首实例在此转发参数并退出（不创建窗口，无闪烁）
    if !single_instance::acquire_or_forward(argv) {
        return;
    }

    tauri::Builder::default()
        .manage(commands::AppState::new())
        .setup(|app| {
            // 首实例：启动单实例监听线程（持有端口监听器直到进程退出）
            let handle = app.handle().clone();
            std::thread::spawn(move || single_instance::server_loop(handle));
            // 2.4.1：后台注册 .lyt 用户级文件关联（best-effort，不阻塞启动；
            // 用户已关联到其他程序时不覆盖）—— 仅 Windows
            #[cfg(windows)]
            std::thread::spawn(file_assoc::register_if_absent);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::create_vault,
            commands::open_vault,
            commands::close_vault,
            commands::list_folder,
            commands::import_file,
            commands::import_files_batch,
            commands::import_folder,
            commands::import_dropped_paths,
            commands::extract_file,
            commands::extract_files,
            commands::delete_files,
            commands::delete_folder,
            commands::new_folder,
            commands::rename_item,
            commands::add_partition,
            commands::remove_partition,
            commands::list_partitions,
            commands::defragment_vault,
            commands::destroy_vault,
            commands::get_file_info,
            commands::load_file_content,
            commands::preview_office_file,

            commands::scan_vault_files,
            commands::check_extract_all_dest,
            commands::extract_all_files,
            commands::get_file_icon,

            // 2.4.1 新增：.lyt 自动识别 + 前端就绪通知
            commands::check_vault_file,
            commands::get_launch_vault_arg,
            commands::frontend_ready,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
