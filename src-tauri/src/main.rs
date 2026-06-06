// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

fn main() {
    tauri::Builder::default()
        .manage(commands::AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::create_vault,
            commands::open_vault,
            commands::close_vault,
            commands::list_folder,
            commands::import_file,
            commands::import_folder,
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
            commands::get_audit_log,
            commands::destroy_vault,
            commands::get_file_info,
            commands::load_file_content,
            commands::preview_office_file,

            commands::secure_delete_source_files,
            commands::secure_delete_source_folder,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
