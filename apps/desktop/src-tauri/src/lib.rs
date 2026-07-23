#![forbid(unsafe_code)]

mod commands;
mod pipeline;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let result = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::get_desktop_shell_snapshot
        ])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("ergaxiom desktop runtime failed: {error}");
        std::process::exit(1);
    }
}
