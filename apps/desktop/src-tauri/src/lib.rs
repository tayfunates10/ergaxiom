#![forbid(unsafe_code)]

mod commands;
mod pipeline;
mod production_startup;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let control_state = match commands::DesktopControlState::new() {
        Ok(state) => state,
        Err(error) => {
            eprintln!("ergaxiom desktop control authority failed to initialize: {error}");
            std::process::exit(1);
        }
    };
    let production_state = production_startup::ProductionStartupState::initialize();
    let result = tauri::Builder::default()
        .manage(control_state)
        .manage(production_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_desktop_shell_snapshot,
            commands::approve_desktop_job,
            commands::start_desktop_job_execution,
            commands::cancel_desktop_job,
            commands::rollback_desktop_job,
            production_startup::get_production_signer_status
        ])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("ergaxiom desktop runtime failed: {error}");
        std::process::exit(1);
    }
}
