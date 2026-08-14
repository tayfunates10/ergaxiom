#![forbid(unsafe_code)]

mod commands;
mod pipeline;
mod production_execution;
mod production_startup;

#[cfg(windows)]
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
    let production_execution_state = production_execution::ProductionExecutionState::initialize();
    let result = tauri::Builder::default()
        .manage(control_state)
        .manage(production_state)
        .manage(production_execution_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_desktop_shell_snapshot,
            commands::approve_desktop_job,
            commands::start_desktop_job_execution,
            commands::cancel_desktop_job,
            commands::rollback_desktop_job,
            production_startup::get_production_signer_status,
            production_startup::refresh_production_signer_status,
            production_startup::recover_production_signer_status
        ])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        eprintln!("ergaxiom desktop runtime failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let control_state = match commands::DesktopControlState::new() {
        Ok(state) => state,
        Err(error) => {
            eprintln!("ergaxiom desktop control authority failed to initialize: {error}");
            return;
        }
    };
    let production_state = production_startup::ProductionStartupState::initialize();
    let production_execution_state = production_execution::ProductionExecutionState::initialize();

    // Ergaxiom Product Alpha is Windows-first. Constructing the complete command boundary keeps
    // non-Windows compilation and fail-closed startup tests honest without generating a runnable
    // platform bundle or requiring Windows release assets on Linux CI.
    let _builder = tauri::Builder::default()
        .manage(control_state)
        .manage(production_state)
        .manage(production_execution_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_desktop_shell_snapshot,
            commands::approve_desktop_job,
            commands::start_desktop_job_execution,
            commands::cancel_desktop_job,
            commands::rollback_desktop_job,
            production_startup::get_production_signer_status,
            production_startup::refresh_production_signer_status,
            production_startup::recover_production_signer_status
        ]);
}
