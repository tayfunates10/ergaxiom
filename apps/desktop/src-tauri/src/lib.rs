#![forbid(unsafe_code)]

mod commands;
mod pipeline;
mod product_jobs;
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
    let product_job_state = product_jobs::ProductJobState::initialize();
    let result = tauri::Builder::default()
        .manage(control_state)
        .manage(production_state)
        .manage(product_job_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_desktop_shell_snapshot,
            commands::approve_desktop_job,
            commands::start_desktop_job_execution,
            commands::cancel_desktop_job,
            commands::rollback_desktop_job,
            product_jobs::list_product_jobs,
            product_jobs::create_product_job,
            product_jobs::import_product_job_input,
            product_jobs::prepare_product_job,
            product_jobs::approve_product_job,
            product_jobs::start_product_job_execution,
            product_jobs::sync_product_job_from_production,
            product_jobs::cancel_product_job,
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
    let product_job_state = product_jobs::ProductJobState::initialize();

    // Ergaxiom Product Alpha is Windows-first. Constructing the complete command boundary keeps
    // non-Windows compilation and fail-closed startup tests honest without generating a runnable
    // platform bundle or requiring Windows release assets on Linux CI.
    let _builder = tauri::Builder::default()
        .manage(control_state)
        .manage(production_state)
        .manage(product_job_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_desktop_shell_snapshot,
            commands::approve_desktop_job,
            commands::start_desktop_job_execution,
            commands::cancel_desktop_job,
            commands::rollback_desktop_job,
            product_jobs::list_product_jobs,
            product_jobs::create_product_job,
            product_jobs::import_product_job_input,
            product_jobs::prepare_product_job,
            product_jobs::approve_product_job,
            product_jobs::start_product_job_execution,
            product_jobs::sync_product_job_from_production,
            product_jobs::cancel_product_job,
            production_startup::get_production_signer_status,
            production_startup::refresh_production_signer_status,
            production_startup::recover_production_signer_status
        ]);
}
