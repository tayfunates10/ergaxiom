use ergaxiom_desktop_shell_runtime::{DesktopShellSnapshot, verify_desktop_shell_snapshot};
use serde::Serialize;

use crate::pipeline::build_pipeline_snapshot;

#[derive(Debug, Serialize)]
pub struct DesktopSnapshotResponse {
    pub verified: bool,
    pub source: &'static str,
    pub snapshot: DesktopShellSnapshot,
}

#[tauri::command]
pub fn get_desktop_shell_snapshot() -> Result<DesktopSnapshotResponse, String> {
    let snapshot = build_pipeline_snapshot()?;
    let verified = verify_desktop_shell_snapshot(&snapshot)
        .map_err(|error| format!("desktop snapshot verification failed: {error}"))?;
    if !verified {
        return Err("desktop snapshot digest mismatch".to_owned());
    }

    Ok(DesktopSnapshotResponse {
        verified: true,
        source: "deterministic_twin",
        snapshot,
    })
}

#[cfg(test)]
mod tests {
    use super::get_desktop_shell_snapshot;

    #[test]
    fn command_returns_only_verified_snapshot() {
        let response = get_desktop_shell_snapshot().expect("verified snapshot command must succeed");
        assert!(response.verified);
        assert_eq!(response.source, "deterministic_twin");
    }
}
