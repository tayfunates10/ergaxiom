from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    target = Path(path)
    text = target.read_text()
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"{label} anchor missing in {path}")
    target.write_text(text.replace(old, new, 1))


replace_once(
    "apps/desktop/src-tauri/src/pipeline.rs",
    '''    use ergaxiom_desktop_shell_runtime::{
        AuthorityStatus, DesktopApprovalRequest, StageStatus, issue_desktop_approval,
        verify_desktop_shell_snapshot,
    };

    use super::{PipelineSnapshotMode, build_pipeline_snapshot};
''',
    '''    use ergaxiom_desktop_shell_runtime::{
        AuthorityStatus, DesktopApprovalRequest, StageStatus, issue_desktop_approval,
        verify_desktop_shell_snapshot,
    };
    use serde_json::Value;

    use super::{PipelineSnapshotMode, build_pipeline_snapshot};
''',
    "pipeline test Value import",
)

replace_once(
    "apps/desktop/src-tauri/src/production_pipeline.rs",
    '''    let executed_snapshot = build_executed_snapshot(
        &prepared,
        approval,
        &production_evidence,
        &assessment.bundle_digest,
        &replay_manifest,
    )?;
''',
    '''    let executed_snapshot = build_executed_snapshot(
        &prepared,
        approval,
        &production_evidence,
        &assessment.bundle_digest,
        &replay_manifest,
    )
    .map_err(boundary_error)?;
''',
    "production executed snapshot error conversion",
)

replace_once(
    "apps/desktop/src-tauri/src/commands.rs",
    '''            Err(error)
                if matches!(
''',
    '''            Err(_error)
                if matches!(
''',
    "restart recovery unused guarded error",
)
