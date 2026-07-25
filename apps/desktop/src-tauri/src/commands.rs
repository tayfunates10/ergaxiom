use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_desktop_shell_runtime::{
    DesktopApprovalRecord, DesktopApprovalRequest, DesktopCommandAction, DesktopCommandReceipt,
    DesktopControlStatus, DesktopShellSnapshot, control_status_from_snapshot,
    issue_desktop_approval, issue_desktop_command_receipt, verify_desktop_approval,
    verify_desktop_approval_binding, verify_desktop_approval_for_execution,
    verify_desktop_command_receipt, verify_desktop_shell_snapshot,
};
use serde::{Deserialize, Serialize};

use crate::pipeline::{PipelineSnapshotMode, build_pipeline_snapshot};

const LOCAL_ACTOR_ID: &str = "ergaxiom.local.operator";
const APPROVAL_TTL_S: u64 = 900;

#[derive(Debug, Clone, Deserialize)]
pub struct DesktopSnapshotRequest {
    pub expected_snapshot_digest: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DesktopApprovedActionRequest {
    pub expected_snapshot_digest: String,
    pub approval_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DesktopControlResponse {
    pub status: DesktopControlStatus,
    pub approval: Option<DesktopApprovalRecord>,
    pub receipts: Vec<DesktopCommandReceipt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DesktopSnapshotResponse {
    pub verified: bool,
    pub source: &'static str,
    pub snapshot: DesktopShellSnapshot,
    pub control: DesktopControlResponse,
}

struct DesktopControlSession {
    snapshot: DesktopShellSnapshot,
    approval: Option<DesktopApprovalRecord>,
    receipts: Vec<DesktopCommandReceipt>,
}

pub struct DesktopControlState {
    inner: Mutex<DesktopControlSession>,
}

impl DesktopControlState {
    pub fn new() -> Result<Self, String> {
        let snapshot = build_pipeline_snapshot(PipelineSnapshotMode::AwaitingApproval)?;
        Ok(Self {
            inner: Mutex::new(DesktopControlSession {
                snapshot,
                approval: None,
                receipts: Vec::new(),
            }),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, DesktopControlSession>, String> {
        self.inner
            .lock()
            .map_err(|_| "desktop control authority lock is poisoned".to_owned())
    }

    pub fn snapshot(&self) -> Result<DesktopSnapshotResponse, String> {
        let session = self.lock()?;
        response_from_session(&session)
    }

    pub fn approve(
        &self,
        request: DesktopApprovalRequest,
    ) -> Result<DesktopSnapshotResponse, String> {
        let now = current_epoch_s()?;
        let mut session = self.lock()?;
        let pre_snapshot = session.snapshot.clone();
        let approval =
            issue_desktop_approval(&pre_snapshot, &request, LOCAL_ACTOR_ID, now, APPROVAL_TTL_S)
                .map_err(|error| format!("desktop approval rejected: {error}"))?;
        let post_snapshot = build_pipeline_snapshot(PipelineSnapshotMode::Approved(&approval))?;
        let receipt = issue_desktop_command_receipt(
            DesktopCommandAction::Approve,
            LOCAL_ACTOR_ID,
            &pre_snapshot,
            &post_snapshot,
            Some(&approval.approval_digest),
            now,
        )
        .map_err(|error| format!("approval receipt construction failed: {error}"))?;
        session.snapshot = post_snapshot;
        session.approval = Some(approval);
        session.receipts.push(receipt);
        response_from_session(&session)
    }

    pub fn execute(
        &self,
        request: DesktopApprovedActionRequest,
    ) -> Result<DesktopSnapshotResponse, String> {
        let now = current_epoch_s()?;
        let mut session = self.lock()?;
        ensure_expected_snapshot(&session.snapshot, &request.expected_snapshot_digest)?;
        let approval = session
            .approval
            .clone()
            .ok_or_else(|| "desktop execution has no backend approval record".to_owned())?;
        verify_desktop_approval_for_execution(
            &session.snapshot,
            &approval,
            &request.approval_digest,
            now,
        )
        .map_err(|error| format!("desktop execution rejected: {error}"))?;
        let pre_snapshot = session.snapshot.clone();
        let post_snapshot = build_pipeline_snapshot(PipelineSnapshotMode::Executed(&approval))?;
        let receipt = issue_desktop_command_receipt(
            DesktopCommandAction::Execute,
            LOCAL_ACTOR_ID,
            &pre_snapshot,
            &post_snapshot,
            Some(&approval.approval_digest),
            now,
        )
        .map_err(|error| format!("execution receipt construction failed: {error}"))?;
        session.snapshot = post_snapshot;
        session.receipts.push(receipt);
        response_from_session(&session)
    }

    pub fn cancel(
        &self,
        request: DesktopSnapshotRequest,
    ) -> Result<DesktopSnapshotResponse, String> {
        let now = current_epoch_s()?;
        let mut session = self.lock()?;
        ensure_expected_snapshot(&session.snapshot, &request.expected_snapshot_digest)?;
        let status = control_status_from_snapshot(&session.snapshot)
            .map_err(|error| format!("desktop control state invalid: {error}"))?;
        if !matches!(
            status,
            DesktopControlStatus::AwaitingApproval | DesktopControlStatus::Approved
        ) {
            return Err("desktop cancellation is allowed only before execution".to_owned());
        }
        let pre_snapshot = session.snapshot.clone();
        let approval = session.approval.clone();
        let post_snapshot =
            build_pipeline_snapshot(PipelineSnapshotMode::Cancelled(approval.as_ref()))?;
        let receipt = issue_desktop_command_receipt(
            DesktopCommandAction::Cancel,
            LOCAL_ACTOR_ID,
            &pre_snapshot,
            &post_snapshot,
            approval
                .as_ref()
                .map(|record| record.approval_digest.as_str()),
            now,
        )
        .map_err(|error| format!("cancellation receipt construction failed: {error}"))?;
        session.snapshot = post_snapshot;
        session.receipts.push(receipt);
        response_from_session(&session)
    }

    pub fn rollback(
        &self,
        request: DesktopApprovedActionRequest,
    ) -> Result<DesktopSnapshotResponse, String> {
        let now = current_epoch_s()?;
        let mut session = self.lock()?;
        ensure_expected_snapshot(&session.snapshot, &request.expected_snapshot_digest)?;
        if control_status_from_snapshot(&session.snapshot)
            .map_err(|error| format!("desktop control state invalid: {error}"))?
            != DesktopControlStatus::Executed
        {
            return Err("desktop rollback requires one completed execution".to_owned());
        }
        let approval = session
            .approval
            .clone()
            .ok_or_else(|| "desktop rollback has no backend approval record".to_owned())?;
        verify_desktop_approval_binding(&session.snapshot, &approval, &request.approval_digest)
            .map_err(|error| format!("desktop rollback rejected: {error}"))?;
        let pre_snapshot = session.snapshot.clone();
        let post_snapshot = build_pipeline_snapshot(PipelineSnapshotMode::RolledBack(&approval))?;
        let receipt = issue_desktop_command_receipt(
            DesktopCommandAction::Rollback,
            LOCAL_ACTOR_ID,
            &pre_snapshot,
            &post_snapshot,
            Some(&approval.approval_digest),
            now,
        )
        .map_err(|error| format!("rollback receipt construction failed: {error}"))?;
        session.snapshot = post_snapshot;
        session.receipts.push(receipt);
        response_from_session(&session)
    }
}

#[tauri::command]
pub fn get_desktop_shell_snapshot(
    state: tauri::State<'_, DesktopControlState>,
) -> Result<DesktopSnapshotResponse, String> {
    state.snapshot()
}

#[tauri::command]
pub fn approve_desktop_job(
    state: tauri::State<'_, DesktopControlState>,
    request: DesktopApprovalRequest,
) -> Result<DesktopSnapshotResponse, String> {
    state.approve(request)
}

#[tauri::command]
pub fn start_desktop_job_execution(
    state: tauri::State<'_, DesktopControlState>,
    request: DesktopApprovedActionRequest,
) -> Result<DesktopSnapshotResponse, String> {
    state.execute(request)
}

#[tauri::command]
pub fn cancel_desktop_job(
    state: tauri::State<'_, DesktopControlState>,
    request: DesktopSnapshotRequest,
) -> Result<DesktopSnapshotResponse, String> {
    state.cancel(request)
}

#[tauri::command]
pub fn rollback_desktop_job(
    state: tauri::State<'_, DesktopControlState>,
    request: DesktopApprovedActionRequest,
) -> Result<DesktopSnapshotResponse, String> {
    state.rollback(request)
}

fn response_from_session(
    session: &DesktopControlSession,
) -> Result<DesktopSnapshotResponse, String> {
    let verified = verify_desktop_shell_snapshot(&session.snapshot)
        .map_err(|error| format!("desktop snapshot verification failed: {error}"))?;
    if !verified {
        return Err("desktop snapshot digest mismatch".to_owned());
    }
    if let Some(approval) = &session.approval {
        if !verify_desktop_approval(approval)
            .map_err(|error| format!("desktop approval verification failed: {error}"))?
        {
            return Err("desktop approval digest mismatch".to_owned());
        }
    }
    for receipt in &session.receipts {
        if !verify_desktop_command_receipt(receipt)
            .map_err(|error| format!("desktop receipt verification failed: {error}"))?
        {
            return Err("desktop command receipt digest mismatch".to_owned());
        }
    }
    let status = control_status_from_snapshot(&session.snapshot)
        .map_err(|error| format!("desktop control metadata invalid: {error}"))?;
    Ok(DesktopSnapshotResponse {
        verified: true,
        source: "desktop_control_authority",
        snapshot: session.snapshot.clone(),
        control: DesktopControlResponse {
            status,
            approval: session.approval.clone(),
            receipts: session.receipts.clone(),
        },
    })
}

fn ensure_expected_snapshot(
    snapshot: &DesktopShellSnapshot,
    expected_snapshot_digest: &str,
) -> Result<(), String> {
    if snapshot.snapshot_digest == expected_snapshot_digest {
        Ok(())
    } else {
        Err("renderer submitted a stale desktop snapshot digest".to_owned())
    }
}

fn current_epoch_s() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("trusted desktop clock failed: {error}"))
}

#[cfg(test)]
mod tests {
    use ergaxiom_desktop_shell_runtime::{DesktopApprovalRequest, DesktopControlStatus};

    use super::{DesktopApprovedActionRequest, DesktopControlState, DesktopSnapshotRequest};

    #[test]
    fn backend_authority_enforces_approval_execution_and_rollback() {
        let authority = DesktopControlState::new().expect("control authority must initialize");
        let initial = authority.snapshot().expect("initial snapshot must verify");
        assert_eq!(
            initial.control.status,
            DesktopControlStatus::AwaitingApproval
        );
        let pending = initial
            .snapshot
            .approval
            .as_ref()
            .expect("pending approval tuple");
        let approved = authority
            .approve(DesktopApprovalRequest {
                expected_snapshot_digest: initial.snapshot.snapshot_digest.clone(),
                contract_digest: pending.contract_digest.clone(),
                plan_digest: pending.plan_digest.clone(),
                permission_digest: pending.permission_digest.clone(),
            })
            .expect("exact digest tuple must approve");
        assert_eq!(approved.control.status, DesktopControlStatus::Approved);
        let approval_digest = approved
            .control
            .approval
            .as_ref()
            .expect("backend approval record")
            .approval_digest
            .clone();
        let executed = authority
            .execute(DesktopApprovedActionRequest {
                expected_snapshot_digest: approved.snapshot.snapshot_digest.clone(),
                approval_digest: approval_digest.clone(),
            })
            .expect("approved execution must succeed");
        assert_eq!(executed.control.status, DesktopControlStatus::Executed);
        assert!(executed.snapshot.replay_manifest.is_some());
        assert!(executed.snapshot.certificate.is_none());
        let rolled_back = authority
            .rollback(DesktopApprovedActionRequest {
                expected_snapshot_digest: executed.snapshot.snapshot_digest.clone(),
                approval_digest,
            })
            .expect("executed job must roll back");
        assert_eq!(rolled_back.control.status, DesktopControlStatus::RolledBack);
        assert!(rolled_back.snapshot.replay_manifest.is_none());
        assert_eq!(rolled_back.control.receipts.len(), 3);
    }

    #[test]
    fn stale_renderer_state_and_post_execution_cancel_fail_closed() {
        let authority = DesktopControlState::new().expect("control authority must initialize");
        assert!(
            authority
                .cancel(DesktopSnapshotRequest {
                    expected_snapshot_digest: "0".repeat(64),
                })
                .is_err()
        );
        let initial = authority.snapshot().expect("initial snapshot must verify");
        let pending = initial
            .snapshot
            .approval
            .as_ref()
            .expect("pending approval tuple");
        let approved = authority
            .approve(DesktopApprovalRequest {
                expected_snapshot_digest: initial.snapshot.snapshot_digest.clone(),
                contract_digest: pending.contract_digest.clone(),
                plan_digest: pending.plan_digest.clone(),
                permission_digest: pending.permission_digest.clone(),
            })
            .expect("approval must succeed");
        let approval_digest = approved
            .control
            .approval
            .as_ref()
            .expect("approval")
            .approval_digest
            .clone();
        let executed = authority
            .execute(DesktopApprovedActionRequest {
                expected_snapshot_digest: approved.snapshot.snapshot_digest,
                approval_digest,
            })
            .expect("execution must succeed");
        assert!(
            authority
                .cancel(DesktopSnapshotRequest {
                    expected_snapshot_digest: executed.snapshot.snapshot_digest,
                })
                .is_err()
        );
    }
}
