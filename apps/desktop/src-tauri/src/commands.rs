use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_desktop_shell_runtime::{
    DesktopApprovalRecord, DesktopApprovalRequest, DesktopCommandAction, DesktopCommandReceipt,
    DesktopControlStatus, DesktopShellMaterial, DesktopShellSnapshot, StageStatus,
    build_desktop_shell_snapshot, control_status_from_snapshot, issue_desktop_approval,
    issue_desktop_command_receipt, verify_desktop_approval, verify_desktop_approval_binding,
    verify_desktop_approval_for_execution, verify_desktop_command_receipt,
    verify_desktop_shell_snapshot,
};
use ergaxiom_production_execution_runtime::{
    ProductionExecutionChainState, ProductionExecutionStage, verify_recovered_certified_chain,
};
use ergaxiom_proof_kernel::AssuranceLevel;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::pipeline::{PipelineSnapshotMode, build_pipeline_snapshot, prepare_desktop_job};
use crate::production_execution::{ProductionExecutionBoundaryError, ProductionExecutionState};
use crate::production_pipeline::execute_approved_job;

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

    pub fn recover_or_new(production: &ProductionExecutionState) -> Result<Self, String> {
        let prepared = prepare_desktop_job()?;
        let recovered = production.with_fresh_lease(|authority, lease, deployment, _client, now| {
            let state = authority.chain_state().clone();
            if matches!(
                state.stage,
                ProductionExecutionStage::Certified | ProductionExecutionStage::RolledBack
            ) {
                let bundle = state
                    .evidence_bundle
                    .as_ref()
                    .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
                let executed_snapshot = state
                    .executed_snapshot
                    .as_ref()
                    .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
                authority
                    .verify_execution_evidence_binding(bundle, executed_snapshot)
                    .map_err(ProductionExecutionBoundaryError::from)?;
                verify_recovered_certified_chain(
                    &state,
                    lease,
                    &deployment.signer.accepted,
                    &deployment.signer.deployment_policy,
                    now,
                    prepared.compiled_contract.clone(),
                    &prepared.compiled_plan,
                    AssuranceLevel::E3,
                    authority.executor_id(),
                    authority.device_id(),
                )
                .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
            }
            Ok(state)
        });
        match recovered {
            Ok(state) => Self::from_chain_state(state),
            Err(_error)
                if matches!(
                    production.startup_code(),
                    "production_execution_configuration_missing"
                        | "production_execution_unsupported_platform"
                ) =>
            {
                Self::new()
            }
            Err(error) => Err(format!(
                "production restart recovery rejected [{}]: {error}",
                error.public_code()
            )),
        }
    }

    fn from_chain_state(state: ProductionExecutionChainState) -> Result<Self, String> {
        match state.stage {
            ProductionExecutionStage::Initial => Self::new(),
            ProductionExecutionStage::Approved
            | ProductionExecutionStage::CapabilitiesIssued
            | ProductionExecutionStage::CapabilitiesConsumed => {
                let snapshot = state
                    .approved_snapshot
                    .ok_or_else(|| "recovered chain is missing approved snapshot".to_owned())?;
                let approval = state
                    .approval
                    .ok_or_else(|| "recovered chain is missing approval record".to_owned())?;
                let receipt = state
                    .approve_receipt
                    .ok_or_else(|| "recovered chain is missing approval receipt".to_owned())?;
                Self::from_recovered(snapshot, Some(approval), vec![receipt])
            }
            ProductionExecutionStage::Executed => {
                let snapshot = state
                    .executed_snapshot
                    .ok_or_else(|| "recovered chain is missing executed snapshot".to_owned())?;
                let approval = state
                    .approval
                    .ok_or_else(|| "recovered chain is missing approval record".to_owned())?;
                let approve = state
                    .approve_receipt
                    .ok_or_else(|| "recovered chain is missing approval receipt".to_owned())?;
                let execute = state
                    .execute_receipt
                    .ok_or_else(|| "recovered chain is missing execute receipt".to_owned())?;
                Self::from_recovered(snapshot, Some(approval), vec![approve, execute])
            }
            ProductionExecutionStage::Certified => {
                let snapshot = state
                    .final_snapshot
                    .ok_or_else(|| "recovered chain is missing certified snapshot".to_owned())?;
                let approval = state
                    .approval
                    .ok_or_else(|| "recovered chain is missing approval record".to_owned())?;
                let approve = state
                    .approve_receipt
                    .ok_or_else(|| "recovered chain is missing approval receipt".to_owned())?;
                let execute = state
                    .execute_receipt
                    .ok_or_else(|| "recovered chain is missing execute receipt".to_owned())?;
                Self::from_recovered(snapshot, Some(approval), vec![approve, execute])
            }
            ProductionExecutionStage::Cancelled => {
                let approval = state.approval;
                let snapshot =
                    build_pipeline_snapshot(PipelineSnapshotMode::Cancelled(approval.as_ref()))?;
                let cancel = state
                    .cancel_receipt
                    .ok_or_else(|| "recovered chain is missing cancellation receipt".to_owned())?;
                if cancel.post_snapshot_digest != snapshot.snapshot_digest {
                    return Err("recovered cancellation snapshot digest mismatch".to_owned());
                }
                let mut receipts = Vec::new();
                if let Some(approve) = state.approve_receipt {
                    receipts.push(approve);
                }
                receipts.push(cancel);
                Self::from_recovered(snapshot, approval, receipts)
            }
            ProductionExecutionStage::RolledBack => {
                let certified = state
                    .final_snapshot
                    .ok_or_else(|| "recovered chain is missing certified snapshot".to_owned())?;
                let approval = state
                    .approval
                    .ok_or_else(|| "recovered chain is missing approval record".to_owned())?;
                let approve = state
                    .approve_receipt
                    .ok_or_else(|| "recovered chain is missing approval receipt".to_owned())?;
                let execute = state
                    .execute_receipt
                    .ok_or_else(|| "recovered chain is missing execute receipt".to_owned())?;
                let rollback = state
                    .rollback_receipt
                    .ok_or_else(|| "recovered chain is missing rollback receipt".to_owned())?;
                let snapshot = terminal_snapshot(&certified, DesktopControlStatus::RolledBack)?;
                if rollback.post_snapshot_digest != snapshot.snapshot_digest {
                    return Err("recovered rollback snapshot digest mismatch".to_owned());
                }
                Self::from_recovered(snapshot, Some(approval), vec![approve, execute, rollback])
            }
        }
    }

    fn from_recovered(
        snapshot: DesktopShellSnapshot,
        approval: Option<DesktopApprovalRecord>,
        receipts: Vec<DesktopCommandReceipt>,
    ) -> Result<Self, String> {
        if !verify_desktop_shell_snapshot(&snapshot)
            .map_err(|error| format!("recovered snapshot verification failed: {error}"))?
        {
            return Err("recovered desktop snapshot digest mismatch".to_owned());
        }
        for receipt in &receipts {
            if !verify_desktop_command_receipt(receipt)
                .map_err(|error| format!("recovered receipt verification failed: {error}"))?
            {
                return Err("recovered desktop receipt digest mismatch".to_owned());
            }
        }
        Ok(Self {
            inner: Mutex::new(DesktopControlSession {
                snapshot,
                approval,
                receipts,
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

    pub fn approve(&self, request: DesktopApprovalRequest) -> Result<DesktopSnapshotResponse, String> {
        self.approve_transaction(request, |_, _, _| Ok(()))
    }

    pub fn approve_persisted(
        &self,
        production: &ProductionExecutionState,
        request: DesktopApprovalRequest,
    ) -> Result<DesktopSnapshotResponse, String> {
        self.approve_transaction(request, |post_snapshot, approval, receipt| {
            production
                .with_fresh_lease(|authority, _lease, _deployment, _client, _now| {
                    authority.record_approval(
                        post_snapshot.clone(),
                        approval.clone(),
                        receipt.clone(),
                    )?;
                    Ok(())
                })
                .map_err(|error| {
                    format!(
                        "production approval persistence rejected [{}]: {error}",
                        error.public_code()
                    )
                })
        })
    }

    fn approve_transaction(
        &self,
        request: DesktopApprovalRequest,
        persist: impl FnOnce(
            &DesktopShellSnapshot,
            &DesktopApprovalRecord,
            &DesktopCommandReceipt,
        ) -> Result<(), String>,
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
        persist(&post_snapshot, &approval, &receipt)?;
        session.snapshot = post_snapshot;
        session.approval = Some(approval);
        session.receipts.push(receipt);
        response_from_session(&session)
    }

    pub fn execute(
        &self,
        production: &ProductionExecutionState,
        request: DesktopApprovedActionRequest,
    ) -> Result<DesktopSnapshotResponse, String> {
        let now = current_epoch_s()?;
        let mut session = self.lock()?;
        ensure_expected_snapshot(&session.snapshot, &request.expected_snapshot_digest)?;
        let approval = session
            .approval
            .clone()
            .ok_or_else(|| "desktop execution has no backend approval record".to_owned())?;
        let status = control_status_from_snapshot(&session.snapshot)
            .map_err(|error| format!("desktop control state invalid: {error}"))?;
        match status {
            DesktopControlStatus::Approved => {
                verify_desktop_approval_for_execution(
                    &session.snapshot,
                    &approval,
                    &request.approval_digest,
                    now,
                )
                .map_err(|error| format!("desktop execution rejected: {error}"))?;
            }
            DesktopControlStatus::Executed if session.snapshot.certificate.is_none() => {
                verify_desktop_approval_binding(
                    &session.snapshot,
                    &approval,
                    &request.approval_digest,
                )
                .map_err(|error| format!("desktop execution resume rejected: {error}"))?;
                let execute_receipt = session
                    .receipts
                    .iter()
                    .rev()
                    .find(|receipt| receipt.action == DesktopCommandAction::Execute)
                    .ok_or_else(|| {
                        "desktop execution resume has no persisted Execute receipt".to_owned()
                    })?;
                if execute_receipt.post_snapshot_digest != session.snapshot.snapshot_digest
                    || execute_receipt.approval_digest.as_deref()
                        != Some(approval.approval_digest.as_str())
                    || execute_receipt.issued_at_epoch_s > approval.expires_at_epoch_s
                {
                    return Err("desktop execution resume receipt binding mismatch".to_owned());
                }
            }
            _ => {
                return Err(
                    "desktop execution requires Approved state or an uncertified persisted execution"
                        .to_owned(),
                );
            }
        }
        let approve_receipt = session
            .receipts
            .iter()
            .rev()
            .find(|receipt| receipt.action == DesktopCommandAction::Approve)
            .cloned()
            .ok_or_else(|| "desktop execution has no durable approval command receipt".to_owned())?;
        let result = execute_approved_job(
            production,
            &session.snapshot,
            &approval,
            &approve_receipt,
        )?;
        session.snapshot = result.final_snapshot;
        if !session
            .receipts
            .iter()
            .any(|receipt| receipt.receipt_digest == result.execute_receipt.receipt_digest)
        {
            session.receipts.push(result.execute_receipt);
        }
        response_from_session(&session)
    }

    pub fn cancel(
        &self,
        production: Option<&ProductionExecutionState>,
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
        if status == DesktopControlStatus::Approved {
            let production = production.ok_or_else(|| {
                "approved production cancellation requires persistent authority".to_owned()
            })?;
            production
                .with_fresh_lease(|authority, _lease, _deployment, _client, _now| {
                    authority.record_cancellation(receipt.clone())?;
                    Ok(())
                })
                .map_err(|error| {
                    format!(
                        "production cancellation persistence rejected [{}]: {error}",
                        error.public_code()
                    )
                })?;
        }
        session.snapshot = post_snapshot;
        session.receipts.push(receipt);
        response_from_session(&session)
    }

    pub fn rollback(
        &self,
        production: &ProductionExecutionState,
        request: DesktopApprovedActionRequest,
    ) -> Result<DesktopSnapshotResponse, String> {
        let now = current_epoch_s()?;
        let mut session = self.lock()?;
        ensure_expected_snapshot(&session.snapshot, &request.expected_snapshot_digest)?;
        if control_status_from_snapshot(&session.snapshot)
            .map_err(|error| format!("desktop control state invalid: {error}"))?
            != DesktopControlStatus::Executed
            || session.snapshot.certificate.is_none()
        {
            return Err("desktop rollback requires one production-certified execution".to_owned());
        }
        let approval = session
            .approval
            .clone()
            .ok_or_else(|| "desktop rollback has no backend approval record".to_owned())?;
        verify_desktop_approval_binding(&session.snapshot, &approval, &request.approval_digest)
            .map_err(|error| format!("desktop rollback rejected: {error}"))?;
        let pre_snapshot = session.snapshot.clone();
        let post_snapshot = terminal_snapshot(&pre_snapshot, DesktopControlStatus::RolledBack)?;
        let receipt = issue_desktop_command_receipt(
            DesktopCommandAction::Rollback,
            LOCAL_ACTOR_ID,
            &pre_snapshot,
            &post_snapshot,
            Some(&approval.approval_digest),
            now,
        )
        .map_err(|error| format!("rollback receipt construction failed: {error}"))?;
        production
            .with_fresh_lease(|authority, _lease, _deployment, _client, _now| {
                authority.record_rollback(receipt.clone())?;
                Ok(())
            })
            .map_err(|error| {
                format!(
                    "production rollback persistence rejected [{}]: {error}",
                    error.public_code()
                )
            })?;
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
    production: tauri::State<'_, ProductionExecutionState>,
    request: DesktopApprovalRequest,
) -> Result<DesktopSnapshotResponse, String> {
    state.approve_persisted(&production, request)
}

#[tauri::command]
pub fn start_desktop_job_execution(
    state: tauri::State<'_, DesktopControlState>,
    production: tauri::State<'_, ProductionExecutionState>,
    request: DesktopApprovedActionRequest,
) -> Result<DesktopSnapshotResponse, String> {
    state.execute(&production, request)
}

#[tauri::command]
pub fn cancel_desktop_job(
    state: tauri::State<'_, DesktopControlState>,
    production: tauri::State<'_, ProductionExecutionState>,
    request: DesktopSnapshotRequest,
) -> Result<DesktopSnapshotResponse, String> {
    state.cancel(Some(&production), request)
}

#[tauri::command]
pub fn rollback_desktop_job(
    state: tauri::State<'_, DesktopControlState>,
    production: tauri::State<'_, ProductionExecutionState>,
    request: DesktopApprovedActionRequest,
) -> Result<DesktopSnapshotResponse, String> {
    state.rollback(&production, request)
}

fn terminal_snapshot(
    snapshot: &DesktopShellSnapshot,
    status: DesktopControlStatus,
) -> Result<DesktopShellSnapshot, String> {
    let mut steps = snapshot.steps.clone();
    for step in &mut steps {
        step.status = StageStatus::Blocked;
    }
    let material = DesktopShellMaterial {
        generated_at: snapshot.generated_at.clone(),
        job_id: snapshot.job_id.clone(),
        unresolved: snapshot.unresolved.clone(),
        staged_inputs: snapshot.staged_inputs.clone(),
        contract: snapshot.contract.clone(),
        approval: snapshot.approval.clone(),
        plan: snapshot.plan.clone(),
        steps,
        validators: snapshot.validators.clone(),
        evidence_bundle: snapshot.evidence_bundle.clone(),
        replay_manifest: snapshot.replay_manifest.clone(),
        certificate: snapshot.certificate.clone(),
        profession_capsules: snapshot.profession_capsules.clone(),
        adapters: snapshot.adapters.clone(),
        trusted_keys: snapshot.trusted_keys.clone(),
        metadata: json!({
            "control_status": status,
            "approval_digest": snapshot.metadata.get("approval_digest").cloned(),
            "terminal_transition": true,
            "certified_evidence_preserved": snapshot.certificate.is_some(),
        }),
    };
    build_desktop_shell_snapshot(material)
        .map_err(|error| format!("terminal snapshot construction failed: {error}"))
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

    use super::{DesktopControlState, DesktopSnapshotRequest};

    #[test]
    fn local_control_can_prepare_approval_without_synthesizing_execution() {
        let authority = DesktopControlState::new().expect("control authority must initialize");
        let initial = authority.snapshot().expect("initial snapshot must verify");
        let pending = initial.snapshot.approval.as_ref().expect("pending approval");
        let approved = authority
            .approve(DesktopApprovalRequest {
                expected_snapshot_digest: initial.snapshot.snapshot_digest.clone(),
                contract_digest: pending.contract_digest.clone(),
                plan_digest: pending.plan_digest.clone(),
                permission_digest: pending.permission_digest.clone(),
            })
            .expect("local approval fixture must succeed");
        assert_eq!(approved.control.status, DesktopControlStatus::Approved);
        assert!(approved.snapshot.evidence_bundle.is_none());
        assert!(approved.snapshot.replay_manifest.is_none());
        assert!(approved.snapshot.certificate.is_none());
        assert_eq!(
            approved
                .snapshot
                .metadata
                .get("twin_executed")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn stale_renderer_state_fails_closed() {
        let authority = DesktopControlState::new().expect("control authority must initialize");
        assert!(
            authority
                .cancel(
                    None,
                    DesktopSnapshotRequest {
                        expected_snapshot_digest: "0".repeat(64),
                    },
                )
                .is_err()
        );
    }
}
