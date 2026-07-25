use std::error::Error;

use ergaxiom_desktop_shell_runtime::{
    ApprovalSummary, DesktopApprovalRequest, DesktopCommandAction, DesktopControlStatus,
    DesktopShellMaterial, DigestItem, StageStatus, build_desktop_shell_snapshot,
    control_status_from_snapshot, issue_desktop_approval, issue_desktop_command_receipt,
    verify_desktop_approval, verify_desktop_approval_for_execution, verify_desktop_command_receipt,
};
use serde_json::json;

#[test]
fn exact_digest_tuple_issues_a_verifiable_approval() -> Result<(), Box<dyn Error>> {
    let awaiting = snapshot(
        DesktopControlStatus::AwaitingApproval,
        StageStatus::Pending,
        None,
    )?;
    let request = request(&awaiting)?;
    let approval =
        issue_desktop_approval(&awaiting, &request, "ergaxiom.local.operator", 1_000, 900)?;
    assert!(verify_desktop_approval(&approval)?);
    assert_eq!(approval.pre_snapshot_digest, awaiting.snapshot_digest);

    let approved = snapshot(
        DesktopControlStatus::Approved,
        StageStatus::Passed,
        Some(&approval.approval_digest),
    )?;
    verify_desktop_approval_for_execution(&approved, &approval, &approval.approval_digest, 1_500)?;
    Ok(())
}

#[test]
fn stale_or_altered_renderer_material_fails_closed() -> Result<(), Box<dyn Error>> {
    let awaiting = snapshot(
        DesktopControlStatus::AwaitingApproval,
        StageStatus::Pending,
        None,
    )?;
    let mut stale = request(&awaiting)?;
    stale.expected_snapshot_digest = "9".repeat(64);
    assert!(
        issue_desktop_approval(&awaiting, &stale, "ergaxiom.local.operator", 1_000, 900).is_err()
    );

    let mut altered = request(&awaiting)?;
    altered.permission_digest = "8".repeat(64);
    assert!(
        issue_desktop_approval(&awaiting, &altered, "ergaxiom.local.operator", 1_000, 900).is_err()
    );
    Ok(())
}

#[test]
fn expired_approval_and_receipt_tampering_fail_closed() -> Result<(), Box<dyn Error>> {
    let awaiting = snapshot(
        DesktopControlStatus::AwaitingApproval,
        StageStatus::Pending,
        None,
    )?;
    let approval = issue_desktop_approval(
        &awaiting,
        &request(&awaiting)?,
        "ergaxiom.local.operator",
        1_000,
        30,
    )?;
    let approved = snapshot(
        DesktopControlStatus::Approved,
        StageStatus::Passed,
        Some(&approval.approval_digest),
    )?;
    assert!(
        verify_desktop_approval_for_execution(
            &approved,
            &approval,
            &approval.approval_digest,
            1_031,
        )
        .is_err()
    );

    let executed = snapshot(
        DesktopControlStatus::Executed,
        StageStatus::Passed,
        Some(&approval.approval_digest),
    )?;
    let receipt = issue_desktop_command_receipt(
        DesktopCommandAction::Execute,
        "ergaxiom.local.operator",
        &approved,
        &executed,
        Some(&approval.approval_digest),
        1_020,
    )?;
    assert!(verify_desktop_command_receipt(&receipt)?);
    let mut tampered = receipt;
    tampered.post_snapshot_digest = "7".repeat(64);
    assert!(!verify_desktop_command_receipt(&tampered)?);
    Ok(())
}

fn request(
    snapshot: &ergaxiom_desktop_shell_runtime::DesktopShellSnapshot,
) -> Result<DesktopApprovalRequest, Box<dyn Error>> {
    let approval = snapshot
        .approval
        .as_ref()
        .ok_or("fixture approval is missing")?;
    Ok(DesktopApprovalRequest {
        expected_snapshot_digest: snapshot.snapshot_digest.clone(),
        contract_digest: approval.contract_digest.clone(),
        plan_digest: approval.plan_digest.clone(),
        permission_digest: approval.permission_digest.clone(),
    })
}

fn snapshot(
    control_status: DesktopControlStatus,
    approval_status: StageStatus,
    approval_digest: Option<&str>,
) -> Result<ergaxiom_desktop_shell_runtime::DesktopShellSnapshot, Box<dyn Error>> {
    let status = match control_status {
        DesktopControlStatus::AwaitingApproval => "awaiting_approval",
        DesktopControlStatus::Approved => "approved",
        DesktopControlStatus::Executed => "executed",
        DesktopControlStatus::Cancelled => "cancelled",
        DesktopControlStatus::RolledBack => "rolled_back",
    };
    let snapshot = build_desktop_shell_snapshot(DesktopShellMaterial {
        generated_at: "2026-07-25T00:00:00Z".to_owned(),
        job_id: Some("job.desktop.control.0001".to_owned()),
        unresolved: Vec::new(),
        staged_inputs: Vec::new(),
        contract: Some(DigestItem {
            id: "contract.desktop.control.0001".to_owned(),
            media_type: Some("application/json".to_owned()),
            digest: "a".repeat(64),
            status: StageStatus::Passed,
        }),
        approval: Some(ApprovalSummary {
            approval_id: "approval.desktop.pending".to_owned(),
            contract_digest: "a".repeat(64),
            plan_digest: "b".repeat(64),
            permission_digest: "c".repeat(64),
            expires_at_epoch_s: 0,
            status: approval_status,
        }),
        plan: Some(DigestItem {
            id: "plan.desktop.control.0001".to_owned(),
            media_type: Some("application/json".to_owned()),
            digest: "b".repeat(64),
            status: StageStatus::Passed,
        }),
        steps: Vec::new(),
        validators: Vec::new(),
        evidence_bundle: None,
        replay_manifest: None,
        certificate: None,
        profession_capsules: Vec::new(),
        adapters: Vec::new(),
        trusted_keys: Vec::new(),
        metadata: json!({
            "approval_digest": approval_digest,
            "control_status": status,
        }),
    })?;
    assert_eq!(control_status_from_snapshot(&snapshot)?, control_status);
    Ok(snapshot)
}
