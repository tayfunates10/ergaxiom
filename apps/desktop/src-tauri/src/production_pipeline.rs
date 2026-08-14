use ergaxiom_attestation_issuance_runtime::AttestationCertificateDraft;
use ergaxiom_attestation_runtime::{ReplayManifest, VerifiedAttestation, build_replay_manifest};
use ergaxiom_capability_issuance_runtime::CapabilityTokenDraft;
use ergaxiom_capability_runtime::{
    AuthorizationReceipt, CapabilityBindings, CapabilityGrant, CapabilitySubject,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess};
use ergaxiom_desktop_shell_runtime::{
    ApprovalSummary, CertificateVerification, DesktopApprovalRecord, DesktopCommandAction,
    DesktopCommandReceipt, DesktopControlStatus, DesktopShellMaterial, DesktopShellSnapshot,
    DigestItem, PlanStepSummary, StageStatus, TrustComponentStatus, ValidatorSummary,
    build_desktop_shell_snapshot, issue_desktop_command_receipt,
};
use ergaxiom_evidence_runtime::{EvidenceBundle, assess_bundle};
use ergaxiom_graphic_production_evidence_runtime::{
    ProductionGraphicEvidence, ProductionGraphicEvidenceRequest, build_production_graphic_evidence,
};
use ergaxiom_operator_plan_runtime::{CompiledPlan, PlanStep};
use ergaxiom_production_execution_runtime::{
    PersistedProductionCapability, ProductionExecutionStage,
};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, canonical_json_sha256};
use ergaxiom_windows_production_governed_issuance_runtime::{
    GovernedCapabilityAuthorizer, verify_governed_production_attestation_against_bundle,
};
use serde_json::{Value, json};

use crate::pipeline::{
    GENERATED_AT, PreparedDesktopJob, prepare_desktop_job, sha256_hex, twin_workspace,
};
use crate::production_execution::{ProductionExecutionBoundaryError, ProductionExecutionState};

const LOCAL_ACTOR_ID: &str = "ergaxiom.local.operator";
const AUTHORIZATION_TTL_S: u64 = 60;
const BUNDLE_ID: &str = "bundle.desktop-shell.production.0001";
const RUN_ID: &str = "run.desktop-shell.production.0001";
const TRACE_ID: &str = "trace.desktop-shell.production.0001";
const MANIFEST_ID: &str = "manifest.desktop-shell.production.0001";
const CERTIFICATE_ID: &str = "certificate.desktop-shell.production.0001";

pub(crate) struct ProductionExecutionResult {
    pub final_snapshot: DesktopShellSnapshot,
    pub execute_receipt: DesktopCommandReceipt,
}

pub(crate) fn execute_approved_job(
    production: &ProductionExecutionState,
    approved_snapshot: &DesktopShellSnapshot,
    approval: &DesktopApprovalRecord,
    approve_receipt: &DesktopCommandReceipt,
) -> Result<ProductionExecutionResult, String> {
    let prepared = prepare_desktop_job()?;
    let stage = production
        .with_fresh_lease(|authority, _lease, _deployment, _client, _now| {
            Ok(authority.chain_state().stage)
        })
        .map_err(boundary_error)?;
    if stage == ProductionExecutionStage::Executed {
        return resume_attestation(production, &prepared, approval);
    }
    validate_approved_bindings(&prepared, approved_snapshot, approval, approve_receipt)?;
    if !matches!(
        stage,
        ProductionExecutionStage::Approved
            | ProductionExecutionStage::CapabilitiesIssued
            | ProductionExecutionStage::CapabilitiesConsumed
    ) {
        return Err(format!(
            "production execution cannot start or resume from persisted stage {stage:?}"
        ));
    }

    ensure_capabilities(
        production,
        &prepared,
        approved_snapshot,
        approval,
        approve_receipt,
    )?;
    let authorization_receipts = collect_authorization_receipts(production, &prepared, approval)?;

    // The Occupational Twin is invoked only after every max_uses=1 production Capability has a
    // durable AuthorizationReceipt. A restart from CapabilitiesConsumed re-verifies and reuses the
    // receipts rather than consuming the tokens again.
    let mut workspace = twin_workspace()?;
    let production_evidence = build_production_graphic_evidence(ProductionGraphicEvidenceRequest {
        workspace: &mut workspace,
        compiled_contract: &prepared.compiled_contract,
        contract_value: &prepared.contract,
        compiled_plan: &prepared.compiled_plan,
        job: &prepared.job,
        authorization_receipts: &authorization_receipts,
        assurance_level: AssuranceLevel::E3,
        bundle_id: BUNDLE_ID,
        run_id: RUN_ID,
        trace_id: TRACE_ID,
    })
    .map_err(|error| format!("production Twin/evidence rejected: {error}"))?;

    let (bundle, bundle_value) = bundle_with_operation_receipts(&production_evidence)?;
    let assessment = assess_bundle(
        prepared.compiled_contract.clone(),
        &prepared.compiled_plan,
        &bundle_value,
        AssuranceLevel::E3,
    )
    .map_err(|error| format!("production Evidence Bundle reassessment failed: {error}"))?;
    if assessment.decision.status != DecisionStatus::Accepted
        || assessment.mandatory_failed != 0
        || assessment.mandatory_unknown != 0
    {
        return Err(
            "production Evidence Bundle is not ACCEPTED with zero failed/unknown mandatory obligations"
                .to_owned(),
        );
    }
    let replay_manifest = build_replay_manifest(
        MANIFEST_ID,
        &prepared.compiled_plan,
        &bundle,
        &assessment.bundle_digest,
        assessment.decision.status,
        AssuranceLevel::E3,
        assessment.mandatory_passed,
        assessment.mandatory_failed,
        assessment.mandatory_unknown,
    )
    .map_err(|error| format!("Replay Manifest construction failed: {error}"))?;

    let executed_snapshot = build_executed_snapshot(
        &prepared,
        approval,
        &production_evidence,
        &assessment.bundle_digest,
        &replay_manifest,
    )?;
    let execute_at = trusted_epoch_s()?;
    let execute_receipt = issue_desktop_command_receipt(
        DesktopCommandAction::Execute,
        LOCAL_ACTOR_ID,
        approved_snapshot,
        &executed_snapshot,
        Some(&approval.approval_digest),
        execute_at,
    )
    .map_err(|error| format!("production Execute receipt construction failed: {error}"))?;

    production
        .with_fresh_lease(|authority, _lease, _deployment, _client, _now| {
            authority.record_execution(
                executed_snapshot.clone(),
                execute_receipt.clone(),
                bundle_value.clone(),
                replay_manifest.clone(),
            )?;
            Ok(())
        })
        .map_err(boundary_error)?;

    let final_snapshot = issue_and_record_certificate(
        production,
        &prepared,
        approval,
        &executed_snapshot,
        &execute_receipt,
        &bundle_value,
        &assessment.bundle_digest,
    )?;

    Ok(ProductionExecutionResult {
        final_snapshot,
        execute_receipt,
    })
}

fn ensure_capabilities(
    production: &ProductionExecutionState,
    prepared: &PreparedDesktopJob,
    approved_snapshot: &DesktopShellSnapshot,
    approval: &DesktopApprovalRecord,
    approve_receipt: &DesktopCommandReceipt,
) -> Result<(), String> {
    for step in &prepared.compiled_plan.steps {
        production
            .with_fresh_lease(|authority, lease, deployment, client, now| {
                let existing = authority
                    .chain_state()
                    .capabilities
                    .iter()
                    .find(|capability| {
                        capability.token.payload.bindings.step_id == step.step_id
                    })
                    .cloned();
                if let Some(existing) = existing {
                    verify_persisted_token(
                        &existing,
                        lease,
                        authority.executor_id(),
                        authority.device_id(),
                        approval,
                        &prepared.compiled_contract,
                        &prepared.compiled_plan,
                        step,
                        now,
                    )?;
                    return Ok(());
                }
                let draft = capability_draft(
                    authority.executor_id(),
                    authority.device_id(),
                    approval,
                    &prepared.compiled_contract,
                    &prepared.compiled_plan,
                    step,
                    now,
                )?;
                authority.issue_capability(
                    client,
                    lease,
                    &deployment.signer.accepted,
                    &deployment.signer.deployment_policy,
                    approved_snapshot,
                    approval,
                    approve_receipt,
                    &prepared.compiled_contract,
                    &prepared.compiled_plan,
                    draft,
                    now,
                    AUTHORIZATION_TTL_S,
                )?;
                Ok(())
            })
            .map_err(boundary_error)?;
    }
    Ok(())
}

fn collect_authorization_receipts(
    production: &ProductionExecutionState,
    prepared: &PreparedDesktopJob,
    approval: &DesktopApprovalRecord,
) -> Result<Vec<AuthorizationReceipt>, String> {
    let mut receipts = Vec::with_capacity(prepared.compiled_plan.steps.len());
    for step in &prepared.compiled_plan.steps {
        let receipt = production
            .with_fresh_lease(|authority, lease, deployment, _client, now| {
                let persisted = authority
                    .chain_state()
                    .capabilities
                    .iter()
                    .find(|capability| {
                        capability.token.payload.bindings.step_id == step.step_id
                    })
                    .cloned()
                    .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
                if let Some(receipt) = persisted.consumption_receipt.clone() {
                    let token_value = serde_json::to_value(&persisted.token)
                        .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
                    persisted
                        .token
                        .signer_package
                        .verify_governed(
                            lease.capability_trust(),
                            lease.registry(),
                            persisted.token.payload.issued_at_epoch_s,
                        )
                        .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
                    let mut authorizer = GovernedCapabilityAuthorizer::new(
                        lease.capability_trust().clone(),
                        lease.registry().clone(),
                    )
                    .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
                    let verified = authorizer
                        .authorize(
                            &token_value,
                            &prepared.compiled_contract,
                            &prepared.compiled_plan,
                            receipt.authorized_at_epoch_s,
                            authority.executor_id(),
                            authority.device_id(),
                        )
                        .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
                    if verified != receipt {
                        return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
                    }
                    verify_persisted_token(
                        &persisted,
                        lease,
                        authority.executor_id(),
                        authority.device_id(),
                        approval,
                        &prepared.compiled_contract,
                        &prepared.compiled_plan,
                        step,
                        now,
                    )?;
                    return Ok(receipt);
                }
                let token_id = step
                    .capability_token_ids
                    .first()
                    .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
                authority
                    .consume_capability(
                        token_id,
                        lease,
                        &deployment.signer.accepted,
                        &deployment.signer.deployment_policy,
                        &prepared.compiled_contract,
                        &prepared.compiled_plan,
                        now,
                    )
                    .map_err(ProductionExecutionBoundaryError::from)
            })
            .map_err(boundary_error)?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

fn resume_attestation(
    production: &ProductionExecutionState,
    prepared: &PreparedDesktopJob,
    approval: &DesktopApprovalRecord,
) -> Result<ProductionExecutionResult, String> {
    let (executed_snapshot, execute_receipt, bundle_value, expected_bundle_digest) = production
        .with_fresh_lease(|authority, _lease, _deployment, _client, _now| {
            let state = authority.chain_state();
            let executed_snapshot = state
                .executed_snapshot
                .clone()
                .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
            let execute_receipt = state
                .execute_receipt
                .clone()
                .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
            let bundle_value = state
                .evidence_bundle
                .clone()
                .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
            let expected_bundle_digest = state
                .evidence_bundle_digest
                .clone()
                .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
            Ok((
                executed_snapshot,
                execute_receipt,
                bundle_value,
                expected_bundle_digest,
            ))
        })
        .map_err(boundary_error)?;
    let assessment = assess_bundle(
        prepared.compiled_contract.clone(),
        &prepared.compiled_plan,
        &bundle_value,
        AssuranceLevel::E3,
    )
    .map_err(|error| format!("recovered production Evidence Bundle rejected: {error}"))?;
    if assessment.bundle_digest != expected_bundle_digest
        || assessment.decision.status != DecisionStatus::Accepted
        || assessment.mandatory_failed != 0
        || assessment.mandatory_unknown != 0
    {
        return Err("recovered production execution material failed reassessment".to_owned());
    }
    let final_snapshot = issue_and_record_certificate(
        production,
        prepared,
        approval,
        &executed_snapshot,
        &execute_receipt,
        &bundle_value,
        &assessment.bundle_digest,
    )?;
    Ok(ProductionExecutionResult {
        final_snapshot,
        execute_receipt,
    })
}

fn issue_and_record_certificate(
    production: &ProductionExecutionState,
    prepared: &PreparedDesktopJob,
    approval: &DesktopApprovalRecord,
    executed_snapshot: &DesktopShellSnapshot,
    execute_receipt: &DesktopCommandReceipt,
    bundle_value: &Value,
    expected_bundle_digest: &str,
) -> Result<DesktopShellSnapshot, String> {
    production
        .with_fresh_lease(|authority, lease, deployment, client, now| {
            let draft = AttestationCertificateDraft {
                manifest_id: MANIFEST_ID.to_owned(),
                certificate_id: CERTIFICATE_ID.to_owned(),
                issued_at_epoch_s: now,
            };
            let issuance = authority.issue_attestation(
                client,
                lease,
                &deployment.signer.accepted,
                &deployment.signer.deployment_policy,
                executed_snapshot,
                approval,
                execute_receipt,
                prepared.compiled_contract.clone(),
                &prepared.compiled_plan,
                bundle_value,
                AssuranceLevel::E3,
                draft,
                now,
                AUTHORIZATION_TTL_S,
            )?;
            let verified = verify_governed_production_attestation_against_bundle(
                &issuance.package,
                lease.attestation_trust(),
                lease.registry(),
                prepared.compiled_contract.clone(),
                &prepared.compiled_plan,
                bundle_value,
                AssuranceLevel::E3,
            )
            .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
            if verified.decision != DecisionStatus::Accepted
                || verified.evidence_bundle_digest != expected_bundle_digest
            {
                return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
            }
            let final_snapshot = build_final_snapshot(
                executed_snapshot,
                &verified,
                lease.attestation_trust().key.public_key_digest.clone(),
                lease.attestation_trust().key.generation,
            )?;
            authority.record_certificate(issuance, final_snapshot.clone())?;
            Ok(final_snapshot)
        })
        .map_err(boundary_error)
}

fn validate_approved_bindings(
    prepared: &PreparedDesktopJob,
    snapshot: &DesktopShellSnapshot,
    approval: &DesktopApprovalRecord,
    approve_receipt: &DesktopCommandReceipt,
) -> Result<(), String> {
    if snapshot.job_id.as_deref() != Some(prepared.job.job_id.as_str())
        || snapshot
            .contract
            .as_ref()
            .map(|item| item.digest.as_str())
            != Some(prepared.compiled_contract.seal.contract_digest.as_str())
        || snapshot.plan.as_ref().map(|item| item.digest.as_str())
            != Some(prepared.compiled_plan.plan_digest.as_str())
        || approve_receipt.action != DesktopCommandAction::Approve
        || approve_receipt.post_snapshot_digest != snapshot.snapshot_digest
        || approve_receipt.approval_digest.as_deref() != Some(approval.approval_digest.as_str())
    {
        return Err("approved desktop snapshot does not bind the canonical production job".to_owned());
    }
    Ok(())
}

fn verify_persisted_token(
    persisted: &PersistedProductionCapability,
    lease: &ergaxiom_windows_production_trust_state_runtime::VerifiedProductionSignerTrustLease,
    executor_id: &str,
    device_id: Option<&str>,
    approval: &DesktopApprovalRecord,
    contract: &CompiledContract,
    plan: &CompiledPlan,
    step: &PlanStep,
    trusted_now_epoch_s: u64,
) -> Result<(), ProductionExecutionBoundaryError> {
    let token = &persisted.token;
    token
        .signer_package
        .verify_governed(
            lease.capability_trust(),
            lease.registry(),
            token.payload.issued_at_epoch_s,
        )
        .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    let expected_token_id = step
        .capability_token_ids
        .first()
        .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    let (capability, resource, access) = expected_permission(step)?;
    let permission = contract
        .permissions
        .iter()
        .find(|permission| {
            permission.capability == capability
                && permission.resource == resource
                && permission.access == access
        })
        .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    if &token.payload.token_id != expected_token_id
        || token.payload.subject.executor_id != executor_id
        || token.payload.subject.device_id.as_deref() != device_id
        || token.payload.max_uses != 1
        || token.payload.issued_at_epoch_s > trusted_now_epoch_s
        || trusted_now_epoch_s < token.payload.not_before_epoch_s
        || trusted_now_epoch_s >= token.payload.expires_at_epoch_s
        || trusted_now_epoch_s >= approval.expires_at_epoch_s
        || token.payload.expires_at_epoch_s != approval.expires_at_epoch_s
        || token.payload.bindings.contract_digest != contract.seal.contract_digest
        || token.payload.bindings.capsule_digest != contract.seal.capsule_digest
        || token.payload.bindings.plan_id != plan.plan_id
        || token.payload.bindings.plan_digest != plan.plan_digest
        || token.payload.bindings.step_id != step.step_id
        || token.payload.bindings.operator_id != step.operator_id
        || token.payload.grant.capability != permission.capability
        || token.payload.grant.resource != permission.resource
        || token.payload.grant.access != permission.access
        || token.payload.grant.constraints != permission.constraints
    {
        return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
    }
    Ok(())
}

fn capability_draft(
    executor_id: &str,
    device_id: Option<&str>,
    approval: &DesktopApprovalRecord,
    contract: &CompiledContract,
    plan: &CompiledPlan,
    step: &PlanStep,
    now: u64,
) -> Result<CapabilityTokenDraft, ProductionExecutionBoundaryError> {
    if now >= approval.expires_at_epoch_s {
        return Err(ProductionExecutionBoundaryError::TrustedClockRejected);
    }
    let token_id = step
        .capability_token_ids
        .first()
        .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?
        .clone();
    let (capability, resource, access) = expected_permission(step)?;
    let permission = contract
        .permissions
        .iter()
        .find(|permission| {
            permission.capability == capability
                && permission.resource == resource
                && permission.access == access
        })
        .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    Ok(CapabilityTokenDraft {
        token_id,
        subject: CapabilitySubject {
            executor_id: executor_id.to_owned(),
            device_id: device_id.map(str::to_owned),
        },
        issued_at_epoch_s: now,
        not_before_epoch_s: now,
        expires_at_epoch_s: approval.expires_at_epoch_s,
        max_uses: 1,
        nonce: random_nonce()?,
        bindings: CapabilityBindings {
            contract_digest: contract.seal.contract_digest.clone(),
            capsule_digest: contract.seal.capsule_digest.clone(),
            plan_id: plan.plan_id.clone(),
            plan_digest: plan.plan_digest.clone(),
            step_id: step.step_id.clone(),
            operator_id: step.operator_id.clone(),
        },
        grant: CapabilityGrant {
            capability: permission.capability.clone(),
            resource: permission.resource.clone(),
            access: permission.access,
            constraints: permission.constraints.clone(),
        },
    })
}

fn expected_permission(
    step: &PlanStep,
) -> Result<(&'static str, &'static str, PermissionAccess), ProductionExecutionBoundaryError> {
    match step.step_id.as_str() {
        "step.canvas" | "step.text" => Ok((
            "design-editor",
            "isolated-workspace",
            PermissionAccess::Control,
        )),
        "step.logo" => Ok((
            "filesystem",
            "contract://inputs/*",
            PermissionAccess::Read,
        )),
        "step.export" => Ok((
            "filesystem",
            "contract://outputs/*",
            PermissionAccess::Write,
        )),
        _ => Err(ProductionExecutionBoundaryError::TrustLeaseRejected),
    }
}

fn bundle_with_operation_receipts(
    evidence: &ProductionGraphicEvidence,
) -> Result<(EvidenceBundle, Value), String> {
    let mut value = serde_json::to_value(&evidence.evidence_bundle)
        .map_err(|error| format!("Evidence Bundle encoding failed: {error}"))?;
    let artifacts = value
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "Evidence Bundle artifacts collection is invalid".to_owned())?;
    for receipt in &evidence.operation_receipts {
        let bytes = serde_json::to_vec(receipt)
            .map_err(|error| format!("operation receipt encoding failed: {error}"))?;
        let artifact_id = format!("execution_receipt.{}", receipt.operation_id);
        if artifacts.iter().any(|artifact| {
            artifact.get("artifact_id").and_then(Value::as_str) == Some(artifact_id.as_str())
        }) {
            return Err(format!("duplicate operation receipt artifact {artifact_id}"));
        }
        artifacts.push(json!({
            "artifact_id": artifact_id,
            "role": "evidence",
            "uri": format!("ergaxiom-inline-hex:{}", hex_encode(&bytes)),
            "media_type": "application/json",
            "algorithm": "sha256",
            "digest": sha256_hex(&bytes),
            "size_bytes": bytes.len() as u64,
        }));
    }
    let bundle: EvidenceBundle = serde_json::from_value(value.clone())
        .map_err(|error| format!("receipt-complete Evidence Bundle decode failed: {error}"))?;
    Ok((bundle, value))
}

fn build_executed_snapshot(
    prepared: &PreparedDesktopJob,
    approval: &DesktopApprovalRecord,
    evidence: &ProductionGraphicEvidence,
    evidence_bundle_digest: &str,
    replay_manifest: &ReplayManifest,
) -> Result<DesktopShellSnapshot, ProductionExecutionBoundaryError> {
    let replay_manifest_digest = canonical_json_sha256(
        &serde_json::to_value(replay_manifest)
            .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?,
    )
    .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    let steps = evidence
        .twin_run
        .simulation
        .steps
        .iter()
        .map(|step| PlanStepSummary {
            step_id: step.step_id.clone(),
            operator_id: prepared
                .compiled_plan
                .steps
                .iter()
                .find(|planned| planned.step_id == step.step_id)
                .map(|planned| planned.operator_id.clone())
                .unwrap_or_else(|| "invalid.operator".to_owned()),
            status: StageStatus::Passed,
            before_digest: Some(step.before_snapshot_digest.clone()),
            after_digest: Some(step.after_snapshot_digest.clone()),
        })
        .collect();
    let validators = evidence
        .twin_run
        .validation
        .observations
        .iter()
        .map(|observation| ValidatorSummary {
            validator_id: observation.validator_id.clone(),
            claim_id: observation.claim_id.clone(),
            report_digest: observation.evidence_digest.clone(),
            status: if observation.passed {
                StageStatus::Passed
            } else {
                StageStatus::Failed
            },
            actionable_message: (!observation.passed)
                .then(|| "production validation observation failed".to_owned()),
        })
        .collect();

    build_desktop_shell_snapshot(DesktopShellMaterial {
        generated_at: GENERATED_AT.to_owned(),
        job_id: Some(prepared.job.job_id.clone()),
        unresolved: Vec::new(),
        staged_inputs: prepared.staged_inputs.clone(),
        contract: Some(DigestItem {
            id: prepared.compiled_contract.contract_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: prepared.compiled_contract.seal.contract_digest.clone(),
            status: StageStatus::Passed,
        }),
        approval: Some(ApprovalSummary {
            approval_id: approval.approval_id.clone(),
            contract_digest: approval.contract_digest.clone(),
            plan_digest: approval.plan_digest.clone(),
            permission_digest: approval.permission_digest.clone(),
            expires_at_epoch_s: approval.expires_at_epoch_s,
            status: StageStatus::Passed,
        }),
        plan: Some(DigestItem {
            id: prepared.compiled_plan.plan_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: prepared.compiled_plan.plan_digest.clone(),
            status: StageStatus::Passed,
        }),
        steps,
        validators,
        evidence_bundle: Some(DigestItem {
            id: BUNDLE_ID.to_owned(),
            media_type: Some("application/json".to_owned()),
            digest: evidence_bundle_digest.to_owned(),
            status: StageStatus::Passed,
        }),
        replay_manifest: Some(DigestItem {
            id: replay_manifest.manifest_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: replay_manifest_digest.clone(),
            status: StageStatus::Passed,
        }),
        certificate: None,
        profession_capsules: vec![TrustComponentStatus {
            component_id: "ergaxiom.profession.graphic-designer".to_owned(),
            version: prepared
                .capsule
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
            digest: prepared.compiled_contract.seal.capsule_digest.clone(),
            trusted: true,
        }],
        adapters: vec![TrustComponentStatus {
            component_id: "ergaxiom.design-document-model".to_owned(),
            version: "0.1.0".to_owned(),
            digest: sha256_hex(b"ergaxiom.design-document-model@0.1.0"),
            trusted: true,
        }],
        trusted_keys: Vec::new(),
        metadata: json!({
            "pipeline": "approved_snapshot -> fresh_signer_lease -> production_capabilities -> durable_consumption -> occupational_twin -> evidence_bundle -> replay_manifest",
            "control_status": DesktopControlStatus::Executed,
            "approval_digest": approval.approval_digest,
            "execution_material_exposed": true,
            "twin_executed": true,
            "production_authorization_receipt_count": evidence.evidence_bundle.trace.authorization_receipts.len(),
            "operation_receipt_count": evidence.operation_receipts.len(),
            "evidence_bundle_digest": evidence_bundle_digest,
            "replay_manifest_digest": replay_manifest_digest,
            "production_certificate_verified": false,
        }),
    })
    .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)
}

fn build_final_snapshot(
    executed: &DesktopShellSnapshot,
    verified: &VerifiedAttestation,
    attestation_key_digest: String,
    attestation_generation: u64,
) -> Result<DesktopShellSnapshot, ProductionExecutionBoundaryError> {
    let mut trusted_keys = executed.trusted_keys.clone();
    trusted_keys.push(TrustComponentStatus {
        component_id: "ergaxiom.production.attestation".to_owned(),
        version: format!("generation-{attestation_generation}"),
        digest: attestation_key_digest,
        trusted: true,
    });
    build_desktop_shell_snapshot(DesktopShellMaterial {
        generated_at: executed.generated_at.clone(),
        job_id: executed.job_id.clone(),
        unresolved: executed.unresolved.clone(),
        staged_inputs: executed.staged_inputs.clone(),
        contract: executed.contract.clone(),
        approval: executed.approval.clone(),
        plan: executed.plan.clone(),
        steps: executed.steps.clone(),
        validators: executed.validators.clone(),
        evidence_bundle: executed.evidence_bundle.clone(),
        replay_manifest: executed.replay_manifest.clone(),
        certificate: Some(CertificateVerification {
            certificate_id: verified.certificate_id.clone(),
            certificate_digest: verified.certificate_digest.clone(),
            evidence_bundle_digest: verified.evidence_bundle_digest.clone(),
            signature_verified: true,
            bundle_verified: true,
            decision_accepted: true,
            mandatory_unknowns: 0,
            mandatory_failures: 0,
        }),
        profession_capsules: executed.profession_capsules.clone(),
        adapters: executed.adapters.clone(),
        trusted_keys,
        metadata: json!({
            "pipeline": "persisted_execution -> fresh_signer_lease -> production_attestation -> independent_verification",
            "control_status": DesktopControlStatus::Executed,
            "approval_digest": executed.metadata.get("approval_digest").cloned(),
            "execution_material_exposed": true,
            "twin_executed": true,
            "evidence_bundle_digest": verified.evidence_bundle_digest,
            "production_certificate_verified": true,
        }),
    })
    .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn random_nonce() -> Result<String, ProductionExecutionBoundaryError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ProductionExecutionBoundaryError::NonceUnavailable)?;
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_| ProductionExecutionBoundaryError::NonceUnavailable)?;
    }
    Ok(encoded)
}

fn trusted_epoch_s() -> Result<u64, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("trusted production clock failed: {error}"))
}

fn boundary_error(error: ProductionExecutionBoundaryError) -> String {
    format!(
        "production execution rejected [{}]: {error}",
        error.public_code()
    )
}
