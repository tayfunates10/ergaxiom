use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use ergaxiom_attestation_issuance_runtime::AttestationCertificateDraft;
use ergaxiom_attestation_runtime::{ReplayManifest, build_replay_manifest};
use ergaxiom_background_cleanup_certified_path_runtime::{
    BackgroundCleanupCertificationRequest, BackgroundCleanupExecutionRequest,
    BackgroundCleanupIntent, BackgroundEvidenceKeyRegistry, certify_background_cleanup,
    execute_background_cleanup, execute_inkscape_cleanup_probe,
    sign_background_cleanup_execution_record, sign_inkscape_cleanup_integration_report,
    validate_background_cleanup,
};
use ergaxiom_brand_compliant_export_certified_path_runtime::{
    BrandEvidenceKeyRegistry, BrandExportCertificationRequest, BrandExportExecutionRequest,
    BrandExportIntent, BrandRuleManifest, certify_brand_export, execute_brand_export,
    execute_inkscape_brand_probe, sign_brand_export_execution_record,
    sign_inkscape_brand_integration_report, validate_brand_export,
};
use ergaxiom_capability_issuance_runtime::CapabilityTokenDraft;
use ergaxiom_capability_runtime::{
    AuthorizationReceipt, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    ProductionSignerBoundCapabilityToken,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_desktop_shell_runtime::{
    ApprovalSummary, CertificateVerification, DesktopCommandAction, DesktopCommandReceipt,
    DesktopControlStatus, DesktopShellMaterial, DesktopShellSnapshot, DigestItem, PlanStepSummary,
    StageStatus, TrustComponentStatus, ValidatorSummary, build_desktop_shell_snapshot,
    issue_desktop_command_receipt,
};
use ergaxiom_desktop_user_job_runtime::{
    GraphicDesignerJobKind, UserJobRecord, UserJobStore,
};
use ergaxiom_evidence_runtime::{
    EnvironmentEvidence, EvidenceBundle, ProofResultStatus, assess_bundle,
};
use ergaxiom_execution_runtime::{
    AuthorizationReceiptRecord, AuthorizedExecutionTrace, ReceiptBoundTraceEvent,
};
use ergaxiom_graphic_designer_twin_runtime::{
    BrandProfile, GraphicDesignJob,
};
use ergaxiom_graphic_production_evidence_runtime::{
    ProductionGraphicEvidenceRequest, build_production_graphic_evidence,
};
use ergaxiom_inkscape_adapter_runtime::VerifiedInkscape;
use ergaxiom_occupational_twin_runtime::{
    ApplicationIdentity, EnvironmentIdentity, OperationOutcome, OperationReceipt, TwinWorkspace,
};
use ergaxiom_operator_plan_runtime::{CompiledPlan, PlanStep, TraceStatus, compile_plan};
use ergaxiom_print_ready_poster_preflight_certified_path_runtime::{
    PrintEvidenceKeyRegistry, PrintPreflightCertificationRequest, PrintPreflightExecutionRequest,
    PrintPreflightIntent, PrintSpecification, certify_print_preflight, execute_print_preflight,
    execute_inkscape_print_probe, sign_inkscape_print_integration_report,
    sign_print_preflight_execution_record, validate_print_preflight,
};
use ergaxiom_production_execution_runtime::{
    ProductionExecutionChainState, ProductionExecutionStage,
};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, canonical_json_sha256};
use ergaxiom_windows_production_governed_issuance_runtime::verify_governed_production_attestation_against_bundle;
use ergaxiom_windows_production_signer_host_runtime::validate_administrator_controlled_file;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::production_execution::{ProductionExecutionBoundaryError, ProductionExecutionState};

const LOCAL_ACTOR_ID: &str = "ergaxiom.local.operator";
const AUTHORIZATION_TTL_S: u64 = 60;
const PRODUCT_INKSCAPE_PATH: Option<&str> = option_env!("ERGAXIOM_PRODUCT_INKSCAPE_PATH");
const PRODUCT_INKSCAPE_SHA256: Option<&str> = option_env!("ERGAXIOM_PRODUCT_INKSCAPE_SHA256");

#[derive(Debug, Clone, Deserialize)]
struct CapabilityRequirement {
    token_id: String,
    step_id: String,
    capability: String,
    resource: String,
    access: String,
}

struct JobExecutionEvidence {
    bundle: EvidenceBundle,
    accepted_artifact_digests: Vec<String>,
    operation_receipts: Vec<OperationReceipt>,
    adapters: Vec<TrustComponentStatus>,
}

pub(crate) fn execute_product_job(
    production: &ProductionExecutionState,
    store: &UserJobStore,
) -> Result<ProductionExecutionChainState, String> {
    let record = store.current();
    let approval_binding = record
        .approval
        .as_ref()
        .ok_or_else(|| "canonical approval binding is missing".to_owned())?;
    let capsule = profession_capsule()?;
    let contract_value = record
        .work_contract
        .clone()
        .ok_or_else(|| "Work Contract is missing".to_owned())?;
    let plan_value = record
        .operator_plan
        .clone()
        .ok_or_else(|| "Operator Plan is missing".to_owned())?;
    let compiled_contract = compile_contract(&contract_value, &capsule)
        .map_err(|error| format!("stored Work Contract rejected at execution: {error}"))?;
    let compiled_plan = compile_plan(&plan_value, &capsule, &compiled_contract)
        .map_err(|error| format!("stored Operator Plan rejected at execution: {error}"))?;
    validate_compiled_bindings(record, &compiled_contract, &compiled_plan)?;
    let requirements = capability_requirements(&plan_value, &compiled_plan)?;

    let issued = issue_capabilities(
        production,
        &record.job_id,
        &compiled_contract,
        &compiled_plan,
        &requirements,
    )?;
    let authorization_receipts = consume_capabilities(
        production,
        &record.job_id,
        &compiled_contract,
        &compiled_plan,
        &issued,
    )?;

    let evidence = execute_job_adapter(
        store,
        &capsule,
        &contract_value,
        &compiled_contract,
        &compiled_plan,
        &authorization_receipts,
    )?;
    let bundle_value = serde_json::to_value(&evidence.bundle)
        .map_err(|error| format!("Evidence Bundle serialization failed: {error}"))?;
    let bundle_digest = canonical_json_sha256(&bundle_value)
        .map_err(|error| format!("Evidence Bundle digest failed: {error}"))?;
    let assessment = assess_bundle(
        compiled_contract.clone(),
        &compiled_plan,
        &evidence.bundle,
        AssuranceLevel::E3,
    )
    .map_err(|error| format!("production evidence assessment failed: {error}"))?;
    if assessment.decision.status != DecisionStatus::Accepted
        || assessment.mandatory_failed != 0
        || assessment.mandatory_unknown != 0
    {
        return Err("production Evidence Bundle was not accepted at E3".to_owned());
    }

    let replay_manifest = build_replay_manifest(
        format!("manifest.{}", record.job_id),
        record.job_id.clone(),
        compiled_contract.seal.contract_digest.clone(),
        compiled_contract.seal.capsule_digest.clone(),
        compiled_plan.plan_digest.clone(),
        bundle_digest.clone(),
        record.created_at.clone(),
        evidence.accepted_artifact_digests.clone(),
        authorization_receipts.clone(),
        evidence.operation_receipts.clone(),
    )
    .map_err(|error| format!("Replay Manifest construction failed: {error}"))?;

    let executed_snapshot = build_execution_snapshot(
        record,
        &compiled_contract,
        &compiled_plan,
        &evidence.bundle,
        &replay_manifest,
        &evidence.adapters,
        None,
        DesktopControlStatus::Executed,
    )?;
    let execute_receipt = issue_desktop_command_receipt(
        DesktopCommandAction::Execute,
        LOCAL_ACTOR_ID,
        &approval_binding.approved_snapshot,
        &executed_snapshot,
        Some(&approval_binding.record.approval_digest),
        current_epoch_s()?,
    )
    .map_err(|error| format!("canonical Execute receipt failed: {error}"))?;

    production
        .with_fresh_lease_for_job(
            &record.job_id,
            |authority, _lease, _deployment, _client, _now| {
                authority.record_execution(
                    executed_snapshot.clone(),
                    execute_receipt.clone(),
                    bundle_value.clone(),
                    replay_manifest.clone(),
                )?;
                Ok(())
            },
        )
        .map_err(boundary_error)?;

    let draft = AttestationCertificateDraft {
        certificate_id: format!("certificate.{}", record.job_id),
        bundle_id: evidence.bundle.bundle_id.clone(),
        contract_digest: compiled_contract.seal.contract_digest.clone(),
        capsule_digest: compiled_contract.seal.capsule_digest.clone(),
        plan_digest: compiled_plan.plan_digest.clone(),
        evidence_bundle_digest: bundle_digest,
        replay_manifest_digest: canonical_json_sha256(
            &serde_json::to_value(&replay_manifest)
                .map_err(|error| format!("Replay Manifest serialization failed: {error}"))?,
        )
        .map_err(|error| format!("Replay Manifest digest failed: {error}"))?,
        decision_status: assessment.decision.status,
        mandatory_passed: assessment.mandatory_passed,
        mandatory_failed: assessment.mandatory_failed,
        mandatory_unknown: assessment.mandatory_unknown,
        accepted_artifact_digests: evidence.accepted_artifact_digests,
        assurance_level: AssuranceLevel::E3,
        acceptance_policy_id: "ergaxiom.policy.acceptance.v1".to_owned(),
        issued_at: record.created_at.clone(),
        issued_at_epoch_s: current_epoch_s()?,
    };

    let (issuance, verified) = production
        .with_fresh_lease_for_job(
            &record.job_id,
            |authority, lease, deployment, client, trusted_now_epoch_s| {
                let issuance = authority.issue_attestation(
                    client,
                    lease,
                    &deployment.signer.accepted,
                    &deployment.signer.deployment_policy,
                    &executed_snapshot,
                    &approval_binding.record,
                    &execute_receipt,
                    compiled_contract.clone(),
                    &compiled_plan,
                    &bundle_value,
                    AssuranceLevel::E3,
                    draft.clone(),
                    trusted_now_epoch_s,
                    AUTHORIZATION_TTL_S,
                )?;
                let verified = verify_governed_production_attestation_against_bundle(
                    &issuance.package,
                    lease.attestation_trust(),
                    lease.registry(),
                    compiled_contract.clone(),
                    &compiled_plan,
                    &evidence.bundle,
                    AssuranceLevel::E3,
                )
                .map_err(|error| {
                    ProductionExecutionBoundaryError::OperationRejected(error.to_string())
                })?;
                Ok((issuance, verified))
            },
        )
        .map_err(boundary_error)?;

    let final_snapshot = build_execution_snapshot(
        record,
        &compiled_contract,
        &compiled_plan,
        &evidence.bundle,
        &replay_manifest,
        &evidence.adapters,
        Some(CertificateVerification {
            certificate_id: verified.certificate_id.clone(),
            certificate_digest: verified.certificate_digest.clone(),
            evidence_bundle_digest: verified.evidence_bundle_digest.clone(),
            signature_verified: true,
            bundle_verified: true,
            decision_accepted: verified.decision_status == DecisionStatus::Accepted,
            mandatory_passed: verified.mandatory_passed,
            mandatory_failures: verified.mandatory_failed,
            mandatory_unknowns: verified.mandatory_unknown,
        }),
        DesktopControlStatus::Executed,
    )?;
    if final_snapshot.authority_status
        != ergaxiom_desktop_shell_runtime::AuthorityStatus::VerifiedAccepted
    {
        return Err("final production snapshot did not reach VerifiedAccepted".to_owned());
    }
    production
        .with_fresh_lease_for_job(
            &record.job_id,
            |authority, _lease, _deployment, _client, _now| {
                authority.record_certificate(issuance, final_snapshot.clone())?;
                Ok(())
            },
        )
        .map_err(boundary_error)?;

    production
        .with_fresh_lease_for_job(
            &record.job_id,
            |authority, _lease, _deployment, _client, _now| Ok(authority.chain_state().clone()),
        )
        .map_err(boundary_error)
}

fn issue_capabilities(
    production: &ProductionExecutionState,
    job_id: &str,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    requirements: &[CapabilityRequirement],
) -> Result<Vec<(CapabilityRequirement, ProductionSignerBoundCapabilityToken)>, String> {
    let mut issued = Vec::with_capacity(requirements.len());
    for requirement in requirements {
        let requirement = requirement.clone();
        let compiled_contract = compiled_contract.clone();
        let compiled_plan = compiled_plan.clone();
        let token = production
            .with_fresh_lease_for_job(
                job_id,
                |authority, lease, deployment, client, trusted_now_epoch_s| {
                    let draft = capability_draft(
                        authority.executor_id(),
                        authority.device_id(),
                        &compiled_contract,
                        &compiled_plan,
                        &requirement,
                        trusted_now_epoch_s,
                    )
                    .map_err(ProductionExecutionBoundaryError::OperationRejected)?;
                    let issuance = authority.issue_capability_with_lease(
                        client,
                        lease,
                        &deployment.signer.accepted,
                        &deployment.signer.deployment_policy,
                        &approval_from_chain(authority)?,
                        compiled_contract.clone(),
                        &compiled_plan,
                        draft,
                        trusted_now_epoch_s,
                        AUTHORIZATION_TTL_S,
                    )?;
                    Ok(issuance.token)
                },
            )
            .map_err(boundary_error)?;
        issued.push((requirement, token));
    }
    Ok(issued)
}

fn consume_capabilities(
    production: &ProductionExecutionState,
    job_id: &str,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    issued: &[(CapabilityRequirement, ProductionSignerBoundCapabilityToken)],
) -> Result<Vec<AuthorizationReceipt>, String> {
    let mut receipts = Vec::with_capacity(issued.len());
    for (requirement, token) in issued {
        let requirement = requirement.clone();
        let token = token.clone();
        let compiled_contract = compiled_contract.clone();
        let compiled_plan = compiled_plan.clone();
        let receipt = production
            .with_fresh_lease_for_job(
                job_id,
                |authority, lease, deployment, _client, trusted_now_epoch_s| {
                    let receipt = authority.consume_capability_with_lease(
                        lease,
                        &deployment.signer.accepted,
                        &deployment.signer.deployment_policy,
                        &token,
                        &compiled_contract,
                        &compiled_plan,
                        trusted_now_epoch_s,
                    )?;
                    if receipt.bindings.step_id != requirement.step_id
                        || receipt.token_id != requirement.token_id
                    {
                        return Err(ProductionExecutionBoundaryError::OperationRejected(
                            "consumption receipt does not bind planned step/token".to_owned(),
                        ));
                    }
                    Ok(receipt)
                },
            )
            .map_err(boundary_error)?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

fn approval_from_chain(
    authority: &ergaxiom_production_execution_authority_runtime::PersistentProductionExecutionAuthority,
) -> Result<ergaxiom_desktop_shell_runtime::DesktopApprovalRecord, ProductionExecutionBoundaryError> {
    authority
        .chain_state()
        .approval
        .clone()
        .ok_or_else(|| ProductionExecutionBoundaryError::OperationRejected("durable approval is missing".to_owned()))
}

fn capability_draft(
    executor_id: &str,
    device_id: Option<&str>,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    requirement: &CapabilityRequirement,
    trusted_now_epoch_s: u64,
) -> Result<CapabilityTokenDraft, String> {
    let step = compiled_plan
        .steps
        .iter()
        .find(|step| step.step_id == requirement.step_id)
        .ok_or_else(|| format!("capability requirement references unknown step {}", requirement.step_id))?;
    if !step.capability_token_ids.contains(&requirement.token_id) {
        return Err(format!(
            "capability requirement token {} is not sealed into step {}",
            requirement.token_id, requirement.step_id
        ));
    }
    let expected_access = parse_access(&requirement.access)?;
    let permission = compiled_contract
        .permissions
        .iter()
        .find(|permission| {
            permission.capability == requirement.capability
                && permission.resource == requirement.resource
                && permission.access == expected_access
        })
        .ok_or_else(|| format!("no exact contract permission for step {}", requirement.step_id))?;
    let expires_at_epoch_s = trusted_now_epoch_s
        .checked_add(AUTHORIZATION_TTL_S)
        .ok_or_else(|| "capability expiry overflow".to_owned())?;
    Ok(CapabilityTokenDraft {
        token_id: requirement.token_id.clone(),
        subject: CapabilitySubject {
            executor_id: executor_id.to_owned(),
            device_id: device_id.map(str::to_owned),
        },
        issued_at_epoch_s: trusted_now_epoch_s,
        not_before_epoch_s: trusted_now_epoch_s,
        expires_at_epoch_s,
        max_uses: 1,
        nonce: random_hex_32()?,
        bindings: CapabilityBindings {
            job_id: compiled_contract.contract_id.clone(),
            contract_digest: compiled_contract.seal.contract_digest.clone(),
            plan_digest: compiled_plan.plan_digest.clone(),
            step_id: requirement.step_id.clone(),
        },
        grant: CapabilityGrant {
            capability: permission.capability.clone(),
            resource: permission.resource.clone(),
            access: permission.access,
            constraints: permission.constraints.clone(),
        },
    })
}

fn capability_requirements(
    plan_value: &Value,
    compiled_plan: &CompiledPlan,
) -> Result<Vec<CapabilityRequirement>, String> {
    let requirements: Vec<CapabilityRequirement> = serde_json::from_value(
        plan_value
            .get("metadata")
            .and_then(|value| value.get("capability_requirements"))
            .cloned()
            .ok_or_else(|| "Operator Plan metadata.capability_requirements is missing".to_owned())?,
    )
    .map_err(|error| format!("capability requirements decode failed: {error}"))?;
    if requirements.len() != compiled_plan.steps.len() {
        return Err("every planned step must have exactly one capability requirement".to_owned());
    }
    for step in &compiled_plan.steps {
        let matching = requirements
            .iter()
            .filter(|requirement| requirement.step_id == step.step_id)
            .count();
        if matching != 1 {
            return Err(format!("step {} does not have exactly one capability requirement", step.step_id));
        }
    }
    Ok(requirements)
}

fn parse_access(access: &str) -> Result<PermissionAccess, String> {
    match access {
        "read" => Ok(PermissionAccess::Read),
        "write" => Ok(PermissionAccess::Write),
        "control" => Ok(PermissionAccess::Control),
        _ => Err(format!("unsupported permission access {access}")),
    }
}

fn execute_job_adapter(
    store: &UserJobStore,
    capsule: &Value,
    contract_value: &Value,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    authorization_receipts: &[AuthorizationReceipt],
) -> Result<JobExecutionEvidence, String> {
    match store.current().job_kind {
        GraphicDesignerJobKind::StaticSocialPost => execute_static_social(
            store,
            capsule,
            contract_value,
            compiled_contract,
            compiled_plan,
            authorization_receipts,
        ),
        GraphicDesignerJobKind::ImageBackgroundCleanup => execute_background(
            store,
            capsule,
            contract_value,
            compiled_contract,
            compiled_plan,
            authorization_receipts,
        ),
        GraphicDesignerJobKind::BrandCompliantImageExport => execute_brand(
            store,
            capsule,
            contract_value,
            compiled_contract,
            compiled_plan,
            authorization_receipts,
        ),
        GraphicDesignerJobKind::PrintReadyPosterPreflight => execute_print(
            store,
            capsule,
            contract_value,
            compiled_contract,
            compiled_plan,
            authorization_receipts,
        ),
    }
}

fn execute_static_social(
    store: &UserJobStore,
    _capsule: &Value,
    contract_value: &Value,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    authorization_receipts: &[AuthorizationReceipt],
) -> Result<JobExecutionEvidence, String> {
    let mut manifest: Value = serde_json::from_slice(
        &store
            .input_bytes("intent_manifest")
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("Static Social intent manifest decode failed: {error}"))?;
    let execution_value = manifest
        .get_mut("execution_job")
        .map(Value::take)
        .ok_or_else(|| "Static Social intent manifest must contain execution_job".to_owned())?;
    let mut job: GraphicDesignJob = serde_json::from_value(execution_value)
        .map_err(|error| format!("execution_job decode failed: {error}"))?;
    job.job_id = store.current().job_id.clone();
    job.evaluated_at = store.current().created_at.clone();
    job.approved_logo.artifact_id = "approved_logo".to_owned();
    job.approved_logo.media_type = input_media_type(store, "approved_logo")?;
    job.approved_logo.content = store
        .input_bytes("approved_logo")
        .map_err(|error| error.to_string())?;
    let approved_copy_bytes = store
        .input_bytes("approved_copy")
        .map_err(|error| error.to_string())?;
    job.approved_copy.artifact_id = "approved_copy".to_owned();
    job.approved_copy.media_type = input_media_type(store, "approved_copy")?;
    job.approved_copy.text = String::from_utf8(approved_copy_bytes)
        .map_err(|_| "approved_copy must be UTF-8 text".to_owned())?;
    let mut brand_profile: BrandProfile = serde_json::from_slice(
        &store
            .input_bytes("brand_profile")
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("brand_profile decode failed: {error}"))?;
    brand_profile.artifact_id = "brand_profile".to_owned();
    brand_profile.media_type = input_media_type(store, "brand_profile")?;
    job.brand_profile = brand_profile;
    job.editable_master_id = "editable_master".to_owned();
    job.delivery_raster_id = "delivery_raster".to_owned();

    let mut workspace = native_graphic_workspace(&store.current().job_id, &store.current().created_at)?;
    let evidence = build_production_graphic_evidence(ProductionGraphicEvidenceRequest {
        bundle_id: &format!("bundle.{}", store.current().job_id),
        run_id: &format!("run.{}", store.current().job_id),
        trace_id: &format!("trace.{}", store.current().job_id),
        compiled_contract,
        contract_value,
        compiled_plan,
        job: &job,
        workspace: &mut workspace,
        authorization_receipts,
    })
    .map_err(|error| format!("Static Social production evidence failed: {error}"))?;
    Ok(JobExecutionEvidence {
        accepted_artifact_digests: vec![
            evidence.editable_master_digest.clone(),
            evidence.rendered_raster_digest.clone(),
        ],
        operation_receipts: evidence.operation_receipts,
        adapters: Vec::new(),
        bundle: evidence.bundle,
    })
}

fn execute_background(
    store: &UserJobStore,
    _capsule: &Value,
    contract_value: &Value,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    authorization_receipts: &[AuthorizationReceipt],
) -> Result<JobExecutionEvidence, String> {
    let intent: BackgroundCleanupIntent = serde_json::from_value(
        store
            .current()
            .resolved_intent
            .clone()
            .ok_or_else(|| "resolved background intent missing".to_owned())?,
    )
    .map_err(|error| format!("resolved background intent decode failed: {error}"))?;
    let expected_width = intent
        .source_width_px
        .ok_or_else(|| "source_width_px is required".to_owned())?;
    let expected_height = intent
        .source_height_px
        .ok_or_else(|| "source_height_px is required".to_owned())?;
    let source_png = store
        .input_bytes("source_raster")
        .map_err(|error| error.to_string())?;
    let mask_png = store
        .input_bytes("approved_cleanup_mask")
        .map_err(|error| error.to_string())?;
    let source_digest = input_digest(store, "source_raster")?;
    let mask_digest = input_digest(store, "approved_cleanup_mask")?;
    let execution = execute_background_cleanup(BackgroundCleanupExecutionRequest {
        request_id: &store.current().job_id,
        source_png: &source_png,
        approved_mask_png: &mask_png,
        expected_source_digest: &source_digest,
        expected_mask_digest: &mask_digest,
        expected_width,
        expected_height,
    })
    .map_err(|error| format!("Background Cleanup execution failed: {error}"))?;
    let validation = validate_background_cleanup(
        &source_png,
        &mask_png,
        &execution.cleaned_png,
        &execution.record,
    )
    .map_err(|error| format!("Background Cleanup validation failed: {error}"))?;
    let inkscape = product_inkscape()?;
    let workspace = execution_workspace(store, "background-cleanup")?;
    let integration = execute_inkscape_cleanup_probe(
        &inkscape,
        &execution.cleaned_png,
        &execution.record.request_id,
        &execution.record.output_digest,
        &workspace,
    )
    .map_err(|error| format!("Background Cleanup Inkscape integration failed: {error}"))?;
    let trace = authorized_trace(
        &store.current().job_id,
        compiled_plan,
        authorization_receipts,
        &store.current().created_at,
    )?;
    let (signing_key, key_id) = evidence_key()?;
    let signed_execution = sign_background_cleanup_execution_record(
        &execution.record,
        &key_id,
        &signing_key,
    )
    .map_err(|error| format!("Background execution record signing failed: {error}"))?;
    let signed_integration = sign_inkscape_cleanup_integration_report(
        &integration,
        &key_id,
        &signing_key,
    )
    .map_err(|error| format!("Background integration report signing failed: {error}"))?;
    let mut registry = BackgroundEvidenceKeyRegistry::new();
    registry
        .insert_ed25519(key_id, &signing_key.verifying_key())
        .map_err(|error| format!("Background evidence key registry failed: {error}"))?;
    let attestation_key = random_signing_key()?;
    let accepted = vec![execution.record.output_digest.clone()];
    let certified = certify_background_cleanup(BackgroundCleanupCertificationRequest {
        bundle_id: &format!("bundle.{}", store.current().job_id),
        certificate_id: &format!("evidence-only.{}", store.current().job_id),
        policy_id: "ergaxiom.product-alpha.evidence-only",
        compiled_contract,
        contract_value,
        compiled_plan,
        execution_trace: &trace,
        validation: &validation,
        integration: &integration,
        unsigned_execution_record: &execution.record,
        signed_execution_record: &signed_execution,
        execution_keys: &registry,
        signed_integration_report: &signed_integration,
        integration_keys: &registry,
        environment: product_environment(&inkscape, &store.current().job_id),
        accepted_artifact_digests: &accepted,
        signing_key_id: "product-evidence-attestation-v1",
        signing_key: &attestation_key,
        evaluated_at: &store.current().created_at,
        assurance_level: AssuranceLevel::E3,
    })
    .map_err(|error| format!("Background Cleanup evidence certification failed: {error}"))?;
    Ok(JobExecutionEvidence {
        bundle: certified.evidence_bundle,
        accepted_artifact_digests: accepted,
        operation_receipts: vec![adapter_operation_receipt(
            &execution.record.request_id,
            &execution.record.operator_id,
            &execution.record.pre_state_digest,
            &execution.record.post_state_digest,
            vec!["delivery_raster".to_owned()],
            &execution.record.record_digest,
        )],
        adapters: vec![inkscape_trust_component(&inkscape)],
    })
}

fn execute_brand(
    store: &UserJobStore,
    _capsule: &Value,
    contract_value: &Value,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    authorization_receipts: &[AuthorizationReceipt],
) -> Result<JobExecutionEvidence, String> {
    let intent: BrandExportIntent = serde_json::from_value(
        store
            .current()
            .resolved_intent
            .clone()
            .ok_or_else(|| "resolved Brand Export intent missing".to_owned())?,
    )
    .map_err(|error| format!("resolved Brand Export intent decode failed: {error}"))?;
    let manifest_bytes = store
        .input_bytes("brand_manifest")
        .map_err(|error| error.to_string())?;
    let manifest: BrandRuleManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("brand_manifest decode failed: {error}"))?;
    if let Some(resolved) = intent.resolved_manifest.as_ref() {
        if resolved != &manifest {
            return Err("resolved Brand manifest does not equal immutable brand_manifest".to_owned());
        }
    }
    let source_svg = store
        .input_bytes("source_svg")
        .map_err(|error| error.to_string())?;
    let logo_png = store
        .input_bytes("approved_logo")
        .map_err(|error| error.to_string())?;
    let inkscape = product_inkscape()?;
    let workspace = execution_workspace(store, "brand-export")?;
    let execution = execute_brand_export(
        &inkscape,
        BrandExportExecutionRequest {
            request_id: &store.current().job_id,
            source_svg: &source_svg,
            approved_logo_png: &logo_png,
            manifest: &manifest,
            expected_source_digest: &input_digest(store, "source_svg")?,
            expected_manifest_digest: &input_digest(store, "brand_manifest")?,
            expected_logo_digest: &input_digest(store, "approved_logo")?,
        },
        &workspace,
    )
    .map_err(|error| format!("Brand Export execution failed: {error}"))?;
    let validation = validate_brand_export(
        &source_svg,
        &logo_png,
        &manifest,
        &execution.editable_svg,
        &execution.raw_export_png,
        &execution.delivery_png,
        &execution.record,
    )
    .map_err(|error| format!("Brand Export validation failed: {error}"))?;
    let integration = execute_inkscape_brand_probe(
        &inkscape,
        &execution.editable_svg,
        &execution.record.request_id,
        &execution.record.editable_svg_digest,
        &workspace,
    )
    .map_err(|error| format!("Brand Export Inkscape probe failed: {error}"))?;
    let trace = authorized_trace(
        &store.current().job_id,
        compiled_plan,
        authorization_receipts,
        &store.current().created_at,
    )?;
    let (signing_key, key_id) = evidence_key()?;
    let signed_execution = sign_brand_export_execution_record(
        &execution.record,
        &key_id,
        &signing_key,
    )
    .map_err(|error| format!("Brand execution record signing failed: {error}"))?;
    let signed_integration = sign_inkscape_brand_integration_report(
        &integration,
        &key_id,
        &signing_key,
    )
    .map_err(|error| format!("Brand integration report signing failed: {error}"))?;
    let mut registry = BrandEvidenceKeyRegistry::new();
    registry
        .insert_ed25519(key_id, &signing_key.verifying_key())
        .map_err(|error| format!("Brand evidence key registry failed: {error}"))?;
    let attestation_key = random_signing_key()?;
    let accepted = vec![
        execution.record.editable_svg_digest.clone(),
        execution.record.delivery_png_digest.clone(),
    ];
    let certified = certify_brand_export(BrandExportCertificationRequest {
        bundle_id: &format!("bundle.{}", store.current().job_id),
        certificate_id: &format!("evidence-only.{}", store.current().job_id),
        policy_id: "ergaxiom.product-alpha.evidence-only",
        compiled_contract,
        contract_value,
        compiled_plan,
        execution_trace: &trace,
        validation: &validation,
        unsigned_execution_record: &execution.record,
        signed_execution_record: &signed_execution,
        execution_keys: &registry,
        signed_integration_report: &signed_integration,
        integration_keys: &registry,
        environment: product_environment(&inkscape, &store.current().job_id),
        accepted_artifact_digests: &accepted,
        signing_key_id: "product-evidence-attestation-v1",
        signing_key: &attestation_key,
        evaluated_at: &store.current().created_at,
        assurance_level: AssuranceLevel::E3,
    })
    .map_err(|error| format!("Brand Export evidence certification failed: {error}"))?;
    Ok(JobExecutionEvidence {
        bundle: certified.evidence_bundle,
        accepted_artifact_digests: accepted,
        operation_receipts: vec![adapter_operation_receipt(
            &execution.record.request_id,
            &execution.record.operator_id,
            &execution.record.source_svg_digest,
            &execution.record.delivery_png_digest,
            vec!["editable_master".to_owned(), "delivery_raster".to_owned()],
            &execution.record.record_digest,
        )],
        adapters: vec![inkscape_trust_component(&inkscape)],
    })
}

fn execute_print(
    store: &UserJobStore,
    _capsule: &Value,
    contract_value: &Value,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    authorization_receipts: &[AuthorizationReceipt],
) -> Result<JobExecutionEvidence, String> {
    let intent: PrintPreflightIntent = serde_json::from_value(
        store
            .current()
            .resolved_intent
            .clone()
            .ok_or_else(|| "resolved Print Poster intent missing".to_owned())?,
    )
    .map_err(|error| format!("resolved Print Poster intent decode failed: {error}"))?;
    let specification_bytes = store
        .input_bytes("print_specification")
        .map_err(|error| error.to_string())?;
    let specification: PrintSpecification = serde_json::from_slice(&specification_bytes)
        .map_err(|error| format!("print_specification decode failed: {error}"))?;
    if let Some(resolved) = intent.resolved_specification.as_ref() {
        if resolved != &specification {
            return Err(
                "resolved Print specification does not equal immutable print_specification"
                    .to_owned(),
            );
        }
    }
    let source_svg = store
        .input_bytes("source_svg")
        .map_err(|error| error.to_string())?;
    let inkscape = product_inkscape()?;
    let workspace = execution_workspace(store, "print-poster")?;
    let execution = execute_print_preflight(
        &inkscape,
        PrintPreflightExecutionRequest {
            request_id: &store.current().job_id,
            source_svg: &source_svg,
            specification: &specification,
            expected_source_digest: &input_digest(store, "source_svg")?,
            expected_specification_digest: &input_digest(store, "print_specification")?,
        },
        &workspace,
    )
    .map_err(|error| format!("Print Poster execution failed: {error}"))?;
    let validation = validate_print_preflight(
        &source_svg,
        &specification,
        &execution.editable_svg,
        &execution.raw_pdf,
        &execution.delivery_pdf,
        &execution.record,
    )
    .map_err(|error| format!("Print Poster validation failed: {error}"))?;
    let integration = execute_inkscape_print_probe(
        &inkscape,
        &execution.editable_svg,
        &execution.record.request_id,
        &execution.record.editable_svg_digest,
        &workspace,
    )
    .map_err(|error| format!("Print Poster Inkscape probe failed: {error}"))?;
    let trace = authorized_trace(
        &store.current().job_id,
        compiled_plan,
        authorization_receipts,
        &store.current().created_at,
    )?;
    let (signing_key, key_id) = evidence_key()?;
    let signed_execution = sign_print_preflight_execution_record(
        &execution.record,
        &key_id,
        &signing_key,
    )
    .map_err(|error| format!("Print execution record signing failed: {error}"))?;
    let signed_integration = sign_inkscape_print_integration_report(
        &integration,
        &key_id,
        &signing_key,
    )
    .map_err(|error| format!("Print integration report signing failed: {error}"))?;
    let mut registry = PrintEvidenceKeyRegistry::new();
    registry
        .insert_ed25519(key_id, &signing_key.verifying_key())
        .map_err(|error| format!("Print evidence key registry failed: {error}"))?;
    let attestation_key = random_signing_key()?;
    let accepted = vec![
        execution.record.editable_svg_digest.clone(),
        execution.record.normalized_pdf_digest.clone(),
    ];
    let certified = certify_print_preflight(PrintPreflightCertificationRequest {
        bundle_id: &format!("bundle.{}", store.current().job_id),
        certificate_id: &format!("evidence-only.{}", store.current().job_id),
        policy_id: "ergaxiom.product-alpha.evidence-only",
        compiled_contract,
        contract_value,
        compiled_plan,
        execution_trace: &trace,
        validation: &validation,
        unsigned_execution_record: &execution.record,
        signed_execution_record: &signed_execution,
        execution_keys: &registry,
        signed_integration_report: &signed_integration,
        integration_keys: &registry,
        environment: product_environment(&inkscape, &store.current().job_id),
        accepted_artifact_digests: &accepted,
        signing_key_id: "product-evidence-attestation-v1",
        signing_key: &attestation_key,
        evaluated_at: &store.current().created_at,
        assurance_level: AssuranceLevel::E3,
    })
    .map_err(|error| format!("Print Poster evidence certification failed: {error}"))?;
    Ok(JobExecutionEvidence {
        bundle: certified.evidence_bundle,
        accepted_artifact_digests: accepted,
        operation_receipts: vec![adapter_operation_receipt(
            &execution.record.request_id,
            &execution.record.operator_id,
            &execution.record.source_svg_digest,
            &execution.record.normalized_pdf_digest,
            vec!["editable_master".to_owned(), "delivery_pdf".to_owned()],
            &execution.record.record_digest,
        )],
        adapters: vec![inkscape_trust_component(&inkscape)],
    })
}

fn authorized_trace(
    job_id: &str,
    compiled_plan: &CompiledPlan,
    receipts: &[AuthorizationReceipt],
    evaluated_at: &str,
) -> Result<AuthorizedExecutionTrace, String> {
    let mut records = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        let receipt_digest = canonical_json_sha256(
            &serde_json::to_value(receipt)
                .map_err(|error| format!("authorization receipt serialization failed: {error}"))?,
        )
        .map_err(|error| format!("authorization receipt digest failed: {error}"))?;
        records.push(AuthorizationReceiptRecord {
            receipt: receipt.clone(),
            receipt_digest,
        });
    }
    let mut events = Vec::with_capacity(compiled_plan.steps.len() * 2);
    let mut event_index = 1_u64;
    for step in &compiled_plan.steps {
        let record = records
            .iter()
            .find(|record| record.receipt.bindings.step_id == step.step_id)
            .ok_or_else(|| format!("authorization receipt missing for step {}", step.step_id))?;
        events.push(ReceiptBoundTraceEvent {
            event_index,
            step_id: step.step_id.clone(),
            operator_id: step.operator_id.clone(),
            status: TraceStatus::Started,
            input_digests: vec![record.receipt_digest.clone()],
            output_digests: Vec::new(),
            authorization_receipt_digest: record.receipt_digest.clone(),
            evaluated_at: evaluated_at.to_owned(),
        });
        event_index = event_index
            .checked_add(1)
            .ok_or_else(|| "trace event index overflow".to_owned())?;
        events.push(ReceiptBoundTraceEvent {
            event_index,
            step_id: step.step_id.clone(),
            operator_id: step.operator_id.clone(),
            status: TraceStatus::Succeeded,
            input_digests: vec![record.receipt_digest.clone()],
            output_digests: vec![record.receipt_digest.clone()],
            authorization_receipt_digest: record.receipt_digest.clone(),
            evaluated_at: evaluated_at.to_owned(),
        });
        event_index = event_index
            .checked_add(1)
            .ok_or_else(|| "trace event index overflow".to_owned())?;
    }
    let mut trace = AuthorizedExecutionTrace {
        schema_version: "0.1.0".to_owned(),
        trace_id: format!("trace.{job_id}"),
        job_id: job_id.to_owned(),
        plan_digest: compiled_plan.plan_digest.clone(),
        authorization_receipts: records,
        events,
        trace_digest: String::new(),
    };
    trace.trace_digest = canonical_json_sha256(
        &serde_json::to_value(&trace)
            .map_err(|error| format!("trace serialization failed: {error}"))?,
    )
    .map_err(|error| format!("trace digest failed: {error}"))?;
    Ok(trace)
}

fn adapter_operation_receipt(
    operation_id: &str,
    operator_id: &str,
    before_digest: &str,
    after_digest: &str,
    changed_artifact_ids: Vec<String>,
    certified_record_digest: &str,
) -> OperationReceipt {
    OperationReceipt {
        operation_id: operation_id.to_owned(),
        operator_id: operator_id.to_owned(),
        outcome: OperationOutcome::Succeeded,
        before_snapshot_digest: before_digest.to_owned(),
        after_snapshot_digest: after_digest.to_owned(),
        changed_artifact_ids,
        violations: Vec::new(),
        operation_digest: certified_record_digest.to_owned(),
    }
}

fn build_execution_snapshot(
    record: &UserJobRecord,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    bundle: &EvidenceBundle,
    replay_manifest: &ReplayManifest,
    adapters: &[TrustComponentStatus],
    certificate: Option<CertificateVerification>,
    status: DesktopControlStatus,
) -> Result<DesktopShellSnapshot, String> {
    let approval = record
        .approval
        .as_ref()
        .ok_or_else(|| "canonical approval missing".to_owned())?;
    let evidence_digest = canonical_json_sha256(
        &serde_json::to_value(bundle)
            .map_err(|error| format!("Evidence Bundle serialization failed: {error}"))?,
    )
    .map_err(|error| format!("Evidence Bundle digest failed: {error}"))?;
    let replay_digest = canonical_json_sha256(
        &serde_json::to_value(replay_manifest)
            .map_err(|error| format!("Replay Manifest serialization failed: {error}"))?,
    )
    .map_err(|error| format!("Replay Manifest digest failed: {error}"))?;
    let material = DesktopShellMaterial {
        generated_at: record.created_at.clone(),
        job_id: Some(record.job_id.clone()),
        unresolved: Vec::new(),
        staged_inputs: record
            .inputs
            .values()
            .map(|input| DigestItem {
                id: input.role.clone(),
                media_type: Some(input.media_type.clone()),
                digest: input.sha256.clone(),
                status: StageStatus::Passed,
            })
            .collect(),
        contract: Some(DigestItem {
            id: compiled_contract.contract_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: compiled_contract.seal.contract_digest.clone(),
            status: StageStatus::Passed,
        }),
        approval: Some(ApprovalSummary {
            approval_id: approval.record.approval_id.clone(),
            contract_digest: approval.record.contract_digest.clone(),
            plan_digest: approval.record.plan_digest.clone(),
            permission_digest: approval.record.permission_digest.clone(),
            expires_at_epoch_s: approval.record.expires_at_epoch_s,
            status: StageStatus::Passed,
        }),
        plan: Some(DigestItem {
            id: compiled_plan.plan_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: compiled_plan.plan_digest.clone(),
            status: StageStatus::Passed,
        }),
        steps: compiled_plan
            .steps
            .iter()
            .map(|step| PlanStepSummary {
                step_id: step.step_id.clone(),
                operator_id: step.operator_id.clone(),
                status: StageStatus::Passed,
                before_digest: None,
                after_digest: None,
            })
            .collect(),
        validators: validators_from_bundle(bundle),
        evidence_bundle: Some(DigestItem {
            id: bundle.bundle_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: evidence_digest,
            status: StageStatus::Passed,
        }),
        replay_manifest: Some(DigestItem {
            id: replay_manifest.manifest_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: replay_digest,
            status: StageStatus::Passed,
        }),
        certificate,
        profession_capsules: vec![TrustComponentStatus {
            component_id: "ergaxiom.profession.graphic-designer".to_owned(),
            version: "0.1.0".to_owned(),
            digest: compiled_contract.seal.capsule_digest.clone(),
            trusted: true,
        }],
        adapters: adapters.to_vec(),
        trusted_keys: Vec::new(),
        metadata: json!({
            "control_status": match status {
                DesktopControlStatus::AwaitingApproval => "awaiting_approval",
                DesktopControlStatus::Approved => "approved",
                DesktopControlStatus::Executed => "executed",
                DesktopControlStatus::Cancelled => "cancelled",
                DesktopControlStatus::RolledBack => "rolled_back",
            },
            "approval_digest": approval.record.approval_digest,
            "job_kind": record.job_kind,
            "persistent_state_digest": record.state_digest,
            "product_alpha": true,
        }),
    };
    build_desktop_shell_snapshot(material)
        .map_err(|error| format!("product execution snapshot failed: {error}"))
}

fn validators_from_bundle(bundle: &EvidenceBundle) -> Vec<ValidatorSummary> {
    bundle
        .proof_results
        .iter()
        .map(|result| ValidatorSummary {
            validator_id: result.validator_id.clone(),
            obligation_id: result.obligation_id.clone(),
            status: match result.status {
                ProofResultStatus::Passed => StageStatus::Passed,
                ProofResultStatus::Failed => StageStatus::Failed,
                ProofResultStatus::Unknown => StageStatus::Unknown,
            },
            evidence_ids: result.evidence_artifact_ids.clone(),
            message: Some(format!(
                "claim={} subject={}",
                result.claim_id, result.subject_artifact_id
            )),
        })
        .collect()
}

fn validate_compiled_bindings(
    record: &UserJobRecord,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
) -> Result<(), String> {
    if record.contract_digest.as_deref() != Some(compiled_contract.seal.contract_digest.as_str())
        || record.plan_digest.as_deref() != Some(compiled_plan.plan_digest.as_str())
        || compiled_plan.contract_digest != compiled_contract.seal.contract_digest
    {
        return Err("persistent job contract/plan digest binding changed before execution".to_owned());
    }
    Ok(())
}

fn input_digest(store: &UserJobStore, role: &str) -> Result<String, String> {
    store
        .current()
        .inputs
        .get(role)
        .map(|input| input.sha256.clone())
        .ok_or_else(|| format!("immutable input {role} is missing"))
}

fn input_media_type(store: &UserJobStore, role: &str) -> Result<String, String> {
    store
        .current()
        .inputs
        .get(role)
        .map(|input| input.media_type.clone())
        .ok_or_else(|| format!("immutable input {role} is missing"))
}

fn product_inkscape() -> Result<VerifiedInkscape, String> {
    let path = PRODUCT_INKSCAPE_PATH
        .ok_or_else(|| "production Inkscape path is not installed at build time".to_owned())?;
    let digest = PRODUCT_INKSCAPE_SHA256
        .ok_or_else(|| "production Inkscape SHA-256 pin is not installed at build time".to_owned())?;
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err("production Inkscape path must be absolute".to_owned());
    }
    validate_administrator_controlled_file(&path)
        .map_err(|error| format!("production Inkscape ACL rejected: {error}"))?;
    VerifiedInkscape::open(&path, digest)
        .map_err(|error| format!("production Inkscape verification failed: {error}"))
}

fn execution_workspace(store: &UserJobStore, specialization: &str) -> Result<PathBuf, String> {
    let root = product_execution_root()?.join(&store.current().job_id).join(format!(
        "{}-{}",
        specialization, store.current().revision
    ));
    if root.exists() {
        return Err(format!("execution workspace already exists: {}", root.display()));
    }
    fs::create_dir_all(&root)
        .map_err(|error| format!("execution workspace creation failed: {error}"))?;
    Ok(root)
}

fn product_execution_root() -> Result<PathBuf, String> {
    if let Some(path) = option_env!("ERGAXIOM_PRODUCT_EXECUTION_WORK_ROOT") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err("ERGAXIOM_PRODUCT_EXECUTION_WORK_ROOT must be absolute".to_owned());
        }
        return Ok(path);
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| "LOCALAPPDATA is unavailable for execution workspace".to_owned())?;
        return Ok(base.join("Ergaxiom").join("ProductAlpha").join("execution-workspaces"));
    }
    #[cfg(not(windows))]
    {
        Ok(std::env::temp_dir().join("ergaxiom-product-alpha-execution-workspaces"))
    }
}

fn product_environment(inkscape: &VerifiedInkscape, job_id: &str) -> EnvironmentEvidence {
    EnvironmentEvidence {
        os: "windows".to_owned(),
        kernel_version: "production".to_owned(),
        applications: vec![inkscape.application_evidence()],
        clock_source: "backend-trusted-clock".to_owned(),
        sandbox_id: Some(job_id.to_owned()),
    }
}

fn inkscape_trust_component(inkscape: &VerifiedInkscape) -> TrustComponentStatus {
    TrustComponentStatus {
        component_id: inkscape.identity().application_id.clone(),
        version: inkscape.identity().version.clone(),
        digest: inkscape.identity().executable_digest.clone(),
        trusted: true,
    }
}

fn native_graphic_workspace(job_id: &str, created_at: &str) -> Result<TwinWorkspace, String> {
    TwinWorkspace::new(
        format!("workspace.{job_id}"),
        EnvironmentIdentity {
            os: "windows".to_owned(),
            architecture: "x86_64".to_owned(),
            runtime_id: "ergaxiom-native-graphic-runtime".to_owned(),
            runtime_version: "0.1.0".to_owned(),
            clock_source: created_at.to_owned(),
            sandbox_id: format!("sandbox.{job_id}"),
            applications: vec![ApplicationIdentity {
                application_id: "design-editor".to_owned(),
                version: "0.1.0".to_owned(),
                digest: native_runtime_digest()?,
            }],
        },
    )
    .map_err(|error| format!("native Graphic Designer workspace failed: {error}"))
}

fn native_runtime_digest() -> Result<String, String> {
    canonical_json_sha256(&json!({
        "runtime_id": "ergaxiom-native-graphic-runtime",
        "runtime_version": "0.1.0",
        "renderer": "ergaxiom-graphic-designer-twin-runtime"
    }))
    .map_err(|error| format!("native runtime digest failed: {error}"))
}

fn evidence_key() -> Result<(SigningKey, String), String> {
    Ok((random_signing_key()?, "product-evidence-key-v1".to_owned()))
}

fn random_signing_key() -> Result<SigningKey, String> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|error| format!("OS evidence-key randomness failed: {error}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn random_hex_32() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| format!("OS nonce randomness failed: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn profession_capsule() -> Result<Value, String> {
    serde_json::from_str(include_str!(
        "../../../../professions/graphic-designer/profession.json"
    ))
    .map_err(|error| format!("Graphic Designer capsule decode failed: {error}"))
}

fn current_epoch_s() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before UNIX epoch".to_owned())
}

fn boundary_error(error: ProductionExecutionBoundaryError) -> String {
    format!("{}: {error}", error.public_code())
}
