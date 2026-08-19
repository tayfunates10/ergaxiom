use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_background_cleanup_certified_path_runtime::{
    BackgroundCleanupCompileOutcome, BackgroundCleanupIntent, BackgroundCleanupPlanIdentity,
    BackgroundCleanupPlanOutcome, CleanupArtifactIntent, compile_background_cleanup_intent,
    synthesize_background_cleanup_plan,
};
use ergaxiom_brand_compliant_export_certified_path_runtime::{
    BrandArtifactIntent, BrandExportCompileOutcome, BrandExportIntent, BrandExportPlanIdentity,
    BrandExportPlanOutcome, compile_brand_export_intent, synthesize_brand_export_plan,
};
use ergaxiom_contract_runtime::compile_contract;
use ergaxiom_desktop_shell_runtime::{
    ApprovalSummary, DesktopApprovalRequest, DesktopApprovalRecord, DesktopCommandAction,
    DesktopControlStatus, DesktopShellMaterial, DesktopShellSnapshot, DigestItem, PlanStepSummary,
    StageStatus, TrustComponentStatus, build_desktop_shell_snapshot, issue_desktop_approval,
    issue_desktop_command_receipt, verify_desktop_approval_for_execution,
};
use ergaxiom_desktop_user_job_runtime::{
    ApprovalAuthorityBinding, CertificateBinding, CompiledJobMaterial, EvidenceBinding,
    GraphicDesignerJobKind, ImmutableInput, JobHistoryEntry, ProductionBinding, UserJobPhase,
    UserJobRecord, UserJobStore, list_job_ids,
};
use ergaxiom_intent_contract_compiler_runtime::{
    InputArtifactIntent, IntentCompileOutcome, StaticSocialPostIntent,
    compile_static_social_post_intent,
};
use ergaxiom_operator_plan_runtime::compile_plan;
use ergaxiom_print_ready_poster_preflight_certified_path_runtime::{
    PrintArtifactIntent, PrintPreflightCompileOutcome, PrintPreflightIntent,
    PrintPreflightPlanIdentity, PrintPreflightPlanOutcome, compile_print_preflight_intent,
    synthesize_print_preflight_plan,
};
use ergaxiom_production_execution_runtime::{
    ProductionExecutionChainState, ProductionExecutionStage,
};
use ergaxiom_typed_planner_runtime::{
    StaticSocialPostPlanIdentity, TypedPlanOutcome, synthesize_static_social_post_plan,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tauri::State;

use crate::production_execution::{ProductionExecutionBoundaryError, ProductionExecutionState};
use crate::production_startup::ProductionStartupState;

const LOCAL_ACTOR_ID: &str = "ergaxiom.local.operator";
const APPROVAL_TTL_S: u64 = 15 * 60;
static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize)]
pub struct ProductJobView {
    pub record: UserJobRecord,
    pub history: Vec<JobHistoryEntry>,
    pub required_input_roles: Vec<String>,
}

struct ProductJobRuntime {
    root: PathBuf,
    jobs: BTreeMap<String, UserJobStore>,
}

pub struct ProductJobState {
    runtime: Mutex<Option<ProductJobRuntime>>,
    init_error: Option<String>,
}

impl ProductJobState {
    #[must_use]
    pub fn initialize() -> Self {
        match initialize_runtime() {
            Ok(runtime) => Self {
                runtime: Mutex::new(Some(runtime)),
                init_error: None,
            },
            Err(error) => Self {
                runtime: Mutex::new(None),
                init_error: Some(error),
            },
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateProductJobRequest {
    pub job_kind: GraphicDesignerJobKind,
    pub original_text: String,
}

#[derive(Debug, Deserialize)]
pub struct ImportProductJobInputRequest {
    pub job_id: String,
    pub expected_state_digest: String,
    pub role: String,
    pub file_name: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct ExpectedProductJobRequest {
    pub job_id: String,
    pub expected_state_digest: String,
}

#[tauri::command]
pub fn list_product_jobs(state: State<'_, ProductJobState>) -> Result<Vec<ProductJobView>, String> {
    let guard = state
        .runtime
        .lock()
        .map_err(|_| "product job state lock poisoned".to_owned())?;
    let runtime = guard.as_ref().ok_or_else(|| {
        state
            .init_error
            .clone()
            .unwrap_or_else(|| "product job runtime unavailable".to_owned())
    })?;
    runtime.jobs.values().map(product_view).collect()
}

#[tauri::command]
pub fn create_product_job(
    state: State<'_, ProductJobState>,
    request: CreateProductJobRequest,
) -> Result<ProductJobView, String> {
    if request.original_text.trim().is_empty() {
        return Err("user request must not be empty".to_owned());
    }
    let now = current_epoch_s()?;
    let sequence = JOB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let job_id = format!("job.product.{now}.{sequence}");
    let created_at = format!("product-state-{now}");
    let mut guard = state
        .runtime
        .lock()
        .map_err(|_| "product job state lock poisoned".to_owned())?;
    let runtime = guard.as_mut().ok_or_else(|| {
        state
            .init_error
            .clone()
            .unwrap_or_else(|| "product job runtime unavailable".to_owned())
    })?;
    let store = UserJobStore::create(
        &runtime.root,
        job_id.clone(),
        request.job_kind,
        created_at,
        request.original_text,
    )
    .map_err(|error| error.to_string())?;
    runtime.jobs.insert(job_id.clone(), store);
    product_view(
        runtime
            .jobs
            .get(&job_id)
            .ok_or_else(|| "created job disappeared".to_owned())?,
    )
}

#[tauri::command]
pub fn import_product_job_input(
    state: State<'_, ProductJobState>,
    request: ImportProductJobInputRequest,
) -> Result<ProductJobView, String> {
    let mut guard = state
        .runtime
        .lock()
        .map_err(|_| "product job state lock poisoned".to_owned())?;
    let runtime = guard.as_mut().ok_or_else(|| {
        state
            .init_error
            .clone()
            .unwrap_or_else(|| "product job runtime unavailable".to_owned())
    })?;
    let store = runtime
        .jobs
        .get_mut(&request.job_id)
        .ok_or_else(|| "unknown product job".to_owned())?;
    store
        .import_input(
            &request.expected_state_digest,
            &request.role,
            &request.file_name,
            &request.media_type,
            &request.bytes,
        )
        .map_err(|error| error.to_string())?;
    product_view(store)
}

#[tauri::command]
pub fn prepare_product_job(
    state: State<'_, ProductJobState>,
    request: ExpectedProductJobRequest,
) -> Result<ProductJobView, String> {
    let mut guard = state
        .runtime
        .lock()
        .map_err(|_| "product job state lock poisoned".to_owned())?;
    let runtime = guard.as_mut().ok_or_else(|| {
        state
            .init_error
            .clone()
            .unwrap_or_else(|| "product job runtime unavailable".to_owned())
    })?;
    let store = runtime
        .jobs
        .get_mut(&request.job_id)
        .ok_or_else(|| "unknown product job".to_owned())?;
    prepare_store(store, &request.expected_state_digest)?;
    product_view(store)
}

#[tauri::command]
pub fn approve_product_job(
    state: State<'_, ProductJobState>,
    request: ExpectedProductJobRequest,
) -> Result<ProductJobView, String> {
    let now = current_epoch_s()?;
    let mut guard = state
        .runtime
        .lock()
        .map_err(|_| "product job state lock poisoned".to_owned())?;
    let runtime = guard.as_mut().ok_or_else(|| {
        state
            .init_error
            .clone()
            .unwrap_or_else(|| "product job runtime unavailable".to_owned())
    })?;
    let store = runtime
        .jobs
        .get_mut(&request.job_id)
        .ok_or_else(|| "unknown product job".to_owned())?;
    if store.current().state_digest != request.expected_state_digest {
        return Err("stale product job snapshot".to_owned());
    }
    if !matches!(
        store.current().phase,
        UserJobPhase::PermissionRequired
            | UserJobPhase::ReadyForApproval
            | UserJobPhase::ApprovalExpired
    ) {
        return Err("job is not awaiting canonical approval".to_owned());
    }
    let awaiting_snapshot = build_product_control_snapshot(store, DesktopControlStatus::AwaitingApproval, None)?;
    let approval = issue_desktop_approval(
        &awaiting_snapshot,
        &DesktopApprovalRequest {
            expected_snapshot_digest: awaiting_snapshot.snapshot_digest.clone(),
            contract_digest: store
                .current()
                .contract_digest
                .clone()
                .ok_or_else(|| "compiled contract binding is missing".to_owned())?,
            plan_digest: store
                .current()
                .plan_digest
                .clone()
                .ok_or_else(|| "compiled plan binding is missing".to_owned())?,
            permission_digest: store
                .current()
                .permission_digest
                .clone()
                .ok_or_else(|| "permission digest binding is missing".to_owned())?,
        },
        LOCAL_ACTOR_ID,
        now,
        APPROVAL_TTL_S,
    )
    .map_err(|error| format!("canonical desktop approval failed: {error}"))?;
    let approved_snapshot =
        build_product_control_snapshot(store, DesktopControlStatus::Approved, Some(&approval))?;
    let approve_receipt = issue_desktop_command_receipt(
        DesktopCommandAction::Approve,
        LOCAL_ACTOR_ID,
        &awaiting_snapshot,
        &approved_snapshot,
        Some(&approval.approval_digest),
        now,
    )
    .map_err(|error| format!("canonical Approve receipt failed: {error}"))?;
    store
        .record_canonical_approval(
            &request.expected_state_digest,
            ApprovalAuthorityBinding {
                record: approval,
                approved_snapshot,
                approve_receipt,
            },
        )
        .map_err(|error| error.to_string())?;
    product_view(store)
}

#[tauri::command]
pub fn start_product_job_execution(
    state: State<'_, ProductJobState>,
    signer_state: State<'_, ProductionStartupState>,
    execution_state: State<'_, ProductionExecutionState>,
    request: ExpectedProductJobRequest,
) -> Result<ProductJobView, String> {
    let signer = signer_state.status();
    let mut guard = state
        .runtime
        .lock()
        .map_err(|_| "product job state lock poisoned".to_owned())?;
    let runtime = guard.as_mut().ok_or_else(|| {
        state
            .init_error
            .clone()
            .unwrap_or_else(|| "product job runtime unavailable".to_owned())
    })?;
    let store = runtime
        .jobs
        .get_mut(&request.job_id)
        .ok_or_else(|| "unknown product job".to_owned())?;
    if store.current().state_digest != request.expected_state_digest {
        return Err("stale product job snapshot".to_owned());
    }
    if store.current().phase != UserJobPhase::Approved {
        return Err("job must have a fresh exact-digest approval before production execution".to_owned());
    }
    let approval_binding = store
        .current()
        .approval
        .clone()
        .ok_or_else(|| "canonical approval binding missing".to_owned())?;
    let now = current_epoch_s()?;
    if now > approval_binding.record.expires_at_epoch_s {
        store
            .record_approval_expired(&request.expected_state_digest)
            .map_err(|error| error.to_string())?;
        return product_view(store);
    }
    verify_desktop_approval_for_execution(
        &approval_binding.approved_snapshot,
        &approval_binding.record,
        &approval_binding.record.approval_digest,
        now,
    )
    .map_err(|error| format!("canonical approval is not executable: {error}"))?;
    if !signer.production_issuance_enabled {
        store
            .record_signer_unavailable(&request.expected_state_digest, signer.code)
            .map_err(|error| error.to_string())?;
        return product_view(store);
    }

    let chain = execution_state
        .with_fresh_lease_for_job(&request.job_id, |authority, _lease, _deployment, _client, _now| {
            if authority.chain_state().stage == ProductionExecutionStage::Initial {
                authority.record_approval(
                    approval_binding.approved_snapshot.clone(),
                    approval_binding.record.clone(),
                    approval_binding.approve_receipt.clone(),
                )?;
            }
            Ok(authority.chain_state().clone())
        })
        .map_err(boundary_error)?;
    store
        .record_production_observation(
            &request.expected_state_digest,
            ProductionBinding {
                chain_state_digest: chain.state_digest.clone(),
                stage: production_stage_name(chain.stage).to_owned(),
            },
        )
        .map_err(|error| error.to_string())?;
    product_view(store)
}

#[tauri::command]
pub fn sync_product_job_from_production(
    state: State<'_, ProductJobState>,
    execution_state: State<'_, ProductionExecutionState>,
    request: ExpectedProductJobRequest,
) -> Result<ProductJobView, String> {
    let mut guard = state
        .runtime
        .lock()
        .map_err(|_| "product job state lock poisoned".to_owned())?;
    let runtime = guard.as_mut().ok_or_else(|| {
        state
            .init_error
            .clone()
            .unwrap_or_else(|| "product job runtime unavailable".to_owned())
    })?;
    let store = runtime
        .jobs
        .get_mut(&request.job_id)
        .ok_or_else(|| "unknown product job".to_owned())?;
    if store.current().state_digest != request.expected_state_digest {
        return Err("stale product job snapshot".to_owned());
    }
    let production = execution_state
        .with_fresh_lease_for_job(&request.job_id, |authority, _lease, _deployment, _client, _now| {
            Ok(authority.chain_state().clone())
        })
        .map_err(boundary_error)?;
    apply_production_chain(store, production)?;
    product_view(store)
}

#[tauri::command]
pub fn cancel_product_job(
    state: State<'_, ProductJobState>,
    request: ExpectedProductJobRequest,
) -> Result<ProductJobView, String> {
    let mut guard = state
        .runtime
        .lock()
        .map_err(|_| "product job state lock poisoned".to_owned())?;
    let runtime = guard.as_mut().ok_or_else(|| {
        state
            .init_error
            .clone()
            .unwrap_or_else(|| "product job runtime unavailable".to_owned())
    })?;
    let store = runtime
        .jobs
        .get_mut(&request.job_id)
        .ok_or_else(|| "unknown product job".to_owned())?;
    store
        .cancel_before_execution(&request.expected_state_digest)
        .map_err(|error| error.to_string())?;
    product_view(store)
}

fn apply_production_chain(
    store: &mut UserJobStore,
    production: ProductionExecutionChainState,
) -> Result<(), String> {
    let expected = store.current().state_digest.clone();
    store
        .record_production_observation(
            &expected,
            ProductionBinding {
                chain_state_digest: production.state_digest.clone(),
                stage: production_stage_name(production.stage).to_owned(),
            },
        )
        .map_err(|error| error.to_string())?;

    if production.stage == ProductionExecutionStage::Certified {
        let bundle = production
            .evidence_bundle
            .clone()
            .ok_or_else(|| "certified production chain is missing Evidence Bundle".to_owned())?;
        let replay = serde_json::to_value(
            production
                .replay_manifest
                .as_ref()
                .ok_or_else(|| "certified production chain is missing Replay Manifest".to_owned())?,
        )
        .map_err(|error| error.to_string())?;
        let final_snapshot = production
            .final_snapshot
            .as_ref()
            .ok_or_else(|| "certified production chain is missing final snapshot".to_owned())?;
        let verification = final_snapshot
            .certificate
            .as_ref()
            .ok_or_else(|| "certified production chain is missing certificate verification".to_owned())?;
        let validator_results = final_snapshot
            .validators
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        let evidence = EvidenceBinding {
            evidence_bundle_digest: production
                .evidence_bundle_digest
                .clone()
                .ok_or_else(|| "certified production chain is missing Evidence Bundle digest".to_owned())?,
            evidence_bundle: bundle,
            replay_manifest_digest: production
                .replay_manifest_digest
                .clone()
                .ok_or_else(|| "certified production chain is missing Replay Manifest digest".to_owned())?,
            replay_manifest: replay,
            validator_results,
            failure_map: None,
            accepted: verification.decision_accepted
                && verification.mandatory_failures == 0
                && verification.mandatory_unknowns == 0
                && verification.signature_verified
                && verification.bundle_verified,
        };
        let expected = store.current().state_digest.clone();
        store
            .record_evidence(&expected, evidence)
            .map_err(|error| error.to_string())?;

        if store.current().phase != UserJobPhase::RecoveryRequired {
            let package = serde_json::to_value(
                production
                    .acceptance_package
                    .as_ref()
                    .ok_or_else(|| {
                        "certified production chain is missing Acceptance Certificate package"
                            .to_owned()
                    })?,
            )
            .map_err(|error| error.to_string())?;
            let expected = store.current().state_digest.clone();
            store
                .record_certificate(
                    &expected,
                    CertificateBinding {
                        certificate_id: verification.certificate_id.clone(),
                        certificate_digest: verification.certificate_digest.clone(),
                        production_state_digest: production.state_digest.clone(),
                        acceptance_certificate: package,
                        signature_verified: verification.signature_verified,
                        bundle_verified: verification.bundle_verified,
                        decision_accepted: verification.decision_accepted,
                        mandatory_failed: verification.mandatory_failures,
                        mandatory_unknown: verification.mandatory_unknowns,
                    },
                )
                .map_err(|error| error.to_string())?;
        }
    } else if production.stage == ProductionExecutionStage::RolledBack {
        let expected = store.current().state_digest.clone();
        store
            .record_rollback_observed(&expected, &production.state_digest)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn build_product_control_snapshot(
    store: &UserJobStore,
    status: DesktopControlStatus,
    approval: Option<&DesktopApprovalRecord>,
) -> Result<DesktopShellSnapshot, String> {
    let capsule = profession_capsule()?;
    let contract_value = store
        .current()
        .work_contract
        .as_ref()
        .ok_or_else(|| "Work Contract is unavailable".to_owned())?;
    let plan_value = store
        .current()
        .operator_plan
        .as_ref()
        .ok_or_else(|| "Operator Plan is unavailable".to_owned())?;
    let compiled_contract = compile_contract(contract_value, &capsule)
        .map_err(|error| format!("stored Work Contract failed compilation: {error}"))?;
    let compiled_plan = compile_plan(plan_value, &capsule, &compiled_contract)
        .map_err(|error| format!("stored Operator Plan failed compilation: {error}"))?;
    if store.current().contract_digest.as_deref()
        != Some(compiled_contract.seal.contract_digest.as_str())
        || store.current().plan_digest.as_deref() != Some(compiled_plan.plan_digest.as_str())
    {
        return Err("stored compiled material no longer matches persistent digests".to_owned());
    }
    let permission_digest = store
        .current()
        .permission_digest
        .clone()
        .ok_or_else(|| "permission digest unavailable".to_owned())?;
    let (approval_id, expires_at_epoch_s, approval_status, approval_digest) = match approval {
        Some(record) => (
            record.approval_id.clone(),
            record.expires_at_epoch_s,
            StageStatus::Passed,
            Some(record.approval_digest.clone()),
        ),
        None => (
            format!("approval.pending.{}", store.current().job_id),
            0,
            StageStatus::Pending,
            None,
        ),
    };
    let capsule_version = capsule
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| "Graphic Designer capsule version missing".to_owned())?;
    let control_status = match status {
        DesktopControlStatus::AwaitingApproval => "awaiting_approval",
        DesktopControlStatus::Approved => "approved",
        DesktopControlStatus::Executed => "executed",
        DesktopControlStatus::Cancelled => "cancelled",
        DesktopControlStatus::RolledBack => "rolled_back",
    };
    let material = DesktopShellMaterial {
        generated_at: store.current().created_at.clone(),
        job_id: Some(store.current().job_id.clone()),
        unresolved: Vec::new(),
        staged_inputs: store
            .current()
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
            approval_id,
            contract_digest: compiled_contract.seal.contract_digest.clone(),
            plan_digest: compiled_plan.plan_digest.clone(),
            permission_digest,
            expires_at_epoch_s,
            status: approval_status,
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
                status: StageStatus::Pending,
                before_digest: None,
                after_digest: None,
            })
            .collect(),
        validators: Vec::new(),
        evidence_bundle: None,
        replay_manifest: None,
        certificate: None,
        profession_capsules: vec![TrustComponentStatus {
            component_id: "ergaxiom.profession.graphic-designer".to_owned(),
            version: capsule_version.to_owned(),
            digest: compiled_contract.seal.capsule_digest.clone(),
            trusted: true,
        }],
        adapters: Vec::new(),
        trusted_keys: Vec::new(),
        metadata: json!({
            "control_status": control_status,
            "approval_digest": approval_digest,
            "job_kind": store.current().job_kind,
            "persistent_state_digest": store.current().state_digest,
        }),
    };
    build_desktop_shell_snapshot(material)
        .map_err(|error| format!("product DesktopShellSnapshot failed: {error}"))
}

fn initialize_runtime() -> Result<ProductJobRuntime, String> {
    let root = product_state_root()?;
    let mut jobs = BTreeMap::new();
    for job_id in list_job_ids(&root).map_err(|error| error.to_string())? {
        let store = UserJobStore::open(&root, &job_id).map_err(|error| {
            format!("persistent job {job_id} failed restart verification: {error}")
        })?;
        jobs.insert(job_id, store);
    }
    Ok(ProductJobRuntime { root, jobs })
}

fn product_view(store: &UserJobStore) -> Result<ProductJobView, String> {
    Ok(ProductJobView {
        record: store.current().clone(),
        history: store.history().map_err(|error| error.to_string())?,
        required_input_roles: store
            .current()
            .job_kind
            .required_input_roles()
            .iter()
            .map(|role| (*role).to_owned())
            .collect(),
    })
}

fn prepare_store(store: &mut UserJobStore, expected_state_digest: &str) -> Result<(), String> {
    if store.current().state_digest != expected_state_digest {
        return Err("stale product job snapshot".to_owned());
    }
    let capsule = profession_capsule()?;
    match store.current().job_kind {
        GraphicDesignerJobKind::StaticSocialPost => {
            prepare_static_social(store, expected_state_digest, &capsule)
        }
        GraphicDesignerJobKind::ImageBackgroundCleanup => {
            prepare_background_cleanup(store, expected_state_digest, &capsule)
        }
        GraphicDesignerJobKind::BrandCompliantImageExport => {
            prepare_brand_export(store, expected_state_digest, &capsule)
        }
        GraphicDesignerJobKind::PrintReadyPosterPreflight => {
            prepare_print_poster(store, expected_state_digest, &capsule)
        }
    }
}

fn prepare_static_social(
    store: &mut UserJobStore,
    expected_state_digest: &str,
    capsule: &Value,
) -> Result<(), String> {
    let mut intent: StaticSocialPostIntent = decode_intent_manifest(store)?;
    intent.original_text = Some(store.current().original_text.clone());
    intent.approved_logo = static_artifact(store, "approved_logo")?;
    intent.brand_profile = static_artifact(store, "brand_profile")?;
    intent.approved_copy = static_artifact(store, "approved_copy")?;
    let resolved_intent = serde_json::to_value(&intent).map_err(|error| error.to_string())?;
    let compile = compile_static_social_post_intent(&intent, capsule)
        .map_err(|error| format!("static social compiler rejected input: {error}"))?;
    let (contract, contract_digest) = match compile {
        IntentCompileOutcome::Compiled {
            contract,
            contract_digest,
            ..
        } => (contract, contract_digest),
        IntentCompileOutcome::NeedsResolution {
            resolution_requests,
            resolution_digest,
            ..
        } => {
            return store
                .record_unresolved(
                    expected_state_digest,
                    json!({"intent": resolved_intent, "resolution_requests": resolution_requests}),
                    format!("intent_resolution_required:{resolution_digest}"),
                )
                .map_err(|error| error.to_string());
        }
    };
    let created_at = intent
        .created_at
        .clone()
        .ok_or_else(|| "compiled intent lost created_at".to_owned())?;
    match synthesize_static_social_post_plan(
        &StaticSocialPostPlanIdentity {
            plan_id: Some(format!("plan.{}", store.current().job_id)),
            created_at: Some(created_at),
        },
        &contract,
        capsule,
    )
    .map_err(|error| format!("static social planner rejected contract: {error}"))?
    {
        TypedPlanOutcome::Planned {
            plan,
            plan_digest,
            capability_requirement_digest,
            ..
        } => store
            .record_compiled(
                expected_state_digest,
                CompiledJobMaterial {
                    resolved_intent,
                    work_contract: contract,
                    contract_digest,
                    operator_plan: plan,
                    plan_digest,
                    permission_digest: capability_requirement_digest,
                },
            )
            .map_err(|error| error.to_string()),
        TypedPlanOutcome::NeedsResolution {
            resolution_requests,
            resolution_digest,
            ..
        } => store
            .record_unresolved(
                expected_state_digest,
                json!({"intent": resolved_intent, "resolution_requests": resolution_requests}),
                format!("plan_resolution_required:{resolution_digest}"),
            )
            .map_err(|error| error.to_string()),
    }
}

fn prepare_background_cleanup(
    store: &mut UserJobStore,
    expected_state_digest: &str,
    capsule: &Value,
) -> Result<(), String> {
    let mut intent: BackgroundCleanupIntent = decode_intent_manifest(store)?;
    intent.original_text = Some(store.current().original_text.clone());
    intent.source_raster = cleanup_artifact(store, "source_raster")?;
    intent.approved_cleanup_mask = cleanup_artifact(store, "approved_cleanup_mask")?;
    let resolved_intent = serde_json::to_value(&intent).map_err(|error| error.to_string())?;
    let compile = compile_background_cleanup_intent(&intent, capsule)
        .map_err(|error| format!("background cleanup compiler rejected input: {error}"))?;
    let (contract, contract_digest) = match compile {
        BackgroundCleanupCompileOutcome::Compiled {
            contract,
            contract_digest,
            ..
        } => (contract, contract_digest),
        BackgroundCleanupCompileOutcome::NeedsResolution {
            resolution_requests,
            resolution_digest,
            ..
        } => {
            return store
                .record_unresolved(
                    expected_state_digest,
                    json!({"intent": resolved_intent, "resolution_requests": resolution_requests}),
                    format!("intent_resolution_required:{resolution_digest}"),
                )
                .map_err(|error| error.to_string());
        }
    };
    let created_at = intent
        .created_at
        .clone()
        .ok_or_else(|| "compiled intent lost created_at".to_owned())?;
    match synthesize_background_cleanup_plan(
        &BackgroundCleanupPlanIdentity {
            plan_id: Some(format!("plan.{}", store.current().job_id)),
            created_at: Some(created_at),
        },
        &contract,
        capsule,
    )
    .map_err(|error| format!("background cleanup planner rejected contract: {error}"))?
    {
        BackgroundCleanupPlanOutcome::Planned {
            plan,
            plan_digest,
            capability_requirement_digest,
            ..
        } => store
            .record_compiled(
                expected_state_digest,
                CompiledJobMaterial {
                    resolved_intent,
                    work_contract: contract,
                    contract_digest,
                    operator_plan: plan,
                    plan_digest,
                    permission_digest: capability_requirement_digest,
                },
            )
            .map_err(|error| error.to_string()),
        BackgroundCleanupPlanOutcome::NeedsResolution {
            resolution_requests,
            resolution_digest,
            ..
        } => store
            .record_unresolved(
                expected_state_digest,
                json!({"intent": resolved_intent, "resolution_requests": resolution_requests}),
                format!("plan_resolution_required:{resolution_digest}"),
            )
            .map_err(|error| error.to_string()),
    }
}

fn prepare_brand_export(
    store: &mut UserJobStore,
    expected_state_digest: &str,
    capsule: &Value,
) -> Result<(), String> {
    let mut intent: BrandExportIntent = decode_intent_manifest(store)?;
    intent.original_text = Some(store.current().original_text.clone());
    intent.source_svg = brand_artifact(store, "source_svg")?;
    intent.brand_manifest = brand_artifact(store, "brand_manifest")?;
    intent.approved_logo = brand_artifact(store, "approved_logo")?;
    let resolved_intent = serde_json::to_value(&intent).map_err(|error| error.to_string())?;
    let compile = compile_brand_export_intent(&intent, capsule)
        .map_err(|error| format!("brand export compiler rejected input: {error}"))?;
    let (contract, contract_digest) = match compile {
        BrandExportCompileOutcome::Compiled {
            contract,
            contract_digest,
            ..
        } => (contract, contract_digest),
        BrandExportCompileOutcome::NeedsResolution {
            resolution_requests,
            resolution_digest,
            ..
        } => {
            return store
                .record_unresolved(
                    expected_state_digest,
                    json!({"intent": resolved_intent, "resolution_requests": resolution_requests}),
                    format!("intent_resolution_required:{resolution_digest}"),
                )
                .map_err(|error| error.to_string());
        }
    };
    let created_at = intent
        .created_at
        .clone()
        .ok_or_else(|| "compiled intent lost created_at".to_owned())?;
    match synthesize_brand_export_plan(
        &BrandExportPlanIdentity {
            plan_id: Some(format!("plan.{}", store.current().job_id)),
            created_at: Some(created_at),
        },
        &contract,
        capsule,
    )
    .map_err(|error| format!("brand export planner rejected contract: {error}"))?
    {
        BrandExportPlanOutcome::Planned {
            plan,
            plan_digest,
            capability_requirement_digest,
            ..
        } => store
            .record_compiled(
                expected_state_digest,
                CompiledJobMaterial {
                    resolved_intent,
                    work_contract: contract,
                    contract_digest,
                    operator_plan: plan,
                    plan_digest,
                    permission_digest: capability_requirement_digest,
                },
            )
            .map_err(|error| error.to_string()),
        BrandExportPlanOutcome::NeedsResolution {
            resolution_requests,
            resolution_digest,
            ..
        } => store
            .record_unresolved(
                expected_state_digest,
                json!({"intent": resolved_intent, "resolution_requests": resolution_requests}),
                format!("plan_resolution_required:{resolution_digest}"),
            )
            .map_err(|error| error.to_string()),
    }
}

fn prepare_print_poster(
    store: &mut UserJobStore,
    expected_state_digest: &str,
    capsule: &Value,
) -> Result<(), String> {
    let mut intent: PrintPreflightIntent = decode_intent_manifest(store)?;
    intent.original_text = Some(store.current().original_text.clone());
    intent.source_svg = print_artifact(store, "source_svg")?;
    intent.print_specification = print_artifact(store, "print_specification")?;
    let resolved_intent = serde_json::to_value(&intent).map_err(|error| error.to_string())?;
    let compile = compile_print_preflight_intent(&intent, capsule)
        .map_err(|error| format!("print preflight compiler rejected input: {error}"))?;
    let (contract, contract_digest) = match compile {
        PrintPreflightCompileOutcome::Compiled {
            contract,
            contract_digest,
            ..
        } => (contract, contract_digest),
        PrintPreflightCompileOutcome::NeedsResolution {
            resolution_requests,
            resolution_digest,
            ..
        } => {
            return store
                .record_unresolved(
                    expected_state_digest,
                    json!({"intent": resolved_intent, "resolution_requests": resolution_requests}),
                    format!("intent_resolution_required:{resolution_digest}"),
                )
                .map_err(|error| error.to_string());
        }
    };
    let created_at = intent
        .created_at
        .clone()
        .ok_or_else(|| "compiled intent lost created_at".to_owned())?;
    match synthesize_print_preflight_plan(
        &PrintPreflightPlanIdentity {
            plan_id: Some(format!("plan.{}", store.current().job_id)),
            created_at: Some(created_at),
        },
        &contract,
        capsule,
    )
    .map_err(|error| format!("print preflight planner rejected contract: {error}"))?
    {
        PrintPreflightPlanOutcome::Planned {
            plan,
            plan_digest,
            capability_requirement_digest,
            ..
        } => store
            .record_compiled(
                expected_state_digest,
                CompiledJobMaterial {
                    resolved_intent,
                    work_contract: contract,
                    contract_digest,
                    operator_plan: plan,
                    plan_digest,
                    permission_digest: capability_requirement_digest,
                },
            )
            .map_err(|error| error.to_string()),
        PrintPreflightPlanOutcome::NeedsResolution {
            resolution_requests,
            resolution_digest,
            ..
        } => store
            .record_unresolved(
                expected_state_digest,
                json!({"intent": resolved_intent, "resolution_requests": resolution_requests}),
                format!("plan_resolution_required:{resolution_digest}"),
            )
            .map_err(|error| error.to_string()),
    }
}

fn decode_intent_manifest<T>(store: &UserJobStore) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = store
        .input_bytes("intent_manifest")
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("intent manifest decode failed: {error}"))
}

fn immutable_input<'a>(store: &'a UserJobStore, role: &str) -> Result<&'a ImmutableInput, String> {
    store
        .current()
        .inputs
        .get(role)
        .ok_or_else(|| format!("required immutable input is missing: {role}"))
}

fn immutable_uri(input: &ImmutableInput) -> String {
    format!("ergaxiom-immutable://sha256/{}", input.sha256)
}

fn static_artifact(store: &UserJobStore, role: &str) -> Result<InputArtifactIntent, String> {
    let input = immutable_input(store, role)?;
    Ok(InputArtifactIntent {
        uri: Some(immutable_uri(input)),
        media_type: Some(input.media_type.clone()),
        sha256: Some(input.sha256.clone()),
    })
}

fn cleanup_artifact(store: &UserJobStore, role: &str) -> Result<CleanupArtifactIntent, String> {
    let input = immutable_input(store, role)?;
    Ok(CleanupArtifactIntent {
        uri: Some(immutable_uri(input)),
        media_type: Some(input.media_type.clone()),
        sha256: Some(input.sha256.clone()),
    })
}

fn brand_artifact(store: &UserJobStore, role: &str) -> Result<BrandArtifactIntent, String> {
    let input = immutable_input(store, role)?;
    Ok(BrandArtifactIntent {
        uri: Some(immutable_uri(input)),
        media_type: Some(input.media_type.clone()),
        sha256: Some(input.sha256.clone()),
    })
}

fn print_artifact(store: &UserJobStore, role: &str) -> Result<PrintArtifactIntent, String> {
    let input = immutable_input(store, role)?;
    Ok(PrintArtifactIntent {
        uri: Some(immutable_uri(input)),
        media_type: Some(input.media_type.clone()),
        sha256: Some(input.sha256.clone()),
    })
}

fn profession_capsule() -> Result<Value, String> {
    serde_json::from_str(include_str!(
        "../../../../professions/graphic-designer/profession.json"
    ))
    .map_err(|error| format!("profession capsule decode failed: {error}"))
}

fn product_state_root() -> Result<PathBuf, String> {
    if let Some(path) = option_env!("ERGAXIOM_PRODUCT_ALPHA_STATE_ROOT") {
        let root = PathBuf::from(path);
        if !root.is_absolute() {
            return Err("ERGAXIOM_PRODUCT_ALPHA_STATE_ROOT must be absolute".to_owned());
        }
        return Ok(root);
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| "LOCALAPPDATA is unavailable for Product Alpha state".to_owned())?;
        if !base.is_absolute() {
            return Err("LOCALAPPDATA resolved to a non-absolute path".to_owned());
        }
        return Ok(base.join("Ergaxiom").join("ProductAlpha"));
    }
    #[cfg(not(windows))]
    {
        Ok(std::env::temp_dir().join(format!(
            "ergaxiom-product-alpha-{}",
            std::process::id()
        )))
    }
}

fn production_stage_name(stage: ProductionExecutionStage) -> &'static str {
    match stage {
        ProductionExecutionStage::Initial => "initial",
        ProductionExecutionStage::Approved => "approved",
        ProductionExecutionStage::CapabilitiesIssued => "capabilities_issued",
        ProductionExecutionStage::CapabilitiesConsumed => "capabilities_consumed",
        ProductionExecutionStage::Executed => "executed",
        ProductionExecutionStage::Certified => "certified",
        ProductionExecutionStage::Cancelled => "cancelled",
        ProductionExecutionStage::RolledBack => "rolled_back",
    }
}

fn boundary_error(error: ProductionExecutionBoundaryError) -> String {
    format!("{}: {error}", error.public_code())
}

fn current_epoch_s() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before UNIX epoch".to_owned())
}
