#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use ergaxiom_capability_runtime::AuthorizationReceipt;
use ergaxiom_contract_runtime::{CompiledContract, ContractRuntimeError, ContractSession};
use ergaxiom_evidence_runtime::{
    ApplicationEvidence, ArtifactEvidence, ArtifactRole, BundleBindings, ClaimedDecision,
    DigestAlgorithm, DigestReference, EnvironmentEvidence, EvidenceBundle, EvidenceBundleError,
    ProofResult, ProofResultStatus, assess_bundle,
};
use ergaxiom_execution_runtime::{
    AuthorizationReceiptRecord, AuthorizedExecutionTrace, ReceiptBoundTraceEvent,
    verify_authorized_trace,
};
use ergaxiom_graphic_designer_twin_runtime::{
    GraphicDesignJob, GraphicDesignTwinRun, GraphicTwinError, ValidatorObservation,
    execute_graphic_design_twin,
};
use ergaxiom_occupational_twin_runtime::{OperationOutcome, OperationReceipt, TwinWorkspace};
use ergaxiom_operator_plan_runtime::{CompiledPlan, TraceEvent, TraceStatus};
use ergaxiom_operator_simulation_runtime::SimulatedStepStatus;
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, HashingError, ObligationState, canonical_json_sha256,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const EVIDENCE_BUNDLE_SCHEMA: &str = "0.4.0";
const AUTHORIZED_TRACE_SCHEMA: &str = "0.1.0";

pub struct ProductionGraphicEvidenceRequest<'a> {
    pub workspace: &'a mut TwinWorkspace,
    pub compiled_contract: &'a CompiledContract,
    pub contract_value: &'a Value,
    pub compiled_plan: &'a CompiledPlan,
    pub job: &'a GraphicDesignJob,
    pub authorization_receipts: &'a [AuthorizationReceipt],
    pub assurance_level: AssuranceLevel,
    pub bundle_id: &'a str,
    pub run_id: &'a str,
    pub trace_id: &'a str,
}

#[derive(Debug)]
pub struct ProductionGraphicEvidence {
    pub twin_run: GraphicDesignTwinRun,
    pub operation_receipts: Vec<OperationReceipt>,
    pub evidence_bundle: EvidenceBundle,
    pub evidence_bundle_digest: String,
}

#[derive(Debug, Error)]
pub enum ProductionGraphicEvidenceError {
    #[error("required production evidence field is empty: {0}")]
    EmptyField(&'static str),
    #[error("one durably consumed production Capability receipt is required for every plan step")]
    CapabilityReceiptCountMismatch,
    #[error("duplicate production Capability receipt for step {0}")]
    DuplicateStepReceipt(String),
    #[error("production Capability receipt is missing for step {0}")]
    MissingStepReceipt(String),
    #[error("production Capability receipt binding is invalid for step {0}")]
    InvalidStepReceipt(String),
    #[error("functional Twin step {0} did not succeed")]
    TwinStepDidNotSucceed(String),
    #[error("functional Twin step {0} is missing its immutable operation receipt")]
    MissingOperationReceipt(String),
    #[error("functional Twin proof decision is {0:?}")]
    ProofDecisionNotAccepted(DecisionStatus),
    #[error("authorized execution trace did not conform")]
    AuthorizedTraceNonConformance,
    #[error("Evidence Bundle decision is {0:?}")]
    EvidenceDecisionNotAccepted(DecisionStatus),
    #[error("validation observation is missing for evidence {0}")]
    MissingValidationObservation(String),
    #[error("proof requirement is missing for obligation {0}")]
    MissingProofRequirement(String),
    #[error("failed to serialize production evidence material: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Contract(#[from] ContractRuntimeError),
    #[error(transparent)]
    GraphicTwin(#[from] GraphicTwinError),
    #[error(transparent)]
    Evidence(#[from] EvidenceBundleError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn build_production_graphic_evidence(
    request: ProductionGraphicEvidenceRequest<'_>,
) -> Result<ProductionGraphicEvidence, ProductionGraphicEvidenceError> {
    validate_request(&request)?;
    let receipt_records = validate_and_index_receipts(&request)?;

    // This is the only point at which the Occupational Twin is invoked. The caller must already
    // have durably consumed every production Capability and supplied the resulting receipts.
    let twin_run = execute_graphic_design_twin(
        request.workspace,
        request.compiled_contract,
        request.contract_value,
        request.compiled_plan,
        request.job,
    )?;
    let operation_receipts = collect_operation_receipts(request.compiled_plan, &twin_run)?;

    let (decision, mandatory_passed, mandatory_failed, mandatory_unknown) =
        independently_evaluate_proofs(
            request.compiled_contract,
            request.assurance_level,
            &twin_run,
        )?;
    if decision != DecisionStatus::Accepted || mandatory_failed != 0 || mandatory_unknown != 0 {
        return Err(ProductionGraphicEvidenceError::ProofDecisionNotAccepted(
            decision,
        ));
    }

    let authorized_trace = build_authorized_trace(
        request.compiled_plan,
        &twin_run,
        receipt_records,
        request.trace_id,
        &request.job.evaluated_at,
    )?;
    let trace_assessment = verify_authorized_trace(request.compiled_plan, &authorized_trace)
        .map_err(|error| {
            ProductionGraphicEvidenceError::Evidence(EvidenceBundleError::ClaimedDecisionMismatch(
                error.to_string(),
            ))
        })?;
    if !trace_assessment.conforms_to_authorized_plan || !trace_assessment.claim_matches {
        return Err(ProductionGraphicEvidenceError::AuthorizedTraceNonConformance);
    }

    let evidence_bundle = build_evidence_bundle(
        &request,
        &twin_run,
        authorized_trace,
        mandatory_passed,
        mandatory_failed,
        mandatory_unknown,
    )?;
    let bundle_value = serde_json::to_value(&evidence_bundle)
        .map_err(ProductionGraphicEvidenceError::Serialization)?;
    let assessment = assess_bundle(
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
    )?;
    if assessment.decision.status != DecisionStatus::Accepted
        || assessment.mandatory_failed != 0
        || assessment.mandatory_unknown != 0
    {
        return Err(ProductionGraphicEvidenceError::EvidenceDecisionNotAccepted(
            assessment.decision.status,
        ));
    }

    Ok(ProductionGraphicEvidence {
        twin_run,
        operation_receipts,
        evidence_bundle,
        evidence_bundle_digest: assessment.bundle_digest,
    })
}

fn validate_request(
    request: &ProductionGraphicEvidenceRequest<'_>,
) -> Result<(), ProductionGraphicEvidenceError> {
    for (field, value) in [
        ("bundle_id", request.bundle_id),
        ("run_id", request.run_id),
        ("trace_id", request.trace_id),
    ] {
        if value.trim().is_empty() {
            return Err(ProductionGraphicEvidenceError::EmptyField(field));
        }
    }
    if request.authorization_receipts.len() != request.compiled_plan.steps.len() {
        return Err(ProductionGraphicEvidenceError::CapabilityReceiptCountMismatch);
    }
    Ok(())
}

fn validate_and_index_receipts(
    request: &ProductionGraphicEvidenceRequest<'_>,
) -> Result<Vec<AuthorizationReceiptRecord>, ProductionGraphicEvidenceError> {
    let mut by_step = BTreeMap::new();
    for receipt in request.authorization_receipts {
        let step = request
            .compiled_plan
            .steps
            .iter()
            .find(|step| step.step_id == receipt.step_id)
            .ok_or_else(|| {
                ProductionGraphicEvidenceError::InvalidStepReceipt(receipt.step_id.clone())
            })?;
        if receipt.contract_digest != request.compiled_contract.seal.contract_digest
            || receipt.capsule_digest != request.compiled_contract.seal.capsule_digest
            || receipt.plan_id != request.compiled_plan.plan_id
            || receipt.plan_digest != request.compiled_plan.plan_digest
            || receipt.operator_id != step.operator_id
            || !step.capability_token_ids.contains(&receipt.token_id)
            || receipt.use_number != 1
            || receipt.max_uses != 1
        {
            return Err(ProductionGraphicEvidenceError::InvalidStepReceipt(
                step.step_id.clone(),
            ));
        }
        let value =
            serde_json::to_value(receipt).map_err(ProductionGraphicEvidenceError::Serialization)?;
        let record = AuthorizationReceiptRecord {
            receipt_digest: canonical_json_sha256(&value)?,
            receipt: receipt.clone(),
        };
        if by_step.insert(step.step_id.clone(), record).is_some() {
            return Err(ProductionGraphicEvidenceError::DuplicateStepReceipt(
                step.step_id.clone(),
            ));
        }
    }

    request
        .compiled_plan
        .steps
        .iter()
        .map(|step| {
            by_step.remove(&step.step_id).ok_or_else(|| {
                ProductionGraphicEvidenceError::MissingStepReceipt(step.step_id.clone())
            })
        })
        .collect()
}

fn collect_operation_receipts(
    compiled_plan: &CompiledPlan,
    twin_run: &GraphicDesignTwinRun,
) -> Result<Vec<OperationReceipt>, ProductionGraphicEvidenceError> {
    let reports: BTreeMap<_, _> = twin_run
        .simulation
        .steps
        .iter()
        .map(|report| (report.step_id.as_str(), report))
        .collect();
    compiled_plan
        .steps
        .iter()
        .map(|step| {
            let report = reports.get(step.step_id.as_str()).ok_or_else(|| {
                ProductionGraphicEvidenceError::TwinStepDidNotSucceed(step.step_id.clone())
            })?;
            if report.status != SimulatedStepStatus::Succeeded {
                return Err(ProductionGraphicEvidenceError::TwinStepDidNotSucceed(
                    step.step_id.clone(),
                ));
            }
            let receipt = report.receipt.clone().ok_or_else(|| {
                ProductionGraphicEvidenceError::MissingOperationReceipt(step.step_id.clone())
            })?;
            if receipt.outcome != OperationOutcome::Succeeded
                || receipt.operator_id != step.operator_id
                || receipt.before_snapshot_digest != report.before_snapshot_digest
                || receipt.after_snapshot_digest != report.after_snapshot_digest
                || !receipt.violations.is_empty()
            {
                return Err(ProductionGraphicEvidenceError::TwinStepDidNotSucceed(
                    step.step_id.clone(),
                ));
            }
            Ok(receipt)
        })
        .collect()
}

fn independently_evaluate_proofs(
    compiled_contract: &CompiledContract,
    assurance_level: AssuranceLevel,
    twin_run: &GraphicDesignTwinRun,
) -> Result<(DecisionStatus, usize, usize, usize), ProductionGraphicEvidenceError> {
    let mut session = ContractSession::new(compiled_contract.clone(), assurance_level)?;
    for evidence in twin_run.proof_evidence.iter().cloned() {
        session.ingest_evidence(evidence)?;
    }
    let decision = session.evaluate();
    let mut passed = 0_usize;
    let mut failed = 0_usize;
    let mut unknown = 0_usize;
    for report in decision
        .obligation_reports
        .iter()
        .filter(|report| report.mandatory)
    {
        match report.state {
            ObligationState::Satisfied => passed += 1,
            ObligationState::Failed | ObligationState::Invalidated => failed += 1,
            ObligationState::Pending | ObligationState::Indeterminate => unknown += 1,
        }
    }
    Ok((decision.status, passed, failed, unknown))
}

fn build_authorized_trace(
    compiled_plan: &CompiledPlan,
    twin_run: &GraphicDesignTwinRun,
    receipt_records: Vec<AuthorizationReceiptRecord>,
    trace_id: &str,
    timestamp: &str,
) -> Result<AuthorizedExecutionTrace, ProductionGraphicEvidenceError> {
    let receipt_by_step: BTreeMap<_, _> = receipt_records
        .iter()
        .map(|record| (record.receipt.step_id.as_str(), record))
        .collect();
    let report_by_step: BTreeMap<_, _> = twin_run
        .simulation
        .steps
        .iter()
        .map(|report| (report.step_id.as_str(), report))
        .collect();
    let mut events = Vec::with_capacity(compiled_plan.steps.len() * 2);
    for step in &compiled_plan.steps {
        let receipt = receipt_by_step.get(step.step_id.as_str()).ok_or_else(|| {
            ProductionGraphicEvidenceError::MissingStepReceipt(step.step_id.clone())
        })?;
        let report = report_by_step.get(step.step_id.as_str()).ok_or_else(|| {
            ProductionGraphicEvidenceError::TwinStepDidNotSucceed(step.step_id.clone())
        })?;
        let started_sequence = events.len();
        events.push(ReceiptBoundTraceEvent {
            event: TraceEvent {
                event_id: format!("event.{}.started", step.step_id),
                step_id: step.step_id.clone(),
                sequence: started_sequence,
                timestamp: timestamp.to_owned(),
                operator_id: step.operator_id.clone(),
                status: TraceStatus::Started,
                input_digests: vec![report.before_snapshot_digest.clone()],
                output_digests: Vec::new(),
                capability_token_id: Some(receipt.receipt.token_id.clone()),
            },
            authorization_receipt_digest: Some(receipt.receipt_digest.clone()),
        });
        let succeeded_sequence = events.len();
        events.push(ReceiptBoundTraceEvent {
            event: TraceEvent {
                event_id: format!("event.{}.succeeded", step.step_id),
                step_id: step.step_id.clone(),
                sequence: succeeded_sequence,
                timestamp: timestamp.to_owned(),
                operator_id: step.operator_id.clone(),
                status: TraceStatus::Succeeded,
                input_digests: vec![report.before_snapshot_digest.clone()],
                output_digests: vec![report.after_snapshot_digest.clone()],
                capability_token_id: Some(receipt.receipt.token_id.clone()),
            },
            authorization_receipt_digest: Some(receipt.receipt_digest.clone()),
        });
    }
    Ok(AuthorizedExecutionTrace {
        schema_version: AUTHORIZED_TRACE_SCHEMA.to_owned(),
        trace_id: trace_id.to_owned(),
        plan_id: compiled_plan.plan_id.clone(),
        plan_digest: compiled_plan.plan_digest.clone(),
        claimed_conforms_to_authorized_plan: true,
        authorization_receipts: receipt_records,
        events,
    })
}

fn build_evidence_bundle(
    request: &ProductionGraphicEvidenceRequest<'_>,
    twin_run: &GraphicDesignTwinRun,
    trace: AuthorizedExecutionTrace,
    mandatory_passed: usize,
    mandatory_failed: usize,
    mandatory_unknown: usize,
) -> Result<EvidenceBundle, ProductionGraphicEvidenceError> {
    let editable_master = serde_json::to_vec(&twin_run.document)
        .map_err(ProductionGraphicEvidenceError::Serialization)?;
    let brand_profile = serde_json::to_vec(&request.job.brand_profile)
        .map_err(ProductionGraphicEvidenceError::Serialization)?;
    let mut artifacts = vec![
        artifact(
            &request.job.approved_logo.artifact_id,
            ArtifactRole::Input,
            Some(&request.job.approved_logo.media_type),
            &request.job.approved_logo.content,
        ),
        artifact(
            &request.job.approved_copy.artifact_id,
            ArtifactRole::Input,
            Some(&request.job.approved_copy.media_type),
            request.job.approved_copy.text.as_bytes(),
        ),
        artifact(
            &request.job.brand_profile.artifact_id,
            ArtifactRole::Input,
            Some(&request.job.brand_profile.media_type),
            &brand_profile,
        ),
        artifact(
            &request.job.editable_master_id,
            ArtifactRole::Output,
            Some("application/x-ergaxiom-design-document"),
            &editable_master,
        ),
        artifact(
            &request.job.delivery_raster_id,
            ArtifactRole::Output,
            Some("image/png"),
            &twin_run.raster_png,
        ),
    ];

    let requirements: BTreeMap<_, _> = request
        .compiled_contract
        .proof_requirements
        .iter()
        .map(|requirement| (requirement.obligation_id.as_str(), requirement))
        .collect();
    let observations: BTreeMap<_, _> = twin_run
        .validation
        .observations
        .iter()
        .map(|observation| {
            (
                (
                    observation.validator_id.as_str(),
                    observation.claim_id.as_str(),
                ),
                observation,
            )
        })
        .collect();
    let mut proof_results = Vec::with_capacity(twin_run.proof_evidence.len());
    let mut evidence_artifact_ids = BTreeSet::new();
    for evidence in &twin_run.proof_evidence {
        let observation = observations
            .get(&(
                evidence.validator_id.as_str(),
                evidence.constraint_id.as_str(),
            ))
            .ok_or_else(|| {
                ProductionGraphicEvidenceError::MissingValidationObservation(
                    evidence.evidence_id.clone(),
                )
            })?;
        let requirement = requirements
            .get(evidence.obligation_id.as_str())
            .ok_or_else(|| {
                ProductionGraphicEvidenceError::MissingProofRequirement(
                    evidence.obligation_id.clone(),
                )
            })?;
        let evidence_artifact_id = format!("artifact.{}", evidence.evidence_id);
        let observation_bytes = serde_json::to_vec(observation)
            .map_err(ProductionGraphicEvidenceError::Serialization)?;
        artifacts.push(artifact(
            &evidence_artifact_id,
            ArtifactRole::Evidence,
            Some("application/json"),
            &observation_bytes,
        ));
        evidence_artifact_ids.insert(evidence_artifact_id.clone());
        proof_results.push(proof_result(
            request,
            evidence,
            observation,
            requirement.mandatory,
            evidence_artifact_id,
        ));
    }
    if evidence_artifact_ids.len() != proof_results.len() {
        return Err(
            ProductionGraphicEvidenceError::MissingValidationObservation(
                "duplicate evidence artifact identifier".to_owned(),
            ),
        );
    }

    let environment = request.workspace.environment();
    Ok(EvidenceBundle {
        schema_version: EVIDENCE_BUNDLE_SCHEMA.to_owned(),
        bundle_id: request.bundle_id.to_owned(),
        run_id: request.run_id.to_owned(),
        created_at: request.job.evaluated_at.clone(),
        bindings: BundleBindings {
            contract: digest_reference(
                &request.compiled_contract.contract_id,
                &request.compiled_contract.seal.contract_digest,
            ),
            profession_capsule: digest_reference(
                "ergaxiom.profession.graphic-designer",
                &request.compiled_contract.seal.capsule_digest,
            ),
            operator_plan: digest_reference(
                &request.compiled_plan.plan_id,
                &request.compiled_plan.plan_digest,
            ),
            policy_snapshot: None,
        },
        environment: EnvironmentEvidence {
            os: environment.os.clone(),
            kernel_version: format!("{}/{}", environment.runtime_id, environment.runtime_version),
            applications: environment
                .applications
                .iter()
                .map(|application| ApplicationEvidence {
                    id: application.application_id.clone(),
                    version: application.version.clone(),
                    digest: application.digest.clone(),
                })
                .collect(),
            clock_source: environment.clock_source.clone(),
            sandbox_id: Some(environment.sandbox_id.clone()),
        },
        artifacts,
        trace,
        proof_results,
        claimed_decision: ClaimedDecision {
            status: DecisionStatus::Accepted,
            assurance_level: request.assurance_level,
            mandatory_passed,
            mandatory_failed,
            mandatory_unknown,
            reason: "Production-authorized Twin execution and all mandatory proofs passed."
                .to_owned(),
            sealed_at: None,
            signature: None,
        },
    })
}

fn proof_result(
    request: &ProductionGraphicEvidenceRequest<'_>,
    evidence: &ergaxiom_proof_kernel::EvidenceRecord,
    observation: &ValidatorObservation,
    mandatory: bool,
    evidence_artifact_id: String,
) -> ProofResult {
    let subject_artifact_id = if evidence.validator_id.starts_with("document.") {
        request.job.editable_master_id.clone()
    } else {
        request.job.delivery_raster_id.clone()
    };
    ProofResult {
        evidence_id: evidence.evidence_id.clone(),
        obligation_id: evidence.obligation_id.clone(),
        claim_id: evidence.constraint_id.clone(),
        subject_artifact_id,
        validator_id: evidence.validator_id.clone(),
        validator_version: evidence.validator_version.clone(),
        independence_class: evidence.independence,
        status: match evidence.result {
            ergaxiom_proof_kernel::TruthValue::True => ProofResultStatus::Passed,
            ergaxiom_proof_kernel::TruthValue::False => ProofResultStatus::Failed,
            ergaxiom_proof_kernel::TruthValue::Unknown => ProofResultStatus::Unknown,
        },
        mandatory,
        observed: observation.observed.clone(),
        expected: Some(observation.expected.clone()),
        unit: None,
        tolerance: None,
        evidence_artifact_ids: vec![evidence_artifact_id],
        evaluated_at: evidence.observed_at.clone(),
    }
}

fn artifact(
    artifact_id: &str,
    role: ArtifactRole,
    media_type: Option<&str>,
    bytes: &[u8],
) -> ArtifactEvidence {
    ArtifactEvidence {
        artifact_id: artifact_id.to_owned(),
        role,
        uri: format!("bundle://artifacts/{artifact_id}"),
        media_type: media_type.map(str::to_owned),
        algorithm: DigestAlgorithm::Sha256,
        digest: sha256_hex(bytes),
        size_bytes: bytes.len() as u64,
    }
}

fn digest_reference(id: &str, digest: &str) -> DigestReference {
    DigestReference {
        id: id.to_owned(),
        algorithm: DigestAlgorithm::Sha256,
        digest: digest.to_owned(),
        uri: None,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
