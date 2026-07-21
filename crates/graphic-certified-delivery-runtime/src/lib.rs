#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use ergaxiom_attestation_runtime::{
    AttestationIssueError, AttestationKeyRegistry, AttestationPackage, AttestationVerifyError,
    VerifiedAttestation, issue_attestation, verify_attestation_against_bundle,
};
use ergaxiom_capability_runtime::{CapabilityAuthorizer, CapabilityError};
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
use ergaxiom_occupational_twin_runtime::TwinWorkspace;
use ergaxiom_operator_plan_runtime::{CompiledPlan, TraceEvent, TraceStatus};
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, HashingError, ObligationState, canonical_json_sha256,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const EVIDENCE_BUNDLE_SCHEMA: &str = "0.4.0";
const AUTHORIZED_TRACE_SCHEMA: &str = "0.1.0";

pub struct GraphicCertificationRequest<'a> {
    pub workspace: &'a mut TwinWorkspace,
    pub authorizer: &'a mut CapabilityAuthorizer,
    pub compiled_contract: &'a CompiledContract,
    pub contract_value: &'a Value,
    pub compiled_plan: &'a CompiledPlan,
    pub job: &'a GraphicDesignJob,
    pub signed_capability_tokens: &'a [Value],
    pub trusted_now_epoch_s: u64,
    pub executor_id: &'a str,
    pub device_id: Option<&'a str>,
    pub assurance_level: AssuranceLevel,
    pub bundle_id: &'a str,
    pub run_id: &'a str,
    pub trace_id: &'a str,
    pub manifest_id: &'a str,
    pub certificate_id: &'a str,
    pub attestation_issuer_id: &'a str,
    pub attestation_key_id: &'a str,
    pub certificate_issued_at_epoch_s: u64,
    pub attestation_signing_key: &'a SigningKey,
}

#[derive(Debug)]
pub struct CertifiedGraphicDelivery {
    pub twin_run: GraphicDesignTwinRun,
    pub evidence_bundle: EvidenceBundle,
    pub evidence_bundle_digest: String,
    pub attestation: AttestationPackage,
    pub verified_attestation: VerifiedAttestation,
}

#[derive(Debug, Error)]
pub enum GraphicCertificationError {
    #[error("required certification field is empty: {0}")]
    EmptyField(&'static str),
    #[error("one signed capability token is required for every plan step")]
    CapabilityTokenCountMismatch,
    #[error("multiple authorization receipts were produced for step {0}")]
    DuplicateStepReceipt(String),
    #[error("authorization receipt is missing for step {0}")]
    MissingStepReceipt(String),
    #[error("functional-twin step {0} did not succeed")]
    TwinStepDidNotSucceed(String),
    #[error("functional-twin proof decision is {0:?}, so delivery cannot be certified")]
    ProofDecisionNotAccepted(DecisionStatus),
    #[error("authorized execution trace did not conform")]
    AuthorizedTraceNonConformance,
    #[error("evidence bundle decision is {0:?}, so delivery cannot be certified")]
    EvidenceDecisionNotAccepted(DecisionStatus),
    #[error("validation observation is missing for evidence {0}")]
    MissingValidationObservation(String),
    #[error("proof requirement is missing for obligation {0}")]
    MissingProofRequirement(String),
    #[error("failed to serialize certified delivery material: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Capability(#[from] CapabilityError),
    #[error(transparent)]
    Contract(#[from] ContractRuntimeError),
    #[error(transparent)]
    GraphicTwin(#[from] GraphicTwinError),
    #[error(transparent)]
    Evidence(#[from] EvidenceBundleError),
    #[error(transparent)]
    AttestationIssue(#[from] AttestationIssueError),
    #[error(transparent)]
    AttestationVerify(#[from] AttestationVerifyError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn certify_graphic_delivery(
    mut request: GraphicCertificationRequest<'_>,
) -> Result<CertifiedGraphicDelivery, GraphicCertificationError> {
    validate_request(&request)?;
    if request.signed_capability_tokens.len() != request.compiled_plan.steps.len() {
        return Err(GraphicCertificationError::CapabilityTokenCountMismatch);
    }

    let receipt_records = authorize_plan_steps(&mut request)?;
    let twin_run = execute_graphic_design_twin(
        request.workspace,
        request.compiled_contract,
        request.contract_value,
        request.compiled_plan,
        request.job,
    )?;
    for step in &twin_run.simulation.steps {
        if step.status != ergaxiom_operator_simulation_runtime::SimulatedStepStatus::Succeeded {
            return Err(GraphicCertificationError::TwinStepDidNotSucceed(
                step.step_id.clone(),
            ));
        }
    }

    let (decision, mandatory_passed, mandatory_failed, mandatory_unknown) =
        independently_evaluate_proofs(
            request.compiled_contract,
            request.assurance_level,
            &twin_run,
        )?;
    if decision != DecisionStatus::Accepted {
        return Err(GraphicCertificationError::ProofDecisionNotAccepted(
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
            GraphicCertificationError::Evidence(EvidenceBundleError::ClaimedDecisionMismatch(
                error.to_string(),
            ))
        })?;
    if !trace_assessment.conforms_to_authorized_plan || !trace_assessment.claim_matches {
        return Err(GraphicCertificationError::AuthorizedTraceNonConformance);
    }

    let evidence_bundle = build_evidence_bundle(
        &request,
        &twin_run,
        authorized_trace,
        mandatory_passed,
        mandatory_failed,
        mandatory_unknown,
    )?;
    let bundle_value =
        serde_json::to_value(&evidence_bundle).map_err(GraphicCertificationError::Serialization)?;
    let assessment = assess_bundle(
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
    )?;
    if assessment.decision.status != DecisionStatus::Accepted {
        return Err(GraphicCertificationError::EvidenceDecisionNotAccepted(
            assessment.decision.status,
        ));
    }

    let attestation = issue_attestation(
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
        request.manifest_id,
        request.certificate_id,
        request.attestation_issuer_id,
        request.attestation_key_id,
        request.certificate_issued_at_epoch_s,
        request.attestation_signing_key,
    )?;
    let mut attestation_keys = AttestationKeyRegistry::default();
    attestation_keys.insert_ed25519(
        request.attestation_issuer_id,
        request.attestation_key_id,
        request.attestation_signing_key.verifying_key().to_bytes(),
    )?;
    let verified_attestation = verify_attestation_against_bundle(
        &attestation,
        &attestation_keys,
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
    )?;

    Ok(CertifiedGraphicDelivery {
        twin_run,
        evidence_bundle,
        evidence_bundle_digest: assessment.bundle_digest,
        attestation,
        verified_attestation,
    })
}

fn validate_request(
    request: &GraphicCertificationRequest<'_>,
) -> Result<(), GraphicCertificationError> {
    for (field, value) in [
        ("executor_id", request.executor_id),
        ("bundle_id", request.bundle_id),
        ("run_id", request.run_id),
        ("trace_id", request.trace_id),
        ("manifest_id", request.manifest_id),
        ("certificate_id", request.certificate_id),
        ("attestation_issuer_id", request.attestation_issuer_id),
        ("attestation_key_id", request.attestation_key_id),
    ] {
        if value.trim().is_empty() {
            return Err(GraphicCertificationError::EmptyField(field));
        }
    }
    Ok(())
}

fn authorize_plan_steps(
    request: &mut GraphicCertificationRequest<'_>,
) -> Result<Vec<AuthorizationReceiptRecord>, GraphicCertificationError> {
    let mut receipts_by_step = BTreeMap::new();
    for token in request.signed_capability_tokens {
        let receipt = request.authorizer.authorize(
            token,
            request.compiled_contract,
            request.compiled_plan,
            request.trusted_now_epoch_s,
            request.executor_id,
            request.device_id,
        )?;
        let step_id = receipt.step_id.clone();
        let receipt_value =
            serde_json::to_value(&receipt).map_err(GraphicCertificationError::Serialization)?;
        let record = AuthorizationReceiptRecord {
            receipt_digest: canonical_json_sha256(&receipt_value)?,
            receipt,
        };
        if receipts_by_step.insert(step_id.clone(), record).is_some() {
            return Err(GraphicCertificationError::DuplicateStepReceipt(step_id));
        }
    }

    request
        .compiled_plan
        .steps
        .iter()
        .map(|step| {
            receipts_by_step
                .remove(&step.step_id)
                .ok_or_else(|| GraphicCertificationError::MissingStepReceipt(step.step_id.clone()))
        })
        .collect()
}

fn independently_evaluate_proofs(
    compiled_contract: &CompiledContract,
    assurance_level: AssuranceLevel,
    twin_run: &GraphicDesignTwinRun,
) -> Result<(DecisionStatus, usize, usize, usize), GraphicCertificationError> {
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
) -> Result<AuthorizedExecutionTrace, GraphicCertificationError> {
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
        let receipt = receipt_by_step
            .get(step.step_id.as_str())
            .ok_or_else(|| GraphicCertificationError::MissingStepReceipt(step.step_id.clone()))?;
        let report = report_by_step.get(step.step_id.as_str()).ok_or_else(|| {
            GraphicCertificationError::TwinStepDidNotSucceed(step.step_id.clone())
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
    request: &GraphicCertificationRequest<'_>,
    twin_run: &GraphicDesignTwinRun,
    trace: AuthorizedExecutionTrace,
    mandatory_passed: usize,
    mandatory_failed: usize,
    mandatory_unknown: usize,
) -> Result<EvidenceBundle, GraphicCertificationError> {
    let editable_master =
        serde_json::to_vec(&twin_run.document).map_err(GraphicCertificationError::Serialization)?;
    let brand_profile = serde_json::to_vec(&request.job.brand_profile)
        .map_err(GraphicCertificationError::Serialization)?;
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
                GraphicCertificationError::MissingValidationObservation(
                    evidence.evidence_id.clone(),
                )
            })?;
        let requirement = requirements
            .get(evidence.obligation_id.as_str())
            .ok_or_else(|| {
                GraphicCertificationError::MissingProofRequirement(evidence.obligation_id.clone())
            })?;
        let evidence_artifact_id = format!("artifact.{}", evidence.evidence_id);
        let observation_bytes =
            serde_json::to_vec(observation).map_err(GraphicCertificationError::Serialization)?;
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
        return Err(GraphicCertificationError::MissingValidationObservation(
            "duplicate evidence artifact identifier".to_owned(),
        ));
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
            reason: "Authorized functional-twin execution and all mandatory proofs passed."
                .to_owned(),
            sealed_at: None,
            signature: None,
        },
    })
}

fn proof_result(
    request: &GraphicCertificationRequest<'_>,
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
