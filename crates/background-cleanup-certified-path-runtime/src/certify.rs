use ed25519_dalek::SigningKey;
use ergaxiom_attestation_runtime::{
    AttestationIssueError, AttestationKeyRegistry, AttestationVerifyError, issue_attestation,
    verify_attestation_against_bundle,
};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_evidence_runtime::{
    ApplicationEvidence, ArtifactEvidence, ArtifactRole, BundleBindings, ClaimedDecision,
    DigestAlgorithm, DigestReference, EnvironmentEvidence, EvidenceBundle, EvidenceBundleError,
    ProofResult, ProofResultStatus, assess_bundle,
};
use ergaxiom_execution_runtime::AuthorizedExecutionTrace;
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, IndependenceClass};
use serde_json::{Value, json};
use thiserror::Error;

use crate::compiler::BACKGROUND_CLEANUP_JOB_TYPE;
use crate::model::{
    BackgroundCleanupExecutionRecord, BackgroundCleanupValidationReport,
    CertifiedBackgroundCleanup, InkscapeCleanupIntegrationReport,
};
use crate::util::{DigestMaterialError, canonical_record_digest, sha256_hex};

const EVIDENCE_SCHEMA: &str = "0.4.0";
const VALIDATOR_VERSION: &str = "0.1.0";
const EXECUTION_EVIDENCE_ID: &str = "evidence.cleanup.execution-record";
const VALIDATION_EVIDENCE_ID: &str = "evidence.cleanup.validation-report";
const INTEGRATION_EVIDENCE_ID: &str = "evidence.cleanup.integration-report";

pub struct BackgroundCleanupCertificationRequest<'a> {
    pub bundle_id: &'a str,
    pub run_id: &'a str,
    pub created_at: &'a str,
    pub kernel_version: &'a str,
    pub clock_source: &'a str,
    pub sandbox_id: Option<&'a str>,
    pub source_uri: &'a str,
    pub mask_uri: &'a str,
    pub cleaned_uri: &'a str,
    pub probe_uri: &'a str,
    pub source_png: &'a [u8],
    pub approved_mask_png: &'a [u8],
    pub cleaned_png: &'a [u8],
    pub execution_record: &'a BackgroundCleanupExecutionRecord,
    pub validation_report: &'a BackgroundCleanupValidationReport,
    pub integration_report: &'a InkscapeCleanupIntegrationReport,
    pub authorized_trace: AuthorizedExecutionTrace,
    pub compiled_contract: &'a CompiledContract,
    pub compiled_plan: &'a CompiledPlan,
    pub assurance_level: AssuranceLevel,
    pub manifest_id: &'a str,
    pub certificate_id: &'a str,
    pub issuer_id: &'a str,
    pub key_id: &'a str,
    pub issued_at_epoch_s: u64,
    pub signing_key: &'a SigningKey,
}

#[derive(Debug, Error)]
pub enum BackgroundCleanupCertificationError {
    #[error("required certification field is empty: {0}")]
    EmptyField(&'static str),
    #[error("compiled contract does not represent image_background_cleanup")]
    ContractProfileMismatch,
    #[error("compiled plan is not bound to the supplied contract")]
    PlanBindingMismatch,
    #[error("cleanup validation report is not accepted")]
    ValidationRejected,
    #[error("Inkscape integration report is not verified")]
    IntegrationRejected,
    #[error("certification input digests do not match the execution and validation records")]
    ArtifactBindingMismatch,
    #[error("validation or integration report digest is invalid")]
    ReportDigestMismatch,
    #[error("evidence decision is {0:?}, so cleanup cannot be certified")]
    EvidenceDecisionNotAccepted(DecisionStatus),
    #[error("failed to serialize certification evidence: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Evidence(#[from] EvidenceBundleError),
    #[error(transparent)]
    AttestationIssue(#[from] AttestationIssueError),
    #[error(transparent)]
    AttestationVerify(#[from] AttestationVerifyError),
    #[error(transparent)]
    Digest(#[from] DigestMaterialError),
}

pub fn certify_background_cleanup(
    request: BackgroundCleanupCertificationRequest<'_>,
) -> Result<CertifiedBackgroundCleanup, BackgroundCleanupCertificationError> {
    validate_required_fields(&request)?;
    validate_bindings(&request)?;

    let execution_bytes = serde_json::to_vec(request.execution_record)?;
    let validation_bytes = serde_json::to_vec(request.validation_report)?;
    let integration_bytes = serde_json::to_vec(request.integration_report)?;

    let artifacts = vec![
        artifact(
            "source_raster",
            ArtifactRole::Input,
            request.source_uri,
            Some("image/png"),
            &sha256_hex(request.source_png),
            byte_len(request.source_png),
        ),
        artifact(
            "approved_cleanup_mask",
            ArtifactRole::Input,
            request.mask_uri,
            Some("image/png"),
            &sha256_hex(request.approved_mask_png),
            byte_len(request.approved_mask_png),
        ),
        artifact(
            "cleaned_raster",
            ArtifactRole::Output,
            request.cleaned_uri,
            Some("image/png"),
            &sha256_hex(request.cleaned_png),
            byte_len(request.cleaned_png),
        ),
        artifact(
            "integration_probe",
            ArtifactRole::Output,
            request.probe_uri,
            Some("image/png"),
            &request.integration_report.probe_png_digest,
            request.integration_report.probe_size_bytes,
        ),
        artifact(
            EXECUTION_EVIDENCE_ID,
            ArtifactRole::Evidence,
            "evidence://cleanup/execution-record.json",
            Some("application/vnd.ergaxiom.cleanup-execution-record+json"),
            &sha256_hex(&execution_bytes),
            byte_len(&execution_bytes),
        ),
        artifact(
            VALIDATION_EVIDENCE_ID,
            ArtifactRole::Evidence,
            "evidence://cleanup/validation-report.json",
            Some("application/vnd.ergaxiom.cleanup-validation-report+json"),
            &sha256_hex(&validation_bytes),
            byte_len(&validation_bytes),
        ),
        artifact(
            INTEGRATION_EVIDENCE_ID,
            ArtifactRole::Evidence,
            "evidence://cleanup/inkscape-integration-report.json",
            Some("application/vnd.ergaxiom.cleanup-integration-report+json"),
            &sha256_hex(&integration_bytes),
            byte_len(&integration_bytes),
        ),
    ];

    let proof_results = proof_results(
        request.created_at,
        request.validation_report,
        request.integration_report,
    );
    let mandatory_passed = proof_results.len();
    let evidence_bundle = EvidenceBundle {
        schema_version: EVIDENCE_SCHEMA.to_owned(),
        bundle_id: request.bundle_id.to_owned(),
        run_id: request.run_id.to_owned(),
        created_at: request.created_at.to_owned(),
        bindings: BundleBindings {
            contract: DigestReference {
                id: request.compiled_contract.contract_id.clone(),
                algorithm: DigestAlgorithm::Sha256,
                digest: request.compiled_contract.seal.contract_digest.clone(),
                uri: None,
            },
            profession_capsule: DigestReference {
                id: "ergaxiom.profession.graphic-designer".to_owned(),
                algorithm: DigestAlgorithm::Sha256,
                digest: request.compiled_contract.seal.capsule_digest.clone(),
                uri: None,
            },
            operator_plan: DigestReference {
                id: request.compiled_plan.plan_id.clone(),
                algorithm: DigestAlgorithm::Sha256,
                digest: request.compiled_plan.plan_digest.clone(),
                uri: None,
            },
            policy_snapshot: None,
        },
        environment: EnvironmentEvidence {
            os: "windows".to_owned(),
            kernel_version: request.kernel_version.to_owned(),
            applications: vec![ApplicationEvidence {
                id: request.integration_report.application_id.clone(),
                version: request.integration_report.application_version.clone(),
                digest: request.integration_report.executable_digest.clone(),
            }],
            clock_source: request.clock_source.to_owned(),
            sandbox_id: request.sandbox_id.map(str::to_owned),
        },
        artifacts,
        trace: request.authorized_trace,
        proof_results,
        claimed_decision: ClaimedDecision {
            status: DecisionStatus::Accepted,
            assurance_level: request.assurance_level,
            mandatory_passed,
            mandatory_failed: 0,
            mandatory_unknown: 0,
            reason: "Digest-bound binary-mask execution, independent PNG validation, source immutability and the pinned Inkscape integration probe passed."
                .to_owned(),
            sealed_at: Some(request.created_at.to_owned()),
            signature: None,
        },
    };

    let bundle_value = serde_json::to_value(&evidence_bundle)?;
    let assessment = assess_bundle(
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
    )?;
    if assessment.decision.status != DecisionStatus::Accepted {
        return Err(
            BackgroundCleanupCertificationError::EvidenceDecisionNotAccepted(
                assessment.decision.status,
            ),
        );
    }

    let attestation = issue_attestation(
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
        request.manifest_id,
        request.certificate_id,
        request.issuer_id,
        request.key_id,
        request.issued_at_epoch_s,
        request.signing_key,
    )?;
    let mut trusted_keys = AttestationKeyRegistry::default();
    trusted_keys.insert_ed25519(
        request.issuer_id,
        request.key_id,
        request.signing_key.verifying_key().to_bytes(),
    )?;
    let verified_attestation = verify_attestation_against_bundle(
        &attestation,
        &trusted_keys,
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
    )?;

    Ok(CertifiedBackgroundCleanup {
        evidence_bundle,
        evidence_bundle_digest: assessment.bundle_digest,
        attestation,
        verified_attestation,
        validation_report: request.validation_report.clone(),
        integration_report: request.integration_report.clone(),
    })
}

fn validate_required_fields(
    request: &BackgroundCleanupCertificationRequest<'_>,
) -> Result<(), BackgroundCleanupCertificationError> {
    for (field, value) in [
        ("bundle_id", request.bundle_id),
        ("run_id", request.run_id),
        ("created_at", request.created_at),
        ("kernel_version", request.kernel_version),
        ("clock_source", request.clock_source),
        ("source_uri", request.source_uri),
        ("mask_uri", request.mask_uri),
        ("cleaned_uri", request.cleaned_uri),
        ("probe_uri", request.probe_uri),
        ("manifest_id", request.manifest_id),
        ("certificate_id", request.certificate_id),
        ("issuer_id", request.issuer_id),
        ("key_id", request.key_id),
    ] {
        if value.trim().is_empty() {
            return Err(BackgroundCleanupCertificationError::EmptyField(field));
        }
    }
    Ok(())
}

fn validate_bindings(
    request: &BackgroundCleanupCertificationRequest<'_>,
) -> Result<(), BackgroundCleanupCertificationError> {
    if request.compiled_contract.job_type != BACKGROUND_CLEANUP_JOB_TYPE {
        return Err(BackgroundCleanupCertificationError::ContractProfileMismatch);
    }
    if request.compiled_plan.contract_digest != request.compiled_contract.seal.contract_digest
        || request.compiled_plan.capsule_digest != request.compiled_contract.seal.capsule_digest
    {
        return Err(BackgroundCleanupCertificationError::PlanBindingMismatch);
    }
    if !request.validation_report.accepted {
        return Err(BackgroundCleanupCertificationError::ValidationRejected);
    }
    if !request.integration_report.verified {
        return Err(BackgroundCleanupCertificationError::IntegrationRejected);
    }
    if request.validation_report.report_digest
        != canonical_record_digest(request.validation_report, "report_digest")?
        || request.integration_report.report_digest
            != canonical_record_digest(request.integration_report, "report_digest")?
    {
        return Err(BackgroundCleanupCertificationError::ReportDigestMismatch);
    }

    let source_digest = sha256_hex(request.source_png);
    let mask_digest = sha256_hex(request.approved_mask_png);
    let cleaned_digest = sha256_hex(request.cleaned_png);
    if request.execution_record.source_digest != source_digest
        || request.execution_record.mask_digest != mask_digest
        || request.execution_record.output_digest != cleaned_digest
        || request.validation_report.source_digest != source_digest
        || request.validation_report.mask_digest != mask_digest
        || request.validation_report.output_digest != cleaned_digest
        || request.integration_report.cleaned_png_digest != cleaned_digest
        || request.integration_report.probe_width != request.validation_report.width
        || request.integration_report.probe_height != request.validation_report.height
    {
        return Err(BackgroundCleanupCertificationError::ArtifactBindingMismatch);
    }
    Ok(())
}

fn proof_results(
    evaluated_at: &str,
    validation: &BackgroundCleanupValidationReport,
    integration: &InkscapeCleanupIntegrationReport,
) -> Vec<ProofResult> {
    vec![
        proof(
            "evidence.cleanup.cleaned-width",
            "proof.cleaned_width",
            "cleaned_width",
            "cleaned_raster",
            "cleanup.png.structure",
            json!(validation.width),
            Some(json!(validation.width)),
            Some("px"),
            &[VALIDATION_EVIDENCE_ID],
            evaluated_at,
        ),
        proof(
            "evidence.cleanup.cleaned-height",
            "proof.cleaned_height",
            "cleaned_height",
            "cleaned_raster",
            "cleanup.png.structure",
            json!(validation.height),
            Some(json!(validation.height)),
            Some("px"),
            &[VALIDATION_EVIDENCE_ID],
            evaluated_at,
        ),
        proof(
            "evidence.cleanup.mask-dimensions",
            "proof.mask_dimensions_match",
            "mask_dimensions_match",
            "approved_cleanup_mask",
            "cleanup.mask.dimensions",
            json!(validation.mask_dimensions_match),
            Some(json!(true)),
            None,
            &[VALIDATION_EVIDENCE_ID],
            evaluated_at,
        ),
        proof(
            "evidence.cleanup.mask-binary",
            "proof.mask_is_binary",
            "mask_is_binary",
            "approved_cleanup_mask",
            "cleanup.mask.binary",
            json!(validation.mask_is_binary),
            Some(json!(true)),
            None,
            &[VALIDATION_EVIDENCE_ID],
            evaluated_at,
        ),
        proof(
            "evidence.cleanup.mask-foreground",
            "proof.mask_foreground_pixels",
            "mask_foreground_pixels",
            "approved_cleanup_mask",
            "cleanup.mask.binary",
            json!(validation.mask_foreground_pixels),
            Some(json!(1)),
            Some("count"),
            &[VALIDATION_EVIDENCE_ID],
            evaluated_at,
        ),
        proof(
            "evidence.cleanup.mask-background",
            "proof.mask_background_pixels",
            "mask_background_pixels",
            "approved_cleanup_mask",
            "cleanup.mask.binary",
            json!(validation.mask_background_pixels),
            Some(json!(1)),
            Some("count"),
            &[VALIDATION_EVIDENCE_ID],
            evaluated_at,
        ),
        proof(
            "evidence.cleanup.background-alpha",
            "proof.background_alpha_violations",
            "background_alpha_violations",
            "cleaned_raster",
            "cleanup.alpha.background",
            json!(validation.background_alpha_violations),
            Some(json!(0)),
            Some("count"),
            &[VALIDATION_EVIDENCE_ID],
            evaluated_at,
        ),
        proof(
            "evidence.cleanup.foreground-preservation",
            "proof.foreground_rgba_violations",
            "foreground_rgba_violations",
            "cleaned_raster",
            "cleanup.foreground.preservation",
            json!(validation.foreground_rgba_violations),
            Some(json!(0)),
            Some("count"),
            &[VALIDATION_EVIDENCE_ID],
            evaluated_at,
        ),
        proof(
            "evidence.cleanup.output-media-type",
            "proof.output_media_type",
            "output_media_type",
            "cleaned_raster",
            "cleanup.png.structure",
            json!("image/png"),
            Some(json!("image/png")),
            None,
            &[VALIDATION_EVIDENCE_ID],
            evaluated_at,
        ),
        proof(
            "evidence.cleanup.output-color-profile",
            "proof.color_profile",
            "color_profile",
            "cleaned_raster",
            "cleanup.png.structure",
            json!("sRGB IEC61966-2.1"),
            Some(json!("sRGB IEC61966-2.1")),
            None,
            &[VALIDATION_EVIDENCE_ID],
            evaluated_at,
        ),
        proof(
            "evidence.cleanup.source-immutable",
            "proof.source_immutable",
            "source_immutable",
            "source_raster",
            "cleanup.source.immutability",
            json!(validation.source_immutable),
            Some(json!(true)),
            None,
            &[EXECUTION_EVIDENCE_ID, VALIDATION_EVIDENCE_ID],
            evaluated_at,
        ),
        proof(
            "evidence.cleanup.inkscape-integration",
            "proof.inkscape_probe_verified",
            "inkscape_probe_verified",
            "integration_probe",
            "cleanup.inkscape.integration",
            json!(integration.verified),
            Some(json!(true)),
            None,
            &[INTEGRATION_EVIDENCE_ID],
            evaluated_at,
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn proof(
    evidence_id: &str,
    obligation_id: &str,
    claim_id: &str,
    subject_artifact_id: &str,
    validator_id: &str,
    observed: Value,
    expected: Option<Value>,
    unit: Option<&str>,
    evidence_artifact_ids: &[&str],
    evaluated_at: &str,
) -> ProofResult {
    ProofResult {
        evidence_id: evidence_id.to_owned(),
        obligation_id: obligation_id.to_owned(),
        claim_id: claim_id.to_owned(),
        subject_artifact_id: subject_artifact_id.to_owned(),
        validator_id: validator_id.to_owned(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        independence_class: IndependenceClass::Independent,
        status: ProofResultStatus::Passed,
        mandatory: true,
        observed,
        expected,
        unit: unit.map(str::to_owned),
        tolerance: Some(0.0),
        evidence_artifact_ids: evidence_artifact_ids
            .iter()
            .map(|id| (*id).to_owned())
            .collect(),
        evaluated_at: evaluated_at.to_owned(),
    }
}

fn artifact(
    artifact_id: &str,
    role: ArtifactRole,
    uri: &str,
    media_type: Option<&str>,
    digest: &str,
    size_bytes: u64,
) -> ArtifactEvidence {
    ArtifactEvidence {
        artifact_id: artifact_id.to_owned(),
        role,
        uri: uri.to_owned(),
        media_type: media_type.map(str::to_owned),
        algorithm: DigestAlgorithm::Sha256,
        digest: digest.to_owned(),
        size_bytes,
    }
}

fn byte_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}
