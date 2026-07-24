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
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, IndependenceClass, canonical_json_bytes,
};
use serde_json::{Value, json};
use thiserror::Error;

use crate::compiler::PRINT_PREFLIGHT_JOB_TYPE;
use crate::model::{CertifiedPrintPreflight, PrintPreflightValidationReport, PrintSpecification};
use crate::runtime::{PrintPreflightRuntimeError, validate_print_preflight};
use crate::signing::{
    PrintEvidenceKeyRegistry, PrintEvidenceSignatureError, SignedPrintPreflightExecutionRecord,
    verify_print_preflight_execution_record,
};
use crate::util::{PrintDigestError, canonical_value_digest, sha256_hex};

const EVIDENCE_SCHEMA: &str = "0.4.0";
const VALIDATOR_VERSION: &str = "0.1.0";
const EXECUTION_EVIDENCE_ID: &str = "evidence.print.execution-record";
const VALIDATION_EVIDENCE_ID: &str = "evidence.print.validation-report";

pub struct PrintPreflightCertificationRequest<'a> {
    pub bundle_id: &'a str,
    pub run_id: &'a str,
    pub created_at: &'a str,
    pub operating_system: &'a str,
    pub kernel_version: &'a str,
    pub clock_source: &'a str,
    pub sandbox_id: Option<&'a str>,
    pub source_uri: &'a str,
    pub specification_uri: &'a str,
    pub editable_uri: &'a str,
    pub delivery_uri: &'a str,
    pub source_svg: &'a [u8],
    pub print_specification: &'a PrintSpecification,
    pub editable_svg: &'a [u8],
    pub raw_pdf: &'a [u8],
    pub delivery_pdf: &'a [u8],
    pub signed_execution: &'a SignedPrintPreflightExecutionRecord,
    pub validation_report: &'a PrintPreflightValidationReport,
    pub evidence_keys: &'a PrintEvidenceKeyRegistry,
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
pub enum PrintPreflightCertificationError {
    #[error("required certification field is empty: {0}")]
    EmptyField(&'static str),
    #[error("compiled contract is not print_ready_poster_preflight")]
    ContractProfileMismatch,
    #[error("compiled plan is not bound to the supplied contract")]
    PlanBindingMismatch,
    #[error("print preflight validation report is not accepted")]
    ValidationRejected,
    #[error("supplied validation report differs from independent recomputation")]
    ValidationReportMismatch,
    #[error("certification artefacts do not match the execution and validation records")]
    ArtifactBindingMismatch,
    #[error("evidence decision is {0:?}; print preflight cannot be certified")]
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
    Digest(#[from] PrintDigestError),
    #[error(transparent)]
    Runtime(#[from] PrintPreflightRuntimeError),
    #[error(transparent)]
    SignedEvidence(#[from] PrintEvidenceSignatureError),
    #[error(transparent)]
    Hashing(#[from] ergaxiom_proof_kernel::HashingError),
}

pub fn certify_print_preflight(
    request: PrintPreflightCertificationRequest<'_>,
) -> Result<CertifiedPrintPreflight, PrintPreflightCertificationError> {
    validate_required_fields(&request)?;
    verify_print_preflight_execution_record(request.signed_execution, request.evidence_keys)?;
    let execution_record = &request.signed_execution.record;
    let validation_report = validate_print_preflight(
        request.source_svg,
        request.print_specification,
        request.editable_svg,
        request.raw_pdf,
        request.delivery_pdf,
        execution_record,
    )?;
    if validation_report != *request.validation_report {
        return Err(PrintPreflightCertificationError::ValidationReportMismatch);
    }
    validate_bindings(&request, &validation_report)?;

    let specification_value = serde_json::to_value(request.print_specification)?;
    let specification_bytes = canonical_json_bytes(&specification_value)?;
    let execution_bytes = serde_json::to_vec(request.signed_execution)?;
    let validation_bytes = serde_json::to_vec(&validation_report)?;
    let artifacts = vec![
        artifact(
            "source_svg",
            ArtifactRole::Input,
            request.source_uri,
            Some("image/svg+xml"),
            &sha256_hex(request.source_svg),
            byte_len(request.source_svg),
        ),
        artifact(
            "print_specification",
            ArtifactRole::Input,
            request.specification_uri,
            Some("application/json"),
            &sha256_hex(&specification_bytes),
            byte_len(&specification_bytes),
        ),
        artifact(
            "editable_master",
            ArtifactRole::Output,
            request.editable_uri,
            Some("image/svg+xml"),
            &sha256_hex(request.editable_svg),
            byte_len(request.editable_svg),
        ),
        artifact(
            "raw_inkscape_pdf",
            ArtifactRole::Evidence,
            "evidence://print/raw-inkscape.pdf",
            Some("application/pdf"),
            &sha256_hex(request.raw_pdf),
            byte_len(request.raw_pdf),
        ),
        artifact(
            "delivery_pdf",
            ArtifactRole::Output,
            request.delivery_uri,
            Some("application/pdf"),
            &sha256_hex(request.delivery_pdf),
            byte_len(request.delivery_pdf),
        ),
        artifact(
            EXECUTION_EVIDENCE_ID,
            ArtifactRole::Evidence,
            "evidence://print/execution-record.json",
            Some("application/vnd.ergaxiom.signed-print-preflight-execution+json"),
            &sha256_hex(&execution_bytes),
            byte_len(&execution_bytes),
        ),
        artifact(
            VALIDATION_EVIDENCE_ID,
            ArtifactRole::Evidence,
            "evidence://print/validation-report.json",
            Some("application/vnd.ergaxiom.print-preflight-validation+json"),
            &sha256_hex(&validation_bytes),
            byte_len(&validation_bytes),
        ),
    ];
    let proof_results = proof_results(request.created_at, &validation_report);
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
            os: request.operating_system.to_owned(),
            kernel_version: request.kernel_version.to_owned(),
            applications: vec![ApplicationEvidence {
                id: execution_record.application_id.clone(),
                version: execution_record.application_version.clone(),
                digest: execution_record.executable_digest.clone(),
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
            reason: "The restricted vector SVG, print geometry, bleed, safe area, palette, PDF page boxes, vector-only resources, outlined fonts, approved color spaces, security boundary, source immutability and pinned Inkscape export all passed independent validation.".to_owned(),
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
            PrintPreflightCertificationError::EvidenceDecisionNotAccepted(
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
    Ok(CertifiedPrintPreflight {
        evidence_bundle,
        evidence_bundle_digest: assessment.bundle_digest,
        attestation,
        verified_attestation,
        validation_report,
    })
}

fn validate_required_fields(
    request: &PrintPreflightCertificationRequest<'_>,
) -> Result<(), PrintPreflightCertificationError> {
    for (field, value) in [
        ("bundle_id", request.bundle_id),
        ("run_id", request.run_id),
        ("created_at", request.created_at),
        ("operating_system", request.operating_system),
        ("kernel_version", request.kernel_version),
        ("clock_source", request.clock_source),
        ("source_uri", request.source_uri),
        ("specification_uri", request.specification_uri),
        ("editable_uri", request.editable_uri),
        ("delivery_uri", request.delivery_uri),
        ("manifest_id", request.manifest_id),
        ("certificate_id", request.certificate_id),
        ("issuer_id", request.issuer_id),
        ("key_id", request.key_id),
    ] {
        if value.trim().is_empty() {
            return Err(PrintPreflightCertificationError::EmptyField(field));
        }
    }
    Ok(())
}

fn validate_bindings(
    request: &PrintPreflightCertificationRequest<'_>,
    validation: &PrintPreflightValidationReport,
) -> Result<(), PrintPreflightCertificationError> {
    if request.compiled_contract.job_type != PRINT_PREFLIGHT_JOB_TYPE {
        return Err(PrintPreflightCertificationError::ContractProfileMismatch);
    }
    if request.compiled_plan.contract_digest != request.compiled_contract.seal.contract_digest
        || request.compiled_plan.capsule_digest != request.compiled_contract.seal.capsule_digest
    {
        return Err(PrintPreflightCertificationError::PlanBindingMismatch);
    }
    if !validation.accepted {
        return Err(PrintPreflightCertificationError::ValidationRejected);
    }
    let record = &request.signed_execution.record;
    if record.source_svg_digest != sha256_hex(request.source_svg)
        || record.specification_digest != canonical_value_digest(request.print_specification)?
        || record.editable_svg_digest != sha256_hex(request.editable_svg)
        || record.raw_pdf_digest != sha256_hex(request.raw_pdf)
        || record.normalized_pdf_digest != sha256_hex(request.delivery_pdf)
        || validation.source_svg_digest != record.source_svg_digest
        || validation.specification_digest != record.specification_digest
        || validation.editable_svg_digest != record.editable_svg_digest
        || validation.raw_pdf_digest != record.raw_pdf_digest
        || validation.delivery_pdf_digest != record.normalized_pdf_digest
    {
        return Err(PrintPreflightCertificationError::ArtifactBindingMismatch);
    }
    Ok(())
}

fn proof_results(evaluated_at: &str, report: &PrintPreflightValidationReport) -> Vec<ProofResult> {
    vec![
        proof(
            "restricted-svg",
            "restricted_svg_profile",
            "source_svg",
            "print.svg.structure",
            json!(report.restricted_svg_profile),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "canvas",
            "canvas_dimensions_match",
            "source_svg",
            "print.canvas.dimensions",
            json!(report.canvas_dimensions_match),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "bleed",
            "bleed_coverage",
            "source_svg",
            "print.bleed.coverage",
            json!(report.bleed_coverage),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "safe-area",
            "safe_area_satisfied",
            "source_svg",
            "print.safe_area.geometry",
            json!(report.safe_area_satisfied),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "palette",
            "palette_violations",
            "source_svg",
            "print.palette.allowlist",
            json!(report.palette_violation_count),
            json!(0),
            Some("count"),
            evaluated_at,
        ),
        proof(
            "vector",
            "vector_only",
            "delivery_pdf",
            "print.pdf.vector_only",
            json!(report.vector_only),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "fonts",
            "fonts_outlined",
            "delivery_pdf",
            "print.pdf.fonts_outlined",
            json!(report.fonts_outlined),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "pages",
            "page_count",
            "delivery_pdf",
            "print.pdf.page",
            json!(report.page_count),
            json!(1),
            Some("page"),
            evaluated_at,
        ),
        proof(
            "media-box",
            "media_box_match",
            "delivery_pdf",
            "print.pdf.boxes",
            json!(report.media_box_match),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "trim-box",
            "trim_box_match",
            "delivery_pdf",
            "print.pdf.boxes",
            json!(report.trim_box_match),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "bleed-box",
            "bleed_box_match",
            "delivery_pdf",
            "print.pdf.boxes",
            json!(report.bleed_box_match),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "crop-box",
            "crop_box_match",
            "delivery_pdf",
            "print.pdf.boxes",
            json!(report.crop_box_match),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "pdf-version",
            "pdf_version",
            "delivery_pdf",
            "print.pdf.version",
            json!(report.pdf_version),
            json!("1.5"),
            None,
            evaluated_at,
        ),
        proof(
            "color-space",
            "allowed_color_spaces",
            "delivery_pdf",
            "print.pdf.color_spaces",
            json!(report.allowed_color_spaces_only),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "transparency",
            "transparency_absent",
            "delivery_pdf",
            "print.pdf.transparency",
            json!(report.transparency_absent),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "security",
            "external_actions_absent",
            "delivery_pdf",
            "print.pdf.security",
            json!(report.external_actions_absent),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "source-immutable",
            "source_immutable",
            "source_svg",
            "print.source.immutability",
            json!(report.source_immutable),
            json!(true),
            None,
            evaluated_at,
        ),
        proof(
            "inkscape",
            "inkscape_export_verified",
            "delivery_pdf",
            "print.inkscape.integration",
            json!(report.inkscape_export_verified),
            json!(true),
            None,
            evaluated_at,
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn proof(
    suffix: &str,
    claim_id: &str,
    subject_artifact_id: &str,
    validator_id: &str,
    observed: Value,
    expected: Value,
    unit: Option<&str>,
    evaluated_at: &str,
) -> ProofResult {
    ProofResult {
        evidence_id: format!("evidence.print.{suffix}"),
        obligation_id: format!("proof.{claim_id}"),
        claim_id: claim_id.to_owned(),
        subject_artifact_id: subject_artifact_id.to_owned(),
        validator_id: validator_id.to_owned(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        independence_class: IndependenceClass::Independent,
        status: ProofResultStatus::Passed,
        mandatory: true,
        observed,
        expected: Some(expected),
        unit: unit.map(str::to_owned),
        tolerance: Some(0.0),
        evidence_artifact_ids: vec![VALIDATION_EVIDENCE_ID.to_owned()],
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
