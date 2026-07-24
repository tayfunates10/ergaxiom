from pathlib import Path

certify = Path("crates/background-cleanup-certified-path-runtime/src/certify.rs")
text = certify.read_text(encoding="utf-8")
old = """use crate::model::{
    BackgroundCleanupExecutionRecord, BackgroundCleanupValidationReport,
    CertifiedBackgroundCleanup, InkscapeCleanupIntegrationReport,
};
use crate::util::{DigestMaterialError, canonical_record_digest, sha256_hex};
"""
new = """use crate::model::{
    BackgroundCleanupExecutionRecord, BackgroundCleanupValidationReport,
    CertifiedBackgroundCleanup, InkscapeCleanupIntegrationReport,
};
use crate::runtime::{BackgroundCleanupRuntimeError, validate_background_cleanup};
use crate::signing::{
    CleanupEvidenceKeyRegistry, CleanupEvidenceSignatureError,
    SignedBackgroundCleanupExecutionRecord, SignedInkscapeCleanupIntegrationReport,
    verify_background_cleanup_execution_record, verify_inkscape_cleanup_integration_report,
};
use crate::util::{DigestMaterialError, sha256_hex};
"""
if old not in text:
    raise SystemExit("certify import block missing")
text = text.replace(old, new, 1)

old = """    pub cleaned_png: &'a [u8],
    pub execution_record: &'a BackgroundCleanupExecutionRecord,
    pub validation_report: &'a BackgroundCleanupValidationReport,
    pub integration_report: &'a InkscapeCleanupIntegrationReport,
    pub authorized_trace: AuthorizedExecutionTrace,
"""
new = """    pub cleaned_png: &'a [u8],
    pub signed_execution: &'a SignedBackgroundCleanupExecutionRecord,
    pub validation_report: &'a BackgroundCleanupValidationReport,
    pub signed_integration: &'a SignedInkscapeCleanupIntegrationReport,
    pub evidence_keys: &'a CleanupEvidenceKeyRegistry,
    pub authorized_trace: AuthorizedExecutionTrace,
"""
if old not in text:
    raise SystemExit("certify request block missing")
text = text.replace(old, new, 1)

old = """    #[error("cleanup validation report is not accepted")]
    ValidationRejected,
    #[error("Inkscape integration report is not verified")]
    IntegrationRejected,
    #[error("certification input digests do not match the execution and validation records")]
    ArtifactBindingMismatch,
    #[error("validation or integration report digest is invalid")]
    ReportDigestMismatch,
"""
new = """    #[error("cleanup validation report is not accepted")]
    ValidationRejected,
    #[error("supplied cleanup validation report does not equal the independently recomputed report")]
    ValidationReportMismatch,
    #[error("certification input digests do not match the execution and validation records")]
    ArtifactBindingMismatch,
"""
if old not in text:
    raise SystemExit("certify error block missing")
text = text.replace(old, new, 1)

old = """    #[error(transparent)]
    Digest(#[from] DigestMaterialError),
"""
new = """    #[error(transparent)]
    Digest(#[from] DigestMaterialError),
    #[error(transparent)]
    Runtime(#[from] BackgroundCleanupRuntimeError),
    #[error(transparent)]
    SignedEvidence(#[from] CleanupEvidenceSignatureError),
"""
if old not in text:
    raise SystemExit("certify error tail missing")
text = text.replace(old, new, 1)

old = """    validate_required_fields(&request)?;
    validate_bindings(&request)?;

    let execution_bytes = serde_json::to_vec(request.execution_record)?;
    let validation_bytes = serde_json::to_vec(request.validation_report)?;
    let integration_bytes = serde_json::to_vec(request.integration_report)?;
"""
new = """    validate_required_fields(&request)?;
    let _verified_execution = verify_background_cleanup_execution_record(
        request.signed_execution,
        request.evidence_keys,
    )?;
    let _verified_integration = verify_inkscape_cleanup_integration_report(
        request.signed_integration,
        request.evidence_keys,
    )?;
    let execution_record = &request.signed_execution.record;
    let integration_report = &request.signed_integration.report;
    let validation_report = validate_background_cleanup(
        request.source_png,
        request.approved_mask_png,
        request.cleaned_png,
        execution_record,
    )?;
    if validation_report != *request.validation_report {
        return Err(BackgroundCleanupCertificationError::ValidationReportMismatch);
    }
    validate_bindings(
        &request,
        execution_record,
        &validation_report,
        integration_report,
    )?;

    let execution_bytes = serde_json::to_vec(request.signed_execution)?;
    let validation_bytes = serde_json::to_vec(&validation_report)?;
    let integration_bytes = serde_json::to_vec(request.signed_integration)?;
"""
if old not in text:
    raise SystemExit("certify function intro missing")
text = text.replace(old, new, 1)

text = text.replace("request.integration_report.probe_png_digest", "integration_report.probe_png_digest")
text = text.replace("request.integration_report.probe_size_bytes", "integration_report.probe_size_bytes")
text = text.replace(
    "application/vnd.ergaxiom.cleanup-execution-record+json",
    "application/vnd.ergaxiom.signed-cleanup-execution-record+json",
)
text = text.replace(
    "application/vnd.ergaxiom.cleanup-integration-report+json",
    "application/vnd.ergaxiom.signed-cleanup-integration-report+json",
)
old = """    let proof_results = proof_results(
        request.created_at,
        request.validation_report,
        request.integration_report,
    );
"""
new = """    let proof_results = proof_results(
        request.created_at,
        &validation_report,
        integration_report,
    );
"""
if old not in text:
    raise SystemExit("proof_results call missing")
text = text.replace(old, new, 1)
text = text.replace("request.integration_report.application_id.clone()", "integration_report.application_id.clone()")
text = text.replace("request.integration_report.application_version.clone()", "integration_report.application_version.clone()")
text = text.replace("request.integration_report.executable_digest.clone()", "integration_report.executable_digest.clone()")
old = """        validation_report: request.validation_report.clone(),
        integration_report: request.integration_report.clone(),
"""
new = """        validation_report,
        integration_report: integration_report.clone(),
"""
if old not in text:
    raise SystemExit("certified return block missing")
text = text.replace(old, new, 1)

start = text.index("fn validate_bindings(")
end = text.index("\nfn proof_results(", start)
replacement = """fn validate_bindings(
    request: &BackgroundCleanupCertificationRequest<'_>,
    execution_record: &BackgroundCleanupExecutionRecord,
    validation_report: &BackgroundCleanupValidationReport,
    integration_report: &InkscapeCleanupIntegrationReport,
) -> Result<(), BackgroundCleanupCertificationError> {
    if request.compiled_contract.job_type != BACKGROUND_CLEANUP_JOB_TYPE {
        return Err(BackgroundCleanupCertificationError::ContractProfileMismatch);
    }
    if request.compiled_plan.contract_digest != request.compiled_contract.seal.contract_digest
        || request.compiled_plan.capsule_digest != request.compiled_contract.seal.capsule_digest
    {
        return Err(BackgroundCleanupCertificationError::PlanBindingMismatch);
    }
    if !validation_report.accepted {
        return Err(BackgroundCleanupCertificationError::ValidationRejected);
    }

    let source_digest = sha256_hex(request.source_png);
    let mask_digest = sha256_hex(request.approved_mask_png);
    let cleaned_digest = sha256_hex(request.cleaned_png);
    if execution_record.source_digest != source_digest
        || execution_record.mask_digest != mask_digest
        || execution_record.output_digest != cleaned_digest
        || validation_report.source_digest != source_digest
        || validation_report.mask_digest != mask_digest
        || validation_report.output_digest != cleaned_digest
        || integration_report.cleaned_png_digest != cleaned_digest
        || integration_report.probe_width != validation_report.width
        || integration_report.probe_height != validation_report.height
    {
        return Err(BackgroundCleanupCertificationError::ArtifactBindingMismatch);
    }
    Ok(())
}
"""
text = text[:start] + replacement + text[end:]
certify.write_text(text, encoding="utf-8")

test = Path("crates/background-cleanup-certified-path-runtime/tests/real_certificate.rs")
text = test.read_text(encoding="utf-8")
old = """    execute_background_cleanup, execute_inkscape_cleanup_probe,
    synthesize_background_cleanup_plan, validate_background_cleanup,
"""
new = """    execute_background_cleanup, execute_inkscape_cleanup_probe,
    sign_background_cleanup_execution_record, sign_inkscape_cleanup_integration_report,
    synthesize_background_cleanup_plan, validate_background_cleanup, CleanupEvidenceKeyRegistry,
"""
if old not in text:
    raise SystemExit("real test import block missing")
text = text.replace(old, new, 1)
old = """    let integration = execute_inkscape_cleanup_probe(
        &inkscape,
        "cleanup.real.0001",
        &execution.cleaned_png,
        4,
        3,
        &directory.path,
    )?;
    assert!(integration.verified);

    let capability_key = SigningKey::from_bytes(&[17_u8; 32]);
"""
new = """    let integration = execute_inkscape_cleanup_probe(
        &inkscape,
        "cleanup.real.0001",
        &execution.cleaned_png,
        4,
        3,
        &directory.path,
    )?;
    assert!(integration.verified);

    let cleanup_execution_key = SigningKey::from_bytes(&[31_u8; 32]);
    let inkscape_evidence_key = SigningKey::from_bytes(&[37_u8; 32]);
    let signed_execution = sign_background_cleanup_execution_record(
        &execution.record,
        "ergaxiom.cleanup-executor",
        "cleanup-execution-ed25519-01",
        &cleanup_execution_key,
    )?;
    let signed_integration = sign_inkscape_cleanup_integration_report(
        &integration,
        "ergaxiom.inkscape-executor",
        "inkscape-integration-ed25519-01",
        &inkscape_evidence_key,
    )?;
    let mut evidence_keys = CleanupEvidenceKeyRegistry::default();
    evidence_keys.insert_ed25519(
        "ergaxiom.cleanup-executor",
        "cleanup-execution-ed25519-01",
        cleanup_execution_key.verifying_key().to_bytes(),
    )?;
    evidence_keys.insert_ed25519(
        "ergaxiom.inkscape-executor",
        "inkscape-integration-ed25519-01",
        inkscape_evidence_key.verifying_key().to_bytes(),
    )?;

    let capability_key = SigningKey::from_bytes(&[17_u8; 32]);
"""
if old not in text:
    raise SystemExit("real test integration marker missing")
text = text.replace(old, new, 1)
old = """        execution_record: &execution.record,
        validation_report: &validation,
        integration_report: &integration,
        authorized_trace: trace,
"""
new = """        signed_execution: &signed_execution,
        validation_report: &validation,
        signed_integration: &signed_integration,
        evidence_keys: &evidence_keys,
        authorized_trace: trace,
"""
if old not in text:
    raise SystemExit("real test certification fields missing")
text = text.replace(old, new, 1)
test.write_text(text, encoding="utf-8")
