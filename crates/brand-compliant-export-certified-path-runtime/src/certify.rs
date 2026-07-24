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

use crate::compiler::BRAND_EXPORT_JOB_TYPE;
use crate::model::{BrandExportValidationReport, BrandRuleManifest, CertifiedBrandExport};
use crate::runtime::{BrandExportRuntimeError, validate_brand_export};
use crate::signing::{
    BrandEvidenceKeyRegistry, BrandEvidenceSignatureError, SignedBrandExportExecutionRecord,
    verify_brand_export_execution_record,
};
use crate::util::{BrandDigestError, canonical_value_digest, sha256_hex};

const EVIDENCE_SCHEMA: &str = "0.4.0";
const VALIDATOR_VERSION: &str = "0.1.0";
const EXECUTION_EVIDENCE_ID: &str = "evidence.brand.execution-record";
const VALIDATION_EVIDENCE_ID: &str = "evidence.brand.validation-report";

pub struct BrandExportCertificationRequest<'a> {
    pub bundle_id: &'a str,
    pub run_id: &'a str,
    pub created_at: &'a str,
    pub operating_system: &'a str,
    pub kernel_version: &'a str,
    pub clock_source: &'a str,
    pub sandbox_id: Option<&'a str>,
    pub source_uri: &'a str,
    pub manifest_uri: &'a str,
    pub logo_uri: &'a str,
    pub editable_uri: &'a str,
    pub delivery_uri: &'a str,
    pub source_svg: &'a [u8],
    pub approved_logo_png: &'a [u8],
    pub brand_manifest: &'a BrandRuleManifest,
    pub editable_svg: &'a [u8],
    pub raw_export_png: &'a [u8],
    pub delivery_png: &'a [u8],
    pub signed_execution: &'a SignedBrandExportExecutionRecord,
    pub validation_report: &'a BrandExportValidationReport,
    pub evidence_keys: &'a BrandEvidenceKeyRegistry,
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
pub enum BrandExportCertificationError {
    #[error("required certification field is empty: {0}")]
    EmptyField(&'static str),
    #[error("compiled contract does not represent brand_compliant_image_export")]
    ContractProfileMismatch,
    #[error("compiled plan is not bound to the supplied contract")]
    PlanBindingMismatch,
    #[error("brand export validation report is not accepted")]
    ValidationRejected,
    #[error("supplied validation report does not equal the independently recomputed report")]
    ValidationReportMismatch,
    #[error("certification input digests do not match the execution and validation records")]
    ArtifactBindingMismatch,
    #[error("evidence decision is {0:?}, so brand export cannot be certified")]
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
    Digest(#[from] BrandDigestError),
    #[error(transparent)]
    Runtime(#[from] BrandExportRuntimeError),
    #[error(transparent)]
    SignedEvidence(#[from] BrandEvidenceSignatureError),
    #[error(transparent)]
    Hashing(#[from] ergaxiom_proof_kernel::HashingError),
}

pub fn certify_brand_export(
    request: BrandExportCertificationRequest<'_>,
) -> Result<CertifiedBrandExport, BrandExportCertificationError> {
    validate_required_fields(&request)?;
    let _verified_execution =
        verify_brand_export_execution_record(request.signed_execution, request.evidence_keys)?;
    let execution_record = &request.signed_execution.record;
    let validation_report = validate_brand_export(
        request.source_svg,
        request.approved_logo_png,
        request.brand_manifest,
        request.editable_svg,
        request.raw_export_png,
        request.delivery_png,
        execution_record,
    )?;
    if validation_report != *request.validation_report {
        return Err(BrandExportCertificationError::ValidationReportMismatch);
    }
    validate_bindings(&request, &validation_report)?;

    let manifest_value = serde_json::to_value(request.brand_manifest)?;
    let manifest_bytes = canonical_json_bytes(&manifest_value)?;
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
            "brand_manifest",
            ArtifactRole::Input,
            request.manifest_uri,
            Some("application/json"),
            &sha256_hex(&manifest_bytes),
            byte_len(&manifest_bytes),
        ),
        artifact(
            "approved_logo",
            ArtifactRole::Input,
            request.logo_uri,
            Some("image/png"),
            &sha256_hex(request.approved_logo_png),
            byte_len(request.approved_logo_png),
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
            "raw_inkscape_export",
            ArtifactRole::Evidence,
            "evidence://brand/raw-inkscape-export.png",
            Some("image/png"),
            &sha256_hex(request.raw_export_png),
            byte_len(request.raw_export_png),
        ),
        artifact(
            "delivery_raster",
            ArtifactRole::Output,
            request.delivery_uri,
            Some("image/png"),
            &sha256_hex(request.delivery_png),
            byte_len(request.delivery_png),
        ),
        artifact(
            EXECUTION_EVIDENCE_ID,
            ArtifactRole::Evidence,
            "evidence://brand/export-execution-record.json",
            Some("application/vnd.ergaxiom.signed-brand-export-execution+json"),
            &sha256_hex(&execution_bytes),
            byte_len(&execution_bytes),
        ),
        artifact(
            VALIDATION_EVIDENCE_ID,
            ArtifactRole::Evidence,
            "evidence://brand/export-validation-report.json",
            Some("application/vnd.ergaxiom.brand-export-validation+json"),
            &sha256_hex(&validation_bytes),
            byte_len(&validation_bytes),
        ),
    ];
    let proof_results = proof_results(
        request.created_at,
        &validation_report,
        request.brand_manifest,
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
            reason: "The restricted source SVG, palette, approved logo, geometry, clear space, typography, copy, PNG delivery profile, source immutability and pinned Inkscape export all passed independent validation."
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
        return Err(BrandExportCertificationError::EvidenceDecisionNotAccepted(
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
    Ok(CertifiedBrandExport {
        evidence_bundle,
        evidence_bundle_digest: assessment.bundle_digest,
        attestation,
        verified_attestation,
        validation_report,
    })
}

fn validate_required_fields(
    request: &BrandExportCertificationRequest<'_>,
) -> Result<(), BrandExportCertificationError> {
    for (field, value) in [
        ("bundle_id", request.bundle_id),
        ("run_id", request.run_id),
        ("created_at", request.created_at),
        ("operating_system", request.operating_system),
        ("kernel_version", request.kernel_version),
        ("clock_source", request.clock_source),
        ("source_uri", request.source_uri),
        ("manifest_uri", request.manifest_uri),
        ("logo_uri", request.logo_uri),
        ("editable_uri", request.editable_uri),
        ("delivery_uri", request.delivery_uri),
        ("manifest_id", request.manifest_id),
        ("certificate_id", request.certificate_id),
        ("issuer_id", request.issuer_id),
        ("key_id", request.key_id),
    ] {
        if value.trim().is_empty() {
            return Err(BrandExportCertificationError::EmptyField(field));
        }
    }
    Ok(())
}

fn validate_bindings(
    request: &BrandExportCertificationRequest<'_>,
    validation: &BrandExportValidationReport,
) -> Result<(), BrandExportCertificationError> {
    if request.compiled_contract.job_type != BRAND_EXPORT_JOB_TYPE {
        return Err(BrandExportCertificationError::ContractProfileMismatch);
    }
    if request.compiled_plan.contract_digest != request.compiled_contract.seal.contract_digest
        || request.compiled_plan.capsule_digest != request.compiled_contract.seal.capsule_digest
    {
        return Err(BrandExportCertificationError::PlanBindingMismatch);
    }
    if !validation.accepted {
        return Err(BrandExportCertificationError::ValidationRejected);
    }
    let record = &request.signed_execution.record;
    let manifest_digest = canonical_value_digest(request.brand_manifest)?;
    if record.source_svg_digest != sha256_hex(request.source_svg)
        || record.manifest_digest != manifest_digest
        || record.approved_logo_digest != sha256_hex(request.approved_logo_png)
        || record.editable_svg_digest != sha256_hex(request.editable_svg)
        || record.raw_export_png_digest != sha256_hex(request.raw_export_png)
        || record.delivery_png_digest != sha256_hex(request.delivery_png)
        || validation.source_svg_digest != record.source_svg_digest
        || validation.manifest_digest != record.manifest_digest
        || validation.approved_logo_digest != record.approved_logo_digest
        || validation.editable_svg_digest != record.editable_svg_digest
        || validation.delivery_png_digest != record.delivery_png_digest
    {
        return Err(BrandExportCertificationError::ArtifactBindingMismatch);
    }
    Ok(())
}

fn proof_results(
    evaluated_at: &str,
    validation: &BrandExportValidationReport,
    manifest: &BrandRuleManifest,
) -> Vec<ProofResult> {
    vec![
        proof(
            "canvas-width",
            "canvas_width",
            "delivery_raster",
            "brand.canvas.dimensions",
            json!(validation.width),
            Some(json!(manifest.canvas_width_px)),
            Some("px"),
            evaluated_at,
        ),
        proof(
            "canvas-height",
            "canvas_height",
            "delivery_raster",
            "brand.canvas.dimensions",
            json!(validation.height),
            Some(json!(manifest.canvas_height_px)),
            Some("px"),
            evaluated_at,
        ),
        proof(
            "restricted-svg",
            "restricted_svg_profile",
            "source_svg",
            "brand.svg.structure",
            json!(validation.restricted_svg_profile),
            Some(json!(true)),
            None,
            evaluated_at,
        ),
        proof(
            "palette",
            "palette_violations",
            "source_svg",
            "brand.palette.allowlist",
            json!(validation.palette_violation_count),
            Some(json!(0)),
            Some("count"),
            evaluated_at,
        ),
        proof(
            "logo-identity",
            "logo_digest_match",
            "source_svg",
            "brand.logo.identity",
            json!(validation.logo_digest_matches),
            Some(json!(true)),
            None,
            evaluated_at,
        ),
        proof(
            "logo-geometry",
            "logo_geometry_match",
            "source_svg",
            "brand.logo.geometry",
            json!(validation.logo_geometry_matches),
            Some(json!(true)),
            None,
            evaluated_at,
        ),
        proof(
            "logo-clear-space",
            "logo_clear_space",
            "source_svg",
            "brand.logo.clear_space",
            json!(validation.logo_clear_space_satisfied),
            Some(json!(true)),
            None,
            evaluated_at,
        ),
        proof(
            "typography",
            "typography_match",
            "source_svg",
            "brand.typography",
            json!(validation.typography_matches),
            Some(json!(true)),
            None,
            evaluated_at,
        ),
        proof(
            "copy",
            "approved_copy_match",
            "source_svg",
            "brand.copy.identity",
            json!(validation.approved_copy_matches),
            Some(json!(true)),
            None,
            evaluated_at,
        ),
        proof(
            "png",
            "output_media_type",
            "delivery_raster",
            "brand.png.structure",
            json!("image/png"),
            Some(json!("image/png")),
            None,
            evaluated_at,
        ),
        proof(
            "srgb",
            "color_profile",
            "delivery_raster",
            "brand.png.structure",
            json!("sRGB IEC61966-2.1"),
            Some(json!("sRGB IEC61966-2.1")),
            None,
            evaluated_at,
        ),
        proof(
            "source-immutable",
            "source_immutable",
            "source_svg",
            "brand.source.immutability",
            json!(validation.source_immutable),
            Some(json!(true)),
            None,
            evaluated_at,
        ),
        proof(
            "inkscape",
            "inkscape_export_verified",
            "delivery_raster",
            "brand.inkscape.integration",
            json!(validation.inkscape_export_verified),
            Some(json!(true)),
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
    expected: Option<Value>,
    unit: Option<&str>,
    evaluated_at: &str,
) -> ProofResult {
    ProofResult {
        evidence_id: format!("evidence.brand.{suffix}"),
        obligation_id: format!("proof.{claim_id}"),
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
