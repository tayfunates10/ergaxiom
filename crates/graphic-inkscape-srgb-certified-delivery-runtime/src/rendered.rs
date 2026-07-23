use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use ergaxiom_attestation_runtime::{
    AttestationIssueError, AttestationKeyRegistry, AttestationPackage, AttestationVerifyError,
    VerifiedAttestation, issue_attestation, verify_attestation_against_bundle,
};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_evidence_runtime::{
    ArtifactEvidence, ArtifactRole, DigestAlgorithm, EvidenceBundle, EvidenceBundleError,
    assess_bundle,
};
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_png_pixel_decoder_runtime::{PngPixelDecodeError, PngPixelReport, decode_png};
use ergaxiom_png_rendered_contrast_runtime::{
    RenderedContrastError, RenderedContrastPolicy, RenderedContrastResult,
    validate_rendered_contrast,
};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::CertifiedInkscapeSrgbGraphicDelivery;

const BINDING_SCHEMA: &str = "0.1.0";
const PIXEL_REPORT_ARTIFACT_ID: &str = "evidence.inkscape.rendered-pixel-report";
const CONTRAST_POLICY_ARTIFACT_ID: &str = "evidence.inkscape.rendered-contrast-policy";
const CONTRAST_RESULT_ARTIFACT_ID: &str = "evidence.inkscape.rendered-contrast-result";
const CONTRAST_BINDING_ARTIFACT_ID: &str = "evidence.inkscape.rendered-contrast-binding";

pub struct RenderedContrastCertificationRequest<'a> {
    pub base_delivery: CertifiedInkscapeSrgbGraphicDelivery,
    pub normalized_png: &'a Path,
    pub contrast_policy: &'a RenderedContrastPolicy,
    pub claimed_contrast_result: &'a RenderedContrastResult,
    pub base_attestation_keys: &'a AttestationKeyRegistry,
    pub contract_value: &'a Value,
    pub compiled_contract: &'a CompiledContract,
    pub compiled_plan: &'a CompiledPlan,
    pub assurance_level: AssuranceLevel,
    pub final_manifest_id: &'a str,
    pub final_certificate_id: &'a str,
    pub attestation_issuer_id: &'a str,
    pub attestation_key_id: &'a str,
    pub certificate_issued_at_epoch_s: u64,
    pub attestation_signing_key: &'a SigningKey,
}

#[derive(Debug)]
pub struct CertifiedInkscapeRenderedGraphicDelivery {
    pub base_delivery: CertifiedInkscapeSrgbGraphicDelivery,
    pub pixel_report: PngPixelReport,
    pub contrast_result: RenderedContrastResult,
    pub rendered_binding: InkscapeRenderedContrastBinding,
    pub rendered_binding_digest: String,
    pub evidence_bundle: EvidenceBundle,
    pub evidence_bundle_digest: String,
    pub attestation: AttestationPackage,
    pub verified_attestation: VerifiedAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InkscapeRenderedContrastBinding {
    pub schema_version: String,
    pub job_id: String,
    pub base_evidence_bundle_digest: String,
    pub normalized_png_digest: String,
    pub normalized_png_size_bytes: u64,
    pub pixel_report_digest: String,
    pub rgba_pixel_digest: String,
    pub contrast_policy_digest: String,
    pub contrast_report_digest: String,
    pub contrast_decision_digest: String,
    pub contract_minimum_contrast_milli: u32,
    pub measured_minimum_contrast_milli: u32,
    pub subject_region: ergaxiom_png_rendered_contrast_runtime::PixelRect,
    pub delivery_raster_artifact_id: String,
}

#[derive(Debug, Error)]
pub enum RenderedContrastCertificationError {
    #[error("required rendered certification field is empty: {0}")]
    EmptyField(&'static str),
    #[error("compiled contract or plan does not match the base sRGB certified delivery")]
    BaseCertificationBindingMismatch,
    #[error("the contract minimum_text_contrast requirement is missing or malformed")]
    ContractContrastRequirementMismatch,
    #[error("contract contrast value cannot be represented exactly in thousandths")]
    ContractContrastPrecisionUnsupported,
    #[error("the contrast policy threshold does not equal the Work Contract threshold")]
    ContrastPolicyThresholdMismatch,
    #[error("the normalized PNG is not the raster certified by the base delivery")]
    NormalizedRasterBindingMismatch,
    #[error("the claimed rendered contrast result does not reproduce independently")]
    ClaimedContrastMismatch,
    #[error("the independently reproduced rendered contrast decision is rejected")]
    RenderedContrastRejected,
    #[error("evidence artifact identifier already exists: {0}")]
    DuplicateEvidenceArtifact(String),
    #[error("final evidence decision is {0:?}, so delivery cannot be certified")]
    EvidenceDecisionNotAccepted(DecisionStatus),
    #[error("failed to serialize rendered contrast certified delivery material: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    PixelDecode(#[from] PngPixelDecodeError),
    #[error(transparent)]
    RenderedContrast(#[from] RenderedContrastError),
    #[error(transparent)]
    Evidence(#[from] EvidenceBundleError),
    #[error(transparent)]
    AttestationIssue(#[from] AttestationIssueError),
    #[error(transparent)]
    AttestationVerify(#[from] AttestationVerifyError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn certify_inkscape_rendered_contrast_delivery(
    request: RenderedContrastCertificationRequest<'_>,
) -> Result<CertifiedInkscapeRenderedGraphicDelivery, RenderedContrastCertificationError> {
    validate_required_field(request.final_manifest_id, "final_manifest_id")?;
    validate_required_field(request.final_certificate_id, "final_certificate_id")?;
    validate_required_field(request.attestation_issuer_id, "attestation_issuer_id")?;
    validate_required_field(request.attestation_key_id, "attestation_key_id")?;
    validate_base_bindings(
        &request.base_delivery,
        request.base_attestation_keys,
        request.compiled_contract,
        request.compiled_plan,
        request.assurance_level,
    )?;

    let contract_minimum_contrast_milli = contract_minimum_contrast_milli(request.contract_value)?;
    if request.contrast_policy.minimum_contrast_milli != contract_minimum_contrast_milli {
        return Err(RenderedContrastCertificationError::ContrastPolicyThresholdMismatch);
    }

    let normalized_bytes = fs::read(request.normalized_png)?;
    let normalized_digest = format!("{:x}", Sha256::digest(&normalized_bytes));
    if normalized_digest != request.base_delivery.normalization_binding.normalized_raster_png_digest
        || normalized_digest != request.base_delivery.verified_normalization.output_png_digest
    {
        return Err(RenderedContrastCertificationError::NormalizedRasterBindingMismatch);
    }

    let decoded = decode_png(request.normalized_png)?;
    if decoded.report.artifact_digest != normalized_digest {
        return Err(RenderedContrastCertificationError::NormalizedRasterBindingMismatch);
    }
    let contrast_result = validate_rendered_contrast(&decoded, request.contrast_policy)?;
    if &contrast_result != request.claimed_contrast_result {
        return Err(RenderedContrastCertificationError::ClaimedContrastMismatch);
    }
    if !contrast_result.accepted || !contrast_result.violations.is_empty() {
        return Err(RenderedContrastCertificationError::RenderedContrastRejected);
    }

    let base_evidence_bundle_digest = request.base_delivery.evidence_bundle_digest.clone();
    let mut evidence_bundle: EvidenceBundle = serde_json::from_value(
        serde_json::to_value(&request.base_delivery.evidence_bundle)
            .map_err(RenderedContrastCertificationError::Serialization)?,
    )
    .map_err(RenderedContrastCertificationError::Serialization)?;

    let pixel_report_bytes = serde_json::to_vec(&decoded.report)
        .map_err(RenderedContrastCertificationError::Serialization)?;
    let contrast_policy_bytes = serde_json::to_vec(request.contrast_policy)
        .map_err(RenderedContrastCertificationError::Serialization)?;
    let contrast_result_bytes = serde_json::to_vec(&contrast_result)
        .map_err(RenderedContrastCertificationError::Serialization)?;
    let contrast_policy_digest = canonical_json_sha256(
        &serde_json::to_value(request.contrast_policy)
            .map_err(RenderedContrastCertificationError::Serialization)?,
    )?;

    let rendered_binding = InkscapeRenderedContrastBinding {
        schema_version: BINDING_SCHEMA.to_owned(),
        job_id: request
            .base_delivery
            .base_delivery
            .execution_binding
            .job_id
            .clone(),
        base_evidence_bundle_digest,
        normalized_png_digest: normalized_digest,
        normalized_png_size_bytes: normalized_bytes.len() as u64,
        pixel_report_digest: decoded.report.report_digest.clone(),
        rgba_pixel_digest: decoded.report.rgba_pixel_digest.clone(),
        contrast_policy_digest,
        contrast_report_digest: contrast_result.report.report_digest.clone(),
        contrast_decision_digest: contrast_result.decision_digest.clone(),
        contract_minimum_contrast_milli,
        measured_minimum_contrast_milli: contrast_result
            .report
            .minimum_dominant_contrast_milli,
        subject_region: request.contrast_policy.subject_region,
        delivery_raster_artifact_id: request
            .base_delivery
            .normalization_binding
            .delivery_raster_artifact_id
            .clone(),
    };
    let rendered_binding_value = serde_json::to_value(&rendered_binding)
        .map_err(RenderedContrastCertificationError::Serialization)?;
    let rendered_binding_digest = canonical_json_sha256(&rendered_binding_value)?;
    let rendered_binding_bytes = serde_json::to_vec(&rendered_binding)
        .map_err(RenderedContrastCertificationError::Serialization)?;

    add_evidence_artifacts(
        &mut evidence_bundle,
        [
            artifact(
                PIXEL_REPORT_ARTIFACT_ID,
                "application/vnd.ergaxiom.png-pixel-report+json",
                &pixel_report_bytes,
            ),
            artifact(
                CONTRAST_POLICY_ARTIFACT_ID,
                "application/vnd.ergaxiom.rendered-contrast-policy+json",
                &contrast_policy_bytes,
            ),
            artifact(
                CONTRAST_RESULT_ARTIFACT_ID,
                "application/vnd.ergaxiom.rendered-contrast-result+json",
                &contrast_result_bytes,
            ),
            artifact(
                CONTRAST_BINDING_ARTIFACT_ID,
                "application/vnd.ergaxiom.inkscape-rendered-contrast-binding+json",
                &rendered_binding_bytes,
            ),
        ],
    )?;
    evidence_bundle.claimed_decision.reason =
        "Authorized functional-twin proofs, signed Inkscape execution, signed sRGB normalization, independent PNG decoding, and independent rendered contrast evidence passed."
            .to_owned();

    let bundle_value = serde_json::to_value(&evidence_bundle)
        .map_err(RenderedContrastCertificationError::Serialization)?;
    let assessment = assess_bundle(
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
    )?;
    if assessment.decision.status != DecisionStatus::Accepted {
        return Err(RenderedContrastCertificationError::EvidenceDecisionNotAccepted(
            assessment.decision.status,
        ));
    }

    let attestation = issue_attestation(
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
        request.final_manifest_id,
        request.final_certificate_id,
        request.attestation_issuer_id,
        request.attestation_key_id,
        request.certificate_issued_at_epoch_s,
        request.attestation_signing_key,
    )?;
    let mut final_keys = AttestationKeyRegistry::default();
    final_keys.insert_ed25519(
        request.attestation_issuer_id,
        request.attestation_key_id,
        request.attestation_signing_key.verifying_key().to_bytes(),
    )?;
    let verified_attestation = verify_attestation_against_bundle(
        &attestation,
        &final_keys,
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
    )?;

    Ok(CertifiedInkscapeRenderedGraphicDelivery {
        base_delivery: request.base_delivery,
        pixel_report: decoded.report,
        contrast_result,
        rendered_binding,
        rendered_binding_digest,
        evidence_bundle,
        evidence_bundle_digest: assessment.bundle_digest,
        attestation,
        verified_attestation,
    })
}

fn validate_required_field(
    value: &str,
    field: &'static str,
) -> Result<(), RenderedContrastCertificationError> {
    if value.trim().is_empty() {
        return Err(RenderedContrastCertificationError::EmptyField(field));
    }
    Ok(())
}

fn validate_base_bindings(
    base: &CertifiedInkscapeSrgbGraphicDelivery,
    base_attestation_keys: &AttestationKeyRegistry,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    assurance_level: AssuranceLevel,
) -> Result<(), RenderedContrastCertificationError> {
    let base_bundle_value = serde_json::to_value(&base.evidence_bundle)
        .map_err(RenderedContrastCertificationError::Serialization)?;
    let independently_verified = verify_attestation_against_bundle(
        &base.attestation,
        base_attestation_keys,
        compiled_contract.clone(),
        compiled_plan,
        &base_bundle_value,
        assurance_level,
    )?;
    if independently_verified != base.verified_attestation {
        return Err(RenderedContrastCertificationError::BaseCertificationBindingMismatch);
    }

    let certificate = &base.attestation.certificate.payload;
    let valid = certificate.contract_digest == compiled_contract.seal.contract_digest
        && certificate.capsule_digest == compiled_contract.seal.capsule_digest
        && certificate.plan_id == compiled_plan.plan_id
        && certificate.plan_digest == compiled_plan.plan_digest
        && certificate.evidence_bundle_digest == base.evidence_bundle_digest
        && independently_verified.evidence_bundle_digest == base.evidence_bundle_digest
        && certificate.assurance_level == assurance_level
        && independently_verified.assurance_level == assurance_level;
    if valid {
        Ok(())
    } else {
        Err(RenderedContrastCertificationError::BaseCertificationBindingMismatch)
    }
}

fn contract_minimum_contrast_milli(
    contract_value: &Value,
) -> Result<u32, RenderedContrastCertificationError> {
    let requirement = contract_value
        .get("requirements")
        .and_then(|value| value.get("hard"))
        .and_then(Value::as_array)
        .and_then(|requirements| {
            requirements.iter().find(|requirement| {
                requirement.get("id").and_then(Value::as_str) == Some("minimum_text_contrast")
            })
        })
        .ok_or(RenderedContrastCertificationError::ContractContrastRequirementMismatch)?;
    if requirement.get("operator").and_then(Value::as_str) != Some("gte")
        || requirement.get("unit").and_then(Value::as_str) != Some("ratio")
        || requirement.get("mandatory").and_then(Value::as_bool) != Some(true)
    {
        return Err(RenderedContrastCertificationError::ContractContrastRequirementMismatch);
    }
    let expected = requirement
        .get("expected")
        .and_then(Value::as_number)
        .ok_or(RenderedContrastCertificationError::ContractContrastRequirementMismatch)?;
    parse_ratio_milli(&expected.to_string())
}

fn parse_ratio_milli(value: &str) -> Result<u32, RenderedContrastCertificationError> {
    if value.is_empty() || value.starts_with('-') || value.contains(['e', 'E']) {
        return Err(RenderedContrastCertificationError::ContractContrastPrecisionUnsupported);
    }
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty() || fraction.len() > 3 || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RenderedContrastCertificationError::ContractContrastPrecisionUnsupported);
    }
    let whole = whole
        .parse::<u32>()
        .map_err(|_| RenderedContrastCertificationError::ContractContrastPrecisionUnsupported)?;
    let mut fraction_value = 0_u32;
    for byte in fraction.bytes() {
        fraction_value = fraction_value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
            .ok_or(RenderedContrastCertificationError::ContractContrastPrecisionUnsupported)?;
    }
    for _ in fraction.len()..3 {
        fraction_value = fraction_value
            .checked_mul(10)
            .ok_or(RenderedContrastCertificationError::ContractContrastPrecisionUnsupported)?;
    }
    whole
        .checked_mul(1000)
        .and_then(|value| value.checked_add(fraction_value))
        .ok_or(RenderedContrastCertificationError::ContractContrastPrecisionUnsupported)
}

fn add_evidence_artifacts<const N: usize>(
    bundle: &mut EvidenceBundle,
    artifacts: [ArtifactEvidence; N],
) -> Result<(), RenderedContrastCertificationError> {
    let mut ids: BTreeSet<String> = bundle
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect();
    for artifact in artifacts {
        if !ids.insert(artifact.artifact_id.clone()) {
            return Err(RenderedContrastCertificationError::DuplicateEvidenceArtifact(
                artifact.artifact_id,
            ));
        }
        bundle.artifacts.push(artifact);
    }
    Ok(())
}

fn artifact(artifact_id: &str, media_type: &str, bytes: &[u8]) -> ArtifactEvidence {
    ArtifactEvidence {
        artifact_id: artifact_id.to_owned(),
        role: ArtifactRole::Evidence,
        uri: format!("bundle://artifacts/{artifact_id}"),
        media_type: Some(media_type.to_owned()),
        algorithm: DigestAlgorithm::Sha256,
        digest: format!("{:x}", Sha256::digest(bytes)),
        size_bytes: bytes.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_ratio_milli;

    #[test]
    fn contrast_ratio_decimal_is_converted_exactly_to_milli() {
        assert_eq!(parse_ratio_milli("4.5"), Ok(4500));
        assert_eq!(parse_ratio_milli("7"), Ok(7000));
        assert_eq!(parse_ratio_milli("1.234"), Ok(1234));
        assert!(parse_ratio_milli("4.5001").is_err());
        assert!(parse_ratio_milli("4e0").is_err());
    }
}
