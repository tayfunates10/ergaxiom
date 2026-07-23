#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;

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
use ergaxiom_graphic_inkscape_certified_delivery_runtime::CertifiedInkscapeGraphicDelivery;
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_png_srgb_normalizer_runtime::{
    NormalizationEvidenceError, NormalizationKeyRegistry, PngSrgbNormalizationMaterial,
    SrgbRenderingIntent, VerifiedPngSrgbNormalization, verify_normalization_material,
};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const BINDING_SCHEMA: &str = "0.1.0";
const REQUIRED_PROFILE: &str = "sRGB IEC61966-2.1";
const NORMALIZATION_PACKAGE_ARTIFACT_ID: &str = "evidence.inkscape.srgb-normalization-package";
const NORMALIZATION_VERIFICATION_ARTIFACT_ID: &str =
    "evidence.inkscape.srgb-normalization-verification";
const NORMALIZED_RASTER_ARTIFACT_ID: &str = "evidence.inkscape.normalized-raster-png";
const DELIVERY_BINDING_ARTIFACT_ID: &str = "evidence.inkscape.srgb-delivery-binding";

pub struct InkscapeSrgbCertificationRequest<'a> {
    pub base_delivery: CertifiedInkscapeGraphicDelivery,
    pub normalization_material: PngSrgbNormalizationMaterial<'a>,
    pub normalization_keys: &'a NormalizationKeyRegistry,
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
pub struct CertifiedInkscapeSrgbGraphicDelivery {
    pub base_delivery: CertifiedInkscapeGraphicDelivery,
    pub verified_normalization: VerifiedPngSrgbNormalization,
    pub normalization_binding: InkscapeSrgbDeliveryBinding,
    pub normalization_binding_digest: String,
    pub evidence_bundle: EvidenceBundle,
    pub evidence_bundle_digest: String,
    pub attestation: AttestationPackage,
    pub verified_attestation: VerifiedAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InkscapeSrgbDeliveryBinding {
    pub schema_version: String,
    pub job_id: String,
    pub base_evidence_bundle_digest: String,
    pub inkscape_execution_package_digest: String,
    pub inkscape_execution_record_digest: String,
    pub normalization_package_digest: String,
    pub normalization_record_digest: String,
    pub normalization_request_digest: String,
    pub editable_svg_digest: String,
    pub raw_raster_png_digest: String,
    pub normalized_raster_png_digest: String,
    pub input_idat_payload_digest: String,
    pub output_idat_payload_digest: String,
    pub contract_color_profile: String,
    pub rendering_intent: SrgbRenderingIntent,
    pub inserted_srgb_crc32: String,
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    pub delivery_raster_artifact_id: String,
}

#[derive(Debug, Error)]
pub enum InkscapeSrgbCertificationError {
    #[error("required final certification field is empty: {0}")]
    EmptyField(&'static str),
    #[error("compiled contract or plan does not match the base certified delivery")]
    BaseCertificationBindingMismatch,
    #[error("the work contract does not require exactly sRGB IEC61966-2.1")]
    ContractColorProfileMismatch,
    #[error("normalization source SVG is not the certified editable SVG")]
    EditableSvgBindingMismatch,
    #[error("normalization input PNG is not the certified raw Inkscape raster")]
    RawRasterBindingMismatch,
    #[error("normalization dimensions do not equal the certified Inkscape export")]
    CanvasBindingMismatch,
    #[error("normalization changed the IDAT payload")]
    IdatMutation,
    #[error("evidence artifact identifier already exists: {0}")]
    DuplicateEvidenceArtifact(String),
    #[error("final evidence decision is {0:?}, so delivery cannot be certified")]
    EvidenceDecisionNotAccepted(DecisionStatus),
    #[error("failed to serialize sRGB certified delivery material: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    NormalizationEvidence(#[from] NormalizationEvidenceError),
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

pub fn certify_inkscape_srgb_graphic_delivery(
    request: InkscapeSrgbCertificationRequest<'_>,
) -> Result<CertifiedInkscapeSrgbGraphicDelivery, InkscapeSrgbCertificationError> {
    validate_required_field(request.final_manifest_id, "final_manifest_id")?;
    validate_required_field(request.final_certificate_id, "final_certificate_id")?;
    validate_required_field(request.attestation_issuer_id, "attestation_issuer_id")?;
    validate_required_field(request.attestation_key_id, "attestation_key_id")?;

    validate_base_bindings(
        &request.base_delivery,
        request.compiled_contract,
        request.compiled_plan,
        request.assurance_level,
    )?;
    let contract_color_profile = contract_color_profile(request.contract_value)?;
    if contract_color_profile != REQUIRED_PROFILE {
        return Err(InkscapeSrgbCertificationError::ContractColorProfileMismatch);
    }

    let verified_normalization = verify_normalization_material(
        &request.normalization_material,
        request.normalization_keys,
    )?;
    validate_normalization_bindings(&request.base_delivery, &verified_normalization)?;

    let base_evidence_bundle_digest = request.base_delivery.evidence_bundle_digest.clone();
    let mut evidence_bundle: EvidenceBundle = serde_json::from_value(
        serde_json::to_value(&request.base_delivery.evidence_bundle)
            .map_err(InkscapeSrgbCertificationError::Serialization)?,
    )
    .map_err(InkscapeSrgbCertificationError::Serialization)?;

    let normalization_package_bytes = serde_json::to_vec(request.normalization_material.package)
        .map_err(InkscapeSrgbCertificationError::Serialization)?;
    let normalization_verification_bytes = serde_json::to_vec(&verified_normalization)
        .map_err(InkscapeSrgbCertificationError::Serialization)?;
    let normalized_raster_bytes = fs::read(request.normalization_material.output_png)?;

    let normalization_binding = InkscapeSrgbDeliveryBinding {
        schema_version: BINDING_SCHEMA.to_owned(),
        job_id: request.base_delivery.execution_binding.job_id.clone(),
        base_evidence_bundle_digest,
        inkscape_execution_package_digest: request
            .base_delivery
            .verified_inkscape_execution
            .package_digest
            .clone(),
        inkscape_execution_record_digest: request
            .base_delivery
            .verified_inkscape_execution
            .record_digest
            .clone(),
        normalization_package_digest: verified_normalization.package_digest.clone(),
        normalization_record_digest: verified_normalization.record_digest.clone(),
        normalization_request_digest: verified_normalization.request_digest.clone(),
        editable_svg_digest: verified_normalization.source_svg_digest.clone(),
        raw_raster_png_digest: verified_normalization.input_png_digest.clone(),
        normalized_raster_png_digest: verified_normalization.output_png_digest.clone(),
        input_idat_payload_digest: verified_normalization.input_idat_payload_digest.clone(),
        output_idat_payload_digest: verified_normalization.output_idat_payload_digest.clone(),
        contract_color_profile,
        rendering_intent: verified_normalization.rendering_intent,
        inserted_srgb_crc32: verified_normalization.inserted_srgb_crc32.clone(),
        width: verified_normalization.width,
        height: verified_normalization.height,
        bit_depth: verified_normalization.bit_depth,
        delivery_raster_artifact_id: request
            .base_delivery
            .execution_binding
            .delivery_raster_artifact_id
            .clone(),
    };
    let normalization_binding_value = serde_json::to_value(&normalization_binding)
        .map_err(InkscapeSrgbCertificationError::Serialization)?;
    let normalization_binding_digest = canonical_json_sha256(&normalization_binding_value)?;
    let normalization_binding_bytes = serde_json::to_vec(&normalization_binding)
        .map_err(InkscapeSrgbCertificationError::Serialization)?;

    add_evidence_artifacts(
        &mut evidence_bundle,
        [
            artifact(
                NORMALIZATION_PACKAGE_ARTIFACT_ID,
                "application/vnd.ergaxiom.png-srgb-normalization+json",
                &normalization_package_bytes,
            ),
            artifact(
                NORMALIZATION_VERIFICATION_ARTIFACT_ID,
                "application/vnd.ergaxiom.png-srgb-normalization-verification+json",
                &normalization_verification_bytes,
            ),
            artifact(
                DELIVERY_BINDING_ARTIFACT_ID,
                "application/vnd.ergaxiom.inkscape-srgb-delivery-binding+json",
                &normalization_binding_bytes,
            ),
            artifact(
                NORMALIZED_RASTER_ARTIFACT_ID,
                "image/png",
                &normalized_raster_bytes,
            ),
        ],
    )?;
    evidence_bundle.claimed_decision.reason =
        "Authorized functional-twin proofs, signed Inkscape execution evidence, and signed sRGB normalization evidence passed."
            .to_owned();

    let bundle_value = serde_json::to_value(&evidence_bundle)
        .map_err(InkscapeSrgbCertificationError::Serialization)?;
    let assessment = assess_bundle(
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
    )?;
    if assessment.decision.status != DecisionStatus::Accepted {
        return Err(InkscapeSrgbCertificationError::EvidenceDecisionNotAccepted(
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

    Ok(CertifiedInkscapeSrgbGraphicDelivery {
        base_delivery: request.base_delivery,
        verified_normalization,
        normalization_binding,
        normalization_binding_digest,
        evidence_bundle,
        evidence_bundle_digest: assessment.bundle_digest,
        attestation,
        verified_attestation,
    })
}

fn validate_required_field(
    value: &str,
    field: &'static str,
) -> Result<(), InkscapeSrgbCertificationError> {
    if value.trim().is_empty() {
        return Err(InkscapeSrgbCertificationError::EmptyField(field));
    }
    Ok(())
}

fn validate_base_bindings(
    base: &CertifiedInkscapeGraphicDelivery,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    assurance_level: AssuranceLevel,
) -> Result<(), InkscapeSrgbCertificationError> {
    let certificate = &base.attestation.certificate.payload;
    let valid = certificate.contract_digest == compiled_contract.seal.contract_digest
        && certificate.capsule_digest == compiled_contract.seal.capsule_digest
        && certificate.plan_id == compiled_plan.plan_id
        && certificate.plan_digest == compiled_plan.plan_digest
        && certificate.evidence_bundle_digest == base.evidence_bundle_digest
        && base.verified_attestation.evidence_bundle_digest == base.evidence_bundle_digest
        && certificate.assurance_level == assurance_level
        && base.verified_attestation.assurance_level == assurance_level;
    if valid {
        Ok(())
    } else {
        Err(InkscapeSrgbCertificationError::BaseCertificationBindingMismatch)
    }
}

fn validate_normalization_bindings(
    base: &CertifiedInkscapeGraphicDelivery,
    verified: &VerifiedPngSrgbNormalization,
) -> Result<(), InkscapeSrgbCertificationError> {
    if verified.source_svg_digest != base.verified_inkscape_execution.editable_svg_digest {
        return Err(InkscapeSrgbCertificationError::EditableSvgBindingMismatch);
    }
    if verified.input_png_digest != base.verified_inkscape_execution.raster_png_digest {
        return Err(InkscapeSrgbCertificationError::RawRasterBindingMismatch);
    }
    if verified.width != base.verified_inkscape_execution.export_width
        || verified.height != base.verified_inkscape_execution.export_height
    {
        return Err(InkscapeSrgbCertificationError::CanvasBindingMismatch);
    }
    if verified.input_idat_payload_digest != verified.output_idat_payload_digest {
        return Err(InkscapeSrgbCertificationError::IdatMutation);
    }
    Ok(())
}

fn contract_color_profile(
    contract_value: &Value,
) -> Result<String, InkscapeSrgbCertificationError> {
    let expected = contract_value
        .get("requirements")
        .and_then(|value| value.get("hard"))
        .and_then(Value::as_array)
        .and_then(|requirements| {
            requirements.iter().find(|requirement| {
                requirement.get("id").and_then(Value::as_str) == Some("color_profile")
            })
        })
        .and_then(|requirement| requirement.get("expected"))
        .and_then(Value::as_str)
        .ok_or(InkscapeSrgbCertificationError::ContractColorProfileMismatch)?;
    Ok(expected.to_owned())
}

fn add_evidence_artifacts<const N: usize>(
    bundle: &mut EvidenceBundle,
    artifacts: [ArtifactEvidence; N],
) -> Result<(), InkscapeSrgbCertificationError> {
    let mut ids: BTreeSet<String> = bundle
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect();
    for artifact in artifacts {
        if !ids.insert(artifact.artifact_id.clone()) {
            return Err(InkscapeSrgbCertificationError::DuplicateEvidenceArtifact(
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
