#![forbid(unsafe_code)]

use std::collections::BTreeSet;

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
use ergaxiom_graphic_final_artifact_verification_runtime::{
    FinalArtifactExpectations, FinalArtifactVerificationBinding, FinalArtifactVerificationError,
    FinalArtifactVerificationRequest, verify_final_artifacts,
};
use ergaxiom_graphic_inkscape_srgb_certified_delivery_runtime::CertifiedInkscapeSrgbGraphicDelivery;
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_png_logo_geometry_runtime::LogoGeometryResult;
use ergaxiom_png_rendered_contrast_runtime::RenderedContrastResult;
use ergaxiom_png_rendered_text_bounds_runtime::RenderedTextBoundsResult;
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, HashingError, canonical_json_sha256,
};
use ergaxiom_svg_approved_copy_runtime::ApprovedCopyResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const CERTIFICATION_BINDING_SCHEMA: &str = "0.1.0";
const APPROVED_COPY_RESULT_ARTIFACT_ID: &str = "evidence.graphic.approved-copy-result";
const LOGO_GEOMETRY_RESULT_ARTIFACT_ID: &str = "evidence.graphic.logo-geometry-result";
const TEXT_BOUNDS_RESULT_ARTIFACT_ID: &str = "evidence.graphic.text-bounds-result";
const RENDERED_CONTRAST_RESULT_ARTIFACT_ID: &str = "evidence.graphic.rendered-contrast-result";
const FINAL_ARTIFACT_BINDING_ARTIFACT_ID: &str = "evidence.graphic.final-artifact-binding";
const FINAL_CERTIFICATION_BINDING_ARTIFACT_ID: &str =
    "evidence.graphic.final-certification-binding";
const EDITABLE_SVG_ARTIFACT_ID: &str = "evidence.inkscape.editable-svg";
const NORMALIZED_RASTER_ARTIFACT_ID: &str = "evidence.inkscape.normalized-raster-png";

pub struct InkscapeFinalArtifactCertificationRequest<'a> {
    pub base_delivery: CertifiedInkscapeSrgbGraphicDelivery,
    pub approved_logo_artifact_id: &'a str,
    pub approved_copy: &'a ApprovedCopyResult,
    pub logo_geometry: &'a LogoGeometryResult,
    pub text_bounds: &'a RenderedTextBoundsResult,
    pub rendered_contrast: &'a RenderedContrastResult,
    pub base_attestation_keys: &'a AttestationKeyRegistry,
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
pub struct CertifiedInkscapeFinalGraphicDelivery {
    pub base_delivery: CertifiedInkscapeSrgbGraphicDelivery,
    pub final_artifact_binding: FinalArtifactVerificationBinding,
    pub certification_binding: InkscapeFinalArtifactCertificationBinding,
    pub evidence_bundle: EvidenceBundle,
    pub evidence_bundle_digest: String,
    pub attestation: AttestationPackage,
    pub verified_attestation: VerifiedAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InkscapeFinalArtifactCertificationBinding {
    pub schema_version: String,
    pub base_evidence_bundle_digest: String,
    pub normalization_binding_digest: String,
    pub final_artifact_binding_digest: String,
    pub contract_digest: String,
    pub capsule_digest: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub assurance_level: AssuranceLevel,
    pub approved_copy_artifact_id: String,
    pub approved_logo_artifact_id: String,
    pub editable_svg_artifact_id: String,
    pub normalized_raster_artifact_id: String,
    pub approved_copy_result_artifact_id: String,
    pub logo_geometry_result_artifact_id: String,
    pub text_bounds_result_artifact_id: String,
    pub rendered_contrast_result_artifact_id: String,
    pub final_artifact_binding_artifact_id: String,
    pub binding_digest: String,
}

#[derive(Debug, Error)]
pub enum InkscapeFinalArtifactCertificationError {
    #[error("required final certification field is empty: {0}")]
    EmptyField(&'static str),
    #[error("compiled contract or plan does not match the base certified delivery")]
    BaseCertificationBindingMismatch,
    #[error("required base artifact is missing: {0}")]
    MissingBaseArtifact(String),
    #[error("base artifact has an unexpected role or digest algorithm: {0}")]
    InvalidBaseArtifact(String),
    #[error("certified editable SVG artifact does not match the normalization binding")]
    EditableSvgArtifactMismatch,
    #[error("certified normalized PNG artifact does not match the normalization binding")]
    NormalizedRasterArtifactMismatch,
    #[error("evidence artifact identifier already exists: {0}")]
    DuplicateEvidenceArtifact(String),
    #[error("final evidence decision is {0:?}, so delivery cannot be certified")]
    EvidenceDecisionNotAccepted(DecisionStatus),
    #[error("failed to serialize final certified delivery material: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    FinalArtifactVerification(#[from] FinalArtifactVerificationError),
    #[error(transparent)]
    Evidence(#[from] EvidenceBundleError),
    #[error(transparent)]
    AttestationIssue(#[from] AttestationIssueError),
    #[error(transparent)]
    AttestationVerify(#[from] AttestationVerifyError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn certify_inkscape_final_artifacts(
    request: InkscapeFinalArtifactCertificationRequest<'_>,
) -> Result<CertifiedInkscapeFinalGraphicDelivery, InkscapeFinalArtifactCertificationError> {
    validate_required_field(
        request.approved_logo_artifact_id,
        "approved_logo_artifact_id",
    )?;
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

    let approved_copy_artifact_id = request
        .base_delivery
        .base_delivery
        .execution_binding
        .approved_copy_artifact_id
        .clone();
    let target_element_id = request
        .base_delivery
        .base_delivery
        .execution_binding
        .target_element_id
        .clone();
    let approved_copy_digest = required_artifact_digest(
        &request.base_delivery.evidence_bundle,
        &approved_copy_artifact_id,
        ArtifactRole::Input,
    )?;
    let approved_logo_digest = required_artifact_digest(
        &request.base_delivery.evidence_bundle,
        request.approved_logo_artifact_id,
        ArtifactRole::Input,
    )?;
    let editable_svg_digest = required_artifact_digest(
        &request.base_delivery.evidence_bundle,
        EDITABLE_SVG_ARTIFACT_ID,
        ArtifactRole::Evidence,
    )?;
    let normalized_png_digest = required_artifact_digest(
        &request.base_delivery.evidence_bundle,
        NORMALIZED_RASTER_ARTIFACT_ID,
        ArtifactRole::Evidence,
    )?;
    if editable_svg_digest != request.base_delivery.normalization_binding.editable_svg_digest {
        return Err(InkscapeFinalArtifactCertificationError::EditableSvgArtifactMismatch);
    }
    if normalized_png_digest
        != request
            .base_delivery
            .normalization_binding
            .normalized_raster_png_digest
    {
        return Err(InkscapeFinalArtifactCertificationError::NormalizedRasterArtifactMismatch);
    }

    let final_artifact_binding = verify_final_artifacts(FinalArtifactVerificationRequest {
        expectations: FinalArtifactExpectations {
            approved_copy_artifact_digest: approved_copy_digest,
            approved_logo_artifact_digest: approved_logo_digest,
            editable_svg_digest,
            normalized_png_digest,
            target_element_id,
        },
        approved_copy: request.approved_copy,
        logo_geometry: request.logo_geometry,
        text_bounds: request.text_bounds,
        rendered_contrast: request.rendered_contrast,
    })?;

    let mut certification_binding = InkscapeFinalArtifactCertificationBinding {
        schema_version: CERTIFICATION_BINDING_SCHEMA.to_owned(),
        base_evidence_bundle_digest: request.base_delivery.evidence_bundle_digest.clone(),
        normalization_binding_digest: request.base_delivery.normalization_binding_digest.clone(),
        final_artifact_binding_digest: final_artifact_binding.binding_digest.clone(),
        contract_digest: request.compiled_contract.seal.contract_digest.clone(),
        capsule_digest: request.compiled_contract.seal.capsule_digest.clone(),
        plan_id: request.compiled_plan.plan_id.clone(),
        plan_digest: request.compiled_plan.plan_digest.clone(),
        assurance_level: request.assurance_level,
        approved_copy_artifact_id,
        approved_logo_artifact_id: request.approved_logo_artifact_id.to_owned(),
        editable_svg_artifact_id: EDITABLE_SVG_ARTIFACT_ID.to_owned(),
        normalized_raster_artifact_id: NORMALIZED_RASTER_ARTIFACT_ID.to_owned(),
        approved_copy_result_artifact_id: APPROVED_COPY_RESULT_ARTIFACT_ID.to_owned(),
        logo_geometry_result_artifact_id: LOGO_GEOMETRY_RESULT_ARTIFACT_ID.to_owned(),
        text_bounds_result_artifact_id: TEXT_BOUNDS_RESULT_ARTIFACT_ID.to_owned(),
        rendered_contrast_result_artifact_id: RENDERED_CONTRAST_RESULT_ARTIFACT_ID.to_owned(),
        final_artifact_binding_artifact_id: FINAL_ARTIFACT_BINDING_ARTIFACT_ID.to_owned(),
        binding_digest: String::new(),
    };
    certification_binding.binding_digest = certification_binding_digest(&certification_binding)?;

    let approved_copy_bytes = serde_json::to_vec(request.approved_copy)
        .map_err(InkscapeFinalArtifactCertificationError::Serialization)?;
    let logo_geometry_bytes = serde_json::to_vec(request.logo_geometry)
        .map_err(InkscapeFinalArtifactCertificationError::Serialization)?;
    let text_bounds_bytes = serde_json::to_vec(request.text_bounds)
        .map_err(InkscapeFinalArtifactCertificationError::Serialization)?;
    let rendered_contrast_bytes = serde_json::to_vec(request.rendered_contrast)
        .map_err(InkscapeFinalArtifactCertificationError::Serialization)?;
    let final_artifact_binding_bytes = serde_json::to_vec(&final_artifact_binding)
        .map_err(InkscapeFinalArtifactCertificationError::Serialization)?;
    let certification_binding_bytes = serde_json::to_vec(&certification_binding)
        .map_err(InkscapeFinalArtifactCertificationError::Serialization)?;

    let mut evidence_bundle: EvidenceBundle = serde_json::from_value(
        serde_json::to_value(&request.base_delivery.evidence_bundle)
            .map_err(InkscapeFinalArtifactCertificationError::Serialization)?,
    )
    .map_err(InkscapeFinalArtifactCertificationError::Serialization)?;
    add_evidence_artifacts(
        &mut evidence_bundle,
        [
            artifact(
                APPROVED_COPY_RESULT_ARTIFACT_ID,
                "application/vnd.ergaxiom.approved-copy-result+json",
                &approved_copy_bytes,
            ),
            artifact(
                LOGO_GEOMETRY_RESULT_ARTIFACT_ID,
                "application/vnd.ergaxiom.logo-geometry-result+json",
                &logo_geometry_bytes,
            ),
            artifact(
                TEXT_BOUNDS_RESULT_ARTIFACT_ID,
                "application/vnd.ergaxiom.text-bounds-result+json",
                &text_bounds_bytes,
            ),
            artifact(
                RENDERED_CONTRAST_RESULT_ARTIFACT_ID,
                "application/vnd.ergaxiom.rendered-contrast-result+json",
                &rendered_contrast_bytes,
            ),
            artifact(
                FINAL_ARTIFACT_BINDING_ARTIFACT_ID,
                "application/vnd.ergaxiom.final-artifact-binding+json",
                &final_artifact_binding_bytes,
            ),
            artifact(
                FINAL_CERTIFICATION_BINDING_ARTIFACT_ID,
                "application/vnd.ergaxiom.final-certification-binding+json",
                &certification_binding_bytes,
            ),
        ],
    )?;
    evidence_bundle.claimed_decision.reason =
        "Authorized functional-twin proofs, signed Inkscape execution, signed sRGB normalization, and independently bound final-artifact validators passed."
            .to_owned();

    let bundle_value = serde_json::to_value(&evidence_bundle)
        .map_err(InkscapeFinalArtifactCertificationError::Serialization)?;
    let assessment = assess_bundle(
        request.compiled_contract.clone(),
        request.compiled_plan,
        &bundle_value,
        request.assurance_level,
    )?;
    if assessment.decision.status != DecisionStatus::Accepted {
        return Err(
            InkscapeFinalArtifactCertificationError::EvidenceDecisionNotAccepted(
                assessment.decision.status,
            ),
        );
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

    Ok(CertifiedInkscapeFinalGraphicDelivery {
        base_delivery: request.base_delivery,
        final_artifact_binding,
        certification_binding,
        evidence_bundle,
        evidence_bundle_digest: assessment.bundle_digest,
        attestation,
        verified_attestation,
    })
}

fn validate_required_field(
    value: &str,
    field: &'static str,
) -> Result<(), InkscapeFinalArtifactCertificationError> {
    if value.trim().is_empty() {
        return Err(InkscapeFinalArtifactCertificationError::EmptyField(field));
    }
    Ok(())
}

fn validate_base_bindings(
    base: &CertifiedInkscapeSrgbGraphicDelivery,
    base_attestation_keys: &AttestationKeyRegistry,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    assurance_level: AssuranceLevel,
) -> Result<(), InkscapeFinalArtifactCertificationError> {
    let base_bundle_value = serde_json::to_value(&base.evidence_bundle)
        .map_err(InkscapeFinalArtifactCertificationError::Serialization)?;
    let independently_verified = verify_attestation_against_bundle(
        &base.attestation,
        base_attestation_keys,
        compiled_contract.clone(),
        compiled_plan,
        &base_bundle_value,
        assurance_level,
    )?;
    if independently_verified != base.verified_attestation {
        return Err(InkscapeFinalArtifactCertificationError::BaseCertificationBindingMismatch);
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
        Err(InkscapeFinalArtifactCertificationError::BaseCertificationBindingMismatch)
    }
}

fn required_artifact_digest(
    bundle: &EvidenceBundle,
    artifact_id: &str,
    expected_role: ArtifactRole,
) -> Result<String, InkscapeFinalArtifactCertificationError> {
    let artifact = bundle
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_id == artifact_id)
        .ok_or_else(|| {
            InkscapeFinalArtifactCertificationError::MissingBaseArtifact(artifact_id.to_owned())
        })?;
    if artifact.role != expected_role || artifact.algorithm != DigestAlgorithm::Sha256 {
        return Err(InkscapeFinalArtifactCertificationError::InvalidBaseArtifact(
            artifact_id.to_owned(),
        ));
    }
    Ok(artifact.digest.clone())
}

fn add_evidence_artifacts<const N: usize>(
    bundle: &mut EvidenceBundle,
    artifacts: [ArtifactEvidence; N],
) -> Result<(), InkscapeFinalArtifactCertificationError> {
    let mut ids: BTreeSet<String> = bundle
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect();
    for artifact in artifacts {
        if !ids.insert(artifact.artifact_id.clone()) {
            return Err(
                InkscapeFinalArtifactCertificationError::DuplicateEvidenceArtifact(
                    artifact.artifact_id,
                ),
            );
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

fn certification_binding_digest(
    binding: &InkscapeFinalArtifactCertificationBinding,
) -> Result<String, InkscapeFinalArtifactCertificationError> {
    let mut value = serde_json::to_value(binding)
        .map_err(InkscapeFinalArtifactCertificationError::Serialization)?;
    let object = value.as_object_mut().ok_or_else(|| {
        InkscapeFinalArtifactCertificationError::Serialization(serde_json::Error::io(
            std::io::Error::other("final certification binding is not an object"),
        ))
    })?;
    object.insert(
        "binding_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}
