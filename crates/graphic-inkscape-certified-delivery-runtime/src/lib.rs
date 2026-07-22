#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;

use ed25519_dalek::SigningKey;
use ergaxiom_attestation_runtime::{
    AttestationIssueError, AttestationKeyRegistry, AttestationPackage, AttestationVerifyError,
    VerifiedAttestation, issue_attestation, verify_attestation_against_bundle,
};
use ergaxiom_evidence_runtime::{
    ApplicationEvidence, ArtifactEvidence, ArtifactRole, DigestAlgorithm, EvidenceBundle,
    EvidenceBundleError, assess_bundle,
};
use ergaxiom_graphic_certified_delivery_runtime::{
    CertifiedGraphicDelivery, GraphicCertificationError, GraphicCertificationRequest,
    certify_graphic_delivery,
};
use ergaxiom_inkscape_execution_evidence_runtime::{
    InkscapeEvidenceError, InkscapeExecutionKeyRegistry, InkscapeExecutionMaterial,
    VerifiedInkscapeExecution, verify_execution_material,
};
use ergaxiom_proof_kernel::{DecisionStatus, HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const BINDING_SCHEMA: &str = "0.1.0";
const EXECUTION_PACKAGE_ARTIFACT_ID: &str = "evidence.inkscape.execution-package";
const EXECUTION_VERIFICATION_ARTIFACT_ID: &str = "evidence.inkscape.verification";
const DELIVERY_BINDING_ARTIFACT_ID: &str = "evidence.inkscape.delivery-binding";
const SOURCE_SVG_ARTIFACT_ID: &str = "evidence.inkscape.source-svg";
const EDITABLE_SVG_ARTIFACT_ID: &str = "evidence.inkscape.editable-svg";
const RASTER_PNG_ARTIFACT_ID: &str = "evidence.inkscape.raster-png";

pub struct InkscapeGraphicCertificationRequest<'a> {
    pub base: GraphicCertificationRequest<'a>,
    pub execution_material: InkscapeExecutionMaterial<'a>,
    pub execution_keys: &'a InkscapeExecutionKeyRegistry,
    pub final_manifest_id: &'a str,
    pub final_certificate_id: &'a str,
}

#[derive(Debug)]
pub struct CertifiedInkscapeGraphicDelivery {
    pub base_delivery: CertifiedGraphicDelivery,
    pub verified_inkscape_execution: VerifiedInkscapeExecution,
    pub execution_binding: InkscapeDeliveryBinding,
    pub execution_binding_digest: String,
    pub evidence_bundle: EvidenceBundle,
    pub evidence_bundle_digest: String,
    pub attestation: AttestationPackage,
    pub verified_attestation: VerifiedAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InkscapeDeliveryBinding {
    pub schema_version: String,
    pub job_id: String,
    pub base_evidence_bundle_digest: String,
    pub execution_package_digest: String,
    pub execution_record_digest: String,
    pub execution_request_digest: String,
    pub source_svg_digest: String,
    pub editable_svg_digest: String,
    pub raster_png_digest: String,
    pub editable_master_artifact_id: String,
    pub delivery_raster_artifact_id: String,
    pub approved_copy_artifact_id: String,
    pub target_element_id: String,
    pub replacement_text: String,
    pub export_width: u32,
    pub export_height: u32,
}

#[derive(Debug, Error)]
pub enum InkscapeGraphicCertificationError {
    #[error("required final certification field is empty: {0}")]
    EmptyField(&'static str),
    #[error("Inkscape replacement text does not equal the approved copy")]
    ApprovedCopyMismatch,
    #[error("Inkscape export dimensions do not equal the graphic job canvas")]
    CanvasBindingMismatch,
    #[error("evidence artifact identifier already exists: {0}")]
    DuplicateEvidenceArtifact(String),
    #[error("evidence bundle already contains a conflicting Inkscape application identity")]
    ApplicationIdentityConflict,
    #[error("final evidence decision is {0:?}, so delivery cannot be certified")]
    EvidenceDecisionNotAccepted(DecisionStatus),
    #[error("failed to serialize Inkscape certified delivery material: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    BaseCertification(#[from] GraphicCertificationError),
    #[error(transparent)]
    InkscapeEvidence(#[from] InkscapeEvidenceError),
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

pub fn certify_inkscape_graphic_delivery(
    request: InkscapeGraphicCertificationRequest<'_>,
) -> Result<CertifiedInkscapeGraphicDelivery, InkscapeGraphicCertificationError> {
    if request.final_manifest_id.trim().is_empty() {
        return Err(InkscapeGraphicCertificationError::EmptyField(
            "final_manifest_id",
        ));
    }
    if request.final_certificate_id.trim().is_empty() {
        return Err(InkscapeGraphicCertificationError::EmptyField(
            "final_certificate_id",
        ));
    }

    let compiled_contract = request.base.compiled_contract;
    let compiled_plan = request.base.compiled_plan;
    let assurance_level = request.base.assurance_level;
    let attestation_issuer_id = request.base.attestation_issuer_id;
    let attestation_key_id = request.base.attestation_key_id;
    let certificate_issued_at_epoch_s = request.base.certificate_issued_at_epoch_s;
    let attestation_signing_key: &SigningKey = request.base.attestation_signing_key;
    let job_id = request.base.job.job_id.clone();
    let approved_copy = request.base.job.approved_copy.text.clone();
    let approved_copy_artifact_id = request.base.job.approved_copy.artifact_id.clone();
    let editable_master_artifact_id = request.base.job.editable_master_id.clone();
    let delivery_raster_artifact_id = request.base.job.delivery_raster_id.clone();
    let canvas_width = request.base.job.canvas.width;
    let canvas_height = request.base.job.canvas.height;

    let verified_inkscape_execution =
        verify_execution_material(&request.execution_material, request.execution_keys)?;
    if verified_inkscape_execution.replacement_text != approved_copy {
        return Err(InkscapeGraphicCertificationError::ApprovedCopyMismatch);
    }
    if verified_inkscape_execution.export_width != canvas_width
        || verified_inkscape_execution.export_height != canvas_height
    {
        return Err(InkscapeGraphicCertificationError::CanvasBindingMismatch);
    }

    let base_delivery = certify_graphic_delivery(request.base)?;
    let base_evidence_bundle_digest = base_delivery.evidence_bundle_digest.clone();
    let mut evidence_bundle: EvidenceBundle = serde_json::from_value(
        serde_json::to_value(&base_delivery.evidence_bundle)
            .map_err(InkscapeGraphicCertificationError::Serialization)?,
    )
    .map_err(InkscapeGraphicCertificationError::Serialization)?;

    bind_application_identity(&mut evidence_bundle, &verified_inkscape_execution)?;

    let execution_package_bytes = serde_json::to_vec(request.execution_material.package)
        .map_err(InkscapeGraphicCertificationError::Serialization)?;
    let execution_verification_bytes = serde_json::to_vec(&verified_inkscape_execution)
        .map_err(InkscapeGraphicCertificationError::Serialization)?;
    let source_svg_bytes = fs::read(request.execution_material.source_svg)?;
    let editable_svg_bytes = fs::read(request.execution_material.editable_svg)?;
    let raster_png_bytes = fs::read(request.execution_material.raster_png)?;

    let execution_binding = InkscapeDeliveryBinding {
        schema_version: BINDING_SCHEMA.to_owned(),
        job_id,
        base_evidence_bundle_digest,
        execution_package_digest: verified_inkscape_execution.package_digest.clone(),
        execution_record_digest: verified_inkscape_execution.record_digest.clone(),
        execution_request_digest: verified_inkscape_execution.request_digest.clone(),
        source_svg_digest: verified_inkscape_execution.source_svg_digest.clone(),
        editable_svg_digest: verified_inkscape_execution.editable_svg_digest.clone(),
        raster_png_digest: verified_inkscape_execution.raster_png_digest.clone(),
        editable_master_artifact_id,
        delivery_raster_artifact_id,
        approved_copy_artifact_id,
        target_element_id: verified_inkscape_execution.target_element_id.clone(),
        replacement_text: verified_inkscape_execution.replacement_text.clone(),
        export_width: verified_inkscape_execution.export_width,
        export_height: verified_inkscape_execution.export_height,
    };
    let execution_binding_value = serde_json::to_value(&execution_binding)
        .map_err(InkscapeGraphicCertificationError::Serialization)?;
    let execution_binding_digest = canonical_json_sha256(&execution_binding_value)?;
    let execution_binding_bytes = serde_json::to_vec(&execution_binding)
        .map_err(InkscapeGraphicCertificationError::Serialization)?;

    add_evidence_artifacts(
        &mut evidence_bundle,
        [
            artifact(
                EXECUTION_PACKAGE_ARTIFACT_ID,
                "application/vnd.ergaxiom.inkscape-execution+json",
                &execution_package_bytes,
            ),
            artifact(
                EXECUTION_VERIFICATION_ARTIFACT_ID,
                "application/vnd.ergaxiom.inkscape-verification+json",
                &execution_verification_bytes,
            ),
            artifact(
                DELIVERY_BINDING_ARTIFACT_ID,
                "application/vnd.ergaxiom.inkscape-delivery-binding+json",
                &execution_binding_bytes,
            ),
            artifact(SOURCE_SVG_ARTIFACT_ID, "image/svg+xml", &source_svg_bytes),
            artifact(EDITABLE_SVG_ARTIFACT_ID, "image/svg+xml", &editable_svg_bytes),
            artifact(RASTER_PNG_ARTIFACT_ID, "image/png", &raster_png_bytes),
        ],
    )?;
    evidence_bundle.claimed_decision.reason =
        "Authorized functional-twin proofs and trusted signed Inkscape execution evidence passed."
            .to_owned();

    let bundle_value = serde_json::to_value(&evidence_bundle)
        .map_err(InkscapeGraphicCertificationError::Serialization)?;
    let assessment = assess_bundle(
        compiled_contract.clone(),
        compiled_plan,
        &bundle_value,
        assurance_level,
    )?;
    if assessment.decision.status != DecisionStatus::Accepted {
        return Err(
            InkscapeGraphicCertificationError::EvidenceDecisionNotAccepted(
                assessment.decision.status,
            ),
        );
    }

    let attestation = issue_attestation(
        compiled_contract.clone(),
        compiled_plan,
        &bundle_value,
        assurance_level,
        request.final_manifest_id,
        request.final_certificate_id,
        attestation_issuer_id,
        attestation_key_id,
        certificate_issued_at_epoch_s,
        attestation_signing_key,
    )?;
    let mut attestation_keys = AttestationKeyRegistry::default();
    attestation_keys.insert_ed25519(
        attestation_issuer_id,
        attestation_key_id,
        attestation_signing_key.verifying_key().to_bytes(),
    )?;
    let verified_attestation = verify_attestation_against_bundle(
        &attestation,
        &attestation_keys,
        compiled_contract.clone(),
        compiled_plan,
        &bundle_value,
        assurance_level,
    )?;

    Ok(CertifiedInkscapeGraphicDelivery {
        base_delivery,
        verified_inkscape_execution,
        execution_binding,
        execution_binding_digest,
        evidence_bundle,
        evidence_bundle_digest: assessment.bundle_digest,
        attestation,
        verified_attestation,
    })
}

fn bind_application_identity(
    bundle: &mut EvidenceBundle,
    verified: &VerifiedInkscapeExecution,
) -> Result<(), InkscapeGraphicCertificationError> {
    if let Some(existing) = bundle
        .environment
        .applications
        .iter()
        .find(|application| application.id == verified.application_id)
    {
        if existing.version != verified.application_version
            || existing.digest != verified.application_digest
        {
            return Err(InkscapeGraphicCertificationError::ApplicationIdentityConflict);
        }
        return Ok(());
    }
    bundle.environment.applications.push(ApplicationEvidence {
        id: verified.application_id.clone(),
        version: verified.application_version.clone(),
        digest: verified.application_digest.clone(),
    });
    Ok(())
}

fn add_evidence_artifacts<const N: usize>(
    bundle: &mut EvidenceBundle,
    artifacts: [ArtifactEvidence; N],
) -> Result<(), InkscapeGraphicCertificationError> {
    let mut ids: BTreeSet<String> = bundle
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect();
    for artifact in artifacts {
        if !ids.insert(artifact.artifact_id.clone()) {
            return Err(InkscapeGraphicCertificationError::DuplicateEvidenceArtifact(
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
