use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_evidence_runtime::{EvidenceBundle, EvidenceBundleError, assess_bundle};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, HashingError, canonical_json_sha256};
use ergaxiom_windows_production_signer_service_runtime::{
    ProductionSignerServiceError, ProductionSignerTrustSnapshot,
};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::issuer::{AttestationIssueError, build_replay_manifest};
use crate::model::{
    AcceptanceCertificatePayload, ProductionSignerBoundAttestationPackage, ReplayManifest,
    VerifiedAttestation,
};

const REPLAY_MANIFEST_SCHEMA: &str = "0.1.0";
const ACCEPTANCE_CERTIFICATE_SCHEMA: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum ProductionAttestationVerifyError {
    #[error("unsupported replay-manifest schema {0}")]
    UnsupportedManifestSchema(String),
    #[error("unsupported acceptance-certificate schema {0}")]
    UnsupportedCertificateSchema(String),
    #[error("production certificate was not issued under the Attestation role")]
    SignerRoleMismatch,
    #[error("production certificate issuer does not match the payload")]
    SignerIssuerMismatch,
    #[error("production certificate key ID does not match the payload")]
    SignerKeyMismatch,
    #[error("production certificate digest does not match the canonical payload")]
    SignerDigestMismatch,
    #[error("certificate decision is not ACCEPTED")]
    DecisionNotAccepted,
    #[error("accepted certificate contains failed or unknown mandatory obligations")]
    InvalidAcceptedCounts,
    #[error("replay-manifest digest does not match certificate payload")]
    ManifestDigestMismatch,
    #[error("certificate payload and replay manifest disagree on {0}")]
    ManifestPayloadMismatch(&'static str),
    #[error("failed to serialize production attestation document: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error("failed to decode accepted Evidence Bundle: {0}")]
    BundleDecode(#[source] serde_json::Error),
    #[error("recomputed replay manifest differs from certified replay manifest")]
    RecomputedManifestMismatch,
    #[error("recomputed evidence decision is not ACCEPTED")]
    RecomputedDecisionNotAccepted,
    #[error(transparent)]
    ProductionSigner(#[from] ProductionSignerServiceError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    Evidence(#[from] EvidenceBundleError),
    #[error(transparent)]
    ManifestBuild(#[from] AttestationIssueError),
}

pub fn verify_production_signer_bound_attestation(
    package: &ProductionSignerBoundAttestationPackage,
    trust: &ProductionSignerTrustSnapshot,
) -> Result<VerifiedAttestation, ProductionAttestationVerifyError> {
    let payload = &package.certificate.payload;
    let replay_manifest_digest = validate_document(&package.replay_manifest, payload)?;
    let envelope = package.certificate.signer_package.verify_trusted(trust)?;
    if envelope.request.identity.role != IssuerRole::Attestation {
        return Err(ProductionAttestationVerifyError::SignerRoleMismatch);
    }
    if envelope.request.identity.issuer_id != payload.issuer_id {
        return Err(ProductionAttestationVerifyError::SignerIssuerMismatch);
    }
    if envelope.request.identity.key_id != payload.key_id {
        return Err(ProductionAttestationVerifyError::SignerKeyMismatch);
    }
    let payload_value =
        serde_json::to_value(payload).map_err(ProductionAttestationVerifyError::Serialization)?;
    if envelope.request.digest != canonical_json_sha256(&payload_value)? {
        return Err(ProductionAttestationVerifyError::SignerDigestMismatch);
    }
    verified_result(payload, &package.certificate, replay_manifest_digest)
}

pub fn verify_production_signer_bound_attestation_against_bundle(
    package: &ProductionSignerBoundAttestationPackage,
    trust: &ProductionSignerTrustSnapshot,
    compiled_contract: CompiledContract,
    compiled_plan: &CompiledPlan,
    bundle_value: &Value,
    verified_assurance_level: AssuranceLevel,
) -> Result<VerifiedAttestation, ProductionAttestationVerifyError> {
    let verified = verify_production_signer_bound_attestation(package, trust)?;
    verify_recomputed_manifest(
        &package.replay_manifest,
        compiled_contract,
        compiled_plan,
        bundle_value,
        verified_assurance_level,
    )?;
    Ok(verified)
}

fn validate_document(
    manifest: &ReplayManifest,
    payload: &AcceptanceCertificatePayload,
) -> Result<String, ProductionAttestationVerifyError> {
    if manifest.schema_version != REPLAY_MANIFEST_SCHEMA {
        return Err(ProductionAttestationVerifyError::UnsupportedManifestSchema(
            manifest.schema_version.clone(),
        ));
    }
    if payload.schema_version != ACCEPTANCE_CERTIFICATE_SCHEMA {
        return Err(
            ProductionAttestationVerifyError::UnsupportedCertificateSchema(
                payload.schema_version.clone(),
            ),
        );
    }
    if payload.decision != DecisionStatus::Accepted
        || manifest.expected_decision != DecisionStatus::Accepted
    {
        return Err(ProductionAttestationVerifyError::DecisionNotAccepted);
    }
    if payload.mandatory_failed > 0
        || payload.mandatory_unknown > 0
        || manifest.mandatory_failed > 0
        || manifest.mandatory_unknown > 0
    {
        return Err(ProductionAttestationVerifyError::InvalidAcceptedCounts);
    }
    let manifest_value =
        serde_json::to_value(manifest).map_err(ProductionAttestationVerifyError::Serialization)?;
    let replay_manifest_digest = canonical_json_sha256(&manifest_value)?;
    if replay_manifest_digest != payload.replay_manifest_digest {
        return Err(ProductionAttestationVerifyError::ManifestDigestMismatch);
    }
    validate_manifest_payload_match(manifest, payload)?;
    Ok(replay_manifest_digest)
}

fn verified_result<T: Serialize>(
    payload: &AcceptanceCertificatePayload,
    certificate: &T,
    replay_manifest_digest: String,
) -> Result<VerifiedAttestation, ProductionAttestationVerifyError> {
    let certificate_value = serde_json::to_value(certificate)
        .map_err(ProductionAttestationVerifyError::Serialization)?;
    Ok(VerifiedAttestation {
        certificate_id: payload.certificate_id.clone(),
        certificate_digest: canonical_json_sha256(&certificate_value)?,
        replay_manifest_digest,
        evidence_bundle_digest: payload.evidence_bundle_digest.clone(),
        decision: payload.decision,
        assurance_level: payload.assurance_level,
    })
}

fn verify_recomputed_manifest(
    manifest: &ReplayManifest,
    compiled_contract: CompiledContract,
    compiled_plan: &CompiledPlan,
    bundle_value: &Value,
    verified_assurance_level: AssuranceLevel,
) -> Result<(), ProductionAttestationVerifyError> {
    let assessment = assess_bundle(
        compiled_contract,
        compiled_plan,
        bundle_value,
        verified_assurance_level,
    )?;
    if assessment.decision.status != DecisionStatus::Accepted {
        return Err(ProductionAttestationVerifyError::RecomputedDecisionNotAccepted);
    }
    let bundle: EvidenceBundle = serde_json::from_value(bundle_value.clone())
        .map_err(ProductionAttestationVerifyError::BundleDecode)?;
    let recomputed = build_replay_manifest(
        &manifest.manifest_id,
        compiled_plan,
        &bundle,
        &assessment.bundle_digest,
        assessment.decision.status,
        verified_assurance_level,
        assessment.mandatory_passed,
        assessment.mandatory_failed,
        assessment.mandatory_unknown,
    )?;
    if recomputed != *manifest {
        return Err(ProductionAttestationVerifyError::RecomputedManifestMismatch);
    }
    Ok(())
}

fn validate_manifest_payload_match(
    manifest: &ReplayManifest,
    payload: &AcceptanceCertificatePayload,
) -> Result<(), ProductionAttestationVerifyError> {
    check_equal(
        manifest.contract_digest == payload.contract_digest,
        "contract_digest",
    )?;
    check_equal(
        manifest.capsule_digest == payload.capsule_digest,
        "capsule_digest",
    )?;
    check_equal(manifest.plan_id == payload.plan_id, "plan_id")?;
    check_equal(manifest.plan_digest == payload.plan_digest, "plan_digest")?;
    check_equal(
        manifest.evidence_bundle_id == payload.evidence_bundle_id,
        "evidence_bundle_id",
    )?;
    check_equal(manifest.run_id == payload.run_id, "run_id")?;
    check_equal(
        manifest.evidence_bundle_digest == payload.evidence_bundle_digest,
        "evidence_bundle_digest",
    )?;
    check_equal(
        manifest.authorized_trace_digest == payload.authorized_trace_digest,
        "authorized_trace_digest",
    )?;
    check_equal(
        manifest.assurance_level == payload.assurance_level,
        "assurance_level",
    )?;
    check_equal(
        manifest.mandatory_passed == payload.mandatory_passed,
        "mandatory_passed",
    )?;
    check_equal(
        manifest.mandatory_failed == payload.mandatory_failed,
        "mandatory_failed",
    )?;
    check_equal(
        manifest.mandatory_unknown == payload.mandatory_unknown,
        "mandatory_unknown",
    )?;
    check_equal(manifest.expected_decision == payload.decision, "decision")?;
    Ok(())
}

fn check_equal(
    condition: bool,
    field: &'static str,
) -> Result<(), ProductionAttestationVerifyError> {
    if condition {
        Ok(())
    } else {
        Err(ProductionAttestationVerifyError::ManifestPayloadMismatch(
            field,
        ))
    }
}
