use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_evidence_runtime::{EvidenceBundle, EvidenceBundleError, assess_bundle};
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, HashingError, canonical_json_bytes, canonical_json_sha256,
};
use serde_json::Value;
use thiserror::Error;

use crate::issuer::{AttestationIssueError, build_replay_manifest};
use crate::model::{AttestationPackage, VerifiedAttestation};

const REPLAY_MANIFEST_SCHEMA: &str = "0.1.0";
const ACCEPTANCE_CERTIFICATE_SCHEMA: &str = "0.1.0";

#[derive(Debug, Clone, Default)]
pub struct AttestationKeyRegistry {
    keys: BTreeMap<(String, String), VerifyingKey>,
}

impl AttestationKeyRegistry {
    pub fn insert_ed25519(
        &mut self,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<(), AttestationVerifyError> {
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| AttestationVerifyError::InvalidTrustedKey)?;
        self.keys.insert((issuer_id.into(), key_id.into()), key);
        Ok(())
    }

    fn get(&self, issuer_id: &str, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(&(issuer_id.to_owned(), key_id.to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum AttestationVerifyError {
    #[error("unsupported replay-manifest schema {0}")]
    UnsupportedManifestSchema(String),
    #[error("unsupported acceptance-certificate schema {0}")]
    UnsupportedCertificateSchema(String),
    #[error("trusted Ed25519 public key is invalid")]
    InvalidTrustedKey,
    #[error("unknown attestation key {issuer_id}/{key_id}")]
    UnknownTrustedKey { issuer_id: String, key_id: String },
    #[error("certificate signature is not valid base64url")]
    InvalidSignatureEncoding,
    #[error("certificate signature has an invalid Ed25519 length")]
    InvalidSignatureLength,
    #[error("acceptance-certificate signature verification failed")]
    SignatureVerificationFailed,
    #[error("failed to serialize attestation document: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("certificate decision is not ACCEPTED")]
    DecisionNotAccepted,
    #[error("accepted certificate contains failed or unknown mandatory obligations")]
    InvalidAcceptedCounts,
    #[error("replay-manifest digest does not match certificate payload")]
    ManifestDigestMismatch,
    #[error("certificate payload and replay manifest disagree on {0}")]
    ManifestPayloadMismatch(&'static str),
    #[error(transparent)]
    Evidence(#[from] EvidenceBundleError),
    #[error("failed to decode accepted Evidence Bundle: {0}")]
    BundleDecode(#[source] serde_json::Error),
    #[error(transparent)]
    ManifestBuild(#[from] AttestationIssueError),
    #[error("recomputed replay manifest differs from certified replay manifest")]
    RecomputedManifestMismatch,
    #[error("recomputed evidence decision is not ACCEPTED")]
    RecomputedDecisionNotAccepted,
}

pub fn verify_attestation(
    package: &AttestationPackage,
    trusted_keys: &AttestationKeyRegistry,
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    if package.replay_manifest.schema_version != REPLAY_MANIFEST_SCHEMA {
        return Err(AttestationVerifyError::UnsupportedManifestSchema(
            package.replay_manifest.schema_version.clone(),
        ));
    }
    if package.certificate.payload.schema_version != ACCEPTANCE_CERTIFICATE_SCHEMA {
        return Err(AttestationVerifyError::UnsupportedCertificateSchema(
            package.certificate.payload.schema_version.clone(),
        ));
    }

    let payload = &package.certificate.payload;
    if payload.decision != DecisionStatus::Accepted
        || package.replay_manifest.expected_decision != DecisionStatus::Accepted
    {
        return Err(AttestationVerifyError::DecisionNotAccepted);
    }
    if payload.mandatory_failed > 0
        || payload.mandatory_unknown > 0
        || package.replay_manifest.mandatory_failed > 0
        || package.replay_manifest.mandatory_unknown > 0
    {
        return Err(AttestationVerifyError::InvalidAcceptedCounts);
    }

    let key = trusted_keys
        .get(&payload.issuer_id, &payload.key_id)
        .ok_or_else(|| AttestationVerifyError::UnknownTrustedKey {
            issuer_id: payload.issuer_id.clone(),
            key_id: payload.key_id.clone(),
        })?;
    let payload_value =
        serde_json::to_value(payload).map_err(AttestationVerifyError::Serialization)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&package.certificate.signature.value)
        .map_err(|_| AttestationVerifyError::InvalidSignatureEncoding)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AttestationVerifyError::InvalidSignatureLength)?;
    key.verify_strict(&canonical_json_bytes(&payload_value)?, &signature)
        .map_err(|_| AttestationVerifyError::SignatureVerificationFailed)?;

    let manifest_value = serde_json::to_value(&package.replay_manifest)
        .map_err(AttestationVerifyError::Serialization)?;
    let replay_manifest_digest = canonical_json_sha256(&manifest_value)?;
    if replay_manifest_digest != payload.replay_manifest_digest {
        return Err(AttestationVerifyError::ManifestDigestMismatch);
    }
    validate_manifest_payload_match(package)?;

    let certificate_value = serde_json::to_value(&package.certificate)
        .map_err(AttestationVerifyError::Serialization)?;
    Ok(VerifiedAttestation {
        certificate_id: payload.certificate_id.clone(),
        certificate_digest: canonical_json_sha256(&certificate_value)?,
        replay_manifest_digest,
        evidence_bundle_digest: payload.evidence_bundle_digest.clone(),
        decision: payload.decision,
        assurance_level: payload.assurance_level,
    })
}

pub fn verify_attestation_against_bundle(
    package: &AttestationPackage,
    trusted_keys: &AttestationKeyRegistry,
    compiled_contract: CompiledContract,
    compiled_plan: &CompiledPlan,
    bundle_value: &Value,
    verified_assurance_level: AssuranceLevel,
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    let verified = verify_attestation(package, trusted_keys)?;
    let assessment = assess_bundle(
        compiled_contract,
        compiled_plan,
        bundle_value,
        verified_assurance_level,
    )?;
    if assessment.decision.status != DecisionStatus::Accepted {
        return Err(AttestationVerifyError::RecomputedDecisionNotAccepted);
    }
    let bundle: EvidenceBundle = serde_json::from_value(bundle_value.clone())
        .map_err(AttestationVerifyError::BundleDecode)?;
    let recomputed = build_replay_manifest(
        &package.replay_manifest.manifest_id,
        compiled_plan,
        &bundle,
        &assessment.bundle_digest,
        assessment.decision.status,
        verified_assurance_level,
        assessment.mandatory_passed,
        assessment.mandatory_failed,
        assessment.mandatory_unknown,
    )?;
    if recomputed != package.replay_manifest {
        return Err(AttestationVerifyError::RecomputedManifestMismatch);
    }
    Ok(verified)
}

fn validate_manifest_payload_match(
    package: &AttestationPackage,
) -> Result<(), AttestationVerifyError> {
    let manifest = &package.replay_manifest;
    let payload = &package.certificate.payload;
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
    check_equal(
        manifest.expected_decision == payload.decision,
        "decision",
    )
}

fn check_equal(matches: bool, field: &'static str) -> Result<(), AttestationVerifyError> {
    if matches {
        Ok(())
    } else {
        Err(AttestationVerifyError::ManifestPayloadMismatch(field))
    }
}
