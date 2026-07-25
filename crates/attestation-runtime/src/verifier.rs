use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_evidence_runtime::{EvidenceBundle, EvidenceBundleError, assess_bundle};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, HashingError, canonical_json_bytes, canonical_json_sha256,
};
use ergaxiom_windows_signer_protocol_runtime::{
    SignerProtocolError, SignerResponse, SignerSuccess, decode_hex_32,
};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::issuer::{AttestationIssueError, build_replay_manifest};
use crate::model::{
    AcceptanceCertificatePayload, AttestationPackage, ReplayManifest,
    SignerBoundAttestationPackage, VerifiedAttestation,
};

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
    #[error("signer-bound certificate was not issued under the Attestation role")]
    SignerRoleMismatch,
    #[error("signer-bound certificate issuer does not match the payload")]
    SignerIssuerMismatch,
    #[error("signer-bound certificate key ID does not match the payload")]
    SignerKeyMismatch,
    #[error("signer-bound certificate digest does not match the canonical payload")]
    SignerDigestMismatch,
    #[error("signer-bound certificate public key does not match the trusted key")]
    SignerPublicKeyMismatch,
    #[error("failed to serialize attestation document: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    SignerProtocol(#[from] SignerProtocolError),
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
    let payload = &package.certificate.payload;
    let key = trusted_key(trusted_keys, payload)?;
    let payload_value =
        serde_json::to_value(payload).map_err(AttestationVerifyError::Serialization)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&package.certificate.signature.value)
        .map_err(|_| AttestationVerifyError::InvalidSignatureEncoding)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AttestationVerifyError::InvalidSignatureLength)?;
    key.verify_strict(&canonical_json_bytes(&payload_value)?, &signature)
        .map_err(|_| AttestationVerifyError::SignatureVerificationFailed)?;
    let replay_manifest_digest = validate_document(&package.replay_manifest, payload)?;
    verified_result(payload, &package.certificate, replay_manifest_digest)
}

pub fn verify_signer_bound_attestation(
    package: &SignerBoundAttestationPackage,
    trusted_keys: &AttestationKeyRegistry,
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    let payload = &package.certificate.payload;
    let replay_manifest_digest = validate_document(&package.replay_manifest, payload)?;
    let key = trusted_key(trusted_keys, payload)?;
    let envelope = package
        .certificate
        .signer_response
        .verify_digest_signature()?;
    if envelope.role != IssuerRole::Attestation {
        return Err(AttestationVerifyError::SignerRoleMismatch);
    }
    if envelope.issuer_id != payload.issuer_id {
        return Err(AttestationVerifyError::SignerIssuerMismatch);
    }
    if envelope.key_id != payload.key_id {
        return Err(AttestationVerifyError::SignerKeyMismatch);
    }
    let payload_value =
        serde_json::to_value(payload).map_err(AttestationVerifyError::Serialization)?;
    if envelope.digest != canonical_json_sha256(&payload_value)? {
        return Err(AttestationVerifyError::SignerDigestMismatch);
    }
    if response_public_key(&package.certificate.signer_response)? != key.to_bytes() {
        return Err(AttestationVerifyError::SignerPublicKeyMismatch);
    }
    verified_result(payload, &package.certificate, replay_manifest_digest)
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
    verify_recomputed_manifest(
        &package.replay_manifest,
        compiled_contract,
        compiled_plan,
        bundle_value,
        verified_assurance_level,
    )?;
    Ok(verified)
}

pub fn verify_signer_bound_attestation_against_bundle(
    package: &SignerBoundAttestationPackage,
    trusted_keys: &AttestationKeyRegistry,
    compiled_contract: CompiledContract,
    compiled_plan: &CompiledPlan,
    bundle_value: &Value,
    verified_assurance_level: AssuranceLevel,
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    let verified = verify_signer_bound_attestation(package, trusted_keys)?;
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
) -> Result<String, AttestationVerifyError> {
    if manifest.schema_version != REPLAY_MANIFEST_SCHEMA {
        return Err(AttestationVerifyError::UnsupportedManifestSchema(
            manifest.schema_version.clone(),
        ));
    }
    if payload.schema_version != ACCEPTANCE_CERTIFICATE_SCHEMA {
        return Err(AttestationVerifyError::UnsupportedCertificateSchema(
            payload.schema_version.clone(),
        ));
    }
    if payload.decision != DecisionStatus::Accepted
        || manifest.expected_decision != DecisionStatus::Accepted
    {
        return Err(AttestationVerifyError::DecisionNotAccepted);
    }
    if payload.mandatory_failed > 0
        || payload.mandatory_unknown > 0
        || manifest.mandatory_failed > 0
        || manifest.mandatory_unknown > 0
    {
        return Err(AttestationVerifyError::InvalidAcceptedCounts);
    }
    let manifest_value =
        serde_json::to_value(manifest).map_err(AttestationVerifyError::Serialization)?;
    let replay_manifest_digest = canonical_json_sha256(&manifest_value)?;
    if replay_manifest_digest != payload.replay_manifest_digest {
        return Err(AttestationVerifyError::ManifestDigestMismatch);
    }
    validate_manifest_payload_match(manifest, payload)?;
    Ok(replay_manifest_digest)
}

fn trusted_key<'a>(
    trusted_keys: &'a AttestationKeyRegistry,
    payload: &AcceptanceCertificatePayload,
) -> Result<&'a VerifyingKey, AttestationVerifyError> {
    trusted_keys
        .get(&payload.issuer_id, &payload.key_id)
        .ok_or_else(|| AttestationVerifyError::UnknownTrustedKey {
            issuer_id: payload.issuer_id.clone(),
            key_id: payload.key_id.clone(),
        })
}

fn response_public_key(response: &SignerResponse) -> Result<[u8; 32], AttestationVerifyError> {
    match response {
        SignerResponse::Success {
            result: SignerSuccess::DigestSigned { public_key_hex, .. },
            ..
        } => Ok(decode_hex_32(public_key_hex)?),
        SignerResponse::Error { .. }
        | SignerResponse::Success {
            result: SignerSuccess::KeyInitialized { .. } | SignerSuccess::PublicKey { .. },
            ..
        } => Err(AttestationVerifyError::SignerProtocol(
            SignerProtocolError::ResponseDoesNotContainSignature,
        )),
    }
}

fn verified_result<T: Serialize>(
    payload: &AcceptanceCertificatePayload,
    certificate: &T,
    replay_manifest_digest: String,
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    let certificate_value =
        serde_json::to_value(certificate).map_err(AttestationVerifyError::Serialization)?;
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
) -> Result<(), AttestationVerifyError> {
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
        return Err(AttestationVerifyError::RecomputedManifestMismatch);
    }
    Ok(())
}

fn validate_manifest_payload_match(
    manifest: &ReplayManifest,
    payload: &AcceptanceCertificatePayload,
) -> Result<(), AttestationVerifyError> {
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
    check_equal(manifest.expected_decision == payload.decision, "decision")
}

fn check_equal(matches: bool, field: &'static str) -> Result<(), AttestationVerifyError> {
    if matches {
        Ok(())
    } else {
        Err(AttestationVerifyError::ManifestPayloadMismatch(field))
    }
}
