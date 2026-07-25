use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_attestation_runtime::{
    AcceptanceCertificatePayload, ReplayManifest, SignerBoundAcceptanceCertificate,
    SignerBoundAttestationPackage,
};
use ergaxiom_governed_verification_runtime::{
    GovernedVerificationError, GovernedVerificationRuntime,
};
use ergaxiom_key_governance_runtime::{IssuerRole, KeyGovernanceError};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, canonical_json_sha256};
use ergaxiom_windows_signer_protocol_runtime::{
    SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ENCODING_BASE64URL, SignerRequest, SignerResponse,
    SignerSuccess, encode_hex,
};

const ISSUER_ID: &str = "ergaxiom.attestation-authority";
const KEY_ID: &str = "attestation-key-v1";

fn package(signing_key: &SigningKey) -> Result<SignerBoundAttestationPackage, Box<dyn Error>> {
    let manifest = ReplayManifest {
        schema_version: "0.1.0".to_owned(),
        manifest_id: "manifest.governed.signer-bound.0001".to_owned(),
        contract_digest: "a".repeat(64),
        capsule_digest: "b".repeat(64),
        plan_id: "plan.governed.signer-bound.0001".to_owned(),
        plan_digest: "c".repeat(64),
        evidence_bundle_id: "bundle.governed.signer-bound.0001".to_owned(),
        run_id: "run.governed.signer-bound.0001".to_owned(),
        evidence_bundle_digest: "d".repeat(64),
        authorized_trace_digest: "e".repeat(64),
        environment_digest: "f".repeat(64),
        artifacts: Vec::new(),
        authorization_receipt_digests: Vec::new(),
        proof_evidence_ids: Vec::new(),
        expected_decision: DecisionStatus::Accepted,
        assurance_level: AssuranceLevel::E3,
        mandatory_passed: 1,
        mandatory_failed: 0,
        mandatory_unknown: 0,
    };
    let manifest_value = serde_json::to_value(&manifest)?;
    let payload = AcceptanceCertificatePayload {
        schema_version: "0.1.0".to_owned(),
        certificate_id: "certificate.governed.signer-bound.0001".to_owned(),
        issuer_id: ISSUER_ID.to_owned(),
        key_id: KEY_ID.to_owned(),
        issued_at_epoch_s: 100,
        contract_digest: manifest.contract_digest.clone(),
        capsule_digest: manifest.capsule_digest.clone(),
        plan_id: manifest.plan_id.clone(),
        plan_digest: manifest.plan_digest.clone(),
        evidence_bundle_id: manifest.evidence_bundle_id.clone(),
        run_id: manifest.run_id.clone(),
        evidence_bundle_digest: manifest.evidence_bundle_digest.clone(),
        authorized_trace_digest: manifest.authorized_trace_digest.clone(),
        replay_manifest_digest: canonical_json_sha256(&manifest_value)?,
        assurance_level: manifest.assurance_level,
        mandatory_passed: manifest.mandatory_passed,
        mandatory_failed: 0,
        mandatory_unknown: 0,
        decision: DecisionStatus::Accepted,
    };
    let payload_value = serde_json::to_value(&payload)?;
    let payload_digest = canonical_json_sha256(&payload_value)?;
    let request = SignerRequest::sign_digest(
        "attestation.issue.governed.0001",
        IssuerRole::Attestation,
        ISSUER_ID,
        KEY_ID,
        payload_digest,
    );
    let envelope = request.signing_envelope()?;
    let signature = signing_key.sign(&envelope.canonical_bytes()?);
    let signer_response = SignerResponse::success(
        request.request_id,
        SignerSuccess::DigestSigned {
            public_key_hex: encode_hex(&signing_key.verifying_key().to_bytes()),
            envelope_digest: envelope.digest()?,
            envelope,
            signature_algorithm: SIGNATURE_ALGORITHM_ED25519.to_owned(),
            signature_encoding: SIGNATURE_ENCODING_BASE64URL.to_owned(),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    );
    Ok(SignerBoundAttestationPackage {
        replay_manifest: manifest,
        certificate: SignerBoundAcceptanceCertificate {
            payload,
            signer_response,
        },
    })
}

#[test]
fn governed_revocation_invalidates_signer_bound_certificate() -> Result<(), Box<dyn Error>> {
    let signing_key = SigningKey::from_bytes(&[71_u8; 32]);
    let package = package(&signing_key)?;
    let mut runtime = GovernedVerificationRuntime::default();
    runtime.insert_attestation_key(
        ISSUER_ID,
        KEY_ID,
        signing_key.verifying_key().to_bytes(),
        0,
        1_000,
    )?;
    runtime.verify_signer_bound_attestation_package(&package)?;

    let revision = runtime.registry_revision();
    let digest = runtime.registry_digest()?;
    runtime.revoke_key_guarded(
        revision,
        &digest,
        IssuerRole::Attestation,
        ISSUER_ID,
        KEY_ID,
        101,
        &"9".repeat(64),
    )?;
    assert!(matches!(
        runtime.verify_signer_bound_attestation_package(&package),
        Err(GovernedVerificationError::KeyGovernance(
            KeyGovernanceError::KeyRevoked
        ))
    ));
    Ok(())
}

#[test]
fn capability_role_key_cannot_verify_attestation_package() -> Result<(), Box<dyn Error>> {
    let signing_key = SigningKey::from_bytes(&[72_u8; 32]);
    let package = package(&signing_key)?;
    let mut runtime = GovernedVerificationRuntime::default();
    runtime.insert_capability_key(
        ISSUER_ID,
        KEY_ID,
        signing_key.verifying_key().to_bytes(),
        0,
        1_000,
    )?;
    assert!(matches!(
        runtime.verify_signer_bound_attestation_package(&package),
        Err(GovernedVerificationError::KeyGovernance(
            KeyGovernanceError::RoleMismatch { .. }
        ))
    ));
    Ok(())
}
