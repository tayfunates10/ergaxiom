use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_attestation_runtime::{
    AcceptanceCertificatePayload, AttestationPackage, AttestationSignature,
    AttestationSignatureAlgorithm, AttestationSignatureEncoding, ReplayManifest,
    SignedAcceptanceCertificate,
};
use ergaxiom_capability_runtime::{
    CapabilityBindings, CapabilityGrant, CapabilitySubject, CapabilityTokenPayload,
    SignatureAlgorithm, SignatureEncoding, SignedCapabilityToken, TokenSignature,
};
use ergaxiom_contract_runtime::PermissionAccess;
use ergaxiom_governed_verification_runtime::{
    GovernedVerificationError, GovernedVerificationRuntime,
};
use ergaxiom_key_governance_runtime::{IssuerRole, KeyGovernanceError};
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, canonical_json_bytes, canonical_json_sha256,
};
use serde_json::json;

#[test]
fn revoked_capability_key_invalidates_a_real_token_signature() -> Result<(), Box<dyn Error>> {
    let signing_key = SigningKey::from_bytes(&[31_u8; 32]);
    let payload = CapabilityTokenPayload {
        schema_version: "0.1.0".to_owned(),
        token_id: "token.governed.0001".to_owned(),
        issuer_id: "capability.local".to_owned(),
        key_id: "capability.v1".to_owned(),
        subject: CapabilitySubject {
            executor_id: "executor.local".to_owned(),
            device_id: Some("device.local".to_owned()),
        },
        issued_at_epoch_s: 100,
        not_before_epoch_s: 100,
        expires_at_epoch_s: 900,
        max_uses: 1,
        nonce: "0123456789abcdef".to_owned(),
        bindings: CapabilityBindings {
            contract_digest: "a".repeat(64),
            capsule_digest: "b".repeat(64),
            plan_id: "plan.governed.0001".to_owned(),
            plan_digest: "c".repeat(64),
            step_id: "step.governed.0001".to_owned(),
            operator_id: "operator.governed.0001".to_owned(),
        },
        grant: CapabilityGrant {
            capability: "application.control".to_owned(),
            resource: "fixture://governed".to_owned(),
            access: PermissionAccess::Control,
            constraints: json!({"bounded": true}),
        },
    };
    let payload_value = serde_json::to_value(&payload)?;
    let signature = signing_key.sign(&canonical_json_bytes(&payload_value)?);
    let token = SignedCapabilityToken {
        payload,
        signature: TokenSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            encoding: SignatureEncoding::Base64url,
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    };
    let token_value = serde_json::to_value(token)?;
    let mut runtime = GovernedVerificationRuntime::default();
    runtime.insert_capability_key(
        "capability.local",
        "capability.v1",
        signing_key.verifying_key().to_bytes(),
        0,
        1_000,
    )?;
    runtime.verify_capability_token_signature(&token_value)?;

    let revision = runtime.registry_revision();
    let digest = runtime.registry_digest()?;
    runtime.revoke_key_guarded(
        revision,
        &digest,
        IssuerRole::Capability,
        "capability.local",
        "capability.v1",
        101,
        &"d".repeat(64),
    )?;
    assert!(matches!(
        runtime.verify_capability_token_signature(&token_value),
        Err(GovernedVerificationError::KeyGovernance(
            KeyGovernanceError::KeyRevoked
        ))
    ));
    Ok(())
}

#[test]
fn capability_key_material_cannot_cross_into_attestation_role() -> Result<(), Box<dyn Error>> {
    let signing_key = SigningKey::from_bytes(&[32_u8; 32]);
    let mut runtime = GovernedVerificationRuntime::default();
    runtime.insert_capability_key(
        "issuer.local",
        "capability.v1",
        signing_key.verifying_key().to_bytes(),
        0,
        1_000,
    )?;
    assert!(matches!(
        runtime.insert_attestation_key(
            "issuer.local",
            "attestation.alias",
            signing_key.verifying_key().to_bytes(),
            0,
            1_000,
        ),
        Err(GovernedVerificationError::KeyGovernance(
            KeyGovernanceError::PublicKeyReuse
        ))
    ));
    Ok(())
}

#[test]
fn revoked_attestation_key_invalidates_a_real_acceptance_certificate() -> Result<(), Box<dyn Error>>
{
    let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
    let manifest = ReplayManifest {
        schema_version: "0.1.0".to_owned(),
        manifest_id: "manifest.governed.0001".to_owned(),
        contract_digest: "a".repeat(64),
        capsule_digest: "b".repeat(64),
        plan_id: "plan.governed.0001".to_owned(),
        plan_digest: "c".repeat(64),
        evidence_bundle_id: "bundle.governed.0001".to_owned(),
        run_id: "run.governed.0001".to_owned(),
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
        certificate_id: "certificate.governed.0001".to_owned(),
        issuer_id: "attestation.local".to_owned(),
        key_id: "attestation.v1".to_owned(),
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
    let signature = signing_key.sign(&canonical_json_bytes(&payload_value)?);
    let package = AttestationPackage {
        replay_manifest: manifest,
        certificate: SignedAcceptanceCertificate {
            payload,
            signature: AttestationSignature {
                algorithm: AttestationSignatureAlgorithm::Ed25519,
                encoding: AttestationSignatureEncoding::Base64url,
                value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        },
    };
    let mut runtime = GovernedVerificationRuntime::default();
    runtime.insert_attestation_key(
        "attestation.local",
        "attestation.v1",
        signing_key.verifying_key().to_bytes(),
        0,
        1_000,
    )?;
    runtime.verify_attestation_package(&package)?;

    let revision = runtime.registry_revision();
    let digest = runtime.registry_digest()?;
    runtime.revoke_key_guarded(
        revision,
        &digest,
        IssuerRole::Attestation,
        "attestation.local",
        "attestation.v1",
        101,
        &"9".repeat(64),
    )?;
    assert!(matches!(
        runtime.verify_attestation_package(&package),
        Err(GovernedVerificationError::KeyGovernance(
            KeyGovernanceError::KeyRevoked
        ))
    ));
    Ok(())
}
