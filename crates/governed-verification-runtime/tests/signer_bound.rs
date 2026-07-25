use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_capability_runtime::{
    CapabilityBindings, CapabilityGrant, CapabilitySubject, CapabilityTokenPayload,
    SignerBoundCapabilityToken,
};
use ergaxiom_contract_runtime::PermissionAccess;
use ergaxiom_governed_verification_runtime::{
    GovernedVerificationError, GovernedVerificationRuntime,
};
use ergaxiom_key_governance_runtime::{IssuerRole, KeyGovernanceError};
use ergaxiom_proof_kernel::canonical_json_sha256;
use ergaxiom_windows_signer_protocol_runtime::{
    SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ENCODING_BASE64URL, SignerRequest, SignerResponse,
    SignerSuccess, encode_hex,
};
use serde_json::json;

const ISSUER_ID: &str = "ergaxiom.policy-authority";
const KEY_ID: &str = "capability-key-v1";

fn token(signing_key: &SigningKey) -> Result<SignerBoundCapabilityToken, Box<dyn Error>> {
    let payload = CapabilityTokenPayload {
        schema_version: "0.1.0".to_owned(),
        token_id: "token.governed.signer-bound.0001".to_owned(),
        issuer_id: ISSUER_ID.to_owned(),
        key_id: KEY_ID.to_owned(),
        subject: CapabilitySubject {
            executor_id: "executor.local.0001".to_owned(),
            device_id: Some("device.local.0001".to_owned()),
        },
        issued_at_epoch_s: 100,
        not_before_epoch_s: 100,
        expires_at_epoch_s: 900,
        max_uses: 1,
        nonce: "nonce-governed-signer-0001".to_owned(),
        bindings: CapabilityBindings {
            contract_digest: "a".repeat(64),
            capsule_digest: "b".repeat(64),
            plan_id: "plan.governed.signer.0001".to_owned(),
            plan_digest: "c".repeat(64),
            step_id: "step.governed.signer.0001".to_owned(),
            operator_id: "operator.governed.signer.0001".to_owned(),
        },
        grant: CapabilityGrant {
            capability: "application.control".to_owned(),
            resource: "fixture://governed-signer".to_owned(),
            access: PermissionAccess::Control,
            constraints: json!({"bounded": true}),
        },
    };
    let payload_value = serde_json::to_value(&payload)?;
    let request = SignerRequest::sign_digest(
        "capability.issue.governed.0001",
        IssuerRole::Capability,
        ISSUER_ID,
        KEY_ID,
        canonical_json_sha256(&payload_value)?,
    );
    let envelope = request.signing_envelope()?;
    let signature = signing_key.sign(&envelope.canonical_bytes()?);
    Ok(SignerBoundCapabilityToken {
        payload,
        signer_response: SignerResponse::success(
            request.request_id,
            SignerSuccess::DigestSigned {
                public_key_hex: encode_hex(&signing_key.verifying_key().to_bytes()),
                envelope_digest: envelope.digest()?,
                envelope,
                signature_algorithm: SIGNATURE_ALGORITHM_ED25519.to_owned(),
                signature_encoding: SIGNATURE_ENCODING_BASE64URL.to_owned(),
                signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        ),
    })
}

#[test]
fn governed_registry_accepts_then_revokes_signer_bound_capability()
-> Result<(), Box<dyn Error>> {
    let signing_key = SigningKey::from_bytes(&[71_u8; 32]);
    let token_value = serde_json::to_value(token(&signing_key)?)?;
    let mut runtime = GovernedVerificationRuntime::default();
    runtime.insert_capability_key(
        ISSUER_ID,
        KEY_ID,
        signing_key.verifying_key().to_bytes(),
        0,
        1_000,
    )?;
    runtime.verify_signer_bound_capability_token_signature(&token_value)?;

    let revision = runtime.registry_revision();
    let registry_digest = runtime.registry_digest()?;
    runtime.revoke_key_guarded(
        revision,
        &registry_digest,
        IssuerRole::Capability,
        ISSUER_ID,
        KEY_ID,
        101,
        &"d".repeat(64),
    )?;
    assert!(matches!(
        runtime.verify_signer_bound_capability_token_signature(&token_value),
        Err(GovernedVerificationError::KeyGovernance(
            KeyGovernanceError::KeyRevoked
        ))
    ));
    Ok(())
}
