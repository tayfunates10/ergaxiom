use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_capability_issuance_runtime::{
    CAPABILITY_ISSUER_ID, CAPABILITY_KEY_ID, CapabilityIssuanceAuthority, CapabilityIssuanceError,
    CapabilitySignerTransport, CapabilityTokenDraft,
};
use ergaxiom_capability_runtime::{CapabilityBindings, CapabilityGrant, CapabilitySubject};
use ergaxiom_contract_runtime::PermissionAccess;
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_windows_signer_protocol_runtime::{
    SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ENCODING_BASE64URL, SignerRequest, SignerResponse,
    SignerSuccess, encode_hex,
};
use serde_json::json;

#[derive(Debug, Clone, Copy)]
enum Mutation {
    None,
    Role,
    Digest,
}

#[derive(Clone)]
struct TestTransport {
    signing_key: SigningKey,
    mutation: Mutation,
}

impl CapabilitySignerTransport for TestTransport {
    fn invoke(&self, request: &SignerRequest) -> Result<SignerResponse, CapabilityIssuanceError> {
        let mut signed_request = request.clone();
        match self.mutation {
            Mutation::None => {}
            Mutation::Role => signed_request.role = IssuerRole::Attestation,
            Mutation::Digest => signed_request.digest = Some("f".repeat(64)),
        }
        let envelope = signed_request.signing_envelope()?;
        let signature = self.signing_key.sign(&envelope.canonical_bytes()?);
        Ok(SignerResponse::success(
            signed_request.request_id.clone(),
            SignerSuccess::DigestSigned {
                public_key_hex: encode_hex(&self.signing_key.verifying_key().to_bytes()),
                envelope_digest: envelope.digest()?,
                envelope,
                signature_algorithm: SIGNATURE_ALGORITHM_ED25519.to_owned(),
                signature_encoding: SIGNATURE_ENCODING_BASE64URL.to_owned(),
                signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        ))
    }
}

fn draft() -> CapabilityTokenDraft {
    CapabilityTokenDraft {
        token_id: "token.capability.issue.0001".to_owned(),
        subject: CapabilitySubject {
            executor_id: "executor.windows.0001".to_owned(),
            device_id: Some("device.windows.0001".to_owned()),
        },
        issued_at_epoch_s: 100,
        not_before_epoch_s: 100,
        expires_at_epoch_s: 900,
        max_uses: 1,
        nonce: "nonce-capability-00000001".to_owned(),
        bindings: CapabilityBindings {
            contract_digest: "a".repeat(64),
            capsule_digest: "b".repeat(64),
            plan_id: "plan.capability.0001".to_owned(),
            plan_digest: "c".repeat(64),
            step_id: "step.capability.0001".to_owned(),
            operator_id: "operator.capability.0001".to_owned(),
        },
        grant: CapabilityGrant {
            capability: "application.control".to_owned(),
            resource: "fixture://capability".to_owned(),
            access: PermissionAccess::Control,
            constraints: json!({"bounded": true}),
        },
    }
}

#[test]
fn authority_fixes_role_issuer_key_request_and_digest() -> Result<(), Box<dyn Error>> {
    let signing_key = SigningKey::from_bytes(&[51_u8; 32]);
    let authority = CapabilityIssuanceAuthority::new(
        TestTransport {
            signing_key: signing_key.clone(),
            mutation: Mutation::None,
        },
        signing_key.verifying_key().to_bytes(),
    );
    let token = authority.issue(draft())?;
    assert_eq!(token.payload.issuer_id, CAPABILITY_ISSUER_ID);
    assert_eq!(token.payload.key_id, CAPABILITY_KEY_ID);
    let envelope = token.signer_response.verify_digest_signature()?;
    assert_eq!(envelope.role, IssuerRole::Capability);
    assert_eq!(envelope.issuer_id, CAPABILITY_ISSUER_ID);
    assert_eq!(envelope.key_id, CAPABILITY_KEY_ID);
    assert!(envelope.request_id.starts_with("capability.issue."));
    assert_eq!(envelope.request_id.len(), "capability.issue.".len() + 48);

    let serialized_draft = serde_json::to_value(draft())?;
    assert!(serialized_draft.get("issuer_id").is_none());
    assert!(serialized_draft.get("key_id").is_none());
    assert!(serialized_draft.get("role").is_none());
    assert!(serialized_draft.get("digest").is_none());
    assert!(serialized_draft.get("request_id").is_none());
    Ok(())
}

#[test]
fn cross_role_and_digest_substitution_fail_closed() {
    let signing_key = SigningKey::from_bytes(&[52_u8; 32]);
    for mutation in [Mutation::Role, Mutation::Digest] {
        let authority = CapabilityIssuanceAuthority::new(
            TestTransport {
                signing_key: signing_key.clone(),
                mutation,
            },
            signing_key.verifying_key().to_bytes(),
        );
        assert!(matches!(
            authority.issue(draft()),
            Err(CapabilityIssuanceError::SignerRoleMismatch)
                | Err(CapabilityIssuanceError::SignerDigestMismatch)
        ));
    }
}

#[test]
fn substituted_signer_public_key_fails_closed() {
    let signing_key = SigningKey::from_bytes(&[53_u8; 32]);
    let different_key = SigningKey::from_bytes(&[54_u8; 32]);
    let authority = CapabilityIssuanceAuthority::new(
        TestTransport {
            signing_key,
            mutation: Mutation::None,
        },
        different_key.verifying_key().to_bytes(),
    );
    assert!(matches!(
        authority.issue(draft()),
        Err(CapabilityIssuanceError::SignerPublicKeyMismatch)
    ));
}

#[test]
fn invalid_temporal_bounds_fail_before_signing() {
    let signing_key = SigningKey::from_bytes(&[55_u8; 32]);
    let authority = CapabilityIssuanceAuthority::new(
        TestTransport {
            signing_key: signing_key.clone(),
            mutation: Mutation::None,
        },
        signing_key.verifying_key().to_bytes(),
    );
    let mut invalid = draft();
    invalid.not_before_epoch_s = invalid.expires_at_epoch_s;
    assert!(matches!(
        authority.issue(invalid),
        Err(CapabilityIssuanceError::InvalidTemporalBounds)
    ));
}
