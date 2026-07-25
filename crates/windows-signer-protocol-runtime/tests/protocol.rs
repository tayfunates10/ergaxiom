use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_windows_signer_protocol_runtime::{
    SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ENCODING_BASE64URL, SignerProtocolError, SignerRequest,
    SignerResponse, SignerSuccess, encode_hex,
};

const ISSUER: &str = "ergaxiom.attestation-authority";
const KEY_ID: &str = "attestation-key-01";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn signed_response(request: &SignerRequest) -> Result<SignerResponse, Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
    let envelope = request.signing_envelope()?;
    let signature = signing_key.sign(&envelope.canonical_bytes()?);
    Ok(SignerResponse::success(
        request.request_id.clone(),
        SignerSuccess::DigestSigned {
            public_key_hex: encode_hex(&signing_key.verifying_key().to_bytes()),
            envelope_digest: envelope.digest()?,
            envelope,
            signature_algorithm: SIGNATURE_ALGORITHM_ED25519.to_owned(),
            signature_encoding: SIGNATURE_ENCODING_BASE64URL.to_owned(),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    ))
}

#[test]
fn exact_role_bound_digest_signature_verifies() -> Result<(), Box<dyn std::error::Error>> {
    let request = SignerRequest::sign_digest(
        "request.attestation.0001",
        IssuerRole::Attestation,
        ISSUER,
        KEY_ID,
        DIGEST,
    );
    let response = signed_response(&request)?;
    let envelope = response.verify_digest_signature()?;
    assert_eq!(envelope.request_id, request.request_id);
    assert_eq!(envelope.role, IssuerRole::Attestation);
    assert_eq!(envelope.digest, DIGEST);
    assert!(!response.contains_private_material_field());
    Ok(())
}

#[test]
fn changed_role_digest_or_request_id_invalidates_signature()
-> Result<(), Box<dyn std::error::Error>> {
    let request = SignerRequest::sign_digest(
        "request.attestation.0002",
        IssuerRole::Attestation,
        ISSUER,
        KEY_ID,
        DIGEST,
    );
    for mutation in 0..3 {
        let mut response = signed_response(&request)?;
        let SignerResponse::Success {
            result: SignerSuccess::DigestSigned { envelope, .. },
            ..
        } = &mut response
        else {
            return Err("expected signed response".into());
        };
        match mutation {
            0 => envelope.role = IssuerRole::Capability,
            1 => envelope.digest = "b".repeat(64),
            2 => envelope.request_id = "request.attestation.changed".to_owned(),
            _ => return Err("unexpected mutation".into()),
        }
        assert!(matches!(
            response.verify_digest_signature(),
            Err(SignerProtocolError::ResponseBindingMismatch)
                | Err(SignerProtocolError::SignatureVerificationFailed)
        ));
    }
    Ok(())
}

#[test]
fn arbitrary_message_and_path_shaped_identifiers_fail_closed() {
    let malformed_digest = SignerRequest::sign_digest(
        "request.release.0001",
        IssuerRole::Release,
        "ergaxiom.release-authority",
        "release-key-01",
        "sign this arbitrary message",
    );
    assert!(matches!(
        malformed_digest.validate(),
        Err(SignerProtocolError::InvalidSha256Digest)
    ));

    let traversal = SignerRequest::public_key(
        "request.release.0002",
        IssuerRole::Release,
        "../release-authority",
        "release-key-01",
    );
    assert!(matches!(
        traversal.validate(),
        Err(SignerProtocolError::InvalidIdentifier("issuer_id"))
    ));
}

#[test]
fn non_signing_operations_reject_digest_fields() {
    let mut request = SignerRequest::initialize_key(
        "request.capability.0001",
        IssuerRole::Capability,
        "ergaxiom.policy-authority",
        "capability-key-01",
    );
    request.digest_algorithm = Some("sha256".to_owned());
    request.digest = Some(DIGEST.to_owned());
    assert!(matches!(
        request.validate(),
        Err(SignerProtocolError::UnexpectedDigestMaterial)
    ));
}

#[test]
fn error_response_uses_generic_message_and_has_no_secret_fields() {
    let response = SignerResponse::rejected(
        Some("request.attestation.0003".to_owned()),
        "KEY_UNPROTECT_FAILED",
    );
    let serialized = serde_json::to_string(&response).expect("response serialization");
    assert!(serialized.contains("signer request rejected"));
    assert!(!serialized.contains("private"));
    assert!(!response.contains_private_material_field());
}
