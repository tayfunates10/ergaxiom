use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_windows_production_signer_protocol_runtime::{
    ProductionSignerProtocolError, ProductionSignerRequest, ProductionSignerResponse,
    ProductionSignerSuccess,
};
use ergaxiom_windows_production_signer_runtime::{
    AUTHENTICATED_CALLER_SCHEMA, AuthenticatedCallerIdentity, ECDSA_P256_SHA256, HardwareAssurance,
    HardwareKeyDescriptor, HardwareSignature, P1363_FIXED_64, ProductionKeyPolicy,
    SEC1_UNCOMPRESSED_P256, SIGNER_SERVICE_IDENTITY_SCHEMA, SignerRequestBinding,
    SignerServiceIdentity,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};

const PAYLOAD_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CALLER_IMAGE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SERVICE_IMAGE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn caller() -> AuthenticatedCallerIdentity {
    AuthenticatedCallerIdentity {
        schema_version: AUTHENTICATED_CALLER_SCHEMA.to_owned(),
        process_id: 5100,
        process_creation_time_100ns: 123_456_789,
        principal_sid: "S-1-5-21-1000".to_owned(),
        session_id: 2,
        executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
        executable_sha256: CALLER_IMAGE.to_owned(),
    }
}

fn service() -> SignerServiceIdentity {
    SignerServiceIdentity {
        schema_version: SIGNER_SERVICE_IDENTITY_SCHEMA.to_owned(),
        service_id: "ergaxiom.production-signer".to_owned(),
        instance_nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        process_id: 6100,
        process_creation_time_100ns: 223_456_789,
        executable_sha256: SERVICE_IMAGE.to_owned(),
        started_at_epoch_s: 1_800_000_000,
    }
}

fn signed_response(
    assurance: HardwareAssurance,
) -> Result<ProductionSignerResponse, Box<dyn std::error::Error>> {
    let policy = ProductionKeyPolicy::capability();
    let request = ProductionSignerRequest::sign_digest(
        "production.capability.sign.0001",
        &policy,
        PAYLOAD_DIGEST,
    )?;
    let binding =
        SignerRequestBinding::build(request.digest_for(&policy)?, &caller(), &service(), &policy)?;
    let envelope = request.envelope(&policy, binding.clone())?;
    let envelope_digest = envelope.digest_for(&policy)?;
    let envelope_digest_bytes = decode_sha256(&envelope_digest)?;

    let signing_key = SigningKey::from_bytes((&[7_u8; 32]).into())?;
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key.as_bytes();
    let public_key_digest = encode_hex(&Sha256::digest(public_key_bytes));
    let signature: Signature = signing_key.sign_prehash(&envelope_digest_bytes)?;
    let descriptor = HardwareKeyDescriptor {
        identity: policy.identity.clone(),
        provider: policy.provider.clone(),
        algorithm: ECDSA_P256_SHA256.to_owned(),
        public_key_encoding: SEC1_UNCOMPRESSED_P256.to_owned(),
        public_key_base64url: URL_SAFE_NO_PAD.encode(public_key_bytes),
        public_key_digest: public_key_digest.clone(),
        signature_encoding: P1363_FIXED_64.to_owned(),
        export_policy: policy.export_policy.clone(),
        provider_implementation_flags: 1,
        assurance,
        policy_digest: policy.digest()?,
    };
    let hardware_signature = HardwareSignature {
        identity: policy.identity.clone(),
        algorithm: ECDSA_P256_SHA256.to_owned(),
        signature_encoding: P1363_FIXED_64.to_owned(),
        digest_algorithm: "sha256".to_owned(),
        digest: envelope_digest.clone(),
        signature_base64url: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        public_key_digest,
        key_policy_digest: policy.digest()?,
        request_binding_digest: binding.digest()?,
    };
    Ok(ProductionSignerResponse::success(
        request.request_id.clone(),
        ProductionSignerSuccess {
            descriptor,
            envelope,
            envelope_digest,
            signature: hardware_signature,
        },
    ))
}

#[test]
fn p256_response_verifies_cryptographically_without_claiming_hardware()
-> Result<(), Box<dyn std::error::Error>> {
    let response = signed_response(HardwareAssurance::Unproven)?;
    let policy = ProductionKeyPolicy::capability();
    let envelope = response.verify_cryptographic(&policy)?;
    assert_eq!(envelope.request.digest, PAYLOAD_DIGEST);
    assert!(matches!(
        response.verify_production_eligible(&policy),
        Err(ProductionSignerProtocolError::Production(_))
    ));
    assert!(!response.contains_private_material_field());
    Ok(())
}

#[test]
fn proven_hardware_response_reaches_eligible_verification() -> Result<(), Box<dyn std::error::Error>>
{
    let response = signed_response(HardwareAssurance::ProvenHardwareBacked)?;
    let envelope = response.verify_production_eligible(&ProductionKeyPolicy::capability())?;
    assert_eq!(
        envelope.request.identity.role,
        ergaxiom_key_governance_runtime::IssuerRole::Capability
    );
    Ok(())
}

#[test]
fn provider_algorithm_and_public_key_substitution_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    for mutation in 0..3 {
        let mut response = signed_response(HardwareAssurance::ProvenHardwareBacked)?;
        let ProductionSignerResponse::Success { result, .. } = &mut response else {
            return Err("expected success".into());
        };
        match mutation {
            0 => result.descriptor.provider = "Microsoft Software Key Storage Provider".to_owned(),
            1 => result.descriptor.algorithm = "ed25519".to_owned(),
            2 => result.descriptor.public_key_base64url = URL_SAFE_NO_PAD.encode([4_u8; 65]),
            _ => return Err("unexpected mutation".into()),
        }
        assert!(
            response
                .verify_cryptographic(&ProductionKeyPolicy::capability())
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn caller_service_and_request_binding_substitution_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    for mutation in 0..3 {
        let mut response = signed_response(HardwareAssurance::ProvenHardwareBacked)?;
        let ProductionSignerResponse::Success { result, .. } = &mut response else {
            return Err("expected success".into());
        };
        match mutation {
            0 => result.envelope.binding.caller_identity_digest = SERVICE_IMAGE.to_owned(),
            1 => result.envelope.binding.signer_service_identity_digest = CALLER_IMAGE.to_owned(),
            2 => result.envelope.binding.request_digest = PAYLOAD_DIGEST.to_owned(),
            _ => return Err("unexpected mutation".into()),
        }
        assert!(matches!(
            response.verify_cryptographic(&ProductionKeyPolicy::capability()),
            Err(ProductionSignerProtocolError::RequestBindingMismatch)
                | Err(ProductionSignerProtocolError::EnvelopeDigestMismatch)
                | Err(ProductionSignerProtocolError::Production(_))
        ));
    }
    Ok(())
}

#[test]
fn signature_and_envelope_mutation_fail_verification() -> Result<(), Box<dyn std::error::Error>> {
    let mut signature_changed = signed_response(HardwareAssurance::ProvenHardwareBacked)?;
    let ProductionSignerResponse::Success { result, .. } = &mut signature_changed else {
        return Err("expected success".into());
    };
    result.signature.signature_base64url = URL_SAFE_NO_PAD.encode([0_u8; 64]);
    assert!(matches!(
        signature_changed.verify_cryptographic(&ProductionKeyPolicy::capability()),
        Err(ProductionSignerProtocolError::SignatureVerificationFailed)
            | Err(ProductionSignerProtocolError::InvalidSignatureEncoding)
    ));

    let mut envelope_changed = signed_response(HardwareAssurance::ProvenHardwareBacked)?;
    let ProductionSignerResponse::Success { result, .. } = &mut envelope_changed else {
        return Err("expected success".into());
    };
    result.envelope.request.digest = SERVICE_IMAGE.to_owned();
    assert!(
        envelope_changed
            .verify_cryptographic(&ProductionKeyPolicy::capability())
            .is_err()
    );
    Ok(())
}

fn decode_sha256(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if value.len() != 64 {
        return Err("invalid digest length".into());
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(chunk[0])? << 4) | nibble(chunk[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, Box<dyn std::error::Error>> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("invalid digest encoding".into()),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
