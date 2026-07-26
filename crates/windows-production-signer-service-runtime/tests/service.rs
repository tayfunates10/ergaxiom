use std::cell::Cell;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_windows_production_signer_protocol_runtime::{
    ProductionSignerRequest, ProductionSignerResponse,
};
use ergaxiom_windows_production_signer_runtime::{
    AUTHENTICATED_CALLER_SCHEMA, AuthenticatedCallerIdentity, ECDSA_P256_SHA256, HardwareAssurance,
    HardwareKeyDescriptor, HardwareSignature, P1363_FIXED_64, ProductionKeyPolicy,
    SEC1_UNCOMPRESSED_P256, SIGNER_SERVICE_IDENTITY_SCHEMA, SignerRequestBinding,
    SignerServiceIdentity,
};
use ergaxiom_windows_production_signer_service_runtime::{
    AuthorizedProductionSignerPackage, HardwareSignerBackend, HardwareSignerBackendError,
    ProductionSignerService, ProductionSignerServiceError, ProductionSignerTrustSnapshot,
};
use ergaxiom_windows_signer_service_identity_runtime::{
    AllowedSignerCaller, SignerCallerAllowlist, SignerIdentityError,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};

const PAYLOAD_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CALLER_IMAGE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SERVICE_IMAGE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const OTHER_DIGEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[derive(Debug)]
struct FakeHardwareBackend {
    signing_key: SigningKey,
    assurance: HardwareAssurance,
    fail_signing: Cell<bool>,
    sign_count: Cell<u32>,
}

impl FakeHardwareBackend {
    fn proven() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            signing_key: SigningKey::from_bytes((&[9_u8; 32]).into())?,
            assurance: HardwareAssurance::ProvenHardwareBacked,
            fail_signing: Cell::new(false),
            sign_count: Cell::new(0),
        })
    }

    fn unproven() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            assurance: HardwareAssurance::Unproven,
            ..Self::proven()?
        })
    }

    fn failing() -> Result<Self, Box<dyn std::error::Error>> {
        let backend = Self::proven()?;
        backend.fail_signing.set(true);
        Ok(backend)
    }
}

impl HardwareSignerBackend for FakeHardwareBackend {
    fn descriptor(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        let public_key = point.as_bytes();
        let public_key_digest = encode_hex(&Sha256::digest(public_key));
        Ok(HardwareKeyDescriptor {
            identity: policy.identity.clone(),
            provider: policy.provider.clone(),
            algorithm: ECDSA_P256_SHA256.to_owned(),
            public_key_encoding: SEC1_UNCOMPRESSED_P256.to_owned(),
            public_key_base64url: URL_SAFE_NO_PAD.encode(public_key),
            public_key_digest,
            signature_encoding: P1363_FIXED_64.to_owned(),
            export_policy: policy.export_policy.clone(),
            provider_implementation_flags: 1,
            assurance: self.assurance,
            policy_digest: policy
                .digest()
                .map_err(|_| HardwareSignerBackendError::new("POLICY_DIGEST_FAILED"))?,
        })
    }

    fn sign_sha256_digest(
        &self,
        policy: &ProductionKeyPolicy,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, HardwareSignerBackendError> {
        self.sign_count.set(self.sign_count.get().saturating_add(1));
        if self.fail_signing.get() {
            return Err(HardwareSignerBackendError::new("SIGNING_FAILED"));
        }
        let digest_bytes = decode_sha256(digest)
            .map_err(|_| HardwareSignerBackendError::new("DIGEST_DECODE_FAILED"))?;
        let signature: Signature = self
            .signing_key
            .sign_prehash(&digest_bytes)
            .map_err(|_| HardwareSignerBackendError::new("SIGNING_FAILED"))?;
        Ok(HardwareSignature {
            identity: policy.identity.clone(),
            algorithm: ECDSA_P256_SHA256.to_owned(),
            signature_encoding: P1363_FIXED_64.to_owned(),
            digest_algorithm: "sha256".to_owned(),
            digest: digest.to_owned(),
            signature_base64url: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            public_key_digest: descriptor.public_key_digest.clone(),
            key_policy_digest: descriptor.policy_digest.clone(),
            request_binding_digest: binding
                .digest()
                .map_err(|_| HardwareSignerBackendError::new("BINDING_DIGEST_FAILED"))?,
        })
    }
}

fn caller() -> AuthenticatedCallerIdentity {
    AuthenticatedCallerIdentity {
        schema_version: AUTHENTICATED_CALLER_SCHEMA.to_owned(),
        process_id: 7000,
        process_creation_time_100ns: 123_456_789,
        principal_sid: "S-1-5-21-1000".to_owned(),
        session_id: 2,
        executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
        executable_sha256: CALLER_IMAGE.to_owned(),
    }
}

fn service_identity() -> SignerServiceIdentity {
    SignerServiceIdentity {
        schema_version: SIGNER_SERVICE_IDENTITY_SCHEMA.to_owned(),
        service_id: "ergaxiom.production-signer".to_owned(),
        instance_nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        process_id: 7100,
        process_creation_time_100ns: 223_456_789,
        executable_sha256: SERVICE_IMAGE.to_owned(),
        started_at_epoch_s: 1_800_000_000,
    }
}

fn allowlist() -> Result<SignerCallerAllowlist, Box<dyn std::error::Error>> {
    Ok(SignerCallerAllowlist::build(
        1,
        vec![AllowedSignerCaller {
            caller_id: "ergaxiom.backend".to_owned(),
            principal_sid: "S-1-5-21-1000".to_owned(),
            session_id: Some(2),
            executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
            executable_sha256: CALLER_IMAGE.to_owned(),
        }],
    )?)
}

fn request(id: &str) -> Result<ProductionSignerRequest, Box<dyn std::error::Error>> {
    Ok(ProductionSignerRequest::sign_digest(
        id,
        &ProductionKeyPolicy::capability(),
        PAYLOAD_DIGEST,
    )?)
}

fn trust_snapshot(
    package: &AuthorizedProductionSignerPackage,
    caller: &AuthenticatedCallerIdentity,
    service: &SignerServiceIdentity,
    allowlist: &SignerCallerAllowlist,
) -> Result<ProductionSignerTrustSnapshot, Box<dyn std::error::Error>> {
    let ProductionSignerResponse::Success { result, .. } = &package.signer_response else {
        return Err("expected production signer success".into());
    };
    Ok(ProductionSignerTrustSnapshot {
        identity: result.descriptor.identity.clone(),
        public_key_digest: result.descriptor.public_key_digest.clone(),
        allowlist_revision: allowlist.revision,
        allowlist_digest: allowlist.allowlist_digest.clone(),
        caller_identity_digest: caller.digest()?,
        signer_service_identity_digest: service.digest()?,
    })
}

#[test]
fn exact_authenticated_request_reaches_verified_production_signature()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = FakeHardwareBackend::proven()?;
    let mut service = ProductionSignerService::new(backend, service_identity(), allowlist()?)?;
    let caller = caller();
    let package = service.handle_authenticated(
        &request("production.capability.sign.1001")?,
        &caller,
        1_800_000_100,
    )?;
    package.verify(&caller, service.service_identity(), service.allowlist())?;
    assert!(!package.signer_response.contains_private_material_field());
    Ok(())
}

#[test]
fn public_trust_snapshot_verifies_the_exact_package() -> Result<(), Box<dyn std::error::Error>> {
    let backend = FakeHardwareBackend::proven()?;
    let mut service = ProductionSignerService::new(backend, service_identity(), allowlist()?)?;
    let caller = caller();
    let package = service.handle_authenticated(
        &request("production.capability.sign.1010")?,
        &caller,
        1_800_000_100,
    )?;
    let trust = trust_snapshot(
        &package,
        &caller,
        service.service_identity(),
        service.allowlist(),
    )?;
    let envelope = package.verify_trusted(&trust)?;
    assert_eq!(envelope.request.digest, PAYLOAD_DIGEST);
    Ok(())
}

#[test]
fn public_trust_snapshot_substitution_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let backend = FakeHardwareBackend::proven()?;
    let mut service = ProductionSignerService::new(backend, service_identity(), allowlist()?)?;
    let caller = caller();
    let package = service.handle_authenticated(
        &request("production.capability.sign.1011")?,
        &caller,
        1_800_000_100,
    )?;
    let trust = trust_snapshot(
        &package,
        &caller,
        service.service_identity(),
        service.allowlist(),
    )?;

    for mutation in 0..5 {
        let mut altered = trust.clone();
        match mutation {
            0 => altered.public_key_digest = OTHER_DIGEST.to_owned(),
            1 => altered.allowlist_revision += 1,
            2 => altered.allowlist_digest = OTHER_DIGEST.to_owned(),
            3 => altered.caller_identity_digest = OTHER_DIGEST.to_owned(),
            4 => altered.signer_service_identity_digest = OTHER_DIGEST.to_owned(),
            _ => return Err("unexpected mutation".into()),
        }
        assert!(package.verify_trusted(&altered).is_err());
    }
    Ok(())
}

#[test]
fn unproven_descriptor_never_reaches_backend_signing() -> Result<(), Box<dyn std::error::Error>> {
    let backend = FakeHardwareBackend::unproven()?;
    let mut service = ProductionSignerService::new(backend, service_identity(), allowlist()?)?;
    assert!(matches!(
        service.handle_authenticated(
            &request("production.capability.sign.1002")?,
            &caller(),
            1_800_000_100,
        ),
        Err(ProductionSignerServiceError::Production(_))
    ));
    Ok(())
}

#[test]
fn backend_failure_consumes_request_replay_authorization() -> Result<(), Box<dyn std::error::Error>>
{
    let backend = FakeHardwareBackend::failing()?;
    let mut service = ProductionSignerService::new(backend, service_identity(), allowlist()?)?;
    let request = request("production.capability.sign.1003")?;
    assert!(matches!(
        service.handle_authenticated(&request, &caller(), 1_800_000_100),
        Err(ProductionSignerServiceError::Backend(_))
    ));
    assert!(matches!(
        service.handle_authenticated(&request, &caller(), 1_800_000_101),
        Err(ProductionSignerServiceError::Identity(
            SignerIdentityError::RequestReplayDetected
        ))
    ));
    Ok(())
}

#[test]
fn renderer_or_modified_backend_identity_is_rejected_before_signing()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = FakeHardwareBackend::proven()?;
    let mut service = ProductionSignerService::new(backend, service_identity(), allowlist()?)?;
    let mut untrusted = caller();
    untrusted.executable_path = r"C:\Program Files\Ergaxiom\ergaxiom-renderer.exe".to_owned();
    untrusted.executable_sha256 = SERVICE_IMAGE.to_owned();
    assert!(matches!(
        service.handle_authenticated(
            &request("production.capability.sign.1004")?,
            &untrusted,
            1_800_000_100,
        ),
        Err(ProductionSignerServiceError::Identity(
            SignerIdentityError::CallerNotAllowlisted
        ))
    ));
    Ok(())
}

#[test]
fn signer_service_instance_substitution_invalidates_package()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = FakeHardwareBackend::proven()?;
    let mut service = ProductionSignerService::new(backend, service_identity(), allowlist()?)?;
    let caller = caller();
    let package = service.handle_authenticated(
        &request("production.capability.sign.1005")?,
        &caller,
        1_800_000_100,
    )?;
    let mut restarted = service_identity();
    restarted.instance_nonce = "fedcba9876543210fedcba9876543210".to_owned();
    assert!(matches!(
        package.verify(&caller, &restarted, service.allowlist()),
        Err(ProductionSignerServiceError::Identity(
            SignerIdentityError::AuthorizationBindingMismatch
        ))
    ));
    Ok(())
}

fn decode_sha256(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if value.len() != 64 {
        return Err("invalid digest length".into());
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = nibble(chunk[0])? << 4 | nibble(chunk[1])?;
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
