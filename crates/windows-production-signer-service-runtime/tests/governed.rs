use std::cell::Cell;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_windows_production_key_governance_runtime::{
    ProductionKeyGovernanceError, ProductionKeyRegistry,
};
use ergaxiom_windows_production_signer_protocol_runtime::{
    ProductionSignerRequest, ProductionSignerResponse,
};
use ergaxiom_windows_production_signer_runtime::{
    AUTHENTICATED_CALLER_SCHEMA, AuthenticatedCallerIdentity, ECDSA_P256_SHA256, HardwareAssurance,
    HardwareKeyDescriptor, HardwareSignature, P1363_FIXED_64, ProductionKeyIdentity,
    ProductionKeyPolicy, SEC1_UNCOMPRESSED_P256, SIGNER_SERVICE_IDENTITY_SCHEMA,
    SignerRequestBinding, SignerServiceIdentity,
};
use ergaxiom_windows_production_signer_service_runtime::{
    GovernedProductionSignerTrustSnapshot, HardwareSignerBackend, HardwareSignerBackendError,
    ProductionSignerService, ProductionSignerServiceError, ProductionSignerTrustSnapshot,
};
use ergaxiom_windows_signer_service_identity_runtime::{
    AllowedSignerCaller, SignerCallerAllowlist,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};

const PAYLOAD_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CALLER_IMAGE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SERVICE_IMAGE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const REASON_DIGEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const SIGNED_AT: u64 = 1_800_000_100;

#[derive(Debug)]
struct FakeHardwareBackend {
    signing_key: SigningKey,
    sign_count: Cell<u32>,
}

impl FakeHardwareBackend {
    fn new(seed: u8) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            signing_key: SigningKey::from_bytes((&[seed; 32]).into())?,
            sign_count: Cell::new(0),
        })
    }
}

impl HardwareSignerBackend for FakeHardwareBackend {
    fn descriptor(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        let public_key = point.as_bytes();
        Ok(HardwareKeyDescriptor {
            identity: policy.identity.clone(),
            provider: policy.provider.clone(),
            algorithm: ECDSA_P256_SHA256.to_owned(),
            public_key_encoding: SEC1_UNCOMPRESSED_P256.to_owned(),
            public_key_base64url: URL_SAFE_NO_PAD.encode(public_key),
            public_key_digest: encode_hex(&Sha256::digest(public_key)),
            signature_encoding: P1363_FIXED_64.to_owned(),
            export_policy: policy.export_policy.clone(),
            provider_implementation_flags: 1,
            assurance: HardwareAssurance::ProvenHardwareBacked,
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
        let signature: Signature = self
            .signing_key
            .sign_prehash(
                &decode_sha256(digest)
                    .map_err(|_| HardwareSignerBackendError::new("DIGEST_DECODE_FAILED"))?,
            )
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

#[test]
fn governed_trust_accepts_exact_generation_and_registry_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let (package, signer_trust, descriptor) = signed_package("governed.capability.1001")?;
    let mut registry = ProductionKeyRegistry::default();
    let empty_digest = registry.registry_digest()?;
    registry.insert_initial_guarded(
        0,
        &empty_digest,
        descriptor,
        1_800_000_000,
        1_900_000_000,
        1_800_000_000,
    )?;
    let trust = GovernedProductionSignerTrustSnapshot {
        signer: signer_trust,
        key: registry.trust_binding(&ProductionKeyIdentity::capability(), 1, SIGNED_AT)?,
    };

    let envelope = package.verify_governed(&trust, &registry, SIGNED_AT)?;
    assert_eq!(envelope.request.digest, PAYLOAD_DIGEST);
    Ok(())
}

#[test]
fn revoked_or_stale_governed_trust_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (package, signer_trust, descriptor) = signed_package("governed.capability.1002")?;
    let identity = ProductionKeyIdentity::capability();
    let mut registry = ProductionKeyRegistry::default();
    let empty_digest = registry.registry_digest()?;
    registry.insert_initial_guarded(
        0,
        &empty_digest,
        descriptor,
        1_800_000_000,
        1_900_000_000,
        1_800_000_000,
    )?;
    let trust = GovernedProductionSignerTrustSnapshot {
        signer: signer_trust,
        key: registry.trust_binding(&identity, 1, SIGNED_AT)?,
    };

    registry.revoke_guarded(
        registry.revision(),
        &registry.registry_digest()?,
        &identity,
        1,
        SIGNED_AT + 1,
        REASON_DIGEST,
    )?;
    assert!(matches!(
        package.verify_governed(&trust, &registry, SIGNED_AT),
        Err(ProductionSignerServiceError::Governance(
            ProductionKeyGovernanceError::RegistryRevisionMismatch { .. }
        ))
    ));

    let current_binding = registry.trust_binding(&identity, 1, SIGNED_AT);
    assert!(matches!(
        current_binding,
        Err(ProductionKeyGovernanceError::KeyRevoked)
    ));
    Ok(())
}

#[test]
fn governed_public_key_or_generation_substitution_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let (package, signer_trust, descriptor) = signed_package("governed.capability.1003")?;
    let identity = ProductionKeyIdentity::capability();
    let mut registry = ProductionKeyRegistry::default();
    let empty_digest = registry.registry_digest()?;
    registry.insert_initial_guarded(
        0,
        &empty_digest,
        descriptor,
        1_800_000_000,
        1_900_000_000,
        1_800_000_000,
    )?;
    let mut trust = GovernedProductionSignerTrustSnapshot {
        signer: signer_trust,
        key: registry.trust_binding(&identity, 1, SIGNED_AT)?,
    };

    trust.key.generation = 2;
    assert!(package
        .verify_governed(&trust, &registry, SIGNED_AT)
        .is_err());

    let mut trust = GovernedProductionSignerTrustSnapshot {
        signer: trust.signer,
        key: registry.trust_binding(&identity, 1, SIGNED_AT)?,
    };
    trust.key.public_key_digest = REASON_DIGEST.to_owned();
    assert!(package
        .verify_governed(&trust, &registry, SIGNED_AT)
        .is_err());
    Ok(())
}

fn signed_package(
    request_id: &str,
) -> Result<
    (
        ergaxiom_windows_production_signer_service_runtime::AuthorizedProductionSignerPackage,
        ProductionSignerTrustSnapshot,
        HardwareKeyDescriptor,
    ),
    Box<dyn std::error::Error>,
> {
    let caller = caller();
    let service_identity = service_identity();
    let allowlist = allowlist()?;
    let mut service = ProductionSignerService::new(
        FakeHardwareBackend::new(9)?,
        service_identity.clone(),
        allowlist.clone(),
    )?;
    let request = ProductionSignerRequest::sign_digest(
        request_id,
        &ProductionKeyPolicy::capability(),
        PAYLOAD_DIGEST,
    )?;
    let package = service.handle_authenticated(&request, &caller, SIGNED_AT)?;
    let ProductionSignerResponse::Success { result, .. } = &package.signer_response else {
        return Err("expected production signer success".into());
    };
    let trust = ProductionSignerTrustSnapshot {
        identity: result.descriptor.identity.clone(),
        public_key_digest: result.descriptor.public_key_digest.clone(),
        allowlist_revision: allowlist.revision,
        allowlist_digest: allowlist.allowlist_digest,
        caller_identity_digest: caller.digest()?,
        signer_service_identity_digest: service_identity.digest()?,
    };
    Ok((package, trust, result.descriptor.clone()))
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
