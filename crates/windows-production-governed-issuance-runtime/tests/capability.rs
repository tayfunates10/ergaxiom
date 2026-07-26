use std::cell::RefCell;
use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_capability_issuance_runtime::{
    CapabilityIssuanceError, CapabilityTokenDraft, ProductionCapabilitySignerTransport,
};
use ergaxiom_capability_runtime::{CapabilityBindings, CapabilityGrant, CapabilitySubject};
use ergaxiom_contract_runtime::PermissionAccess;
use ergaxiom_windows_production_governed_issuance_runtime::{
    GovernedProductionCapabilityIssuanceAuthority, GovernedProductionIssuanceError,
};
use ergaxiom_windows_production_key_governance_runtime::ProductionKeyRegistry;
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
    AuthorizedProductionSignerPackage, GovernedProductionSignerTrustSnapshot, HardwareSignerBackend,
    HardwareSignerBackendError, ProductionSignerService, ProductionSignerTrustSnapshot,
};
use ergaxiom_windows_signer_service_identity_runtime::{
    AllowedSignerCaller, SignerCallerAllowlist,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use serde_json::json;
use sha2::{Digest, Sha256};

const CALLER_IMAGE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SERVICE_IMAGE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const REASON_DIGEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const ISSUED_AT: u64 = 100;

#[derive(Debug)]
struct FakeHardwareBackend {
    signing_key: SigningKey,
}

impl HardwareSignerBackend for FakeHardwareBackend {
    fn descriptor(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
        descriptor_for_key(policy.identity.clone(), &self.signing_key)
            .map_err(|_| HardwareSignerBackendError::new("DESCRIPTOR_FAILED"))
    }

    fn sign_sha256_digest(
        &self,
        policy: &ProductionKeyPolicy,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, HardwareSignerBackendError> {
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

struct TestTransport {
    service: RefCell<ProductionSignerService<FakeHardwareBackend>>,
    caller: AuthenticatedCallerIdentity,
}

impl ProductionCapabilitySignerTransport for TestTransport {
    fn invoke(
        &self,
        request: &ProductionSignerRequest,
    ) -> Result<AuthorizedProductionSignerPackage, CapabilityIssuanceError> {
        self.service
            .borrow_mut()
            .handle_authenticated(request, &self.caller, 200)
            .map_err(CapabilityIssuanceError::ProductionSigner)
    }
}

#[test]
fn governed_capability_authority_issues_only_against_exact_registry_generation()
-> Result<(), Box<dyn Error>> {
    let (transport, trust, registry) = fixture(11)?;
    let authority = GovernedProductionCapabilityIssuanceAuthority::new(
        transport,
        trust.clone(),
        registry.clone(),
    )?;
    let token = authority.issue(draft())?;
    let envelope = token
        .signer_package
        .verify_governed(&trust, &registry, ISSUED_AT)?;
    assert_eq!(envelope.request.identity, ProductionKeyIdentity::capability());
    assert_eq!(envelope.request.digest.len(), 64);
    assert!(matches!(
        token.signer_package.signer_response,
        ProductionSignerResponse::Success { .. }
    ));
    Ok(())
}

#[test]
fn revoked_registry_rejects_stale_governed_authority_before_signing()
-> Result<(), Box<dyn Error>> {
    let (transport, trust, mut registry) = fixture(11)?;
    let identity = ProductionKeyIdentity::capability();
    registry.revoke_guarded(
        registry.revision(),
        &registry.registry_digest()?,
        &identity,
        1,
        300,
        REASON_DIGEST,
    )?;
    assert!(matches!(
        GovernedProductionCapabilityIssuanceAuthority::new(transport, trust, registry),
        Err(GovernedProductionIssuanceError::TrustRegistryMismatch)
    ));
    Ok(())
}

#[test]
fn rotated_registry_rejects_old_signer_public_key()
-> Result<(), Box<dyn Error>> {
    let (transport, old_trust, mut registry) = fixture(11)?;
    let identity = ProductionKeyIdentity::capability();
    registry.rotate_guarded(
        registry.revision(),
        &registry.registry_digest()?,
        &identity,
        1,
        descriptor_for_key(identity.clone(), &SigningKey::from_bytes((&[12_u8; 32]).into())?)?,
        150,
        160,
        1_500,
    )?;
    let new_binding = registry.trust_binding(&identity, 2, 200)?;
    let new_trust = GovernedProductionSignerTrustSnapshot {
        signer: ProductionSignerTrustSnapshot {
            public_key_digest: new_binding.public_key_digest.clone(),
            ..old_trust.signer
        },
        key: new_binding,
    };
    let authority = GovernedProductionCapabilityIssuanceAuthority::new(
        transport,
        new_trust,
        registry,
    )?;
    assert!(authority.issue(draft()).is_err());
    Ok(())
}

fn fixture(
    seed: u8,
) -> Result<
    (
        TestTransport,
        GovernedProductionSignerTrustSnapshot,
        ProductionKeyRegistry,
    ),
    Box<dyn Error>,
> {
    let signing_key = SigningKey::from_bytes((&[seed; 32]).into())?;
    let descriptor = descriptor_for_key(ProductionKeyIdentity::capability(), &signing_key)?;
    let caller = caller();
    let service_identity = service_identity();
    let allowlist = allowlist()?;
    let signer_trust = ProductionSignerTrustSnapshot {
        identity: descriptor.identity.clone(),
        public_key_digest: descriptor.public_key_digest.clone(),
        allowlist_revision: allowlist.revision,
        allowlist_digest: allowlist.allowlist_digest.clone(),
        caller_identity_digest: caller.digest()?,
        signer_service_identity_digest: service_identity.digest()?,
    };
    let mut registry = ProductionKeyRegistry::default();
    let empty_digest = registry.registry_digest()?;
    registry.insert_initial_guarded(0, &empty_digest, descriptor, 1, 1_000, 1)?;
    let trust = GovernedProductionSignerTrustSnapshot {
        signer: signer_trust,
        key: registry.trust_binding(&ProductionKeyIdentity::capability(), 1, ISSUED_AT)?,
    };
    let service = ProductionSignerService::new(
        FakeHardwareBackend { signing_key },
        service_identity,
        allowlist,
    )?;
    Ok((
        TestTransport {
            service: RefCell::new(service),
            caller,
        },
        trust,
        registry,
    ))
}

fn descriptor_for_key(
    identity: ProductionKeyIdentity,
    signing_key: &SigningKey,
) -> Result<HardwareKeyDescriptor, Box<dyn Error>> {
    let point = signing_key.verifying_key().to_encoded_point(false);
    let public_key = point.as_bytes();
    let policy = ProductionKeyPolicy::for_identity(identity.clone());
    Ok(HardwareKeyDescriptor {
        identity,
        provider: policy.provider.clone(),
        algorithm: policy.algorithm.clone(),
        public_key_encoding: policy.public_key_encoding.clone(),
        public_key_base64url: URL_SAFE_NO_PAD.encode(public_key),
        public_key_digest: encode_hex(&Sha256::digest(public_key)),
        signature_encoding: policy.signature_encoding.clone(),
        export_policy: policy.export_policy.clone(),
        provider_implementation_flags: 1,
        assurance: HardwareAssurance::ProvenHardwareBacked,
        policy_digest: policy.digest()?,
    })
}

fn draft() -> CapabilityTokenDraft {
    CapabilityTokenDraft {
        token_id: "token.capability.governed.0001".to_owned(),
        subject: CapabilitySubject {
            executor_id: "executor.windows.0001".to_owned(),
            device_id: Some("device.windows.0001".to_owned()),
        },
        issued_at_epoch_s: ISSUED_AT,
        not_before_epoch_s: ISSUED_AT,
        expires_at_epoch_s: 900,
        max_uses: 1,
        nonce: "nonce-capability-governed-0001".to_owned(),
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

fn caller() -> AuthenticatedCallerIdentity {
    AuthenticatedCallerIdentity {
        schema_version: AUTHENTICATED_CALLER_SCHEMA.to_owned(),
        process_id: 7200,
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
        process_id: 7300,
        process_creation_time_100ns: 223_456_789,
        executable_sha256: SERVICE_IMAGE.to_owned(),
        started_at_epoch_s: 50,
    }
}

fn allowlist() -> Result<SignerCallerAllowlist, Box<dyn Error>> {
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

fn decode_sha256(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    if value.len() != 64 {
        return Err("invalid digest length".into());
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = nibble(chunk[0])? << 4 | nibble(chunk[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, Box<dyn Error>> {
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
