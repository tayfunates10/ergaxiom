include!("authorization.rs");

use std::cell::RefCell;

use ergaxiom_attestation_issuance_runtime::ProductionAttestationSignerTransport;
use ergaxiom_backend_issuance_runtime::{
    BackendAuthorizedProductionIssuanceAuthority, BackendProductionIssuanceError,
};
use ergaxiom_capability_issuance_runtime::ProductionCapabilitySignerTransport;
use ergaxiom_windows_production_governed_issuance_runtime::verify_governed_production_attestation_against_bundle;
use ergaxiom_windows_production_key_governance_runtime::ProductionKeyRegistry;
use ergaxiom_windows_production_signer_protocol_runtime::ProductionSignerRequest;
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
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, signature::hazmat::PrehashSigner,
};
use sha2::{Digest as _, Sha256};

const PRODUCTION_CALLER_IMAGE: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PRODUCTION_SERVICE_IMAGE: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

type ProductionAuthority = BackendAuthorizedProductionIssuanceAuthority<
    ProductionTransport,
    ProductionTransport,
>;

#[derive(Debug)]
struct ProductionBackend {
    signing_key: P256SigningKey,
}

impl HardwareSignerBackend for ProductionBackend {
    fn descriptor(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
        production_descriptor(policy.identity.clone(), &self.signing_key)
    }

    fn sign_sha256_digest(
        &self,
        policy: &ProductionKeyPolicy,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, HardwareSignerBackendError> {
        let signature: P256Signature = self
            .signing_key
            .sign_prehash(&production_decode_sha256(digest)?)
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

struct ProductionTransport {
    service: RefCell<ProductionSignerService<ProductionBackend>>,
    caller: AuthenticatedCallerIdentity,
    calls: Rc<Cell<u32>>,
    reject: bool,
}

impl ProductionTransport {
    fn caller_for_request(&self) -> AuthenticatedCallerIdentity {
        let mut caller = self.caller.clone();
        if self.reject {
            caller.executable_sha256 = "f".repeat(64);
        }
        caller
    }
}

impl ProductionCapabilitySignerTransport for ProductionTransport {
    fn invoke(
        &self,
        request: &ProductionSignerRequest,
    ) -> Result<AuthorizedProductionSignerPackage, CapabilityIssuanceError> {
        self.calls.set(self.calls.get().saturating_add(1));
        self.service
            .borrow_mut()
            .handle_authenticated(request, &self.caller_for_request(), 4_000)
            .map_err(CapabilityIssuanceError::ProductionSigner)
    }
}

impl ProductionAttestationSignerTransport for ProductionTransport {
    fn invoke(
        &self,
        request: &ProductionSignerRequest,
    ) -> Result<AuthorizedProductionSignerPackage, AttestationIssuanceError> {
        self.calls.set(self.calls.get().saturating_add(1));
        self.service
            .borrow_mut()
            .handle_authenticated(request, &self.caller_for_request(), 4_000)
            .map_err(AttestationIssuanceError::ProductionSigner)
    }
}

struct ProductionFixture {
    authority: ProductionAuthority,
    capability_trust: GovernedProductionSignerTrustSnapshot,
    attestation_trust: GovernedProductionSignerTrustSnapshot,
    registry: ProductionKeyRegistry,
    capability_calls: Rc<Cell<u32>>,
    attestation_calls: Rc<Cell<u32>>,
}

#[test]
fn backend_authority_issues_governed_production_capability_and_attestation()
-> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = control_chain(&context)?;
    let mut fixture = production_fixture(false)?;

    let capability = fixture.authority.issue_capability(
        &chain.approved,
        &chain.approval,
        &chain.approve_receipt,
        &context.contract,
        &context.plan,
        capability_draft(&context),
        CAPABILITY_AT,
        60,
    )?;
    assert_eq!(capability.authorization.kind, BackendIssuanceKind::Capability);
    assert_eq!(fixture.capability_calls.get(), 1);
    let capability_envelope = capability.token.signer_package.verify_governed(
        &fixture.capability_trust,
        &fixture.registry,
        CAPABILITY_AT,
    )?;
    assert_eq!(
        capability_envelope.request.identity,
        ProductionKeyIdentity::capability()
    );

    let attestation = fixture.authority.issue_attestation(
        &chain.executed,
        &chain.approval,
        &chain.execute_receipt,
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        chain.attestation_draft,
        ATTESTATION_AT,
        60,
    )?;
    assert_eq!(attestation.authorization.kind, BackendIssuanceKind::Attestation);
    assert_eq!(fixture.attestation_calls.get(), 1);
    verify_governed_production_attestation_against_bundle(
        &attestation.package,
        &fixture.attestation_trust,
        &fixture.registry,
        context.contract,
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
    )?;
    Ok(())
}

#[test]
fn production_signer_rejection_consumes_authorization_and_never_falls_back()
-> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = control_chain(&context)?;
    let mut fixture = production_fixture(true)?;
    let draft = capability_draft(&context);

    assert!(matches!(
        fixture.authority.issue_capability(
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &context.contract,
            &context.plan,
            draft.clone(),
            CAPABILITY_AT,
            60,
        ),
        Err(BackendProductionIssuanceError::Governed(_))
    ));
    assert_eq!(fixture.capability_calls.get(), 1);

    assert!(matches!(
        fixture.authority.issue_capability(
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &context.contract,
            &context.plan,
            draft,
            CAPABILITY_AT,
            60,
        ),
        Err(BackendProductionIssuanceError::Authorization(
            BackendIssuanceError::IntentAlreadyAuthorized
        ))
    ));
    assert_eq!(fixture.capability_calls.get(), 1);
    assert_eq!(fixture.attestation_calls.get(), 0);
    Ok(())
}

fn production_fixture(reject_capability: bool) -> Result<ProductionFixture, Box<dyn Error>> {
    let capability_key = P256SigningKey::from_bytes((&[91_u8; 32]).into())?;
    let attestation_key = P256SigningKey::from_bytes((&[92_u8; 32]).into())?;
    let capability_policy = ProductionKeyPolicy::capability();
    let attestation_policy = ProductionKeyPolicy::attestation();
    let capability_descriptor =
        production_descriptor(capability_policy.identity.clone(), &capability_key)?;
    let attestation_descriptor =
        production_descriptor(attestation_policy.identity.clone(), &attestation_key)?;
    let caller = production_caller();
    let service_identity = production_service_identity();
    let allowlist = production_allowlist()?;

    let mut registry = ProductionKeyRegistry::default();
    let empty_digest = registry.registry_digest()?;
    registry.insert_initial_guarded(
        0,
        &empty_digest,
        capability_descriptor.clone(),
        1,
        10_000,
        1,
    )?;
    let capability_registry_digest = registry.registry_digest()?;
    registry.insert_initial_guarded(
        registry.revision(),
        &capability_registry_digest,
        attestation_descriptor.clone(),
        1,
        10_000,
        1,
    )?;

    let capability_trust = production_trust(
        &capability_descriptor,
        &caller,
        &service_identity,
        &allowlist,
        &registry,
        CAPABILITY_AT,
    )?;
    let attestation_trust = production_trust(
        &attestation_descriptor,
        &caller,
        &service_identity,
        &allowlist,
        &registry,
        ATTESTATION_AT,
    )?;
    let capability_calls = Rc::new(Cell::new(0));
    let attestation_calls = Rc::new(Cell::new(0));
    let capability_service = ProductionSignerService::new(
        ProductionBackend {
            signing_key: capability_key,
        },
        service_identity.clone(),
        allowlist.clone(),
    )?;
    let attestation_service = ProductionSignerService::new(
        ProductionBackend {
            signing_key: attestation_key,
        },
        service_identity,
        allowlist,
    )?;
    let authority = BackendAuthorizedProductionIssuanceAuthority::new(
        ProductionTransport {
            service: RefCell::new(capability_service),
            caller: caller.clone(),
            calls: capability_calls.clone(),
            reject: reject_capability,
        },
        capability_trust.clone(),
        ProductionTransport {
            service: RefCell::new(attestation_service),
            caller,
            calls: attestation_calls.clone(),
            reject: false,
        },
        attestation_trust.clone(),
        registry.clone(),
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    Ok(ProductionFixture {
        authority,
        capability_trust,
        attestation_trust,
        registry,
        capability_calls,
        attestation_calls,
    })
}

fn production_trust(
    descriptor: &HardwareKeyDescriptor,
    caller: &AuthenticatedCallerIdentity,
    service_identity: &SignerServiceIdentity,
    allowlist: &SignerCallerAllowlist,
    registry: &ProductionKeyRegistry,
    signed_at_epoch_s: u64,
) -> Result<GovernedProductionSignerTrustSnapshot, Box<dyn Error>> {
    Ok(GovernedProductionSignerTrustSnapshot {
        signer: ProductionSignerTrustSnapshot {
            identity: descriptor.identity.clone(),
            public_key_digest: descriptor.public_key_digest.clone(),
            allowlist_revision: allowlist.revision,
            allowlist_digest: allowlist.allowlist_digest.clone(),
            caller_identity_digest: caller.digest()?,
            signer_service_identity_digest: service_identity.digest()?,
        },
        key: registry.trust_binding(&descriptor.identity, 1, signed_at_epoch_s)?,
    })
}

fn production_descriptor(
    identity: ProductionKeyIdentity,
    signing_key: &P256SigningKey,
) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
    let point = signing_key.verifying_key().to_encoded_point(false);
    let public_key = point.as_bytes();
    let policy = ProductionKeyPolicy::for_identity(identity.clone());
    Ok(HardwareKeyDescriptor {
        identity,
        provider: policy.provider.clone(),
        algorithm: ECDSA_P256_SHA256.to_owned(),
        public_key_encoding: SEC1_UNCOMPRESSED_P256.to_owned(),
        public_key_base64url: URL_SAFE_NO_PAD.encode(public_key),
        public_key_digest: production_encode_hex(&Sha256::digest(public_key)),
        signature_encoding: P1363_FIXED_64.to_owned(),
        export_policy: policy.export_policy.clone(),
        provider_implementation_flags: 1,
        assurance: HardwareAssurance::ProvenHardwareBacked,
        policy_digest: policy
            .digest()
            .map_err(|_| HardwareSignerBackendError::new("POLICY_DIGEST_FAILED"))?,
    })
}

fn production_caller() -> AuthenticatedCallerIdentity {
    AuthenticatedCallerIdentity {
        schema_version: AUTHENTICATED_CALLER_SCHEMA.to_owned(),
        process_id: 8_100,
        process_creation_time_100ns: 123_456_789,
        principal_sid: "S-1-5-21-1000".to_owned(),
        session_id: 2,
        executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
        executable_sha256: PRODUCTION_CALLER_IMAGE.to_owned(),
    }
}

fn production_service_identity() -> SignerServiceIdentity {
    SignerServiceIdentity {
        schema_version: SIGNER_SERVICE_IDENTITY_SCHEMA.to_owned(),
        service_id: "ergaxiom.production-signer".to_owned(),
        instance_nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        process_id: 8_200,
        process_creation_time_100ns: 223_456_789,
        executable_sha256: PRODUCTION_SERVICE_IMAGE.to_owned(),
        started_at_epoch_s: 3_000,
    }
}

fn production_allowlist() -> Result<SignerCallerAllowlist, Box<dyn Error>> {
    Ok(SignerCallerAllowlist::build(
        1,
        vec![AllowedSignerCaller {
            caller_id: "ergaxiom.backend".to_owned(),
            principal_sid: "S-1-5-21-1000".to_owned(),
            session_id: Some(2),
            executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
            executable_sha256: PRODUCTION_CALLER_IMAGE.to_owned(),
        }],
    )?)
}

fn production_decode_sha256(
    value: &str,
) -> Result<[u8; 32], HardwareSignerBackendError> {
    if value.len() != 64 {
        return Err(HardwareSignerBackendError::new("DIGEST_LENGTH_INVALID"));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = production_nibble(chunk[0])? << 4 | production_nibble(chunk[1])?;
    }
    Ok(output)
}

fn production_nibble(value: u8) -> Result<u8, HardwareSignerBackendError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(HardwareSignerBackendError::new("DIGEST_ENCODING_INVALID")),
    }
}

fn production_encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
