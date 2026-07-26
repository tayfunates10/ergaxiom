use std::cell::Cell;
use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
use ergaxiom_windows_production_key_governance_runtime::ProductionKeyRegistry;
use ergaxiom_windows_production_signer_protocol_runtime::ProductionSignerRequest;
use ergaxiom_windows_production_signer_runtime::{
    AUTHENTICATED_CALLER_SCHEMA, ECDSA_P256_SHA256, HardwareAssurance, HardwareKeyDescriptor,
    HardwareSignature, MICROSOFT_PLATFORM_CRYPTO_PROVIDER, NON_EXPORTABLE_POLICY, P1363_FIXED_64,
    ProductionKeyIdentity, ProductionKeyPolicy, SEC1_UNCOMPRESSED_P256, SIGNER_SERVICE_IDENTITY_SCHEMA,
    SignerRequestBinding, SignerServiceIdentity,
};
use ergaxiom_windows_production_signer_service_runtime::{
    GovernedProductionSignerTrustSnapshot, HardwareSignerBackend, HardwareSignerBackendError,
    ProductionSignerService, ProductionSignerTrustSnapshot,
};
use ergaxiom_windows_production_trust_state_runtime::{
    DeployedProductionSignerError, OfflineBootstrapExpectation, ProductionSignerDeploymentPolicy,
    ProductionTrustStateActivator, ProductionTrustStateBody, ProductionTrustStateEnvelope,
    TrustBoundProductionSignerService, TrustGovernanceKeyRecord, TrustGovernancePolicy,
    TrustGovernanceSignature, trust_state_signature_message,
};
use ergaxiom_windows_signer_service_identity_runtime::{
    AllowedSignerCaller, SignerCallerAllowlist,
};
use p256::ecdsa::{
    Signature, SigningKey,
    signature::hazmat::PrehashSigner,
};
use sha2::{Digest, Sha256};

const ACTIVATION: u64 = 1_900_100_000;
const CALLER_IMAGE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SERVICE_IMAGE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PAYLOAD_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[derive(Debug)]
struct GenerationBackend {
    generation_one: SigningKey,
    generation_two: SigningKey,
    selected_generation: Cell<u64>,
    substitute_generation_two: bool,
}

impl GenerationBackend {
    fn production() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            generation_one: SigningKey::from_bytes((&[17_u8; 32]).into())?,
            generation_two: SigningKey::from_bytes((&[23_u8; 32]).into())?,
            selected_generation: Cell::new(0),
            substitute_generation_two: false,
        })
    }

    fn with_generation_two_substitution() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            substitute_generation_two: true,
            ..Self::production()?
        })
    }

    fn key_for_generation(&self, generation: u64) -> Result<&SigningKey, HardwareSignerBackendError> {
        match generation {
            1 => Ok(&self.generation_one),
            2 if !self.substitute_generation_two => Ok(&self.generation_two),
            2 => Ok(&self.generation_one),
            _ => Err(HardwareSignerBackendError::new("KEY_GENERATION_UNSUPPORTED")),
        }
    }

    fn descriptor_for(
        &self,
        policy: &ProductionKeyPolicy,
        generation: u64,
    ) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
        descriptor_from_key(policy, self.key_for_generation(generation)?)
    }

    fn signature_for(
        &self,
        policy: &ProductionKeyPolicy,
        generation: u64,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, HardwareSignerBackendError> {
        self.selected_generation.set(generation);
        let key = self.key_for_generation(generation)?;
        let digest_bytes = decode_sha256(digest)?;
        let signature: Signature = key
            .sign_prehash(&digest_bytes)
            .map_err(|_| HardwareSignerBackendError::new("SIGN_FAILED"))?;
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
                .map_err(|_| HardwareSignerBackendError::new("BINDING_FAILED"))?,
        })
    }
}

impl HardwareSignerBackend for GenerationBackend {
    fn descriptor(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
        self.descriptor_for(policy, 1)
    }

    fn descriptor_for_generation(
        &self,
        policy: &ProductionKeyPolicy,
        generation: u64,
    ) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
        self.descriptor_for(policy, generation)
    }

    fn sign_sha256_digest(
        &self,
        policy: &ProductionKeyPolicy,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, HardwareSignerBackendError> {
        self.signature_for(policy, 1, descriptor, binding, digest)
    }

    fn sign_sha256_digest_for_generation(
        &self,
        policy: &ProductionKeyPolicy,
        generation: u64,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, HardwareSignerBackendError> {
        self.signature_for(policy, generation, descriptor, binding, digest)
    }
}

#[test]
fn deployed_service_selects_generation_two_and_hardware_signature_binds_exact_trust_state(
) -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::build(GenerationBackend::production()?)?;
    let mut deployed = TrustBoundProductionSignerService::new(
        fixture.service,
        fixture.accepted.clone(),
        fixture.deployment_policy.clone(),
    )?;
    let request = ProductionSignerRequest::sign_digest(
        "deployed-request-1",
        &ProductionKeyPolicy::capability(),
        PAYLOAD_DIGEST,
    )?;
    let package = deployed.handle_authenticated(&request, &fixture.caller, ACTIVATION + 2)?;
    let envelope = package.verify_deployed(
        &fixture.accepted,
        &fixture.deployment_policy,
        &fixture.service_identity,
        &fixture.governed_trust,
        ACTIVATION + 2,
    )?;
    assert_eq!(package.key_generation, 2);
    assert_eq!(fixture.selected_generation.get(), 2);
    assert_eq!(
        envelope.binding.trust_state_binding_digest.as_deref(),
        Some(fixture.accepted.binding().binding_digest.as_str())
    );
    Ok(())
}

#[test]
fn backend_generation_substitution_fails_before_service_start() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::build(GenerationBackend::with_generation_two_substitution()?)?;
    assert!(matches!(
        TrustBoundProductionSignerService::new(
            fixture.service,
            fixture.accepted,
            fixture.deployment_policy,
        ),
        Err(DeployedProductionSignerError::BackendRegistryMismatch)
    ));
    Ok(())
}

#[test]
fn stale_state_and_signed_binding_substitution_fail_closed() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::build(GenerationBackend::production()?)?;
    let mut deployed = TrustBoundProductionSignerService::new(
        fixture.service,
        fixture.accepted.clone(),
        fixture.deployment_policy.clone(),
    )?;
    let request = ProductionSignerRequest::sign_digest(
        "deployed-request-2",
        &ProductionKeyPolicy::capability(),
        PAYLOAD_DIGEST,
    )?;
    let package = deployed.handle_authenticated(&request, &fixture.caller, ACTIVATION + 2)?;

    let newer = fixture.next_accepted_state()?;
    assert!(matches!(
        package.verify_deployed(
            &newer,
            &fixture.deployment_policy,
            &fixture.service_identity,
            &fixture.governed_trust,
            ACTIVATION + 2,
        ),
        Err(DeployedProductionSignerError::TrustStateDivergence)
            | Err(DeployedProductionSignerError::ServiceTrustStateMismatch)
    ));

    let mut altered = package.clone();
    if let ergaxiom_windows_production_signer_protocol_runtime::ProductionSignerResponse::Success {
        result,
        ..
    } = &mut altered.signer_package.signer_response
    {
        result.envelope.binding.trust_state_binding_digest = Some(PAYLOAD_DIGEST.to_owned());
    }
    assert!(altered
        .verify_deployed(
            &fixture.accepted,
            &fixture.deployment_policy,
            &fixture.service_identity,
            &fixture.governed_trust,
            ACTIVATION + 2,
        )
        .is_err());
    Ok(())
}

struct Fixture {
    selected_generation: Cell<u64>,
    service: ProductionSignerService<GenerationBackend>,
    accepted: ergaxiom_windows_production_trust_state_runtime::VerifiedProductionTrustState,
    deployment_policy: ProductionSignerDeploymentPolicy,
    caller: ergaxiom_windows_production_signer_runtime::AuthenticatedCallerIdentity,
    service_identity: SignerServiceIdentity,
    governed_trust: GovernedProductionSignerTrustSnapshot,
    governance_key: Ed25519SigningKey,
    governance_policy: TrustGovernancePolicy,
}

impl Fixture {
    fn build(backend: GenerationBackend) -> Result<Self, Box<dyn Error>> {
        let selected_generation = backend.selected_generation.clone();
        let caller = caller_identity();
        let service_identity = service_identity();
        let allowlist = SignerCallerAllowlist::build(
            1,
            vec![AllowedSignerCaller {
                caller_id: "desktop-backend".to_owned(),
                principal_sid: caller.principal_sid.clone(),
                session_id: Some(caller.session_id),
                executable_path: caller.executable_path.clone(),
                executable_sha256: caller.executable_sha256.clone(),
            }],
        )?;
        let deployment_policy = ProductionSignerDeploymentPolicy::new(
            "ergaxiom-production-a",
            1,
            service_identity.service_id.clone(),
            "local-named-pipe-v1",
            64 * 1024,
            128 * 1024,
            vec![ProductionKeyIdentity::capability()],
        )?;

        let mut registry = ProductionKeyRegistry::default();
        let initial_digest = registry.registry_digest()?;
        registry.insert_initial_guarded(
            0,
            &initial_digest,
            descriptor_from_key(
                &ProductionKeyPolicy::capability(),
                &backend.generation_one,
            )?,
            ACTIVATION - 100,
            ACTIVATION + 1_000,
            ACTIVATION - 90,
        )?;
        let revision = registry.revision();
        let digest = registry.registry_digest()?;
        registry.rotate_guarded(
            revision,
            &digest,
            &ProductionKeyIdentity::capability(),
            1,
            descriptor_from_key(
                &ProductionKeyPolicy::capability(),
                &backend.generation_two,
            )?,
            ACTIVATION,
            ACTIVATION,
            ACTIVATION + 1_000,
        )?;

        let governance_key = Ed25519SigningKey::from_bytes(&[71_u8; 32]);
        let governance_policy = TrustGovernancePolicy::new(
            "production-trust-governance",
            1,
            1,
            vec![TrustGovernanceKeyRecord::new_active(
                "governance-root-a",
                governance_key.verifying_key().to_bytes(),
                ACTIVATION - 100,
                ACTIVATION + 10_000,
            )?],
        )?;
        let body = ProductionTrustStateBody::new(
            "ergaxiom-production-a",
            1,
            None,
            registry.snapshot(),
            allowlist.revision,
            allowlist.allowlist_digest.clone(),
            SERVICE_IMAGE,
            deployment_policy.revision,
            deployment_policy.policy_digest.clone(),
            ACTIVATION,
            ACTIVATION - 10,
            ACTIVATION + 1_000,
            1,
            "offline-recovery-v1",
        )?;
        let envelope = signed_state(&body, &governance_key, &governance_policy)?;
        let expectation = OfflineBootstrapExpectation::new(
            "ergaxiom-production-a",
            envelope.envelope_digest.clone(),
            governance_policy.policy_digest.clone(),
        )?;
        let mut activator = ProductionTrustStateActivator::default();
        let activated = activator.bootstrap(
            &envelope,
            &governance_policy,
            &expectation,
            ACTIVATION,
        )?;
        let accepted = activated.verified;

        let record = accepted.registry().active_record(
            &ProductionKeyIdentity::capability(),
            ACTIVATION + 2,
        )?;
        let signer_trust = ProductionSignerTrustSnapshot {
            identity: record.identity.clone(),
            public_key_digest: record.public_key_digest.clone(),
            allowlist_revision: allowlist.revision,
            allowlist_digest: allowlist.allowlist_digest.clone(),
            caller_identity_digest: caller.digest()?,
            signer_service_identity_digest: service_identity.digest()?,
        };
        let governed_trust = GovernedProductionSignerTrustSnapshot {
            signer: signer_trust,
            key: accepted.registry().trust_binding(
                &ProductionKeyIdentity::capability(),
                record.generation,
                ACTIVATION + 2,
            )?,
        };
        let service = ProductionSignerService::new(
            backend,
            service_identity.clone(),
            allowlist,
        )?;
        Ok(Self {
            selected_generation,
            service,
            accepted,
            deployment_policy,
            caller,
            service_identity,
            governed_trust,
            governance_key,
            governance_policy,
        })
    }

    fn next_accepted_state(
        &self,
    ) -> Result<ergaxiom_windows_production_trust_state_runtime::VerifiedProductionTrustState, Box<dyn Error>> {
        let body = ProductionTrustStateBody::new(
            "ergaxiom-production-a",
            2,
            Some(self.accepted.body().body_digest.clone()),
            self.accepted.body().registry.clone(),
            2,
            self.accepted.body().caller_allowlist_digest.clone(),
            SERVICE_IMAGE,
            self.deployment_policy.revision,
            self.deployment_policy.policy_digest.clone(),
            ACTIVATION + 1,
            ACTIVATION - 10,
            ACTIVATION + 1_000,
            1,
            "offline-recovery-v1",
        )?;
        Ok(signed_state(&body, &self.governance_key, &self.governance_policy)?
            .verify(&self.governance_policy, ACTIVATION + 2)?)
    }
}

fn signed_state(
    body: &ProductionTrustStateBody,
    governance_key: &Ed25519SigningKey,
    policy: &TrustGovernancePolicy,
) -> Result<ProductionTrustStateEnvelope, Box<dyn Error>> {
    let message = trust_state_signature_message(&body.body_digest)?;
    let signature = governance_key.sign(&message).to_bytes();
    Ok(ProductionTrustStateEnvelope::new(
        body.clone(),
        policy,
        vec![TrustGovernanceSignature::from_signature_bytes(
            "governance-root-a",
            body.body_digest.clone(),
            signature,
        )?],
    )?)
}

fn caller_identity() -> ergaxiom_windows_production_signer_runtime::AuthenticatedCallerIdentity {
    ergaxiom_windows_production_signer_runtime::AuthenticatedCallerIdentity {
        schema_version: AUTHENTICATED_CALLER_SCHEMA.to_owned(),
        process_id: 4001,
        process_creation_time_100ns: 5001,
        principal_sid: "S-1-5-21-1000".to_owned(),
        session_id: 1,
        executable_path: r"C:\Program Files\Ergaxiom\backend.exe".to_owned(),
        executable_sha256: CALLER_IMAGE.to_owned(),
    }
}

fn service_identity() -> SignerServiceIdentity {
    SignerServiceIdentity {
        schema_version: SIGNER_SERVICE_IDENTITY_SCHEMA.to_owned(),
        service_id: "ergaxiom-production-signer".to_owned(),
        process_id: 5001,
        process_creation_time_100ns: 6001,
        executable_sha256: SERVICE_IMAGE.to_owned(),
        started_at_epoch_s: ACTIVATION + 1,
        instance_nonce: "production-instance-a".to_owned(),
    }
}

fn descriptor_from_key(
    policy: &ProductionKeyPolicy,
    signing_key: &SigningKey,
) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
    let point = signing_key.verifying_key().to_encoded_point(false);
    let public = point.as_bytes();
    Ok(HardwareKeyDescriptor {
        identity: policy.identity.clone(),
        provider: MICROSOFT_PLATFORM_CRYPTO_PROVIDER.to_owned(),
        algorithm: ECDSA_P256_SHA256.to_owned(),
        public_key_encoding: SEC1_UNCOMPRESSED_P256.to_owned(),
        public_key_base64url: URL_SAFE_NO_PAD.encode(public),
        public_key_digest: encode_hex(&Sha256::digest(public)),
        signature_encoding: P1363_FIXED_64.to_owned(),
        export_policy: NON_EXPORTABLE_POLICY.to_owned(),
        provider_implementation_flags: 1,
        assurance: HardwareAssurance::ProvenHardwareBacked,
        policy_digest: policy
            .digest()
            .map_err(|_| HardwareSignerBackendError::new("POLICY_FAILED"))?,
    })
}

fn decode_sha256(value: &str) -> Result<[u8; 32], HardwareSignerBackendError> {
    if value.len() != 64 {
        return Err(HardwareSignerBackendError::new("DIGEST_INVALID"));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = nibble(chunk[0])? << 4 | nibble(chunk[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, HardwareSignerBackendError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(HardwareSignerBackendError::new("DIGEST_INVALID")),
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
