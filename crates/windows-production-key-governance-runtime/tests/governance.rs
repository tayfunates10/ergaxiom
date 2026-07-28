use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_windows_production_key_governance_runtime::{
    ProductionKeyGovernanceError, ProductionKeyRegistry, ProductionKeyStatus,
};
use ergaxiom_windows_production_signer_runtime::{
    HardwareAssurance, HardwareKeyDescriptor, ProductionKeyIdentity, ProductionKeyPolicy,
};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

const REASON_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn initial_registration_and_binding_are_canonical_and_public_only()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = ProductionKeyRegistry::default();
    let empty_digest = registry.registry_digest()?;
    let descriptor = descriptor(ProductionKeyIdentity::capability(), 7, true)?;
    let receipt = registry.insert_initial_guarded(0, &empty_digest, descriptor, 100, 2_000, 100)?;

    receipt.validate_seal()?;
    assert_eq!(registry.revision(), 1);
    let binding = registry.trust_binding(&ProductionKeyIdentity::capability(), 1, 500)?;
    let record = registry.verify_binding(&binding, 500)?;
    assert_eq!(record.status, ProductionKeyStatus::Active);
    assert_eq!(record.generation, 1);
    let encoded = serde_json::to_string(&(receipt, binding, record))?;
    assert!(!encoded.contains("private_key"));
    assert!(!encoded.contains("seed"));
    Ok(())
}

#[test]
fn guarded_rotation_retires_old_generation_and_activates_successor()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = ProductionKeyIdentity::capability();
    let mut registry = registry_with_initial(identity.clone(), 7)?;
    let revision = registry.revision();
    let digest = registry.registry_digest()?;
    let receipt = registry.rotate_guarded(
        revision,
        &digest,
        &identity,
        1,
        descriptor(identity.clone(), 8, true)?,
        1_200,
        1_300,
        3_000,
    )?;

    receipt.validate_seal()?;
    assert_eq!(receipt.previous_generation, Some(1));
    let old = registry.resolve(&identity, 1, 1_250)?;
    assert_eq!(old.status, ProductionKeyStatus::Retired);
    assert_eq!(old.successor_generation, Some(2));
    assert!(matches!(
        registry.resolve(&identity, 1, 1_300),
        Err(ProductionKeyGovernanceError::KeyExpired)
    ));
    assert!(matches!(
        registry.resolve(&identity, 2, 1_199),
        Err(ProductionKeyGovernanceError::KeyNotYetValid)
    ));
    assert_eq!(registry.resolve(&identity, 2, 1_200)?.generation, 2);
    Ok(())
}

#[test]
fn stale_revision_digest_and_public_key_reuse_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let identity = ProductionKeyIdentity::capability();
    let mut registry = registry_with_initial(identity.clone(), 7)?;
    let current_digest = registry.registry_digest()?;

    assert!(matches!(
        registry.rotate_guarded(
            0,
            &current_digest,
            &identity,
            1,
            descriptor(identity.clone(), 8, true)?,
            1_200,
            1_300,
            3_000,
        ),
        Err(ProductionKeyGovernanceError::RegistryRevisionMismatch { .. })
    ));
    assert!(matches!(
        registry.rotate_guarded(
            registry.revision(),
            REASON_DIGEST,
            &identity,
            1,
            descriptor(identity.clone(), 8, true)?,
            1_200,
            1_300,
            3_000,
        ),
        Err(ProductionKeyGovernanceError::RegistryDigestMismatch)
    ));

    let reused = descriptor(identity.clone(), 7, true)?;
    assert!(matches!(
        registry.rotate_guarded(
            registry.revision(),
            &current_digest,
            &identity,
            1,
            reused,
            1_200,
            1_300,
            3_000,
        ),
        Err(ProductionKeyGovernanceError::PublicKeyReuse)
    ));
    Ok(())
}

#[test]
fn revocation_invalidates_the_generation_and_is_one_way() -> Result<(), Box<dyn std::error::Error>>
{
    let identity = ProductionKeyIdentity::attestation();
    let mut registry = registry_with_initial(identity.clone(), 9)?;
    let receipt = registry.revoke_guarded(
        registry.revision(),
        &registry.registry_digest()?,
        &identity,
        1,
        900,
        REASON_DIGEST,
    )?;
    receipt.validate_seal()?;

    assert!(matches!(
        registry.resolve(&identity, 1, 500),
        Err(ProductionKeyGovernanceError::KeyRevoked)
    ));
    assert!(matches!(
        registry.revoke_guarded(
            registry.revision(),
            &registry.registry_digest()?,
            &identity,
            1,
            901,
            REASON_DIGEST,
        ),
        Err(ProductionKeyGovernanceError::InvalidKeyState)
    ));
    Ok(())
}

#[test]
fn unproven_hardware_cannot_enter_the_production_registry() -> Result<(), Box<dyn std::error::Error>>
{
    let mut registry = ProductionKeyRegistry::default();
    let digest = registry.registry_digest()?;
    assert!(matches!(
        registry.insert_initial_guarded(
            0,
            &digest,
            descriptor(ProductionKeyIdentity::capability(), 7, false)?,
            100,
            2_000,
            100,
        ),
        Err(ProductionKeyGovernanceError::Production(
            ergaxiom_windows_production_signer_runtime::ProductionSignerError::HardwareAssuranceUnproven
        ))
    ));
    Ok(())
}

#[test]
fn trust_binding_substitution_and_stale_registry_snapshot_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = ProductionKeyIdentity::capability();
    let mut registry = registry_with_initial(identity.clone(), 7)?;
    let binding = registry.trust_binding(&identity, 1, 500)?;

    let mut altered = binding.clone();
    altered.public_key_digest = REASON_DIGEST.to_owned();
    assert!(matches!(
        registry.verify_binding(&altered, 500),
        Err(ProductionKeyGovernanceError::TrustBindingMismatch)
    ));

    registry.revoke_guarded(
        registry.revision(),
        &registry.registry_digest()?,
        &identity,
        1,
        900,
        REASON_DIGEST,
    )?;
    assert!(matches!(
        registry.verify_binding(&binding, 500),
        Err(ProductionKeyGovernanceError::RegistryRevisionMismatch { .. })
    ));
    Ok(())
}

fn registry_with_initial(
    identity: ProductionKeyIdentity,
    seed: u8,
) -> Result<ProductionKeyRegistry, Box<dyn std::error::Error>> {
    let mut registry = ProductionKeyRegistry::default();
    let digest = registry.registry_digest()?;
    registry.insert_initial_guarded(
        0,
        &digest,
        descriptor(identity, seed, true)?,
        100,
        2_000,
        100,
    )?;
    Ok(registry)
}

fn descriptor(
    identity: ProductionKeyIdentity,
    seed: u8,
    proven: bool,
) -> Result<HardwareKeyDescriptor, Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes((&[seed; 32]).into())?;
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let public_key = public_key.as_bytes();
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
        assurance: if proven {
            HardwareAssurance::ProvenHardwareBacked
        } else {
            HardwareAssurance::Unproven
        },
        policy_digest: policy.digest()?,
    })
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
