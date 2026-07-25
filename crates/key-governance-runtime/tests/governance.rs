use std::error::Error;

use ed25519_dalek::SigningKey;
use ergaxiom_key_governance_runtime::{GovernedKeyRegistry, IssuerRole, KeyGovernanceError};

#[test]
fn cross_role_reuse_revocation_and_stale_updates_fail_closed() -> Result<(), Box<dyn Error>> {
    let capability_key = SigningKey::from_bytes(&[7_u8; 32]);
    let replacement_key = SigningKey::from_bytes(&[8_u8; 32]);
    let mut registry = GovernedKeyRegistry::default();

    registry.insert_ed25519(
        IssuerRole::Capability,
        "issuer.local",
        "capability.v1",
        capability_key.verifying_key().to_bytes(),
        100,
        1_000,
    )?;
    assert!(
        registry
            .resolve_ed25519(IssuerRole::Capability, "issuer.local", "capability.v1", 500,)
            .is_ok()
    );
    assert!(matches!(
        registry.resolve_ed25519(
            IssuerRole::Attestation,
            "issuer.local",
            "capability.v1",
            500,
        ),
        Err(KeyGovernanceError::RoleMismatch { .. })
    ));
    assert!(matches!(
        registry.insert_ed25519(
            IssuerRole::Attestation,
            "issuer.local",
            "attestation.alias",
            capability_key.verifying_key().to_bytes(),
            100,
            1_000,
        ),
        Err(KeyGovernanceError::PublicKeyReuse)
    ));

    let stale_revision = registry.revision();
    let stale_digest = registry.registry_digest()?;
    registry.revoke_ed25519_guarded(
        stale_revision,
        &stale_digest,
        IssuerRole::Capability,
        "issuer.local",
        "capability.v1",
        600,
        &"a".repeat(64),
    )?;
    assert!(matches!(
        registry.resolve_ed25519(IssuerRole::Capability, "issuer.local", "capability.v1", 500,),
        Err(KeyGovernanceError::KeyRevoked)
    ));
    assert!(matches!(
        registry.insert_ed25519_guarded(
            stale_revision,
            &stale_digest,
            IssuerRole::Capability,
            "issuer.local",
            "capability.v2",
            replacement_key.verifying_key().to_bytes(),
            600,
            2_000,
        ),
        Err(KeyGovernanceError::RegistryRevisionMismatch { .. })
    ));
    Ok(())
}

#[test]
fn rotation_preserves_only_the_declared_historical_window() -> Result<(), Box<dyn Error>> {
    let old_key = SigningKey::from_bytes(&[11_u8; 32]);
    let new_key = SigningKey::from_bytes(&[12_u8; 32]);
    let mut registry = GovernedKeyRegistry::default();
    registry.insert_ed25519(
        IssuerRole::Attestation,
        "attestation.local",
        "attestation.v1",
        old_key.verifying_key().to_bytes(),
        0,
        100,
    )?;
    let revision = registry.revision();
    let digest = registry.registry_digest()?;
    registry.rotate_ed25519_guarded(
        revision,
        &digest,
        IssuerRole::Attestation,
        "attestation.local",
        "attestation.v1",
        "attestation.v2",
        new_key.verifying_key().to_bytes(),
        50,
        60,
        200,
    )?;

    assert!(
        registry
            .resolve_ed25519(
                IssuerRole::Attestation,
                "attestation.local",
                "attestation.v1",
                59,
            )
            .is_ok()
    );
    assert!(matches!(
        registry.resolve_ed25519(
            IssuerRole::Attestation,
            "attestation.local",
            "attestation.v1",
            60,
        ),
        Err(KeyGovernanceError::KeyExpired)
    ));
    assert!(matches!(
        registry.resolve_ed25519(
            IssuerRole::Attestation,
            "attestation.local",
            "attestation.v2",
            49,
        ),
        Err(KeyGovernanceError::KeyNotYetValid)
    ));
    assert!(
        registry
            .resolve_ed25519(
                IssuerRole::Attestation,
                "attestation.local",
                "attestation.v2",
                50,
            )
            .is_ok()
    );
    Ok(())
}

#[test]
fn identical_mutation_sequences_produce_identical_registry_digests() -> Result<(), Box<dyn Error>> {
    let key = SigningKey::from_bytes(&[21_u8; 32]);
    let mut left = GovernedKeyRegistry::default();
    let mut right = GovernedKeyRegistry::default();
    for registry in [&mut left, &mut right] {
        registry.insert_ed25519(
            IssuerRole::Release,
            "release.local",
            "release.v1",
            key.verifying_key().to_bytes(),
            0,
            u64::MAX,
        )?;
    }
    assert_eq!(left.revision(), right.revision());
    assert_eq!(left.registry_digest()?, right.registry_digest()?);
    Ok(())
}
