use ergaxiom_windows_cng_key_provider_runtime::{CngPlatformKeyProvider, CngProviderError};
use ergaxiom_windows_production_signer_runtime::ProductionKeyPolicy;

#[test]
fn generation_one_preserves_the_original_persisted_key_name()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = ProductionKeyPolicy::capability();
    let legacy = CngPlatformKeyProvider::key_name_for(&policy)?;
    let generation_one = CngPlatformKeyProvider::key_name_for_generation(&policy, 1)?;
    assert_eq!(generation_one, legacy);
    assert_eq!(
        CngPlatformKeyProvider::generation_from_key_name(&policy, &legacy)?,
        1
    );
    Ok(())
}

#[test]
fn later_generations_are_deterministic_distinct_and_round_trip()
-> Result<(), Box<dyn std::error::Error>> {
    let capability = ProductionKeyPolicy::capability();
    let attestation = ProductionKeyPolicy::attestation();
    let capability_two = CngPlatformKeyProvider::key_name_for_generation(&capability, 2)?;
    let capability_two_again = CngPlatformKeyProvider::key_name_for_generation(&capability, 2)?;
    let capability_three = CngPlatformKeyProvider::key_name_for_generation(&capability, 3)?;
    let attestation_two = CngPlatformKeyProvider::key_name_for_generation(&attestation, 2)?;

    assert_eq!(capability_two, capability_two_again);
    assert_ne!(capability_two, capability_three);
    assert_ne!(capability_two, attestation_two);
    assert!(capability_two.ends_with(".g00000000000000000002"));
    assert_eq!(
        CngPlatformKeyProvider::generation_from_key_name(&capability, &capability_two)?,
        2
    );
    assert_eq!(
        CngPlatformKeyProvider::generation_from_key_name(&capability, &capability_three)?,
        3
    );
    Ok(())
}

#[test]
fn zero_and_noncanonical_generation_names_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = ProductionKeyPolicy::capability();
    assert!(matches!(
        CngPlatformKeyProvider::key_name_for_generation(&policy, 0),
        Err(CngProviderError::InvalidKeyGeneration)
    ));
    let base = CngPlatformKeyProvider::key_name_for(&policy)?;
    for altered in [
        format!("{base}.g2"),
        format!("{base}.g00000000000000000001"),
        format!("{base}.g00000000000000000000"),
        format!("{base}.g0000000000000000000x"),
        format!("{base}.g00000000000000000002.extra"),
    ] {
        assert!(matches!(
            CngPlatformKeyProvider::generation_from_key_name(&policy, &altered),
            Err(CngProviderError::InvalidKeyGenerationName)
        ));
    }
    Ok(())
}
