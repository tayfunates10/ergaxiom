use ergaxiom_windows_cng_key_provider_runtime::{CngPlatformKeyProvider, CngProviderError};
use ergaxiom_windows_production_signer_runtime::ProductionKeyPolicy;

#[test]
fn persisted_key_names_are_deterministic_and_role_separated()
-> Result<(), Box<dyn std::error::Error>> {
    let capability = CngPlatformKeyProvider::key_name_for(&ProductionKeyPolicy::capability())?;
    let capability_again =
        CngPlatformKeyProvider::key_name_for(&ProductionKeyPolicy::capability())?;
    let attestation = CngPlatformKeyProvider::key_name_for(&ProductionKeyPolicy::attestation())?;
    assert_eq!(capability, capability_again);
    assert_ne!(capability, attestation);
    assert!(capability.starts_with("Ergaxiom.Production."));
    assert!(!capability.contains("private"));
    assert!(!capability.contains("seed"));
    Ok(())
}

#[cfg(not(windows))]
#[test]
fn non_windows_platform_fails_closed_without_emulation() {
    let provider = CngPlatformKeyProvider::production();
    assert!(matches!(
        provider.probe(),
        Err(CngProviderError::UnsupportedPlatform)
    ));
    assert!(matches!(
        provider.describe_existing_unverified(&ProductionKeyPolicy::capability(), None),
        Err(CngProviderError::UnsupportedPlatform)
    ));
    #[cfg(feature = "provisioning")]
    assert!(matches!(
        provider.provision_unverified(&ProductionKeyPolicy::capability(), None),
        Err(CngProviderError::UnsupportedPlatform)
    ));
}

#[cfg(windows)]
#[test]
fn hosted_windows_probe_never_falls_back_to_software_provider()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = CngPlatformKeyProvider::production();
    match provider.probe() {
        Ok(probe) => {
            assert_eq!(probe.provider, "Microsoft Platform Crypto Provider");
            assert!(probe.hardware_flag_present);
            assert!(!probe.software_flag_present);
            assert_eq!(
                probe.assurance,
                ergaxiom_windows_production_signer_runtime::HardwareAssurance::Unproven
            );
        }
        Err(
            CngProviderError::ProviderOpenFailed(_)
            | CngProviderError::ProviderPropertyReadFailed(_)
            | CngProviderError::ProviderNotHardwareBacked
            | CngProviderError::ProviderReportedSoftware,
        ) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
