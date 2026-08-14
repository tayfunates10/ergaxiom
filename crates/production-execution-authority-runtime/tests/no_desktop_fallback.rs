const PRODUCTION_EXECUTION: &str =
    include_str!("../../../apps/desktop/src-tauri/src/production_execution.rs");
const PRODUCTION_PIPELINE: &str =
    include_str!("../../../apps/desktop/src-tauri/src/production_pipeline.rs");
const PRODUCTION_RECOVERY: &str =
    include_str!("../../../apps/desktop/src-tauri/src/production_recovery.rs");

#[test]
fn desktop_production_boundary_contains_no_development_signer_fallback() {
    let source = format!(
        "{PRODUCTION_EXECUTION}\n{PRODUCTION_PIPELINE}\n{PRODUCTION_RECOVERY}"
    );
    let lowercase = source.to_ascii_lowercase();

    for forbidden in [
        "signerprocessclient",
        "capabilityissuanceauthority",
        "attestationissuanceauthority",
        "dpapi",
        "ed25519",
        "microsoft software key storage provider",
        "software cng",
        "in-process signer",
        "in_process_signer",
    ] {
        assert!(
            !lowercase.contains(forbidden),
            "production desktop boundary contains forbidden fallback marker: {forbidden}"
        );
    }

    assert!(source.contains("ProductionSignerPipeClient"));
    assert!(source.contains("VerifiedProductionSignerTrustLease"));
    assert!(source.contains("PersistentProductionExecutionAuthority"));
    assert!(source.contains("verify_governed_production_attestation_against_bundle"));
}
