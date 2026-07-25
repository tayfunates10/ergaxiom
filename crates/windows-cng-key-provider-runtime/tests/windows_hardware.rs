#![cfg(windows)]

use ergaxiom_windows_cng_key_provider_runtime::CngPlatformKeyProvider;
use ergaxiom_windows_production_signer_runtime::{
    AUTHENTICATED_CALLER_SCHEMA, AuthenticatedCallerIdentity, HardwareAssurance,
    ProductionKeyPolicy, SIGNER_SERVICE_IDENTITY_SCHEMA, SignerRequestBinding,
    SignerServiceIdentity,
};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn dedicated_tpm_gate_provisions_and_signs_without_exporting_private_material()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("ERGAXIOM_TPM_HARDWARE_TEST").as_deref() != Ok("1") {
        return Ok(());
    }

    let provider = CngPlatformKeyProvider::production();
    let policy = ProductionKeyPolicy::capability();
    let provisioning = provider.describe_or_provision_unverified(&policy, None)?;
    assert_eq!(
        provisioning.descriptor.assurance,
        HardwareAssurance::Unproven
    );
    assert_eq!(provisioning.descriptor.export_policy, "non-exportable");
    assert_eq!(provisioning.descriptor.algorithm, "ecdsa-p256-sha256");
    assert!(!provisioning.descriptor.public_key_base64url.is_empty());

    let caller = AuthenticatedCallerIdentity {
        schema_version: AUTHENTICATED_CALLER_SCHEMA.to_owned(),
        process_id: std::process::id(),
        process_creation_time_100ns: 1,
        principal_sid: "S-1-5-18".to_owned(),
        session_id: 0,
        executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
        executable_sha256: DIGEST.to_owned(),
    };
    let service = SignerServiceIdentity {
        schema_version: SIGNER_SERVICE_IDENTITY_SCHEMA.to_owned(),
        service_id: "ergaxiom.production-signer".to_owned(),
        instance_nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        process_id: std::process::id(),
        process_creation_time_100ns: 2,
        executable_sha256: DIGEST.to_owned(),
        started_at_epoch_s: 1,
    };
    let binding = SignerRequestBinding::build(DIGEST, &caller, &service, &policy)?;
    let signature =
        provider.sign_sha256_digest_unverified(&policy, &provisioning, &binding, DIGEST)?;
    assert!(!signature.signature_base64url.is_empty());
    assert_eq!(
        signature.public_key_digest,
        provisioning.descriptor.public_key_digest
    );
    assert_eq!(signature.request_binding_digest, binding.digest()?);
    Ok(())
}
