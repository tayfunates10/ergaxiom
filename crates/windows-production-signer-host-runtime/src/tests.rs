use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn sealed_manifest() -> Result<ProductionSignerServiceManifest, ProductionSignerHostError> {
    let root = std::env::temp_dir().join("ergaxiom-production-signer-contract");
    let mut manifest = ProductionSignerServiceManifest {
        schema_version: PRODUCTION_SIGNER_SERVICE_MANIFEST_SCHEMA.to_owned(),
        deployment_id: "ergaxiom-production-a".to_owned(),
        service_name: PRODUCTION_SIGNER_SERVICE_NAME.to_owned(),
        display_name: PRODUCTION_SIGNER_SERVICE_DISPLAY_NAME.to_owned(),
        service_account: PRODUCTION_SIGNER_SERVICE_ACCOUNT.to_owned(),
        service_type: PRODUCTION_SIGNER_SERVICE_TYPE.to_owned(),
        start_mode: PRODUCTION_SIGNER_START_MODE.to_owned(),
        error_control: PRODUCTION_SIGNER_ERROR_CONTROL.to_owned(),
        service_sid_type: PRODUCTION_SIGNER_SERVICE_SID_TYPE.to_owned(),
        required_privileges: vec![PRODUCTION_SIGNER_REQUIRED_PRIVILEGE.to_owned()],
        failure_restart_delays_ms: PRODUCTION_SIGNER_RESTART_DELAYS_MS.to_vec(),
        preshutdown_timeout_ms: PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS,
        executable_path: path_text(&root.join("ErgaxiomProductionSigner.exe"))?,
        executable_sha256: DIGEST_A.to_owned(),
        trust_store_root: path_text(&root.join("trust"))?,
        governance_policy_path: path_text(&root.join("governance.json"))?,
        governance_policy_digest: DIGEST_B.to_owned(),
        caller_allowlist_path: path_text(&root.join("allowlist.json"))?,
        caller_allowlist_revision: 7,
        caller_allowlist_digest: DIGEST_C.to_owned(),
        deployment_policy_path: path_text(&root.join("deployment.json"))?,
        deployment_policy_revision: 11,
        deployment_policy_digest: DIGEST_D.to_owned(),
        pipe_allowed_principal_sid: "S-1-5-18".to_owned(),
        max_config_file_bytes: PRODUCTION_SIGNER_MAX_CONFIG_BYTES,
        manifest_digest: String::new(),
    };
    manifest.manifest_digest = manifest.expected_digest()?;
    manifest.validate_seal()?;
    Ok(manifest)
}

#[test]
fn canonical_service_manifest_and_command_line_validate() -> Result<(), Box<dyn Error>> {
    let manifest = sealed_manifest()?;
    manifest.validate_seal()?;
    let manifest_path = std::env::temp_dir().join("ergaxiom-production-signer-manifest.json");
    let command = manifest.service_command_line(&manifest_path)?;
    assert!(command.starts_with('"'));
    assert!(command.contains(" --service --manifest \""));
    assert!(command.ends_with('"'));
    Ok(())
}

#[test]
fn scm_hardening_mutations_fail_closed() -> Result<(), Box<dyn Error>> {
    let manifest = sealed_manifest()?;
    let mutations: [fn(&mut ProductionSignerServiceManifest); 10] = [
        |value| value.service_name = "ErgaxiomSignerDev".to_owned(),
        |value| value.service_account = "LocalService".to_owned(),
        |value| value.service_type = "SHARED_PROCESS".to_owned(),
        |value| value.start_mode = "DEMAND".to_owned(),
        |value| value.error_control = "IGNORE".to_owned(),
        |value| value.service_sid_type = "NONE".to_owned(),
        |value| {
            value
                .required_privileges
                .push("SeDebugPrivilege".to_owned())
        },
        |value| value.failure_restart_delays_ms = vec![0, 0],
        |value| value.preshutdown_timeout_ms = 0,
        |value| value.max_config_file_bytes = 0,
    ];
    for mutate in mutations {
        let mut altered = manifest.clone();
        mutate(&mut altered);
        assert!(matches!(
            altered.validate_seal(),
            Err(ProductionSignerHostError::ServiceHardeningWeakened)
        ));
    }
    Ok(())
}

#[test]
fn path_and_manifest_substitution_fail_closed() -> Result<(), Box<dyn Error>> {
    let manifest = sealed_manifest()?;

    let mut relative = manifest.clone();
    relative.trust_store_root = "relative/trust".to_owned();
    relative.manifest_digest = relative.expected_digest()?;
    assert!(matches!(
        relative.validate_seal(),
        Err(ProductionSignerHostError::PathNotAbsolute)
    ));

    let mut quote_injection = manifest.clone();
    quote_injection.executable_path.push('"');
    quote_injection.manifest_digest = quote_injection.expected_digest()?;
    assert!(matches!(
        quote_injection.validate_seal(),
        Err(ProductionSignerHostError::InvalidPathEncoding)
    ));

    let mut digest_substitution = manifest.clone();
    digest_substitution.executable_sha256 = DIGEST_B.to_owned();
    assert!(matches!(
        digest_substitution.validate_seal(),
        Err(ProductionSignerHostError::ManifestDigestMismatch)
    ));
    Ok(())
}

#[test]
fn manifest_write_is_create_new_and_response_is_sealed() -> Result<(), Box<dyn Error>> {
    let manifest = sealed_manifest()?;
    let root = unique_test_root()?;
    fs::create_dir_all(&root)?;
    let destination = root.join("service-manifest.json");
    manifest.write_create_new(&destination)?;
    assert!(manifest.write_create_new(&destination).is_err());

    let bytes = fs::read(&destination)?;
    let stored: ProductionSignerServiceManifest = serde_json::from_slice(&bytes)?;
    stored.validate_seal()?;

    let mut rejected =
        ProductionSignerHostResponse::rejected(Some("request-1".to_owned()), "SIGNING_REJECTED")?;
    rejected.validate_seal()?;
    if let ProductionSignerHostResponse::Rejected { code, .. } = &mut rejected {
        *code = "ACCEPTED".to_owned();
    }
    assert!(matches!(
        rejected.validate_seal(),
        Err(ProductionSignerTransportError::HostResponseDigestMismatch)
    ));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn rejected_host_response_uses_the_client_wire_contract() -> Result<(), Box<dyn Error>> {
    let response =
        ProductionSignerHostResponse::rejected(Some("request-1".to_owned()), "SIGNING_REJECTED")?;
    let bytes = serde_json::to_vec(&response)?;
    assert!(matches!(
        ProductionSignerPipeClient.decode_host_response(&bytes, "request-1"),
        Err(ProductionSignerTransportError::HostRejected { code, .. })
            if code == "SIGNING_REJECTED"
    ));
    Ok(())
}

#[cfg(windows)]
#[test]
fn transport_failures_are_scoped_to_one_connection() {
    assert!(crate::windows::is_recoverable_connection_error(
        &ProductionSignerHostError::Transport(ProductionSignerTransportError::MessageSizeInvalid,),
    ));
    assert!(!crate::windows::is_recoverable_connection_error(
        &ProductionSignerHostError::ServiceHardeningWeakened,
    ));
}

#[cfg(not(windows))]
#[test]
fn scm_operations_are_unavailable_off_windows() -> Result<(), Box<dyn Error>> {
    let path = std::path::Path::new("/tmp/ergaxiom-production-service.json");
    assert!(matches!(
        install_service(path, 1),
        Err(ProductionSignerHostError::UnsupportedPlatform)
    ));
    assert!(matches!(
        validate_installed_service(path, 1),
        Err(ProductionSignerHostError::UnsupportedPlatform)
    ));
    assert!(matches!(
        uninstall_service(path),
        Err(ProductionSignerHostError::UnsupportedPlatform)
    ));
    assert!(matches!(
        validate_administrator_controlled_file(path),
        Err(ProductionSignerHostError::UnsupportedPlatform)
    ));
    assert!(matches!(
        validate_administrator_controlled_directory(path),
        Err(ProductionSignerHostError::UnsupportedPlatform)
    ));
    Ok(())
}

#[cfg(windows)]
#[test]
fn current_service_identity_binds_current_executable() -> Result<(), Box<dyn Error>> {
    let current = std::env::current_exe()?;
    let digest = hash_stable_file(&current, PRODUCTION_SIGNER_MAX_EXECUTABLE_BYTES)?;
    let identity = crate::windows::current_service_identity(
        "ergaxiom-production-signer",
        &current,
        &digest,
        trusted_test_time()?,
    )?;
    identity.validate()?;
    assert_eq!(identity.executable_sha256, digest);
    assert!(identity.instance_nonce.len() >= 64);
    Ok(())
}

fn unique_test_root() -> Result<PathBuf, Box<dyn Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "ergaxiom-service-host-{}-{nonce}",
        std::process::id()
    )))
}

#[cfg(windows)]
fn trusted_test_time() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
