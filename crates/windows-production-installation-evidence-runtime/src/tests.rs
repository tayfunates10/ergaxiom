use ergaxiom_proof_kernel::canonical_json_sha256;
use ergaxiom_windows_production_signer_host_runtime::{
    PRODUCTION_SIGNER_ERROR_CONTROL, PRODUCTION_SIGNER_MAX_CONFIG_BYTES,
    PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS, PRODUCTION_SIGNER_REQUIRED_PRIVILEGE,
    PRODUCTION_SIGNER_RESTART_DELAYS_MS, PRODUCTION_SIGNER_SERVICE_ACCOUNT,
    PRODUCTION_SIGNER_SERVICE_DISPLAY_NAME, PRODUCTION_SIGNER_SERVICE_MANIFEST_SCHEMA,
    PRODUCTION_SIGNER_SERVICE_NAME, PRODUCTION_SIGNER_SERVICE_SID_TYPE,
    PRODUCTION_SIGNER_SERVICE_TYPE, PRODUCTION_SIGNER_START_MODE, ProductionSignerServiceManifest,
};
use ergaxiom_windows_production_signer_runtime::ProductionKeyIdentity;
use ergaxiom_windows_production_trust_state_runtime::ProductionTrustStateBinding;
use serde::Serialize;
use serde_json::Value;

use super::*;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const DIGEST_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const MANIFEST_PATH: &str = r"C:\ProgramData\Ergaxiom\Signer\manifest.json";
const EXECUTABLE_PATH: &str = r"C:\Program Files\Ergaxiom\signer.exe";

#[test]
fn valid_installation_receipt_is_canonical_and_contains_no_raw_machine_guid() {
    let receipt = valid_receipt();
    assert!(receipt.validate_seal().is_ok());
    let json = serde_json::to_string(&receipt)
        .unwrap_or_else(|error| panic!("serialize receipt failed: {error}"));
    assert!(!json.contains("00112233-4455-6677-8899-aabbccddeeff"));
    assert!(!json.contains("MachineGuid"));
}

#[test]
fn service_account_mutation_fails_even_after_resealing() {
    let mut receipt = valid_receipt();
    receipt.service_snapshot.service_account = "LocalService".to_owned();
    seal_snapshot(&mut receipt.service_snapshot);
    seal_receipt(&mut receipt);
    assert!(matches!(
        receipt.validate_seal(),
        Err(InstallationEvidenceError::ServiceHardeningMismatch)
    ));
}

#[test]
fn receipt_machine_identity_mutation_without_review_fails_seal() {
    let mut receipt = valid_receipt();
    receipt.machine_identity_digest = DIGEST_E.to_owned();
    assert!(matches!(
        receipt.validate_seal(),
        Err(InstallationEvidenceError::InstallationReceiptDigestMismatch)
    ));
}

#[test]
fn active_key_order_and_identity_substitution_fail_closed() {
    let mut receipt = valid_receipt();
    let mut attestation = receipt.active_keys[0].clone();
    attestation.identity = ProductionKeyIdentity::attestation();
    attestation.generation = 3;
    attestation.key_name = "Ergaxiom.Attestation.g00000000000000000003".to_owned();
    attestation.public_key_digest = DIGEST_E.to_owned();
    seal_observation(&mut attestation);
    receipt
        .enabled_identities
        .push(attestation.identity.clone());
    receipt.active_keys.push(attestation);
    seal_receipt(&mut receipt);
    assert!(receipt.validate_seal().is_ok());

    receipt.enabled_identities.swap(0, 1);
    receipt.active_keys.swap(0, 1);
    seal_receipt(&mut receipt);
    assert!(matches!(
        receipt.validate_seal(),
        Err(InstallationEvidenceError::CngObservationsNotCanonical)
    ));
}

#[test]
fn manifest_service_identity_mutation_fails_even_after_resealing() {
    let mut receipt = valid_receipt();
    receipt.manifest.service_name = "SubstitutedProductionSigner".to_owned();
    seal_manifest(&mut receipt.manifest);
    receipt.manifest_digest = receipt.manifest.manifest_digest.clone();
    seal_receipt(&mut receipt);
    assert!(receipt.validate_seal().is_err());
}

#[test]
fn recovery_requires_a_distinct_service_process_instance() {
    let before = valid_receipt();
    let mut after = before.clone();
    after.ceremony_id = "controlled-install.after".to_owned();
    after.observed_at_epoch_s += 10;
    seal_receipt(&mut after);
    let mut recovery = ProductionSignerRecoveryExerciseReceipt {
        schema_version: RECOVERY_EXERCISE_RECEIPT_SCHEMA.to_owned(),
        exercise_id: "controlled-recovery-1".to_owned(),
        deployment_id: before.deployment_id.clone(),
        started_at_epoch_s: before.observed_at_epoch_s,
        service_stopped_at_epoch_s: before.observed_at_epoch_s + 2,
        service_restarted_at_epoch_s: before.observed_at_epoch_s + 5,
        completed_at_epoch_s: after.observed_at_epoch_s,
        before,
        after,
        receipt_digest: String::new(),
    };
    seal_recovery(&mut recovery);
    assert!(matches!(
        recovery.validate_seal(),
        Err(InstallationEvidenceError::RecoveryExerciseDivergence)
    ));
}

#[test]
fn recovery_rejects_trust_state_rollback_or_fork() {
    let before = valid_receipt();
    let mut after = before.clone();
    after.ceremony_id = "controlled-install.after".to_owned();
    after.observed_at_epoch_s += 10;
    after.service_snapshot.process_id += 1;
    after.service_snapshot.process_creation_time_100ns += 1;
    seal_snapshot(&mut after.service_snapshot);
    after.trust_state_binding.state_digest = DIGEST_E.to_owned();
    seal_binding(&mut after.trust_state_binding);
    seal_receipt(&mut after);
    let mut recovery = ProductionSignerRecoveryExerciseReceipt {
        schema_version: RECOVERY_EXERCISE_RECEIPT_SCHEMA.to_owned(),
        exercise_id: "controlled-recovery-2".to_owned(),
        deployment_id: before.deployment_id.clone(),
        started_at_epoch_s: before.observed_at_epoch_s,
        service_stopped_at_epoch_s: before.observed_at_epoch_s + 2,
        service_restarted_at_epoch_s: before.observed_at_epoch_s + 5,
        completed_at_epoch_s: after.observed_at_epoch_s,
        before,
        after,
        receipt_digest: String::new(),
    };
    seal_recovery(&mut recovery);
    assert!(matches!(
        recovery.validate_seal(),
        Err(InstallationEvidenceError::RecoveryExerciseDivergence)
    ));
}

fn valid_receipt() -> ProductionSignerInstallationValidationReceipt {
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
        executable_path: EXECUTABLE_PATH.to_owned(),
        executable_sha256: DIGEST_A.to_owned(),
        trust_store_root: r"C:\ProgramData\Ergaxiom\Signer\trust".to_owned(),
        governance_policy_path: r"C:\ProgramData\Ergaxiom\Signer\governance.json".to_owned(),
        governance_policy_digest: DIGEST_B.to_owned(),
        caller_allowlist_path: r"C:\ProgramData\Ergaxiom\Signer\allowlist.json".to_owned(),
        caller_allowlist_revision: 2,
        caller_allowlist_digest: DIGEST_C.to_owned(),
        deployment_policy_path: r"C:\ProgramData\Ergaxiom\Signer\deployment.json".to_owned(),
        deployment_policy_revision: 3,
        deployment_policy_digest: DIGEST_D.to_owned(),
        pipe_allowed_principal_sid: "S-1-5-21-1000".to_owned(),
        max_config_file_bytes: PRODUCTION_SIGNER_MAX_CONFIG_BYTES,
        manifest_digest: String::new(),
    };
    seal_manifest(&mut manifest);

    let mut binding = ProductionTrustStateBinding {
        schema_version: "0.1.0".to_owned(),
        deployment_id: manifest.deployment_id.clone(),
        revision: 4,
        state_digest: DIGEST_A.to_owned(),
        envelope_digest: DIGEST_B.to_owned(),
        registry_revision: 5,
        registry_digest: DIGEST_C.to_owned(),
        caller_allowlist_revision: manifest.caller_allowlist_revision,
        caller_allowlist_digest: manifest.caller_allowlist_digest.clone(),
        signer_service_executable_digest: manifest.executable_sha256.clone(),
        service_policy_revision: manifest.deployment_policy_revision,
        service_policy_digest: manifest.deployment_policy_digest.clone(),
        binding_digest: String::new(),
    };
    seal_binding(&mut binding);

    let mut snapshot = InstalledProductionSignerServiceSnapshot {
        schema_version: INSTALLED_SERVICE_SNAPSHOT_SCHEMA.to_owned(),
        service_name: PRODUCTION_SIGNER_SERVICE_NAME.to_owned(),
        service_type: PRODUCTION_SIGNER_SERVICE_TYPE.to_owned(),
        start_mode: PRODUCTION_SIGNER_START_MODE.to_owned(),
        error_control: PRODUCTION_SIGNER_ERROR_CONTROL.to_owned(),
        binary_path: format!("\"{EXECUTABLE_PATH}\" --service --manifest \"{MANIFEST_PATH}\""),
        service_account: PRODUCTION_SIGNER_SERVICE_ACCOUNT.to_owned(),
        delayed_auto_start: true,
        service_sid_type: PRODUCTION_SIGNER_SERVICE_SID_TYPE.to_owned(),
        required_privileges: vec![PRODUCTION_SIGNER_REQUIRED_PRIVILEGE.to_owned()],
        failure_actions: vec![
            ServiceFailureActionObservation {
                action: "RESTART".to_owned(),
                delay_ms: PRODUCTION_SIGNER_RESTART_DELAYS_MS[0],
            },
            ServiceFailureActionObservation {
                action: "RESTART".to_owned(),
                delay_ms: PRODUCTION_SIGNER_RESTART_DELAYS_MS[1],
            },
            ServiceFailureActionObservation {
                action: "NONE".to_owned(),
                delay_ms: 0,
            },
        ],
        failure_actions_on_non_crash_failures: true,
        failure_reset_period_seconds: EXPECTED_FAILURE_RESET_PERIOD_SECONDS,
        preshutdown_timeout_ms: PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS,
        service_dacl_sddl: EXPECTED_SERVICE_DACL_SDDL.to_owned(),
        runtime_state: "RUNNING".to_owned(),
        process_id: 4001,
        process_creation_time_100ns: 5001,
        process_executable_path: EXECUTABLE_PATH.to_owned(),
        process_executable_sha256: manifest.executable_sha256.clone(),
        snapshot_digest: String::new(),
    };
    seal_snapshot(&mut snapshot);

    let mut observation = InstalledCngKeyObservation {
        schema_version: INSTALLED_CNG_KEY_OBSERVATION_SCHEMA.to_owned(),
        identity: ProductionKeyIdentity::capability(),
        generation: 2,
        key_name: "Ergaxiom.Capability.g00000000000000000002".to_owned(),
        public_key_digest: DIGEST_A.to_owned(),
        key_record_digest: DIGEST_B.to_owned(),
        policy_digest: DIGEST_C.to_owned(),
        descriptor_digest: DIGEST_D.to_owned(),
        provider_implementation_flags: 1,
        provider_hardware_flag_present: true,
        provider_software_flag_present: false,
        observation_digest: String::new(),
    };
    seal_observation(&mut observation);

    let mut receipt = ProductionSignerInstallationValidationReceipt {
        schema_version: INSTALLATION_VALIDATION_RECEIPT_SCHEMA.to_owned(),
        ceremony_id: "controlled-install-1".to_owned(),
        deployment_id: manifest.deployment_id.clone(),
        machine_identity_scheme: MACHINE_IDENTITY_SCHEME.to_owned(),
        machine_identity_digest: DIGEST_E.to_owned(),
        observed_at_epoch_s: 1_900_200_000,
        manifest_path: MANIFEST_PATH.to_owned(),
        manifest_digest: manifest.manifest_digest.clone(),
        governance_policy_digest: manifest.governance_policy_digest.clone(),
        manifest,
        trust_state_binding: binding,
        enabled_identities: vec![ProductionKeyIdentity::capability()],
        service_snapshot: snapshot,
        active_keys: vec![observation],
        pipe_probe_response_digest: DIGEST_D.to_owned(),
        receipt_digest: String::new(),
    };
    seal_receipt(&mut receipt);
    receipt
}

fn seal_manifest(value: &mut ProductionSignerServiceManifest) {
    value.manifest_digest = digest_with_blank(value, "manifest_digest");
}

fn seal_binding(value: &mut ProductionTrustStateBinding) {
    value.binding_digest = digest_with_blank(value, "binding_digest");
}

fn seal_snapshot(value: &mut InstalledProductionSignerServiceSnapshot) {
    value.snapshot_digest = digest_with_blank(value, "snapshot_digest");
}

fn seal_observation(value: &mut InstalledCngKeyObservation) {
    value.observation_digest = digest_with_blank(value, "observation_digest");
}

fn seal_receipt(value: &mut ProductionSignerInstallationValidationReceipt) {
    value.receipt_digest = digest_with_blank(value, "receipt_digest");
}

fn seal_recovery(value: &mut ProductionSignerRecoveryExerciseReceipt) {
    value.receipt_digest = digest_with_blank(value, "receipt_digest");
}

fn digest_with_blank<T: Serialize>(value: &T, field: &str) -> String {
    let mut json = serde_json::to_value(value)
        .unwrap_or_else(|error| panic!("serialize canonical test value failed: {error}"));
    let Some(object) = json.as_object_mut() else {
        panic!("canonical test value is not an object");
    };
    object.insert(field.to_owned(), Value::String(String::new()));
    canonical_json_sha256(&json)
        .unwrap_or_else(|error| panic!("hash canonical test value failed: {error}"))
}
