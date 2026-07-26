#![cfg_attr(not(windows), forbid(unsafe_code))]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_production_key_governance_runtime::ProductionKeyStatus;
use ergaxiom_windows_production_signer_runtime::{
    ProductionKeyIdentity, ProductionKeyPolicy, ProductionSignerError, validate_identifier,
    validate_sha256,
};
use ergaxiom_windows_production_trust_state_runtime::{
    ProductionTrustStateBinding, ProductionTrustStateError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    LoadedProductionSignerHostConfig, PRODUCTION_SIGNER_ERROR_CONTROL,
    PRODUCTION_SIGNER_MAX_CONFIG_BYTES, PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS,
    PRODUCTION_SIGNER_REQUIRED_PRIVILEGE, PRODUCTION_SIGNER_RESTART_DELAYS_MS,
    PRODUCTION_SIGNER_SERVICE_ACCOUNT, PRODUCTION_SIGNER_SERVICE_NAME,
    PRODUCTION_SIGNER_SERVICE_SID_TYPE, PRODUCTION_SIGNER_SERVICE_TYPE,
    PRODUCTION_SIGNER_START_MODE, ProductionSignerHostError, ProductionSignerServiceManifest,
};

pub const INSTALLED_SERVICE_SNAPSHOT_SCHEMA: &str = "0.1.0";
pub const INSTALLED_CNG_KEY_OBSERVATION_SCHEMA: &str = "0.1.0";
pub const INSTALLATION_VALIDATION_RECEIPT_SCHEMA: &str = "0.1.0";
pub const RECOVERY_EXERCISE_RECEIPT_SCHEMA: &str = "0.1.0";
pub const MACHINE_IDENTITY_SCHEME: &str = "windows-machine-guid-domain-sha256-v1";
pub const EXPECTED_SERVICE_DACL_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
pub const EXPECTED_FAILURE_RESET_PERIOD_SECONDS: u32 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceFailureActionObservation {
    pub action: String,
    pub delay_ms: u32,
}

impl ServiceFailureActionObservation {
    fn validate(&self) -> Result<(), InstallationEvidenceError> {
        match self.action.as_str() {
            "RESTART" => {
                if self.delay_ms == 0 {
                    return Err(InstallationEvidenceError::ServiceHardeningMismatch);
                }
            }
            "NONE" => {
                if self.delay_ms != 0 {
                    return Err(InstallationEvidenceError::ServiceHardeningMismatch);
                }
            }
            _ => return Err(InstallationEvidenceError::ServiceHardeningMismatch),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledProductionSignerServiceSnapshot {
    pub schema_version: String,
    pub service_name: String,
    pub service_type: String,
    pub start_mode: String,
    pub error_control: String,
    pub binary_path: String,
    pub service_account: String,
    pub delayed_auto_start: bool,
    pub service_sid_type: String,
    pub required_privileges: Vec<String>,
    pub failure_actions: Vec<ServiceFailureActionObservation>,
    pub failure_actions_on_non_crash_failures: bool,
    pub failure_reset_period_seconds: u32,
    pub preshutdown_timeout_ms: u32,
    pub service_dacl_sddl: String,
    pub runtime_state: String,
    pub process_id: u32,
    pub process_executable_path: String,
    pub process_executable_sha256: String,
    pub snapshot_digest: String,
}

impl InstalledProductionSignerServiceSnapshot {
    pub fn validate_for(
        &self,
        manifest: &ProductionSignerServiceManifest,
        manifest_path: &Path,
    ) -> Result<(), InstallationEvidenceError> {
        manifest.validate_seal()?;
        if self.schema_version != INSTALLED_SERVICE_SNAPSHOT_SCHEMA
            || self.service_name != PRODUCTION_SIGNER_SERVICE_NAME
            || self.service_type != PRODUCTION_SIGNER_SERVICE_TYPE
            || self.start_mode != PRODUCTION_SIGNER_START_MODE
            || self.error_control != PRODUCTION_SIGNER_ERROR_CONTROL
            || self.service_account != PRODUCTION_SIGNER_SERVICE_ACCOUNT
            || !self.delayed_auto_start
            || self.service_sid_type != PRODUCTION_SIGNER_SERVICE_SID_TYPE
            || self.required_privileges != vec![PRODUCTION_SIGNER_REQUIRED_PRIVILEGE.to_owned()]
            || self.failure_actions
                != vec![
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
                ]
            || !self.failure_actions_on_non_crash_failures
            || self.failure_reset_period_seconds != EXPECTED_FAILURE_RESET_PERIOD_SECONDS
            || self.preshutdown_timeout_ms != PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS
            || self.service_dacl_sddl != EXPECTED_SERVICE_DACL_SDDL
            || self.runtime_state != "RUNNING"
            || self.process_id == 0
            || self.process_executable_path != manifest.executable_path
            || self.process_executable_sha256 != manifest.executable_sha256
            || self.binary_path != manifest.service_command_line(manifest_path)?
        {
            return Err(InstallationEvidenceError::ServiceHardeningMismatch);
        }
        for action in &self.failure_actions {
            action.validate()?;
        }
        validate_sha256(&self.process_executable_sha256)?;
        validate_sha256(&self.snapshot_digest)?;
        if self.snapshot_digest != self.expected_digest()? {
            return Err(InstallationEvidenceError::ServiceSnapshotDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, InstallationEvidenceError> {
        digest_with_blank_field(self, "snapshot_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledCngKeyObservation {
    pub schema_version: String,
    pub identity: ProductionKeyIdentity,
    pub generation: u64,
    pub key_name: String,
    pub public_key_digest: String,
    pub key_record_digest: String,
    pub policy_digest: String,
    pub descriptor_digest: String,
    pub provider_implementation_flags: u32,
    pub provider_hardware_flag_present: bool,
    pub provider_software_flag_present: bool,
    pub observation_digest: String,
}

impl InstalledCngKeyObservation {
    pub fn validate(&self) -> Result<(), InstallationEvidenceError> {
        if self.schema_version != INSTALLED_CNG_KEY_OBSERVATION_SCHEMA
            || self.generation == 0
            || self.key_name.trim().is_empty()
            || !self.provider_hardware_flag_present
            || self.provider_software_flag_present
        {
            return Err(InstallationEvidenceError::CngObservationInvalid);
        }
        self.identity.validate()?;
        for digest in [
            &self.public_key_digest,
            &self.key_record_digest,
            &self.policy_digest,
            &self.descriptor_digest,
            &self.observation_digest,
        ] {
            validate_sha256(digest)?;
        }
        if self.observation_digest != self.expected_digest()? {
            return Err(InstallationEvidenceError::CngObservationDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, InstallationEvidenceError> {
        digest_with_blank_field(self, "observation_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSignerInstallationValidationReceipt {
    pub schema_version: String,
    pub ceremony_id: String,
    pub deployment_id: String,
    pub machine_identity_scheme: String,
    pub machine_identity_digest: String,
    pub observed_at_epoch_s: u64,
    pub manifest_path: String,
    pub manifest_digest: String,
    pub governance_policy_digest: String,
    pub trust_state_binding: ProductionTrustStateBinding,
    pub service_snapshot: InstalledProductionSignerServiceSnapshot,
    pub active_keys: Vec<InstalledCngKeyObservation>,
    pub pipe_probe_response_digest: String,
    pub receipt_digest: String,
}

impl ProductionSignerInstallationValidationReceipt {
    #[cfg(windows)]
    pub fn capture_live(
        manifest_path: &Path,
        ceremony_id: impl Into<String>,
        trusted_now_epoch_s: u64,
    ) -> Result<Self, InstallationEvidenceError> {
        platform::capture_installation_receipt(
            manifest_path,
            ceremony_id.into(),
            trusted_now_epoch_s,
        )
    }

    #[cfg(not(windows))]
    pub fn capture_live(
        _manifest_path: &Path,
        _ceremony_id: impl Into<String>,
        _trusted_now_epoch_s: u64,
    ) -> Result<Self, InstallationEvidenceError> {
        Err(InstallationEvidenceError::UnsupportedPlatform)
    }

    pub fn validate_seal(&self) -> Result<(), InstallationEvidenceError> {
        if self.schema_version != INSTALLATION_VALIDATION_RECEIPT_SCHEMA
            || self.machine_identity_scheme != MACHINE_IDENTITY_SCHEME
            || self.observed_at_epoch_s == 0
            || self.active_keys.is_empty()
        {
            return Err(InstallationEvidenceError::InstallationReceiptInvalid);
        }
        validate_identifier("installation_ceremony_id", &self.ceremony_id)?;
        validate_identifier("deployment_id", &self.deployment_id)?;
        for digest in [
            &self.machine_identity_digest,
            &self.manifest_digest,
            &self.governance_policy_digest,
            &self.pipe_probe_response_digest,
            &self.receipt_digest,
        ] {
            validate_sha256(digest)?;
        }
        self.trust_state_binding.validate_seal()?;
        if self.trust_state_binding.deployment_id != self.deployment_id {
            return Err(InstallationEvidenceError::InstallationTrustMismatch);
        }
        let manifest_path = require_absolute_path_text(&self.manifest_path)?;
        let manifest: ProductionSignerServiceManifest =
            read_bounded_json(&manifest_path, PRODUCTION_SIGNER_MAX_CONFIG_BYTES)?;
        manifest.validate_seal()?;
        if manifest.manifest_digest != self.manifest_digest
            || manifest.deployment_id != self.deployment_id
            || manifest.governance_policy_digest != self.governance_policy_digest
            || manifest.executable_sha256
                != self.trust_state_binding.signer_service_executable_digest
            || manifest.caller_allowlist_revision
                != self.trust_state_binding.caller_allowlist_revision
            || manifest.caller_allowlist_digest
                != self.trust_state_binding.caller_allowlist_digest
            || manifest.deployment_policy_revision
                != self.trust_state_binding.service_policy_revision
            || manifest.deployment_policy_digest
                != self.trust_state_binding.service_policy_digest
        {
            return Err(InstallationEvidenceError::InstallationTrustMismatch);
        }
        self.service_snapshot.validate_for(&manifest, &manifest_path)?;
        let mut previous: Option<(u8, String, String, u64)> = None;
        for observation in &self.active_keys {
            observation.validate()?;
            let key = canonical_identity_key(&observation.identity, observation.generation);
            if previous.as_ref().is_some_and(|candidate| candidate >= &key) {
                return Err(InstallationEvidenceError::CngObservationsNotCanonical);
            }
            previous = Some(key);
        }
        if self.receipt_digest != self.expected_digest()? {
            return Err(InstallationEvidenceError::InstallationReceiptDigestMismatch);
        }
        Ok(())
    }

    pub fn write_create_new(&self, destination: &Path) -> Result<(), InstallationEvidenceError> {
        self.validate_seal()?;
        write_create_new_json(self, destination)
    }

    fn expected_digest(&self) -> Result<String, InstallationEvidenceError> {
        digest_with_blank_field(self, "receipt_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSignerRecoveryExerciseReceipt {
    pub schema_version: String,
    pub exercise_id: String,
    pub deployment_id: String,
    pub started_at_epoch_s: u64,
    pub service_stopped_at_epoch_s: u64,
    pub service_restarted_at_epoch_s: u64,
    pub completed_at_epoch_s: u64,
    pub before: ProductionSignerInstallationValidationReceipt,
    pub after: ProductionSignerInstallationValidationReceipt,
    pub receipt_digest: String,
}

impl ProductionSignerRecoveryExerciseReceipt {
    #[cfg(windows)]
    pub fn execute_live(
        manifest_path: &Path,
        exercise_id: impl Into<String>,
        trusted_now_epoch_s: u64,
    ) -> Result<Self, InstallationEvidenceError> {
        platform::execute_recovery_exercise(
            manifest_path,
            exercise_id.into(),
            trusted_now_epoch_s,
        )
    }

    #[cfg(not(windows))]
    pub fn execute_live(
        _manifest_path: &Path,
        _exercise_id: impl Into<String>,
        _trusted_now_epoch_s: u64,
    ) -> Result<Self, InstallationEvidenceError> {
        Err(InstallationEvidenceError::UnsupportedPlatform)
    }

    pub fn validate_seal(&self) -> Result<(), InstallationEvidenceError> {
        if self.schema_version != RECOVERY_EXERCISE_RECEIPT_SCHEMA
            || self.started_at_epoch_s == 0
            || self.started_at_epoch_s > self.service_stopped_at_epoch_s
            || self.service_stopped_at_epoch_s > self.service_restarted_at_epoch_s
            || self.service_restarted_at_epoch_s > self.completed_at_epoch_s
        {
            return Err(InstallationEvidenceError::RecoveryExerciseInvalid);
        }
        validate_identifier("recovery_exercise_id", &self.exercise_id)?;
        validate_identifier("deployment_id", &self.deployment_id)?;
        self.before.validate_seal()?;
        self.after.validate_seal()?;
        if self.before.deployment_id != self.deployment_id
            || self.after.deployment_id != self.deployment_id
            || self.before.machine_identity_digest != self.after.machine_identity_digest
            || self.before.manifest_digest != self.after.manifest_digest
            || self.before.governance_policy_digest != self.after.governance_policy_digest
            || self.before.trust_state_binding != self.after.trust_state_binding
            || self.before.service_snapshot.binary_path != self.after.service_snapshot.binary_path
            || self.before.service_snapshot.process_id == self.after.service_snapshot.process_id
            || self.after.observed_at_epoch_s < self.before.observed_at_epoch_s
        {
            return Err(InstallationEvidenceError::RecoveryExerciseDivergence);
        }
        validate_sha256(&self.receipt_digest)?;
        if self.receipt_digest != self.expected_digest()? {
            return Err(InstallationEvidenceError::RecoveryExerciseDigestMismatch);
        }
        Ok(())
    }

    pub fn write_create_new(&self, destination: &Path) -> Result<(), InstallationEvidenceError> {
        self.validate_seal()?;
        write_create_new_json(self, destination)
    }

    fn expected_digest(&self) -> Result<String, InstallationEvidenceError> {
        digest_with_blank_field(self, "receipt_digest")
    }
}

fn canonical_identity_key(
    identity: &ProductionKeyIdentity,
    generation: u64,
) -> (u8, String, String, u64) {
    let role = match identity.role {
        ergaxiom_key_governance_runtime::IssuerRole::Execution => 0,
        ergaxiom_key_governance_runtime::IssuerRole::Normalization => 1,
        ergaxiom_key_governance_runtime::IssuerRole::Capability => 2,
        ergaxiom_key_governance_runtime::IssuerRole::Attestation => 3,
        ergaxiom_key_governance_runtime::IssuerRole::Release => 4,
    };
    (
        role,
        identity.issuer_id.clone(),
        identity.key_id.clone(),
        generation,
    )
}

fn require_absolute_path_text(value: &str) -> Result<PathBuf, InstallationEvidenceError> {
    if value.is_empty() || value.contains('\0') || value.contains('"') {
        return Err(InstallationEvidenceError::PathInvalid);
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(InstallationEvidenceError::PathInvalid);
    }
    Ok(path)
}

fn read_bounded_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    maximum_bytes: u64,
) -> Result<T, InstallationEvidenceError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(InstallationEvidenceError::PathInvalid);
    }
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        return Err(InstallationEvidenceError::PathInvalid);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_create_new_json<T: Serialize>(
    value: &T,
    destination: &Path,
) -> Result<(), InstallationEvidenceError> {
    if !destination.is_absolute() {
        return Err(InstallationEvidenceError::PathInvalid);
    }
    if std::fs::symlink_metadata(destination)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(InstallationEvidenceError::PathInvalid);
    }
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() as u64 > PRODUCTION_SIGNER_MAX_CONFIG_BYTES {
        return Err(InstallationEvidenceError::PathInvalid);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn digest_with_blank_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, InstallationEvidenceError> {
    let mut value = serde_json::to_value(value)?;
    let object = value
        .as_object_mut()
        .ok_or(InstallationEvidenceError::InvalidCanonicalObject)?;
    object.insert(field.to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use ergaxiom_windows_cng_key_provider_runtime::CngPlatformKeyProvider;
    use ergaxiom_windows_production_signer_transport_runtime::ProductionSignerPipeClient;
    use sha2::{Digest, Sha256};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_ALREADY_RUNNING,
        ERROR_SERVICE_NOT_ACTIVE, HANDLE, HKEY_LOCAL_MACHINE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::System::Registry::{
        RRF_RT_REG_SZ, RegGetValueW,
    };
    use windows_sys::Win32::System::Services::{
        ControlService, OpenSCManagerW, OpenServiceW, QueryServiceConfig2W,
        QueryServiceConfigW, QueryServiceObjectSecurity, QueryServiceStatusEx,
        SC_ACTION_NONE, SC_ACTION_RESTART, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_FAILURE_ACTIONS,
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONFIG_PRESHUTDOWN_INFO,
        SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, SERVICE_CONFIG_SERVICE_SID_INFO,
        SERVICE_CONTROL_STOP, SERVICE_DELAYED_AUTO_START_INFO, SERVICE_ERROR_SEVERE,
        SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW, SERVICE_PRESHUTDOWN_INFO,
        SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_REQUIRED_PRIVILEGES_INFOW,
        SERVICE_RUNNING, SERVICE_SID_INFO, SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_START,
        SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED,
        SERVICE_WIN32_OWN_PROCESS, StartServiceW,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    use super::*;
    use crate::{ProductionSignerHostResponse, hash_stable_file};

    const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
    const SDDL_REVISION_1: u32 = 1;
    const MAX_PROCESS_PATH_UNITS: usize = 32_768;
    const MAX_WAIT_ATTEMPTS: usize = 300;
    const WAIT_INTERVAL_MS: u64 = 100;
    const MACHINE_GUID_SUBKEY: &str = r"SOFTWARE\Microsoft\Cryptography";
    const MACHINE_GUID_VALUE: &str = "MachineGuid";
    const MACHINE_GUID_DOMAIN: &[u8] = b"ergaxiom-windows-machine-guid-v1";

    pub fn capture_installation_receipt(
        manifest_path: &Path,
        ceremony_id: String,
        trusted_now_epoch_s: u64,
    ) -> Result<ProductionSignerInstallationValidationReceipt, InstallationEvidenceError> {
        validate_identifier("installation_ceremony_id", &ceremony_id)?;
        let manifest_path = std::path::absolute(manifest_path)?;
        let loaded = LoadedProductionSignerHostConfig::load(&manifest_path, trusted_now_epoch_s)?;
        let service_snapshot = query_hardened_service_snapshot(&loaded.manifest, &manifest_path)?;
        let active_keys = observe_active_keys(&loaded, trusted_now_epoch_s)?;
        let pipe_probe_response_digest = probe_service_pipe()?;
        let mut receipt = ProductionSignerInstallationValidationReceipt {
            schema_version: INSTALLATION_VALIDATION_RECEIPT_SCHEMA.to_owned(),
            ceremony_id,
            deployment_id: loaded.manifest.deployment_id.clone(),
            machine_identity_scheme: MACHINE_IDENTITY_SCHEME.to_owned(),
            machine_identity_digest: machine_identity_digest()?,
            observed_at_epoch_s: trusted_now_epoch_s,
            manifest_path: path_text(&manifest_path)?,
            manifest_digest: loaded.manifest.manifest_digest.clone(),
            governance_policy_digest: loaded.governance_policy.policy_digest.clone(),
            trust_state_binding: loaded.accepted.binding().clone(),
            service_snapshot,
            active_keys,
            pipe_probe_response_digest,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate_seal()?;
        Ok(receipt)
    }

    pub fn execute_recovery_exercise(
        manifest_path: &Path,
        exercise_id: String,
        trusted_now_epoch_s: u64,
    ) -> Result<ProductionSignerRecoveryExerciseReceipt, InstallationEvidenceError> {
        validate_identifier("recovery_exercise_id", &exercise_id)?;
        let manifest_path = std::path::absolute(manifest_path)?;
        let before_id = format!("{exercise_id}.before");
        let after_id = format!("{exercise_id}.after");
        let before = capture_installation_receipt(
            &manifest_path,
            before_id,
            trusted_now_epoch_s,
        )?;
        let started_at_epoch_s = system_now_epoch_s()?;
        let service_stopped_at_epoch_s = stop_fixed_service()?;
        let service_restarted_at_epoch_s = start_fixed_service()?;
        let completed_at_epoch_s = system_now_epoch_s()?;
        let after = capture_installation_receipt(
            &manifest_path,
            after_id,
            completed_at_epoch_s,
        )?;
        let mut receipt = ProductionSignerRecoveryExerciseReceipt {
            schema_version: RECOVERY_EXERCISE_RECEIPT_SCHEMA.to_owned(),
            exercise_id,
            deployment_id: before.deployment_id.clone(),
            started_at_epoch_s,
            service_stopped_at_epoch_s,
            service_restarted_at_epoch_s,
            completed_at_epoch_s,
            before,
            after,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate_seal()?;
        Ok(receipt)
    }

    fn observe_active_keys(
        loaded: &LoadedProductionSignerHostConfig,
        trusted_now_epoch_s: u64,
    ) -> Result<Vec<InstalledCngKeyObservation>, InstallationEvidenceError> {
        let provider = CngPlatformKeyProvider::production();
        let probe = provider.probe()?;
        if !probe.hardware_flag_present || probe.software_flag_present {
            return Err(InstallationEvidenceError::CngObservationInvalid);
        }
        let mut observations = Vec::with_capacity(loaded.deployment_policy.enabled_identities.len());
        for identity in &loaded.deployment_policy.enabled_identities {
            let record = loaded
                .accepted
                .registry()
                .active_record(identity, trusted_now_epoch_s)?;
            if record.status != ProductionKeyStatus::Active {
                return Err(InstallationEvidenceError::CngObservationInvalid);
            }
            let policy = ProductionKeyPolicy::for_identity(identity.clone());
            let provisioning = provider.describe_existing_generation_unverified(
                &policy,
                record.generation,
                Some(&record.public_key_digest),
            )?;
            let descriptor = &provisioning.descriptor;
            if descriptor.identity != record.identity
                || descriptor.public_key_base64url != record.public_key_base64url
                || descriptor.public_key_digest != record.public_key_digest
                || descriptor.policy_digest != record.policy_digest
                || descriptor.provider != record.provider
                || descriptor.algorithm != record.algorithm
                || descriptor.public_key_encoding != record.public_key_encoding
                || descriptor.signature_encoding != record.signature_encoding
                || descriptor.export_policy != record.export_policy
            {
                return Err(InstallationEvidenceError::CngObservationInvalid);
            }
            let mut observation = InstalledCngKeyObservation {
                schema_version: INSTALLED_CNG_KEY_OBSERVATION_SCHEMA.to_owned(),
                identity: identity.clone(),
                generation: record.generation,
                key_name: provisioning.key_name,
                public_key_digest: record.public_key_digest.clone(),
                key_record_digest: record.record_digest.clone(),
                policy_digest: record.policy_digest.clone(),
                descriptor_digest: descriptor.digest()?,
                provider_implementation_flags: probe.implementation_flags,
                provider_hardware_flag_present: probe.hardware_flag_present,
                provider_software_flag_present: probe.software_flag_present,
                observation_digest: String::new(),
            };
            observation.observation_digest = observation.expected_digest()?;
            observation.validate()?;
            observations.push(observation);
        }
        observations.sort_by(|left, right| {
            canonical_identity_key(&left.identity, left.generation)
                .cmp(&canonical_identity_key(&right.identity, right.generation))
        });
        Ok(observations)
    }

    fn query_hardened_service_snapshot(
        manifest: &ProductionSignerServiceManifest,
        manifest_path: &Path,
    ) -> Result<InstalledProductionSignerServiceSnapshot, InstallationEvidenceError> {
        let scm = OwnedHandle::open_manager()?;
        let service_name = wide(PRODUCTION_SIGNER_SERVICE_NAME);
        let service = unsafe {
            OpenServiceW(
                scm.raw,
                service_name.as_ptr(),
                SERVICE_QUERY_CONFIG
                    | SERVICE_QUERY_STATUS
                    | SERVICE_START
                    | SERVICE_STOP
                    | READ_CONTROL_ACCESS,
            )
        };
        if service.is_null() {
            return Err(last_windows_error());
        }
        let service = OwnedHandle::owned(service);
        let base = query_base_config(service.raw)?;
        let delayed = query_config2::<SERVICE_DELAYED_AUTO_START_INFO>(
            service.raw,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
        )?;
        let sid = query_config2::<SERVICE_SID_INFO>(
            service.raw,
            SERVICE_CONFIG_SERVICE_SID_INFO,
        )?;
        let privileges = query_required_privileges(service.raw)?;
        let (failure_actions, failure_reset_period_seconds) = query_failure_actions(service.raw)?;
        let failure_flag = query_config2::<SERVICE_FAILURE_ACTIONS_FLAG>(
            service.raw,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
        )?;
        let preshutdown = query_config2::<SERVICE_PRESHUTDOWN_INFO>(
            service.raw,
            SERVICE_CONFIG_PRESHUTDOWN_INFO,
        )?;
        let dacl = query_service_dacl_sddl(service.raw)?;
        let status = query_status(service.raw)?;
        if status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
            return Err(InstallationEvidenceError::ServiceNotRunning);
        }
        let process_path = query_process_path(status.dwProcessId)?;
        let process_digest = hash_stable_file(
            Path::new(&process_path),
            crate::PRODUCTION_SIGNER_MAX_EXECUTABLE_BYTES,
        )?;
        let mut snapshot = InstalledProductionSignerServiceSnapshot {
            schema_version: INSTALLED_SERVICE_SNAPSHOT_SCHEMA.to_owned(),
            service_name: PRODUCTION_SIGNER_SERVICE_NAME.to_owned(),
            service_type: if base.service_type == SERVICE_WIN32_OWN_PROCESS {
                PRODUCTION_SIGNER_SERVICE_TYPE.to_owned()
            } else {
                format!("0x{:08x}", base.service_type)
            },
            start_mode: if base.start_type == windows_sys::Win32::System::Services::SERVICE_AUTO_START {
                PRODUCTION_SIGNER_START_MODE.to_owned()
            } else {
                format!("0x{:08x}", base.start_type)
            },
            error_control: if base.error_control == SERVICE_ERROR_SEVERE {
                PRODUCTION_SIGNER_ERROR_CONTROL.to_owned()
            } else {
                format!("0x{:08x}", base.error_control)
            },
            binary_path: base.binary_path,
            service_account: normalize_account(&base.account_name),
            delayed_auto_start: delayed.fDelayedAutostart != 0,
            service_sid_type: if sid.dwServiceSidType == SERVICE_SID_TYPE_UNRESTRICTED {
                PRODUCTION_SIGNER_SERVICE_SID_TYPE.to_owned()
            } else {
                format!("0x{:08x}", sid.dwServiceSidType)
            },
            required_privileges: privileges,
            failure_actions,
            failure_actions_on_non_crash_failures:
                failure_flag.fFailureActionsOnNonCrashFailures != 0,
            failure_reset_period_seconds,
            preshutdown_timeout_ms: preshutdown.dwPreshutdownTimeout,
            service_dacl_sddl: dacl,
            runtime_state: "RUNNING".to_owned(),
            process_id: status.dwProcessId,
            process_executable_path: process_path,
            process_executable_sha256: process_digest,
            snapshot_digest: String::new(),
        };
        snapshot.snapshot_digest = snapshot.expected_digest()?;
        snapshot.validate_for(manifest, manifest_path)?;
        Ok(snapshot)
    }

    fn probe_service_pipe() -> Result<String, InstallationEvidenceError> {
        let client = ProductionSignerPipeClient;
        let response: ProductionSignerHostResponse = client.exchange(
            &serde_json::json!({"deployment_evidence_probe": true}),
            64 * 1024,
            128 * 1024,
        )?;
        response.validate_seal()?;
        match response {
            ProductionSignerHostResponse::Rejected {
                code,
                response_digest,
                ..
            } if code == "REQUEST_REJECTED" => Ok(response_digest),
            _ => Err(InstallationEvidenceError::PipeProbeFailed),
        }
    }

    fn stop_fixed_service() -> Result<u64, InstallationEvidenceError> {
        let service = open_control_service()?;
        let status = query_status(service.raw)?;
        if status.dwCurrentState != SERVICE_STOPPED {
            let mut basic: SERVICE_STATUS = unsafe { zeroed() };
            if unsafe { ControlService(service.raw, SERVICE_CONTROL_STOP, &mut basic) } == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_SERVICE_NOT_ACTIVE as i32) {
                    return Err(InstallationEvidenceError::Windows(error));
                }
            }
            wait_for_state(service.raw, SERVICE_STOPPED)?;
        }
        system_now_epoch_s()
    }

    fn start_fixed_service() -> Result<u64, InstallationEvidenceError> {
        let service = open_control_service()?;
        let status = query_status(service.raw)?;
        if status.dwCurrentState != SERVICE_RUNNING {
            if unsafe { StartServiceW(service.raw, 0, null()) } == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32) {
                    return Err(InstallationEvidenceError::Windows(error));
                }
            }
            wait_for_state(service.raw, SERVICE_RUNNING)?;
        }
        system_now_epoch_s()
    }

    fn open_control_service() -> Result<OwnedHandle, InstallationEvidenceError> {
        let scm = OwnedHandle::open_manager()?;
        let service_name = wide(PRODUCTION_SIGNER_SERVICE_NAME);
        let service = unsafe {
            OpenServiceW(
                scm.raw,
                service_name.as_ptr(),
                SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP,
            )
        };
        if service.is_null() {
            return Err(last_windows_error());
        }
        Ok(OwnedHandle::owned(service))
    }

    fn wait_for_state(handle: isize, expected: u32) -> Result<(), InstallationEvidenceError> {
        for _ in 0..MAX_WAIT_ATTEMPTS {
            if query_status(handle)?.dwCurrentState == expected {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(WAIT_INTERVAL_MS));
        }
        Err(InstallationEvidenceError::ServiceStateTimeout)
    }

    fn query_status(handle: isize) -> Result<SERVICE_STATUS_PROCESS, InstallationEvidenceError> {
        let mut status: SERVICE_STATUS_PROCESS = unsafe { zeroed() };
        let mut needed = 0_u32;
        if unsafe {
            QueryServiceStatusEx(
                handle,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(last_windows_error());
        }
        Ok(status)
    }

    struct BaseConfig {
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_path: String,
        account_name: String,
    }

    fn query_base_config(handle: isize) -> Result<BaseConfig, InstallationEvidenceError> {
        let mut required = 0_u32;
        unsafe {
            let _ = QueryServiceConfigW(handle, null_mut(), 0, &mut required);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) || required == 0 {
            return Err(InstallationEvidenceError::Windows(error));
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        if unsafe {
            QueryServiceConfigW(
                handle,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(last_windows_error());
        }
        let config = unsafe {
            &*buffer
                .as_ptr()
                .cast::<windows_sys::Win32::System::Services::QUERY_SERVICE_CONFIGW>()
        };
        Ok(BaseConfig {
            service_type: config.dwServiceType,
            start_type: config.dwStartType,
            error_control: config.dwErrorControl,
            binary_path: wide_ptr_to_string(config.lpBinaryPathName)?,
            account_name: wide_ptr_to_string(config.lpServiceStartName)?,
        })
    }

    fn query_config2<T: Copy>(
        handle: isize,
        level: u32,
    ) -> Result<T, InstallationEvidenceError> {
        let bytes = query_config2_bytes(handle, level)?;
        if bytes.len() < size_of::<T>() {
            return Err(InstallationEvidenceError::ServiceHardeningMismatch);
        }
        Ok(unsafe { *(bytes.as_ptr().cast::<T>()) })
    }

    fn query_config2_bytes(
        handle: isize,
        level: u32,
    ) -> Result<Vec<usize>, InstallationEvidenceError> {
        let mut required = 0_u32;
        unsafe {
            let _ = QueryServiceConfig2W(handle, level, null_mut(), 0, &mut required);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) || required == 0 {
            return Err(InstallationEvidenceError::Windows(error));
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        if unsafe {
            QueryServiceConfig2W(
                handle,
                level,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(last_windows_error());
        }
        Ok(buffer)
    }

    fn query_required_privileges(handle: isize) -> Result<Vec<String>, InstallationEvidenceError> {
        let buffer = query_config2_bytes(handle, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)?;
        let info = unsafe { &*buffer.as_ptr().cast::<SERVICE_REQUIRED_PRIVILEGES_INFOW>() };
        read_multisz(info.pmszRequiredPrivileges)
    }

    fn query_failure_actions(
        handle: isize,
    ) -> Result<(Vec<ServiceFailureActionObservation>, u32), InstallationEvidenceError> {
        let buffer = query_config2_bytes(handle, SERVICE_CONFIG_FAILURE_ACTIONS)?;
        let info = unsafe { &*buffer.as_ptr().cast::<SERVICE_FAILURE_ACTIONSW>() };
        if info.cActions == 0 || info.lpsaActions.is_null() {
            return Err(InstallationEvidenceError::ServiceHardeningMismatch);
        }
        let actions = unsafe {
            std::slice::from_raw_parts(info.lpsaActions, info.cActions as usize)
        };
        let mut output = Vec::with_capacity(actions.len());
        for action in actions {
            let name = match action.Type {
                SC_ACTION_RESTART => "RESTART",
                SC_ACTION_NONE => "NONE",
                _ => return Err(InstallationEvidenceError::ServiceHardeningMismatch),
            };
            output.push(ServiceFailureActionObservation {
                action: name.to_owned(),
                delay_ms: action.Delay,
            });
        }
        Ok((output, info.dwResetPeriod))
    }

    fn query_service_dacl_sddl(handle: isize) -> Result<String, InstallationEvidenceError> {
        let mut required = 0_u32;
        unsafe {
            let _ = QueryServiceObjectSecurity(
                handle,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                0,
                &mut required,
            );
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) || required == 0 {
            return Err(InstallationEvidenceError::Windows(error));
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut descriptor = vec![0_usize; words];
        if unsafe {
            QueryServiceObjectSecurity(
                handle,
                DACL_SECURITY_INFORMATION,
                descriptor.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(last_windows_error());
        }
        let mut text = null_mut();
        if unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.as_ptr().cast_mut().cast(),
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            )
        } == 0
        {
            return Err(last_windows_error());
        }
        let text = LocalWideString { raw: text };
        wide_ptr_to_string(text.raw)
    }

    fn query_process_path(process_id: u32) -> Result<String, InstallationEvidenceError> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if process.is_null() {
            return Err(last_windows_error());
        }
        let process = KernelHandle { raw: process };
        let mut buffer = vec![0_u16; MAX_PROCESS_PATH_UNITS];
        let mut length = buffer.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(process.raw, 0, buffer.as_mut_ptr(), &mut length)
        } == 0
        {
            return Err(last_windows_error());
        }
        buffer.truncate(length as usize);
        let path = String::from_utf16(&buffer)
            .map_err(|_| InstallationEvidenceError::PathInvalid)?;
        let canonical = std::fs::canonicalize(path)?;
        path_text(&canonical)
    }

    fn machine_identity_digest() -> Result<String, InstallationEvidenceError> {
        let subkey = wide(MACHINE_GUID_SUBKEY);
        let value = wide(MACHINE_GUID_VALUE);
        let mut bytes = 0_u32;
        if unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                null_mut(),
                null_mut(),
                &mut bytes,
            )
        } != 0
            || bytes < 4
        {
            return Err(last_windows_error());
        }
        let mut buffer = vec![0_u16; (bytes as usize).div_ceil(2)];
        if unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        } != 0
        {
            return Err(last_windows_error());
        }
        while buffer.last() == Some(&0) {
            buffer.pop();
        }
        let value = String::from_utf16(&buffer)
            .map_err(|_| InstallationEvidenceError::MachineIdentityUnavailable)?;
        let normalized = value.trim().to_ascii_lowercase();
        if normalized.len() < 16 {
            return Err(InstallationEvidenceError::MachineIdentityUnavailable);
        }
        let mut hasher = Sha256::new();
        hasher.update(MACHINE_GUID_DOMAIN);
        hasher.update([0]);
        hasher.update(normalized.as_bytes());
        Ok(encode_hex(&hasher.finalize()))
    }

    fn normalize_account(value: &str) -> String {
        let normalized = value.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "localsystem" | ".\\localsystem") {
            PRODUCTION_SIGNER_SERVICE_ACCOUNT.to_owned()
        } else {
            value.to_owned()
        }
    }

    fn read_multisz(pointer: *mut u16) -> Result<Vec<String>, InstallationEvidenceError> {
        if pointer.is_null() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        let mut offset = 0_usize;
        loop {
            let start = unsafe { pointer.add(offset) };
            if unsafe { *start } == 0 {
                break;
            }
            let mut length = 0_usize;
            while unsafe { *start.add(length) } != 0 {
                length += 1;
                if length > 32_768 {
                    return Err(InstallationEvidenceError::ServiceHardeningMismatch);
                }
            }
            let units = unsafe { std::slice::from_raw_parts(start, length) };
            output.push(
                String::from_utf16(units)
                    .map_err(|_| InstallationEvidenceError::ServiceHardeningMismatch)?,
            );
            offset += length + 1;
        }
        Ok(output)
    }

    fn path_text(path: &Path) -> Result<String, InstallationEvidenceError> {
        path.to_str()
            .map(str::to_owned)
            .ok_or(InstallationEvidenceError::PathInvalid)
    }

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn wide_ptr_to_string(pointer: *mut u16) -> Result<String, InstallationEvidenceError> {
        if pointer.is_null() {
            return Err(InstallationEvidenceError::PathInvalid);
        }
        let mut length = 0_usize;
        while unsafe { *pointer.add(length) } != 0 {
            length += 1;
            if length > 65_536 {
                return Err(InstallationEvidenceError::PathInvalid);
            }
        }
        let units = unsafe { std::slice::from_raw_parts(pointer, length) };
        String::from_utf16(units).map_err(|_| InstallationEvidenceError::PathInvalid)
    }

    fn system_now_epoch_s() -> Result<u64, InstallationEvidenceError> {
        Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
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

    fn last_windows_error() -> InstallationEvidenceError {
        InstallationEvidenceError::Windows(std::io::Error::last_os_error())
    }

    struct OwnedHandle {
        raw: isize,
    }

    impl OwnedHandle {
        fn owned(raw: isize) -> Self {
            Self { raw }
        }

        fn open_manager() -> Result<Self, InstallationEvidenceError> {
            let raw = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
            if raw.is_null() {
                return Err(last_windows_error());
            }
            Ok(Self { raw })
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.raw.is_null() {
                let _ = unsafe { windows_sys::Win32::System::Services::CloseServiceHandle(self.raw) };
            }
        }
    }

    struct KernelHandle {
        raw: HANDLE,
    }

    impl Drop for KernelHandle {
        fn drop(&mut self) {
            if !self.raw.is_null() {
                let _ = unsafe { CloseHandle(self.raw) };
            }
        }
    }

    struct LocalWideString {
        raw: *mut u16,
    }

    impl Drop for LocalWideString {
        fn drop(&mut self) {
            if !self.raw.is_null() {
                let _ = unsafe { LocalFree(self.raw.cast()) };
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum InstallationEvidenceError {
    #[error("controlled-machine installation evidence is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("controlled-machine installation evidence path is invalid")]
    PathInvalid,
    #[error("controlled-machine installation evidence canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("installed production signer service hardening does not match the fixed contract")]
    ServiceHardeningMismatch,
    #[error("installed production signer service is not running")]
    ServiceNotRunning,
    #[error("installed production signer service state transition timed out")]
    ServiceStateTimeout,
    #[error("installed production signer service snapshot digest does not match")]
    ServiceSnapshotDigestMismatch,
    #[error("installed CNG key observation is invalid")]
    CngObservationInvalid,
    #[error("installed CNG key observation digest does not match")]
    CngObservationDigestMismatch,
    #[error("installed CNG key observations are not canonical and unique")]
    CngObservationsNotCanonical,
    #[error("production signer installation receipt is invalid")]
    InstallationReceiptInvalid,
    #[error("production signer installation receipt trust binding does not match")]
    InstallationTrustMismatch,
    #[error("production signer installation receipt digest does not match")]
    InstallationReceiptDigestMismatch,
    #[error("production signer recovery exercise receipt is invalid")]
    RecoveryExerciseInvalid,
    #[error("production signer recovery exercise diverged from the accepted installation state")]
    RecoveryExerciseDivergence,
    #[error("production signer recovery exercise digest does not match")]
    RecoveryExerciseDigestMismatch,
    #[error("production signer local pipe health probe failed")]
    PipeProbeFailed,
    #[error("Windows machine identity digest is unavailable")]
    MachineIdentityUnavailable,
    #[error("Windows installation evidence operation failed: {0}")]
    Windows(#[source] std::io::Error),
    #[error("system clock failed: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("installation evidence I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("installation evidence JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Host(#[from] ProductionSignerHostError),
    #[error(transparent)]
    ProductionSigner(#[from] ProductionSignerError),
    #[error(transparent)]
    TrustState(#[from] ProductionTrustStateError),
    #[error(transparent)]
    KeyGovernance(
        #[from] ergaxiom_windows_production_key_governance_runtime::ProductionKeyGovernanceError,
    ),
    #[error(transparent)]
    Cng(#[from] ergaxiom_windows_cng_key_provider_runtime::CngProviderError),
    #[error(transparent)]
    Transport(
        #[from] ergaxiom_windows_production_signer_transport_runtime::ProductionSignerTransportError,
    ),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}
