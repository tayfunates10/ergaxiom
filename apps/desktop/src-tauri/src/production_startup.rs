use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_backend_issuance_runtime::{
    BackendProductionDeploymentManifest, LoadedBackendProductionDeployment,
};
use ergaxiom_windows_production_signer_host_runtime::ProductionSignerPipeClient;
use serde::Serialize;

const MANIFEST_PATH: Option<&str> = option_env!("ERGAXIOM_BACKEND_PRODUCTION_MANIFEST_PATH");
const MANIFEST_PIN_PATH: Option<&str> =
    option_env!("ERGAXIOM_BACKEND_PRODUCTION_MANIFEST_PIN_PATH");
const SHA256_HEX_BYTES: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionSignerStartupPhase {
    Unconfigured,
    UnsupportedPlatform,
    Configured,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSignerStatus {
    pub phase: ProductionSignerStartupPhase,
    pub code: &'static str,
    pub configuration_verified: bool,
    pub pipe_clients_initialized: bool,
    pub production_issuance_enabled: bool,
    pub deployment_id: Option<String>,
    pub backend_id: Option<String>,
    pub manifest_digest: Option<String>,
    pub trust_state_revision: Option<u64>,
    pub trust_state_binding_digest: Option<String>,
    pub registry_revision: Option<u64>,
    pub registry_digest: Option<String>,
    pub capability_generation: Option<u64>,
    pub attestation_generation: Option<u64>,
}

struct ProductionStartupRuntime {
    deployment: LoadedBackendProductionDeployment,
    capability_client: ProductionSignerPipeClient,
    attestation_client: ProductionSignerPipeClient,
}

impl ProductionStartupRuntime {
    fn new(deployment: LoadedBackendProductionDeployment) -> Self {
        Self {
            deployment,
            capability_client: ProductionSignerPipeClient,
            attestation_client: ProductionSignerPipeClient,
        }
    }

    fn clients_initialized(&self) -> bool {
        let _clients = (&self.capability_client, &self.attestation_client);
        true
    }

    fn public_status(&self) -> ProductionSignerStatus {
        configured_status(&self.deployment.manifest, self.clients_initialized())
    }
}

pub struct ProductionStartupState {
    status: ProductionSignerStatus,
    runtime: Option<ProductionStartupRuntime>,
}

impl ProductionStartupState {
    #[must_use]
    pub fn initialize() -> Self {
        if !cfg!(windows) {
            return Self::without_runtime(status_without_configuration(
                ProductionSignerStartupPhase::UnsupportedPlatform,
                "production_signer_unsupported_platform",
            ));
        }

        let (Some(manifest_path), Some(pin_path)) = (MANIFEST_PATH, MANIFEST_PIN_PATH) else {
            return Self::without_runtime(status_without_configuration(
                ProductionSignerStartupPhase::Unconfigured,
                "production_configuration_not_installed",
            ));
        };
        let (Some(manifest_path), Some(pin_path)) = (
            fixed_absolute_path(manifest_path),
            fixed_absolute_path(pin_path),
        ) else {
            return Self::without_runtime(status_without_configuration(
                ProductionSignerStartupPhase::Rejected,
                "production_configuration_path_rejected",
            ));
        };
        let Ok(expected_manifest_digest) = read_stable_manifest_pin(&pin_path) else {
            return Self::without_runtime(status_without_configuration(
                ProductionSignerStartupPhase::Rejected,
                "production_configuration_pin_rejected",
            ));
        };
        let Ok(current_executable) = std::env::current_exe() else {
            return Self::without_runtime(status_without_configuration(
                ProductionSignerStartupPhase::Rejected,
                "production_backend_identity_unavailable",
            ));
        };
        let Ok(trusted_now_epoch_s) = current_epoch_s() else {
            return Self::without_runtime(status_without_configuration(
                ProductionSignerStartupPhase::Rejected,
                "production_trusted_clock_unavailable",
            ));
        };
        let Ok(deployment) = BackendProductionDeploymentManifest::load_pinned(
            &manifest_path,
            &expected_manifest_digest,
            &current_executable,
            trusted_now_epoch_s,
        ) else {
            return Self::without_runtime(status_without_configuration(
                ProductionSignerStartupPhase::Rejected,
                "production_configuration_rejected",
            ));
        };

        let runtime = ProductionStartupRuntime::new(deployment);
        let status = runtime.public_status();
        Self {
            status,
            runtime: Some(runtime),
        }
    }

    #[must_use]
    pub fn status(&self) -> ProductionSignerStatus {
        if let Some(runtime) = &self.runtime {
            debug_assert!(runtime.clients_initialized());
        }
        self.status.clone()
    }

    fn without_runtime(status: ProductionSignerStatus) -> Self {
        Self {
            status,
            runtime: None,
        }
    }
}

#[tauri::command]
pub fn get_production_signer_status(
    state: tauri::State<'_, ProductionStartupState>,
) -> ProductionSignerStatus {
    state.status()
}

fn configured_status(
    manifest: &BackendProductionDeploymentManifest,
    pipe_clients_initialized: bool,
) -> ProductionSignerStatus {
    ProductionSignerStatus {
        phase: ProductionSignerStartupPhase::Configured,
        code: "production_configuration_verified",
        configuration_verified: true,
        pipe_clients_initialized,
        // Enabling issuance remains a separate gate. This slice only proves startup configuration
        // and retains real pipe clients inside the Rust backend.
        production_issuance_enabled: false,
        deployment_id: Some(manifest.deployment_id.clone()),
        backend_id: Some(manifest.backend_id.clone()),
        manifest_digest: Some(manifest.manifest_digest.clone()),
        trust_state_revision: Some(manifest.accepted_trust_state_revision),
        trust_state_binding_digest: Some(manifest.accepted_trust_state_binding_digest.clone()),
        registry_revision: Some(manifest.registry_revision),
        registry_digest: Some(manifest.registry_digest.clone()),
        capability_generation: Some(manifest.capability_key.generation),
        attestation_generation: Some(manifest.attestation_key.generation),
    }
}

fn status_without_configuration(
    phase: ProductionSignerStartupPhase,
    code: &'static str,
) -> ProductionSignerStatus {
    ProductionSignerStatus {
        phase,
        code,
        configuration_verified: false,
        pipe_clients_initialized: false,
        production_issuance_enabled: false,
        deployment_id: None,
        backend_id: None,
        manifest_digest: None,
        trust_state_revision: None,
        trust_state_binding_digest: None,
        registry_revision: None,
        registry_digest: None,
        capability_generation: None,
        attestation_generation: None,
    }
}

fn fixed_absolute_path(value: &str) -> Option<PathBuf> {
    if value.is_empty() || value.contains(['\0', '\n', '\r', '"']) {
        return None;
    }
    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}

fn read_stable_manifest_pin(path: &Path) -> Result<String, ()> {
    let before = fs::symlink_metadata(path).map_err(|_| ())?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() != SHA256_HEX_BYTES {
        return Err(());
    }
    let before_modified = before.modified().ok();
    let bytes = fs::read(path).map_err(|_| ())?;
    let after = fs::symlink_metadata(path).map_err(|_| ())?;
    if after.file_type().is_symlink()
        || !after.is_file()
        || after.len() != SHA256_HEX_BYTES
        || before.len() != after.len()
        || before_modified != after.modified().ok()
        || bytes.len() as u64 != SHA256_HEX_BYTES
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
    {
        return Err(());
    }
    String::from_utf8(bytes).map_err(|_| ())
}

fn current_epoch_s() -> Result<u64, ()> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use ergaxiom_windows_production_key_governance_runtime::{
        PRODUCTION_KEY_TRUST_BINDING_SCHEMA, ProductionKeyTrustBinding,
    };
    use ergaxiom_windows_production_signer_runtime::ProductionKeyIdentity;

    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    static NEXT_PIN: AtomicU64 = AtomicU64::new(1);

    fn key_binding(
        identity: ProductionKeyIdentity,
        generation: u64,
        digest: &str,
    ) -> ProductionKeyTrustBinding {
        ProductionKeyTrustBinding {
            schema_version: PRODUCTION_KEY_TRUST_BINDING_SCHEMA.to_owned(),
            identity,
            generation,
            public_key_digest: digest.to_owned(),
            key_record_digest: DIGEST_C.to_owned(),
            registry_revision: 7,
            registry_digest: DIGEST_B.to_owned(),
        }
    }

    fn public_manifest() -> BackendProductionDeploymentManifest {
        BackendProductionDeploymentManifest {
            schema_version: "0.1.0".to_owned(),
            deployment_id: "ergaxiom-production-a".to_owned(),
            backend_id: "ergaxiom.desktop.production".to_owned(),
            backend_caller_id: "ergaxiom.desktop.backend".to_owned(),
            backend_principal_sid: "S-1-5-21-1000".to_owned(),
            backend_session_id: Some(7),
            backend_executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-desktop.exe".to_owned(),
            backend_executable_sha256: DIGEST_A.to_owned(),
            signer_service_manifest_path: r"C:\ProgramData\Ergaxiom\signer.json".to_owned(),
            signer_service_manifest_digest: DIGEST_B.to_owned(),
            signer_service_executable_sha256: DIGEST_C.to_owned(),
            caller_allowlist_revision: 3,
            caller_allowlist_digest: DIGEST_A.to_owned(),
            deployment_policy_revision: 4,
            deployment_policy_digest: DIGEST_B.to_owned(),
            accepted_trust_state_revision: 5,
            minimum_accepted_trust_state_revision: 4,
            accepted_trust_state_binding_digest: DIGEST_C.to_owned(),
            registry_revision: 7,
            registry_digest: DIGEST_B.to_owned(),
            capability_key: key_binding(ProductionKeyIdentity::capability(), 2, DIGEST_A),
            attestation_key: key_binding(ProductionKeyIdentity::attestation(), 3, DIGEST_C),
            manifest_digest: DIGEST_A.to_owned(),
        }
    }

    fn pin_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "ergaxiom-production-pin-{}-{}",
            std::process::id(),
            NEXT_PIN.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn manifest_pin_requires_exact_lowercase_sha256_text() {
        let path = pin_path();
        fs::write(&path, DIGEST_A).expect("write canonical pin");
        assert_eq!(
            read_stable_manifest_pin(&path).expect("canonical pin must load"),
            DIGEST_A
        );

        fs::write(&path, DIGEST_A.to_uppercase()).expect("write uppercase pin");
        assert!(read_stable_manifest_pin(&path).is_err());
        fs::write(&path, format!("{DIGEST_A}\n")).expect("write newline pin");
        assert!(read_stable_manifest_pin(&path).is_err());
        fs::write(&path, &DIGEST_A[..63]).expect("write short pin");
        assert!(read_stable_manifest_pin(&path).is_err());
        fs::remove_file(path).expect("remove test pin");
    }

    #[test]
    fn configured_status_exposes_only_public_digests_and_keeps_issuance_disabled() {
        let status = configured_status(&public_manifest(), true);
        assert_eq!(status.phase, ProductionSignerStartupPhase::Configured);
        assert!(status.configuration_verified);
        assert!(status.pipe_clients_initialized);
        assert!(!status.production_issuance_enabled);
        assert_eq!(status.trust_state_revision, Some(5));
        assert_eq!(status.registry_revision, Some(7));
        assert_eq!(status.capability_generation, Some(2));
        assert_eq!(status.attestation_generation, Some(3));
        let value = serde_json::to_value(status).expect("serialize public status");
        let text = value.to_string();
        assert!(!text.contains("principal_sid"));
        assert!(!text.contains("executable_path"));
        assert!(!text.contains("signer_service_manifest_path"));
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_never_enables_production() {
        let state = ProductionStartupState::initialize();
        let status = state.status();
        assert_eq!(
            status.phase,
            ProductionSignerStartupPhase::UnsupportedPlatform
        );
        assert!(!status.configuration_verified);
        assert!(!status.pipe_clients_initialized);
        assert!(!status.production_issuance_enabled);
    }
}
