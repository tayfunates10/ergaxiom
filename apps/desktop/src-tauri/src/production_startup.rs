use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_backend_issuance_runtime::{
    BackendProductionDeploymentManifest, LoadedBackendProductionDeployment,
};
use ergaxiom_windows_production_signer_host_runtime::{
    ProductionSignerPipeClient, validate_administrator_controlled_directory,
    validate_administrator_controlled_file,
};
use ergaxiom_windows_production_signer_runtime::SignerServiceIdentity;
use ergaxiom_windows_production_trust_state_runtime::ProductionSignerIdentityChallenge;
use serde::Serialize;

const MANIFEST_PATH: Option<&str> = option_env!("ERGAXIOM_BACKEND_PRODUCTION_MANIFEST_PATH");
const MANIFEST_PIN_PATH: Option<&str> =
    option_env!("ERGAXIOM_BACKEND_PRODUCTION_MANIFEST_PIN_PATH");
const SHA256_HEX_BYTES: u64 = 64;
const LIVE_IDENTITY_CHALLENGE_TTL_S: u64 = 30;
const MAX_RETIRED_IDENTITY_CHALLENGES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionSignerStartupPhase {
    Unconfigured,
    UnsupportedPlatform,
    Configured,
    LiveVerified,
    ServiceUnavailable,
    ServiceRejected,
    RecoveryRequired,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSignerStatus {
    pub phase: ProductionSignerStartupPhase,
    pub code: &'static str,
    pub configuration_verified: bool,
    pub configuration_acl_verified: bool,
    pub pipe_clients_initialized: bool,
    pub live_service_identity_verified: bool,
    pub service_restart_detected: bool,
    pub recovery_required: bool,
    pub last_identity_proof_epoch_s: Option<u64>,
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
    challenges: IdentityChallengeState,
    identity_gate: LiveIdentityGate,
    last_identity_proof_epoch_s: Option<u64>,
}

impl ProductionStartupRuntime {
    fn new(deployment: LoadedBackendProductionDeployment) -> Self {
        Self {
            deployment,
            capability_client: ProductionSignerPipeClient,
            attestation_client: ProductionSignerPipeClient,
            challenges: IdentityChallengeState::default(),
            identity_gate: LiveIdentityGate::default(),
            last_identity_proof_epoch_s: None,
        }
    }

    fn clients_initialized(&self) -> bool {
        let _clients = (&self.capability_client, &self.attestation_client);
        true
    }

    fn public_status(
        &self,
        phase: ProductionSignerStartupPhase,
        code: &'static str,
        live_service_identity_verified: bool,
    ) -> ProductionSignerStatus {
        live_status(
            &self.deployment.manifest,
            self.clients_initialized(),
            phase,
            code,
            live_service_identity_verified,
            self.identity_gate.recovery_required(),
            self.last_identity_proof_epoch_s,
        )
    }

    fn prove_live_identity(
        &mut self,
        trusted_now_epoch_s: u64,
    ) -> Result<SignerServiceIdentity, LiveProofFailure> {
        let challenge = self.issue_challenge(trusted_now_epoch_s)?;
        let challenge_digest = challenge.challenge_digest.clone();
        self.challenges
            .begin(challenge_digest.clone())
            .map_err(|()| {
                LiveProofFailure::rejected("production_identity_challenge_reuse_rejected")
            })?;

        let exchange = self.attestation_client.prove_identity(&challenge);
        self.challenges.retire(&challenge_digest).map_err(|()| {
            LiveProofFailure::rejected("production_identity_challenge_state_rejected")
        })?;
        let proof = exchange
            .map_err(|_| LiveProofFailure::unavailable("production_signer_service_unavailable"))?;

        if proof
            .signed_package
            .signer_package
            .caller_authorization
            .caller_id
            != self.deployment.manifest.backend_caller_id
        {
            return Err(LiveProofFailure::rejected(
                "production_signer_caller_binding_rejected",
            ));
        }

        proof
            .verify(
                &challenge,
                &self.deployment.signer.accepted,
                &self.deployment.signer.deployment_policy,
                trusted_now_epoch_s,
            )
            .map_err(|_| LiveProofFailure::rejected("production_signer_identity_proof_rejected"))
    }

    fn issue_challenge(
        &self,
        trusted_now_epoch_s: u64,
    ) -> Result<ProductionSignerIdentityChallenge, LiveProofFailure> {
        let client_nonce = random_sha256_hex()
            .map_err(|()| LiveProofFailure::rejected("production_identity_nonce_unavailable"))?;
        let expires_at_epoch_s = trusted_now_epoch_s
            .checked_add(LIVE_IDENTITY_CHALLENGE_TTL_S)
            .ok_or_else(|| {
                LiveProofFailure::rejected("production_identity_challenge_window_rejected")
            })?;
        let request_id = format!(
            "identity-proof-{trusted_now_epoch_s}-{}",
            &client_nonce[..16]
        );
        ProductionSignerIdentityChallenge::build(
            request_id,
            client_nonce,
            &self.deployment.signer.accepted,
            &self.deployment.signer.deployment_policy,
            trusted_now_epoch_s,
            expires_at_epoch_s,
        )
        .map_err(|_| LiveProofFailure::rejected("production_identity_challenge_rejected"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityRefreshMode {
    Observe,
    Recover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveProofFailureKind {
    Unavailable,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LiveProofFailure {
    kind: LiveProofFailureKind,
    code: &'static str,
}

impl LiveProofFailure {
    const fn unavailable(code: &'static str) -> Self {
        Self {
            kind: LiveProofFailureKind::Unavailable,
            code,
        }
    }

    const fn rejected(code: &'static str) -> Self {
        Self {
            kind: LiveProofFailureKind::Rejected,
            code,
        }
    }
}

#[derive(Debug, Default)]
struct IdentityChallengeState {
    active_digest: Option<String>,
    retired_digests: VecDeque<String>,
}

impl IdentityChallengeState {
    fn begin(&mut self, digest: String) -> Result<(), ()> {
        if self.active_digest.is_some()
            || self
                .retired_digests
                .iter()
                .any(|retired| retired == &digest)
        {
            return Err(());
        }
        self.active_digest = Some(digest);
        Ok(())
    }

    fn retire(&mut self, digest: &str) -> Result<(), ()> {
        if self.active_digest.as_deref() != Some(digest) {
            return Err(());
        }
        self.active_digest = None;
        self.retired_digests.push_back(digest.to_owned());
        while self.retired_digests.len() > MAX_RETIRED_IDENTITY_CHALLENGES {
            self.retired_digests.pop_front();
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct LiveIdentityGate {
    active: Option<SignerServiceIdentity>,
    pending_recovery: Option<SignerServiceIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveIdentityOutcome {
    Verified,
    RecoveryRequired,
}

impl LiveIdentityGate {
    fn observe(
        &mut self,
        identity: SignerServiceIdentity,
        mode: IdentityRefreshMode,
    ) -> LiveIdentityOutcome {
        let Some(active) = &self.active else {
            self.active = Some(identity);
            self.pending_recovery = None;
            return LiveIdentityOutcome::Verified;
        };

        if let Some(pending) = &self.pending_recovery {
            if mode == IdentityRefreshMode::Recover && pending == &identity {
                self.active = Some(identity);
                self.pending_recovery = None;
                return LiveIdentityOutcome::Verified;
            }
            if active != &identity {
                self.pending_recovery = Some(identity);
            }
            return LiveIdentityOutcome::RecoveryRequired;
        }

        if active == &identity {
            LiveIdentityOutcome::Verified
        } else {
            self.pending_recovery = Some(identity);
            LiveIdentityOutcome::RecoveryRequired
        }
    }

    fn recovery_required(&self) -> bool {
        self.pending_recovery.is_some()
    }
}

struct ProductionStartupInner {
    status: ProductionSignerStatus,
    runtime: Option<ProductionStartupRuntime>,
}

pub struct ProductionStartupState {
    inner: Mutex<ProductionStartupInner>,
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
        if validate_administrator_controlled_file(&manifest_path).is_err()
            || validate_administrator_controlled_file(&pin_path).is_err()
        {
            return Self::without_runtime(status_without_configuration(
                ProductionSignerStartupPhase::Rejected,
                "production_configuration_acl_rejected",
            ));
        }
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
        if validate_administrator_controlled_file(&current_executable).is_err() {
            return Self::without_runtime(status_without_configuration(
                ProductionSignerStartupPhase::Rejected,
                "production_backend_acl_rejected",
            ));
        }
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
        if validate_loaded_configuration_acl(&deployment).is_err() {
            return Self::without_runtime(status_without_configuration(
                ProductionSignerStartupPhase::Rejected,
                "production_signer_configuration_acl_rejected",
            ));
        }

        let runtime = ProductionStartupRuntime::new(deployment);
        let status = runtime.public_status(
            ProductionSignerStartupPhase::Configured,
            "production_configuration_verified",
            false,
        );
        let mut inner = ProductionStartupInner {
            status,
            runtime: Some(runtime),
        };
        inner.refresh(IdentityRefreshMode::Observe);
        Self {
            inner: Mutex::new(inner),
        }
    }

    #[must_use]
    pub fn status(&self) -> ProductionSignerStatus {
        self.inner.lock().map_or_else(
            |_| {
                status_without_configuration(
                    ProductionSignerStartupPhase::Rejected,
                    "production_startup_state_poisoned",
                )
            },
            |inner| inner.status.clone(),
        )
    }

    fn refresh(&self, mode: IdentityRefreshMode) -> ProductionSignerStatus {
        self.inner.lock().map_or_else(
            |_| {
                status_without_configuration(
                    ProductionSignerStartupPhase::Rejected,
                    "production_startup_state_poisoned",
                )
            },
            |mut inner| {
                inner.refresh(mode);
                inner.status.clone()
            },
        )
    }

    fn without_runtime(status: ProductionSignerStatus) -> Self {
        Self {
            inner: Mutex::new(ProductionStartupInner {
                status,
                runtime: None,
            }),
        }
    }
}

impl ProductionStartupInner {
    fn refresh(&mut self, mode: IdentityRefreshMode) {
        let Some(runtime) = &mut self.runtime else {
            return;
        };
        let Ok(trusted_now_epoch_s) = current_epoch_s() else {
            self.status = runtime.public_status(
                ProductionSignerStartupPhase::ServiceRejected,
                "production_trusted_clock_unavailable",
                false,
            );
            return;
        };

        match runtime.prove_live_identity(trusted_now_epoch_s) {
            Ok(identity) => {
                runtime.last_identity_proof_epoch_s = Some(trusted_now_epoch_s);
                self.status = match runtime.identity_gate.observe(identity, mode) {
                    LiveIdentityOutcome::Verified => runtime.public_status(
                        ProductionSignerStartupPhase::LiveVerified,
                        "production_signer_live_identity_verified",
                        true,
                    ),
                    LiveIdentityOutcome::RecoveryRequired => runtime.public_status(
                        ProductionSignerStartupPhase::RecoveryRequired,
                        "production_signer_restart_recovery_required",
                        false,
                    ),
                };
            }
            Err(failure) => {
                let phase = match failure.kind {
                    LiveProofFailureKind::Unavailable => {
                        ProductionSignerStartupPhase::ServiceUnavailable
                    }
                    LiveProofFailureKind::Rejected => ProductionSignerStartupPhase::ServiceRejected,
                };
                self.status = runtime.public_status(phase, failure.code, false);
            }
        }
    }
}

#[tauri::command]
pub fn get_production_signer_status(
    state: tauri::State<'_, ProductionStartupState>,
) -> ProductionSignerStatus {
    state.status()
}

#[tauri::command]
pub fn refresh_production_signer_status(
    state: tauri::State<'_, ProductionStartupState>,
) -> ProductionSignerStatus {
    state.refresh(IdentityRefreshMode::Observe)
}

#[tauri::command]
pub fn recover_production_signer_status(
    state: tauri::State<'_, ProductionStartupState>,
) -> ProductionSignerStatus {
    state.refresh(IdentityRefreshMode::Recover)
}

fn configured_status(
    manifest: &BackendProductionDeploymentManifest,
    pipe_clients_initialized: bool,
) -> ProductionSignerStatus {
    ProductionSignerStatus {
        phase: ProductionSignerStartupPhase::Configured,
        code: "production_configuration_verified",
        configuration_verified: true,
        configuration_acl_verified: true,
        pipe_clients_initialized,
        live_service_identity_verified: false,
        service_restart_detected: false,
        recovery_required: false,
        last_identity_proof_epoch_s: None,
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

#[allow(clippy::too_many_arguments)]
fn live_status(
    manifest: &BackendProductionDeploymentManifest,
    pipe_clients_initialized: bool,
    phase: ProductionSignerStartupPhase,
    code: &'static str,
    live_service_identity_verified: bool,
    recovery_required: bool,
    last_identity_proof_epoch_s: Option<u64>,
) -> ProductionSignerStatus {
    let mut status = configured_status(manifest, pipe_clients_initialized);
    status.phase = phase;
    status.code = code;
    status.live_service_identity_verified = live_service_identity_verified;
    status.service_restart_detected = recovery_required;
    status.recovery_required = recovery_required;
    status.last_identity_proof_epoch_s = last_identity_proof_epoch_s;
    status.production_issuance_enabled = phase == ProductionSignerStartupPhase::LiveVerified
        && live_service_identity_verified
        && !recovery_required;
    status
}

fn status_without_configuration(
    phase: ProductionSignerStartupPhase,
    code: &'static str,
) -> ProductionSignerStatus {
    ProductionSignerStatus {
        phase,
        code,
        configuration_verified: false,
        configuration_acl_verified: false,
        pipe_clients_initialized: false,
        live_service_identity_verified: false,
        service_restart_detected: false,
        recovery_required: false,
        last_identity_proof_epoch_s: None,
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

fn random_sha256_hex() -> Result<String, ()> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_| ())?;
    }
    Ok(encoded)
}

fn validate_loaded_configuration_acl(
    deployment: &LoadedBackendProductionDeployment,
) -> Result<(), ()> {
    let signer_manifest = &deployment.signer.manifest;
    for path in [
        deployment.manifest.signer_service_manifest_path.as_str(),
        signer_manifest.executable_path.as_str(),
        signer_manifest.governance_policy_path.as_str(),
        signer_manifest.caller_allowlist_path.as_str(),
        signer_manifest.deployment_policy_path.as_str(),
    ] {
        validate_administrator_controlled_file(Path::new(path)).map_err(|_| ())?;
    }
    validate_administrator_controlled_directory(Path::new(&signer_manifest.trust_store_root))
        .map_err(|_| ())
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
        assert!(status.configuration_acl_verified);
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
        assert!(!status.configuration_acl_verified);
        assert!(!status.pipe_clients_initialized);
        assert!(!status.production_issuance_enabled);
    }

    fn service_identity(instance: u8, process_id: u32) -> SignerServiceIdentity {
        SignerServiceIdentity {
            schema_version: "0.1.0".to_owned(),
            service_id: "ergaxiom.production-signer".to_owned(),
            instance_nonce: format!("{instance:064x}"),
            process_id,
            process_creation_time_100ns: 10_000 + u64::from(process_id),
            executable_sha256: DIGEST_C.to_owned(),
            started_at_epoch_s: 1_000 + u64::from(process_id),
        }
    }

    #[test]
    fn os_csprng_nonce_is_canonical_and_not_reused() {
        let first = random_sha256_hex().expect("first OS nonce");
        let second = random_sha256_hex().expect("second OS nonce");
        assert_eq!(first.len(), 64);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        );
        assert_ne!(first, second);
    }

    #[test]
    fn challenge_state_retires_and_rejects_reuse() {
        let mut state = IdentityChallengeState::default();
        assert!(state.begin(DIGEST_A.to_owned()).is_ok());
        assert!(state.begin(DIGEST_B.to_owned()).is_err());
        assert!(state.retire(DIGEST_A).is_ok());
        assert!(state.begin(DIGEST_A.to_owned()).is_err());
        assert!(state.begin(DIGEST_B.to_owned()).is_ok());
        assert!(state.retire(DIGEST_B).is_ok());
    }

    #[test]
    fn service_restart_requires_second_stable_recovery_proof() {
        let first = service_identity(1, 10);
        let restarted = service_identity(2, 11);
        let mut gate = LiveIdentityGate::default();
        assert_eq!(
            gate.observe(first.clone(), IdentityRefreshMode::Observe),
            LiveIdentityOutcome::Verified
        );
        assert_eq!(
            gate.observe(restarted.clone(), IdentityRefreshMode::Observe),
            LiveIdentityOutcome::RecoveryRequired
        );
        assert!(gate.recovery_required());
        assert_eq!(
            gate.observe(restarted, IdentityRefreshMode::Recover),
            LiveIdentityOutcome::Verified
        );
        assert!(!gate.recovery_required());
    }

    #[test]
    fn recovery_does_not_accept_a_moving_service_identity() {
        let mut gate = LiveIdentityGate::default();
        let first = service_identity(1, 10);
        let second = service_identity(2, 11);
        let third = service_identity(3, 12);
        assert_eq!(
            gate.observe(first, IdentityRefreshMode::Observe),
            LiveIdentityOutcome::Verified
        );
        assert_eq!(
            gate.observe(second, IdentityRefreshMode::Observe),
            LiveIdentityOutcome::RecoveryRequired
        );
        assert_eq!(
            gate.observe(third, IdentityRefreshMode::Recover),
            LiveIdentityOutcome::RecoveryRequired
        );
        assert!(gate.recovery_required());
    }

    #[test]
    fn public_live_status_does_not_expose_process_or_pipe_identity() {
        let manifest = public_manifest();
        let status = live_status(
            &manifest,
            true,
            ProductionSignerStartupPhase::LiveVerified,
            "production_signer_live_identity_verified",
            true,
            false,
            Some(1234),
        );
        let json = serde_json::to_string(&status).expect("serialize public status");
        for forbidden in [
            "process_id",
            "process_creation_time_100ns",
            "instance_nonce",
            "executable_path",
            "principal_sid",
            "pipe_name",
            "proof_digest",
        ] {
            assert!(!json.contains(forbidden), "leaked field: {forbidden}");
        }
        assert!(status.production_issuance_enabled);

        for (phase, identity_verified, recovery_required) in [
            (ProductionSignerStartupPhase::Configured, false, false),
            (ProductionSignerStartupPhase::ServiceRejected, false, false),
            (ProductionSignerStartupPhase::RecoveryRequired, false, true),
            (ProductionSignerStartupPhase::LiveVerified, false, false),
            (ProductionSignerStartupPhase::LiveVerified, true, true),
        ] {
            let blocked = live_status(
                &manifest,
                true,
                phase,
                "production_issuance_must_remain_blocked",
                identity_verified,
                recovery_required,
                Some(1234),
            );
            assert!(
                !blocked.production_issuance_enabled,
                "issuance escaped the live-identity gate for {phase:?}"
            );
        }
    }
}
