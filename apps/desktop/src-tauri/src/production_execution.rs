use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_backend_issuance_runtime::{
    BackendProductionDeploymentManifest, LoadedBackendProductionDeployment,
};
use ergaxiom_production_execution_authority_runtime::PersistentProductionExecutionAuthority;
use ergaxiom_windows_production_signer_host_runtime::{
    ProductionSignerPipeClient, validate_administrator_controlled_directory,
    validate_administrator_controlled_file,
};
use ergaxiom_windows_production_signer_runtime::SignerServiceIdentity;
use ergaxiom_windows_production_trust_state_runtime::{
    ProductionSignerIdentityChallenge, VerifiedProductionSignerTrustLease,
};
use thiserror::Error;

const MANIFEST_PATH: Option<&str> = option_env!("ERGAXIOM_BACKEND_PRODUCTION_MANIFEST_PATH");
const MANIFEST_PIN_PATH: Option<&str> =
    option_env!("ERGAXIOM_BACKEND_PRODUCTION_MANIFEST_PIN_PATH");
const POLICY_STORE_ROOT: Option<&str> =
    option_env!("ERGAXIOM_BACKEND_ISSUANCE_POLICY_STORE_ROOT");
const EXECUTION_STORE_ROOT: Option<&str> =
    option_env!("ERGAXIOM_PRODUCTION_EXECUTION_CHAIN_STORE_ROOT");
const DESKTOP_JOB_ID: &str = "job.desktop-shell.0001";
const SHA256_HEX_BYTES: u64 = 64;
const LEASE_TTL_S: u64 = 30;

pub struct ProductionExecutionState {
    inner: Mutex<Option<ProductionExecutionRuntime>>,
    startup_code: &'static str,
}

struct ProductionExecutionRuntime {
    deployment: LoadedBackendProductionDeployment,
    signer_client: ProductionSignerPipeClient,
    authority: PersistentProductionExecutionAuthority,
    active_service_identity: Option<SignerServiceIdentity>,
}

impl ProductionExecutionState {
    #[must_use]
    pub fn initialize() -> Self {
        match ProductionExecutionRuntime::initialize() {
            Ok(runtime) => Self {
                inner: Mutex::new(Some(runtime)),
                startup_code: "production_execution_authority_ready",
            },
            Err(error) => Self {
                inner: Mutex::new(None),
                startup_code: error.public_code(),
            },
        }
    }

    pub fn with_fresh_lease<R>(
        &self,
        operation: impl FnOnce(
            &mut PersistentProductionExecutionAuthority,
            &VerifiedProductionSignerTrustLease,
            &LoadedBackendProductionDeployment,
            ProductionSignerPipeClient,
            u64,
        ) -> Result<R, ProductionExecutionBoundaryError>,
    ) -> Result<R, ProductionExecutionBoundaryError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| ProductionExecutionBoundaryError::StatePoisoned)?;
        let runtime = guard
            .as_mut()
            .ok_or(ProductionExecutionBoundaryError::Unavailable(self.startup_code))?;
        let trusted_now_epoch_s = current_epoch_s()?;
        let lease = runtime.fresh_lease(trusted_now_epoch_s)?;
        let client = runtime.signer_client;
        operation(
            &mut runtime.authority,
            &lease,
            &runtime.deployment,
            client,
            trusted_now_epoch_s,
        )
    }

    #[must_use]
    pub const fn startup_code(&self) -> &'static str {
        self.startup_code
    }
}

impl ProductionExecutionRuntime {
    fn initialize() -> Result<Self, ProductionExecutionBoundaryError> {
        if !cfg!(windows) {
            return Err(ProductionExecutionBoundaryError::UnsupportedPlatform);
        }
        let manifest_path = fixed_absolute_path(MANIFEST_PATH.ok_or(
            ProductionExecutionBoundaryError::ConfigurationMissing,
        )?)?;
        let pin_path = fixed_absolute_path(
            MANIFEST_PIN_PATH.ok_or(ProductionExecutionBoundaryError::ConfigurationMissing)?,
        )?;
        let policy_store_root = fixed_absolute_path(
            POLICY_STORE_ROOT.ok_or(ProductionExecutionBoundaryError::ConfigurationMissing)?,
        )?;
        let execution_store_root = fixed_absolute_path(
            EXECUTION_STORE_ROOT.ok_or(ProductionExecutionBoundaryError::ConfigurationMissing)?,
        )?;

        validate_administrator_controlled_file(&manifest_path)
            .map_err(|_| ProductionExecutionBoundaryError::ConfigurationAclRejected)?;
        validate_administrator_controlled_file(&pin_path)
            .map_err(|_| ProductionExecutionBoundaryError::ConfigurationAclRejected)?;
        validate_administrator_controlled_directory(&policy_store_root)
            .map_err(|_| ProductionExecutionBoundaryError::StoreAclRejected)?;
        validate_administrator_controlled_directory(&execution_store_root)
            .map_err(|_| ProductionExecutionBoundaryError::StoreAclRejected)?;

        let expected_manifest_digest = read_stable_manifest_pin(&pin_path)?;
        let current_executable = std::env::current_exe()
            .map_err(|_| ProductionExecutionBoundaryError::BackendIdentityUnavailable)?;
        validate_administrator_controlled_file(&current_executable)
            .map_err(|_| ProductionExecutionBoundaryError::BackendIdentityRejected)?;
        let trusted_now_epoch_s = current_epoch_s()?;
        let deployment = BackendProductionDeploymentManifest::load_pinned(
            &manifest_path,
            &expected_manifest_digest,
            &current_executable,
            trusted_now_epoch_s,
        )
        .map_err(|_| ProductionExecutionBoundaryError::ConfigurationRejected)?;
        validate_loaded_configuration_acl(&deployment)?;

        // The executor/device subject is derived from the pinned backend/deployment identity. It is
        // never supplied by the renderer and therefore cannot be widened at invocation time.
        let executor_id = deployment.manifest.backend_id.clone();
        let device_id = Some(deployment.manifest.deployment_id.clone());
        let chain_store_root = execution_store_root.join(DESKTOP_JOB_ID);
        let authority = PersistentProductionExecutionAuthority::load_or_create(
            policy_store_root,
            &chain_store_root,
            DESKTOP_JOB_ID,
            executor_id,
            device_id,
        )?;
        validate_administrator_controlled_directory(&chain_store_root)
            .map_err(|_| ProductionExecutionBoundaryError::StoreAclRejected)?;

        Ok(Self {
            deployment,
            signer_client: ProductionSignerPipeClient,
            authority,
            active_service_identity: None,
        })
    }

    fn fresh_lease(
        &mut self,
        trusted_now_epoch_s: u64,
    ) -> Result<VerifiedProductionSignerTrustLease, ProductionExecutionBoundaryError> {
        let nonce = random_sha256_hex()?;
        let expires_at_epoch_s = trusted_now_epoch_s
            .checked_add(LEASE_TTL_S)
            .ok_or(ProductionExecutionBoundaryError::TrustedClockRejected)?;
        let request_id = format!(
            "production-execution-lease-{trusted_now_epoch_s}-{}",
            &nonce[..16]
        );
        let challenge = ProductionSignerIdentityChallenge::build(
            request_id,
            nonce,
            &self.deployment.signer.accepted,
            &self.deployment.signer.deployment_policy,
            trusted_now_epoch_s,
            expires_at_epoch_s,
        )
        .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
        let proof = self
            .signer_client
            .prove_identity(&challenge)
            .map_err(|_| ProductionExecutionBoundaryError::SignerUnavailable)?;
        if proof
            .signed_package
            .signer_package
            .caller_authorization
            .caller_id
            != self.deployment.manifest.backend_caller_id
        {
            return Err(ProductionExecutionBoundaryError::BackendIdentityRejected);
        }
        let lease = proof
            .verify_trust_lease(
                &challenge,
                &self.deployment.signer.accepted,
                &self.deployment.signer.deployment_policy,
                trusted_now_epoch_s,
            )
            .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
        let identity = lease.service_identity().clone();
        match &self.active_service_identity {
            None => self.active_service_identity = Some(identity),
            Some(active) if active == &identity => {}
            Some(_) => return Err(ProductionExecutionBoundaryError::SignerRestartDetected),
        }
        Ok(lease)
    }
}

fn validate_loaded_configuration_acl(
    deployment: &LoadedBackendProductionDeployment,
) -> Result<(), ProductionExecutionBoundaryError> {
    let signer_manifest = &deployment.signer.manifest;
    for path in [
        deployment.manifest.signer_service_manifest_path.as_str(),
        signer_manifest.executable_path.as_str(),
        signer_manifest.governance_policy_path.as_str(),
        signer_manifest.caller_allowlist_path.as_str(),
        signer_manifest.deployment_policy_path.as_str(),
    ] {
        validate_administrator_controlled_file(Path::new(path))
            .map_err(|_| ProductionExecutionBoundaryError::ConfigurationAclRejected)?;
    }
    validate_administrator_controlled_directory(Path::new(&signer_manifest.trust_store_root))
        .map_err(|_| ProductionExecutionBoundaryError::ConfigurationAclRejected)
}

fn fixed_absolute_path(value: &str) -> Result<PathBuf, ProductionExecutionBoundaryError> {
    if value.is_empty() || value.contains(['\0', '\n', '\r', '"']) {
        return Err(ProductionExecutionBoundaryError::ConfigurationPathRejected);
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(ProductionExecutionBoundaryError::ConfigurationPathRejected);
    }
    Ok(path)
}

fn read_stable_manifest_pin(path: &Path) -> Result<String, ProductionExecutionBoundaryError> {
    let before = fs::symlink_metadata(path)
        .map_err(|_| ProductionExecutionBoundaryError::ConfigurationPinRejected)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() != SHA256_HEX_BYTES {
        return Err(ProductionExecutionBoundaryError::ConfigurationPinRejected);
    }
    let before_modified = before.modified().ok();
    let bytes = fs::read(path)
        .map_err(|_| ProductionExecutionBoundaryError::ConfigurationPinRejected)?;
    let after = fs::symlink_metadata(path)
        .map_err(|_| ProductionExecutionBoundaryError::ConfigurationPinRejected)?;
    if after.file_type().is_symlink()
        || !after.is_file()
        || before.len() != after.len()
        || before_modified != after.modified().ok()
        || bytes.len() as u64 != SHA256_HEX_BYTES
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
    {
        return Err(ProductionExecutionBoundaryError::ConfigurationPinRejected);
    }
    String::from_utf8(bytes).map_err(|_| ProductionExecutionBoundaryError::ConfigurationPinRejected)
}

fn current_epoch_s() -> Result<u64, ProductionExecutionBoundaryError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ProductionExecutionBoundaryError::TrustedClockRejected)
}

fn random_sha256_hex() -> Result<String, ProductionExecutionBoundaryError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ProductionExecutionBoundaryError::NonceUnavailable)?;
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_| ProductionExecutionBoundaryError::NonceUnavailable)?;
    }
    Ok(encoded)
}

#[derive(Debug, Error)]
pub enum ProductionExecutionBoundaryError {
    #[error("production execution is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("production execution configuration is not installed")]
    ConfigurationMissing,
    #[error("production execution configuration path was rejected")]
    ConfigurationPathRejected,
    #[error("production execution configuration ACL was rejected")]
    ConfigurationAclRejected,
    #[error("production execution persistent-store ACL was rejected")]
    StoreAclRejected,
    #[error("production execution configuration pin was rejected")]
    ConfigurationPinRejected,
    #[error("production execution configuration did not verify")]
    ConfigurationRejected,
    #[error("production backend identity is unavailable")]
    BackendIdentityUnavailable,
    #[error("production backend identity was rejected")]
    BackendIdentityRejected,
    #[error("production trusted clock was rejected")]
    TrustedClockRejected,
    #[error("production identity nonce is unavailable")]
    NonceUnavailable,
    #[error("production signer service is unavailable")]
    SignerUnavailable,
    #[error("production signer trust lease was rejected")]
    TrustLeaseRejected,
    #[error("production signer restart requires application recovery before execution")]
    SignerRestartDetected,
    #[error("production execution state lock is unavailable")]
    StatePoisoned,
    #[error("production execution authority is unavailable: {0}")]
    Unavailable(&'static str),
    #[error(transparent)]
    Authority(#[from] ergaxiom_production_execution_authority_runtime::PersistentProductionExecutionAuthorityError),
}

impl ProductionExecutionBoundaryError {
    #[must_use]
    pub const fn public_code(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "production_execution_unsupported_platform",
            Self::ConfigurationMissing => "production_execution_configuration_missing",
            Self::ConfigurationPathRejected => "production_execution_configuration_path_rejected",
            Self::ConfigurationAclRejected => "production_execution_configuration_acl_rejected",
            Self::StoreAclRejected => "production_execution_store_acl_rejected",
            Self::ConfigurationPinRejected => "production_execution_configuration_pin_rejected",
            Self::ConfigurationRejected => "production_execution_configuration_rejected",
            Self::BackendIdentityUnavailable => "production_backend_identity_unavailable",
            Self::BackendIdentityRejected => "production_backend_identity_rejected",
            Self::TrustedClockRejected => "production_trusted_clock_rejected",
            Self::NonceUnavailable => "production_identity_nonce_unavailable",
            Self::SignerUnavailable => "production_signer_unavailable",
            Self::TrustLeaseRejected => "production_trust_lease_rejected",
            Self::SignerRestartDetected => "production_signer_restart_recovery_required",
            Self::StatePoisoned => "production_execution_state_poisoned",
            Self::Unavailable(code) => code,
            Self::Authority(_) => "production_execution_authority_rejected",
        }
    }
}
