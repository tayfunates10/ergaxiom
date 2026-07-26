#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod windows;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_cng_key_provider_runtime::{
    CngPlatformKeyProvider, CngProviderError, CngProvisioningResult,
};
use ergaxiom_windows_production_key_governance_runtime::{
    ProductionKeyRecord, ProductionKeyStatus,
};
use ergaxiom_windows_production_signer_runtime::{
    HardwareAssurance, HardwareKeyDescriptor, HardwareSignature, ProductionKeyIdentity,
    ProductionKeyPolicy, ProductionSignerError, SignerRequestBinding, validate_identifier,
    validate_sha256,
};
use ergaxiom_windows_production_signer_service_runtime::{
    HardwareSignerBackend, HardwareSignerBackendError, ProductionSignerServiceError,
};
use ergaxiom_windows_production_signer_transport_runtime::{
    AuthenticatedPipeConnection, ProductionSignerTransportError,
};
use ergaxiom_windows_production_trust_state_runtime::{
    DeployedAuthorizedProductionSignerPackage, DeployedProductionSignerError,
    ProductionSignerDeploymentPolicy, ProductionTrustStateStore, ProductionTrustStoreError,
    TrustBoundProductionSignerService, TrustGovernancePolicy, VerifiedProductionTrustState,
};
use ergaxiom_windows_signer_service_identity_runtime::{
    NamedPipeSecurityContract, SignerCallerAllowlist, SignerIdentityError,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PRODUCTION_SIGNER_SERVICE_MANIFEST_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_SIGNER_HOST_RESPONSE_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_SIGNER_SERVICE_NAME: &str = "ErgaxiomProductionSigner";
pub const PRODUCTION_SIGNER_SERVICE_DISPLAY_NAME: &str = "Ergaxiom Production Signer";
pub const PRODUCTION_SIGNER_SERVICE_ACCOUNT: &str = "LocalSystem";
pub const PRODUCTION_SIGNER_SERVICE_TYPE: &str = "WIN32_OWN_PROCESS";
pub const PRODUCTION_SIGNER_START_MODE: &str = "AUTO_DELAYED";
pub const PRODUCTION_SIGNER_ERROR_CONTROL: &str = "SEVERE";
pub const PRODUCTION_SIGNER_SERVICE_SID_TYPE: &str = "UNRESTRICTED";
pub const PRODUCTION_SIGNER_REQUIRED_PRIVILEGE: &str = "SeChangeNotifyPrivilege";
pub const PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS: u32 = 10_000;
pub const PRODUCTION_SIGNER_MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
pub const PRODUCTION_SIGNER_MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
pub const PRODUCTION_SIGNER_RESTART_DELAYS_MS: [u32; 2] = [5_000, 30_000];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSignerServiceManifest {
    pub schema_version: String,
    pub deployment_id: String,
    pub service_name: String,
    pub display_name: String,
    pub service_account: String,
    pub service_type: String,
    pub start_mode: String,
    pub error_control: String,
    pub service_sid_type: String,
    pub required_privileges: Vec<String>,
    pub failure_restart_delays_ms: Vec<u32>,
    pub preshutdown_timeout_ms: u32,
    pub executable_path: String,
    pub executable_sha256: String,
    pub trust_store_root: String,
    pub governance_policy_path: String,
    pub governance_policy_digest: String,
    pub caller_allowlist_path: String,
    pub caller_allowlist_revision: u64,
    pub caller_allowlist_digest: String,
    pub deployment_policy_path: String,
    pub deployment_policy_revision: u64,
    pub deployment_policy_digest: String,
    pub pipe_allowed_principal_sid: String,
    pub max_config_file_bytes: u64,
    pub manifest_digest: String,
}

impl ProductionSignerServiceManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn from_files(
        executable_path: impl Into<PathBuf>,
        trust_store_root: impl Into<PathBuf>,
        governance_policy_path: impl Into<PathBuf>,
        caller_allowlist_path: impl Into<PathBuf>,
        deployment_policy_path: impl Into<PathBuf>,
        pipe_allowed_principal_sid: impl Into<String>,
        trusted_now_epoch_s: u64,
    ) -> Result<Self, ProductionSignerHostError> {
        let executable_path = require_absolute_path(executable_path.into())?;
        let trust_store_root = require_absolute_path(trust_store_root.into())?;
        let governance_policy_path = require_absolute_path(governance_policy_path.into())?;
        let caller_allowlist_path = require_absolute_path(caller_allowlist_path.into())?;
        let deployment_policy_path = require_absolute_path(deployment_policy_path.into())?;

        let executable_sha256 =
            hash_stable_file(&executable_path, PRODUCTION_SIGNER_MAX_EXECUTABLE_BYTES)?;
        let governance_policy: TrustGovernancePolicy =
            read_bounded_json(&governance_policy_path, PRODUCTION_SIGNER_MAX_CONFIG_BYTES)?;
        governance_policy.validate_seal()?;
        let caller_allowlist: SignerCallerAllowlist =
            read_bounded_json(&caller_allowlist_path, PRODUCTION_SIGNER_MAX_CONFIG_BYTES)?;
        caller_allowlist.validate()?;
        let deployment_policy: ProductionSignerDeploymentPolicy =
            read_bounded_json(&deployment_policy_path, PRODUCTION_SIGNER_MAX_CONFIG_BYTES)?;
        deployment_policy.validate_seal()?;
        let accepted = ProductionTrustStateStore::new(&trust_store_root)?
            .load_accepted(&governance_policy, trusted_now_epoch_s)?;

        let mut manifest = Self {
            schema_version: PRODUCTION_SIGNER_SERVICE_MANIFEST_SCHEMA.to_owned(),
            deployment_id: deployment_policy.deployment_id.clone(),
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
            executable_path: path_text(&executable_path)?,
            executable_sha256,
            trust_store_root: path_text(&trust_store_root)?,
            governance_policy_path: path_text(&governance_policy_path)?,
            governance_policy_digest: governance_policy.policy_digest.clone(),
            caller_allowlist_path: path_text(&caller_allowlist_path)?,
            caller_allowlist_revision: caller_allowlist.revision,
            caller_allowlist_digest: caller_allowlist.allowlist_digest.clone(),
            deployment_policy_path: path_text(&deployment_policy_path)?,
            deployment_policy_revision: deployment_policy.revision,
            deployment_policy_digest: deployment_policy.policy_digest.clone(),
            pipe_allowed_principal_sid: pipe_allowed_principal_sid.into(),
            max_config_file_bytes: PRODUCTION_SIGNER_MAX_CONFIG_BYTES,
            manifest_digest: String::new(),
        };
        validate_loaded_state(
            &manifest,
            &governance_policy,
            &caller_allowlist,
            &deployment_policy,
            &accepted,
        )?;
        manifest.manifest_digest = manifest.expected_digest()?;
        manifest.validate_seal()?;
        Ok(manifest)
    }

    pub fn validate_seal(&self) -> Result<(), ProductionSignerHostError> {
        if self.schema_version != PRODUCTION_SIGNER_SERVICE_MANIFEST_SCHEMA {
            return Err(ProductionSignerHostError::UnsupportedManifestSchema);
        }
        validate_identifier("deployment_id", &self.deployment_id)?;
        if self.service_name != PRODUCTION_SIGNER_SERVICE_NAME
            || self.display_name != PRODUCTION_SIGNER_SERVICE_DISPLAY_NAME
            || self.service_account != PRODUCTION_SIGNER_SERVICE_ACCOUNT
            || self.service_type != PRODUCTION_SIGNER_SERVICE_TYPE
            || self.start_mode != PRODUCTION_SIGNER_START_MODE
            || self.error_control != PRODUCTION_SIGNER_ERROR_CONTROL
            || self.service_sid_type != PRODUCTION_SIGNER_SERVICE_SID_TYPE
            || self.required_privileges != vec![PRODUCTION_SIGNER_REQUIRED_PRIVILEGE.to_owned()]
            || self.failure_restart_delays_ms != PRODUCTION_SIGNER_RESTART_DELAYS_MS
            || self.preshutdown_timeout_ms != PRODUCTION_SIGNER_PRESHUTDOWN_TIMEOUT_MS
            || self.max_config_file_bytes == 0
            || self.max_config_file_bytes > PRODUCTION_SIGNER_MAX_CONFIG_BYTES
        {
            return Err(ProductionSignerHostError::ServiceHardeningWeakened);
        }
        for path in [
            &self.executable_path,
            &self.trust_store_root,
            &self.governance_policy_path,
            &self.caller_allowlist_path,
            &self.deployment_policy_path,
        ] {
            validate_absolute_path_text(path)?;
        }
        validate_sha256(&self.executable_sha256)?;
        validate_sha256(&self.governance_policy_digest)?;
        validate_sha256(&self.caller_allowlist_digest)?;
        validate_sha256(&self.deployment_policy_digest)?;
        validate_sha256(&self.manifest_digest)?;
        if self.caller_allowlist_revision == 0 || self.deployment_policy_revision == 0 {
            return Err(ProductionSignerHostError::InvalidManifestRevision);
        }
        let pipe = NamedPipeSecurityContract::production(&self.pipe_allowed_principal_sid)?;
        pipe.validate()?;
        if self.manifest_digest != self.expected_digest()? {
            return Err(ProductionSignerHostError::ManifestDigestMismatch);
        }
        Ok(())
    }

    pub fn service_command_line(
        &self,
        manifest_path: &Path,
    ) -> Result<String, ProductionSignerHostError> {
        self.validate_seal()?;
        let manifest_path = require_absolute_path(manifest_path.to_path_buf())?;
        let executable = quote_windows_argument(&self.executable_path)?;
        let manifest = quote_windows_argument(&path_text(&manifest_path)?)?;
        Ok(format!("{executable} --service --manifest {manifest}"))
    }

    pub fn write_create_new(&self, destination: &Path) -> Result<(), ProductionSignerHostError> {
        self.validate_seal()?;
        let destination = require_absolute_path(destination.to_path_buf())?;
        reject_symlink_if_present(&destination)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.is_empty() || bytes.len() as u64 > PRODUCTION_SIGNER_MAX_CONFIG_BYTES {
            return Err(ProductionSignerHostError::FileSizeInvalid);
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionSignerHostError> {
        digest_with_blank_field(self, "manifest_digest")
    }
}

#[derive(Debug, Clone)]
pub struct LoadedProductionSignerHostConfig {
    pub manifest: ProductionSignerServiceManifest,
    pub governance_policy: TrustGovernancePolicy,
    pub caller_allowlist: SignerCallerAllowlist,
    pub deployment_policy: ProductionSignerDeploymentPolicy,
    pub accepted: VerifiedProductionTrustState,
}

impl LoadedProductionSignerHostConfig {
    pub fn load(
        manifest_path: &Path,
        trusted_now_epoch_s: u64,
    ) -> Result<Self, ProductionSignerHostError> {
        let manifest_path = require_absolute_path(manifest_path.to_path_buf())?;
        let manifest: ProductionSignerServiceManifest =
            read_bounded_json(&manifest_path, PRODUCTION_SIGNER_MAX_CONFIG_BYTES)?;
        manifest.validate_seal()?;
        let executable_path = PathBuf::from(&manifest.executable_path);
        if hash_stable_file(&executable_path, PRODUCTION_SIGNER_MAX_EXECUTABLE_BYTES)?
            != manifest.executable_sha256
        {
            return Err(ProductionSignerHostError::ExecutableDigestMismatch);
        }
        let governance_policy: TrustGovernancePolicy = read_bounded_json(
            Path::new(&manifest.governance_policy_path),
            manifest.max_config_file_bytes,
        )?;
        governance_policy.validate_seal()?;
        let caller_allowlist: SignerCallerAllowlist = read_bounded_json(
            Path::new(&manifest.caller_allowlist_path),
            manifest.max_config_file_bytes,
        )?;
        caller_allowlist.validate()?;
        let deployment_policy: ProductionSignerDeploymentPolicy = read_bounded_json(
            Path::new(&manifest.deployment_policy_path),
            manifest.max_config_file_bytes,
        )?;
        deployment_policy.validate_seal()?;
        let accepted = ProductionTrustStateStore::new(&manifest.trust_store_root)?
            .load_accepted(&governance_policy, trusted_now_epoch_s)?;
        validate_loaded_state(
            &manifest,
            &governance_policy,
            &caller_allowlist,
            &deployment_policy,
            &accepted,
        )?;
        Ok(Self {
            manifest,
            governance_policy,
            caller_allowlist,
            deployment_policy,
            accepted: accepted.verified,
        })
    }
}

#[derive(Debug, Clone)]
struct OpenedCngGeneration {
    identity: ProductionKeyIdentity,
    generation: u64,
    provisioning: CngProvisioningResult,
    descriptor: HardwareKeyDescriptor,
}

#[derive(Debug, Clone)]
pub struct GovernedCngSignerBackend {
    provider: CngPlatformKeyProvider,
    opened: Vec<OpenedCngGeneration>,
}

impl GovernedCngSignerBackend {
    pub fn open(
        accepted: &VerifiedProductionTrustState,
        deployment_policy: &ProductionSignerDeploymentPolicy,
        at_epoch_s: u64,
    ) -> Result<Self, ProductionSignerHostError> {
        deployment_policy.validate_seal()?;
        let provider = CngPlatformKeyProvider::production();
        let probe = provider.probe()?;
        if !probe.hardware_flag_present || probe.software_flag_present {
            return Err(ProductionSignerHostError::CngProviderNotHardwareOnly);
        }
        let mut opened = Vec::with_capacity(deployment_policy.enabled_identities.len());
        for identity in &deployment_policy.enabled_identities {
            let record = accepted.registry().active_record(identity, at_epoch_s)?;
            if record.status != ProductionKeyStatus::Active {
                return Err(ProductionSignerHostError::ActiveGenerationUnavailable);
            }
            let policy = ProductionKeyPolicy::for_identity(identity.clone());
            let provisioning = provider.describe_existing_generation_unverified(
                &policy,
                record.generation,
                Some(&record.public_key_digest),
            )?;
            validate_cng_record_binding(&provisioning.descriptor, record)?;
            let mut descriptor = provisioning.descriptor.clone();
            descriptor.assurance = HardwareAssurance::ProvenHardwareBacked;
            descriptor.validate_for(&policy)?;
            opened.push(OpenedCngGeneration {
                identity: identity.clone(),
                generation: record.generation,
                provisioning,
                descriptor,
            });
        }
        Ok(Self { provider, opened })
    }

    fn find(
        &self,
        identity: &ProductionKeyIdentity,
        generation: u64,
    ) -> Result<&OpenedCngGeneration, HardwareSignerBackendError> {
        let matching: Vec<&OpenedCngGeneration> = self
            .opened
            .iter()
            .filter(|candidate| {
                candidate.identity == *identity && candidate.generation == generation
            })
            .collect();
        match matching.as_slice() {
            [opened] => Ok(*opened),
            _ => Err(HardwareSignerBackendError::new(
                "KEY_GENERATION_UNAVAILABLE",
            )),
        }
    }
}

impl HardwareSignerBackend for GovernedCngSignerBackend {
    fn descriptor(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
        self.descriptor_for_generation(policy, 1)
    }

    fn descriptor_for_generation(
        &self,
        policy: &ProductionKeyPolicy,
        generation: u64,
    ) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
        policy
            .validate()
            .map_err(|_| HardwareSignerBackendError::new("POLICY_INVALID"))?;
        Ok(self.find(&policy.identity, generation)?.descriptor.clone())
    }

    fn sign_sha256_digest(
        &self,
        policy: &ProductionKeyPolicy,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, HardwareSignerBackendError> {
        self.sign_sha256_digest_for_generation(policy, 1, descriptor, binding, digest)
    }

    fn sign_sha256_digest_for_generation(
        &self,
        policy: &ProductionKeyPolicy,
        generation: u64,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, HardwareSignerBackendError> {
        let opened = self.find(&policy.identity, generation)?;
        if descriptor != &opened.descriptor {
            return Err(HardwareSignerBackendError::new("DESCRIPTOR_SUBSTITUTION"));
        }
        self.provider
            .sign_sha256_digest_unverified(policy, &opened.provisioning, binding, digest)
            .map_err(|_| HardwareSignerBackendError::new("CNG_SIGN_FAILED"))
    }
}

#[derive(Debug)]
pub struct PreparedProductionSignerHost {
    pub manifest: ProductionSignerServiceManifest,
    pub pipe_contract: NamedPipeSecurityContract,
    service: TrustBoundProductionSignerService<GovernedCngSignerBackend>,
}

impl PreparedProductionSignerHost {
    #[cfg(windows)]
    pub fn load(
        manifest_path: &Path,
        trusted_now_epoch_s: u64,
    ) -> Result<Self, ProductionSignerHostError> {
        let loaded = LoadedProductionSignerHostConfig::load(manifest_path, trusted_now_epoch_s)?;
        let service_identity = windows::current_service_identity(
            &loaded.deployment_policy.service_id,
            &loaded.manifest.executable_sha256,
            trusted_now_epoch_s,
        )?;
        let backend = GovernedCngSignerBackend::open(
            &loaded.accepted,
            &loaded.deployment_policy,
            service_identity.started_at_epoch_s,
        )?;
        let service = ProductionSignerService::new(
            backend,
            service_identity,
            loaded.caller_allowlist.clone(),
        )?;
        let service = TrustBoundProductionSignerService::new(
            service,
            loaded.accepted,
            loaded.deployment_policy.clone(),
        )?;
        let pipe_contract =
            NamedPipeSecurityContract::production(&loaded.manifest.pipe_allowed_principal_sid)?;
        if pipe_contract.max_request_bytes != loaded.deployment_policy.max_request_bytes
            || pipe_contract.max_response_bytes != loaded.deployment_policy.max_response_bytes
        {
            return Err(ProductionSignerHostError::PipePolicyMismatch);
        }
        Ok(Self {
            manifest: loaded.manifest,
            pipe_contract,
            service,
        })
    }

    #[cfg(not(windows))]
    pub fn load(
        _manifest_path: &Path,
        _trusted_now_epoch_s: u64,
    ) -> Result<Self, ProductionSignerHostError> {
        Err(ProductionSignerHostError::UnsupportedPlatform)
    }

    pub fn serve_connection(
        &mut self,
        connection: &mut AuthenticatedPipeConnection,
        trusted_now_epoch_s: u64,
    ) -> Result<(), ProductionSignerHostError> {
        let request = match connection.read_request() {
            Ok(request) => request,
            Err(_) => {
                let response = ProductionSignerHostResponse::rejected(None, "REQUEST_REJECTED")?;
                connection.write_json(&response, self.pipe_contract.max_response_bytes)?;
                return Ok(());
            }
        };
        let caller = connection.caller()?.clone();
        let response =
            match self
                .service
                .handle_authenticated(&request, &caller, trusted_now_epoch_s)
            {
                Ok(package) => ProductionSignerHostResponse::success(package)?,
                Err(_) => ProductionSignerHostResponse::rejected(
                    Some(request.request_id.clone()),
                    "SIGNING_REJECTED",
                )?,
            };
        connection.write_json(&response, self.pipe_contract.max_response_bytes)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductionSignerHostResponse {
    Success {
        schema_version: String,
        package: DeployedAuthorizedProductionSignerPackage,
        response_digest: String,
    },
    Rejected {
        schema_version: String,
        request_id: Option<String>,
        code: String,
        response_digest: String,
    },
}

impl ProductionSignerHostResponse {
    pub fn success(
        package: DeployedAuthorizedProductionSignerPackage,
    ) -> Result<Self, ProductionSignerHostError> {
        let mut response = Self::Success {
            schema_version: PRODUCTION_SIGNER_HOST_RESPONSE_SCHEMA.to_owned(),
            package,
            response_digest: String::new(),
        };
        response.set_digest()?;
        Ok(response)
    }

    pub fn rejected(
        request_id: Option<String>,
        code: impl Into<String>,
    ) -> Result<Self, ProductionSignerHostError> {
        let mut response = Self::Rejected {
            schema_version: PRODUCTION_SIGNER_HOST_RESPONSE_SCHEMA.to_owned(),
            request_id,
            code: code.into(),
            response_digest: String::new(),
        };
        response.set_digest()?;
        Ok(response)
    }

    pub fn validate_seal(&self) -> Result<(), ProductionSignerHostError> {
        match self {
            Self::Success {
                schema_version,
                response_digest,
                ..
            }
            | Self::Rejected {
                schema_version,
                response_digest,
                ..
            } => {
                if schema_version != PRODUCTION_SIGNER_HOST_RESPONSE_SCHEMA {
                    return Err(ProductionSignerHostError::UnsupportedResponseSchema);
                }
                validate_sha256(response_digest)?;
                if response_digest != &self.expected_digest()? {
                    return Err(ProductionSignerHostError::ResponseDigestMismatch);
                }
            }
        }
        Ok(())
    }

    fn set_digest(&mut self) -> Result<(), ProductionSignerHostError> {
        let digest = self.expected_digest()?;
        match self {
            Self::Success {
                response_digest, ..
            }
            | Self::Rejected {
                response_digest, ..
            } => *response_digest = digest,
        }
        self.validate_seal()
    }

    fn expected_digest(&self) -> Result<String, ProductionSignerHostError> {
        digest_with_blank_field(self, "response_digest")
    }
}

#[cfg(windows)]
pub use windows::{
    install_service, run_service_dispatcher, uninstall_service, validate_installed_service,
};

#[cfg(not(windows))]
pub fn install_service(
    _manifest_path: &Path,
    _trusted_now_epoch_s: u64,
) -> Result<(), ProductionSignerHostError> {
    Err(ProductionSignerHostError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub fn uninstall_service(_manifest_path: &Path) -> Result<(), ProductionSignerHostError> {
    Err(ProductionSignerHostError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub fn validate_installed_service(
    _manifest_path: &Path,
    _trusted_now_epoch_s: u64,
) -> Result<(), ProductionSignerHostError> {
    Err(ProductionSignerHostError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub fn run_service_dispatcher(_manifest_path: PathBuf) -> Result<(), ProductionSignerHostError> {
    Err(ProductionSignerHostError::UnsupportedPlatform)
}

fn validate_loaded_state(
    manifest: &ProductionSignerServiceManifest,
    governance_policy: &TrustGovernancePolicy,
    caller_allowlist: &SignerCallerAllowlist,
    deployment_policy: &ProductionSignerDeploymentPolicy,
    accepted: &ergaxiom_windows_production_trust_state_runtime::ActivatedProductionTrustState,
) -> Result<(), ProductionSignerHostError> {
    manifest.validate_shape_without_digest()?;
    governance_policy.validate_seal()?;
    caller_allowlist.validate()?;
    deployment_policy.validate_seal()?;
    accepted.checkpoint.validate_seal()?;
    let body = accepted.verified.body();
    if manifest.governance_policy_digest != governance_policy.policy_digest
        || manifest.caller_allowlist_revision != caller_allowlist.revision
        || manifest.caller_allowlist_digest != caller_allowlist.allowlist_digest
        || manifest.deployment_policy_revision != deployment_policy.revision
        || manifest.deployment_policy_digest != deployment_policy.policy_digest
        || manifest.deployment_id != deployment_policy.deployment_id
        || body.deployment_id != manifest.deployment_id
        || body.signer_service_executable_digest != manifest.executable_sha256
        || body.caller_allowlist_revision != caller_allowlist.revision
        || body.caller_allowlist_digest != caller_allowlist.allowlist_digest
        || body.service_policy_revision != deployment_policy.revision
        || body.service_policy_digest != deployment_policy.policy_digest
    {
        return Err(ProductionSignerHostError::AcceptedStateConfigurationMismatch);
    }
    let pipe = NamedPipeSecurityContract::production(&manifest.pipe_allowed_principal_sid)?;
    if pipe.max_request_bytes != deployment_policy.max_request_bytes
        || pipe.max_response_bytes != deployment_policy.max_response_bytes
        || deployment_policy.transport_id != "local-named-pipe-v1"
    {
        return Err(ProductionSignerHostError::PipePolicyMismatch);
    }
    Ok(())
}

impl ProductionSignerServiceManifest {
    fn validate_shape_without_digest(&self) -> Result<(), ProductionSignerHostError> {
        if self.schema_version != PRODUCTION_SIGNER_SERVICE_MANIFEST_SCHEMA {
            return Err(ProductionSignerHostError::UnsupportedManifestSchema);
        }
        validate_identifier("deployment_id", &self.deployment_id)?;
        validate_sha256(&self.executable_sha256)?;
        validate_sha256(&self.governance_policy_digest)?;
        validate_sha256(&self.caller_allowlist_digest)?;
        validate_sha256(&self.deployment_policy_digest)?;
        Ok(())
    }
}

fn validate_cng_record_binding(
    descriptor: &HardwareKeyDescriptor,
    record: &ProductionKeyRecord,
) -> Result<(), ProductionSignerHostError> {
    record.validate_seal()?;
    if descriptor.identity != record.identity
        || descriptor.public_key_base64url != record.public_key_base64url
        || descriptor.public_key_digest != record.public_key_digest
        || descriptor.provider != record.provider
        || descriptor.algorithm != record.algorithm
        || descriptor.public_key_encoding != record.public_key_encoding
        || descriptor.signature_encoding != record.signature_encoding
        || descriptor.export_policy != record.export_policy
        || descriptor.provider_implementation_flags != record.provider_implementation_flags
        || descriptor.policy_digest != record.policy_digest
    {
        return Err(ProductionSignerHostError::CngRegistryMismatch);
    }
    Ok(())
}

fn read_bounded_json<T: DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
) -> Result<T, ProductionSignerHostError> {
    let bytes = read_bounded_file(path, max_bytes)?;
    serde_json::from_slice(&bytes).map_err(ProductionSignerHostError::Json)
}

fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ProductionSignerHostError> {
    if max_bytes == 0 {
        return Err(ProductionSignerHostError::FileSizeInvalid);
    }
    reject_symlink(path)?;
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > max_bytes {
        return Err(ProductionSignerHostError::FileSizeInvalid);
    }
    let before_modified = before.modified().ok();
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || bytes.len() as u64 > max_bytes
        || after.len() != before.len()
        || (before_modified.is_some() && after.modified().ok() != before_modified)
    {
        return Err(ProductionSignerHostError::FileChangedDuringRead);
    }
    Ok(bytes)
}

fn hash_stable_file(path: &Path, max_bytes: u64) -> Result<String, ProductionSignerHostError> {
    let bytes = read_bounded_file(path, max_bytes)?;
    Ok(encode_hex(&Sha256::digest(bytes)))
}

fn require_absolute_path(path: PathBuf) -> Result<PathBuf, ProductionSignerHostError> {
    if !path.is_absolute() {
        return Err(ProductionSignerHostError::PathNotAbsolute);
    }
    reject_symlink_if_present(&path)?;
    Ok(path)
}

fn validate_absolute_path_text(value: &str) -> Result<(), ProductionSignerHostError> {
    if value.is_empty() || value.contains('\0') || value.contains('"') {
        return Err(ProductionSignerHostError::InvalidPathEncoding);
    }
    require_absolute_path(PathBuf::from(value)).map(|_| ())
}

fn path_text(path: &Path) -> Result<String, ProductionSignerHostError> {
    path.to_str()
        .filter(|value| !value.is_empty() && !value.contains('\0') && !value.contains('"'))
        .map(ToOwned::to_owned)
        .ok_or(ProductionSignerHostError::InvalidPathEncoding)
}

fn quote_windows_argument(value: &str) -> Result<String, ProductionSignerHostError> {
    if value.is_empty() || value.contains('\0') || value.contains('"') {
        return Err(ProductionSignerHostError::InvalidPathEncoding);
    }
    Ok(format!("\"{value}\""))
}

fn reject_symlink(path: &Path) -> Result<(), ProductionSignerHostError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(ProductionSignerHostError::SymbolicLinkRejected);
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path) -> Result<(), ProductionSignerHostError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ProductionSignerHostError::SymbolicLinkRejected)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ProductionSignerHostError::Io(error)),
    }
}

fn digest_with_blank_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, ProductionSignerHostError> {
    let mut value = serde_json::to_value(value)?;
    let object = value
        .as_object_mut()
        .ok_or(ProductionSignerHostError::InvalidCanonicalObject)?;
    blank_digest_field(object, field)?;
    Ok(canonical_json_sha256(&value)?)
}

fn blank_digest_field(
    object: &mut serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), ProductionSignerHostError> {
    if object.contains_key(field) {
        object.insert(field.to_owned(), Value::String(String::new()));
        return Ok(());
    }
    let status = object
        .get_mut("status")
        .and_then(Value::as_object_mut)
        .ok_or(ProductionSignerHostError::InvalidCanonicalObject)?;
    if !status.contains_key(field) {
        return Err(ProductionSignerHostError::InvalidCanonicalObject);
    }
    status.insert(field.to_owned(), Value::String(String::new()));
    Ok(())
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

#[derive(Debug, Error)]
pub enum ProductionSignerHostError {
    #[error("production signer host is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("production signer service manifest schema is unsupported")]
    UnsupportedManifestSchema,
    #[error("production signer host response schema is unsupported")]
    UnsupportedResponseSchema,
    #[error("production signer service manifest digest does not match")]
    ManifestDigestMismatch,
    #[error("production signer host response digest does not match")]
    ResponseDigestMismatch,
    #[error("production signer service hardening policy was weakened")]
    ServiceHardeningWeakened,
    #[error("production signer service manifest revision is invalid")]
    InvalidManifestRevision,
    #[error("production signer service path must be absolute")]
    PathNotAbsolute,
    #[error("production signer service path encoding is invalid")]
    InvalidPathEncoding,
    #[error("production signer service symbolic link was rejected")]
    SymbolicLinkRejected,
    #[error("production signer service file size is invalid")]
    FileSizeInvalid,
    #[error("production signer service file changed while being read")]
    FileChangedDuringRead,
    #[error("production signer executable digest does not match the manifest")]
    ExecutableDigestMismatch,
    #[error("accepted production trust state does not match installed configuration")]
    AcceptedStateConfigurationMismatch,
    #[error("production signer named-pipe policy does not match deployment policy")]
    PipePolicyMismatch,
    #[error("production CNG provider is not hardware-only")]
    CngProviderNotHardwareOnly,
    #[error("production CNG key does not match the accepted registry record")]
    CngRegistryMismatch,
    #[error("no active production signer generation is available")]
    ActiveGenerationUnavailable,
    #[error("production signer host canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("production signer service SCM operation failed: {0}")]
    WindowsService(#[source] std::io::Error),
    #[error("production signer host I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("production signer host JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    ProductionSigner(#[from] ProductionSignerError),
    #[error(transparent)]
    SignerService(#[from] ProductionSignerServiceError),
    #[error(transparent)]
    SignerIdentity(#[from] SignerIdentityError),
    #[error(transparent)]
    Transport(#[from] ProductionSignerTransportError),
    #[error(transparent)]
    TrustState(#[from] ergaxiom_windows_production_trust_state_runtime::ProductionTrustStateError),
    #[error(transparent)]
    TrustStore(#[from] ProductionTrustStoreError),
    #[error(transparent)]
    DeployedSigner(#[from] DeployedProductionSignerError),
    #[error(transparent)]
    KeyGovernance(
        #[from] ergaxiom_windows_production_key_governance_runtime::ProductionKeyGovernanceError,
    ),
    #[error(transparent)]
    Cng(#[from] CngProviderError),
}
