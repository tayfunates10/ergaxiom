use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_production_key_governance_runtime::{
    ProductionKeyGovernanceError, ProductionKeyTrustBinding,
};
use ergaxiom_windows_production_signer_host_runtime::{
    LoadedProductionSignerHostConfig, ProductionSignerHostError,
};
use ergaxiom_windows_production_signer_runtime::{
    ProductionKeyIdentity, ProductionSignerError, validate_identifier, validate_sha256,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const BACKEND_PRODUCTION_DEPLOYMENT_MANIFEST_SCHEMA: &str = "0.1.0";
pub const BACKEND_PRODUCTION_MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
pub const BACKEND_PRODUCTION_MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendProductionDeploymentManifest {
    pub schema_version: String,
    pub deployment_id: String,
    pub backend_id: String,
    pub backend_caller_id: String,
    pub backend_principal_sid: String,
    pub backend_session_id: Option<u32>,
    pub backend_executable_path: String,
    pub backend_executable_sha256: String,
    pub signer_service_manifest_path: String,
    pub signer_service_manifest_digest: String,
    pub signer_service_executable_sha256: String,
    pub caller_allowlist_revision: u64,
    pub caller_allowlist_digest: String,
    pub deployment_policy_revision: u64,
    pub deployment_policy_digest: String,
    pub accepted_trust_state_revision: u64,
    pub minimum_accepted_trust_state_revision: u64,
    pub accepted_trust_state_binding_digest: String,
    pub registry_revision: u64,
    pub registry_digest: String,
    pub capability_key: ProductionKeyTrustBinding,
    pub attestation_key: ProductionKeyTrustBinding,
    pub manifest_digest: String,
}

impl BackendProductionDeploymentManifest {
    pub fn provision(
        backend_id: impl Into<String>,
        backend_caller_id: impl Into<String>,
        backend_executable_path: impl Into<PathBuf>,
        signer_service_manifest_path: impl Into<PathBuf>,
        trusted_now_epoch_s: u64,
    ) -> Result<Self, BackendProductionDeploymentError> {
        let backend_id = backend_id.into();
        let backend_caller_id = backend_caller_id.into();
        let backend_executable_path = require_absolute_path(backend_executable_path.into())?;
        let signer_service_manifest_path =
            require_absolute_path(signer_service_manifest_path.into())?;
        let backend_executable_sha256 = hash_stable_file(
            &backend_executable_path,
            BACKEND_PRODUCTION_MAX_EXECUTABLE_BYTES,
        )?;
        let signer = LoadedProductionSignerHostConfig::load(
            &signer_service_manifest_path,
            trusted_now_epoch_s,
        )?;
        let evidence = BackendProductionDeploymentEvidence::from_loaded(
            &signer,
            &backend_caller_id,
            &path_text(&backend_executable_path)?,
            &backend_executable_sha256,
            &path_text(&signer_service_manifest_path)?,
            trusted_now_epoch_s,
        )?;
        let manifest = Self::from_evidence(backend_id, evidence)?;
        manifest.verify_against_loaded(&signer, trusted_now_epoch_s)?;
        Ok(manifest)
    }

    pub fn load_pinned(
        manifest_path: &Path,
        expected_manifest_digest: &str,
        current_backend_executable_path: &Path,
        trusted_now_epoch_s: u64,
    ) -> Result<LoadedBackendProductionDeployment, BackendProductionDeploymentError> {
        let manifest = read_pinned_manifest(manifest_path, expected_manifest_digest)?;
        let current_backend_executable_path =
            require_absolute_path(current_backend_executable_path.to_path_buf())?;
        let current_path = path_text(&current_backend_executable_path)?;
        if current_path != manifest.backend_executable_path {
            return Err(BackendProductionDeploymentError::BackendExecutablePathMismatch);
        }
        let current_digest = hash_stable_file(
            &current_backend_executable_path,
            BACKEND_PRODUCTION_MAX_EXECUTABLE_BYTES,
        )?;
        if current_digest != manifest.backend_executable_sha256 {
            return Err(BackendProductionDeploymentError::BackendExecutableDigestMismatch);
        }
        let signer_manifest_path = Path::new(&manifest.signer_service_manifest_path);
        let signer =
            LoadedProductionSignerHostConfig::load(signer_manifest_path, trusted_now_epoch_s)?;
        manifest.verify_against_loaded(&signer, trusted_now_epoch_s)?;
        Ok(LoadedBackendProductionDeployment { manifest, signer })
    }

    pub fn validate_seal(&self) -> Result<(), BackendProductionDeploymentError> {
        if self.schema_version != BACKEND_PRODUCTION_DEPLOYMENT_MANIFEST_SCHEMA {
            return Err(BackendProductionDeploymentError::UnsupportedManifestSchema);
        }
        validate_identifier("deployment_id", &self.deployment_id)?;
        validate_identifier("backend_id", &self.backend_id)?;
        validate_identifier("backend_caller_id", &self.backend_caller_id)?;
        validate_absolute_path_text(&self.backend_executable_path)?;
        validate_absolute_path_text(&self.signer_service_manifest_path)?;
        for digest in [
            &self.backend_executable_sha256,
            &self.signer_service_manifest_digest,
            &self.signer_service_executable_sha256,
            &self.caller_allowlist_digest,
            &self.deployment_policy_digest,
            &self.accepted_trust_state_binding_digest,
            &self.registry_digest,
            &self.manifest_digest,
        ] {
            validate_sha256(digest)?;
        }
        if self.caller_allowlist_revision == 0
            || self.deployment_policy_revision == 0
            || self.accepted_trust_state_revision == 0
            || self.minimum_accepted_trust_state_revision == 0
            || self.minimum_accepted_trust_state_revision > self.accepted_trust_state_revision
            || self.registry_revision == 0
        {
            return Err(BackendProductionDeploymentError::InvalidManifestRevision);
        }
        self.capability_key.validate_shape()?;
        self.attestation_key.validate_shape()?;
        if self.capability_key.identity != ProductionKeyIdentity::capability()
            || self.attestation_key.identity != ProductionKeyIdentity::attestation()
        {
            return Err(BackendProductionDeploymentError::ProductionIdentitySubstitution);
        }
        for binding in [&self.capability_key, &self.attestation_key] {
            if binding.registry_revision != self.registry_revision
                || binding.registry_digest != self.registry_digest
            {
                return Err(BackendProductionDeploymentError::RegistryBindingMismatch);
            }
        }
        if self.capability_key.public_key_digest == self.attestation_key.public_key_digest {
            return Err(BackendProductionDeploymentError::ProductionKeyReuse);
        }
        if self.manifest_digest != self.expected_digest()? {
            return Err(BackendProductionDeploymentError::ManifestDigestMismatch);
        }
        Ok(())
    }

    pub fn write_create_new(
        &self,
        destination: &Path,
    ) -> Result<(), BackendProductionDeploymentError> {
        self.validate_seal()?;
        let destination = require_absolute_path(destination.to_path_buf())?;
        reject_symlink_if_present(&destination)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.is_empty() || bytes.len() as u64 > BACKEND_PRODUCTION_MAX_CONFIG_BYTES {
            return Err(BackendProductionDeploymentError::FileSizeInvalid);
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn from_evidence(
        backend_id: String,
        evidence: BackendProductionDeploymentEvidence,
    ) -> Result<Self, BackendProductionDeploymentError> {
        let mut manifest = Self {
            schema_version: BACKEND_PRODUCTION_DEPLOYMENT_MANIFEST_SCHEMA.to_owned(),
            deployment_id: evidence.deployment_id,
            backend_id,
            backend_caller_id: evidence.backend_caller_id,
            backend_principal_sid: evidence.backend_principal_sid,
            backend_session_id: evidence.backend_session_id,
            backend_executable_path: evidence.backend_executable_path,
            backend_executable_sha256: evidence.backend_executable_sha256,
            signer_service_manifest_path: evidence.signer_service_manifest_path,
            signer_service_manifest_digest: evidence.signer_service_manifest_digest,
            signer_service_executable_sha256: evidence.signer_service_executable_sha256,
            caller_allowlist_revision: evidence.caller_allowlist_revision,
            caller_allowlist_digest: evidence.caller_allowlist_digest,
            deployment_policy_revision: evidence.deployment_policy_revision,
            deployment_policy_digest: evidence.deployment_policy_digest,
            accepted_trust_state_revision: evidence.accepted_trust_state_revision,
            minimum_accepted_trust_state_revision: evidence
                .minimum_accepted_trust_state_revision,
            accepted_trust_state_binding_digest: evidence.accepted_trust_state_binding_digest,
            registry_revision: evidence.registry_revision,
            registry_digest: evidence.registry_digest,
            capability_key: evidence.capability_key,
            attestation_key: evidence.attestation_key,
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = manifest.expected_digest()?;
        manifest.validate_seal()?;
        Ok(manifest)
    }

    fn verify_against_loaded(
        &self,
        signer: &LoadedProductionSignerHostConfig,
        trusted_now_epoch_s: u64,
    ) -> Result<(), BackendProductionDeploymentError> {
        self.validate_seal()?;
        let evidence = BackendProductionDeploymentEvidence::from_loaded(
            signer,
            &self.backend_caller_id,
            &self.backend_executable_path,
            &self.backend_executable_sha256,
            &self.signer_service_manifest_path,
            trusted_now_epoch_s,
        )?;
        self.verify_against_evidence(&evidence)
    }

    fn verify_against_evidence(
        &self,
        evidence: &BackendProductionDeploymentEvidence,
    ) -> Result<(), BackendProductionDeploymentError> {
        if self.deployment_id != evidence.deployment_id
            || self.signer_service_manifest_path != evidence.signer_service_manifest_path
            || self.signer_service_manifest_digest != evidence.signer_service_manifest_digest
            || self.signer_service_executable_sha256
                != evidence.signer_service_executable_sha256
            || self.caller_allowlist_revision != evidence.caller_allowlist_revision
            || self.caller_allowlist_digest != evidence.caller_allowlist_digest
            || self.deployment_policy_revision != evidence.deployment_policy_revision
            || self.deployment_policy_digest != evidence.deployment_policy_digest
        {
            return Err(BackendProductionDeploymentError::SignerConfigurationMismatch);
        }
        if self.accepted_trust_state_revision != evidence.accepted_trust_state_revision
            || self.minimum_accepted_trust_state_revision
                != evidence.minimum_accepted_trust_state_revision
            || self.accepted_trust_state_binding_digest
                != evidence.accepted_trust_state_binding_digest
            || self.registry_revision != evidence.registry_revision
            || self.registry_digest != evidence.registry_digest
        {
            return Err(BackendProductionDeploymentError::AcceptedTrustStateMismatch);
        }
        if self.backend_caller_id != evidence.backend_caller_id
            || self.backend_principal_sid != evidence.backend_principal_sid
            || self.backend_session_id != evidence.backend_session_id
            || self.backend_executable_path != evidence.backend_executable_path
            || self.backend_executable_sha256 != evidence.backend_executable_sha256
        {
            return Err(BackendProductionDeploymentError::BackendCallerBindingMismatch);
        }
        if self.capability_key != evidence.capability_key
            || self.attestation_key != evidence.attestation_key
        {
            return Err(BackendProductionDeploymentError::ProductionKeyBindingMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, BackendProductionDeploymentError> {
        digest_with_blank_field(self, "manifest_digest")
    }
}

#[derive(Debug, Clone)]
pub struct LoadedBackendProductionDeployment {
    pub manifest: BackendProductionDeploymentManifest,
    pub signer: LoadedProductionSignerHostConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackendProductionDeploymentEvidence {
    deployment_id: String,
    backend_caller_id: String,
    backend_principal_sid: String,
    backend_session_id: Option<u32>,
    backend_executable_path: String,
    backend_executable_sha256: String,
    signer_service_manifest_path: String,
    signer_service_manifest_digest: String,
    signer_service_executable_sha256: String,
    caller_allowlist_revision: u64,
    caller_allowlist_digest: String,
    deployment_policy_revision: u64,
    deployment_policy_digest: String,
    accepted_trust_state_revision: u64,
    minimum_accepted_trust_state_revision: u64,
    accepted_trust_state_binding_digest: String,
    registry_revision: u64,
    registry_digest: String,
    capability_key: ProductionKeyTrustBinding,
    attestation_key: ProductionKeyTrustBinding,
}

impl BackendProductionDeploymentEvidence {
    fn from_loaded(
        signer: &LoadedProductionSignerHostConfig,
        backend_caller_id: &str,
        backend_executable_path: &str,
        backend_executable_sha256: &str,
        signer_service_manifest_path: &str,
        trusted_now_epoch_s: u64,
    ) -> Result<Self, BackendProductionDeploymentError> {
        validate_identifier("backend_caller_id", backend_caller_id)?;
        validate_absolute_path_text(backend_executable_path)?;
        validate_absolute_path_text(signer_service_manifest_path)?;
        validate_sha256(backend_executable_sha256)?;
        signer.manifest.validate_seal()?;

        let matching: Vec<_> = signer
            .caller_allowlist
            .entries
            .iter()
            .filter(|entry| entry.caller_id == backend_caller_id)
            .collect();
        let caller = match matching.as_slice() {
            [caller] => *caller,
            [] => return Err(BackendProductionDeploymentError::BackendCallerUnavailable),
            _ => return Err(BackendProductionDeploymentError::BackendCallerAmbiguous),
        };
        if caller.executable_path != backend_executable_path
            || caller.executable_sha256 != backend_executable_sha256
        {
            return Err(BackendProductionDeploymentError::BackendCallerBindingMismatch);
        }

        let accepted = &signer.accepted;
        let capability_identity = ProductionKeyIdentity::capability();
        let attestation_identity = ProductionKeyIdentity::attestation();
        if !signer.deployment_policy.permits(&capability_identity)
            || !signer.deployment_policy.permits(&attestation_identity)
        {
            return Err(BackendProductionDeploymentError::ProductionIdentityDisabled);
        }
        let capability_generation = accepted
            .registry()
            .active_record(&capability_identity, trusted_now_epoch_s)?
            .generation;
        let attestation_generation = accepted
            .registry()
            .active_record(&attestation_identity, trusted_now_epoch_s)?
            .generation;
        let capability_key = accepted.registry().trust_binding(
            &capability_identity,
            capability_generation,
            trusted_now_epoch_s,
        )?;
        let attestation_key = accepted.registry().trust_binding(
            &attestation_identity,
            attestation_generation,
            trusted_now_epoch_s,
        )?;
        let binding = accepted.binding();
        let body = accepted.body();

        Ok(Self {
            deployment_id: signer.manifest.deployment_id.clone(),
            backend_caller_id: caller.caller_id.clone(),
            backend_principal_sid: caller.principal_sid.clone(),
            backend_session_id: caller.session_id,
            backend_executable_path: caller.executable_path.clone(),
            backend_executable_sha256: caller.executable_sha256.clone(),
            signer_service_manifest_path: signer_service_manifest_path.to_owned(),
            signer_service_manifest_digest: signer.manifest.manifest_digest.clone(),
            signer_service_executable_sha256: signer.manifest.executable_sha256.clone(),
            caller_allowlist_revision: signer.caller_allowlist.revision,
            caller_allowlist_digest: signer.caller_allowlist.allowlist_digest.clone(),
            deployment_policy_revision: signer.deployment_policy.revision,
            deployment_policy_digest: signer.deployment_policy.policy_digest.clone(),
            accepted_trust_state_revision: body.revision,
            minimum_accepted_trust_state_revision: body.minimum_accepted_revision,
            accepted_trust_state_binding_digest: binding.binding_digest.clone(),
            registry_revision: accepted.registry().revision(),
            registry_digest: accepted.registry().registry_digest()?,
            capability_key,
            attestation_key,
        })
    }
}

fn read_pinned_manifest(
    manifest_path: &Path,
    expected_manifest_digest: &str,
) -> Result<BackendProductionDeploymentManifest, BackendProductionDeploymentError> {
    validate_sha256(expected_manifest_digest)?;
    let manifest_path = require_absolute_path(manifest_path.to_path_buf())?;
    let manifest: BackendProductionDeploymentManifest =
        read_bounded_json(&manifest_path, BACKEND_PRODUCTION_MAX_CONFIG_BYTES)?;
    manifest.validate_seal()?;
    if manifest.manifest_digest != expected_manifest_digest {
        return Err(BackendProductionDeploymentError::PinnedManifestDigestMismatch);
    }
    Ok(manifest)
}

fn require_absolute_path(path: PathBuf) -> Result<PathBuf, BackendProductionDeploymentError> {
    if !path.is_absolute() {
        return Err(BackendProductionDeploymentError::PathNotAbsolute);
    }
    path_text(&path)?;
    reject_symlink_if_present(&path)?;
    Ok(path)
}

fn validate_absolute_path_text(path: &str) -> Result<(), BackendProductionDeploymentError> {
    if path.is_empty()
        || path.contains(['\0', '\n', '\r', '"'])
        || !(Path::new(path).is_absolute() || looks_like_windows_absolute(path))
    {
        return Err(BackendProductionDeploymentError::PathNotAbsolute);
    }
    Ok(())
}

fn looks_like_windows_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/'))
        || path.starts_with(r"\\?\")
}

fn path_text(path: &Path) -> Result<String, BackendProductionDeploymentError> {
    let value = path
        .to_str()
        .ok_or(BackendProductionDeploymentError::InvalidPathEncoding)?;
    if value.contains(['\0', '\n', '\r', '"']) {
        return Err(BackendProductionDeploymentError::InvalidPathEncoding);
    }
    Ok(value.to_owned())
}

fn reject_symlink_if_present(path: &Path) -> Result<(), BackendProductionDeploymentError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(BackendProductionDeploymentError::SymbolicLinkRejected)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_bounded_json<T: DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
) -> Result<T, BackendProductionDeploymentError> {
    let bytes = read_stable_file(path, max_bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn hash_stable_file(
    path: &Path,
    max_bytes: u64,
) -> Result<String, BackendProductionDeploymentError> {
    let bytes = read_stable_file(path, max_bytes)?;
    Ok(encode_hex(&Sha256::digest(bytes)))
}

fn read_stable_file(
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, BackendProductionDeploymentError> {
    let path = require_absolute_path(path.to_path_buf())?;
    let before = fs::metadata(&path)?;
    if !before.is_file() || before.len() == 0 || before.len() > max_bytes {
        return Err(BackendProductionDeploymentError::FileSizeInvalid);
    }
    let before_modified = before.modified().ok();
    let mut file = File::open(&path)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(BackendProductionDeploymentError::FileSizeInvalid);
    }
    let after = fs::metadata(&path)?;
    if before.len() != after.len()
        || before_modified != after.modified().ok()
        || after.file_type().is_symlink()
    {
        return Err(BackendProductionDeploymentError::FileChangedDuringRead);
    }
    Ok(bytes)
}

fn digest_with_blank_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, BackendProductionDeploymentError> {
    let mut value = serde_json::to_value(value)?;
    let object = value
        .as_object_mut()
        .ok_or(BackendProductionDeploymentError::InvalidCanonicalObject)?;
    if !object.contains_key(field) {
        return Err(BackendProductionDeploymentError::InvalidCanonicalObject);
    }
    object.insert(field.to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
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
pub enum BackendProductionDeploymentError {
    #[error("backend production deployment manifest schema is unsupported")]
    UnsupportedManifestSchema,
    #[error("backend production deployment manifest digest does not match")]
    ManifestDigestMismatch,
    #[error("backend production deployment manifest does not match the installer pin")]
    PinnedManifestDigestMismatch,
    #[error("backend production deployment manifest revision is invalid")]
    InvalidManifestRevision,
    #[error("backend production deployment path must be absolute")]
    PathNotAbsolute,
    #[error("backend production deployment path encoding is invalid")]
    InvalidPathEncoding,
    #[error("backend production deployment symbolic link was rejected")]
    SymbolicLinkRejected,
    #[error("backend production deployment file size is invalid")]
    FileSizeInvalid,
    #[error("backend production deployment file changed while being read")]
    FileChangedDuringRead,
    #[error("current backend executable path does not match the deployment manifest")]
    BackendExecutablePathMismatch,
    #[error("current backend executable digest does not match the deployment manifest")]
    BackendExecutableDigestMismatch,
    #[error("backend caller is absent from the signer allowlist")]
    BackendCallerUnavailable,
    #[error("backend caller identity is ambiguous in the signer allowlist")]
    BackendCallerAmbiguous,
    #[error("backend caller path, digest, principal or session binding does not match")]
    BackendCallerBindingMismatch,
    #[error("signer service manifest, allowlist or deployment policy does not match")]
    SignerConfigurationMismatch,
    #[error("accepted production trust state does not match the backend deployment manifest")]
    AcceptedTrustStateMismatch,
    #[error("production signer identity was substituted")]
    ProductionIdentitySubstitution,
    #[error("required production signer identity is disabled")]
    ProductionIdentityDisabled,
    #[error("production key registry binding does not match")]
    RegistryBindingMismatch,
    #[error("production capability and attestation keys must remain separate")]
    ProductionKeyReuse,
    #[error("production key generation binding does not match")]
    ProductionKeyBindingMismatch,
    #[error("backend production deployment canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("backend production deployment I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("backend production deployment JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    ProductionSigner(#[from] ProductionSignerError),
    #[error(transparent)]
    KeyGovernance(#[from] ProductionKeyGovernanceError),
    #[error(transparent)]
    SignerHost(#[from] ProductionSignerHostError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use ergaxiom_windows_production_key_governance_runtime::PRODUCTION_KEY_TRUST_BINDING_SCHEMA;

    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const DIGEST_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const DIGEST_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const DIGEST_F: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    fn unique_root() -> Result<PathBuf, Box<dyn Error>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!(
            "ergaxiom-backend-production-deployment-{now}-{}",
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn key_binding(identity: ProductionKeyIdentity, generation: u64, digest: &str) -> ProductionKeyTrustBinding {
        ProductionKeyTrustBinding {
            schema_version: PRODUCTION_KEY_TRUST_BINDING_SCHEMA.to_owned(),
            identity,
            generation,
            public_key_digest: digest.to_owned(),
            key_record_digest: if generation == 1 { DIGEST_D } else { DIGEST_E }.to_owned(),
            registry_revision: 2,
            registry_digest: DIGEST_C.to_owned(),
        }
    }

    fn fixture() -> Result<(PathBuf, BackendProductionDeploymentEvidence), Box<dyn Error>> {
        let root = unique_root()?;
        fs::create_dir_all(&root)?;
        let backend = root.join("ergaxiom-desktop.exe");
        fs::write(&backend, b"verified backend image")?;
        let signer_manifest = root.join("production-signer-manifest.json");
        fs::write(&signer_manifest, b"signer manifest placeholder")?;
        let backend_digest = hash_stable_file(&backend, BACKEND_PRODUCTION_MAX_EXECUTABLE_BYTES)?;
        let evidence = BackendProductionDeploymentEvidence {
            deployment_id: "ergaxiom-production-a".to_owned(),
            backend_caller_id: "ergaxiom.desktop.backend".to_owned(),
            backend_principal_sid: "S-1-5-21-1000".to_owned(),
            backend_session_id: Some(7),
            backend_executable_path: path_text(&backend)?,
            backend_executable_sha256: backend_digest,
            signer_service_manifest_path: path_text(&signer_manifest)?,
            signer_service_manifest_digest: DIGEST_A.to_owned(),
            signer_service_executable_sha256: DIGEST_B.to_owned(),
            caller_allowlist_revision: 3,
            caller_allowlist_digest: DIGEST_D.to_owned(),
            deployment_policy_revision: 4,
            deployment_policy_digest: DIGEST_E.to_owned(),
            accepted_trust_state_revision: 5,
            minimum_accepted_trust_state_revision: 4,
            accepted_trust_state_binding_digest: DIGEST_F.to_owned(),
            registry_revision: 2,
            registry_digest: DIGEST_C.to_owned(),
            capability_key: key_binding(ProductionKeyIdentity::capability(), 1, DIGEST_A),
            attestation_key: key_binding(ProductionKeyIdentity::attestation(), 2, DIGEST_B),
        };
        Ok((root, evidence))
    }

    #[test]
    fn sealed_manifest_requires_external_pin_and_create_new_storage() -> Result<(), Box<dyn Error>> {
        let (root, evidence) = fixture()?;
        let manifest = BackendProductionDeploymentManifest::from_evidence(
            "ergaxiom.desktop.production".to_owned(),
            evidence,
        )?;
        manifest.validate_seal()?;
        let destination = root.join("backend-production-manifest.json");
        manifest.write_create_new(&destination)?;
        assert!(manifest.write_create_new(&destination).is_err());
        let loaded = read_pinned_manifest(&destination, &manifest.manifest_digest)?;
        assert_eq!(loaded, manifest);
        assert!(matches!(
            read_pinned_manifest(&destination, DIGEST_A),
            Err(BackendProductionDeploymentError::PinnedManifestDigestMismatch)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn recomputed_tampered_manifest_still_fails_the_installer_pin() -> Result<(), Box<dyn Error>> {
        let (root, evidence) = fixture()?;
        let manifest = BackendProductionDeploymentManifest::from_evidence(
            "ergaxiom.desktop.production".to_owned(),
            evidence,
        )?;
        let original_pin = manifest.manifest_digest.clone();
        let mut altered = manifest;
        altered.backend_id = "ergaxiom.desktop.substituted".to_owned();
        altered.manifest_digest = altered.expected_digest()?;
        altered.validate_seal()?;
        let destination = root.join("backend-production-manifest.json");
        altered.write_create_new(&destination)?;
        assert!(matches!(
            read_pinned_manifest(&destination, &original_pin),
            Err(BackendProductionDeploymentError::PinnedManifestDigestMismatch)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn path_role_registry_and_key_reuse_mutations_fail_closed() -> Result<(), Box<dyn Error>> {
        let (root, evidence) = fixture()?;
        let manifest = BackendProductionDeploymentManifest::from_evidence(
            "ergaxiom.desktop.production".to_owned(),
            evidence,
        )?;

        let mut relative = manifest.clone();
        relative.backend_executable_path = "relative/ergaxiom-desktop.exe".to_owned();
        relative.manifest_digest = relative.expected_digest()?;
        assert!(matches!(
            relative.validate_seal(),
            Err(BackendProductionDeploymentError::PathNotAbsolute)
        ));

        let mut role = manifest.clone();
        role.capability_key.identity = ProductionKeyIdentity::attestation();
        role.manifest_digest = role.expected_digest()?;
        assert!(matches!(
            role.validate_seal(),
            Err(BackendProductionDeploymentError::ProductionIdentitySubstitution)
        ));

        let mut registry = manifest.clone();
        registry.capability_key.registry_revision = 9;
        registry.manifest_digest = registry.expected_digest()?;
        assert!(matches!(
            registry.validate_seal(),
            Err(BackendProductionDeploymentError::RegistryBindingMismatch)
        ));

        let mut reused = manifest;
        reused.attestation_key.public_key_digest = reused.capability_key.public_key_digest.clone();
        reused.manifest_digest = reused.expected_digest()?;
        assert!(matches!(
            reused.validate_seal(),
            Err(BackendProductionDeploymentError::ProductionKeyReuse)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stale_trust_allowlist_and_backend_identity_evidence_fail_closed() -> Result<(), Box<dyn Error>> {
        let (root, evidence) = fixture()?;
        let manifest = BackendProductionDeploymentManifest::from_evidence(
            "ergaxiom.desktop.production".to_owned(),
            evidence.clone(),
        )?;

        let mut stale_trust = evidence.clone();
        stale_trust.accepted_trust_state_revision += 1;
        assert!(matches!(
            manifest.verify_against_evidence(&stale_trust),
            Err(BackendProductionDeploymentError::AcceptedTrustStateMismatch)
        ));

        let mut stale_allowlist = evidence.clone();
        stale_allowlist.caller_allowlist_revision += 1;
        assert!(matches!(
            manifest.verify_against_evidence(&stale_allowlist),
            Err(BackendProductionDeploymentError::SignerConfigurationMismatch)
        ));

        let mut substituted_backend = evidence;
        substituted_backend.backend_executable_sha256 = DIGEST_F.to_owned();
        assert!(matches!(
            manifest.verify_against_evidence(&substituted_backend),
            Err(BackendProductionDeploymentError::BackendCallerBindingMismatch)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_manifest_is_rejected() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let (root, evidence) = fixture()?;
        let manifest = BackendProductionDeploymentManifest::from_evidence(
            "ergaxiom.desktop.production".to_owned(),
            evidence,
        )?;
        let destination = root.join("backend-production-manifest.json");
        manifest.write_create_new(&destination)?;
        let linked = root.join("linked-manifest.json");
        symlink(&destination, &linked)?;
        assert!(matches!(
            read_pinned_manifest(&linked, &manifest.manifest_digest),
            Err(BackendProductionDeploymentError::SymbolicLinkRejected)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
