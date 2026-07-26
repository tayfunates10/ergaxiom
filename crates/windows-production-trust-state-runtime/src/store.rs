use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ergaxiom_proof_kernel::canonical_json_sha256;
use ergaxiom_windows_production_signer_runtime::validate_sha256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AcceptedTrustCheckpoint, ActivatedProductionTrustState, ProductionTrustRecoveryEnvelope,
    ProductionTrustStateActivator, ProductionTrustStateEnvelope, ProductionTrustStateError,
    TrustGovernancePolicy,
};

pub const STORED_TRUST_STATE_FILE_SCHEMA: &str = "0.1.0";
pub const ACCEPTED_TRUST_POINTER_SCHEMA: &str = "0.1.0";
pub const DEFAULT_MAX_TRUST_FILE_BYTES: u64 = 16 * 1024 * 1024;

const STATES_DIRECTORY: &str = "states";
const RECOVERIES_DIRECTORY: &str = "recoveries";
const ACCEPTED_POINTER_FILE: &str = "accepted.json";
const TEMP_SUFFIX: &str = ".tmp";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredTrustStateFile {
    schema_version: String,
    envelope: ProductionTrustStateEnvelope,
    file_digest: String,
}

impl StoredTrustStateFile {
    fn new(envelope: ProductionTrustStateEnvelope) -> Result<Self, ProductionTrustStoreError> {
        let mut stored = Self {
            schema_version: STORED_TRUST_STATE_FILE_SCHEMA.to_owned(),
            envelope,
            file_digest: String::new(),
        };
        stored.file_digest = stored.expected_digest()?;
        stored.validate_seal()?;
        Ok(stored)
    }

    fn validate_seal(&self) -> Result<(), ProductionTrustStoreError> {
        if self.schema_version != STORED_TRUST_STATE_FILE_SCHEMA {
            return Err(ProductionTrustStoreError::UnsupportedStoredStateSchema);
        }
        validate_sha256(&self.file_digest)?;
        if self.file_digest != self.expected_digest()? {
            return Err(ProductionTrustStoreError::StoredStateDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionTrustStoreError> {
        digest_with_blank_field(self, "file_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AcceptedTrustPointer {
    schema_version: String,
    checkpoint: AcceptedTrustCheckpoint,
    state_file_digest: String,
    recovery_envelope_digest: Option<String>,
    pointer_digest: String,
}

impl AcceptedTrustPointer {
    fn new(
        checkpoint: AcceptedTrustCheckpoint,
        state_file_digest: String,
        recovery_envelope_digest: Option<String>,
    ) -> Result<Self, ProductionTrustStoreError> {
        let mut pointer = Self {
            schema_version: ACCEPTED_TRUST_POINTER_SCHEMA.to_owned(),
            checkpoint,
            state_file_digest,
            recovery_envelope_digest,
            pointer_digest: String::new(),
        };
        pointer.pointer_digest = pointer.expected_digest()?;
        pointer.validate_seal()?;
        Ok(pointer)
    }

    fn validate_seal(&self) -> Result<(), ProductionTrustStoreError> {
        if self.schema_version != ACCEPTED_TRUST_POINTER_SCHEMA {
            return Err(ProductionTrustStoreError::UnsupportedAcceptedPointerSchema);
        }
        self.checkpoint.validate_seal()?;
        validate_sha256(&self.state_file_digest)?;
        if let Some(recovery_digest) = &self.recovery_envelope_digest {
            validate_sha256(recovery_digest)?;
        }
        validate_sha256(&self.pointer_digest)?;
        if self.pointer_digest != self.expected_digest()? {
            return Err(ProductionTrustStoreError::AcceptedPointerDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionTrustStoreError> {
        digest_with_blank_field(self, "pointer_digest")
    }
}

#[derive(Debug, Clone)]
pub struct ProductionTrustStateStore {
    root: PathBuf,
    max_file_bytes: u64,
}

impl ProductionTrustStateStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, ProductionTrustStoreError> {
        Self::with_max_file_bytes(root, DEFAULT_MAX_TRUST_FILE_BYTES)
    }

    pub fn with_max_file_bytes(
        root: impl Into<PathBuf>,
        max_file_bytes: u64,
    ) -> Result<Self, ProductionTrustStoreError> {
        let root = root.into();
        if !root.is_absolute() || max_file_bytes == 0 {
            return Err(ProductionTrustStoreError::InvalidStoreConfiguration);
        }
        reject_symlink_if_present(&root)?;
        Ok(Self {
            root,
            max_file_bytes,
        })
    }

    #[must_use]
    pub const fn root(&self) -> &PathBuf {
        &self.root
    }

    pub fn initialize_protected(&self) -> Result<(), ProductionTrustStoreError> {
        reject_symlink_if_present(&self.root)?;
        fs::create_dir_all(&self.root)?;
        reject_symlink(&self.root)?;
        let states = self.states_directory();
        let recoveries = self.recoveries_directory();
        fs::create_dir_all(&states)?;
        fs::create_dir_all(&recoveries)?;
        reject_symlink(&states)?;
        reject_symlink(&recoveries)?;
        platform::harden_directory(&self.root)?;
        platform::harden_directory(&states)?;
        platform::harden_directory(&recoveries)?;
        sync_directory(&self.root)?;
        Ok(())
    }

    pub fn persist_activated(
        &self,
        activated: &ActivatedProductionTrustState,
    ) -> Result<(), ProductionTrustStoreError> {
        self.require_initialized_layout()?;
        activated.checkpoint.validate_seal()?;
        let stored = StoredTrustStateFile::new(activated.verified.envelope().clone())?;
        if stored.envelope.envelope_digest != activated.checkpoint.envelope_digest {
            return Err(ProductionTrustStoreError::CheckpointEnvelopeMismatch);
        }
        let state_path = self.state_path(&stored.envelope.envelope_digest)?;
        write_immutable_json(&state_path, &stored, self.max_file_bytes)?;
        sync_directory(&self.states_directory())?;

        let recovery_digest = if let Some(recovery) = &activated.recovery {
            let path = self.recovery_path(&recovery.envelope_digest)?;
            write_immutable_json(&path, recovery, self.max_file_bytes)?;
            sync_directory(&self.recoveries_directory())?;
            Some(recovery.envelope_digest.clone())
        } else {
            None
        };

        let pointer = AcceptedTrustPointer::new(
            activated.checkpoint.clone(),
            stored.file_digest,
            recovery_digest,
        )?;
        let pointer_bytes = serde_json::to_vec(&pointer)?;
        ensure_size(pointer_bytes.len() as u64, self.max_file_bytes)?;
        let accepted_path = self.accepted_pointer_path();
        write_atomic_pointer(&accepted_path, &pointer_bytes)?;
        sync_directory(&self.root)?;
        Ok(())
    }

    pub fn load_accepted(
        &self,
        governance_policy: &TrustGovernancePolicy,
        trusted_now_epoch_s: u64,
    ) -> Result<ActivatedProductionTrustState, ProductionTrustStoreError> {
        self.require_initialized_layout()?;
        let pointer: AcceptedTrustPointer =
            read_bounded_json(&self.accepted_pointer_path(), self.max_file_bytes)?;
        pointer.validate_seal()?;
        let stored_path = self.state_path(&pointer.checkpoint.envelope_digest)?;
        let stored: StoredTrustStateFile = read_bounded_json(&stored_path, self.max_file_bytes)?;
        stored.validate_seal()?;
        if stored.file_digest != pointer.state_file_digest
            || stored.envelope.envelope_digest != pointer.checkpoint.envelope_digest
        {
            return Err(ProductionTrustStoreError::AcceptedPointerStateMismatch);
        }
        let verified = stored
            .envelope
            .verify(governance_policy, trusted_now_epoch_s)?;
        let activator = ProductionTrustStateActivator::from_accepted(
            verified.clone(),
            pointer.checkpoint.clone(),
        )?;
        let checkpoint = activator
            .checkpoint()
            .cloned()
            .ok_or(ProductionTrustStoreError::AcceptedPointerStateMismatch)?;
        let recovery = match pointer.recovery_envelope_digest {
            Some(digest) => {
                let recovery: ProductionTrustRecoveryEnvelope =
                    read_bounded_json(&self.recovery_path(&digest)?, self.max_file_bytes)?;
                if recovery.envelope_digest != digest {
                    return Err(ProductionTrustStoreError::RecoveryFileDigestMismatch);
                }
                recovery.verify(governance_policy, trusted_now_epoch_s)?;
                Some(recovery)
            }
            None => None,
        };
        Ok(ActivatedProductionTrustState {
            verified,
            checkpoint,
            recovery,
        })
    }

    fn require_initialized_layout(&self) -> Result<(), ProductionTrustStoreError> {
        reject_symlink(&self.root)?;
        reject_symlink(&self.states_directory())?;
        reject_symlink(&self.recoveries_directory())?;
        if !self.root.is_dir()
            || !self.states_directory().is_dir()
            || !self.recoveries_directory().is_dir()
        {
            return Err(ProductionTrustStoreError::StoreNotInitialized);
        }
        Ok(())
    }

    fn states_directory(&self) -> PathBuf {
        self.root.join(STATES_DIRECTORY)
    }

    fn recoveries_directory(&self) -> PathBuf {
        self.root.join(RECOVERIES_DIRECTORY)
    }

    fn accepted_pointer_path(&self) -> PathBuf {
        self.root.join(ACCEPTED_POINTER_FILE)
    }

    fn state_path(&self, envelope_digest: &str) -> Result<PathBuf, ProductionTrustStoreError> {
        validate_sha256(envelope_digest)?;
        Ok(self
            .states_directory()
            .join(format!("{envelope_digest}.json")))
    }

    fn recovery_path(&self, envelope_digest: &str) -> Result<PathBuf, ProductionTrustStoreError> {
        validate_sha256(envelope_digest)?;
        Ok(self
            .recoveries_directory()
            .join(format!("{envelope_digest}.json")))
    }
}

fn write_immutable_json<T: Serialize>(
    destination: &Path,
    value: &T,
    max_file_bytes: u64,
) -> Result<(), ProductionTrustStoreError> {
    reject_symlink_if_present(destination)?;
    let bytes = serde_json::to_vec(value)?;
    ensure_size(bytes.len() as u64, max_file_bytes)?;
    if destination.exists() {
        let existing = read_bounded_bytes(destination, max_file_bytes)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(ProductionTrustStoreError::ImmutableStateConflict);
    }
    let temporary = temporary_path(destination)?;
    reject_symlink_if_present(&temporary)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, destination)?;
    Ok(())
}

fn write_atomic_pointer(destination: &Path, bytes: &[u8]) -> Result<(), ProductionTrustStoreError> {
    reject_symlink_if_present(destination)?;
    let temporary = temporary_path(destination)?;
    reject_symlink_if_present(&temporary)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    platform::atomic_replace(&temporary, destination)?;
    Ok(())
}

fn temporary_path(destination: &Path) -> Result<PathBuf, ProductionTrustStoreError> {
    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ProductionTrustStoreError::InvalidStoreConfiguration)?;
    Ok(destination.with_file_name(format!("{file_name}{TEMP_SUFFIX}")))
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_file_bytes: u64,
) -> Result<T, ProductionTrustStoreError> {
    let bytes = read_bounded_bytes(path, max_file_bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_bounded_bytes(
    path: &Path,
    max_file_bytes: u64,
) -> Result<Vec<u8>, ProductionTrustStoreError> {
    reject_symlink(path)?;
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    ensure_size(metadata.len(), max_file_bytes)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_file_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure_size(bytes.len() as u64, max_file_bytes)?;
    let after = fs::metadata(path)?;
    if after.len() != metadata.len() || after.modified()? != metadata.modified()? {
        return Err(ProductionTrustStoreError::FileChangedDuringRead);
    }
    Ok(bytes)
}

fn ensure_size(size: u64, maximum: u64) -> Result<(), ProductionTrustStoreError> {
    if size == 0 || size > maximum {
        return Err(ProductionTrustStoreError::TrustFileSizeInvalid);
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path) -> Result<(), ProductionTrustStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ProductionTrustStoreError::SymlinkPathRejected)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn reject_symlink(path: &Path) -> Result<(), ProductionTrustStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(ProductionTrustStoreError::SymlinkPathRejected);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ProductionTrustStoreError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<(), ProductionTrustStoreError> {
    platform::sync_directory(path)
}

fn digest_with_blank_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, ProductionTrustStoreError> {
    let mut value = serde_json::to_value(value)?;
    let object = value
        .as_object_mut()
        .ok_or(ProductionTrustStoreError::InvalidCanonicalObject)?;
    object.insert(field.to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

#[cfg(windows)]
mod platform {
    pub use crate::windows::{atomic_replace, harden_directory, sync_directory};
}

#[cfg(not(windows))]
mod platform {
    use std::fs;
    use std::path::Path;

    use super::ProductionTrustStoreError;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    pub fn harden_directory(path: &Path) -> Result<(), ProductionTrustStoreError> {
        #[cfg(unix)]
        {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    pub fn atomic_replace(
        source: &Path,
        destination: &Path,
    ) -> Result<(), ProductionTrustStoreError> {
        fs::rename(source, destination)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ProductionTrustStoreError {
    #[error("production trust store configuration is invalid")]
    InvalidStoreConfiguration,
    #[error("production trust store is not initialized")]
    StoreNotInitialized,
    #[error("production trust store path may not be a symbolic link")]
    SymlinkPathRejected,
    #[error("production trust file size is invalid")]
    TrustFileSizeInvalid,
    #[error("production trust file changed while it was being read")]
    FileChangedDuringRead,
    #[error("immutable production trust-state file conflicts with existing bytes")]
    ImmutableStateConflict,
    #[error("stored production trust-state schema is unsupported")]
    UnsupportedStoredStateSchema,
    #[error("stored production trust-state digest does not match")]
    StoredStateDigestMismatch,
    #[error("accepted production trust pointer schema is unsupported")]
    UnsupportedAcceptedPointerSchema,
    #[error("accepted production trust pointer digest does not match")]
    AcceptedPointerDigestMismatch,
    #[error("accepted production trust pointer does not match its immutable state file")]
    AcceptedPointerStateMismatch,
    #[error("accepted production trust checkpoint does not match the envelope")]
    CheckpointEnvelopeMismatch,
    #[error("production trust recovery file digest does not match")]
    RecoveryFileDigestMismatch,
    #[error("production trust store canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("production trust store Windows security operation failed: {0}")]
    WindowsSecurity(#[source] std::io::Error),
    #[error("production trust store atomic replacement failed: {0}")]
    AtomicReplace(#[source] std::io::Error),
    #[error("production trust store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("production trust store JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    TrustState(#[from] ProductionTrustStateError),
    #[error(transparent)]
    ProductionSigner(#[from] ergaxiom_windows_production_signer_runtime::ProductionSignerError),
    #[error(transparent)]
    Hashing(#[from] ergaxiom_proof_kernel::HashingError),
}
