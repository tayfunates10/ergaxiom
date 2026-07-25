use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_proof_kernel::canonical_json_sha256;
use ergaxiom_windows_signer_protocol_runtime::{
    SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ENCODING_BASE64URL, SignerOperation,
    SignerProtocolError, SignerRequest, SignerResponse, SignerSuccess, encode_hex,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const KEY_RECORD_SCHEMA: &str = "0.1.0";
const MAX_KEY_RECORD_BYTES: u64 = 128 * 1024;
const DPAPI_ENTROPY_DOMAIN: &[u8] = b"ergaxiom.windows-signer.dpapi.entropy.v1\0";

pub trait SecretProtector {
    fn protect(&self, plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, SignerServiceError>;
    fn unprotect(&self, ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, SignerServiceError>;
}

pub trait SeedSource {
    fn fill_seed(&mut self, seed: &mut [u8; 32]) -> Result<(), SignerServiceError>;
}

#[derive(Debug, Default)]
pub struct OsSeedSource;

impl SeedSource for OsSeedSource {
    fn fill_seed(&mut self, seed: &mut [u8; 32]) -> Result<(), SignerServiceError> {
        OsRng
            .try_fill_bytes(seed)
            .map_err(|_| SignerServiceError::RandomGenerationFailed)
    }
}

#[derive(Debug)]
pub struct SignerService<P, S> {
    root: PathBuf,
    protector: P,
    seed_source: S,
}

impl<P, S> SignerService<P, S>
where
    P: SecretProtector,
    S: SeedSource,
{
    pub fn new(
        root: impl Into<PathBuf>,
        protector: P,
        seed_source: S,
    ) -> Result<Self, SignerServiceError> {
        let root = root.into();
        if !root.is_absolute() {
            return Err(SignerServiceError::StorePathMustBeAbsolute);
        }
        Ok(Self {
            root,
            protector,
            seed_source,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn handle(
        &mut self,
        request: &SignerRequest,
    ) -> Result<SignerResponse, SignerServiceError> {
        request.validate()?;
        self.mark_request_id(request)?;
        match request.operation {
            SignerOperation::InitializeKey => self.initialize_key(request),
            SignerOperation::PublicKey => self.public_key(request),
            SignerOperation::SignDigest => self.sign_digest(request),
        }
    }

    fn initialize_key(
        &mut self,
        request: &SignerRequest,
    ) -> Result<SignerResponse, SignerServiceError> {
        let path = self.key_path(request)?;
        if path.exists() {
            return Err(SignerServiceError::KeyAlreadyExists);
        }

        let mut seed = Zeroizing::new([0_u8; 32]);
        self.seed_source.fill_seed(&mut seed)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key_hex = encode_hex(&signing_key.verifying_key().to_bytes());
        let entropy = identity_entropy(request)?;
        let protected_seed = self.protector.protect(seed.as_ref(), &entropy)?;
        if protected_seed.as_slice() == seed.as_ref() {
            return Err(SignerServiceError::ProtectorReturnedPlaintext);
        }

        let mut record = StoredKeyRecord {
            schema_version: KEY_RECORD_SCHEMA.to_owned(),
            role: request.role,
            issuer_id: request.issuer_id.clone(),
            key_id: request.key_id.clone(),
            public_key_hex: public_key_hex.clone(),
            protected_seed_base64: STANDARD.encode(protected_seed),
            record_digest: String::new(),
        };
        record.record_digest = stored_record_digest(&record)?;
        self.write_record_atomically(&path, request, &record)?;

        Ok(SignerResponse::success(
            request.request_id.clone(),
            SignerSuccess::KeyInitialized {
                role: request.role,
                issuer_id: request.issuer_id.clone(),
                key_id: request.key_id.clone(),
                public_key_hex,
                record_digest: record.record_digest,
            },
        ))
    }

    fn public_key(&self, request: &SignerRequest) -> Result<SignerResponse, SignerServiceError> {
        let record = self.load_record(request)?;
        Ok(SignerResponse::success(
            request.request_id.clone(),
            SignerSuccess::PublicKey {
                role: record.role,
                issuer_id: record.issuer_id,
                key_id: record.key_id,
                public_key_hex: record.public_key_hex,
                record_digest: record.record_digest,
            },
        ))
    }

    fn sign_digest(&self, request: &SignerRequest) -> Result<SignerResponse, SignerServiceError> {
        let record = self.load_record(request)?;
        let protected_seed = STANDARD
            .decode(&record.protected_seed_base64)
            .map_err(|_| SignerServiceError::StoredKeyCorrupt)?;
        let entropy = identity_entropy(request)?;
        let plaintext = Zeroizing::new(self.protector.unprotect(&protected_seed, &entropy)?);
        if plaintext.len() != 32 {
            return Err(SignerServiceError::StoredKeyCorrupt);
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        seed.copy_from_slice(&plaintext);
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key_hex = encode_hex(&signing_key.verifying_key().to_bytes());
        if public_key_hex != record.public_key_hex {
            return Err(SignerServiceError::StoredKeyPublicKeyMismatch);
        }

        let envelope = request.signing_envelope()?;
        let envelope_digest = envelope.digest()?;
        let signature = signing_key.sign(&envelope.canonical_bytes()?);
        Ok(SignerResponse::success(
            request.request_id.clone(),
            SignerSuccess::DigestSigned {
                public_key_hex,
                envelope,
                envelope_digest,
                signature_algorithm: SIGNATURE_ALGORITHM_ED25519.to_owned(),
                signature_encoding: SIGNATURE_ENCODING_BASE64URL.to_owned(),
                signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(signature.to_bytes()),
            },
        ))
    }

    fn mark_request_id(&self, request: &SignerRequest) -> Result<(), SignerServiceError> {
        let directory = self.root.join("replay");
        fs::create_dir_all(&directory).map_err(SignerServiceError::CreateStoreDirectory)?;
        let request_id_digest = encode_hex(&Sha256::digest(request.request_id.as_bytes()));
        let marker = directory.join(format!("{request_id_digest}.seen"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(marker)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    SignerServiceError::ReplayDetected
                } else {
                    SignerServiceError::CreateReplayMarker(error)
                }
            })?;
        file.write_all(request.request_digest()?.as_bytes())
            .map_err(SignerServiceError::WriteReplayMarker)?;
        file.sync_all()
            .map_err(SignerServiceError::WriteReplayMarker)?;
        Ok(())
    }

    fn key_path(&self, request: &SignerRequest) -> Result<PathBuf, SignerServiceError> {
        Ok(self
            .root
            .join("keys")
            .join(format!("{}.json", request.identity_digest()?)))
    }

    fn load_record(&self, request: &SignerRequest) -> Result<StoredKeyRecord, SignerServiceError> {
        let path = self.key_path(request)?;
        let metadata = fs::metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SignerServiceError::UnknownKey
            } else {
                SignerServiceError::ReadStoredKey(error)
            }
        })?;
        if !metadata.is_file() || metadata.len() > MAX_KEY_RECORD_BYTES {
            return Err(SignerServiceError::StoredKeyCorrupt);
        }
        let bytes = fs::read(path).map_err(SignerServiceError::ReadStoredKey)?;
        let record: StoredKeyRecord =
            serde_json::from_slice(&bytes).map_err(|_| SignerServiceError::StoredKeyCorrupt)?;
        record.validate_for(request)?;
        Ok(record)
    }

    fn write_record_atomically(
        &self,
        target: &Path,
        request: &SignerRequest,
        record: &StoredKeyRecord,
    ) -> Result<(), SignerServiceError> {
        let parent = target
            .parent()
            .ok_or(SignerServiceError::InvalidStoreLayout)?;
        fs::create_dir_all(parent).map_err(SignerServiceError::CreateStoreDirectory)?;
        let lock_path = target.with_extension("lock");
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    SignerServiceError::KeyInitializationBusy
                } else {
                    SignerServiceError::CreateKeyLock(error)
                }
            })?;

        let result = (|| {
            if target.exists() {
                return Err(SignerServiceError::KeyAlreadyExists);
            }
            let request_digest = request.request_digest()?;
            let temporary = target.with_extension(format!("{request_digest}.tmp"));
            let mut temporary_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(SignerServiceError::CreateTemporaryKey)?;
            let serialized = serde_json::to_vec(record)?;
            temporary_file
                .write_all(&serialized)
                .map_err(SignerServiceError::WriteTemporaryKey)?;
            temporary_file
                .sync_all()
                .map_err(SignerServiceError::WriteTemporaryKey)?;
            drop(temporary_file);
            if let Err(error) = fs::rename(&temporary, target) {
                let _ = fs::remove_file(&temporary);
                return Err(SignerServiceError::CommitStoredKey(error));
            }
            Ok(())
        })();

        drop(lock);
        let _ = fs::remove_file(lock_path);
        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKeyRecord {
    schema_version: String,
    role: ergaxiom_key_governance_runtime::IssuerRole,
    issuer_id: String,
    key_id: String,
    public_key_hex: String,
    protected_seed_base64: String,
    record_digest: String,
}

impl StoredKeyRecord {
    fn validate_for(&self, request: &SignerRequest) -> Result<(), SignerServiceError> {
        if self.schema_version != KEY_RECORD_SCHEMA
            || self.role != request.role
            || self.issuer_id != request.issuer_id
            || self.key_id != request.key_id
            || self.record_digest != stored_record_digest(self)?
            || ergaxiom_windows_signer_protocol_runtime::decode_hex_32(&self.public_key_hex)
                .is_err()
            || self.protected_seed_base64.is_empty()
        {
            return Err(SignerServiceError::StoredKeyCorrupt);
        }
        Ok(())
    }
}

fn stored_record_digest(record: &StoredKeyRecord) -> Result<String, SignerServiceError> {
    let mut value = serde_json::to_value(record)?;
    let object = value
        .as_object_mut()
        .ok_or(SignerServiceError::StoredKeyCorrupt)?;
    object.insert(
        "record_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

fn identity_entropy(request: &SignerRequest) -> Result<[u8; 32], SignerServiceError> {
    let mut hasher = Sha256::new();
    hasher.update(DPAPI_ENTROPY_DOMAIN);
    hasher.update(request.identity_digest()?.as_bytes());
    Ok(hasher.finalize().into())
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DpapiProtector;

#[cfg(windows)]
impl SecretProtector for DpapiProtector {
    fn protect(&self, plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, SignerServiceError> {
        dpapi_transform(plaintext, entropy, true)
    }

    fn unprotect(&self, ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, SignerServiceError> {
        dpapi_transform(ciphertext, entropy, false)
    }
}

#[cfg(windows)]
fn dpapi_transform(
    input: &[u8],
    entropy: &[u8],
    protect: bool,
) -> Result<Vec<u8>, SignerServiceError> {
    use std::ptr::{null, null_mut};
    use std::slice;

    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows_sys::Win32::System::Memory::LocalFree;

    let input_len =
        u32::try_from(input.len()).map_err(|_| SignerServiceError::DpapiInputTooLarge)?;
    let entropy_len =
        u32::try_from(entropy.len()).map_err(|_| SignerServiceError::DpapiInputTooLarge)?;
    let input_blob = CRYPT_INTEGER_BLOB {
        cbData: input_len,
        pbData: input.as_ptr().cast_mut(),
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_len,
        pbData: entropy.as_ptr().cast_mut(),
    };
    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let result = if protect {
        // SAFETY: all DATA_BLOB pointers reference live slices for the duration of the call;
        // reserved and prompt pointers are null as required; output is released with LocalFree.
        unsafe {
            CryptProtectData(
                &input_blob,
                null(),
                &entropy_blob,
                null_mut(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output_blob,
            )
        }
    } else {
        // SAFETY: the same pointer and allocation guarantees as the protection call apply.
        unsafe {
            CryptUnprotectData(
                &input_blob,
                null_mut(),
                &entropy_blob,
                null_mut(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output_blob,
            )
        }
    };
    if result == 0 {
        return Err(if protect {
            SignerServiceError::DpapiProtect(std::io::Error::last_os_error())
        } else {
            SignerServiceError::DpapiUnprotect(std::io::Error::last_os_error())
        });
    }
    if output_blob.pbData.is_null() || output_blob.cbData == 0 {
        return Err(SignerServiceError::DpapiReturnedEmptyOutput);
    }
    // SAFETY: DPAPI returned a valid output allocation of cbData bytes on success.
    let output =
        unsafe { slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize).to_vec() };
    // SAFETY: DPAPI documents that the returned buffer must be released with LocalFree.
    let free_result = unsafe { LocalFree(output_blob.pbData.cast()) };
    if !free_result.is_null() {
        return Err(SignerServiceError::DpapiFreeFailed);
    }
    Ok(output)
}

#[cfg(not(windows))]
#[derive(Debug, Clone, Copy, Default)]
pub struct DpapiProtector;

#[cfg(not(windows))]
impl SecretProtector for DpapiProtector {
    fn protect(&self, _plaintext: &[u8], _entropy: &[u8]) -> Result<Vec<u8>, SignerServiceError> {
        Err(SignerServiceError::UnsupportedPlatform)
    }

    fn unprotect(
        &self,
        _ciphertext: &[u8],
        _entropy: &[u8],
    ) -> Result<Vec<u8>, SignerServiceError> {
        Err(SignerServiceError::UnsupportedPlatform)
    }
}

pub fn default_store_root() -> Result<PathBuf, SignerServiceError> {
    let local_app_data =
        std::env::var_os("LOCALAPPDATA").ok_or(SignerServiceError::LocalAppDataUnavailable)?;
    let root = PathBuf::from(local_app_data)
        .join("Ergaxiom")
        .join("Signer")
        .join("v1");
    if !root.is_absolute() {
        return Err(SignerServiceError::StorePathMustBeAbsolute);
    }
    Ok(root)
}

#[derive(Debug, Error)]
pub enum SignerServiceError {
    #[error("signer store path must be absolute")]
    StorePathMustBeAbsolute,
    #[error("LOCALAPPDATA is unavailable")]
    LocalAppDataUnavailable,
    #[error("signer platform is unsupported")]
    UnsupportedPlatform,
    #[error("signer random generation failed")]
    RandomGenerationFailed,
    #[error("secret protector returned plaintext")]
    ProtectorReturnedPlaintext,
    #[error("key already exists")]
    KeyAlreadyExists,
    #[error("key initialization is busy")]
    KeyInitializationBusy,
    #[error("key is unknown")]
    UnknownKey,
    #[error("signer request ID was already used")]
    ReplayDetected,
    #[error("stored key material is corrupt")]
    StoredKeyCorrupt,
    #[error("stored key public key does not match private material")]
    StoredKeyPublicKeyMismatch,
    #[error("signer store layout is invalid")]
    InvalidStoreLayout,
    #[error("DPAPI input is too large")]
    DpapiInputTooLarge,
    #[error("DPAPI protection failed: {0}")]
    DpapiProtect(#[source] std::io::Error),
    #[error("DPAPI unprotection failed: {0}")]
    DpapiUnprotect(#[source] std::io::Error),
    #[error("DPAPI returned empty output")]
    DpapiReturnedEmptyOutput,
    #[error("DPAPI output could not be released")]
    DpapiFreeFailed,
    #[error("signer store directory could not be created: {0}")]
    CreateStoreDirectory(#[source] std::io::Error),
    #[error("replay marker could not be created: {0}")]
    CreateReplayMarker(#[source] std::io::Error),
    #[error("replay marker could not be written: {0}")]
    WriteReplayMarker(#[source] std::io::Error),
    #[error("key lock could not be created: {0}")]
    CreateKeyLock(#[source] std::io::Error),
    #[error("temporary key file could not be created: {0}")]
    CreateTemporaryKey(#[source] std::io::Error),
    #[error("temporary key file could not be written: {0}")]
    WriteTemporaryKey(#[source] std::io::Error),
    #[error("stored key could not be committed: {0}")]
    CommitStoredKey(#[source] std::io::Error),
    #[error("stored key could not be read: {0}")]
    ReadStoredKey(#[source] std::io::Error),
    #[error("stored key JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Protocol(#[from] SignerProtocolError),
    #[error(transparent)]
    Hashing(#[from] ergaxiom_proof_kernel::HashingError),
}

impl SignerServiceError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::StorePathMustBeAbsolute => "STORE_PATH_INVALID",
            Self::LocalAppDataUnavailable => "LOCAL_APP_DATA_UNAVAILABLE",
            Self::UnsupportedPlatform => "UNSUPPORTED_PLATFORM",
            Self::RandomGenerationFailed => "RANDOM_GENERATION_FAILED",
            Self::ProtectorReturnedPlaintext => "PROTECTOR_FAILED_CLOSED",
            Self::KeyAlreadyExists => "KEY_ALREADY_EXISTS",
            Self::KeyInitializationBusy => "KEY_INITIALIZATION_BUSY",
            Self::UnknownKey => "UNKNOWN_KEY",
            Self::ReplayDetected => "REQUEST_REPLAYED",
            Self::StoredKeyCorrupt => "STORED_KEY_CORRUPT",
            Self::StoredKeyPublicKeyMismatch => "KEY_MATERIAL_MISMATCH",
            Self::InvalidStoreLayout => "STORE_LAYOUT_INVALID",
            Self::DpapiInputTooLarge => "DPAPI_INPUT_TOO_LARGE",
            Self::DpapiProtect(_) => "DPAPI_PROTECT_FAILED",
            Self::DpapiUnprotect(_) => "DPAPI_UNPROTECT_FAILED",
            Self::DpapiReturnedEmptyOutput => "DPAPI_EMPTY_OUTPUT",
            Self::DpapiFreeFailed => "DPAPI_MEMORY_RELEASE_FAILED",
            Self::CreateStoreDirectory(_)
            | Self::CreateReplayMarker(_)
            | Self::WriteReplayMarker(_)
            | Self::CreateKeyLock(_)
            | Self::CreateTemporaryKey(_)
            | Self::WriteTemporaryKey(_)
            | Self::CommitStoredKey(_)
            | Self::ReadStoredKey(_) => "SIGNER_STORAGE_FAILED",
            Self::Json(_) => "SIGNER_JSON_FAILED",
            Self::Protocol(_) => "SIGNER_PROTOCOL_REJECTED",
            Self::Hashing(_) => "SIGNER_HASHING_FAILED",
        }
    }
}
