#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod windows;

use std::collections::{BTreeMap, BTreeSet};

use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_production_signer_runtime::{
    AuthenticatedCallerIdentity, ProductionSignerError, SignerServiceIdentity, validate_identifier,
    validate_sha256,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CALLER_ALLOWLIST_SCHEMA: &str = "0.1.0";
pub const CALLER_AUTHORIZATION_RECEIPT_SCHEMA: &str = "0.1.0";
pub const NAMED_PIPE_SECURITY_CONTRACT_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_PIPE_NAME: &str = r"\\.\pipe\Ergaxiom.ProductionSigner.v1";
pub const MAX_ALLOWLIST_ENTRIES: usize = 32;
pub const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedSignerCaller {
    pub caller_id: String,
    pub principal_sid: String,
    pub session_id: Option<u32>,
    pub executable_path: String,
    pub executable_sha256: String,
}

impl AllowedSignerCaller {
    pub fn validate(&self) -> Result<(), SignerIdentityError> {
        validate_identifier("caller_id", &self.caller_id)?;
        validate_sid(&self.principal_sid)?;
        validate_path(&self.executable_path)?;
        validate_sha256(&self.executable_sha256)?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String, SignerIdentityError> {
        self.validate()?;
        digest_value(self)
    }

    fn matches(&self, caller: &AuthenticatedCallerIdentity) -> Result<bool, SignerIdentityError> {
        caller.validate()?;
        Ok(self.principal_sid == caller.principal_sid
            && self.session_id.is_none_or(|session_id| session_id == caller.session_id)
            && paths_equal(&self.executable_path, &caller.executable_path)
            && self.executable_sha256 == caller.executable_sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerCallerAllowlist {
    pub schema_version: String,
    pub revision: u64,
    pub entries: Vec<AllowedSignerCaller>,
    pub allowlist_digest: String,
}

impl SignerCallerAllowlist {
    pub fn build(
        revision: u64,
        mut entries: Vec<AllowedSignerCaller>,
    ) -> Result<Self, SignerIdentityError> {
        if revision == 0 {
            return Err(SignerIdentityError::InvalidAllowlistRevision);
        }
        if entries.is_empty() || entries.len() > MAX_ALLOWLIST_ENTRIES {
            return Err(SignerIdentityError::InvalidAllowlistSize);
        }
        for entry in &entries {
            entry.validate()?;
        }
        entries.sort_by(|left, right| left.caller_id.cmp(&right.caller_id));
        reject_duplicate_entries(&entries)?;
        let mut allowlist = Self {
            schema_version: CALLER_ALLOWLIST_SCHEMA.to_owned(),
            revision,
            entries,
            allowlist_digest: String::new(),
        };
        allowlist.allowlist_digest = allowlist.expected_digest()?;
        Ok(allowlist)
    }

    pub fn validate(&self) -> Result<(), SignerIdentityError> {
        if self.schema_version != CALLER_ALLOWLIST_SCHEMA {
            return Err(SignerIdentityError::UnsupportedAllowlistSchema);
        }
        if self.revision == 0 {
            return Err(SignerIdentityError::InvalidAllowlistRevision);
        }
        if self.entries.is_empty() || self.entries.len() > MAX_ALLOWLIST_ENTRIES {
            return Err(SignerIdentityError::InvalidAllowlistSize);
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        let mut sorted = self.entries.clone();
        sorted.sort_by(|left, right| left.caller_id.cmp(&right.caller_id));
        if sorted != self.entries {
            return Err(SignerIdentityError::AllowlistNotCanonical);
        }
        reject_duplicate_entries(&self.entries)?;
        if self.allowlist_digest != self.expected_digest()? {
            return Err(SignerIdentityError::AllowlistDigestMismatch);
        }
        Ok(())
    }

    pub fn find_match(
        &self,
        caller: &AuthenticatedCallerIdentity,
    ) -> Result<&AllowedSignerCaller, SignerIdentityError> {
        self.validate()?;
        caller.validate()?;
        let matching: Vec<&AllowedSignerCaller> = self
            .entries
            .iter()
            .filter(|entry| entry.matches(caller).unwrap_or(false))
            .collect();
        match matching.as_slice() {
            [entry] => Ok(*entry),
            [] => Err(SignerIdentityError::CallerNotAllowlisted),
            _ => Err(SignerIdentityError::AmbiguousCallerIdentity),
        }
    }

    fn expected_digest(&self) -> Result<String, SignerIdentityError> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(SignerIdentityError::InvalidCanonicalObject)?;
        object.insert(
            "allowlist_digest".to_owned(),
            serde_json::Value::String(String::new()),
        );
        Ok(canonical_json_sha256(&value)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedPipeSecurityContract {
    pub schema_version: String,
    pub pipe_name: String,
    pub reject_remote_clients: bool,
    pub message_type: bool,
    pub message_read_mode: bool,
    pub first_instance_only: bool,
    pub allowed_principal_sid: String,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub contract_digest: String,
}

impl NamedPipeSecurityContract {
    pub fn production(
        allowed_principal_sid: impl Into<String>,
    ) -> Result<Self, SignerIdentityError> {
        let mut contract = Self {
            schema_version: NAMED_PIPE_SECURITY_CONTRACT_SCHEMA.to_owned(),
            pipe_name: PRODUCTION_PIPE_NAME.to_owned(),
            reject_remote_clients: true,
            message_type: true,
            message_read_mode: true,
            first_instance_only: true,
            allowed_principal_sid: allowed_principal_sid.into(),
            max_request_bytes: 64 * 1024,
            max_response_bytes: 128 * 1024,
            contract_digest: String::new(),
        };
        contract.contract_digest = contract.expected_digest()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), SignerIdentityError> {
        if self.schema_version != NAMED_PIPE_SECURITY_CONTRACT_SCHEMA {
            return Err(SignerIdentityError::UnsupportedPipeContractSchema);
        }
        if self.pipe_name != PRODUCTION_PIPE_NAME {
            return Err(SignerIdentityError::PipeNameSubstitution);
        }
        if !self.reject_remote_clients
            || !self.message_type
            || !self.message_read_mode
            || !self.first_instance_only
        {
            return Err(SignerIdentityError::PipeSecurityWeakened);
        }
        validate_sid(&self.allowed_principal_sid)?;
        if self.max_request_bytes == 0
            || self.max_response_bytes == 0
            || self.max_request_bytes > 64 * 1024
            || self.max_response_bytes > 128 * 1024
        {
            return Err(SignerIdentityError::InvalidPipeSizeLimit);
        }
        if self.contract_digest != self.expected_digest()? {
            return Err(SignerIdentityError::PipeContractDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, SignerIdentityError> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(SignerIdentityError::InvalidCanonicalObject)?;
        object.insert(
            "contract_digest".to_owned(),
            serde_json::Value::String(String::new()),
        );
        Ok(canonical_json_sha256(&value)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerAuthorizationReceipt {
    pub schema_version: String,
    pub caller_id: String,
    pub request_digest: String,
    pub caller_identity_digest: String,
    pub signer_service_identity_digest: String,
    pub allowlist_revision: u64,
    pub allowlist_digest: String,
    pub authorized_at_epoch_s: u64,
    pub receipt_digest: String,
}

impl CallerAuthorizationReceipt {
    pub fn validate(
        &self,
        caller: &AuthenticatedCallerIdentity,
        service: &SignerServiceIdentity,
        allowlist: &SignerCallerAllowlist,
    ) -> Result<(), SignerIdentityError> {
        if self.schema_version != CALLER_AUTHORIZATION_RECEIPT_SCHEMA {
            return Err(SignerIdentityError::UnsupportedReceiptSchema);
        }
        validate_identifier("caller_id", &self.caller_id)?;
        validate_sha256(&self.request_digest)?;
        validate_sha256(&self.caller_identity_digest)?;
        validate_sha256(&self.signer_service_identity_digest)?;
        validate_sha256(&self.allowlist_digest)?;
        if self.authorized_at_epoch_s == 0 {
            return Err(SignerIdentityError::InvalidAuthorizationTime);
        }
        allowlist.validate()?;
        if self.caller_identity_digest != caller.digest()?
            || self.signer_service_identity_digest != service.digest()?
            || self.allowlist_revision != allowlist.revision
            || self.allowlist_digest != allowlist.allowlist_digest
        {
            return Err(SignerIdentityError::AuthorizationBindingMismatch);
        }
        if self.receipt_digest != self.expected_digest()? {
            return Err(SignerIdentityError::AuthorizationReceiptDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, SignerIdentityError> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(SignerIdentityError::InvalidCanonicalObject)?;
        object.insert(
            "receipt_digest".to_owned(),
            serde_json::Value::String(String::new()),
        );
        Ok(canonical_json_sha256(&value)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeenProcessIdentity {
    process_creation_time_100ns: u64,
    caller_identity_digest: String,
}

#[derive(Debug, Default)]
pub struct SignerIdentityAuthorizer {
    seen_processes: BTreeMap<u32, SeenProcessIdentity>,
    used_request_digests: BTreeSet<String>,
}

impl SignerIdentityAuthorizer {
    pub fn authorize(
        &mut self,
        caller: &AuthenticatedCallerIdentity,
        service: &SignerServiceIdentity,
        allowlist: &SignerCallerAllowlist,
        request_digest: &str,
        trusted_now_epoch_s: u64,
    ) -> Result<CallerAuthorizationReceipt, SignerIdentityError> {
        caller.validate()?;
        service.validate()?;
        allowlist.validate()?;
        validate_sha256(request_digest)?;
        if trusted_now_epoch_s == 0 {
            return Err(SignerIdentityError::InvalidAuthorizationTime);
        }
        if self.used_request_digests.contains(request_digest) {
            return Err(SignerIdentityError::RequestReplayDetected);
        }
        let allowed = allowlist.find_match(caller)?;
        let caller_identity_digest = caller.digest()?;
        if let Some(seen) = self.seen_processes.get(&caller.process_id) {
            if seen.process_creation_time_100ns != caller.process_creation_time_100ns {
                return Err(SignerIdentityError::ProcessIdReused);
            }
            if seen.caller_identity_digest != caller_identity_digest {
                return Err(SignerIdentityError::ProcessIdentityChanged);
            }
        }

        let mut receipt = CallerAuthorizationReceipt {
            schema_version: CALLER_AUTHORIZATION_RECEIPT_SCHEMA.to_owned(),
            caller_id: allowed.caller_id.clone(),
            request_digest: request_digest.to_owned(),
            caller_identity_digest: caller_identity_digest.clone(),
            signer_service_identity_digest: service.digest()?,
            allowlist_revision: allowlist.revision,
            allowlist_digest: allowlist.allowlist_digest.clone(),
            authorized_at_epoch_s: trusted_now_epoch_s,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest()?;

        self.seen_processes.insert(
            caller.process_id,
            SeenProcessIdentity {
                process_creation_time_100ns: caller.process_creation_time_100ns,
                caller_identity_digest,
            },
        );
        self.used_request_digests.insert(request_digest.to_owned());
        Ok(receipt)
    }
}

#[cfg(windows)]
pub use windows::derive_authenticated_caller_from_named_pipe;

#[cfg(not(windows))]
pub fn derive_authenticated_caller_from_named_pipe(
    _pipe_handle: isize,
) -> Result<AuthenticatedCallerIdentity, SignerIdentityError> {
    Err(SignerIdentityError::UnsupportedPlatform)
}

fn reject_duplicate_entries(entries: &[AllowedSignerCaller]) -> Result<(), SignerIdentityError> {
    let mut caller_ids = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for entry in entries {
        if !caller_ids.insert(entry.caller_id.clone()) {
            return Err(SignerIdentityError::DuplicateCallerId);
        }
        let identity = (
            entry.principal_sid.clone(),
            entry.session_id,
            normalize_path(&entry.executable_path),
            entry.executable_sha256.clone(),
        );
        if !identities.insert(identity) {
            return Err(SignerIdentityError::DuplicateCallerIdentity);
        }
    }
    Ok(())
}

fn validate_sid(value: &str) -> Result<(), SignerIdentityError> {
    if value.len() < 5
        || value.len() > 184
        || !value.starts_with("S-")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'S' || byte == b'-')
    {
        return Err(SignerIdentityError::InvalidPrincipalSid);
    }
    Ok(())
}

fn validate_path(value: &str) -> Result<(), SignerIdentityError> {
    if value.len() < 3 || value.len() > 32_768 || value.contains('\0') {
        return Err(SignerIdentityError::InvalidExecutablePath);
    }
    let normalized = normalize_path(value);
    if !normalized.contains(":\\") || normalized.contains("..\\") {
        return Err(SignerIdentityError::InvalidExecutablePath);
    }
    Ok(())
}

fn paths_equal(left: &str, right: &str) -> bool {
    normalize_path(left) == normalize_path(right)
}

fn normalize_path(value: &str) -> String {
    value.replace('/', "\\").to_ascii_lowercase()
}

fn digest_value<T: Serialize>(value: &T) -> Result<String, SignerIdentityError> {
    let value = serde_json::to_value(value)?;
    Ok(canonical_json_sha256(&value)?)
}

#[derive(Debug, Error)]
pub enum SignerIdentityError {
    #[error("signer-service identity platform is unsupported")]
    UnsupportedPlatform,
    #[error("production signer identity material is invalid: {0}")]
    Production(#[from] ProductionSignerError),
    #[error("caller allowlist schema is unsupported")]
    UnsupportedAllowlistSchema,
    #[error("caller allowlist revision is invalid")]
    InvalidAllowlistRevision,
    #[error("caller allowlist size is invalid")]
    InvalidAllowlistSize,
    #[error("caller allowlist must be sorted canonically")]
    AllowlistNotCanonical,
    #[error("caller allowlist digest does not match")]
    AllowlistDigestMismatch,
    #[error("caller ID is duplicated")]
    DuplicateCallerId,
    #[error("caller identity tuple is duplicated")]
    DuplicateCallerIdentity,
    #[error("caller identity is ambiguous")]
    AmbiguousCallerIdentity,
    #[error("caller principal SID is invalid")]
    InvalidPrincipalSid,
    #[error("caller executable path is invalid")]
    InvalidExecutablePath,
    #[error("caller is not present in the signer allowlist")]
    CallerNotAllowlisted,
    #[error("named-pipe security contract schema is unsupported")]
    UnsupportedPipeContractSchema,
    #[error("named-pipe name was substituted")]
    PipeNameSubstitution,
    #[error("named-pipe security controls were weakened")]
    PipeSecurityWeakened,
    #[error("named-pipe size limits are invalid")]
    InvalidPipeSizeLimit,
    #[error("named-pipe security contract digest does not match")]
    PipeContractDigestMismatch,
    #[error("caller authorization receipt schema is unsupported")]
    UnsupportedReceiptSchema,
    #[error("caller authorization time is invalid")]
    InvalidAuthorizationTime,
    #[error("caller authorization fields do not match the trusted inputs")]
    AuthorizationBindingMismatch,
    #[error("caller authorization receipt digest does not match")]
    AuthorizationReceiptDigestMismatch,
    #[error("signer request digest was already authorized")]
    RequestReplayDetected,
    #[error("client process ID was reused by a different process instance")]
    ProcessIdReused,
    #[error("client process identity changed after first authorization")]
    ProcessIdentityChanged,
    #[error("canonical JSON object is invalid")]
    InvalidCanonicalObject,
    #[error("named-pipe client process ID could not be read: {0}")]
    ClientProcessIdReadFailed(#[source] std::io::Error),
    #[error("named-pipe client session ID could not be read: {0}")]
    ClientSessionIdReadFailed(#[source] std::io::Error),
    #[error("named-pipe client process could not be opened: {0}")]
    ClientProcessOpenFailed(#[source] std::io::Error),
    #[error("named-pipe client process times could not be read: {0}")]
    ClientProcessTimesReadFailed(#[source] std::io::Error),
    #[error("named-pipe client image path could not be read: {0}")]
    ClientImagePathReadFailed(#[source] std::io::Error),
    #[error("named-pipe client image is too large")]
    ClientImageTooLarge,
    #[error("named-pipe client image changed while hashing")]
    ClientImageChangedDuringHash,
    #[error("named-pipe client impersonation failed: {0}")]
    ClientImpersonationFailed(#[source] std::io::Error),
    #[error("named-pipe client thread token could not be opened: {0}")]
    ClientTokenOpenFailed(#[source] std::io::Error),
    #[error("named-pipe client token user could not be read: {0}")]
    ClientTokenUserReadFailed(#[source] std::io::Error),
    #[error("named-pipe client SID could not be rendered: {0}")]
    ClientSidRenderFailed(#[source] std::io::Error),
    #[error("Windows handle could not be closed")]
    HandleCloseFailed,
    #[error("client impersonation could not be reverted")]
    RevertImpersonationFailed,
    #[error("signer-service identity JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}
