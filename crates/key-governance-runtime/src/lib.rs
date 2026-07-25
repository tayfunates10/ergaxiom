#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const REGISTRY_SCHEMA: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IssuerRole {
    Capability,
    Execution,
    Normalization,
    Attestation,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernedKeyStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyMutationAction {
    Add,
    Rotate,
    Revoke,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMutationReceipt {
    pub schema_version: String,
    pub action: KeyMutationAction,
    pub role: IssuerRole,
    pub issuer_id: String,
    pub key_id: String,
    pub previous_key_id: Option<String>,
    pub revision: u64,
    pub previous_registry_digest: String,
    pub registry_digest: String,
    pub effective_at_epoch_s: u64,
    pub receipt_digest: String,
}

#[derive(Debug, Clone)]
struct GovernedKeyRecord {
    role: IssuerRole,
    issuer_id: String,
    key_id: String,
    verifying_key: VerifyingKey,
    status: GovernedKeyStatus,
    not_before_epoch_s: u64,
    not_after_epoch_s: u64,
    retired_at_epoch_s: Option<u64>,
    revoked_at_epoch_s: Option<u64>,
    revocation_reason_digest: Option<String>,
    successor_key_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GovernedKeySnapshot {
    role: IssuerRole,
    issuer_id: String,
    key_id: String,
    public_key_hex: String,
    status: GovernedKeyStatus,
    not_before_epoch_s: u64,
    not_after_epoch_s: u64,
    retired_at_epoch_s: Option<u64>,
    revoked_at_epoch_s: Option<u64>,
    revocation_reason_digest: Option<String>,
    successor_key_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RegistrySnapshot {
    schema_version: String,
    revision: u64,
    keys: Vec<GovernedKeySnapshot>,
}

#[derive(Debug, Clone, Default)]
pub struct GovernedKeyRegistry {
    revision: u64,
    records: BTreeMap<(IssuerRole, String, String), GovernedKeyRecord>,
}

#[derive(Debug, Error)]
pub enum KeyGovernanceError {
    #[error("key-governance identifier is invalid: {0}")]
    InvalidIdentifier(&'static str),
    #[error("trusted Ed25519 public key is invalid")]
    InvalidPublicKey,
    #[error("key validity window is invalid")]
    InvalidValidityWindow,
    #[error("key mutation targets stale registry revision {actual}; expected {expected}")]
    RegistryRevisionMismatch { actual: u64, expected: u64 },
    #[error("key mutation targets a stale registry digest")]
    RegistryDigestMismatch,
    #[error("key identity already exists: {role:?}/{issuer_id}/{key_id}")]
    DuplicateKeyIdentity {
        role: IssuerRole,
        issuer_id: String,
        key_id: String,
    },
    #[error("the same public key material cannot be assigned to multiple identities or roles")]
    PublicKeyReuse,
    #[error("unknown governed key {role:?}/{issuer_id}/{key_id}")]
    UnknownKey {
        role: IssuerRole,
        issuer_id: String,
        key_id: String,
    },
    #[error("key {issuer_id}/{key_id} is registered for {actual:?}, not {expected:?}")]
    RoleMismatch {
        issuer_id: String,
        key_id: String,
        actual: IssuerRole,
        expected: IssuerRole,
    },
    #[error("governed key is not valid yet")]
    KeyNotYetValid,
    #[error("governed key validity window has expired")]
    KeyExpired,
    #[error("governed key has been revoked")]
    KeyRevoked,
    #[error("revoked key cannot be rotated or revoked again")]
    InvalidKeyState,
    #[error("revocation reason digest must be lowercase SHA-256")]
    InvalidRevocationReasonDigest,
    #[error("failed to serialize key-governance material: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

impl GovernedKeyRegistry {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn registry_digest(&self) -> Result<String, KeyGovernanceError> {
        let value =
            serde_json::to_value(self.snapshot()).map_err(KeyGovernanceError::Serialization)?;
        Ok(canonical_json_sha256(&value)?)
    }

    pub fn insert_ed25519(
        &mut self,
        role: IssuerRole,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
        not_before_epoch_s: u64,
        not_after_epoch_s: u64,
    ) -> Result<KeyMutationReceipt, KeyGovernanceError> {
        self.insert_ed25519_internal(
            None,
            None,
            role,
            issuer_id.into(),
            key_id.into(),
            public_key,
            not_before_epoch_s,
            not_after_epoch_s,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_ed25519_guarded(
        &mut self,
        expected_revision: u64,
        expected_registry_digest: &str,
        role: IssuerRole,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
        not_before_epoch_s: u64,
        not_after_epoch_s: u64,
    ) -> Result<KeyMutationReceipt, KeyGovernanceError> {
        self.insert_ed25519_internal(
            Some(expected_revision),
            Some(expected_registry_digest),
            role,
            issuer_id.into(),
            key_id.into(),
            public_key,
            not_before_epoch_s,
            not_after_epoch_s,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rotate_ed25519_guarded(
        &mut self,
        expected_revision: u64,
        expected_registry_digest: &str,
        role: IssuerRole,
        issuer_id: &str,
        current_key_id: &str,
        new_key_id: &str,
        new_public_key: [u8; 32],
        activation_at_epoch_s: u64,
        current_retirement_at_epoch_s: u64,
        new_not_after_epoch_s: u64,
    ) -> Result<KeyMutationReceipt, KeyGovernanceError> {
        self.require_base(expected_revision, expected_registry_digest)?;
        validate_identifier("issuer_id", issuer_id)?;
        validate_identifier("current_key_id", current_key_id)?;
        validate_identifier("new_key_id", new_key_id)?;
        if current_key_id == new_key_id
            || activation_at_epoch_s > current_retirement_at_epoch_s
            || activation_at_epoch_s >= new_not_after_epoch_s
        {
            return Err(KeyGovernanceError::InvalidValidityWindow);
        }
        let new_verifying_key = VerifyingKey::from_bytes(&new_public_key)
            .map_err(|_| KeyGovernanceError::InvalidPublicKey)?;
        self.require_unused_public_key(&new_verifying_key)?;

        let current_identity = (role, issuer_id.to_owned(), current_key_id.to_owned());
        let current = self
            .records
            .get(&current_identity)
            .ok_or_else(|| self.unknown_or_role_mismatch(role, issuer_id, current_key_id))?;
        if current.status == GovernedKeyStatus::Revoked
            || current_retirement_at_epoch_s <= current.not_before_epoch_s
        {
            return Err(KeyGovernanceError::InvalidKeyState);
        }
        let new_identity = (role, issuer_id.to_owned(), new_key_id.to_owned());
        if self.records.contains_key(&new_identity) {
            return Err(KeyGovernanceError::DuplicateKeyIdentity {
                role,
                issuer_id: issuer_id.to_owned(),
                key_id: new_key_id.to_owned(),
            });
        }

        let previous_registry_digest = self.registry_digest()?;
        if let Some(current_mut) = self.records.get_mut(&current_identity) {
            current_mut.status = GovernedKeyStatus::Retired;
            current_mut.not_after_epoch_s = current_retirement_at_epoch_s;
            current_mut.retired_at_epoch_s = Some(current_retirement_at_epoch_s);
            current_mut.successor_key_id = Some(new_key_id.to_owned());
        } else {
            return Err(KeyGovernanceError::UnknownKey {
                role,
                issuer_id: issuer_id.to_owned(),
                key_id: current_key_id.to_owned(),
            });
        }
        self.records.insert(
            new_identity,
            GovernedKeyRecord {
                role,
                issuer_id: issuer_id.to_owned(),
                key_id: new_key_id.to_owned(),
                verifying_key: new_verifying_key,
                status: GovernedKeyStatus::Active,
                not_before_epoch_s: activation_at_epoch_s,
                not_after_epoch_s: new_not_after_epoch_s,
                retired_at_epoch_s: None,
                revoked_at_epoch_s: None,
                revocation_reason_digest: None,
                successor_key_id: None,
            },
        );
        self.revision = self.revision.saturating_add(1);
        self.build_receipt(
            KeyMutationAction::Rotate,
            role,
            issuer_id,
            new_key_id,
            Some(current_key_id),
            activation_at_epoch_s,
            previous_registry_digest,
        )
    }

    pub fn revoke_ed25519_guarded(
        &mut self,
        expected_revision: u64,
        expected_registry_digest: &str,
        role: IssuerRole,
        issuer_id: &str,
        key_id: &str,
        revoked_at_epoch_s: u64,
        revocation_reason_digest: &str,
    ) -> Result<KeyMutationReceipt, KeyGovernanceError> {
        self.require_base(expected_revision, expected_registry_digest)?;
        validate_identifier("issuer_id", issuer_id)?;
        validate_identifier("key_id", key_id)?;
        if !is_sha256(revocation_reason_digest) {
            return Err(KeyGovernanceError::InvalidRevocationReasonDigest);
        }
        let identity = (role, issuer_id.to_owned(), key_id.to_owned());
        let current = self
            .records
            .get(&identity)
            .ok_or_else(|| self.unknown_or_role_mismatch(role, issuer_id, key_id))?;
        if current.status == GovernedKeyStatus::Revoked {
            return Err(KeyGovernanceError::InvalidKeyState);
        }
        let previous_registry_digest = self.registry_digest()?;
        if let Some(current_mut) = self.records.get_mut(&identity) {
            current_mut.status = GovernedKeyStatus::Revoked;
            current_mut.revoked_at_epoch_s = Some(revoked_at_epoch_s);
            current_mut.revocation_reason_digest = Some(revocation_reason_digest.to_owned());
        } else {
            return Err(KeyGovernanceError::UnknownKey {
                role,
                issuer_id: issuer_id.to_owned(),
                key_id: key_id.to_owned(),
            });
        }
        self.revision = self.revision.saturating_add(1);
        self.build_receipt(
            KeyMutationAction::Revoke,
            role,
            issuer_id,
            key_id,
            None,
            revoked_at_epoch_s,
            previous_registry_digest,
        )
    }

    pub fn resolve_ed25519(
        &self,
        role: IssuerRole,
        issuer_id: &str,
        key_id: &str,
        signed_at_epoch_s: u64,
    ) -> Result<&VerifyingKey, KeyGovernanceError> {
        let identity = (role, issuer_id.to_owned(), key_id.to_owned());
        let record = self
            .records
            .get(&identity)
            .ok_or_else(|| self.unknown_or_role_mismatch(role, issuer_id, key_id))?;
        if record.status == GovernedKeyStatus::Revoked {
            return Err(KeyGovernanceError::KeyRevoked);
        }
        if signed_at_epoch_s < record.not_before_epoch_s {
            return Err(KeyGovernanceError::KeyNotYetValid);
        }
        if signed_at_epoch_s >= record.not_after_epoch_s {
            return Err(KeyGovernanceError::KeyExpired);
        }
        Ok(&record.verifying_key)
    }

    fn insert_ed25519_internal(
        &mut self,
        expected_revision: Option<u64>,
        expected_registry_digest: Option<&str>,
        role: IssuerRole,
        issuer_id: String,
        key_id: String,
        public_key: [u8; 32],
        not_before_epoch_s: u64,
        not_after_epoch_s: u64,
    ) -> Result<KeyMutationReceipt, KeyGovernanceError> {
        if let (Some(revision), Some(digest)) = (expected_revision, expected_registry_digest) {
            self.require_base(revision, digest)?;
        }
        validate_identifier("issuer_id", &issuer_id)?;
        validate_identifier("key_id", &key_id)?;
        if not_before_epoch_s >= not_after_epoch_s {
            return Err(KeyGovernanceError::InvalidValidityWindow);
        }
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| KeyGovernanceError::InvalidPublicKey)?;
        self.require_unused_public_key(&verifying_key)?;
        let identity = (role, issuer_id.clone(), key_id.clone());
        if self.records.contains_key(&identity) {
            return Err(KeyGovernanceError::DuplicateKeyIdentity {
                role,
                issuer_id,
                key_id,
            });
        }
        let previous_registry_digest = self.registry_digest()?;
        self.records.insert(
            identity,
            GovernedKeyRecord {
                role,
                issuer_id: issuer_id.clone(),
                key_id: key_id.clone(),
                verifying_key,
                status: GovernedKeyStatus::Active,
                not_before_epoch_s,
                not_after_epoch_s,
                retired_at_epoch_s: None,
                revoked_at_epoch_s: None,
                revocation_reason_digest: None,
                successor_key_id: None,
            },
        );
        self.revision = self.revision.saturating_add(1);
        self.build_receipt(
            KeyMutationAction::Add,
            role,
            &issuer_id,
            &key_id,
            None,
            not_before_epoch_s,
            previous_registry_digest,
        )
    }

    fn require_base(
        &self,
        expected_revision: u64,
        expected_registry_digest: &str,
    ) -> Result<(), KeyGovernanceError> {
        if self.revision != expected_revision {
            return Err(KeyGovernanceError::RegistryRevisionMismatch {
                actual: self.revision,
                expected: expected_revision,
            });
        }
        if self.registry_digest()? != expected_registry_digest {
            return Err(KeyGovernanceError::RegistryDigestMismatch);
        }
        Ok(())
    }

    fn require_unused_public_key(
        &self,
        candidate: &VerifyingKey,
    ) -> Result<(), KeyGovernanceError> {
        if self
            .records
            .values()
            .any(|record| record.verifying_key.to_bytes() == candidate.to_bytes())
        {
            Err(KeyGovernanceError::PublicKeyReuse)
        } else {
            Ok(())
        }
    }

    fn unknown_or_role_mismatch(
        &self,
        expected_role: IssuerRole,
        issuer_id: &str,
        key_id: &str,
    ) -> KeyGovernanceError {
        if let Some((actual, _, _)) = self
            .records
            .keys()
            .find(|(_, issuer, key)| issuer == issuer_id && key == key_id)
        {
            KeyGovernanceError::RoleMismatch {
                issuer_id: issuer_id.to_owned(),
                key_id: key_id.to_owned(),
                actual: *actual,
                expected: expected_role,
            }
        } else {
            KeyGovernanceError::UnknownKey {
                role: expected_role,
                issuer_id: issuer_id.to_owned(),
                key_id: key_id.to_owned(),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_receipt(
        &self,
        action: KeyMutationAction,
        role: IssuerRole,
        issuer_id: &str,
        key_id: &str,
        previous_key_id: Option<&str>,
        effective_at_epoch_s: u64,
        previous_registry_digest: String,
    ) -> Result<KeyMutationReceipt, KeyGovernanceError> {
        let registry_digest = self.registry_digest()?;
        let mut receipt = KeyMutationReceipt {
            schema_version: REGISTRY_SCHEMA.to_owned(),
            action,
            role,
            issuer_id: issuer_id.to_owned(),
            key_id: key_id.to_owned(),
            previous_key_id: previous_key_id.map(str::to_owned),
            revision: self.revision,
            previous_registry_digest,
            registry_digest,
            effective_at_epoch_s,
            receipt_digest: String::new(),
        };
        let mut value =
            serde_json::to_value(&receipt).map_err(KeyGovernanceError::Serialization)?;
        let object = value.as_object_mut().ok_or_else(|| {
            KeyGovernanceError::Serialization(serde_json::Error::io(std::io::Error::other(
                "key mutation receipt did not serialize to an object",
            )))
        })?;
        object.insert("receipt_digest".to_owned(), Value::String(String::new()));
        receipt.receipt_digest = canonical_json_sha256(&value)?;
        Ok(receipt)
    }

    fn snapshot(&self) -> RegistrySnapshot {
        let keys = self
            .records
            .values()
            .map(|record| GovernedKeySnapshot {
                role: record.role,
                issuer_id: record.issuer_id.clone(),
                key_id: record.key_id.clone(),
                public_key_hex: record
                    .verifying_key
                    .to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                status: record.status,
                not_before_epoch_s: record.not_before_epoch_s,
                not_after_epoch_s: record.not_after_epoch_s,
                retired_at_epoch_s: record.retired_at_epoch_s,
                revoked_at_epoch_s: record.revoked_at_epoch_s,
                revocation_reason_digest: record.revocation_reason_digest.clone(),
                successor_key_id: record.successor_key_id.clone(),
            })
            .collect();
        RegistrySnapshot {
            schema_version: REGISTRY_SCHEMA.to_owned(),
            revision: self.revision,
            keys,
        }
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), KeyGovernanceError> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
    {
        Err(KeyGovernanceError::InvalidIdentifier(field))
    } else {
        Ok(())
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
