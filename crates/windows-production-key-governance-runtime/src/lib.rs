#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_production_signer_runtime::{
    HardwareAssurance, HardwareKeyDescriptor, ProductionKeyIdentity, ProductionKeyPolicy,
    ProductionSignerError, validate_sha256,
};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PRODUCTION_KEY_REGISTRY_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_KEY_RECORD_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_KEY_MUTATION_RECEIPT_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_KEY_TRUST_BINDING_SCHEMA: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductionKeyStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductionKeyMutationAction {
    Add,
    Rotate,
    Revoke,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionKeyRecord {
    pub schema_version: String,
    pub identity: ProductionKeyIdentity,
    pub generation: u64,
    pub public_key_base64url: String,
    pub public_key_digest: String,
    pub provider: String,
    pub algorithm: String,
    pub public_key_encoding: String,
    pub signature_encoding: String,
    pub export_policy: String,
    pub provider_implementation_flags: u32,
    pub assurance: HardwareAssurance,
    pub policy_digest: String,
    pub status: ProductionKeyStatus,
    pub not_before_epoch_s: u64,
    pub not_after_epoch_s: u64,
    pub retired_at_epoch_s: Option<u64>,
    pub revoked_at_epoch_s: Option<u64>,
    pub revocation_reason_digest: Option<String>,
    pub successor_generation: Option<u64>,
    pub record_digest: String,
}

impl ProductionKeyRecord {
    pub fn validate_seal(&self) -> Result<(), ProductionKeyGovernanceError> {
        if self.schema_version != PRODUCTION_KEY_RECORD_SCHEMA {
            return Err(ProductionKeyGovernanceError::UnsupportedRecordSchema);
        }
        self.identity.validate()?;
        if self.generation == 0 || self.not_before_epoch_s >= self.not_after_epoch_s {
            return Err(ProductionKeyGovernanceError::InvalidValidityWindow);
        }
        validate_sha256(&self.public_key_digest)?;
        validate_sha256(&self.policy_digest)?;
        if self.assurance != HardwareAssurance::ProvenHardwareBacked {
            return Err(ProductionKeyGovernanceError::HardwareAssuranceUnproven);
        }
        if let Some(reason) = &self.revocation_reason_digest {
            validate_sha256(reason)
                .map_err(|_| ProductionKeyGovernanceError::InvalidRevocationReasonDigest)?;
        }
        match self.status {
            ProductionKeyStatus::Active => {
                if self.retired_at_epoch_s.is_some()
                    || self.revoked_at_epoch_s.is_some()
                    || self.revocation_reason_digest.is_some()
                    || self.successor_generation.is_some()
                {
                    return Err(ProductionKeyGovernanceError::InvalidKeyState);
                }
            }
            ProductionKeyStatus::Retired => {
                if self.retired_at_epoch_s != Some(self.not_after_epoch_s)
                    || self.successor_generation.is_none()
                    || self.revoked_at_epoch_s.is_some()
                    || self.revocation_reason_digest.is_some()
                {
                    return Err(ProductionKeyGovernanceError::InvalidKeyState);
                }
            }
            ProductionKeyStatus::Revoked => {
                if self.revoked_at_epoch_s.is_none() || self.revocation_reason_digest.is_none() {
                    return Err(ProductionKeyGovernanceError::InvalidKeyState);
                }
            }
        }
        validate_public_key(self)?;
        if self.record_digest != self.expected_digest()? {
            return Err(ProductionKeyGovernanceError::RecordDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionKeyGovernanceError> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(ProductionKeyGovernanceError::InvalidCanonicalObject)?;
        object.insert("record_digest".to_owned(), Value::String(String::new()));
        Ok(canonical_json_sha256(&value)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionKeyMutationReceipt {
    pub schema_version: String,
    pub action: ProductionKeyMutationAction,
    pub identity: ProductionKeyIdentity,
    pub generation: u64,
    pub previous_generation: Option<u64>,
    pub revision: u64,
    pub previous_registry_digest: String,
    pub registry_digest: String,
    pub effective_at_epoch_s: u64,
    pub receipt_digest: String,
}

impl ProductionKeyMutationReceipt {
    pub fn validate_seal(&self) -> Result<(), ProductionKeyGovernanceError> {
        if self.schema_version != PRODUCTION_KEY_MUTATION_RECEIPT_SCHEMA {
            return Err(ProductionKeyGovernanceError::UnsupportedMutationReceiptSchema);
        }
        self.identity.validate()?;
        if self.generation == 0 || self.revision == 0 || self.effective_at_epoch_s == 0 {
            return Err(ProductionKeyGovernanceError::InvalidMutationReceipt);
        }
        validate_sha256(&self.previous_registry_digest)?;
        validate_sha256(&self.registry_digest)?;
        if self.receipt_digest != self.expected_digest()? {
            return Err(ProductionKeyGovernanceError::MutationReceiptDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionKeyGovernanceError> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(ProductionKeyGovernanceError::InvalidCanonicalObject)?;
        object.insert("receipt_digest".to_owned(), Value::String(String::new()));
        Ok(canonical_json_sha256(&value)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionKeyTrustBinding {
    pub schema_version: String,
    pub identity: ProductionKeyIdentity,
    pub generation: u64,
    pub public_key_digest: String,
    pub key_record_digest: String,
    pub registry_revision: u64,
    pub registry_digest: String,
}

impl ProductionKeyTrustBinding {
    pub fn validate_shape(&self) -> Result<(), ProductionKeyGovernanceError> {
        if self.schema_version != PRODUCTION_KEY_TRUST_BINDING_SCHEMA {
            return Err(ProductionKeyGovernanceError::UnsupportedTrustBindingSchema);
        }
        self.identity.validate()?;
        if self.generation == 0 || self.registry_revision == 0 {
            return Err(ProductionKeyGovernanceError::InvalidTrustBinding);
        }
        validate_sha256(&self.public_key_digest)?;
        validate_sha256(&self.key_record_digest)?;
        validate_sha256(&self.registry_digest)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionKeyRegistrySnapshot {
    pub schema_version: String,
    pub revision: u64,
    pub records: Vec<ProductionKeyRecord>,
}

impl ProductionKeyRegistrySnapshot {
    pub fn validate_seal(&self) -> Result<(), ProductionKeyGovernanceError> {
        if self.schema_version != PRODUCTION_KEY_REGISTRY_SCHEMA {
            return Err(ProductionKeyGovernanceError::UnsupportedRegistrySchema);
        }
        if self.revision == 0 && !self.records.is_empty() {
            return Err(ProductionKeyGovernanceError::InvalidRegistrySnapshot);
        }
        let mut identities = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        let mut previous = None;
        for record in &self.records {
            record.validate_seal()?;
            let key = (
                record.identity.role,
                record.identity.issuer_id.clone(),
                record.identity.key_id.clone(),
                record.generation,
            );
            if previous.as_ref().is_some_and(|candidate| candidate >= &key) {
                return Err(ProductionKeyGovernanceError::RegistrySnapshotNotCanonical);
            }
            previous = Some(key.clone());
            if !identities.insert(key) {
                return Err(ProductionKeyGovernanceError::DuplicateRegistryRecord);
            }
            if !public_keys.insert(record.public_key_digest.clone()) {
                return Err(ProductionKeyGovernanceError::PublicKeyReuse);
            }
        }
        Ok(())
    }

    pub fn validate_active_generations(
        &self,
        at_epoch_s: u64,
    ) -> Result<(), ProductionKeyGovernanceError> {
        self.validate_seal()?;
        let mut active = BTreeSet::new();
        for record in &self.records {
            if record.status == ProductionKeyStatus::Active
                && at_epoch_s >= record.not_before_epoch_s
                && at_epoch_s < record.not_after_epoch_s
            {
                let identity = (
                    record.identity.role,
                    record.identity.issuer_id.clone(),
                    record.identity.key_id.clone(),
                );
                if !active.insert(identity) {
                    return Err(ProductionKeyGovernanceError::ActiveGenerationAmbiguity);
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ProductionKeyGovernanceError> {
        self.validate_seal()?;
        Ok(canonical_json_sha256(&serde_json::to_value(self)?)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RecordKey {
    role: IssuerRole,
    issuer_id: String,
    key_id: String,
    generation: u64,
}

impl RecordKey {
    fn from_identity(identity: &ProductionKeyIdentity, generation: u64) -> Self {
        Self {
            role: identity.role,
            issuer_id: identity.issuer_id.clone(),
            key_id: identity.key_id.clone(),
            generation,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProductionKeyRegistry {
    revision: u64,
    records: BTreeMap<RecordKey, ProductionKeyRecord>,
}

impl ProductionKeyRegistry {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn registry_digest(&self) -> Result<String, ProductionKeyGovernanceError> {
        self.snapshot().digest()
    }

    pub fn from_snapshot(
        snapshot: ProductionKeyRegistrySnapshot,
    ) -> Result<Self, ProductionKeyGovernanceError> {
        snapshot.validate_seal()?;
        let mut records = BTreeMap::new();
        for record in snapshot.records.iter().cloned() {
            let key = RecordKey::from_identity(&record.identity, record.generation);
            if records.insert(key, record).is_some() {
                return Err(ProductionKeyGovernanceError::DuplicateRegistryRecord);
            }
        }
        let registry = Self {
            revision: snapshot.revision,
            records,
        };
        if registry.snapshot() != snapshot {
            return Err(ProductionKeyGovernanceError::RegistrySnapshotNotCanonical);
        }
        Ok(registry)
    }

    pub fn active_record(
        &self,
        identity: &ProductionKeyIdentity,
        at_epoch_s: u64,
    ) -> Result<&ProductionKeyRecord, ProductionKeyGovernanceError> {
        identity.validate()?;
        let mut active = None;
        for record in self.records.values().filter(|record| {
            record.identity == *identity
                && record.status == ProductionKeyStatus::Active
                && at_epoch_s >= record.not_before_epoch_s
                && at_epoch_s < record.not_after_epoch_s
        }) {
            record.validate_seal()?;
            if active.is_some() {
                return Err(ProductionKeyGovernanceError::ActiveGenerationAmbiguity);
            }
            active = Some(record);
        }
        active.ok_or(ProductionKeyGovernanceError::NoActiveGeneration)
    }

    pub fn insert_initial_guarded(
        &mut self,
        expected_revision: u64,
        expected_registry_digest: &str,
        descriptor: HardwareKeyDescriptor,
        not_before_epoch_s: u64,
        not_after_epoch_s: u64,
        effective_at_epoch_s: u64,
    ) -> Result<ProductionKeyMutationReceipt, ProductionKeyGovernanceError> {
        self.require_base(expected_revision, expected_registry_digest)?;
        if not_before_epoch_s >= not_after_epoch_s || effective_at_epoch_s == 0 {
            return Err(ProductionKeyGovernanceError::InvalidValidityWindow);
        }
        let identity = descriptor.identity.clone();
        if self
            .records
            .keys()
            .any(|key| same_logical_identity(key, &identity))
        {
            return Err(ProductionKeyGovernanceError::LogicalIdentityAlreadyExists);
        }
        self.require_unused_public_key(&descriptor.public_key_digest)?;
        let record = build_record(
            descriptor,
            1,
            ProductionKeyStatus::Active,
            not_before_epoch_s,
            not_after_epoch_s,
            None,
            None,
            None,
            None,
        )?;
        let previous_registry_digest = self.registry_digest()?;
        self.records
            .insert(RecordKey::from_identity(&identity, 1), record);
        self.revision = self.revision.saturating_add(1);
        self.build_receipt(
            ProductionKeyMutationAction::Add,
            identity,
            1,
            None,
            effective_at_epoch_s,
            previous_registry_digest,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rotate_guarded(
        &mut self,
        expected_revision: u64,
        expected_registry_digest: &str,
        identity: &ProductionKeyIdentity,
        current_generation: u64,
        new_descriptor: HardwareKeyDescriptor,
        activation_at_epoch_s: u64,
        current_retirement_at_epoch_s: u64,
        new_not_after_epoch_s: u64,
    ) -> Result<ProductionKeyMutationReceipt, ProductionKeyGovernanceError> {
        self.require_base(expected_revision, expected_registry_digest)?;
        identity.validate()?;
        if new_descriptor.identity != *identity {
            return Err(ProductionKeyGovernanceError::IdentitySubstitution);
        }
        let current_key = RecordKey::from_identity(identity, current_generation);
        let current = self
            .records
            .get(&current_key)
            .cloned()
            .ok_or(ProductionKeyGovernanceError::UnknownKeyGeneration)?;
        current.validate_seal()?;
        if current.status != ProductionKeyStatus::Active
            || current_generation == u64::MAX
            || activation_at_epoch_s < current.not_before_epoch_s
            || activation_at_epoch_s > current_retirement_at_epoch_s
            || current_retirement_at_epoch_s > current.not_after_epoch_s
            || activation_at_epoch_s >= new_not_after_epoch_s
        {
            return Err(ProductionKeyGovernanceError::InvalidKeyState);
        }
        let new_generation = current_generation + 1;
        let new_key = RecordKey::from_identity(identity, new_generation);
        if self.records.contains_key(&new_key) {
            return Err(ProductionKeyGovernanceError::DuplicateKeyGeneration);
        }
        self.require_unused_public_key(&new_descriptor.public_key_digest)?;
        let new_record = build_record(
            new_descriptor,
            new_generation,
            ProductionKeyStatus::Active,
            activation_at_epoch_s,
            new_not_after_epoch_s,
            None,
            None,
            None,
            None,
        )?;
        let previous_registry_digest = self.registry_digest()?;
        let Some(current_mut) = self.records.get_mut(&current_key) else {
            return Err(ProductionKeyGovernanceError::UnknownKeyGeneration);
        };
        current_mut.status = ProductionKeyStatus::Retired;
        current_mut.not_after_epoch_s = current_retirement_at_epoch_s;
        current_mut.retired_at_epoch_s = Some(current_retirement_at_epoch_s);
        current_mut.successor_generation = Some(new_generation);
        current_mut.record_digest = current_mut.expected_digest()?;
        current_mut.validate_seal()?;
        self.records.insert(new_key, new_record);
        self.revision = self.revision.saturating_add(1);
        self.build_receipt(
            ProductionKeyMutationAction::Rotate,
            identity.clone(),
            new_generation,
            Some(current_generation),
            activation_at_epoch_s,
            previous_registry_digest,
        )
    }

    pub fn revoke_guarded(
        &mut self,
        expected_revision: u64,
        expected_registry_digest: &str,
        identity: &ProductionKeyIdentity,
        generation: u64,
        revoked_at_epoch_s: u64,
        revocation_reason_digest: &str,
    ) -> Result<ProductionKeyMutationReceipt, ProductionKeyGovernanceError> {
        self.require_base(expected_revision, expected_registry_digest)?;
        identity.validate()?;
        if revoked_at_epoch_s == 0 {
            return Err(ProductionKeyGovernanceError::InvalidKeyState);
        }
        validate_sha256(revocation_reason_digest)
            .map_err(|_| ProductionKeyGovernanceError::InvalidRevocationReasonDigest)?;
        let key = RecordKey::from_identity(identity, generation);
        let current = self
            .records
            .get(&key)
            .cloned()
            .ok_or(ProductionKeyGovernanceError::UnknownKeyGeneration)?;
        current.validate_seal()?;
        if current.status == ProductionKeyStatus::Revoked {
            return Err(ProductionKeyGovernanceError::InvalidKeyState);
        }
        let previous_registry_digest = self.registry_digest()?;
        let Some(current_mut) = self.records.get_mut(&key) else {
            return Err(ProductionKeyGovernanceError::UnknownKeyGeneration);
        };
        current_mut.status = ProductionKeyStatus::Revoked;
        current_mut.revoked_at_epoch_s = Some(revoked_at_epoch_s);
        current_mut.revocation_reason_digest = Some(revocation_reason_digest.to_owned());
        current_mut.record_digest = current_mut.expected_digest()?;
        current_mut.validate_seal()?;
        self.revision = self.revision.saturating_add(1);
        self.build_receipt(
            ProductionKeyMutationAction::Revoke,
            identity.clone(),
            generation,
            None,
            revoked_at_epoch_s,
            previous_registry_digest,
        )
    }

    pub fn resolve(
        &self,
        identity: &ProductionKeyIdentity,
        generation: u64,
        signed_at_epoch_s: u64,
    ) -> Result<&ProductionKeyRecord, ProductionKeyGovernanceError> {
        identity.validate()?;
        let record = self
            .records
            .get(&RecordKey::from_identity(identity, generation))
            .ok_or_else(|| self.unknown_or_identity_mismatch(identity, generation))?;
        record.validate_seal()?;
        if record.status == ProductionKeyStatus::Revoked {
            return Err(ProductionKeyGovernanceError::KeyRevoked);
        }
        if signed_at_epoch_s < record.not_before_epoch_s {
            return Err(ProductionKeyGovernanceError::KeyNotYetValid);
        }
        if signed_at_epoch_s >= record.not_after_epoch_s {
            return Err(ProductionKeyGovernanceError::KeyExpired);
        }
        Ok(record)
    }

    pub fn trust_binding(
        &self,
        identity: &ProductionKeyIdentity,
        generation: u64,
        signed_at_epoch_s: u64,
    ) -> Result<ProductionKeyTrustBinding, ProductionKeyGovernanceError> {
        let record = self.resolve(identity, generation, signed_at_epoch_s)?;
        Ok(ProductionKeyTrustBinding {
            schema_version: PRODUCTION_KEY_TRUST_BINDING_SCHEMA.to_owned(),
            identity: identity.clone(),
            generation,
            public_key_digest: record.public_key_digest.clone(),
            key_record_digest: record.record_digest.clone(),
            registry_revision: self.revision,
            registry_digest: self.registry_digest()?,
        })
    }

    pub fn verify_binding(
        &self,
        binding: &ProductionKeyTrustBinding,
        signed_at_epoch_s: u64,
    ) -> Result<&ProductionKeyRecord, ProductionKeyGovernanceError> {
        binding.validate_shape()?;
        if binding.registry_revision != self.revision {
            return Err(ProductionKeyGovernanceError::RegistryRevisionMismatch {
                expected: self.revision,
                actual: binding.registry_revision,
            });
        }
        if binding.registry_digest != self.registry_digest()? {
            return Err(ProductionKeyGovernanceError::RegistryDigestMismatch);
        }
        let record = self.resolve(&binding.identity, binding.generation, signed_at_epoch_s)?;
        if record.public_key_digest != binding.public_key_digest
            || record.record_digest != binding.key_record_digest
        {
            return Err(ProductionKeyGovernanceError::TrustBindingMismatch);
        }
        Ok(record)
    }

    pub fn snapshot(&self) -> ProductionKeyRegistrySnapshot {
        ProductionKeyRegistrySnapshot {
            schema_version: PRODUCTION_KEY_REGISTRY_SCHEMA.to_owned(),
            revision: self.revision,
            records: self.records.values().cloned().collect(),
        }
    }

    fn require_base(
        &self,
        expected_revision: u64,
        expected_registry_digest: &str,
    ) -> Result<(), ProductionKeyGovernanceError> {
        if expected_revision != self.revision {
            return Err(ProductionKeyGovernanceError::RegistryRevisionMismatch {
                expected: self.revision,
                actual: expected_revision,
            });
        }
        if expected_registry_digest != self.registry_digest()? {
            return Err(ProductionKeyGovernanceError::RegistryDigestMismatch);
        }
        Ok(())
    }

    fn require_unused_public_key(
        &self,
        public_key_digest: &str,
    ) -> Result<(), ProductionKeyGovernanceError> {
        validate_sha256(public_key_digest)?;
        if self
            .records
            .values()
            .any(|record| record.public_key_digest == public_key_digest)
        {
            return Err(ProductionKeyGovernanceError::PublicKeyReuse);
        }
        Ok(())
    }

    fn unknown_or_identity_mismatch(
        &self,
        identity: &ProductionKeyIdentity,
        generation: u64,
    ) -> ProductionKeyGovernanceError {
        if self.records.keys().any(|key| {
            key.issuer_id == identity.issuer_id
                && key.key_id == identity.key_id
                && key.generation == generation
                && key.role != identity.role
        }) {
            ProductionKeyGovernanceError::RoleMismatch
        } else {
            ProductionKeyGovernanceError::UnknownKeyGeneration
        }
    }

    fn build_receipt(
        &self,
        action: ProductionKeyMutationAction,
        identity: ProductionKeyIdentity,
        generation: u64,
        previous_generation: Option<u64>,
        effective_at_epoch_s: u64,
        previous_registry_digest: String,
    ) -> Result<ProductionKeyMutationReceipt, ProductionKeyGovernanceError> {
        let mut receipt = ProductionKeyMutationReceipt {
            schema_version: PRODUCTION_KEY_MUTATION_RECEIPT_SCHEMA.to_owned(),
            action,
            identity,
            generation,
            previous_generation,
            revision: self.revision,
            previous_registry_digest,
            registry_digest: self.registry_digest()?,
            effective_at_epoch_s,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate_seal()?;
        Ok(receipt)
    }
}

#[allow(clippy::too_many_arguments)]
fn build_record(
    descriptor: HardwareKeyDescriptor,
    generation: u64,
    status: ProductionKeyStatus,
    not_before_epoch_s: u64,
    not_after_epoch_s: u64,
    retired_at_epoch_s: Option<u64>,
    revoked_at_epoch_s: Option<u64>,
    revocation_reason_digest: Option<String>,
    successor_generation: Option<u64>,
) -> Result<ProductionKeyRecord, ProductionKeyGovernanceError> {
    let policy = ProductionKeyPolicy::for_identity(descriptor.identity.clone());
    descriptor.validate_for(&policy)?;
    if descriptor.assurance != HardwareAssurance::ProvenHardwareBacked {
        return Err(ProductionKeyGovernanceError::HardwareAssuranceUnproven);
    }
    if generation == 0 || not_before_epoch_s >= not_after_epoch_s {
        return Err(ProductionKeyGovernanceError::InvalidValidityWindow);
    }
    let mut record = ProductionKeyRecord {
        schema_version: PRODUCTION_KEY_RECORD_SCHEMA.to_owned(),
        identity: descriptor.identity,
        generation,
        public_key_base64url: descriptor.public_key_base64url,
        public_key_digest: descriptor.public_key_digest,
        provider: descriptor.provider,
        algorithm: descriptor.algorithm,
        public_key_encoding: descriptor.public_key_encoding,
        signature_encoding: descriptor.signature_encoding,
        export_policy: descriptor.export_policy,
        provider_implementation_flags: descriptor.provider_implementation_flags,
        assurance: descriptor.assurance,
        policy_digest: descriptor.policy_digest,
        status,
        not_before_epoch_s,
        not_after_epoch_s,
        retired_at_epoch_s,
        revoked_at_epoch_s,
        revocation_reason_digest,
        successor_generation,
        record_digest: String::new(),
    };
    record.record_digest = record.expected_digest()?;
    record.validate_seal()?;
    Ok(record)
}

fn validate_public_key(record: &ProductionKeyRecord) -> Result<(), ProductionKeyGovernanceError> {
    let public_key = URL_SAFE_NO_PAD
        .decode(&record.public_key_base64url)
        .map_err(|_| ProductionKeyGovernanceError::InvalidPublicKey)?;
    if public_key.len() != 65 || public_key.first() != Some(&0x04) {
        return Err(ProductionKeyGovernanceError::InvalidPublicKey);
    }
    VerifyingKey::from_sec1_bytes(&public_key)
        .map_err(|_| ProductionKeyGovernanceError::InvalidPublicKey)?;
    if encode_hex(&Sha256::digest(&public_key)) != record.public_key_digest {
        return Err(ProductionKeyGovernanceError::PublicKeyDigestMismatch);
    }
    let descriptor = HardwareKeyDescriptor {
        identity: record.identity.clone(),
        provider: record.provider.clone(),
        algorithm: record.algorithm.clone(),
        public_key_encoding: record.public_key_encoding.clone(),
        public_key_base64url: record.public_key_base64url.clone(),
        public_key_digest: record.public_key_digest.clone(),
        signature_encoding: record.signature_encoding.clone(),
        export_policy: record.export_policy.clone(),
        provider_implementation_flags: record.provider_implementation_flags,
        assurance: record.assurance,
        policy_digest: record.policy_digest.clone(),
    };
    descriptor.validate_for(&ProductionKeyPolicy::for_identity(record.identity.clone()))?;
    Ok(())
}

fn same_logical_identity(key: &RecordKey, identity: &ProductionKeyIdentity) -> bool {
    key.role == identity.role
        && key.issuer_id == identity.issuer_id
        && key.key_id == identity.key_id
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
pub enum ProductionKeyGovernanceError {
    #[error("production key registry schema is unsupported")]
    UnsupportedRegistrySchema,
    #[error("production key registry snapshot is invalid")]
    InvalidRegistrySnapshot,
    #[error("production key registry snapshot is not canonical")]
    RegistrySnapshotNotCanonical,
    #[error("production key registry contains a duplicate record")]
    DuplicateRegistryRecord,
    #[error("production key registry contains multiple active generations")]
    ActiveGenerationAmbiguity,
    #[error("production key registry has no active generation for the identity")]
    NoActiveGeneration,
    #[error("production key record schema is unsupported")]
    UnsupportedRecordSchema,
    #[error("production key mutation receipt schema is unsupported")]
    UnsupportedMutationReceiptSchema,
    #[error("production key trust binding schema is unsupported")]
    UnsupportedTrustBindingSchema,
    #[error("production key validity window is invalid")]
    InvalidValidityWindow,
    #[error("production key state transition is invalid")]
    InvalidKeyState,
    #[error("production key public key is invalid")]
    InvalidPublicKey,
    #[error("production key public-key digest does not match the public key")]
    PublicKeyDigestMismatch,
    #[error("production key hardware assurance is unproven")]
    HardwareAssuranceUnproven,
    #[error("production key record digest does not match")]
    RecordDigestMismatch,
    #[error("production key mutation receipt is invalid")]
    InvalidMutationReceipt,
    #[error("production key mutation receipt digest does not match")]
    MutationReceiptDigestMismatch,
    #[error("production key trust binding is invalid")]
    InvalidTrustBinding,
    #[error("production key registry revision mismatch: expected {expected}, got {actual}")]
    RegistryRevisionMismatch { expected: u64, actual: u64 },
    #[error("production key registry digest does not match")]
    RegistryDigestMismatch,
    #[error("production logical key identity already exists")]
    LogicalIdentityAlreadyExists,
    #[error("production key generation already exists")]
    DuplicateKeyGeneration,
    #[error("production public key material cannot be reused")]
    PublicKeyReuse,
    #[error("production key identity was substituted")]
    IdentitySubstitution,
    #[error("production key role does not match the governed identity")]
    RoleMismatch,
    #[error("unknown production key generation")]
    UnknownKeyGeneration,
    #[error("production key is not valid yet")]
    KeyNotYetValid,
    #[error("production key validity window has expired")]
    KeyExpired,
    #[error("production key has been revoked")]
    KeyRevoked,
    #[error("production key revocation reason must be lowercase SHA-256")]
    InvalidRevocationReasonDigest,
    #[error("production key trust binding does not match the registry record")]
    TrustBindingMismatch,
    #[error("production key canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("production key governance serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    Production(#[from] ProductionSignerError),
}
