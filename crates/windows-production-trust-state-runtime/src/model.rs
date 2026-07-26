use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_production_key_governance_runtime::{
    ProductionKeyGovernanceError, ProductionKeyRecord, ProductionKeyRegistry,
    ProductionKeyRegistrySnapshot, ProductionKeyStatus,
};
use ergaxiom_windows_production_signer_runtime::{
    ProductionSignerError, validate_identifier, validate_sha256,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const TRUST_GOVERNANCE_KEY_SCHEMA: &str = "0.1.0";
pub const TRUST_GOVERNANCE_POLICY_SCHEMA: &str = "0.1.0";
pub const TRUST_GOVERNANCE_SIGNATURE_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_TRUST_STATE_BODY_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_TRUST_STATE_ENVELOPE_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_TRUST_STATE_BINDING_SCHEMA: &str = "0.1.0";
pub const ACCEPTED_TRUST_CHECKPOINT_SCHEMA: &str = "0.1.0";
pub const OFFLINE_BOOTSTRAP_EXPECTATION_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_TRUST_RECOVERY_BODY_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_TRUST_RECOVERY_ENVELOPE_SCHEMA: &str = "0.1.0";
pub const GOVERNANCE_ALGORITHM: &str = "ed25519-sha256-digest";

const TRUST_STATE_SIGNATURE_DOMAIN: &[u8] = b"ergaxiom-production-trust-state-v1";
const TRUST_RECOVERY_SIGNATURE_DOMAIN: &[u8] = b"ergaxiom-production-trust-recovery-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustGovernanceKeyStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGovernanceKeyRecord {
    pub schema_version: String,
    pub key_id: String,
    pub public_key_base64url: String,
    pub public_key_digest: String,
    pub status: TrustGovernanceKeyStatus,
    pub not_before_epoch_s: u64,
    pub not_after_epoch_s: u64,
    pub revoked_at_epoch_s: Option<u64>,
    pub revocation_reason_digest: Option<String>,
    pub record_digest: String,
}

impl TrustGovernanceKeyRecord {
    pub fn new_active(
        key_id: impl Into<String>,
        public_key: [u8; 32],
        not_before_epoch_s: u64,
        not_after_epoch_s: u64,
    ) -> Result<Self, ProductionTrustStateError> {
        let mut record = Self {
            schema_version: TRUST_GOVERNANCE_KEY_SCHEMA.to_owned(),
            key_id: key_id.into(),
            public_key_base64url: URL_SAFE_NO_PAD.encode(public_key),
            public_key_digest: lowercase_sha256(&public_key),
            status: TrustGovernanceKeyStatus::Active,
            not_before_epoch_s,
            not_after_epoch_s,
            revoked_at_epoch_s: None,
            revocation_reason_digest: None,
            record_digest: String::new(),
        };
        record.record_digest = record.expected_digest()?;
        record.validate_seal()?;
        Ok(record)
    }

    pub fn validate_seal(&self) -> Result<(), ProductionTrustStateError> {
        if self.schema_version != TRUST_GOVERNANCE_KEY_SCHEMA {
            return Err(ProductionTrustStateError::UnsupportedGovernanceKeySchema);
        }
        validate_identifier("governance_key_id", &self.key_id)?;
        validate_sha256(&self.public_key_digest)?;
        if self.not_before_epoch_s >= self.not_after_epoch_s {
            return Err(ProductionTrustStateError::InvalidValidityWindow);
        }
        let public_key = decode_fixed::<32>(&self.public_key_base64url)
            .map_err(|_| ProductionTrustStateError::InvalidGovernancePublicKey)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| ProductionTrustStateError::InvalidGovernancePublicKey)?;
        if lowercase_sha256(&public_key) != self.public_key_digest {
            return Err(ProductionTrustStateError::GovernancePublicKeyDigestMismatch);
        }
        match self.status {
            TrustGovernanceKeyStatus::Active => {
                if self.revoked_at_epoch_s.is_some() || self.revocation_reason_digest.is_some() {
                    return Err(ProductionTrustStateError::InvalidGovernanceKeyState);
                }
            }
            TrustGovernanceKeyStatus::Revoked => {
                let revoked_at = self
                    .revoked_at_epoch_s
                    .ok_or(ProductionTrustStateError::InvalidGovernanceKeyState)?;
                if revoked_at == 0 || self.revocation_reason_digest.is_none() {
                    return Err(ProductionTrustStateError::InvalidGovernanceKeyState);
                }
                validate_sha256(
                    self.revocation_reason_digest
                        .as_deref()
                        .ok_or(ProductionTrustStateError::InvalidGovernanceKeyState)?,
                )?;
            }
        }
        if self.record_digest != self.expected_digest()? {
            return Err(ProductionTrustStateError::GovernanceKeyRecordDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionTrustStateError> {
        digest_with_blank_field(self, "record_digest")
    }

    fn verifying_key(&self) -> Result<VerifyingKey, ProductionTrustStateError> {
        let bytes = decode_fixed::<32>(&self.public_key_base64url)
            .map_err(|_| ProductionTrustStateError::InvalidGovernancePublicKey)?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| ProductionTrustStateError::InvalidGovernancePublicKey)
    }

    fn valid_for_signature_at(
        &self,
        signed_at_epoch_s: u64,
    ) -> Result<(), ProductionTrustStateError> {
        self.validate_seal()?;
        if self.status == TrustGovernanceKeyStatus::Revoked {
            return Err(ProductionTrustStateError::GovernanceKeyRevoked);
        }
        if signed_at_epoch_s < self.not_before_epoch_s {
            return Err(ProductionTrustStateError::GovernanceKeyNotYetValid);
        }
        if signed_at_epoch_s >= self.not_after_epoch_s {
            return Err(ProductionTrustStateError::GovernanceKeyExpired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGovernancePolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub revision: u64,
    pub signature_threshold: u16,
    pub keys: Vec<TrustGovernanceKeyRecord>,
    pub policy_digest: String,
}

impl TrustGovernancePolicy {
    pub fn new(
        policy_id: impl Into<String>,
        revision: u64,
        signature_threshold: u16,
        mut keys: Vec<TrustGovernanceKeyRecord>,
    ) -> Result<Self, ProductionTrustStateError> {
        keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        let mut policy = Self {
            schema_version: TRUST_GOVERNANCE_POLICY_SCHEMA.to_owned(),
            policy_id: policy_id.into(),
            revision,
            signature_threshold,
            keys,
            policy_digest: String::new(),
        };
        policy.policy_digest = policy.expected_digest()?;
        policy.validate_seal()?;
        Ok(policy)
    }

    pub fn validate_seal(&self) -> Result<(), ProductionTrustStateError> {
        if self.schema_version != TRUST_GOVERNANCE_POLICY_SCHEMA {
            return Err(ProductionTrustStateError::UnsupportedGovernancePolicySchema);
        }
        validate_identifier("governance_policy_id", &self.policy_id)?;
        if self.revision == 0
            || self.signature_threshold == 0
            || usize::from(self.signature_threshold) > self.keys.len()
        {
            return Err(ProductionTrustStateError::InvalidGovernanceThreshold);
        }
        let mut key_ids = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        let mut previous_key_id: Option<&str> = None;
        for key in &self.keys {
            key.validate_seal()?;
            if previous_key_id.is_some_and(|previous| previous >= key.key_id.as_str()) {
                return Err(ProductionTrustStateError::GovernanceKeysNotCanonical);
            }
            previous_key_id = Some(&key.key_id);
            if !key_ids.insert(key.key_id.clone()) {
                return Err(ProductionTrustStateError::DuplicateGovernanceKey);
            }
            if !public_keys.insert(key.public_key_digest.clone()) {
                return Err(ProductionTrustStateError::GovernancePublicKeyReuse);
            }
        }
        if self.policy_digest != self.expected_digest()? {
            return Err(ProductionTrustStateError::GovernancePolicyDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionTrustStateError> {
        digest_with_blank_field(self, "policy_digest")
    }

    fn verify_signatures(
        &self,
        domain: &[u8],
        digest: &str,
        signed_at_epoch_s: u64,
        signatures: &[TrustGovernanceSignature],
    ) -> Result<(), ProductionTrustStateError> {
        self.validate_seal()?;
        validate_sha256(digest)?;
        if signatures.is_empty() {
            return Err(ProductionTrustStateError::GovernanceSignaturesMissing);
        }
        let records: BTreeMap<&str, &TrustGovernanceKeyRecord> = self
            .keys
            .iter()
            .map(|record| (record.key_id.as_str(), record))
            .collect();
        let message = signature_message(domain, digest)?;
        let mut verified_ids = BTreeSet::new();
        for governance_signature in signatures {
            governance_signature.validate_shape()?;
            if governance_signature.signed_digest != digest {
                return Err(ProductionTrustStateError::GovernanceSignatureDigestMismatch);
            }
            if !verified_ids.insert(governance_signature.key_id.clone()) {
                return Err(ProductionTrustStateError::DuplicateGovernanceSignature);
            }
            let record = records
                .get(governance_signature.key_id.as_str())
                .ok_or(ProductionTrustStateError::UnknownGovernanceKey)?;
            record.valid_for_signature_at(signed_at_epoch_s)?;
            let signature_bytes = decode_fixed::<64>(&governance_signature.signature_base64url)
                .map_err(|_| ProductionTrustStateError::InvalidGovernanceSignature)?;
            let signature = Signature::from_slice(&signature_bytes)
                .map_err(|_| ProductionTrustStateError::InvalidGovernanceSignature)?;
            record
                .verifying_key()?
                .verify(&message, &signature)
                .map_err(|_| ProductionTrustStateError::GovernanceSignatureVerificationFailed)?;
        }
        if verified_ids.len() < usize::from(self.signature_threshold) {
            return Err(ProductionTrustStateError::GovernanceThresholdNotMet);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGovernanceSignature {
    pub schema_version: String,
    pub key_id: String,
    pub algorithm: String,
    pub signed_digest: String,
    pub signature_base64url: String,
}

impl TrustGovernanceSignature {
    pub fn from_signature_bytes(
        key_id: impl Into<String>,
        signed_digest: impl Into<String>,
        signature: [u8; 64],
    ) -> Result<Self, ProductionTrustStateError> {
        let value = Self {
            schema_version: TRUST_GOVERNANCE_SIGNATURE_SCHEMA.to_owned(),
            key_id: key_id.into(),
            algorithm: GOVERNANCE_ALGORITHM.to_owned(),
            signed_digest: signed_digest.into(),
            signature_base64url: URL_SAFE_NO_PAD.encode(signature),
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_shape(&self) -> Result<(), ProductionTrustStateError> {
        if self.schema_version != TRUST_GOVERNANCE_SIGNATURE_SCHEMA {
            return Err(ProductionTrustStateError::UnsupportedGovernanceSignatureSchema);
        }
        validate_identifier("governance_key_id", &self.key_id)?;
        if self.algorithm != GOVERNANCE_ALGORITHM {
            return Err(ProductionTrustStateError::GovernanceAlgorithmSubstitution);
        }
        validate_sha256(&self.signed_digest)?;
        decode_fixed::<64>(&self.signature_base64url)
            .map_err(|_| ProductionTrustStateError::InvalidGovernanceSignature)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionTrustStateBody {
    pub schema_version: String,
    pub deployment_id: String,
    pub revision: u64,
    pub previous_state_digest: Option<String>,
    pub registry: ProductionKeyRegistrySnapshot,
    pub registry_digest: String,
    pub caller_allowlist_revision: u64,
    pub caller_allowlist_digest: String,
    pub signer_service_executable_digest: String,
    pub service_policy_revision: u64,
    pub service_policy_digest: String,
    pub activated_at_epoch_s: u64,
    pub not_before_epoch_s: u64,
    pub not_after_epoch_s: u64,
    pub minimum_accepted_revision: u64,
    pub recovery_policy_id: String,
    pub body_digest: String,
}

impl ProductionTrustStateBody {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment_id: impl Into<String>,
        revision: u64,
        previous_state_digest: Option<String>,
        registry: ProductionKeyRegistrySnapshot,
        caller_allowlist_revision: u64,
        caller_allowlist_digest: impl Into<String>,
        signer_service_executable_digest: impl Into<String>,
        service_policy_revision: u64,
        service_policy_digest: impl Into<String>,
        activated_at_epoch_s: u64,
        not_before_epoch_s: u64,
        not_after_epoch_s: u64,
        minimum_accepted_revision: u64,
        recovery_policy_id: impl Into<String>,
    ) -> Result<Self, ProductionTrustStateError> {
        let registry_digest = registry.digest()?;
        let mut body = Self {
            schema_version: PRODUCTION_TRUST_STATE_BODY_SCHEMA.to_owned(),
            deployment_id: deployment_id.into(),
            revision,
            previous_state_digest,
            registry,
            registry_digest,
            caller_allowlist_revision,
            caller_allowlist_digest: caller_allowlist_digest.into(),
            signer_service_executable_digest: signer_service_executable_digest.into(),
            service_policy_revision,
            service_policy_digest: service_policy_digest.into(),
            activated_at_epoch_s,
            not_before_epoch_s,
            not_after_epoch_s,
            minimum_accepted_revision,
            recovery_policy_id: recovery_policy_id.into(),
            body_digest: String::new(),
        };
        body.body_digest = body.expected_digest()?;
        body.validate_shape()?;
        Ok(body)
    }

    pub fn validate_shape(&self) -> Result<(), ProductionTrustStateError> {
        if self.schema_version != PRODUCTION_TRUST_STATE_BODY_SCHEMA {
            return Err(ProductionTrustStateError::UnsupportedTrustStateBodySchema);
        }
        validate_identifier("deployment_id", &self.deployment_id)?;
        validate_identifier("recovery_policy_id", &self.recovery_policy_id)?;
        if self.revision == 0
            || self.minimum_accepted_revision == 0
            || self.minimum_accepted_revision > self.revision
            || self.caller_allowlist_revision == 0
            || self.service_policy_revision == 0
        {
            return Err(ProductionTrustStateError::InvalidTrustStateRevision);
        }
        match (&self.previous_state_digest, self.revision) {
            (None, 1) => {}
            (Some(digest), revision) if revision > 1 => validate_sha256(digest)?,
            _ => return Err(ProductionTrustStateError::InvalidPreviousStateBinding),
        }
        if self.not_before_epoch_s >= self.not_after_epoch_s
            || self.activated_at_epoch_s < self.not_before_epoch_s
            || self.activated_at_epoch_s >= self.not_after_epoch_s
        {
            return Err(ProductionTrustStateError::InvalidValidityWindow);
        }
        self.registry.validate_seal()?;
        self.registry
            .validate_active_generations(self.activated_at_epoch_s)?;
        validate_sha256(&self.registry_digest)?;
        if self.registry_digest != self.registry.digest()? {
            return Err(ProductionTrustStateError::RegistryDigestMismatch);
        }
        validate_sha256(&self.caller_allowlist_digest)?;
        validate_sha256(&self.signer_service_executable_digest)?;
        validate_sha256(&self.service_policy_digest)?;
        if self.body_digest != self.expected_digest()? {
            return Err(ProductionTrustStateError::TrustStateBodyDigestMismatch);
        }
        if contains_secret_shaped_field(&serde_json::to_value(self)?) {
            return Err(ProductionTrustStateError::SecretShapedTrustMaterial);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionTrustStateError> {
        digest_with_blank_field(self, "body_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionTrustStateEnvelope {
    pub schema_version: String,
    pub body: ProductionTrustStateBody,
    pub governance_policy_digest: String,
    pub signatures: Vec<TrustGovernanceSignature>,
    pub envelope_digest: String,
}

impl ProductionTrustStateEnvelope {
    pub fn new(
        body: ProductionTrustStateBody,
        governance_policy: &TrustGovernancePolicy,
        mut signatures: Vec<TrustGovernanceSignature>,
    ) -> Result<Self, ProductionTrustStateError> {
        signatures.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        let mut envelope = Self {
            schema_version: PRODUCTION_TRUST_STATE_ENVELOPE_SCHEMA.to_owned(),
            body,
            governance_policy_digest: governance_policy.policy_digest.clone(),
            signatures,
            envelope_digest: String::new(),
        };
        envelope.envelope_digest = envelope.expected_digest()?;
        envelope.verify(governance_policy, envelope.body.activated_at_epoch_s)?;
        Ok(envelope)
    }

    pub fn verify(
        &self,
        governance_policy: &TrustGovernancePolicy,
        trusted_now_epoch_s: u64,
    ) -> Result<VerifiedProductionTrustState, ProductionTrustStateError> {
        if self.schema_version != PRODUCTION_TRUST_STATE_ENVELOPE_SCHEMA {
            return Err(ProductionTrustStateError::UnsupportedTrustStateEnvelopeSchema);
        }
        self.body.validate_shape()?;
        governance_policy.validate_seal()?;
        if self.governance_policy_digest != governance_policy.policy_digest {
            return Err(ProductionTrustStateError::GovernancePolicyDigestMismatch);
        }
        if trusted_now_epoch_s < self.body.not_before_epoch_s
            || trusted_now_epoch_s >= self.body.not_after_epoch_s
        {
            return Err(ProductionTrustStateError::TrustStateOutsideValidityWindow);
        }
        governance_policy.verify_signatures(
            TRUST_STATE_SIGNATURE_DOMAIN,
            &self.body.body_digest,
            self.body.activated_at_epoch_s,
            &self.signatures,
        )?;
        if self.envelope_digest != self.expected_digest()? {
            return Err(ProductionTrustStateError::TrustStateEnvelopeDigestMismatch);
        }
        let registry = ProductionKeyRegistry::from_snapshot(self.body.registry.clone())?;
        let binding = ProductionTrustStateBinding::from_parts(self)?;
        Ok(VerifiedProductionTrustState {
            envelope: self.clone(),
            registry,
            binding,
        })
    }

    fn expected_digest(&self) -> Result<String, ProductionTrustStateError> {
        digest_with_blank_field(self, "envelope_digest")
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedProductionTrustState {
    envelope: ProductionTrustStateEnvelope,
    registry: ProductionKeyRegistry,
    binding: ProductionTrustStateBinding,
}

impl VerifiedProductionTrustState {
    #[must_use]
    pub const fn envelope(&self) -> &ProductionTrustStateEnvelope {
        &self.envelope
    }

    #[must_use]
    pub const fn body(&self) -> &ProductionTrustStateBody {
        &self.envelope.body
    }

    #[must_use]
    pub const fn registry(&self) -> &ProductionKeyRegistry {
        &self.registry
    }

    #[must_use]
    pub const fn binding(&self) -> &ProductionTrustStateBinding {
        &self.binding
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionTrustStateBinding {
    pub schema_version: String,
    pub deployment_id: String,
    pub revision: u64,
    pub state_digest: String,
    pub envelope_digest: String,
    pub registry_revision: u64,
    pub registry_digest: String,
    pub caller_allowlist_revision: u64,
    pub caller_allowlist_digest: String,
    pub signer_service_executable_digest: String,
    pub service_policy_revision: u64,
    pub service_policy_digest: String,
    pub binding_digest: String,
}

impl ProductionTrustStateBinding {
    fn from_parts(
        envelope: &ProductionTrustStateEnvelope,
    ) -> Result<Self, ProductionTrustStateError> {
        let body = &envelope.body;
        let mut binding = Self {
            schema_version: PRODUCTION_TRUST_STATE_BINDING_SCHEMA.to_owned(),
            deployment_id: body.deployment_id.clone(),
            revision: body.revision,
            state_digest: body.body_digest.clone(),
            envelope_digest: envelope.envelope_digest.clone(),
            registry_revision: body.registry.revision,
            registry_digest: body.registry_digest.clone(),
            caller_allowlist_revision: body.caller_allowlist_revision,
            caller_allowlist_digest: body.caller_allowlist_digest.clone(),
            signer_service_executable_digest: body.signer_service_executable_digest.clone(),
            service_policy_revision: body.service_policy_revision,
            service_policy_digest: body.service_policy_digest.clone(),
            binding_digest: String::new(),
        };
        binding.binding_digest = binding.expected_digest()?;
        binding.validate_seal()?;
        Ok(binding)
    }

    pub fn validate_seal(&self) -> Result<(), ProductionTrustStateError> {
        if self.schema_version != PRODUCTION_TRUST_STATE_BINDING_SCHEMA {
            return Err(ProductionTrustStateError::UnsupportedTrustStateBindingSchema);
        }
        validate_identifier("deployment_id", &self.deployment_id)?;
        if self.revision == 0
            || self.registry_revision == 0
            || self.caller_allowlist_revision == 0
            || self.service_policy_revision == 0
        {
            return Err(ProductionTrustStateError::InvalidTrustStateRevision);
        }
        for digest in [
            &self.state_digest,
            &self.envelope_digest,
            &self.registry_digest,
            &self.caller_allowlist_digest,
            &self.signer_service_executable_digest,
            &self.service_policy_digest,
            &self.binding_digest,
        ] {
            validate_sha256(digest)?;
        }
        if self.binding_digest != self.expected_digest()? {
            return Err(ProductionTrustStateError::TrustStateBindingDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionTrustStateError> {
        digest_with_blank_field(self, "binding_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedTrustCheckpoint {
    pub schema_version: String,
    pub deployment_id: String,
    pub revision: u64,
    pub state_digest: String,
    pub envelope_digest: String,
    pub registry_revision: u64,
    pub registry_digest: String,
    pub caller_allowlist_revision: u64,
    pub service_policy_revision: u64,
    pub minimum_accepted_revision: u64,
    pub last_recovery_sequence: u64,
    pub checkpoint_digest: String,
}

impl AcceptedTrustCheckpoint {
    fn from_verified(
        verified: &VerifiedProductionTrustState,
        last_recovery_sequence: u64,
    ) -> Result<Self, ProductionTrustStateError> {
        let body = verified.body();
        let mut checkpoint = Self {
            schema_version: ACCEPTED_TRUST_CHECKPOINT_SCHEMA.to_owned(),
            deployment_id: body.deployment_id.clone(),
            revision: body.revision,
            state_digest: body.body_digest.clone(),
            envelope_digest: verified.envelope().envelope_digest.clone(),
            registry_revision: body.registry.revision,
            registry_digest: body.registry_digest.clone(),
            caller_allowlist_revision: body.caller_allowlist_revision,
            service_policy_revision: body.service_policy_revision,
            minimum_accepted_revision: body.minimum_accepted_revision,
            last_recovery_sequence,
            checkpoint_digest: String::new(),
        };
        checkpoint.checkpoint_digest = checkpoint.expected_digest()?;
        checkpoint.validate_seal()?;
        Ok(checkpoint)
    }

    pub fn validate_seal(&self) -> Result<(), ProductionTrustStateError> {
        if self.schema_version != ACCEPTED_TRUST_CHECKPOINT_SCHEMA {
            return Err(ProductionTrustStateError::UnsupportedCheckpointSchema);
        }
        validate_identifier("deployment_id", &self.deployment_id)?;
        if self.revision == 0
            || self.registry_revision == 0
            || self.caller_allowlist_revision == 0
            || self.service_policy_revision == 0
            || self.minimum_accepted_revision == 0
            || self.minimum_accepted_revision > self.revision
        {
            return Err(ProductionTrustStateError::InvalidCheckpoint);
        }
        for digest in [
            &self.state_digest,
            &self.envelope_digest,
            &self.registry_digest,
            &self.checkpoint_digest,
        ] {
            validate_sha256(digest)?;
        }
        if self.checkpoint_digest != self.expected_digest()? {
            return Err(ProductionTrustStateError::CheckpointDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionTrustStateError> {
        digest_with_blank_field(self, "checkpoint_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineBootstrapExpectation {
    pub schema_version: String,
    pub deployment_id: String,
    pub expected_envelope_digest: String,
    pub expected_governance_policy_digest: String,
    pub expectation_digest: String,
}

impl OfflineBootstrapExpectation {
    pub fn new(
        deployment_id: impl Into<String>,
        expected_envelope_digest: impl Into<String>,
        expected_governance_policy_digest: impl Into<String>,
    ) -> Result<Self, ProductionTrustStateError> {
        let mut expectation = Self {
            schema_version: OFFLINE_BOOTSTRAP_EXPECTATION_SCHEMA.to_owned(),
            deployment_id: deployment_id.into(),
            expected_envelope_digest: expected_envelope_digest.into(),
            expected_governance_policy_digest: expected_governance_policy_digest.into(),
            expectation_digest: String::new(),
        };
        expectation.expectation_digest = expectation.expected_digest()?;
        expectation.validate_seal()?;
        Ok(expectation)
    }

    pub fn validate_seal(&self) -> Result<(), ProductionTrustStateError> {
        if self.schema_version != OFFLINE_BOOTSTRAP_EXPECTATION_SCHEMA {
            return Err(ProductionTrustStateError::UnsupportedBootstrapSchema);
        }
        validate_identifier("deployment_id", &self.deployment_id)?;
        validate_sha256(&self.expected_envelope_digest)?;
        validate_sha256(&self.expected_governance_policy_digest)?;
        if self.expectation_digest != self.expected_digest()? {
            return Err(ProductionTrustStateError::BootstrapExpectationDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionTrustStateError> {
        digest_with_blank_field(self, "expectation_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionTrustRecoveryBody {
    pub schema_version: String,
    pub deployment_id: String,
    pub recovery_policy_id: String,
    pub damaged_state_digest: String,
    pub replacement_state_digest: String,
    pub recovery_reason_digest: String,
    pub recovery_sequence: u64,
    pub minimum_uncompromised_revision: u64,
    pub maximum_replacement_revision: u64,
    pub expires_at_epoch_s: u64,
    pub body_digest: String,
}

impl ProductionTrustRecoveryBody {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment_id: impl Into<String>,
        recovery_policy_id: impl Into<String>,
        damaged_state_digest: impl Into<String>,
        replacement_state_digest: impl Into<String>,
        recovery_reason_digest: impl Into<String>,
        recovery_sequence: u64,
        minimum_uncompromised_revision: u64,
        maximum_replacement_revision: u64,
        expires_at_epoch_s: u64,
    ) -> Result<Self, ProductionTrustStateError> {
        let mut body = Self {
            schema_version: PRODUCTION_TRUST_RECOVERY_BODY_SCHEMA.to_owned(),
            deployment_id: deployment_id.into(),
            recovery_policy_id: recovery_policy_id.into(),
            damaged_state_digest: damaged_state_digest.into(),
            replacement_state_digest: replacement_state_digest.into(),
            recovery_reason_digest: recovery_reason_digest.into(),
            recovery_sequence,
            minimum_uncompromised_revision,
            maximum_replacement_revision,
            expires_at_epoch_s,
            body_digest: String::new(),
        };
        body.body_digest = body.expected_digest()?;
        body.validate_shape()?;
        Ok(body)
    }

    pub fn validate_shape(&self) -> Result<(), ProductionTrustStateError> {
        if self.schema_version != PRODUCTION_TRUST_RECOVERY_BODY_SCHEMA {
            return Err(ProductionTrustStateError::UnsupportedRecoveryBodySchema);
        }
        validate_identifier("deployment_id", &self.deployment_id)?;
        validate_identifier("recovery_policy_id", &self.recovery_policy_id)?;
        for digest in [
            &self.damaged_state_digest,
            &self.replacement_state_digest,
            &self.recovery_reason_digest,
        ] {
            validate_sha256(digest)?;
        }
        if self.recovery_sequence == 0
            || self.minimum_uncompromised_revision == 0
            || self.maximum_replacement_revision < self.minimum_uncompromised_revision
            || self.expires_at_epoch_s == 0
        {
            return Err(ProductionTrustStateError::InvalidRecoveryBounds);
        }
        if self.body_digest != self.expected_digest()? {
            return Err(ProductionTrustStateError::RecoveryBodyDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionTrustStateError> {
        digest_with_blank_field(self, "body_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionTrustRecoveryEnvelope {
    pub schema_version: String,
    pub body: ProductionTrustRecoveryBody,
    pub governance_policy_digest: String,
    pub signatures: Vec<TrustGovernanceSignature>,
    pub envelope_digest: String,
}

impl ProductionTrustRecoveryEnvelope {
    pub fn new(
        body: ProductionTrustRecoveryBody,
        governance_policy: &TrustGovernancePolicy,
        mut signatures: Vec<TrustGovernanceSignature>,
    ) -> Result<Self, ProductionTrustStateError> {
        signatures.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        let mut envelope = Self {
            schema_version: PRODUCTION_TRUST_RECOVERY_ENVELOPE_SCHEMA.to_owned(),
            body,
            governance_policy_digest: governance_policy.policy_digest.clone(),
            signatures,
            envelope_digest: String::new(),
        };
        envelope.envelope_digest = envelope.expected_digest()?;
        envelope.verify(
            governance_policy,
            envelope.body.expires_at_epoch_s.saturating_sub(1),
        )?;
        Ok(envelope)
    }

    pub fn verify(
        &self,
        governance_policy: &TrustGovernancePolicy,
        trusted_now_epoch_s: u64,
    ) -> Result<(), ProductionTrustStateError> {
        if self.schema_version != PRODUCTION_TRUST_RECOVERY_ENVELOPE_SCHEMA {
            return Err(ProductionTrustStateError::UnsupportedRecoveryEnvelopeSchema);
        }
        self.body.validate_shape()?;
        governance_policy.validate_seal()?;
        if self.governance_policy_digest != governance_policy.policy_digest {
            return Err(ProductionTrustStateError::GovernancePolicyDigestMismatch);
        }
        if trusted_now_epoch_s >= self.body.expires_at_epoch_s {
            return Err(ProductionTrustStateError::RecoveryExpired);
        }
        governance_policy.verify_signatures(
            TRUST_RECOVERY_SIGNATURE_DOMAIN,
            &self.body.body_digest,
            trusted_now_epoch_s,
            &self.signatures,
        )?;
        if self.envelope_digest != self.expected_digest()? {
            return Err(ProductionTrustStateError::RecoveryEnvelopeDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionTrustStateError> {
        digest_with_blank_field(self, "envelope_digest")
    }
}

#[derive(Debug, Clone)]
pub struct ActivatedProductionTrustState {
    pub verified: VerifiedProductionTrustState,
    pub checkpoint: AcceptedTrustCheckpoint,
    pub recovery: Option<ProductionTrustRecoveryEnvelope>,
}

#[derive(Debug, Clone, Default)]
pub struct ProductionTrustStateActivator {
    current: Option<VerifiedProductionTrustState>,
    checkpoint: Option<AcceptedTrustCheckpoint>,
}

impl ProductionTrustStateActivator {
    pub fn from_accepted(
        current: VerifiedProductionTrustState,
        checkpoint: AcceptedTrustCheckpoint,
    ) -> Result<Self, ProductionTrustStateError> {
        checkpoint.validate_seal()?;
        validate_checkpoint_matches(&current, &checkpoint)?;
        Ok(Self {
            current: Some(current),
            checkpoint: Some(checkpoint),
        })
    }

    pub fn bootstrap(
        &mut self,
        envelope: &ProductionTrustStateEnvelope,
        governance_policy: &TrustGovernancePolicy,
        expectation: &OfflineBootstrapExpectation,
        trusted_now_epoch_s: u64,
    ) -> Result<ActivatedProductionTrustState, ProductionTrustStateError> {
        if self.current.is_some() || self.checkpoint.is_some() {
            return Err(ProductionTrustStateError::AlreadyBootstrapped);
        }
        expectation.validate_seal()?;
        let verified = envelope.verify(governance_policy, trusted_now_epoch_s)?;
        let body = verified.body();
        if body.revision != 1
            || body.previous_state_digest.is_some()
            || body.deployment_id != expectation.deployment_id
            || envelope.envelope_digest != expectation.expected_envelope_digest
            || governance_policy.policy_digest != expectation.expected_governance_policy_digest
        {
            return Err(ProductionTrustStateError::BootstrapExpectationMismatch);
        }
        let checkpoint = AcceptedTrustCheckpoint::from_verified(&verified, 0)?;
        self.current = Some(verified.clone());
        self.checkpoint = Some(checkpoint.clone());
        Ok(ActivatedProductionTrustState {
            verified,
            checkpoint,
            recovery: None,
        })
    }

    pub fn activate(
        &mut self,
        envelope: &ProductionTrustStateEnvelope,
        governance_policy: &TrustGovernancePolicy,
        trusted_now_epoch_s: u64,
    ) -> Result<ActivatedProductionTrustState, ProductionTrustStateError> {
        let current = self
            .current
            .as_ref()
            .ok_or(ProductionTrustStateError::BootstrapRequired)?;
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or(ProductionTrustStateError::BootstrapRequired)?;
        checkpoint.validate_seal()?;
        validate_checkpoint_matches(current, checkpoint)?;
        let verified = envelope.verify(governance_policy, trusted_now_epoch_s)?;
        let next = verified.body();
        if next.deployment_id != checkpoint.deployment_id {
            return Err(ProductionTrustStateError::DeploymentIdentityMismatch);
        }
        if next.revision != checkpoint.revision.saturating_add(1) {
            return Err(ProductionTrustStateError::NonMonotonicRevision);
        }
        if next.previous_state_digest.as_deref() != Some(checkpoint.state_digest.as_str()) {
            return Err(ProductionTrustStateError::PreviousStateDigestMismatch);
        }
        if next.minimum_accepted_revision < checkpoint.minimum_accepted_revision
            || next.registry.revision < checkpoint.registry_revision
            || next.caller_allowlist_revision < checkpoint.caller_allowlist_revision
            || next.service_policy_revision < checkpoint.service_policy_revision
        {
            return Err(ProductionTrustStateError::TrustStateDowngrade);
        }
        let next_checkpoint =
            AcceptedTrustCheckpoint::from_verified(&verified, checkpoint.last_recovery_sequence)?;
        self.current = Some(verified.clone());
        self.checkpoint = Some(next_checkpoint.clone());
        Ok(ActivatedProductionTrustState {
            verified,
            checkpoint: next_checkpoint,
            recovery: None,
        })
    }

    pub fn recover(
        &mut self,
        replacement: &ProductionTrustStateEnvelope,
        recovery: &ProductionTrustRecoveryEnvelope,
        governance_policy: &TrustGovernancePolicy,
        trusted_now_epoch_s: u64,
    ) -> Result<ActivatedProductionTrustState, ProductionTrustStateError> {
        let current = self
            .current
            .as_ref()
            .ok_or(ProductionTrustStateError::BootstrapRequired)?;
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or(ProductionTrustStateError::BootstrapRequired)?;
        checkpoint.validate_seal()?;
        validate_checkpoint_matches(current, checkpoint)?;
        recovery.verify(governance_policy, trusted_now_epoch_s)?;
        let replacement_verified = replacement.verify(governance_policy, trusted_now_epoch_s)?;
        let recovery_body = &recovery.body;
        let replacement_body = replacement_verified.body();
        if recovery_body.deployment_id != checkpoint.deployment_id
            || replacement_body.deployment_id != checkpoint.deployment_id
            || recovery_body.recovery_policy_id != current.body().recovery_policy_id
            || replacement_body.recovery_policy_id != current.body().recovery_policy_id
        {
            return Err(ProductionTrustStateError::DeploymentIdentityMismatch);
        }
        if recovery_body.damaged_state_digest != checkpoint.state_digest
            || recovery_body.replacement_state_digest != replacement_body.body_digest
        {
            return Err(ProductionTrustStateError::RecoveryStateDigestMismatch);
        }
        if recovery_body.recovery_sequence <= checkpoint.last_recovery_sequence {
            return Err(ProductionTrustStateError::RecoveryReplay);
        }
        let minimum = checkpoint
            .minimum_accepted_revision
            .max(recovery_body.minimum_uncompromised_revision);
        if replacement_body.revision < minimum
            || replacement_body.minimum_accepted_revision < minimum
            || replacement_body.revision > recovery_body.maximum_replacement_revision
        {
            return Err(ProductionTrustStateError::RecoveryBelowMinimumRevision);
        }
        reject_revoked_key_reactivation(
            &current.body().registry.records,
            &replacement_body.registry.records,
        )?;
        let next_checkpoint = AcceptedTrustCheckpoint::from_verified(
            &replacement_verified,
            recovery_body.recovery_sequence,
        )?;
        self.current = Some(replacement_verified.clone());
        self.checkpoint = Some(next_checkpoint.clone());
        Ok(ActivatedProductionTrustState {
            verified: replacement_verified,
            checkpoint: next_checkpoint,
            recovery: Some(recovery.clone()),
        })
    }

    #[must_use]
    pub const fn checkpoint(&self) -> Option<&AcceptedTrustCheckpoint> {
        self.checkpoint.as_ref()
    }

    #[must_use]
    pub const fn current(&self) -> Option<&VerifiedProductionTrustState> {
        self.current.as_ref()
    }
}

pub fn trust_state_signature_message(digest: &str) -> Result<Vec<u8>, ProductionTrustStateError> {
    signature_message(TRUST_STATE_SIGNATURE_DOMAIN, digest)
}

pub fn trust_recovery_signature_message(
    digest: &str,
) -> Result<Vec<u8>, ProductionTrustStateError> {
    signature_message(TRUST_RECOVERY_SIGNATURE_DOMAIN, digest)
}

fn validate_checkpoint_matches(
    verified: &VerifiedProductionTrustState,
    checkpoint: &AcceptedTrustCheckpoint,
) -> Result<(), ProductionTrustStateError> {
    let body = verified.body();
    if body.deployment_id != checkpoint.deployment_id
        || body.revision != checkpoint.revision
        || body.body_digest != checkpoint.state_digest
        || verified.envelope().envelope_digest != checkpoint.envelope_digest
        || body.registry.revision != checkpoint.registry_revision
        || body.registry_digest != checkpoint.registry_digest
        || body.caller_allowlist_revision != checkpoint.caller_allowlist_revision
        || body.service_policy_revision != checkpoint.service_policy_revision
        || body.minimum_accepted_revision != checkpoint.minimum_accepted_revision
    {
        return Err(ProductionTrustStateError::CheckpointStateMismatch);
    }
    Ok(())
}

fn reject_revoked_key_reactivation(
    current_records: &[ProductionKeyRecord],
    replacement_records: &[ProductionKeyRecord],
) -> Result<(), ProductionTrustStateError> {
    for current in current_records
        .iter()
        .filter(|record| record.status == ProductionKeyStatus::Revoked)
    {
        let replacement = replacement_records.iter().find(|candidate| {
            candidate.identity == current.identity && candidate.generation == current.generation
        });
        let Some(replacement) = replacement else {
            return Err(ProductionTrustStateError::RevokedKeyReactivation);
        };
        if replacement.status != ProductionKeyStatus::Revoked
            || replacement.public_key_digest != current.public_key_digest
            || replacement.revocation_reason_digest != current.revocation_reason_digest
        {
            return Err(ProductionTrustStateError::RevokedKeyReactivation);
        }
    }
    Ok(())
}

fn signature_message(domain: &[u8], digest: &str) -> Result<Vec<u8>, ProductionTrustStateError> {
    let digest_bytes = decode_sha256(digest)?;
    let mut message = Vec::with_capacity(domain.len() + 1 + digest_bytes.len());
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(&digest_bytes);
    Ok(message)
}

fn digest_with_blank_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, ProductionTrustStateError> {
    let mut value = serde_json::to_value(value)?;
    let object = value
        .as_object_mut()
        .ok_or(ProductionTrustStateError::InvalidCanonicalObject)?;
    object.insert(field.to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

fn decode_sha256(value: &str) -> Result<[u8; 32], ProductionTrustStateError> {
    validate_sha256(value)?;
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = decode_nibble(chunk[0])? << 4 | decode_nibble(chunk[1])?;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Result<u8, ProductionTrustStateError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ProductionTrustStateError::InvalidDigestEncoding),
    }
}

fn lowercase_sha256(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
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

fn contains_secret_shaped_field(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, nested)| {
            matches!(
                key.as_str(),
                "private_key"
                    | "private_seed"
                    | "seed"
                    | "secret"
                    | "protected_seed"
                    | "key_material"
                    | "password"
                    | "dpapi_blob"
            ) || contains_secret_shaped_field(nested)
        }),
        Value::Array(values) => values.iter().any(contains_secret_shaped_field),
        _ => false,
    }
}

#[derive(Debug, Error)]
pub enum ProductionTrustStateError {
    #[error("trust governance key schema is unsupported")]
    UnsupportedGovernanceKeySchema,
    #[error("trust governance policy schema is unsupported")]
    UnsupportedGovernancePolicySchema,
    #[error("trust governance signature schema is unsupported")]
    UnsupportedGovernanceSignatureSchema,
    #[error("production trust-state body schema is unsupported")]
    UnsupportedTrustStateBodySchema,
    #[error("production trust-state envelope schema is unsupported")]
    UnsupportedTrustStateEnvelopeSchema,
    #[error("production trust-state binding schema is unsupported")]
    UnsupportedTrustStateBindingSchema,
    #[error("accepted trust checkpoint schema is unsupported")]
    UnsupportedCheckpointSchema,
    #[error("offline bootstrap expectation schema is unsupported")]
    UnsupportedBootstrapSchema,
    #[error("production trust recovery body schema is unsupported")]
    UnsupportedRecoveryBodySchema,
    #[error("production trust recovery envelope schema is unsupported")]
    UnsupportedRecoveryEnvelopeSchema,
    #[error("trust governance public key is invalid")]
    InvalidGovernancePublicKey,
    #[error("trust governance public-key digest does not match")]
    GovernancePublicKeyDigestMismatch,
    #[error("trust governance key state is invalid")]
    InvalidGovernanceKeyState,
    #[error("trust governance key record digest does not match")]
    GovernanceKeyRecordDigestMismatch,
    #[error("trust governance threshold is invalid")]
    InvalidGovernanceThreshold,
    #[error("trust governance keys are not in canonical order")]
    GovernanceKeysNotCanonical,
    #[error("duplicate trust governance key identity")]
    DuplicateGovernanceKey,
    #[error("trust governance public key is reused")]
    GovernancePublicKeyReuse,
    #[error("trust governance policy digest does not match")]
    GovernancePolicyDigestMismatch,
    #[error("trust governance signatures are missing")]
    GovernanceSignaturesMissing,
    #[error("trust governance signature digest does not match")]
    GovernanceSignatureDigestMismatch,
    #[error("duplicate trust governance signature")]
    DuplicateGovernanceSignature,
    #[error("unknown trust governance key")]
    UnknownGovernanceKey,
    #[error("trust governance key has been revoked")]
    GovernanceKeyRevoked,
    #[error("trust governance key is not yet valid")]
    GovernanceKeyNotYetValid,
    #[error("trust governance key has expired")]
    GovernanceKeyExpired,
    #[error("trust governance signature is invalid")]
    InvalidGovernanceSignature,
    #[error("trust governance signature verification failed")]
    GovernanceSignatureVerificationFailed,
    #[error("trust governance threshold was not met")]
    GovernanceThresholdNotMet,
    #[error("trust governance algorithm was substituted")]
    GovernanceAlgorithmSubstitution,
    #[error("production trust-state revision is invalid")]
    InvalidTrustStateRevision,
    #[error("production trust-state previous-state binding is invalid")]
    InvalidPreviousStateBinding,
    #[error("production trust-state validity window is invalid")]
    InvalidValidityWindow,
    #[error("production trust-state registry digest does not match")]
    RegistryDigestMismatch,
    #[error("production trust-state body digest does not match")]
    TrustStateBodyDigestMismatch,
    #[error("production trust-state envelope digest does not match")]
    TrustStateEnvelopeDigestMismatch,
    #[error("production trust-state is outside its declared validity window")]
    TrustStateOutsideValidityWindow,
    #[error("production trust-state binding digest does not match")]
    TrustStateBindingDigestMismatch,
    #[error("accepted trust checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("accepted trust checkpoint digest does not match")]
    CheckpointDigestMismatch,
    #[error("accepted trust checkpoint does not match the state")]
    CheckpointStateMismatch,
    #[error("offline bootstrap expectation digest does not match")]
    BootstrapExpectationDigestMismatch,
    #[error("offline bootstrap expectation does not match the supplied trust root")]
    BootstrapExpectationMismatch,
    #[error("production trust state is already bootstrapped")]
    AlreadyBootstrapped,
    #[error("production trust state requires explicit offline bootstrap")]
    BootstrapRequired,
    #[error("production trust-state deployment identity does not match")]
    DeploymentIdentityMismatch,
    #[error("production trust-state revision is not monotonic")]
    NonMonotonicRevision,
    #[error("production trust-state previous digest does not match the accepted state")]
    PreviousStateDigestMismatch,
    #[error("production trust-state update attempts a downgrade")]
    TrustStateDowngrade,
    #[error("production trust recovery bounds are invalid")]
    InvalidRecoveryBounds,
    #[error("production trust recovery body digest does not match")]
    RecoveryBodyDigestMismatch,
    #[error("production trust recovery envelope digest does not match")]
    RecoveryEnvelopeDigestMismatch,
    #[error("production trust recovery artifact has expired")]
    RecoveryExpired,
    #[error("production trust recovery state digests do not match")]
    RecoveryStateDigestMismatch,
    #[error("production trust recovery artifact was replayed")]
    RecoveryReplay,
    #[error("production trust recovery falls below the minimum uncompromised revision")]
    RecoveryBelowMinimumRevision,
    #[error("production trust recovery attempts to reactivate a revoked key")]
    RevokedKeyReactivation,
    #[error("production trust state contains secret-shaped material")]
    SecretShapedTrustMaterial,
    #[error("production trust-state digest encoding is invalid")]
    InvalidDigestEncoding,
    #[error("production trust-state canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("production trust-state JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    ProductionSigner(#[from] ProductionSignerError),
    #[error(transparent)]
    ProductionKeyGovernance(#[from] ProductionKeyGovernanceError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}
