#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_production_signer_host_runtime::{
    InstallationEvidenceError, ProductionSignerInstallationValidationReceipt,
    ProductionSignerRecoveryExerciseReceipt,
};
use ergaxiom_windows_production_signer_runtime::{
    ProductionSignerError, validate_identifier, validate_sha256,
};
use ergaxiom_windows_production_trust_state_runtime::{
    ProductionTrustStateError, TrustGovernancePolicy, VerifiedProductionTrustState,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const DEPLOYMENT_EVIDENCE_KEY_SCHEMA: &str = "0.1.0";
pub const DEPLOYMENT_EVIDENCE_POLICY_SCHEMA: &str = "0.1.0";
pub const DEPLOYMENT_EVIDENCE_SIGNATURE_SCHEMA: &str = "0.1.0";
pub const SIGNED_INSTALLATION_EVIDENCE_SCHEMA: &str = "0.1.0";
pub const SIGNED_RECOVERY_EVIDENCE_SCHEMA: &str = "0.1.0";
pub const DEPLOYMENT_EVIDENCE_POLICY_ID: &str = "ergaxiom.production-deployment-evidence";
pub const DEPLOYMENT_EVIDENCE_ALGORITHM: &str = "ed25519-sha256-digest";

const INSTALLATION_SIGNATURE_DOMAIN: &[u8] =
    b"ergaxiom-production-installation-evidence-v1";
const RECOVERY_SIGNATURE_DOMAIN: &[u8] = b"ergaxiom-production-recovery-evidence-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeploymentEvidenceKeyStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentEvidenceKeyRecord {
    pub schema_version: String,
    pub key_id: String,
    pub public_key_base64url: String,
    pub public_key_digest: String,
    pub status: DeploymentEvidenceKeyStatus,
    pub not_before_epoch_s: u64,
    pub not_after_epoch_s: u64,
    pub revoked_at_epoch_s: Option<u64>,
    pub revocation_reason_digest: Option<String>,
    pub record_digest: String,
}

impl DeploymentEvidenceKeyRecord {
    pub fn new_active(
        key_id: impl Into<String>,
        public_key: [u8; 32],
        not_before_epoch_s: u64,
        not_after_epoch_s: u64,
    ) -> Result<Self, DeploymentEvidenceError> {
        let mut record = Self {
            schema_version: DEPLOYMENT_EVIDENCE_KEY_SCHEMA.to_owned(),
            key_id: key_id.into(),
            public_key_base64url: URL_SAFE_NO_PAD.encode(public_key),
            public_key_digest: lowercase_sha256(&public_key),
            status: DeploymentEvidenceKeyStatus::Active,
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

    pub fn validate_seal(&self) -> Result<(), DeploymentEvidenceError> {
        if self.schema_version != DEPLOYMENT_EVIDENCE_KEY_SCHEMA {
            return Err(DeploymentEvidenceError::UnsupportedKeySchema);
        }
        validate_identifier("deployment_evidence_key_id", &self.key_id)?;
        validate_sha256(&self.public_key_digest)?;
        if self.not_before_epoch_s >= self.not_after_epoch_s {
            return Err(DeploymentEvidenceError::InvalidKeyValidity);
        }
        let public_key = decode_fixed::<32>(&self.public_key_base64url)
            .map_err(|_| DeploymentEvidenceError::InvalidPublicKey)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| DeploymentEvidenceError::InvalidPublicKey)?;
        if lowercase_sha256(&public_key) != self.public_key_digest {
            return Err(DeploymentEvidenceError::PublicKeyDigestMismatch);
        }
        match self.status {
            DeploymentEvidenceKeyStatus::Active => {
                if self.revoked_at_epoch_s.is_some() || self.revocation_reason_digest.is_some() {
                    return Err(DeploymentEvidenceError::InvalidKeyState);
                }
            }
            DeploymentEvidenceKeyStatus::Revoked => {
                if self.revoked_at_epoch_s.is_none() || self.revocation_reason_digest.is_none() {
                    return Err(DeploymentEvidenceError::InvalidKeyState);
                }
                validate_sha256(
                    self.revocation_reason_digest
                        .as_deref()
                        .ok_or(DeploymentEvidenceError::InvalidKeyState)?,
                )?;
            }
        }
        validate_sha256(&self.record_digest)?;
        if self.record_digest != self.expected_digest()? {
            return Err(DeploymentEvidenceError::KeyRecordDigestMismatch);
        }
        Ok(())
    }

    fn valid_for_signature_at(&self, signed_at_epoch_s: u64) -> Result<(), DeploymentEvidenceError> {
        self.validate_seal()?;
        if self.status != DeploymentEvidenceKeyStatus::Active {
            return Err(DeploymentEvidenceError::KeyRevoked);
        }
        if signed_at_epoch_s < self.not_before_epoch_s {
            return Err(DeploymentEvidenceError::KeyNotYetValid);
        }
        if signed_at_epoch_s >= self.not_after_epoch_s {
            return Err(DeploymentEvidenceError::KeyExpired);
        }
        Ok(())
    }

    fn verifying_key(&self) -> Result<VerifyingKey, DeploymentEvidenceError> {
        let bytes = decode_fixed::<32>(&self.public_key_base64url)
            .map_err(|_| DeploymentEvidenceError::InvalidPublicKey)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| DeploymentEvidenceError::InvalidPublicKey)
    }

    fn expected_digest(&self) -> Result<String, DeploymentEvidenceError> {
        digest_with_blank_field(self, "record_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentEvidencePolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub revision: u64,
    pub signature_threshold: u16,
    pub keys: Vec<DeploymentEvidenceKeyRecord>,
    pub policy_digest: String,
}

impl DeploymentEvidencePolicy {
    pub fn new(
        revision: u64,
        signature_threshold: u16,
        mut keys: Vec<DeploymentEvidenceKeyRecord>,
    ) -> Result<Self, DeploymentEvidenceError> {
        keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        let mut policy = Self {
            schema_version: DEPLOYMENT_EVIDENCE_POLICY_SCHEMA.to_owned(),
            policy_id: DEPLOYMENT_EVIDENCE_POLICY_ID.to_owned(),
            revision,
            signature_threshold,
            keys,
            policy_digest: String::new(),
        };
        policy.policy_digest = policy.expected_digest()?;
        policy.validate_seal()?;
        Ok(policy)
    }

    pub fn validate_seal(&self) -> Result<(), DeploymentEvidenceError> {
        if self.schema_version != DEPLOYMENT_EVIDENCE_POLICY_SCHEMA
            || self.policy_id != DEPLOYMENT_EVIDENCE_POLICY_ID
            || self.revision == 0
            || self.signature_threshold == 0
            || usize::from(self.signature_threshold) > self.keys.len()
        {
            return Err(DeploymentEvidenceError::InvalidPolicy);
        }
        let mut key_ids = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for key in &self.keys {
            key.validate_seal()?;
            if previous.is_some_and(|candidate| candidate >= key.key_id.as_str()) {
                return Err(DeploymentEvidenceError::PolicyKeysNotCanonical);
            }
            previous = Some(&key.key_id);
            if !key_ids.insert(key.key_id.clone()) {
                return Err(DeploymentEvidenceError::DuplicateKey);
            }
            if !public_keys.insert(key.public_key_digest.clone()) {
                return Err(DeploymentEvidenceError::PublicKeyReuse);
            }
        }
        validate_sha256(&self.policy_digest)?;
        if self.policy_digest != self.expected_digest()? {
            return Err(DeploymentEvidenceError::PolicyDigestMismatch);
        }
        Ok(())
    }

    pub fn validate_cryptographic_separation(
        &self,
        trust_governance_policy: &TrustGovernancePolicy,
        accepted: &VerifiedProductionTrustState,
    ) -> Result<(), DeploymentEvidenceError> {
        self.validate_seal()?;
        trust_governance_policy.validate_seal()?;
        let evidence_digests: BTreeSet<&str> = self
            .keys
            .iter()
            .map(|record| record.public_key_digest.as_str())
            .collect();
        if trust_governance_policy
            .keys
            .iter()
            .any(|record| evidence_digests.contains(record.public_key_digest.as_str()))
            || accepted
                .body()
                .registry
                .records
                .iter()
                .any(|record| evidence_digests.contains(record.public_key_digest.as_str()))
        {
            return Err(DeploymentEvidenceError::AuthorityKeyReuse);
        }
        Ok(())
    }

    fn verify_signatures(
        &self,
        domain: &[u8],
        digest: &str,
        signed_at_epoch_s: u64,
        signatures: &[DeploymentEvidenceSignature],
    ) -> Result<(), DeploymentEvidenceError> {
        self.validate_seal()?;
        validate_sha256(digest)?;
        if signatures.is_empty() {
            return Err(DeploymentEvidenceError::SignaturesMissing);
        }
        let records: BTreeMap<&str, &DeploymentEvidenceKeyRecord> = self
            .keys
            .iter()
            .map(|record| (record.key_id.as_str(), record))
            .collect();
        let message = signature_message(domain, digest)?;
        let mut verified_ids = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for evidence_signature in signatures {
            evidence_signature.validate_shape()?;
            if previous.is_some_and(|candidate| candidate >= evidence_signature.key_id.as_str()) {
                return Err(DeploymentEvidenceError::SignaturesNotCanonical);
            }
            previous = Some(&evidence_signature.key_id);
            if evidence_signature.signed_digest != digest {
                return Err(DeploymentEvidenceError::SignatureDigestMismatch);
            }
            if !verified_ids.insert(evidence_signature.key_id.clone()) {
                return Err(DeploymentEvidenceError::DuplicateSignature);
            }
            let record = records
                .get(evidence_signature.key_id.as_str())
                .ok_or(DeploymentEvidenceError::UnknownKey)?;
            record.valid_for_signature_at(signed_at_epoch_s)?;
            let signature_bytes = decode_fixed::<64>(&evidence_signature.signature_base64url)
                .map_err(|_| DeploymentEvidenceError::InvalidSignature)?;
            let signature = Signature::from_slice(&signature_bytes)
                .map_err(|_| DeploymentEvidenceError::InvalidSignature)?;
            record
                .verifying_key()?
                .verify(&message, &signature)
                .map_err(|_| DeploymentEvidenceError::SignatureVerificationFailed)?;
        }
        if verified_ids.len() < usize::from(self.signature_threshold) {
            return Err(DeploymentEvidenceError::ThresholdNotMet);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, DeploymentEvidenceError> {
        digest_with_blank_field(self, "policy_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentEvidenceSignature {
    pub schema_version: String,
    pub key_id: String,
    pub algorithm: String,
    pub signed_digest: String,
    pub signature_base64url: String,
}

impl DeploymentEvidenceSignature {
    pub fn from_signature_bytes(
        key_id: impl Into<String>,
        signed_digest: impl Into<String>,
        signature: [u8; 64],
    ) -> Result<Self, DeploymentEvidenceError> {
        let value = Self {
            schema_version: DEPLOYMENT_EVIDENCE_SIGNATURE_SCHEMA.to_owned(),
            key_id: key_id.into(),
            algorithm: DEPLOYMENT_EVIDENCE_ALGORITHM.to_owned(),
            signed_digest: signed_digest.into(),
            signature_base64url: URL_SAFE_NO_PAD.encode(signature),
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_shape(&self) -> Result<(), DeploymentEvidenceError> {
        if self.schema_version != DEPLOYMENT_EVIDENCE_SIGNATURE_SCHEMA
            || self.algorithm != DEPLOYMENT_EVIDENCE_ALGORITHM
        {
            return Err(DeploymentEvidenceError::InvalidSignatureShape);
        }
        validate_identifier("deployment_evidence_key_id", &self.key_id)?;
        validate_sha256(&self.signed_digest)?;
        decode_fixed::<64>(&self.signature_base64url)
            .map_err(|_| DeploymentEvidenceError::InvalidSignature)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedProductionSignerInstallationEvidence {
    pub schema_version: String,
    pub receipt: ProductionSignerInstallationValidationReceipt,
    pub evidence_policy_digest: String,
    pub signed_at_epoch_s: u64,
    pub signatures: Vec<DeploymentEvidenceSignature>,
    pub envelope_digest: String,
}

impl SignedProductionSignerInstallationEvidence {
    pub fn new(
        receipt: ProductionSignerInstallationValidationReceipt,
        policy: &DeploymentEvidencePolicy,
        signed_at_epoch_s: u64,
        mut signatures: Vec<DeploymentEvidenceSignature>,
    ) -> Result<Self, DeploymentEvidenceError> {
        receipt.validate_seal()?;
        policy.validate_seal()?;
        signatures.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        let mut envelope = Self {
            schema_version: SIGNED_INSTALLATION_EVIDENCE_SCHEMA.to_owned(),
            receipt,
            evidence_policy_digest: policy.policy_digest.clone(),
            signed_at_epoch_s,
            signatures,
            envelope_digest: String::new(),
        };
        envelope.envelope_digest = envelope.expected_digest()?;
        Ok(envelope)
    }

    pub fn verify(
        &self,
        policy: &DeploymentEvidencePolicy,
        trust_governance_policy: &TrustGovernancePolicy,
        accepted: &VerifiedProductionTrustState,
        trusted_now_epoch_s: u64,
    ) -> Result<&ProductionSignerInstallationValidationReceipt, DeploymentEvidenceError> {
        if self.schema_version != SIGNED_INSTALLATION_EVIDENCE_SCHEMA
            || self.signed_at_epoch_s == 0
            || self.signed_at_epoch_s < self.receipt.observed_at_epoch_s
            || trusted_now_epoch_s < self.signed_at_epoch_s
        {
            return Err(DeploymentEvidenceError::InvalidInstallationEnvelope);
        }
        self.receipt.validate_seal()?;
        policy.validate_cryptographic_separation(trust_governance_policy, accepted)?;
        if self.evidence_policy_digest != policy.policy_digest
            || self.receipt.trust_state_binding != *accepted.binding()
        {
            return Err(DeploymentEvidenceError::EvidenceTrustMismatch);
        }
        policy.verify_signatures(
            INSTALLATION_SIGNATURE_DOMAIN,
            &self.receipt.receipt_digest,
            self.signed_at_epoch_s,
            &self.signatures,
        )?;
        validate_sha256(&self.envelope_digest)?;
        if self.envelope_digest != self.expected_digest()? {
            return Err(DeploymentEvidenceError::EnvelopeDigestMismatch);
        }
        Ok(&self.receipt)
    }

    fn expected_digest(&self) -> Result<String, DeploymentEvidenceError> {
        digest_with_blank_field(self, "envelope_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedProductionSignerRecoveryEvidence {
    pub schema_version: String,
    pub receipt: ProductionSignerRecoveryExerciseReceipt,
    pub evidence_policy_digest: String,
    pub signed_at_epoch_s: u64,
    pub signatures: Vec<DeploymentEvidenceSignature>,
    pub envelope_digest: String,
}

impl SignedProductionSignerRecoveryEvidence {
    pub fn new(
        receipt: ProductionSignerRecoveryExerciseReceipt,
        policy: &DeploymentEvidencePolicy,
        signed_at_epoch_s: u64,
        mut signatures: Vec<DeploymentEvidenceSignature>,
    ) -> Result<Self, DeploymentEvidenceError> {
        receipt.validate_seal()?;
        policy.validate_seal()?;
        signatures.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        let mut envelope = Self {
            schema_version: SIGNED_RECOVERY_EVIDENCE_SCHEMA.to_owned(),
            receipt,
            evidence_policy_digest: policy.policy_digest.clone(),
            signed_at_epoch_s,
            signatures,
            envelope_digest: String::new(),
        };
        envelope.envelope_digest = envelope.expected_digest()?;
        Ok(envelope)
    }

    pub fn verify(
        &self,
        policy: &DeploymentEvidencePolicy,
        trust_governance_policy: &TrustGovernancePolicy,
        accepted: &VerifiedProductionTrustState,
        trusted_now_epoch_s: u64,
    ) -> Result<&ProductionSignerRecoveryExerciseReceipt, DeploymentEvidenceError> {
        if self.schema_version != SIGNED_RECOVERY_EVIDENCE_SCHEMA
            || self.signed_at_epoch_s == 0
            || self.signed_at_epoch_s < self.receipt.completed_at_epoch_s
            || trusted_now_epoch_s < self.signed_at_epoch_s
        {
            return Err(DeploymentEvidenceError::InvalidRecoveryEnvelope);
        }
        self.receipt.validate_seal()?;
        policy.validate_cryptographic_separation(trust_governance_policy, accepted)?;
        if self.evidence_policy_digest != policy.policy_digest
            || self.receipt.after.trust_state_binding != *accepted.binding()
        {
            return Err(DeploymentEvidenceError::EvidenceTrustMismatch);
        }
        policy.verify_signatures(
            RECOVERY_SIGNATURE_DOMAIN,
            &self.receipt.receipt_digest,
            self.signed_at_epoch_s,
            &self.signatures,
        )?;
        validate_sha256(&self.envelope_digest)?;
        if self.envelope_digest != self.expected_digest()? {
            return Err(DeploymentEvidenceError::EnvelopeDigestMismatch);
        }
        Ok(&self.receipt)
    }

    fn expected_digest(&self) -> Result<String, DeploymentEvidenceError> {
        digest_with_blank_field(self, "envelope_digest")
    }
}

pub fn installation_evidence_signature_message(
    receipt_digest: &str,
) -> Result<Vec<u8>, DeploymentEvidenceError> {
    signature_message(INSTALLATION_SIGNATURE_DOMAIN, receipt_digest)
}

pub fn recovery_evidence_signature_message(
    receipt_digest: &str,
) -> Result<Vec<u8>, DeploymentEvidenceError> {
    signature_message(RECOVERY_SIGNATURE_DOMAIN, receipt_digest)
}

fn signature_message(domain: &[u8], digest: &str) -> Result<Vec<u8>, DeploymentEvidenceError> {
    validate_sha256(digest)?;
    let digest_bytes = decode_hex_sha256(digest)?;
    let mut message = Vec::with_capacity(domain.len() + 1 + digest_bytes.len());
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(&digest_bytes);
    Ok(message)
}

fn digest_with_blank_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, DeploymentEvidenceError> {
    let mut value = serde_json::to_value(value)?;
    let object = value
        .as_object_mut()
        .ok_or(DeploymentEvidenceError::InvalidCanonicalObject)?;
    object.insert(field.to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

fn decode_hex_sha256(value: &str) -> Result<[u8; 32], DeploymentEvidenceError> {
    validate_sha256(value)?;
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = nibble(chunk[0])? << 4 | nibble(chunk[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, DeploymentEvidenceError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(DeploymentEvidenceError::InvalidDigestEncoding),
    }
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], base64::DecodeError> {
    let bytes = URL_SAFE_NO_PAD.decode(value)?;
    bytes
        .try_into()
        .map_err(|_| base64::DecodeError::InvalidLength(bytes.len()))
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

#[derive(Debug, Error)]
pub enum DeploymentEvidenceError {
    #[error("deployment-evidence key schema is unsupported")]
    UnsupportedKeySchema,
    #[error("deployment-evidence key validity window is invalid")]
    InvalidKeyValidity,
    #[error("deployment-evidence public key is invalid")]
    InvalidPublicKey,
    #[error("deployment-evidence public-key digest does not match")]
    PublicKeyDigestMismatch,
    #[error("deployment-evidence key state is invalid")]
    InvalidKeyState,
    #[error("deployment-evidence key record digest does not match")]
    KeyRecordDigestMismatch,
    #[error("deployment-evidence key is revoked")]
    KeyRevoked,
    #[error("deployment-evidence key is not yet valid")]
    KeyNotYetValid,
    #[error("deployment-evidence key is expired")]
    KeyExpired,
    #[error("deployment-evidence policy is invalid")]
    InvalidPolicy,
    #[error("deployment-evidence policy keys are not canonical")]
    PolicyKeysNotCanonical,
    #[error("deployment-evidence policy has a duplicate key")]
    DuplicateKey,
    #[error("deployment-evidence policy reuses a public key")]
    PublicKeyReuse,
    #[error("deployment-evidence policy digest does not match")]
    PolicyDigestMismatch,
    #[error("deployment-evidence authority reuses an issuer or trust-governance key")]
    AuthorityKeyReuse,
    #[error("deployment-evidence signatures are missing")]
    SignaturesMissing,
    #[error("deployment-evidence signatures are not canonical")]
    SignaturesNotCanonical,
    #[error("deployment-evidence signature digest does not match")]
    SignatureDigestMismatch,
    #[error("deployment-evidence signature is duplicated")]
    DuplicateSignature,
    #[error("deployment-evidence signature references an unknown key")]
    UnknownKey,
    #[error("deployment-evidence signature is invalid")]
    InvalidSignature,
    #[error("deployment-evidence signature verification failed")]
    SignatureVerificationFailed,
    #[error("deployment-evidence signature threshold was not met")]
    ThresholdNotMet,
    #[error("deployment-evidence signature shape is invalid")]
    InvalidSignatureShape,
    #[error("signed installation evidence envelope is invalid")]
    InvalidInstallationEnvelope,
    #[error("signed recovery evidence envelope is invalid")]
    InvalidRecoveryEnvelope,
    #[error("signed deployment evidence does not match accepted trust")]
    EvidenceTrustMismatch,
    #[error("signed deployment evidence envelope digest does not match")]
    EnvelopeDigestMismatch,
    #[error("deployment-evidence canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("deployment-evidence digest encoding is invalid")]
    InvalidDigestEncoding,
    #[error(transparent)]
    Installation(#[from] InstallationEvidenceError),
    #[error(transparent)]
    ProductionSigner(#[from] ProductionSignerError),
    #[error(transparent)]
    TrustState(#[from] ProductionTrustStateError),
    #[error("deployment-evidence JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}
