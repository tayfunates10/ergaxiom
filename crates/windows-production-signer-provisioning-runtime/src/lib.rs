#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod windows;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_cng_key_provider_runtime::{
    CngKeyPossessionSignature, CngPlatformKeyProvider, CngProviderError, CngProvisioningResult,
};
use ergaxiom_windows_production_signer_runtime::{
    ECDSA_P256_SHA256, HardwareAssurance, MICROSOFT_PLATFORM_CRYPTO_PROVIDER,
    NON_EXPORTABLE_POLICY, P1363_FIXED_64, PROVISIONING_RECEIPT_SCHEMA, ProductionKeyIdentity,
    ProductionKeyPolicy, ProductionSignerError, ProvisioningReceipt, SEC1_UNCOMPRESSED_P256,
    validate_sha256,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROVISIONING_EVIDENCE_SCHEMA: &str = "0.1.0";
pub const PROVISIONING_STATEMENT_SCHEMA: &str = "0.1.0";
pub const PROVISIONING_DOMAIN: &str = "ergaxiom.windows-production-signer.provisioning.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningStatement {
    pub schema_version: String,
    pub domain: String,
    pub identity: ProductionKeyIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    pub receipt_digest: String,
    pub key_name_digest: String,
    pub public_key_digest: String,
    pub policy_digest: String,
    pub created: bool,
}

impl ProvisioningStatement {
    pub fn validate_for(
        &self,
        policy: &ProductionKeyPolicy,
        receipt: &ProvisioningReceipt,
    ) -> Result<(), ProvisioningError> {
        if self.schema_version != PROVISIONING_STATEMENT_SCHEMA
            || self.domain != PROVISIONING_DOMAIN
        {
            return Err(ProvisioningError::InvalidProvisioningDomain);
        }
        policy.validate()?;
        self.identity.validate()?;
        if self.identity != policy.identity || self.identity != receipt.identity {
            return Err(ProvisioningError::IdentityBindingMismatch);
        }
        validate_sha256(&self.receipt_digest)?;
        validate_sha256(&self.key_name_digest)?;
        validate_sha256(&self.public_key_digest)?;
        validate_sha256(&self.policy_digest)?;
        if self.receipt_digest != receipt.receipt_digest
            || self.public_key_digest != receipt.public_key_digest
            || self.policy_digest != receipt.policy_digest
        {
            return Err(ProvisioningError::StatementReceiptBindingMismatch);
        }
        let generation = self.generation.unwrap_or(1);
        if generation == 0 {
            return Err(ProvisioningError::InvalidKeyGeneration);
        }
        let key_name = CngPlatformKeyProvider::key_name_for_generation(policy, generation)?;
        if self.key_name_digest != lowercase_sha256(key_name.as_bytes()) {
            return Err(ProvisioningError::KeyNameDigestMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ProvisioningError> {
        let value = serde_json::to_value(self)?;
        Ok(canonical_json_sha256(&value)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPossessionSignature {
    pub digest_algorithm: String,
    pub digest: String,
    pub signature_encoding: String,
    pub signature_base64url: String,
    pub public_key_digest: String,
    pub key_policy_digest: String,
}

impl From<CngKeyPossessionSignature> for KeyPossessionSignature {
    fn from(value: CngKeyPossessionSignature) -> Self {
        Self {
            digest_algorithm: value.digest_algorithm,
            digest: value.digest,
            signature_encoding: value.signature_encoding,
            signature_base64url: value.signature_base64url,
            public_key_digest: value.public_key_digest,
            key_policy_digest: value.key_policy_digest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningEvidence {
    pub schema_version: String,
    pub statement: ProvisioningStatement,
    pub receipt: ProvisioningReceipt,
    pub key_possession: KeyPossessionSignature,
    pub evidence_digest: String,
}

impl ProvisioningEvidence {
    pub fn verify_contract(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<VerifiedProvisioningEvidence, ProvisioningError> {
        policy.validate()?;
        if self.schema_version != PROVISIONING_EVIDENCE_SCHEMA {
            return Err(ProvisioningError::UnsupportedEvidenceSchema);
        }
        validate_receipt_contract(&self.receipt, policy)?;
        self.statement.validate_for(policy, &self.receipt)?;
        validate_possession_signature(&self.key_possession, &self.statement, &self.receipt)?;
        validate_sha256(&self.evidence_digest)?;
        if self.evidence_digest != self.expected_digest()? {
            return Err(ProvisioningError::EvidenceDigestMismatch);
        }
        if contains_secret_shaped_field(&serde_json::to_value(self)?) {
            return Err(ProvisioningError::SecretShapedProvisioningMaterial);
        }
        Ok(VerifiedProvisioningEvidence {
            identity: self.receipt.identity.clone(),
            generation: self.statement.generation.unwrap_or(1),
            public_key_digest: self.receipt.public_key_digest.clone(),
            policy_digest: self.receipt.policy_digest.clone(),
            receipt_digest: self.receipt.receipt_digest.clone(),
            evidence_digest: self.evidence_digest.clone(),
            assurance: self.receipt.assurance,
            created: self.statement.created,
        })
    }

    pub fn verify_production_eligible(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<VerifiedProvisioningEvidence, ProvisioningError> {
        let verified = self.verify_contract(policy)?;
        self.receipt.validate_for(policy)?;
        Ok(verified)
    }

    fn expected_digest(&self) -> Result<String, ProvisioningError> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(ProvisioningError::InvalidCanonicalObject)?;
        object.insert("evidence_digest".to_owned(), Value::String(String::new()));
        Ok(canonical_json_sha256(&value)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProvisioningEvidence {
    pub identity: ProductionKeyIdentity,
    pub generation: u64,
    pub public_key_digest: String,
    pub policy_digest: String,
    pub receipt_digest: String,
    pub evidence_digest: String,
    pub assurance: HardwareAssurance,
    pub created: bool,
}

pub trait ProvisioningBackend {
    fn provision(
        &self,
        policy: &ProductionKeyPolicy,
        expected_public_key_digest: Option<&str>,
    ) -> Result<CngProvisioningResult, ProvisioningError>;

    fn provision_generation(
        &self,
        policy: &ProductionKeyPolicy,
        generation: u64,
        expected_public_key_digest: Option<&str>,
    ) -> Result<CngProvisioningResult, ProvisioningError> {
        if generation == 1 {
            self.provision(policy, expected_public_key_digest)
        } else {
            Err(ProvisioningError::UnsupportedKeyGeneration(generation))
        }
    }

    fn sign_key_possession(
        &self,
        policy: &ProductionKeyPolicy,
        provisioning: &CngProvisioningResult,
        digest: &str,
    ) -> Result<KeyPossessionSignature, ProvisioningError>;
}

impl ProvisioningBackend for CngPlatformKeyProvider {
    fn provision(
        &self,
        policy: &ProductionKeyPolicy,
        expected_public_key_digest: Option<&str>,
    ) -> Result<CngProvisioningResult, ProvisioningError> {
        Ok(self.provision_unverified(policy, expected_public_key_digest)?)
    }

    fn provision_generation(
        &self,
        policy: &ProductionKeyPolicy,
        generation: u64,
        expected_public_key_digest: Option<&str>,
    ) -> Result<CngProvisioningResult, ProvisioningError> {
        Ok(self.provision_generation_unverified(policy, generation, expected_public_key_digest)?)
    }

    fn sign_key_possession(
        &self,
        policy: &ProductionKeyPolicy,
        provisioning: &CngProvisioningResult,
        digest: &str,
    ) -> Result<KeyPossessionSignature, ProvisioningError> {
        Ok(self
            .sign_key_possession_sha256_digest_unverified(policy, provisioning, digest)?
            .into())
    }
}

#[derive(Debug, Clone)]
pub struct ProvisioningAuthority<B> {
    backend: B,
}

impl<B> ProvisioningAuthority<B>
where
    B: ProvisioningBackend,
{
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn provision(
        &self,
        policy: &ProductionKeyPolicy,
        expected_public_key_digest: Option<&str>,
        provisioned_at_epoch_s: u64,
    ) -> Result<ProvisioningEvidence, ProvisioningError> {
        self.provision_generation(
            policy,
            1,
            expected_public_key_digest,
            provisioned_at_epoch_s,
        )
    }

    pub fn provision_generation(
        &self,
        policy: &ProductionKeyPolicy,
        generation: u64,
        expected_public_key_digest: Option<&str>,
        provisioned_at_epoch_s: u64,
    ) -> Result<ProvisioningEvidence, ProvisioningError> {
        policy.validate()?;
        if generation == 0 {
            return Err(ProvisioningError::InvalidKeyGeneration);
        }
        if provisioned_at_epoch_s == 0 {
            return Err(ProvisioningError::InvalidProvisioningTime);
        }
        let provisioning =
            self.backend
                .provision_generation(policy, generation, expected_public_key_digest)?;
        validate_descriptor_contract(&provisioning, policy)?;
        let receipt = ProvisioningReceipt::from_descriptor(
            provisioning.descriptor.clone(),
            provisioned_at_epoch_s,
        )?;
        let key_name_digest = lowercase_sha256(provisioning.key_name.as_bytes());
        let statement = ProvisioningStatement {
            schema_version: PROVISIONING_STATEMENT_SCHEMA.to_owned(),
            domain: PROVISIONING_DOMAIN.to_owned(),
            identity: policy.identity.clone(),
            generation: Some(generation),
            receipt_digest: receipt.receipt_digest.clone(),
            key_name_digest,
            public_key_digest: receipt.public_key_digest.clone(),
            policy_digest: receipt.policy_digest.clone(),
            created: provisioning.created,
        };
        statement.validate_for(policy, &receipt)?;
        let statement_digest = statement.digest()?;
        let key_possession =
            self.backend
                .sign_key_possession(policy, &provisioning, &statement_digest)?;
        let mut evidence = ProvisioningEvidence {
            schema_version: PROVISIONING_EVIDENCE_SCHEMA.to_owned(),
            statement,
            receipt,
            key_possession,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.expected_digest()?;
        evidence.verify_contract(policy)?;
        Ok(evidence)
    }
}

pub fn require_elevated_administrator() -> Result<(), ProvisioningError> {
    platform::require_elevated_administrator()
}

fn validate_descriptor_contract(
    provisioning: &CngProvisioningResult,
    policy: &ProductionKeyPolicy,
) -> Result<(), ProvisioningError> {
    let descriptor = &provisioning.descriptor;
    descriptor.identity.validate()?;
    if descriptor.identity != policy.identity {
        return Err(ProvisioningError::IdentityBindingMismatch);
    }
    if descriptor.provider != MICROSOFT_PLATFORM_CRYPTO_PROVIDER
        || descriptor.algorithm != ECDSA_P256_SHA256
        || descriptor.public_key_encoding != SEC1_UNCOMPRESSED_P256
        || descriptor.signature_encoding != P1363_FIXED_64
        || descriptor.export_policy != NON_EXPORTABLE_POLICY
    {
        return Err(ProvisioningError::DescriptorContractMismatch);
    }
    validate_sha256(&descriptor.public_key_digest)?;
    validate_sha256(&descriptor.policy_digest)?;
    if descriptor.policy_digest != policy.digest()? {
        return Err(ProvisioningError::PolicyDigestMismatch);
    }
    if descriptor.assurance == HardwareAssurance::Rejected {
        return Err(ProvisioningError::RejectedHardwareAssurance);
    }
    let public_key = decode_public_key(&descriptor.public_key_base64url)?;
    if lowercase_sha256(&public_key) != descriptor.public_key_digest {
        return Err(ProvisioningError::PublicKeyDigestMismatch);
    }
    Ok(())
}

fn validate_receipt_contract(
    receipt: &ProvisioningReceipt,
    policy: &ProductionKeyPolicy,
) -> Result<(), ProvisioningError> {
    if receipt.schema_version != PROVISIONING_RECEIPT_SCHEMA {
        return Err(ProvisioningError::UnsupportedReceiptSchema);
    }
    let provisioning = CngProvisioningResult {
        key_name: CngPlatformKeyProvider::key_name_for(policy)?,
        created: false,
        descriptor: ergaxiom_windows_production_signer_runtime::HardwareKeyDescriptor {
            identity: receipt.identity.clone(),
            provider: receipt.provider.clone(),
            algorithm: receipt.algorithm.clone(),
            public_key_encoding: receipt.public_key_encoding.clone(),
            public_key_base64url: receipt.public_key_base64url.clone(),
            public_key_digest: receipt.public_key_digest.clone(),
            signature_encoding: receipt.signature_encoding.clone(),
            export_policy: receipt.export_policy.clone(),
            provider_implementation_flags: receipt.provider_implementation_flags,
            assurance: receipt.assurance,
            policy_digest: receipt.policy_digest.clone(),
        },
    };
    validate_descriptor_contract(&provisioning, policy)?;
    if receipt.provisioned_at_epoch_s == 0 {
        return Err(ProvisioningError::InvalidProvisioningTime);
    }
    validate_sha256(&receipt.receipt_digest)?;
    if receipt.receipt_digest != expected_receipt_digest(receipt)? {
        return Err(ProvisioningError::ReceiptDigestMismatch);
    }
    if contains_secret_shaped_field(&serde_json::to_value(receipt)?) {
        return Err(ProvisioningError::SecretShapedProvisioningMaterial);
    }
    Ok(())
}

fn expected_receipt_digest(receipt: &ProvisioningReceipt) -> Result<String, ProvisioningError> {
    let mut value = serde_json::to_value(receipt)?;
    let object = value
        .as_object_mut()
        .ok_or(ProvisioningError::InvalidCanonicalObject)?;
    object.insert("receipt_digest".to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

fn validate_possession_signature(
    possession: &KeyPossessionSignature,
    statement: &ProvisioningStatement,
    receipt: &ProvisioningReceipt,
) -> Result<(), ProvisioningError> {
    if possession.digest_algorithm != "sha256" || possession.signature_encoding != P1363_FIXED_64 {
        return Err(ProvisioningError::SignatureMetadataMismatch);
    }
    validate_sha256(&possession.digest)?;
    validate_sha256(&possession.public_key_digest)?;
    validate_sha256(&possession.key_policy_digest)?;
    if possession.digest != statement.digest()?
        || possession.public_key_digest != receipt.public_key_digest
        || possession.key_policy_digest != receipt.policy_digest
    {
        return Err(ProvisioningError::SignatureBindingMismatch);
    }
    let public_key = decode_public_key(&receipt.public_key_base64url)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)
        .map_err(|_| ProvisioningError::InvalidPublicKeyEncoding)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&possession.signature_base64url)
        .map_err(|_| ProvisioningError::InvalidSignatureEncoding)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| ProvisioningError::InvalidSignatureEncoding)?;
    let digest = decode_sha256(&possession.digest)?;
    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|_| ProvisioningError::KeyPossessionVerificationFailed)
}

fn decode_public_key(value: &str) -> Result<Vec<u8>, ProvisioningError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ProvisioningError::InvalidPublicKeyEncoding)?;
    if bytes.len() != 65 || bytes.first() != Some(&0x04) {
        return Err(ProvisioningError::InvalidPublicKeyEncoding);
    }
    Ok(bytes)
}

fn decode_sha256(value: &str) -> Result<[u8; 32], ProvisioningError> {
    validate_sha256(value)?;
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(chunk[0])? << 4) | decode_nibble(chunk[1])?;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Result<u8, ProvisioningError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ProvisioningError::InvalidDigestEncoding),
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
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "private_key"
                    | "private_seed"
                    | "seed"
                    | "secret"
                    | "protected_seed"
                    | "key_material"
            ) || contains_secret_shaped_field(value)
        }),
        Value::Array(values) => values.iter().any(contains_secret_shaped_field),
        _ => false,
    }
}

#[cfg(windows)]
mod platform {
    pub use crate::windows::require_elevated_administrator;
}

#[cfg(not(windows))]
mod platform {
    use crate::ProvisioningError;

    pub fn require_elevated_administrator() -> Result<(), ProvisioningError> {
        Err(ProvisioningError::UnsupportedPlatform)
    }
}

#[derive(Debug, Error)]
pub enum ProvisioningError {
    #[error("production signer provisioning is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("production signer provisioning requires an elevated administrator token")]
    ElevatedAdministratorRequired,
    #[error("production signer administrator token could not be opened: {0}")]
    AdministratorTokenOpenFailed(#[source] std::io::Error),
    #[error("production signer token elevation could not be read: {0}")]
    TokenElevationReadFailed(#[source] std::io::Error),
    #[error("production signer provisioning evidence schema is unsupported")]
    UnsupportedEvidenceSchema,
    #[error("production signer provisioning receipt schema is unsupported")]
    UnsupportedReceiptSchema,
    #[error("production signer provisioning domain is invalid")]
    InvalidProvisioningDomain,
    #[error("production signer key generation must be greater than zero")]
    InvalidKeyGeneration,
    #[error("provisioning backend does not support key generation {0}")]
    UnsupportedKeyGeneration(u64),
    #[error("production signer provisioning identity binding does not match")]
    IdentityBindingMismatch,
    #[error("production signer descriptor contract does not match")]
    DescriptorContractMismatch,
    #[error("production signer policy digest does not match")]
    PolicyDigestMismatch,
    #[error("production signer hardware assurance was rejected")]
    RejectedHardwareAssurance,
    #[error("production signer public key encoding is invalid")]
    InvalidPublicKeyEncoding,
    #[error("production signer public-key digest does not match")]
    PublicKeyDigestMismatch,
    #[error("production signer provisioning time is invalid")]
    InvalidProvisioningTime,
    #[error("production signer provisioning receipt digest does not match")]
    ReceiptDigestMismatch,
    #[error("production signer provisioning statement does not match the receipt")]
    StatementReceiptBindingMismatch,
    #[error("production signer persisted-key name digest does not match")]
    KeyNameDigestMismatch,
    #[error("production signer key-possession signature metadata does not match")]
    SignatureMetadataMismatch,
    #[error("production signer key-possession signature binding does not match")]
    SignatureBindingMismatch,
    #[error("production signer key-possession signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("production signer key-possession verification failed")]
    KeyPossessionVerificationFailed,
    #[error("production signer provisioning evidence digest does not match")]
    EvidenceDigestMismatch,
    #[error("production signer provisioning material contains secret-shaped fields")]
    SecretShapedProvisioningMaterial,
    #[error("production signer canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("production signer digest encoding is invalid")]
    InvalidDigestEncoding,
    #[error("production signer provisioning JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Cng(#[from] CngProviderError),
    #[error(transparent)]
    Production(#[from] ProductionSignerError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}
