use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ergaxiom_proof_kernel::{canonical_json_bytes, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::BrandExportExecutionRecord;
use crate::util::{BrandDigestError, canonical_record_digest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BrandEvidenceSignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BrandEvidenceSignatureEncoding {
    Base64url,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandEvidenceSignature {
    pub issuer_id: String,
    pub key_id: String,
    pub algorithm: BrandEvidenceSignatureAlgorithm,
    pub encoding: BrandEvidenceSignatureEncoding,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBrandExportExecutionRecord {
    pub record: BrandExportExecutionRecord,
    pub signature: BrandEvidenceSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedBrandExportExecutionEvidence {
    pub package_digest: String,
    pub record_digest: String,
    pub issuer_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct BrandEvidenceKeyRegistry {
    keys: BTreeMap<(String, String), VerifyingKey>,
}

impl BrandEvidenceKeyRegistry {
    pub fn insert_ed25519(
        &mut self,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<(), BrandEvidenceSignatureError> {
        let issuer_id = issuer_id.into();
        let key_id = key_id.into();
        validate_identity("issuer_id", &issuer_id)?;
        validate_identity("key_id", &key_id)?;
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| BrandEvidenceSignatureError::InvalidTrustedKey)?;
        self.keys.insert((issuer_id, key_id), key);
        Ok(())
    }

    fn get(&self, issuer_id: &str, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(&(issuer_id.to_owned(), key_id.to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum BrandEvidenceSignatureError {
    #[error("required brand evidence signature field is empty: {0}")]
    EmptyField(&'static str),
    #[error("brand evidence trusted key is invalid")]
    InvalidTrustedKey,
    #[error("unknown brand evidence key {issuer_id}/{key_id}")]
    UnknownTrustedKey { issuer_id: String, key_id: String },
    #[error("brand evidence signature metadata is unsupported")]
    UnsupportedSignatureMetadata,
    #[error("brand evidence signature is not valid base64url")]
    InvalidSignatureEncoding,
    #[error("brand evidence signature has an invalid Ed25519 length")]
    InvalidSignatureLength,
    #[error("brand evidence signature verification failed")]
    SignatureVerificationFailed,
    #[error("brand export execution record is not verified and source-immutable")]
    ExecutionRecordNotVerified,
    #[error("brand export execution record digest does not reproduce")]
    ExecutionRecordDigestMismatch,
    #[error("failed to serialize signed brand evidence: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Digest(#[from] BrandDigestError),
    #[error(transparent)]
    Hashing(#[from] ergaxiom_proof_kernel::HashingError),
}

pub fn sign_brand_export_execution_record(
    record: &BrandExportExecutionRecord,
    issuer_id: impl Into<String>,
    key_id: impl Into<String>,
    signing_key: &SigningKey,
) -> Result<SignedBrandExportExecutionRecord, BrandEvidenceSignatureError> {
    validate_execution_record(record)?;
    let issuer_id = issuer_id.into();
    let key_id = key_id.into();
    let signature = sign_value(record, issuer_id, key_id, signing_key)?;
    Ok(SignedBrandExportExecutionRecord {
        record: record.clone(),
        signature,
    })
}

pub fn verify_brand_export_execution_record(
    package: &SignedBrandExportExecutionRecord,
    trusted_keys: &BrandEvidenceKeyRegistry,
) -> Result<VerifiedBrandExportExecutionEvidence, BrandEvidenceSignatureError> {
    validate_execution_record(&package.record)?;
    verify_value(&package.record, &package.signature, trusted_keys)?;
    Ok(VerifiedBrandExportExecutionEvidence {
        package_digest: package_digest(package)?,
        record_digest: package.record.record_digest.clone(),
        issuer_id: package.signature.issuer_id.clone(),
        key_id: package.signature.key_id.clone(),
    })
}

fn validate_execution_record(
    record: &BrandExportExecutionRecord,
) -> Result<(), BrandEvidenceSignatureError> {
    if !record.verified || !record.source_immutable {
        return Err(BrandEvidenceSignatureError::ExecutionRecordNotVerified);
    }
    if record.record_digest != canonical_record_digest(record, "record_digest")? {
        return Err(BrandEvidenceSignatureError::ExecutionRecordDigestMismatch);
    }
    Ok(())
}

fn sign_value<T: Serialize>(
    value: &T,
    issuer_id: String,
    key_id: String,
    signing_key: &SigningKey,
) -> Result<BrandEvidenceSignature, BrandEvidenceSignatureError> {
    validate_identity("issuer_id", &issuer_id)?;
    validate_identity("key_id", &key_id)?;
    let value = serde_json::to_value(value)?;
    let signature = signing_key.sign(&canonical_json_bytes(&value)?);
    Ok(BrandEvidenceSignature {
        issuer_id,
        key_id,
        algorithm: BrandEvidenceSignatureAlgorithm::Ed25519,
        encoding: BrandEvidenceSignatureEncoding::Base64url,
        value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

fn verify_value<T: Serialize>(
    value: &T,
    signature: &BrandEvidenceSignature,
    trusted_keys: &BrandEvidenceKeyRegistry,
) -> Result<(), BrandEvidenceSignatureError> {
    if signature.algorithm != BrandEvidenceSignatureAlgorithm::Ed25519
        || signature.encoding != BrandEvidenceSignatureEncoding::Base64url
    {
        return Err(BrandEvidenceSignatureError::UnsupportedSignatureMetadata);
    }
    validate_identity("issuer_id", &signature.issuer_id)?;
    validate_identity("key_id", &signature.key_id)?;
    let key = trusted_keys
        .get(&signature.issuer_id, &signature.key_id)
        .ok_or_else(|| BrandEvidenceSignatureError::UnknownTrustedKey {
            issuer_id: signature.issuer_id.clone(),
            key_id: signature.key_id.clone(),
        })?;
    let decoded = URL_SAFE_NO_PAD
        .decode(signature.value.as_bytes())
        .map_err(|_| BrandEvidenceSignatureError::InvalidSignatureEncoding)?;
    let bytes: [u8; 64] = decoded
        .try_into()
        .map_err(|_| BrandEvidenceSignatureError::InvalidSignatureLength)?;
    let signature = Signature::from_bytes(&bytes);
    let value = serde_json::to_value(value)?;
    key.verify(&canonical_json_bytes(&value)?, &signature)
        .map_err(|_| BrandEvidenceSignatureError::SignatureVerificationFailed)
}

fn package_digest<T: Serialize>(value: &T) -> Result<String, BrandEvidenceSignatureError> {
    Ok(canonical_json_sha256(&serde_json::to_value(value)?)?)
}

fn validate_identity(field: &'static str, value: &str) -> Result<(), BrandEvidenceSignatureError> {
    if value.trim().is_empty() {
        Err(BrandEvidenceSignatureError::EmptyField(field))
    } else {
        Ok(())
    }
}
