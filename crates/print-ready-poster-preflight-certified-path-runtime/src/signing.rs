use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ergaxiom_proof_kernel::{canonical_json_bytes, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::PrintPreflightExecutionRecord;
use crate::util::{PrintDigestError, canonical_record_digest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrintEvidenceSignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrintEvidenceSignatureEncoding {
    Base64url,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintEvidenceSignature {
    pub issuer_id: String,
    pub key_id: String,
    pub algorithm: PrintEvidenceSignatureAlgorithm,
    pub encoding: PrintEvidenceSignatureEncoding,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPrintPreflightExecutionRecord {
    pub record: PrintPreflightExecutionRecord,
    pub signature: PrintEvidenceSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedPrintPreflightExecutionEvidence {
    pub package_digest: String,
    pub record_digest: String,
    pub issuer_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct PrintEvidenceKeyRegistry {
    keys: BTreeMap<(String, String), VerifyingKey>,
}

impl PrintEvidenceKeyRegistry {
    pub fn insert_ed25519(
        &mut self,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<(), PrintEvidenceSignatureError> {
        let issuer_id = issuer_id.into();
        let key_id = key_id.into();
        validate_identity("issuer_id", &issuer_id)?;
        validate_identity("key_id", &key_id)?;
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| PrintEvidenceSignatureError::InvalidTrustedKey)?;
        self.keys.insert((issuer_id, key_id), key);
        Ok(())
    }

    fn get(&self, issuer_id: &str, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(&(issuer_id.to_owned(), key_id.to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum PrintEvidenceSignatureError {
    #[error("required print evidence signature field is empty: {0}")]
    EmptyField(&'static str),
    #[error("print evidence trusted key is invalid")]
    InvalidTrustedKey,
    #[error("unknown print evidence key {issuer_id}/{key_id}")]
    UnknownTrustedKey { issuer_id: String, key_id: String },
    #[error("print evidence signature metadata is unsupported")]
    UnsupportedSignatureMetadata,
    #[error("print evidence signature is not valid base64url")]
    InvalidSignatureEncoding,
    #[error("print evidence signature has an invalid Ed25519 length")]
    InvalidSignatureLength,
    #[error("print evidence signature verification failed")]
    SignatureVerificationFailed,
    #[error("print execution record is not verified and source-immutable")]
    ExecutionRecordNotVerified,
    #[error("print execution record digest does not reproduce")]
    ExecutionRecordDigestMismatch,
    #[error("failed to serialize signed print evidence: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Digest(#[from] PrintDigestError),
    #[error(transparent)]
    Hashing(#[from] ergaxiom_proof_kernel::HashingError),
}

pub fn sign_print_preflight_execution_record(
    record: &PrintPreflightExecutionRecord,
    issuer_id: impl Into<String>,
    key_id: impl Into<String>,
    signing_key: &SigningKey,
) -> Result<SignedPrintPreflightExecutionRecord, PrintEvidenceSignatureError> {
    validate_execution_record(record)?;
    let issuer_id = issuer_id.into();
    let key_id = key_id.into();
    let signature = sign_value(record, issuer_id, key_id, signing_key)?;
    Ok(SignedPrintPreflightExecutionRecord {
        record: record.clone(),
        signature,
    })
}

pub fn verify_print_preflight_execution_record(
    package: &SignedPrintPreflightExecutionRecord,
    trusted_keys: &PrintEvidenceKeyRegistry,
) -> Result<VerifiedPrintPreflightExecutionEvidence, PrintEvidenceSignatureError> {
    validate_execution_record(&package.record)?;
    verify_value(&package.record, &package.signature, trusted_keys)?;
    Ok(VerifiedPrintPreflightExecutionEvidence {
        package_digest: canonical_json_sha256(&serde_json::to_value(package)?)?,
        record_digest: package.record.record_digest.clone(),
        issuer_id: package.signature.issuer_id.clone(),
        key_id: package.signature.key_id.clone(),
    })
}

fn validate_execution_record(
    record: &PrintPreflightExecutionRecord,
) -> Result<(), PrintEvidenceSignatureError> {
    if !record.verified || !record.source_immutable {
        return Err(PrintEvidenceSignatureError::ExecutionRecordNotVerified);
    }
    if record.record_digest != canonical_record_digest(record, "record_digest")? {
        return Err(PrintEvidenceSignatureError::ExecutionRecordDigestMismatch);
    }
    Ok(())
}

fn sign_value<T: Serialize>(
    value: &T,
    issuer_id: String,
    key_id: String,
    signing_key: &SigningKey,
) -> Result<PrintEvidenceSignature, PrintEvidenceSignatureError> {
    validate_identity("issuer_id", &issuer_id)?;
    validate_identity("key_id", &key_id)?;
    let value = serde_json::to_value(value)?;
    let signature = signing_key.sign(&canonical_json_bytes(&value)?);
    Ok(PrintEvidenceSignature {
        issuer_id,
        key_id,
        algorithm: PrintEvidenceSignatureAlgorithm::Ed25519,
        encoding: PrintEvidenceSignatureEncoding::Base64url,
        value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

fn verify_value<T: Serialize>(
    value: &T,
    signature: &PrintEvidenceSignature,
    trusted_keys: &PrintEvidenceKeyRegistry,
) -> Result<(), PrintEvidenceSignatureError> {
    if signature.algorithm != PrintEvidenceSignatureAlgorithm::Ed25519
        || signature.encoding != PrintEvidenceSignatureEncoding::Base64url
    {
        return Err(PrintEvidenceSignatureError::UnsupportedSignatureMetadata);
    }
    validate_identity("issuer_id", &signature.issuer_id)?;
    validate_identity("key_id", &signature.key_id)?;
    let key = trusted_keys
        .get(&signature.issuer_id, &signature.key_id)
        .ok_or_else(|| PrintEvidenceSignatureError::UnknownTrustedKey {
            issuer_id: signature.issuer_id.clone(),
            key_id: signature.key_id.clone(),
        })?;
    let decoded = URL_SAFE_NO_PAD
        .decode(signature.value.as_bytes())
        .map_err(|_| PrintEvidenceSignatureError::InvalidSignatureEncoding)?;
    let bytes: [u8; 64] = decoded
        .try_into()
        .map_err(|_| PrintEvidenceSignatureError::InvalidSignatureLength)?;
    let signature = Signature::from_bytes(&bytes);
    let value = serde_json::to_value(value)?;
    key.verify(&canonical_json_bytes(&value)?, &signature)
        .map_err(|_| PrintEvidenceSignatureError::SignatureVerificationFailed)
}

fn validate_identity(
    field: &'static str,
    value: &str,
) -> Result<(), PrintEvidenceSignatureError> {
    if value.trim().is_empty() {
        Err(PrintEvidenceSignatureError::EmptyField(field))
    } else {
        Ok(())
    }
}
