use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ergaxiom_proof_kernel::{canonical_json_bytes, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    BackgroundCleanupExecutionRecord, InkscapeCleanupIntegrationReport,
};
use crate::util::{DigestMaterialError, canonical_record_digest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CleanupEvidenceSignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CleanupEvidenceSignatureEncoding {
    Base64url,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupEvidenceSignature {
    pub issuer_id: String,
    pub key_id: String,
    pub algorithm: CleanupEvidenceSignatureAlgorithm,
    pub encoding: CleanupEvidenceSignatureEncoding,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBackgroundCleanupExecutionRecord {
    pub record: BackgroundCleanupExecutionRecord,
    pub signature: CleanupEvidenceSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInkscapeCleanupIntegrationReport {
    pub report: InkscapeCleanupIntegrationReport,
    pub signature: CleanupEvidenceSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCleanupExecutionEvidence {
    pub package_digest: String,
    pub record_digest: String,
    pub issuer_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCleanupIntegrationEvidence {
    pub package_digest: String,
    pub report_digest: String,
    pub issuer_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct CleanupEvidenceKeyRegistry {
    keys: BTreeMap<(String, String), VerifyingKey>,
}

impl CleanupEvidenceKeyRegistry {
    pub fn insert_ed25519(
        &mut self,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<(), CleanupEvidenceSignatureError> {
        let issuer_id = issuer_id.into();
        let key_id = key_id.into();
        validate_identity("issuer_id", &issuer_id)?;
        validate_identity("key_id", &key_id)?;
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| CleanupEvidenceSignatureError::InvalidTrustedKey)?;
        self.keys.insert((issuer_id, key_id), key);
        Ok(())
    }

    fn get(&self, issuer_id: &str, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(&(issuer_id.to_owned(), key_id.to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum CleanupEvidenceSignatureError {
    #[error("required cleanup evidence signature field is empty: {0}")]
    EmptyField(&'static str),
    #[error("cleanup evidence trusted key is invalid")]
    InvalidTrustedKey,
    #[error("unknown cleanup evidence key {issuer_id}/{key_id}")]
    UnknownTrustedKey { issuer_id: String, key_id: String },
    #[error("cleanup evidence signature metadata is unsupported")]
    UnsupportedSignatureMetadata,
    #[error("cleanup evidence signature is not valid base64url")]
    InvalidSignatureEncoding,
    #[error("cleanup evidence signature has an invalid Ed25519 length")]
    InvalidSignatureLength,
    #[error("cleanup evidence signature verification failed")]
    SignatureVerificationFailed,
    #[error("cleanup execution record is not verified and source-immutable")]
    ExecutionRecordNotVerified,
    #[error("cleanup execution record digest does not reproduce")]
    ExecutionRecordDigestMismatch,
    #[error("Inkscape cleanup integration report is not verified")]
    IntegrationReportNotVerified,
    #[error("Inkscape cleanup integration report digest does not reproduce")]
    IntegrationReportDigestMismatch,
    #[error("failed to serialize signed cleanup evidence: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Digest(#[from] DigestMaterialError),
    #[error(transparent)]
    Hashing(#[from] ergaxiom_proof_kernel::HashingError),
}

pub fn sign_background_cleanup_execution_record(
    record: &BackgroundCleanupExecutionRecord,
    issuer_id: impl Into<String>,
    key_id: impl Into<String>,
    signing_key: &SigningKey,
) -> Result<SignedBackgroundCleanupExecutionRecord, CleanupEvidenceSignatureError> {
    validate_execution_record(record)?;
    let issuer_id = issuer_id.into();
    let key_id = key_id.into();
    let signature = sign_value(record, issuer_id, key_id, signing_key)?;
    Ok(SignedBackgroundCleanupExecutionRecord {
        record: record.clone(),
        signature,
    })
}

pub fn sign_inkscape_cleanup_integration_report(
    report: &InkscapeCleanupIntegrationReport,
    issuer_id: impl Into<String>,
    key_id: impl Into<String>,
    signing_key: &SigningKey,
) -> Result<SignedInkscapeCleanupIntegrationReport, CleanupEvidenceSignatureError> {
    validate_integration_report(report)?;
    let issuer_id = issuer_id.into();
    let key_id = key_id.into();
    let signature = sign_value(report, issuer_id, key_id, signing_key)?;
    Ok(SignedInkscapeCleanupIntegrationReport {
        report: report.clone(),
        signature,
    })
}

pub fn verify_background_cleanup_execution_record(
    package: &SignedBackgroundCleanupExecutionRecord,
    trusted_keys: &CleanupEvidenceKeyRegistry,
) -> Result<VerifiedCleanupExecutionEvidence, CleanupEvidenceSignatureError> {
    validate_execution_record(&package.record)?;
    verify_value(&package.record, &package.signature, trusted_keys)?;
    Ok(VerifiedCleanupExecutionEvidence {
        package_digest: package_digest(package)?,
        record_digest: package.record.record_digest.clone(),
        issuer_id: package.signature.issuer_id.clone(),
        key_id: package.signature.key_id.clone(),
    })
}

pub fn verify_inkscape_cleanup_integration_report(
    package: &SignedInkscapeCleanupIntegrationReport,
    trusted_keys: &CleanupEvidenceKeyRegistry,
) -> Result<VerifiedCleanupIntegrationEvidence, CleanupEvidenceSignatureError> {
    validate_integration_report(&package.report)?;
    verify_value(&package.report, &package.signature, trusted_keys)?;
    Ok(VerifiedCleanupIntegrationEvidence {
        package_digest: package_digest(package)?,
        report_digest: package.report.report_digest.clone(),
        issuer_id: package.signature.issuer_id.clone(),
        key_id: package.signature.key_id.clone(),
    })
}

fn validate_execution_record(
    record: &BackgroundCleanupExecutionRecord,
) -> Result<(), CleanupEvidenceSignatureError> {
    if !record.verified || !record.source_immutable {
        return Err(CleanupEvidenceSignatureError::ExecutionRecordNotVerified);
    }
    if record.record_digest != canonical_record_digest(record, "record_digest")? {
        return Err(CleanupEvidenceSignatureError::ExecutionRecordDigestMismatch);
    }
    Ok(())
}

fn validate_integration_report(
    report: &InkscapeCleanupIntegrationReport,
) -> Result<(), CleanupEvidenceSignatureError> {
    if !report.verified {
        return Err(CleanupEvidenceSignatureError::IntegrationReportNotVerified);
    }
    if report.report_digest != canonical_record_digest(report, "report_digest")? {
        return Err(CleanupEvidenceSignatureError::IntegrationReportDigestMismatch);
    }
    Ok(())
}

fn sign_value<T: Serialize>(
    value: &T,
    issuer_id: String,
    key_id: String,
    signing_key: &SigningKey,
) -> Result<CleanupEvidenceSignature, CleanupEvidenceSignatureError> {
    validate_identity("issuer_id", &issuer_id)?;
    validate_identity("key_id", &key_id)?;
    let value = serde_json::to_value(value)?;
    let signature = signing_key.sign(&canonical_json_bytes(&value)?);
    Ok(CleanupEvidenceSignature {
        issuer_id,
        key_id,
        algorithm: CleanupEvidenceSignatureAlgorithm::Ed25519,
        encoding: CleanupEvidenceSignatureEncoding::Base64url,
        value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

fn verify_value<T: Serialize>(
    value: &T,
    signature: &CleanupEvidenceSignature,
    trusted_keys: &CleanupEvidenceKeyRegistry,
) -> Result<(), CleanupEvidenceSignatureError> {
    if signature.algorithm != CleanupEvidenceSignatureAlgorithm::Ed25519
        || signature.encoding != CleanupEvidenceSignatureEncoding::Base64url
    {
        return Err(CleanupEvidenceSignatureError::UnsupportedSignatureMetadata);
    }
    validate_identity("issuer_id", &signature.issuer_id)?;
    validate_identity("key_id", &signature.key_id)?;
    let key = trusted_keys
        .get(&signature.issuer_id, &signature.key_id)
        .ok_or_else(|| CleanupEvidenceSignatureError::UnknownTrustedKey {
            issuer_id: signature.issuer_id.clone(),
            key_id: signature.key_id.clone(),
        })?;
    let decoded = URL_SAFE_NO_PAD
        .decode(signature.value.as_bytes())
        .map_err(|_| CleanupEvidenceSignatureError::InvalidSignatureEncoding)?;
    let bytes: [u8; 64] = decoded
        .try_into()
        .map_err(|_| CleanupEvidenceSignatureError::InvalidSignatureLength)?;
    let signature = Signature::from_bytes(&bytes);
    let value = serde_json::to_value(value)?;
    key.verify(&canonical_json_bytes(&value)?, &signature)
        .map_err(|_| CleanupEvidenceSignatureError::SignatureVerificationFailed)
}

fn package_digest<T: Serialize>(value: &T) -> Result<String, CleanupEvidenceSignatureError> {
    Ok(canonical_json_sha256(&serde_json::to_value(value)?)?)
}

fn validate_identity(
    field: &'static str,
    value: &str,
) -> Result<(), CleanupEvidenceSignatureError> {
    if value.trim().is_empty() {
        Err(CleanupEvidenceSignatureError::EmptyField(field))
    } else {
        Ok(())
    }
}
