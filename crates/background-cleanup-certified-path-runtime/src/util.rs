use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DigestMaterialError {
    #[error("failed to serialize digest material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("digest material must serialize to an object")]
    InvalidShape,
    #[error("digest material does not contain field {0}")]
    MissingDigestField(String),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, DigestMaterialError> {
    let serialized = serde_json::to_value(value)?;
    Ok(canonical_json_sha256(&serialized)?)
}

pub(crate) fn canonical_record_digest<T: Serialize>(
    value: &T,
    digest_field: &str,
) -> Result<String, DigestMaterialError> {
    let mut serialized = serde_json::to_value(value)?;
    let object = serialized
        .as_object_mut()
        .ok_or(DigestMaterialError::InvalidShape)?;
    if !object.contains_key(digest_field) {
        return Err(DigestMaterialError::MissingDigestField(
            digest_field.to_owned(),
        ));
    }
    object.insert(digest_field.to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&serialized)?)
}
