use ergaxiom_proof_kernel::canonical_json_sha256;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrandDigestError {
    #[error("failed to serialize brand evidence material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] ergaxiom_proof_kernel::HashingError),
    #[error("record did not serialize to a JSON object")]
    InvalidRecordShape,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn canonical_value_digest<T: Serialize>(value: &T) -> Result<String, BrandDigestError> {
    Ok(canonical_json_sha256(&serde_json::to_value(value)?)?)
}

pub fn canonical_record_digest<T: Serialize>(
    value: &T,
    digest_field: &str,
) -> Result<String, BrandDigestError> {
    let mut value = serde_json::to_value(value)?;
    let Value::Object(object) = &mut value else {
        return Err(BrandDigestError::InvalidRecordShape);
    };
    object.insert(digest_field.to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
