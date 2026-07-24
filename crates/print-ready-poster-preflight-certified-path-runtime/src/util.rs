use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrintDigestError {
    #[error("failed to serialize canonical material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("record must serialize as a JSON object")]
    InvalidRecordShape,
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[must_use]
pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub fn canonical_value_digest<T: Serialize>(value: &T) -> Result<String, PrintDigestError> {
    let json = serde_json::to_value(value)?;
    Ok(ergaxiom_proof_kernel::canonical_json_sha256(&json)?)
}

pub fn canonical_record_digest<T: Serialize>(
    value: &T,
    digest_field: &str,
) -> Result<String, PrintDigestError> {
    let mut json = serde_json::to_value(value)?;
    let Value::Object(map) = &mut json else {
        return Err(PrintDigestError::InvalidRecordShape);
    };
    map.insert(digest_field.to_owned(), Value::String(String::new()));
    Ok(ergaxiom_proof_kernel::canonical_json_sha256(&json)?)
}

impl From<ergaxiom_proof_kernel::HashingError> for PrintDigestError {
    fn from(error: ergaxiom_proof_kernel::HashingError) -> Self {
        Self::Serialization(serde_json::Error::io(std::io::Error::other(error.to_string())))
    }
}
