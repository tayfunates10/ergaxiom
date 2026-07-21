use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashingError {
    #[error("failed to serialize canonical JSON: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Produces deterministic canonical JSON bytes for signing and hashing.
///
/// Object keys are recursively sorted before serialization. Array order is
/// preserved because it can be semantically significant in sealed documents.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, HashingError> {
    let canonical = canonicalize(value);
    Ok(serde_json::to_vec(&canonical)?)
}

/// Produces a deterministic SHA-256 digest for a JSON value.
pub fn canonical_json_sha256(value: &Value) -> Result<String, HashingError> {
    let digest = Sha256::digest(canonical_json_bytes(value)?);
    Ok(format!("{digest:x}"))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_by_key(|(key, _)| *key);

            let mut canonical = Map::new();
            for (key, child) in entries {
                canonical.insert(key.clone(), canonicalize(child));
            }
            Value::Object(canonical)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}
