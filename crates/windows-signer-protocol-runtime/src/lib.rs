#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_proof_kernel::{HashingError, canonical_json_bytes, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const SIGNER_PROTOCOL_SCHEMA: &str = "0.1.0";
pub const SIGNING_DOMAIN: &str = "ergaxiom.windows-signer.digest.v1";
pub const DIGEST_ALGORITHM_SHA256: &str = "sha256";
pub const SIGNATURE_ALGORITHM_ED25519: &str = "ed25519";
pub const SIGNATURE_ENCODING_BASE64URL: &str = "base64url";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignerOperation {
    InitializeKey,
    PublicKey,
    SignDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerRequest {
    pub schema_version: String,
    pub request_id: String,
    pub operation: SignerOperation,
    pub role: IssuerRole,
    pub issuer_id: String,
    pub key_id: String,
    pub digest_algorithm: Option<String>,
    pub digest: Option<String>,
}

impl SignerRequest {
    #[must_use]
    pub fn initialize_key(
        request_id: impl Into<String>,
        role: IssuerRole,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SIGNER_PROTOCOL_SCHEMA.to_owned(),
            request_id: request_id.into(),
            operation: SignerOperation::InitializeKey,
            role,
            issuer_id: issuer_id.into(),
            key_id: key_id.into(),
            digest_algorithm: None,
            digest: None,
        }
    }

    #[must_use]
    pub fn public_key(
        request_id: impl Into<String>,
        role: IssuerRole,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SIGNER_PROTOCOL_SCHEMA.to_owned(),
            request_id: request_id.into(),
            operation: SignerOperation::PublicKey,
            role,
            issuer_id: issuer_id.into(),
            key_id: key_id.into(),
            digest_algorithm: None,
            digest: None,
        }
    }

    #[must_use]
    pub fn sign_digest(
        request_id: impl Into<String>,
        role: IssuerRole,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        digest: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SIGNER_PROTOCOL_SCHEMA.to_owned(),
            request_id: request_id.into(),
            operation: SignerOperation::SignDigest,
            role,
            issuer_id: issuer_id.into(),
            key_id: key_id.into(),
            digest_algorithm: Some(DIGEST_ALGORITHM_SHA256.to_owned()),
            digest: Some(digest.into()),
        }
    }

    pub fn validate(&self) -> Result<(), SignerProtocolError> {
        if self.schema_version != SIGNER_PROTOCOL_SCHEMA {
            return Err(SignerProtocolError::UnsupportedSchema);
        }
        validate_identifier("request_id", &self.request_id)?;
        validate_identifier("issuer_id", &self.issuer_id)?;
        validate_identifier("key_id", &self.key_id)?;
        match self.operation {
            SignerOperation::InitializeKey | SignerOperation::PublicKey => {
                if self.digest_algorithm.is_some() || self.digest.is_some() {
                    return Err(SignerProtocolError::UnexpectedDigestMaterial);
                }
            }
            SignerOperation::SignDigest => {
                if self.digest_algorithm.as_deref() != Some(DIGEST_ALGORITHM_SHA256) {
                    return Err(SignerProtocolError::UnsupportedDigestAlgorithm);
                }
                validate_sha256(self.digest.as_deref().unwrap_or_default())?;
            }
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, SignerProtocolError> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(SignerProtocolError::Serialization)?;
        Ok(canonical_json_sha256(&value)?)
    }

    pub fn identity_digest(&self) -> Result<String, SignerProtocolError> {
        self.validate()?;
        key_identity_digest(self.role, &self.issuer_id, &self.key_id)
    }

    pub fn signing_envelope(&self) -> Result<SignerEnvelope, SignerProtocolError> {
        self.validate()?;
        if self.operation != SignerOperation::SignDigest {
            return Err(SignerProtocolError::OperationDoesNotSign);
        }
        Ok(SignerEnvelope {
            schema_version: SIGNER_PROTOCOL_SCHEMA.to_owned(),
            domain: SIGNING_DOMAIN.to_owned(),
            request_id: self.request_id.clone(),
            role: self.role,
            issuer_id: self.issuer_id.clone(),
            key_id: self.key_id.clone(),
            digest_algorithm: DIGEST_ALGORITHM_SHA256.to_owned(),
            digest: self.digest.clone().unwrap_or_default(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerEnvelope {
    pub schema_version: String,
    pub domain: String,
    pub request_id: String,
    pub role: IssuerRole,
    pub issuer_id: String,
    pub key_id: String,
    pub digest_algorithm: String,
    pub digest: String,
}

impl SignerEnvelope {
    pub fn validate(&self) -> Result<(), SignerProtocolError> {
        if self.schema_version != SIGNER_PROTOCOL_SCHEMA || self.domain != SIGNING_DOMAIN {
            return Err(SignerProtocolError::InvalidSigningDomain);
        }
        validate_identifier("request_id", &self.request_id)?;
        validate_identifier("issuer_id", &self.issuer_id)?;
        validate_identifier("key_id", &self.key_id)?;
        if self.digest_algorithm != DIGEST_ALGORITHM_SHA256 {
            return Err(SignerProtocolError::UnsupportedDigestAlgorithm);
        }
        validate_sha256(&self.digest)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SignerProtocolError> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(SignerProtocolError::Serialization)?;
        Ok(canonical_json_bytes(&value)?)
    }

    pub fn digest(&self) -> Result<String, SignerProtocolError> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(SignerProtocolError::Serialization)?;
        Ok(canonical_json_sha256(&value)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignerSuccess {
    KeyInitialized {
        role: IssuerRole,
        issuer_id: String,
        key_id: String,
        public_key_hex: String,
        record_digest: String,
    },
    PublicKey {
        role: IssuerRole,
        issuer_id: String,
        key_id: String,
        public_key_hex: String,
        record_digest: String,
    },
    DigestSigned {
        public_key_hex: String,
        envelope: SignerEnvelope,
        envelope_digest: String,
        signature_algorithm: String,
        signature_encoding: String,
        signature: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignerResponse {
    Success {
        request_id: String,
        result: SignerSuccess,
    },
    Error {
        request_id: Option<String>,
        code: String,
        message: String,
    },
}

impl SignerResponse {
    #[must_use]
    pub fn success(request_id: impl Into<String>, result: SignerSuccess) -> Self {
        Self::Success {
            request_id: request_id.into(),
            result,
        }
    }

    #[must_use]
    pub fn rejected(request_id: Option<String>, code: impl Into<String>) -> Self {
        Self::Error {
            request_id,
            code: code.into(),
            message: "signer request rejected".to_owned(),
        }
    }

    pub fn verify_digest_signature(&self) -> Result<SignerEnvelope, SignerProtocolError> {
        let SignerResponse::Success {
            request_id,
            result:
                SignerSuccess::DigestSigned {
                    public_key_hex,
                    envelope,
                    envelope_digest,
                    signature_algorithm,
                    signature_encoding,
                    signature,
                },
        } = self
        else {
            return Err(SignerProtocolError::ResponseDoesNotContainSignature);
        };
        if request_id != &envelope.request_id
            || signature_algorithm != SIGNATURE_ALGORITHM_ED25519
            || signature_encoding != SIGNATURE_ENCODING_BASE64URL
            || envelope.digest()? != *envelope_digest
        {
            return Err(SignerProtocolError::ResponseBindingMismatch);
        }
        let public_key_bytes = decode_hex_32(public_key_hex)
            .map_err(|_| SignerProtocolError::InvalidPublicKeyEncoding)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|_| SignerProtocolError::InvalidPublicKeyEncoding)?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| SignerProtocolError::InvalidSignatureEncoding)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| SignerProtocolError::InvalidSignatureEncoding)?;
        verifying_key
            .verify(&envelope.canonical_bytes()?, &signature)
            .map_err(|_| SignerProtocolError::SignatureVerificationFailed)?;
        Ok(envelope.clone())
    }

    #[must_use]
    pub fn contains_private_material_field(&self) -> bool {
        let Ok(value) = serde_json::to_value(self) else {
            return true;
        };
        contains_forbidden_field(&value)
    }
}

pub fn key_identity_digest(
    role: IssuerRole,
    issuer_id: &str,
    key_id: &str,
) -> Result<String, SignerProtocolError> {
    validate_identifier("issuer_id", issuer_id)?;
    validate_identifier("key_id", key_id)?;
    let value = serde_json::json!({
        "schema_version": SIGNER_PROTOCOL_SCHEMA,
        "role": role,
        "issuer_id": issuer_id,
        "key_id": key_id,
    });
    Ok(canonical_json_sha256(&value)?)
}

pub fn validate_identifier(field: &'static str, value: &str) -> Result<(), SignerProtocolError> {
    let valid_length = (3..=128).contains(&value.len());
    let mut chars = value.chars();
    let starts_valid = chars
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric());
    let remaining_valid = chars
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'));
    if !valid_length || !starts_valid || !remaining_valid {
        return Err(SignerProtocolError::InvalidIdentifier(field));
    }
    Ok(())
}

pub fn validate_sha256(value: &str) -> Result<(), SignerProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SignerProtocolError::InvalidSha256Digest);
    }
    Ok(())
}

#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn decode_hex_32(value: &str) -> Result<[u8; 32], SignerProtocolError> {
    if value.len() != 64 {
        return Err(SignerProtocolError::InvalidHexEncoding);
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = decode_nibble(chunk[0])? << 4 | decode_nibble(chunk[1])?;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Result<u8, SignerProtocolError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(SignerProtocolError::InvalidHexEncoding),
    }
}

fn contains_forbidden_field(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "private_key" | "private_seed" | "seed" | "secret" | "protected_seed"
            ) || contains_forbidden_field(value)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_field),
        _ => false,
    }
}

#[derive(Debug, Error)]
pub enum SignerProtocolError {
    #[error("signer protocol schema is unsupported")]
    UnsupportedSchema,
    #[error("signer identifier is invalid: {0}")]
    InvalidIdentifier(&'static str),
    #[error("request contains digest material for a non-signing operation")]
    UnexpectedDigestMaterial,
    #[error("digest algorithm is unsupported")]
    UnsupportedDigestAlgorithm,
    #[error("digest is not lowercase SHA-256")]
    InvalidSha256Digest,
    #[error("request operation does not produce a signature")]
    OperationDoesNotSign,
    #[error("signing domain is invalid")]
    InvalidSigningDomain,
    #[error("response does not contain a digest signature")]
    ResponseDoesNotContainSignature,
    #[error("response fields are not bound to the signed envelope")]
    ResponseBindingMismatch,
    #[error("public key encoding is invalid")]
    InvalidPublicKeyEncoding,
    #[error("signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("hex encoding is invalid")]
    InvalidHexEncoding,
    #[error("failed to serialize signer protocol material: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}
