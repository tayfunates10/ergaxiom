#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_proof_kernel::{HashingError, canonical_json_bytes, canonical_json_sha256};
use ergaxiom_windows_production_signer_runtime::{
    ECDSA_P256_SHA256, HardwareKeyDescriptor, HardwareSignature,
    MICROSOFT_PLATFORM_CRYPTO_PROVIDER, NON_EXPORTABLE_POLICY, P1363_FIXED_64,
    ProductionKeyIdentity, ProductionKeyPolicy, ProductionSignerError, SEC1_UNCOMPRESSED_P256,
    SignerRequestBinding, validate_identifier, validate_sha256,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PRODUCTION_SIGNER_PROTOCOL_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_SIGNING_DOMAIN: &str = "ergaxiom.windows-production-signer.digest.v1";
pub const DIGEST_ALGORITHM_SHA256: &str = "sha256";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSignerRequest {
    pub schema_version: String,
    pub request_id: String,
    pub identity: ProductionKeyIdentity,
    pub digest_algorithm: String,
    pub digest: String,
    pub key_policy_digest: String,
}

impl ProductionSignerRequest {
    pub fn sign_digest(
        request_id: impl Into<String>,
        policy: &ProductionKeyPolicy,
        digest: impl Into<String>,
    ) -> Result<Self, ProductionSignerProtocolError> {
        policy.validate()?;
        let request = Self {
            schema_version: PRODUCTION_SIGNER_PROTOCOL_SCHEMA.to_owned(),
            request_id: request_id.into(),
            identity: policy.identity.clone(),
            digest_algorithm: DIGEST_ALGORITHM_SHA256.to_owned(),
            digest: digest.into(),
            key_policy_digest: policy.digest()?,
        };
        request.validate_for(policy)?;
        Ok(request)
    }

    pub fn validate_for(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<(), ProductionSignerProtocolError> {
        policy.validate()?;
        if self.schema_version != PRODUCTION_SIGNER_PROTOCOL_SCHEMA {
            return Err(ProductionSignerProtocolError::UnsupportedSchema);
        }
        validate_identifier("request_id", &self.request_id)?;
        self.identity.validate()?;
        if self.identity != policy.identity {
            return Err(ProductionSignerProtocolError::IdentitySubstitution);
        }
        if self.digest_algorithm != DIGEST_ALGORITHM_SHA256 {
            return Err(ProductionSignerProtocolError::DigestAlgorithmSubstitution);
        }
        validate_sha256(&self.digest)?;
        validate_sha256(&self.key_policy_digest)?;
        if self.key_policy_digest != policy.digest()? {
            return Err(ProductionSignerProtocolError::PolicyDigestMismatch);
        }
        Ok(())
    }

    pub fn digest_for(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<String, ProductionSignerProtocolError> {
        self.validate_for(policy)?;
        digest_value(self)
    }

    pub fn envelope(
        &self,
        policy: &ProductionKeyPolicy,
        binding: SignerRequestBinding,
    ) -> Result<ProductionSignerEnvelope, ProductionSignerProtocolError> {
        self.validate_for(policy)?;
        binding.validate()?;
        if binding.request_digest != self.digest_for(policy)?
            || binding.key_policy_digest != self.key_policy_digest
        {
            return Err(ProductionSignerProtocolError::RequestBindingMismatch);
        }
        let envelope = ProductionSignerEnvelope {
            schema_version: PRODUCTION_SIGNER_PROTOCOL_SCHEMA.to_owned(),
            domain: PRODUCTION_SIGNING_DOMAIN.to_owned(),
            request: self.clone(),
            binding,
        };
        envelope.validate_for(policy)?;
        Ok(envelope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSignerEnvelope {
    pub schema_version: String,
    pub domain: String,
    pub request: ProductionSignerRequest,
    pub binding: SignerRequestBinding,
}

impl ProductionSignerEnvelope {
    pub fn validate_for(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<(), ProductionSignerProtocolError> {
        if self.schema_version != PRODUCTION_SIGNER_PROTOCOL_SCHEMA
            || self.domain != PRODUCTION_SIGNING_DOMAIN
        {
            return Err(ProductionSignerProtocolError::InvalidSigningDomain);
        }
        self.request.validate_for(policy)?;
        self.binding.validate()?;
        if self.binding.request_digest != self.request.digest_for(policy)?
            || self.binding.key_policy_digest != self.request.key_policy_digest
        {
            return Err(ProductionSignerProtocolError::RequestBindingMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<Vec<u8>, ProductionSignerProtocolError> {
        self.validate_for(policy)?;
        let value = serde_json::to_value(self)?;
        Ok(canonical_json_bytes(&value)?)
    }

    pub fn digest_for(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<String, ProductionSignerProtocolError> {
        self.validate_for(policy)?;
        let value = serde_json::to_value(self)?;
        Ok(canonical_json_sha256(&value)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSignerSuccess {
    pub descriptor: HardwareKeyDescriptor,
    pub envelope: ProductionSignerEnvelope,
    pub envelope_digest: String,
    pub signature: HardwareSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductionSignerResponse {
    Success {
        request_id: String,
        result: ProductionSignerSuccess,
    },
    Error {
        request_id: Option<String>,
        code: String,
        message: String,
    },
}

impl ProductionSignerResponse {
    #[must_use]
    pub fn success(request_id: impl Into<String>, result: ProductionSignerSuccess) -> Self {
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
            message: "production signer request rejected".to_owned(),
        }
    }

    pub fn verify_cryptographic(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<ProductionSignerEnvelope, ProductionSignerProtocolError> {
        let Self::Success { request_id, result } = self else {
            return Err(ProductionSignerProtocolError::ResponseDoesNotContainSignature);
        };
        result.envelope.validate_for(policy)?;
        if request_id != &result.envelope.request.request_id {
            return Err(ProductionSignerProtocolError::ResponseBindingMismatch);
        }
        validate_descriptor_contract(&result.descriptor, policy)?;
        let envelope_digest = result.envelope.digest_for(policy)?;
        if result.envelope_digest != envelope_digest || result.signature.digest != envelope_digest {
            return Err(ProductionSignerProtocolError::EnvelopeDigestMismatch);
        }
        result
            .signature
            .validate_for(&result.descriptor, &result.envelope.binding)?;
        let public_key = decode_public_key(&result.descriptor)?;
        let signature = decode_signature(&result.signature)?;
        let digest = decode_sha256(&envelope_digest)?;
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)
            .map_err(|_| ProductionSignerProtocolError::InvalidPublicKeyEncoding)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| ProductionSignerProtocolError::SignatureVerificationFailed)?;
        Ok(result.envelope.clone())
    }

    pub fn verify_production_eligible(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<ProductionSignerEnvelope, ProductionSignerProtocolError> {
        let envelope = self.verify_cryptographic(policy)?;
        let Self::Success { result, .. } = self else {
            return Err(ProductionSignerProtocolError::ResponseDoesNotContainSignature);
        };
        result.descriptor.validate_for(policy)?;
        Ok(envelope)
    }

    #[must_use]
    pub fn contains_private_material_field(&self) -> bool {
        let Ok(value) = serde_json::to_value(self) else {
            return true;
        };
        contains_forbidden_field(&value)
    }
}

fn validate_descriptor_contract(
    descriptor: &HardwareKeyDescriptor,
    policy: &ProductionKeyPolicy,
) -> Result<(), ProductionSignerProtocolError> {
    policy.validate()?;
    descriptor.identity.validate()?;
    if descriptor.identity != policy.identity {
        return Err(ProductionSignerProtocolError::IdentitySubstitution);
    }
    if descriptor.provider != MICROSOFT_PLATFORM_CRYPTO_PROVIDER
        || descriptor.provider != policy.provider
    {
        return Err(ProductionSignerProtocolError::ProviderSubstitution);
    }
    if descriptor.algorithm != ECDSA_P256_SHA256 || descriptor.algorithm != policy.algorithm {
        return Err(ProductionSignerProtocolError::AlgorithmSubstitution);
    }
    if descriptor.public_key_encoding != SEC1_UNCOMPRESSED_P256
        || descriptor.public_key_encoding != policy.public_key_encoding
    {
        return Err(ProductionSignerProtocolError::PublicKeyEncodingSubstitution);
    }
    if descriptor.signature_encoding != P1363_FIXED_64
        || descriptor.signature_encoding != policy.signature_encoding
    {
        return Err(ProductionSignerProtocolError::SignatureEncodingSubstitution);
    }
    if descriptor.export_policy != NON_EXPORTABLE_POLICY
        || descriptor.export_policy != policy.export_policy
    {
        return Err(ProductionSignerProtocolError::ExportPolicySubstitution);
    }
    validate_sha256(&descriptor.public_key_digest)?;
    validate_sha256(&descriptor.policy_digest)?;
    if descriptor.policy_digest != policy.digest()? {
        return Err(ProductionSignerProtocolError::PolicyDigestMismatch);
    }
    let public_key = URL_SAFE_NO_PAD
        .decode(&descriptor.public_key_base64url)
        .map_err(|_| ProductionSignerProtocolError::InvalidPublicKeyEncoding)?;
    if public_key.len() != 65 || public_key.first() != Some(&0x04) {
        return Err(ProductionSignerProtocolError::InvalidPublicKeyEncoding);
    }
    if encode_hex(&Sha256::digest(&public_key)) != descriptor.public_key_digest {
        return Err(ProductionSignerProtocolError::PublicKeyDigestMismatch);
    }
    Ok(())
}

fn decode_public_key(
    descriptor: &HardwareKeyDescriptor,
) -> Result<Vec<u8>, ProductionSignerProtocolError> {
    let public_key = URL_SAFE_NO_PAD
        .decode(&descriptor.public_key_base64url)
        .map_err(|_| ProductionSignerProtocolError::InvalidPublicKeyEncoding)?;
    if public_key.len() != 65 || public_key.first() != Some(&0x04) {
        return Err(ProductionSignerProtocolError::InvalidPublicKeyEncoding);
    }
    Ok(public_key)
}

fn decode_signature(
    signature: &HardwareSignature,
) -> Result<Signature, ProductionSignerProtocolError> {
    if signature.algorithm != ECDSA_P256_SHA256
        || signature.signature_encoding != P1363_FIXED_64
        || signature.digest_algorithm != DIGEST_ALGORITHM_SHA256
    {
        return Err(ProductionSignerProtocolError::SignatureMetadataSubstitution);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(&signature.signature_base64url)
        .map_err(|_| ProductionSignerProtocolError::InvalidSignatureEncoding)?;
    Signature::from_slice(&bytes)
        .map_err(|_| ProductionSignerProtocolError::InvalidSignatureEncoding)
}

fn decode_sha256(value: &str) -> Result<[u8; 32], ProductionSignerProtocolError> {
    validate_sha256(value)?;
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(chunk[0])? << 4) | decode_nibble(chunk[1])?;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Result<u8, ProductionSignerProtocolError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ProductionSignerProtocolError::InvalidDigestEncoding),
    }
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

fn digest_value<T: Serialize>(value: &T) -> Result<String, ProductionSignerProtocolError> {
    let value = serde_json::to_value(value)?;
    Ok(canonical_json_sha256(&value)?)
}

fn contains_forbidden_field(value: &Value) -> bool {
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
            ) || contains_forbidden_field(value)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_field),
        _ => false,
    }
}

#[derive(Debug, Error)]
pub enum ProductionSignerProtocolError {
    #[error("production signer protocol schema is unsupported")]
    UnsupportedSchema,
    #[error("production signer signing domain is invalid")]
    InvalidSigningDomain,
    #[error("production signer key identity was substituted")]
    IdentitySubstitution,
    #[error("production signer digest algorithm was substituted")]
    DigestAlgorithmSubstitution,
    #[error("production signer policy digest does not match")]
    PolicyDigestMismatch,
    #[error("production signer request binding does not match")]
    RequestBindingMismatch,
    #[error("production signer response does not contain a signature")]
    ResponseDoesNotContainSignature,
    #[error("production signer response fields are not bound")]
    ResponseBindingMismatch,
    #[error("production signer envelope digest does not match")]
    EnvelopeDigestMismatch,
    #[error("production signer provider was substituted")]
    ProviderSubstitution,
    #[error("production signer algorithm was substituted")]
    AlgorithmSubstitution,
    #[error("production signer public-key encoding was substituted")]
    PublicKeyEncodingSubstitution,
    #[error("production signer signature encoding was substituted")]
    SignatureEncodingSubstitution,
    #[error("production signer export policy was substituted")]
    ExportPolicySubstitution,
    #[error("production signer public key encoding is invalid")]
    InvalidPublicKeyEncoding,
    #[error("production signer public-key digest does not match")]
    PublicKeyDigestMismatch,
    #[error("production signer signature metadata was substituted")]
    SignatureMetadataSubstitution,
    #[error("production signer signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("production signer signature verification failed")]
    SignatureVerificationFailed,
    #[error("production signer digest encoding is invalid")]
    InvalidDigestEncoding,
    #[error("production signer JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Production(#[from] ProductionSignerError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}
