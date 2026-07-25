#![forbid(unsafe_code)]

use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const PRODUCTION_SIGNER_POLICY_SCHEMA: &str = "0.1.0";
pub const PROVISIONING_RECEIPT_SCHEMA: &str = "0.1.0";
pub const SIGNER_SERVICE_IDENTITY_SCHEMA: &str = "0.1.0";
pub const AUTHENTICATED_CALLER_SCHEMA: &str = "0.1.0";
pub const SIGNER_REQUEST_BINDING_SCHEMA: &str = "0.1.0";

pub const MICROSOFT_PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";
pub const ECDSA_P256_SHA256: &str = "ecdsa-p256-sha256";
pub const SEC1_UNCOMPRESSED_P256: &str = "sec1-uncompressed-p256";
pub const P1363_FIXED_64: &str = "p1363-fixed-64";
pub const NON_EXPORTABLE_POLICY: &str = "non-exportable";
pub const CAPABILITY_ISSUER_ID: &str = "ergaxiom.policy-authority";
pub const CAPABILITY_KEY_ID: &str = "capability-key-v1";
pub const ATTESTATION_ISSUER_ID: &str = "ergaxiom.attestation-authority";
pub const ATTESTATION_KEY_ID: &str = "attestation-key-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HardwareAssurance {
    ProvenHardwareBacked,
    Unproven,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionKeyIdentity {
    pub role: IssuerRole,
    pub issuer_id: String,
    pub key_id: String,
}

impl ProductionKeyIdentity {
    #[must_use]
    pub fn capability() -> Self {
        Self {
            role: IssuerRole::Capability,
            issuer_id: CAPABILITY_ISSUER_ID.to_owned(),
            key_id: CAPABILITY_KEY_ID.to_owned(),
        }
    }

    #[must_use]
    pub fn attestation() -> Self {
        Self {
            role: IssuerRole::Attestation,
            issuer_id: ATTESTATION_ISSUER_ID.to_owned(),
            key_id: ATTESTATION_KEY_ID.to_owned(),
        }
    }

    pub fn validate(&self) -> Result<(), ProductionSignerError> {
        validate_identifier("issuer_id", &self.issuer_id)?;
        validate_identifier("key_id", &self.key_id)?;
        match self.role {
            IssuerRole::Capability => {
                if self.issuer_id != CAPABILITY_ISSUER_ID || self.key_id != CAPABILITY_KEY_ID {
                    return Err(ProductionSignerError::UnsupportedProductionIdentity);
                }
            }
            IssuerRole::Attestation => {
                if self.issuer_id != ATTESTATION_ISSUER_ID || self.key_id != ATTESTATION_KEY_ID {
                    return Err(ProductionSignerError::UnsupportedProductionIdentity);
                }
            }
            IssuerRole::Execution | IssuerRole::Normalization | IssuerRole::Release => {
                return Err(ProductionSignerError::UnsupportedProductionRole);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ProductionSignerError> {
        self.validate()?;
        digest_value(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionKeyPolicy {
    pub schema_version: String,
    pub identity: ProductionKeyIdentity,
    pub provider: String,
    pub algorithm: String,
    pub public_key_encoding: String,
    pub signature_encoding: String,
    pub export_policy: String,
    pub require_hardware_backing: bool,
}

impl ProductionKeyPolicy {
    #[must_use]
    pub fn capability() -> Self {
        Self::for_identity(ProductionKeyIdentity::capability())
    }

    #[must_use]
    pub fn attestation() -> Self {
        Self::for_identity(ProductionKeyIdentity::attestation())
    }

    #[must_use]
    pub fn for_identity(identity: ProductionKeyIdentity) -> Self {
        Self {
            schema_version: PRODUCTION_SIGNER_POLICY_SCHEMA.to_owned(),
            identity,
            provider: MICROSOFT_PLATFORM_CRYPTO_PROVIDER.to_owned(),
            algorithm: ECDSA_P256_SHA256.to_owned(),
            public_key_encoding: SEC1_UNCOMPRESSED_P256.to_owned(),
            signature_encoding: P1363_FIXED_64.to_owned(),
            export_policy: NON_EXPORTABLE_POLICY.to_owned(),
            require_hardware_backing: true,
        }
    }

    pub fn validate(&self) -> Result<(), ProductionSignerError> {
        self.identity.validate()?;
        if self.schema_version != PRODUCTION_SIGNER_POLICY_SCHEMA {
            return Err(ProductionSignerError::UnsupportedPolicySchema);
        }
        if self.provider != MICROSOFT_PLATFORM_CRYPTO_PROVIDER {
            return Err(ProductionSignerError::ProviderSubstitution);
        }
        if self.algorithm != ECDSA_P256_SHA256 {
            return Err(ProductionSignerError::AlgorithmSubstitution);
        }
        if self.public_key_encoding != SEC1_UNCOMPRESSED_P256 {
            return Err(ProductionSignerError::PublicKeyEncodingSubstitution);
        }
        if self.signature_encoding != P1363_FIXED_64 {
            return Err(ProductionSignerError::SignatureEncodingSubstitution);
        }
        if self.export_policy != NON_EXPORTABLE_POLICY {
            return Err(ProductionSignerError::ExportPolicySubstitution);
        }
        if !self.require_hardware_backing {
            return Err(ProductionSignerError::HardwareRequirementDisabled);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ProductionSignerError> {
        self.validate()?;
        digest_value(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareKeyDescriptor {
    pub identity: ProductionKeyIdentity,
    pub provider: String,
    pub algorithm: String,
    pub public_key_encoding: String,
    pub public_key_base64url: String,
    pub public_key_digest: String,
    pub signature_encoding: String,
    pub export_policy: String,
    pub provider_implementation_flags: u32,
    pub assurance: HardwareAssurance,
    pub policy_digest: String,
}

impl HardwareKeyDescriptor {
    pub fn validate_for(&self, policy: &ProductionKeyPolicy) -> Result<(), ProductionSignerError> {
        policy.validate()?;
        self.identity.validate()?;
        if self.identity != policy.identity {
            return Err(ProductionSignerError::IdentitySubstitution);
        }
        if self.provider != policy.provider {
            return Err(ProductionSignerError::ProviderSubstitution);
        }
        if self.algorithm != policy.algorithm {
            return Err(ProductionSignerError::AlgorithmSubstitution);
        }
        if self.public_key_encoding != policy.public_key_encoding {
            return Err(ProductionSignerError::PublicKeyEncodingSubstitution);
        }
        if self.signature_encoding != policy.signature_encoding {
            return Err(ProductionSignerError::SignatureEncodingSubstitution);
        }
        if self.export_policy != policy.export_policy {
            return Err(ProductionSignerError::ExportPolicySubstitution);
        }
        validate_sha256(&self.public_key_digest)?;
        validate_sha256(&self.policy_digest)?;
        if self.public_key_base64url.is_empty() {
            return Err(ProductionSignerError::PublicKeyMissing);
        }
        if self.policy_digest != policy.digest()? {
            return Err(ProductionSignerError::PolicyDigestMismatch);
        }
        if self.assurance != HardwareAssurance::ProvenHardwareBacked {
            return Err(ProductionSignerError::HardwareAssuranceUnproven);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ProductionSignerError> {
        validate_sha256(&self.public_key_digest)?;
        validate_sha256(&self.policy_digest)?;
        digest_value(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedCallerIdentity {
    pub schema_version: String,
    pub process_id: u32,
    pub process_creation_time_100ns: u64,
    pub principal_sid: String,
    pub session_id: u32,
    pub executable_path: String,
    pub executable_sha256: String,
}

impl AuthenticatedCallerIdentity {
    pub fn validate(&self) -> Result<(), ProductionSignerError> {
        if self.schema_version != AUTHENTICATED_CALLER_SCHEMA {
            return Err(ProductionSignerError::UnsupportedCallerSchema);
        }
        if self.process_id == 0 || self.process_creation_time_100ns == 0 {
            return Err(ProductionSignerError::InvalidProcessIdentity);
        }
        if self.principal_sid.len() < 4 || !self.principal_sid.starts_with("S-") {
            return Err(ProductionSignerError::InvalidPrincipalSid);
        }
        if self.executable_path.trim().is_empty() {
            return Err(ProductionSignerError::ExecutablePathMissing);
        }
        validate_sha256(&self.executable_sha256)
    }

    pub fn digest(&self) -> Result<String, ProductionSignerError> {
        self.validate()?;
        digest_value(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerServiceIdentity {
    pub schema_version: String,
    pub service_id: String,
    pub instance_nonce: String,
    pub process_id: u32,
    pub process_creation_time_100ns: u64,
    pub executable_sha256: String,
    pub started_at_epoch_s: u64,
}

impl SignerServiceIdentity {
    pub fn validate(&self) -> Result<(), ProductionSignerError> {
        if self.schema_version != SIGNER_SERVICE_IDENTITY_SCHEMA {
            return Err(ProductionSignerError::UnsupportedServiceSchema);
        }
        validate_identifier("service_id", &self.service_id)?;
        if self.instance_nonce.len() < 32 {
            return Err(ProductionSignerError::ServiceInstanceNonceTooShort);
        }
        if self.process_id == 0 || self.process_creation_time_100ns == 0 {
            return Err(ProductionSignerError::InvalidProcessIdentity);
        }
        validate_sha256(&self.executable_sha256)?;
        if self.started_at_epoch_s == 0 {
            return Err(ProductionSignerError::InvalidServiceStartTime);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ProductionSignerError> {
        self.validate()?;
        digest_value(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerRequestBinding {
    pub schema_version: String,
    pub request_digest: String,
    pub caller_identity_digest: String,
    pub signer_service_identity_digest: String,
    pub key_policy_digest: String,
}

impl SignerRequestBinding {
    pub fn build(
        request_digest: impl Into<String>,
        caller: &AuthenticatedCallerIdentity,
        service: &SignerServiceIdentity,
        policy: &ProductionKeyPolicy,
    ) -> Result<Self, ProductionSignerError> {
        let binding = Self {
            schema_version: SIGNER_REQUEST_BINDING_SCHEMA.to_owned(),
            request_digest: request_digest.into(),
            caller_identity_digest: caller.digest()?,
            signer_service_identity_digest: service.digest()?,
            key_policy_digest: policy.digest()?,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), ProductionSignerError> {
        if self.schema_version != SIGNER_REQUEST_BINDING_SCHEMA {
            return Err(ProductionSignerError::UnsupportedBindingSchema);
        }
        validate_sha256(&self.request_digest)?;
        validate_sha256(&self.caller_identity_digest)?;
        validate_sha256(&self.signer_service_identity_digest)?;
        validate_sha256(&self.key_policy_digest)
    }

    pub fn digest(&self) -> Result<String, ProductionSignerError> {
        self.validate()?;
        digest_value(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningReceipt {
    pub schema_version: String,
    pub identity: ProductionKeyIdentity,
    pub provider: String,
    pub algorithm: String,
    pub public_key_encoding: String,
    pub public_key_base64url: String,
    pub public_key_digest: String,
    pub signature_encoding: String,
    pub export_policy: String,
    pub provider_implementation_flags: u32,
    pub assurance: HardwareAssurance,
    pub policy_digest: String,
    pub provisioned_at_epoch_s: u64,
    pub receipt_digest: String,
}

impl ProvisioningReceipt {
    pub fn from_descriptor(
        descriptor: HardwareKeyDescriptor,
        provisioned_at_epoch_s: u64,
    ) -> Result<Self, ProductionSignerError> {
        if provisioned_at_epoch_s == 0 {
            return Err(ProductionSignerError::InvalidProvisioningTime);
        }
        let mut receipt = Self {
            schema_version: PROVISIONING_RECEIPT_SCHEMA.to_owned(),
            identity: descriptor.identity,
            provider: descriptor.provider,
            algorithm: descriptor.algorithm,
            public_key_encoding: descriptor.public_key_encoding,
            public_key_base64url: descriptor.public_key_base64url,
            public_key_digest: descriptor.public_key_digest,
            signature_encoding: descriptor.signature_encoding,
            export_policy: descriptor.export_policy,
            provider_implementation_flags: descriptor.provider_implementation_flags,
            assurance: descriptor.assurance,
            policy_digest: descriptor.policy_digest,
            provisioned_at_epoch_s,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        Ok(receipt)
    }

    pub fn validate_for(&self, policy: &ProductionKeyPolicy) -> Result<(), ProductionSignerError> {
        if self.schema_version != PROVISIONING_RECEIPT_SCHEMA {
            return Err(ProductionSignerError::UnsupportedProvisioningReceiptSchema);
        }
        let descriptor = HardwareKeyDescriptor {
            identity: self.identity.clone(),
            provider: self.provider.clone(),
            algorithm: self.algorithm.clone(),
            public_key_encoding: self.public_key_encoding.clone(),
            public_key_base64url: self.public_key_base64url.clone(),
            public_key_digest: self.public_key_digest.clone(),
            signature_encoding: self.signature_encoding.clone(),
            export_policy: self.export_policy.clone(),
            provider_implementation_flags: self.provider_implementation_flags,
            assurance: self.assurance,
            policy_digest: self.policy_digest.clone(),
        };
        descriptor.validate_for(policy)?;
        if self.provisioned_at_epoch_s == 0 {
            return Err(ProductionSignerError::InvalidProvisioningTime);
        }
        if self.receipt_digest != self.expected_digest()? {
            return Err(ProductionSignerError::ProvisioningReceiptDigestMismatch);
        }
        if contains_secret_shaped_field(&serde_json::to_value(self)?) {
            return Err(ProductionSignerError::SecretShapedProvisioningMaterial);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionSignerError> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(ProductionSignerError::InvalidCanonicalObject)?;
        object.insert("receipt_digest".to_owned(), Value::String(String::new()));
        Ok(canonical_json_sha256(&value)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareSignature {
    pub identity: ProductionKeyIdentity,
    pub algorithm: String,
    pub signature_encoding: String,
    pub digest_algorithm: String,
    pub digest: String,
    pub signature_base64url: String,
    pub public_key_digest: String,
    pub key_policy_digest: String,
    pub request_binding_digest: String,
}

impl HardwareSignature {
    pub fn validate_for(
        &self,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
    ) -> Result<(), ProductionSignerError> {
        if self.identity != descriptor.identity {
            return Err(ProductionSignerError::IdentitySubstitution);
        }
        if self.algorithm != descriptor.algorithm {
            return Err(ProductionSignerError::AlgorithmSubstitution);
        }
        if self.signature_encoding != descriptor.signature_encoding {
            return Err(ProductionSignerError::SignatureEncodingSubstitution);
        }
        if self.digest_algorithm != "sha256" {
            return Err(ProductionSignerError::DigestAlgorithmSubstitution);
        }
        validate_sha256(&self.digest)?;
        if self.signature_base64url.is_empty() {
            return Err(ProductionSignerError::SignatureMissing);
        }
        if self.public_key_digest != descriptor.public_key_digest {
            return Err(ProductionSignerError::PublicKeyDigestMismatch);
        }
        if self.key_policy_digest != descriptor.policy_digest {
            return Err(ProductionSignerError::PolicyDigestMismatch);
        }
        if self.request_binding_digest != binding.digest()? {
            return Err(ProductionSignerError::RequestBindingDigestMismatch);
        }
        Ok(())
    }
}

pub trait ProductionKeyProvider {
    fn describe_or_provision(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<HardwareKeyDescriptor, ProductionSignerError>;

    fn sign_sha256_digest(
        &self,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, ProductionSignerError>;
}

pub fn validate_identifier(field: &'static str, value: &str) -> Result<(), ProductionSignerError> {
    let valid_length = (3..=128).contains(&value.len());
    let mut chars = value.chars();
    let starts_valid = chars
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric());
    let remaining_valid = chars
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'));
    if !valid_length || !starts_valid || !remaining_valid {
        return Err(ProductionSignerError::InvalidIdentifier(field));
    }
    Ok(())
}

pub fn validate_sha256(value: &str) -> Result<(), ProductionSignerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProductionSignerError::InvalidSha256);
    }
    Ok(())
}

fn digest_value<T: Serialize>(value: &T) -> Result<String, ProductionSignerError> {
    let value = serde_json::to_value(value)?;
    Ok(canonical_json_sha256(&value)?)
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

#[derive(Debug, Error)]
pub enum ProductionSignerError {
    #[error("production signer identifier is invalid: {0}")]
    InvalidIdentifier(&'static str),
    #[error("value is not lowercase SHA-256")]
    InvalidSha256,
    #[error("production key role is not yet supported")]
    UnsupportedProductionRole,
    #[error("production key identity is not one of the fixed issuer identities")]
    UnsupportedProductionIdentity,
    #[error("production signer policy schema is unsupported")]
    UnsupportedPolicySchema,
    #[error("production signer provider was substituted")]
    ProviderSubstitution,
    #[error("production signer algorithm was substituted")]
    AlgorithmSubstitution,
    #[error("production public-key encoding was substituted")]
    PublicKeyEncodingSubstitution,
    #[error("production signature encoding was substituted")]
    SignatureEncodingSubstitution,
    #[error("production key export policy was substituted")]
    ExportPolicySubstitution,
    #[error("production hardware requirement was disabled")]
    HardwareRequirementDisabled,
    #[error("production key identity was substituted")]
    IdentitySubstitution,
    #[error("production public key is missing")]
    PublicKeyMissing,
    #[error("production public-key digest does not match")]
    PublicKeyDigestMismatch,
    #[error("production key policy digest does not match")]
    PolicyDigestMismatch,
    #[error("hardware-backed assurance is not independently proven")]
    HardwareAssuranceUnproven,
    #[error("authenticated caller schema is unsupported")]
    UnsupportedCallerSchema,
    #[error("caller or service process identity is invalid")]
    InvalidProcessIdentity,
    #[error("caller Windows principal SID is invalid")]
    InvalidPrincipalSid,
    #[error("caller executable path is missing")]
    ExecutablePathMissing,
    #[error("signer-service identity schema is unsupported")]
    UnsupportedServiceSchema,
    #[error("signer-service instance nonce is too short")]
    ServiceInstanceNonceTooShort,
    #[error("signer-service start time is invalid")]
    InvalidServiceStartTime,
    #[error("signer request binding schema is unsupported")]
    UnsupportedBindingSchema,
    #[error("provisioning receipt schema is unsupported")]
    UnsupportedProvisioningReceiptSchema,
    #[error("provisioning time is invalid")]
    InvalidProvisioningTime,
    #[error("provisioning receipt digest does not match")]
    ProvisioningReceiptDigestMismatch,
    #[error("provisioning receipt contains secret-shaped material")]
    SecretShapedProvisioningMaterial,
    #[error("hardware signature digest algorithm was substituted")]
    DigestAlgorithmSubstitution,
    #[error("hardware signature is missing")]
    SignatureMissing,
    #[error("signer request binding digest does not match")]
    RequestBindingDigestMismatch,
    #[error("canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("production signer JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}
