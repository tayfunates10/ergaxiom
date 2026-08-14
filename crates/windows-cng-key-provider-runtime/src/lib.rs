#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod windows;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_windows_production_signer_runtime::{
    ECDSA_P256_SHA256, HardwareAssurance, HardwareKeyDescriptor, HardwareSignature,
    MICROSOFT_PLATFORM_CRYPTO_PROVIDER, NON_EXPORTABLE_POLICY, P1363_FIXED_64, ProductionKeyPolicy,
    ProductionSignerError, SEC1_UNCOMPRESSED_P256, SignerRequestBinding, validate_sha256,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const KEY_NAME_PREFIX: &str = "Ergaxiom.Production";
const GENERATION_SEPARATOR: &str = ".g";
const GENERATION_WIDTH: usize = 20;
const SHA256_DIGEST_BYTES: usize = 32;
const P256_PUBLIC_KEY_BYTES: usize = 65;
const P256_SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CngProviderProbe {
    pub provider: String,
    pub implementation_flags: u32,
    pub hardware_flag_present: bool,
    pub software_flag_present: bool,
    pub assurance: HardwareAssurance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CngProvisioningResult {
    pub key_name: String,
    pub created: bool,
    pub descriptor: HardwareKeyDescriptor,
}

#[cfg(feature = "provisioning")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CngKeyPossessionSignature {
    pub digest_algorithm: String,
    pub digest: String,
    pub signature_encoding: String,
    pub signature_base64url: String,
    pub public_key_digest: String,
    pub key_policy_digest: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CngPlatformKeyProvider;

impl CngPlatformKeyProvider {
    #[must_use]
    pub const fn production() -> Self {
        Self
    }

    pub fn key_name_for(policy: &ProductionKeyPolicy) -> Result<String, CngProviderError> {
        Self::key_name_for_generation(policy, 1)
    }

    pub fn key_name_for_generation(
        policy: &ProductionKeyPolicy,
        generation: u64,
    ) -> Result<String, CngProviderError> {
        policy.validate()?;
        if generation == 0 {
            return Err(CngProviderError::InvalidKeyGeneration);
        }
        let identity_digest = policy.identity.digest()?;
        let base = format!("{KEY_NAME_PREFIX}.{identity_digest}");
        if generation == 1 {
            Ok(base)
        } else {
            Ok(format!("{base}{GENERATION_SEPARATOR}{generation:020}"))
        }
    }

    pub fn generation_from_key_name(
        policy: &ProductionKeyPolicy,
        key_name: &str,
    ) -> Result<u64, CngProviderError> {
        policy.validate()?;
        let generation_one = Self::key_name_for(policy)?;
        if key_name == generation_one {
            return Ok(1);
        }
        let prefix = format!("{generation_one}{GENERATION_SEPARATOR}");
        let suffix = key_name
            .strip_prefix(&prefix)
            .ok_or(CngProviderError::InvalidKeyGenerationName)?;
        if suffix.len() != GENERATION_WIDTH || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CngProviderError::InvalidKeyGenerationName);
        }
        let generation = suffix
            .parse::<u64>()
            .map_err(|_| CngProviderError::InvalidKeyGenerationName)?;
        if generation < 2 || Self::key_name_for_generation(policy, generation)? != key_name {
            return Err(CngProviderError::InvalidKeyGenerationName);
        }
        Ok(generation)
    }

    pub fn probe(&self) -> Result<CngProviderProbe, CngProviderError> {
        platform::probe()
    }

    pub fn describe_existing_unverified(
        &self,
        policy: &ProductionKeyPolicy,
        expected_public_key_digest: Option<&str>,
    ) -> Result<CngProvisioningResult, CngProviderError> {
        self.describe_existing_generation_unverified(policy, 1, expected_public_key_digest)
    }

    pub fn describe_existing_generation_unverified(
        &self,
        policy: &ProductionKeyPolicy,
        generation: u64,
        expected_public_key_digest: Option<&str>,
    ) -> Result<CngProvisioningResult, CngProviderError> {
        policy.validate()?;
        validate_expected_digest(expected_public_key_digest)?;
        let key_name = Self::key_name_for_generation(policy, generation)?;
        let native = platform::describe_existing(&key_name)?;
        build_result(policy, key_name, native, expected_public_key_digest)
    }

    #[cfg(feature = "provisioning")]
    pub fn provision_unverified(
        &self,
        policy: &ProductionKeyPolicy,
        expected_public_key_digest: Option<&str>,
    ) -> Result<CngProvisioningResult, CngProviderError> {
        self.provision_generation_unverified(policy, 1, expected_public_key_digest)
    }

    #[cfg(feature = "provisioning")]
    pub fn provision_generation_unverified(
        &self,
        policy: &ProductionKeyPolicy,
        generation: u64,
        expected_public_key_digest: Option<&str>,
    ) -> Result<CngProvisioningResult, CngProviderError> {
        policy.validate()?;
        validate_expected_digest(expected_public_key_digest)?;
        let key_name = Self::key_name_for_generation(policy, generation)?;
        let native = platform::provision(&key_name)?;
        build_result(policy, key_name, native, expected_public_key_digest)
    }

    pub fn sign_sha256_digest_unverified(
        &self,
        policy: &ProductionKeyPolicy,
        provisioning: &CngProvisioningResult,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, CngProviderError> {
        policy.validate()?;
        binding.validate()?;
        validate_sha256(digest)?;
        validate_key_binding(policy, provisioning)?;
        let digest_bytes = decode_sha256(digest)?;
        let signature = platform::sign(&provisioning.key_name, &digest_bytes)?;
        validate_signature_length(&signature)?;
        Ok(HardwareSignature {
            identity: policy.identity.clone(),
            algorithm: ECDSA_P256_SHA256.to_owned(),
            signature_encoding: P1363_FIXED_64.to_owned(),
            digest_algorithm: "sha256".to_owned(),
            digest: digest.to_owned(),
            signature_base64url: URL_SAFE_NO_PAD.encode(signature),
            public_key_digest: provisioning.descriptor.public_key_digest.clone(),
            key_policy_digest: provisioning.descriptor.policy_digest.clone(),
            request_binding_digest: binding.digest()?,
        })
    }

    #[cfg(feature = "provisioning")]
    pub fn sign_key_possession_sha256_digest_unverified(
        &self,
        policy: &ProductionKeyPolicy,
        provisioning: &CngProvisioningResult,
        digest: &str,
    ) -> Result<CngKeyPossessionSignature, CngProviderError> {
        policy.validate()?;
        validate_sha256(digest)?;
        validate_key_binding(policy, provisioning)?;
        let digest_bytes = decode_sha256(digest)?;
        let signature = platform::sign(&provisioning.key_name, &digest_bytes)?;
        validate_signature_length(&signature)?;
        Ok(CngKeyPossessionSignature {
            digest_algorithm: "sha256".to_owned(),
            digest: digest.to_owned(),
            signature_encoding: P1363_FIXED_64.to_owned(),
            signature_base64url: URL_SAFE_NO_PAD.encode(signature),
            public_key_digest: provisioning.descriptor.public_key_digest.clone(),
            key_policy_digest: provisioning.descriptor.policy_digest.clone(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct NativeProvisioning {
    pub created: bool,
    pub provider_implementation_flags: u32,
    pub public_blob: Vec<u8>,
}

fn build_result(
    policy: &ProductionKeyPolicy,
    key_name: String,
    native: NativeProvisioning,
    expected_public_key_digest: Option<&str>,
) -> Result<CngProvisioningResult, CngProviderError> {
    let public_key = parse_p256_public_blob(&native.public_blob)?;
    let public_key_digest = lowercase_sha256(&public_key);
    if expected_public_key_digest.is_some_and(|expected| expected != public_key_digest) {
        return Err(CngProviderError::ExistingPublicKeyMismatch);
    }
    Ok(CngProvisioningResult {
        key_name,
        created: native.created,
        descriptor: HardwareKeyDescriptor {
            identity: policy.identity.clone(),
            provider: MICROSOFT_PLATFORM_CRYPTO_PROVIDER.to_owned(),
            algorithm: ECDSA_P256_SHA256.to_owned(),
            public_key_encoding: SEC1_UNCOMPRESSED_P256.to_owned(),
            public_key_base64url: URL_SAFE_NO_PAD.encode(public_key),
            public_key_digest,
            signature_encoding: P1363_FIXED_64.to_owned(),
            export_policy: NON_EXPORTABLE_POLICY.to_owned(),
            provider_implementation_flags: native.provider_implementation_flags,
            assurance: HardwareAssurance::Unproven,
            policy_digest: policy.digest()?,
        },
    })
}

fn validate_expected_digest(expected: Option<&str>) -> Result<(), CngProviderError> {
    if let Some(expected) = expected {
        validate_sha256(expected)?;
    }
    Ok(())
}

fn validate_key_binding(
    policy: &ProductionKeyPolicy,
    provisioning: &CngProvisioningResult,
) -> Result<(), CngProviderError> {
    CngPlatformKeyProvider::generation_from_key_name(policy, &provisioning.key_name)?;
    if provisioning.descriptor.identity != policy.identity
        || provisioning.descriptor.provider != MICROSOFT_PLATFORM_CRYPTO_PROVIDER
        || provisioning.descriptor.algorithm != ECDSA_P256_SHA256
        || provisioning.descriptor.public_key_encoding != SEC1_UNCOMPRESSED_P256
        || provisioning.descriptor.signature_encoding != P1363_FIXED_64
        || provisioning.descriptor.export_policy != NON_EXPORTABLE_POLICY
        || provisioning.descriptor.policy_digest != policy.digest()?
    {
        return Err(CngProviderError::ProvisioningBindingMismatch);
    }
    Ok(())
}

fn validate_signature_length(signature: &[u8]) -> Result<(), CngProviderError> {
    if signature.len() != P256_SIGNATURE_BYTES {
        return Err(CngProviderError::InvalidSignatureLength(signature.len()));
    }
    Ok(())
}

fn parse_p256_public_blob(blob: &[u8]) -> Result<[u8; P256_PUBLIC_KEY_BYTES], CngProviderError> {
    const HEADER_BYTES: usize = 8;
    const COORDINATE_BYTES: usize = 32;
    if blob.len() != HEADER_BYTES + (2 * COORDINATE_BYTES) {
        return Err(CngProviderError::InvalidPublicBlobLength(blob.len()));
    }
    let magic = u32::from_le_bytes(
        blob[0..4]
            .try_into()
            .map_err(|_| CngProviderError::InvalidPublicBlob)?,
    );
    let key_bytes = u32::from_le_bytes(
        blob[4..8]
            .try_into()
            .map_err(|_| CngProviderError::InvalidPublicBlob)?,
    );
    if magic != platform::ecdsa_p256_public_magic() || key_bytes != COORDINATE_BYTES as u32 {
        return Err(CngProviderError::InvalidPublicBlob);
    }
    let mut public_key = [0_u8; P256_PUBLIC_KEY_BYTES];
    public_key[0] = 0x04;
    public_key[1..].copy_from_slice(&blob[HEADER_BYTES..]);
    Ok(public_key)
}

fn lowercase_sha256(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn decode_sha256(value: &str) -> Result<[u8; SHA256_DIGEST_BYTES], CngProviderError> {
    validate_sha256(value)?;
    let mut bytes = [0_u8; SHA256_DIGEST_BYTES];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble(chunk[0])? << 4) | decode_nibble(chunk[1])?;
    }
    Ok(bytes)
}

fn decode_nibble(value: u8) -> Result<u8, CngProviderError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CngProviderError::InvalidDigestEncoding),
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

#[cfg(windows)]
mod platform {
    #[cfg(feature = "provisioning")]
    pub use crate::windows::provision;
    pub use crate::windows::{describe_existing, ecdsa_p256_public_magic, probe, sign};
}

#[cfg(not(windows))]
mod platform {
    use crate::{CngProviderError, CngProviderProbe, NativeProvisioning};

    pub fn probe() -> Result<CngProviderProbe, CngProviderError> {
        Err(CngProviderError::UnsupportedPlatform)
    }

    pub fn describe_existing(_key_name: &str) -> Result<NativeProvisioning, CngProviderError> {
        Err(CngProviderError::UnsupportedPlatform)
    }

    #[cfg(feature = "provisioning")]
    pub fn provision(_key_name: &str) -> Result<NativeProvisioning, CngProviderError> {
        Err(CngProviderError::UnsupportedPlatform)
    }

    pub fn sign(_key_name: &str, _digest: &[u8; 32]) -> Result<Vec<u8>, CngProviderError> {
        Err(CngProviderError::UnsupportedPlatform)
    }

    pub const fn ecdsa_p256_public_magic() -> u32 {
        0x3153_4345
    }
}

#[derive(Debug, Error)]
pub enum CngProviderError {
    #[error("Windows CNG is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("production signer policy is invalid: {0}")]
    Policy(#[from] ProductionSignerError),
    #[error("production CNG key generation must be greater than zero")]
    InvalidKeyGeneration,
    #[error("persisted CNG key name does not contain a canonical generation")]
    InvalidKeyGenerationName,
    #[error("Microsoft Platform Crypto Provider could not be opened: 0x{0:08x}")]
    ProviderOpenFailed(i32),
    #[error("CNG provider implementation flags could not be read: 0x{0:08x}")]
    ProviderPropertyReadFailed(i32),
    #[error("CNG provider does not report hardware-backed implementation")]
    ProviderNotHardwareBacked,
    #[error("CNG provider reports software implementation")]
    ProviderReportedSoftware,
    #[error("persisted CNG key could not be opened: 0x{0:08x}")]
    KeyOpenFailed(i32),
    #[error("persisted CNG key could not be created: 0x{0:08x}")]
    KeyCreateFailed(i32),
    #[error("CNG key property {property} could not be set: 0x{status:08x}")]
    KeyPropertySetFailed { property: &'static str, status: i32 },
    #[error("CNG key could not be finalized: 0x{0:08x}")]
    KeyFinalizeFailed(i32),
    #[error("CNG key property {property} could not be read: 0x{status:08x}")]
    KeyPropertyReadFailed { property: &'static str, status: i32 },
    #[error("CNG key export policy is not non-exportable")]
    KeyIsExportable,
    #[error("CNG key usage is not signing-only")]
    KeyUsageMismatch,
    #[error("CNG public key could not be exported: 0x{0:08x}")]
    PublicKeyExportFailed(i32),
    #[error("CNG public-key blob length is invalid: {0}")]
    InvalidPublicBlobLength(usize),
    #[error("CNG public-key blob is invalid")]
    InvalidPublicBlob,
    #[error("existing CNG public key does not match the expected digest")]
    ExistingPublicKeyMismatch,
    #[error("CNG provisioning result does not match the requested policy")]
    ProvisioningBindingMismatch,
    #[error("SHA-256 digest encoding is invalid")]
    InvalidDigestEncoding,
    #[error("CNG signing failed: 0x{0:08x}")]
    SignFailed(i32),
    #[error("CNG signature length is invalid: {0}")]
    InvalidSignatureLength(usize),
}
