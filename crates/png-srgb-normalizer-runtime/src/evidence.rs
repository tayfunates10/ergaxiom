use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ergaxiom_png_artifact_validator_runtime::{PngColorProfileEvidence, inspect_png};
use ergaxiom_proof_kernel::{HashingError, canonical_json_bytes, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PngSrgbNormalizationError, PngSrgbNormalizationRecord, PngSrgbNormalizationRequest,
    inspect_svg_srgb,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NormalizationSignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NormalizationSignatureEncoding {
    Base64url,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationSignature {
    pub issuer_id: String,
    pub key_id: String,
    pub algorithm: NormalizationSignatureAlgorithm,
    pub encoding: NormalizationSignatureEncoding,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPngSrgbNormalizationRecord {
    pub record: PngSrgbNormalizationRecord,
    pub signature: NormalizationSignature,
}

#[derive(Debug, Clone)]
pub struct PngSrgbNormalizationMaterial<'a> {
    pub request: &'a PngSrgbNormalizationRequest,
    pub package: &'a SignedPngSrgbNormalizationRecord,
    pub source_svg: &'a Path,
    pub input_png: &'a Path,
    pub output_png: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedPngSrgbNormalization {
    pub package_digest: String,
    pub record_digest: String,
    pub request_digest: String,
    pub source_svg_digest: String,
    pub input_png_digest: String,
    pub output_png_digest: String,
    pub input_idat_payload_digest: String,
    pub output_idat_payload_digest: String,
    pub rendering_intent: crate::SrgbRenderingIntent,
    pub inserted_srgb_crc32: String,
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    pub issuer_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct NormalizationKeyRegistry {
    keys: BTreeMap<(String, String), VerifyingKey>,
}

impl NormalizationKeyRegistry {
    pub fn insert_ed25519(
        &mut self,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<(), NormalizationEvidenceError> {
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| NormalizationEvidenceError::InvalidTrustedKey)?;
        self.keys.insert((issuer_id.into(), key_id.into()), key);
        Ok(())
    }

    fn get(&self, issuer_id: &str, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(&(issuer_id.to_owned(), key_id.to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum NormalizationEvidenceError {
    #[error("normalization record is not verified")]
    RecordNotVerified,
    #[error("normalization record digest does not reproduce")]
    RecordDigestMismatch,
    #[error("normalization request digest does not reproduce")]
    RequestDigestMismatch,
    #[error("normalization request and record are not bound")]
    RequestRecordBindingMismatch,
    #[error("trusted normalization key is invalid")]
    InvalidTrustedKey,
    #[error("unknown normalization key {issuer_id}/{key_id}")]
    UnknownTrustedKey { issuer_id: String, key_id: String },
    #[error("normalization signature metadata is unsupported")]
    UnsupportedSignatureMetadata,
    #[error("normalization signature is not valid base64url")]
    InvalidSignatureEncoding,
    #[error("normalization signature has an invalid Ed25519 length")]
    InvalidSignatureLength,
    #[error("normalization signature verification failed")]
    SignatureVerificationFailed,
    #[error("normalization material path mismatch: {0}")]
    MaterialPathMismatch(&'static str),
    #[error("source SVG evidence does not reproduce")]
    SourceEvidenceMismatch,
    #[error("input PNG digest does not reproduce")]
    InputDigestMismatch,
    #[error("output PNG digest does not reproduce")]
    OutputDigestMismatch,
    #[error("input PNG report digest does not reproduce")]
    InputReportMismatch,
    #[error("output PNG report digest does not reproduce")]
    OutputReportMismatch,
    #[error("input PNG unexpectedly contains profile evidence")]
    InputProfileMismatch,
    #[error("output PNG sRGB evidence does not match the record")]
    OutputProfileMismatch,
    #[error("IDAT payload digest does not reproduce")]
    IdatDigestMismatch,
    #[error("normalization did not preserve IDAT payload bytes")]
    IdatMutation,
    #[error("failed to serialize normalization evidence: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Normalizer(#[from] PngSrgbNormalizationError),
    #[error(transparent)]
    Png(#[from] ergaxiom_png_artifact_validator_runtime::PngArtifactError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn sign_normalization_record(
    record: &PngSrgbNormalizationRecord,
    issuer_id: impl Into<String>,
    key_id: impl Into<String>,
    signing_key: &SigningKey,
) -> Result<SignedPngSrgbNormalizationRecord, NormalizationEvidenceError> {
    validate_record_digest(record)?;
    if !record.verified {
        return Err(NormalizationEvidenceError::RecordNotVerified);
    }
    let issuer_id = issuer_id.into();
    let key_id = key_id.into();
    let value = serde_json::to_value(record).map_err(NormalizationEvidenceError::Serialization)?;
    let signature = signing_key.sign(&canonical_json_bytes(&value)?);
    Ok(SignedPngSrgbNormalizationRecord {
        record: record.clone(),
        signature: NormalizationSignature {
            issuer_id,
            key_id,
            algorithm: NormalizationSignatureAlgorithm::Ed25519,
            encoding: NormalizationSignatureEncoding::Base64url,
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })
}

pub fn verify_normalization_material(
    material: &PngSrgbNormalizationMaterial<'_>,
    keys: &NormalizationKeyRegistry,
) -> Result<VerifiedPngSrgbNormalization, NormalizationEvidenceError> {
    let record = &material.package.record;
    if !record.verified {
        return Err(NormalizationEvidenceError::RecordNotVerified);
    }
    verify_signature(material.package, keys)?;
    validate_record_digest(record)?;

    let request_value = serde_json::to_value(material.request)
        .map_err(NormalizationEvidenceError::Serialization)?;
    let request_digest = canonical_json_sha256(&request_value)?;
    if request_digest != record.request_digest {
        return Err(NormalizationEvidenceError::RequestDigestMismatch);
    }
    if material.request.request_id != record.request_id
        || material.request.rendering_intent != record.rendering_intent
    {
        return Err(NormalizationEvidenceError::RequestRecordBindingMismatch);
    }
    require_same_file(
        &material.request.source_svg,
        material.source_svg,
        "source_svg",
    )?;
    require_same_file(&material.request.input_png, material.input_png, "input_png")?;
    require_same_file(
        &material.request.output_png,
        material.output_png,
        "output_png",
    )?;

    let source_evidence = inspect_svg_srgb(material.source_svg)?;
    if source_evidence != record.source_svg_evidence
        || source_evidence.source_digest != material.request.expected_source_svg_digest
    {
        return Err(NormalizationEvidenceError::SourceEvidenceMismatch);
    }

    let input_bytes = fs::read(material.input_png)?;
    let output_bytes = fs::read(material.output_png)?;
    let input_digest = format!("{:x}", Sha256::digest(&input_bytes));
    let output_digest = format!("{:x}", Sha256::digest(&output_bytes));
    if input_digest != record.input_png_digest
        || input_digest != material.request.expected_input_png_digest
    {
        return Err(NormalizationEvidenceError::InputDigestMismatch);
    }
    if output_digest != record.output_png_digest {
        return Err(NormalizationEvidenceError::OutputDigestMismatch);
    }

    let input_report = inspect_png(material.input_png)?;
    let output_report = inspect_png(material.output_png)?;
    if input_report.report_digest != record.input_report_digest {
        return Err(NormalizationEvidenceError::InputReportMismatch);
    }
    if output_report.report_digest != record.output_report_digest {
        return Err(NormalizationEvidenceError::OutputReportMismatch);
    }
    if !matches!(input_report.color_profile, PngColorProfileEvidence::None) {
        return Err(NormalizationEvidenceError::InputProfileMismatch);
    }
    if output_report.color_profile
        != (PngColorProfileEvidence::Srgb {
            rendering_intent: record.rendering_intent.png_value(),
        })
        || output_report.width != record.width
        || output_report.height != record.height
        || output_report.bit_depth != record.bit_depth
    {
        return Err(NormalizationEvidenceError::OutputProfileMismatch);
    }

    let input_idat = idat_digest(&input_bytes)?;
    let output_idat = idat_digest(&output_bytes)?;
    if input_idat != record.input_idat_payload_digest
        || output_idat != record.output_idat_payload_digest
    {
        return Err(NormalizationEvidenceError::IdatDigestMismatch);
    }
    if input_idat != output_idat {
        return Err(NormalizationEvidenceError::IdatMutation);
    }

    let package_value = serde_json::to_value(material.package)
        .map_err(NormalizationEvidenceError::Serialization)?;
    Ok(VerifiedPngSrgbNormalization {
        package_digest: canonical_json_sha256(&package_value)?,
        record_digest: record.record_digest.clone(),
        request_digest,
        source_svg_digest: source_evidence.source_digest,
        input_png_digest: input_digest,
        output_png_digest: output_digest,
        input_idat_payload_digest: input_idat,
        output_idat_payload_digest: output_idat,
        rendering_intent: record.rendering_intent,
        inserted_srgb_crc32: record.inserted_srgb_crc32.clone(),
        width: record.width,
        height: record.height,
        bit_depth: record.bit_depth,
        issuer_id: material.package.signature.issuer_id.clone(),
        key_id: material.package.signature.key_id.clone(),
    })
}

fn verify_signature(
    package: &SignedPngSrgbNormalizationRecord,
    keys: &NormalizationKeyRegistry,
) -> Result<(), NormalizationEvidenceError> {
    if package.signature.algorithm != NormalizationSignatureAlgorithm::Ed25519
        || package.signature.encoding != NormalizationSignatureEncoding::Base64url
    {
        return Err(NormalizationEvidenceError::UnsupportedSignatureMetadata);
    }
    let key = keys
        .get(&package.signature.issuer_id, &package.signature.key_id)
        .ok_or_else(|| NormalizationEvidenceError::UnknownTrustedKey {
            issuer_id: package.signature.issuer_id.clone(),
            key_id: package.signature.key_id.clone(),
        })?;
    let bytes = URL_SAFE_NO_PAD
        .decode(&package.signature.value)
        .map_err(|_| NormalizationEvidenceError::InvalidSignatureEncoding)?;
    let signature = Signature::from_slice(&bytes)
        .map_err(|_| NormalizationEvidenceError::InvalidSignatureLength)?;
    let value =
        serde_json::to_value(&package.record).map_err(NormalizationEvidenceError::Serialization)?;
    key.verify_strict(&canonical_json_bytes(&value)?, &signature)
        .map_err(|_| NormalizationEvidenceError::SignatureVerificationFailed)
}

fn validate_record_digest(
    record: &PngSrgbNormalizationRecord,
) -> Result<(), NormalizationEvidenceError> {
    let mut value =
        serde_json::to_value(record).map_err(NormalizationEvidenceError::Serialization)?;
    let object = value.as_object_mut().ok_or_else(|| {
        NormalizationEvidenceError::Serialization(serde_json::Error::io(std::io::Error::other(
            "record did not serialize to an object",
        )))
    })?;
    object.insert("record_digest".to_owned(), Value::String(String::new()));
    if canonical_json_sha256(&value)? != record.record_digest {
        return Err(NormalizationEvidenceError::RecordDigestMismatch);
    }
    Ok(())
}

fn require_same_file(
    requested: &Path,
    supplied: &Path,
    field: &'static str,
) -> Result<(), NormalizationEvidenceError> {
    if fs::canonicalize(requested)? != fs::canonicalize(supplied)? {
        return Err(NormalizationEvidenceError::MaterialPathMismatch(field));
    }
    Ok(())
}

fn idat_digest(bytes: &[u8]) -> Result<String, NormalizationEvidenceError> {
    if bytes.len() < 8 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" {
        return Err(NormalizationEvidenceError::Png(
            ergaxiom_png_artifact_validator_runtime::PngArtifactError::InvalidSignature,
        ));
    }
    let mut offset = 8_usize;
    let mut hasher = Sha256::new();
    let mut found = false;
    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err(NormalizationEvidenceError::Png(
                ergaxiom_png_artifact_validator_runtime::PngArtifactError::TruncatedChunk,
            ));
        }
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().map_err(|_| {
            ergaxiom_png_artifact_validator_runtime::PngArtifactError::TruncatedChunk
        })?) as usize;
        let data_start = offset + 8;
        let data_end = data_start.checked_add(length).ok_or({
            NormalizationEvidenceError::Png(
                ergaxiom_png_artifact_validator_runtime::PngArtifactError::TruncatedChunk,
            )
        })?;
        let chunk_end = data_end.checked_add(4).ok_or({
            NormalizationEvidenceError::Png(
                ergaxiom_png_artifact_validator_runtime::PngArtifactError::TruncatedChunk,
            )
        })?;
        if chunk_end > bytes.len() {
            return Err(NormalizationEvidenceError::Png(
                ergaxiom_png_artifact_validator_runtime::PngArtifactError::TruncatedChunk,
            ));
        }
        if &bytes[offset + 4..offset + 8] == b"IDAT" {
            found = true;
            hasher.update(&bytes[data_start..data_end]);
        }
        offset = chunk_end;
    }
    if !found {
        return Err(NormalizationEvidenceError::IdatDigestMismatch);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
