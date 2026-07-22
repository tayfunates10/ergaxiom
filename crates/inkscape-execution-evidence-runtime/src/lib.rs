#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ergaxiom_inkscape_adapter_runtime::{
    InkscapeAdapterError, InkscapeExecutionRecord, SetTextAndExportRequest, SvgDocumentSnapshot,
    observe_svg, read_png_info, sha256_file,
};
use ergaxiom_proof_kernel::{HashingError, canonical_json_bytes, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const RECORD_SCHEMA: &str = "0.1.0";
const APPLICATION_ID: &str = "org.inkscape.Inkscape";
const MIN_SUPPORTED_MINOR: u32 = 2;
const MAX_SUPPORTED_MINOR: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InkscapeSignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InkscapeSignatureEncoding {
    Base64url,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InkscapeExecutionSignature {
    pub issuer_id: String,
    pub key_id: String,
    pub algorithm: InkscapeSignatureAlgorithm,
    pub encoding: InkscapeSignatureEncoding,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInkscapeExecutionRecord {
    pub record: InkscapeExecutionRecord,
    pub signature: InkscapeExecutionSignature,
}

#[derive(Debug, Clone)]
pub struct InkscapeExecutionMaterial<'a> {
    pub request: &'a SetTextAndExportRequest,
    pub package: &'a SignedInkscapeExecutionRecord,
    pub source_svg: &'a Path,
    pub editable_svg: &'a Path,
    pub raster_png: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedInkscapeExecution {
    pub package_digest: String,
    pub record_digest: String,
    pub request_digest: String,
    pub source_svg_digest: String,
    pub editable_svg_digest: String,
    pub raster_png_digest: String,
    pub pre_snapshot_digest: String,
    pub post_snapshot_digest: String,
    pub application_id: String,
    pub application_version: String,
    pub application_digest: String,
    pub target_element_id: String,
    pub replacement_text: String,
    pub export_width: u32,
    pub export_height: u32,
    pub issuer_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct InkscapeExecutionKeyRegistry {
    keys: BTreeMap<(String, String), VerifyingKey>,
}

impl InkscapeExecutionKeyRegistry {
    pub fn insert_ed25519(
        &mut self,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<(), InkscapeEvidenceError> {
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| InkscapeEvidenceError::InvalidTrustedKey)?;
        self.keys.insert((issuer_id.into(), key_id.into()), key);
        Ok(())
    }

    fn get(&self, issuer_id: &str, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(&(issuer_id.to_owned(), key_id.to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum InkscapeEvidenceError {
    #[error("required Inkscape evidence field is empty: {0}")]
    EmptyField(&'static str),
    #[error("trusted Inkscape execution key is invalid")]
    InvalidTrustedKey,
    #[error("unknown Inkscape execution key {issuer_id}/{key_id}")]
    UnknownTrustedKey { issuer_id: String, key_id: String },
    #[error("Inkscape execution signature metadata is unsupported")]
    UnsupportedSignatureMetadata,
    #[error("Inkscape execution signature is not valid base64url")]
    InvalidSignatureEncoding,
    #[error("Inkscape execution signature has an invalid Ed25519 length")]
    InvalidSignatureLength,
    #[error("Inkscape execution signature verification failed")]
    SignatureVerificationFailed,
    #[error("Inkscape execution record schema is unsupported")]
    UnsupportedRecordSchema,
    #[error("Inkscape execution record is not marked verified")]
    RecordNotVerified,
    #[error("Inkscape execution record digest does not reproduce")]
    RecordDigestMismatch,
    #[error("Inkscape execution request digest does not reproduce")]
    RequestDigestMismatch,
    #[error("Inkscape execution record does not match its request")]
    RequestRecordBindingMismatch,
    #[error("Inkscape binary identity is unsupported")]
    UnsupportedApplicationIdentity,
    #[error("Inkscape material path does not match the signed request path: {0}")]
    MaterialPathMismatch(&'static str),
    #[error("source SVG digest does not match the signed request and record")]
    SourceDigestMismatch,
    #[error("editable SVG digest does not match the execution record")]
    EditableDigestMismatch,
    #[error("raster PNG digest does not match the execution record")]
    RasterDigestMismatch,
    #[error("pre-execution SVG snapshot digest does not match the record")]
    PreSnapshotDigestMismatch,
    #[error("post-execution SVG snapshot digest does not match the record")]
    PostSnapshotDigestMismatch,
    #[error("SVG material changed outside the declared direct-text target")]
    UndeclaredSvgChange,
    #[error("raster PNG dimensions do not match the execution record")]
    RasterDimensionMismatch,
    #[error("failed to serialize Inkscape evidence material: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Adapter(#[from] InkscapeAdapterError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn sign_execution_record(
    record: &InkscapeExecutionRecord,
    issuer_id: impl Into<String>,
    key_id: impl Into<String>,
    signing_key: &SigningKey,
) -> Result<SignedInkscapeExecutionRecord, InkscapeEvidenceError> {
    validate_record_self_digest(record)?;
    let issuer_id = issuer_id.into();
    let key_id = key_id.into();
    if issuer_id.trim().is_empty() {
        return Err(InkscapeEvidenceError::EmptyField("issuer_id"));
    }
    if key_id.trim().is_empty() {
        return Err(InkscapeEvidenceError::EmptyField("key_id"));
    }
    let value = serde_json::to_value(record).map_err(InkscapeEvidenceError::Serialization)?;
    let signature = signing_key.sign(&canonical_json_bytes(&value)?);
    Ok(SignedInkscapeExecutionRecord {
        record: record.clone(),
        signature: InkscapeExecutionSignature {
            issuer_id,
            key_id,
            algorithm: InkscapeSignatureAlgorithm::Ed25519,
            encoding: InkscapeSignatureEncoding::Base64url,
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })
}

pub fn verify_execution_material(
    material: &InkscapeExecutionMaterial<'_>,
    trusted_keys: &InkscapeExecutionKeyRegistry,
) -> Result<VerifiedInkscapeExecution, InkscapeEvidenceError> {
    let record = &material.package.record;
    validate_record_shape(record)?;
    verify_signature(material.package, trusted_keys)?;
    validate_record_self_digest(record)?;

    let request_value =
        serde_json::to_value(material.request).map_err(InkscapeEvidenceError::Serialization)?;
    let request_digest = canonical_json_sha256(&request_value)?;
    if request_digest != record.request_digest {
        return Err(InkscapeEvidenceError::RequestDigestMismatch);
    }
    validate_request_record_binding(material.request, record)?;
    validate_material_paths(material)?;

    let source_svg_digest = sha256_file(material.source_svg)?;
    if source_svg_digest != material.request.expected_source_digest
        || source_svg_digest != record.pre_source_digest()
    {
        return Err(InkscapeEvidenceError::SourceDigestMismatch);
    }
    let editable_svg_digest = sha256_file(material.editable_svg)?;
    if editable_svg_digest != record.editable_output_digest {
        return Err(InkscapeEvidenceError::EditableDigestMismatch);
    }
    let raster_png_digest = sha256_file(material.raster_png)?;
    if raster_png_digest != record.raster_output_digest {
        return Err(InkscapeEvidenceError::RasterDigestMismatch);
    }

    let pre = observe_svg(material.source_svg)?;
    let post = observe_svg(material.editable_svg)?;
    if pre.snapshot_digest != record.pre_snapshot_digest {
        return Err(InkscapeEvidenceError::PreSnapshotDigestMismatch);
    }
    if post.snapshot_digest != record.post_snapshot_digest {
        return Err(InkscapeEvidenceError::PostSnapshotDigestMismatch);
    }
    verify_declared_text_change(
        &pre,
        &post,
        &record.target_element_id,
        &record.replacement_text,
    )?;

    let png = read_png_info(material.raster_png)?;
    if png.width != record.export_width || png.height != record.export_height {
        return Err(InkscapeEvidenceError::RasterDimensionMismatch);
    }
    if png.artifact_digest != raster_png_digest {
        return Err(InkscapeEvidenceError::RasterDigestMismatch);
    }

    let package_value = serde_json::to_value(material.package)
        .map_err(InkscapeEvidenceError::Serialization)?;
    Ok(VerifiedInkscapeExecution {
        package_digest: canonical_json_sha256(&package_value)?,
        record_digest: record.record_digest.clone(),
        request_digest,
        source_svg_digest,
        editable_svg_digest,
        raster_png_digest,
        pre_snapshot_digest: pre.snapshot_digest,
        post_snapshot_digest: post.snapshot_digest,
        application_id: record.binary.application_id.clone(),
        application_version: record.binary.version_text.clone(),
        application_digest: record.binary.executable_digest.clone(),
        target_element_id: record.target_element_id.clone(),
        replacement_text: record.replacement_text.clone(),
        export_width: record.export_width,
        export_height: record.export_height,
        issuer_id: material.package.signature.issuer_id.clone(),
        key_id: material.package.signature.key_id.clone(),
    })
}

trait RecordSourceDigest {
    fn pre_source_digest(&self) -> &str;
}

impl RecordSourceDigest for InkscapeExecutionRecord {
    fn pre_source_digest(&self) -> &str {
        &self.request_source_digest_fallback()
    }
}

trait RecordSourceDigestFallback {
    fn request_source_digest_fallback(&self) -> String;
}

impl RecordSourceDigestFallback for InkscapeExecutionRecord {
    fn request_source_digest_fallback(&self) -> String {
        String::new()
    }
}

fn validate_record_shape(record: &InkscapeExecutionRecord) -> Result<(), InkscapeEvidenceError> {
    if record.schema_version != RECORD_SCHEMA {
        return Err(InkscapeEvidenceError::UnsupportedRecordSchema);
    }
    if !record.verified {
        return Err(InkscapeEvidenceError::RecordNotVerified);
    }
    if record.binary.application_id != APPLICATION_ID
        || record.binary.version_major != 1
        || !(MIN_SUPPORTED_MINOR..=MAX_SUPPORTED_MINOR).contains(&record.binary.version_minor)
        || !is_sha256(&record.binary.executable_digest)
    {
        return Err(InkscapeEvidenceError::UnsupportedApplicationIdentity);
    }
    for (field, value) in [
        ("request_id", record.request_id.as_str()),
        ("target_element_id", record.target_element_id.as_str()),
        ("record_digest", record.record_digest.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(InkscapeEvidenceError::EmptyField(field));
        }
    }
    Ok(())
}

fn verify_signature(
    package: &SignedInkscapeExecutionRecord,
    trusted_keys: &InkscapeExecutionKeyRegistry,
) -> Result<(), InkscapeEvidenceError> {
    if package.signature.algorithm != InkscapeSignatureAlgorithm::Ed25519
        || package.signature.encoding != InkscapeSignatureEncoding::Base64url
    {
        return Err(InkscapeEvidenceError::UnsupportedSignatureMetadata);
    }
    let key = trusted_keys
        .get(&package.signature.issuer_id, &package.signature.key_id)
        .ok_or_else(|| InkscapeEvidenceError::UnknownTrustedKey {
            issuer_id: package.signature.issuer_id.clone(),
            key_id: package.signature.key_id.clone(),
        })?;
    let bytes = URL_SAFE_NO_PAD
        .decode(&package.signature.value)
        .map_err(|_| InkscapeEvidenceError::InvalidSignatureEncoding)?;
    let signature =
        Signature::from_slice(&bytes).map_err(|_| InkscapeEvidenceError::InvalidSignatureLength)?;
    let value =
        serde_json::to_value(&package.record).map_err(InkscapeEvidenceError::Serialization)?;
    key.verify_strict(&canonical_json_bytes(&value)?, &signature)
        .map_err(|_| InkscapeEvidenceError::SignatureVerificationFailed)
}

fn validate_record_self_digest(
    record: &InkscapeExecutionRecord,
) -> Result<(), InkscapeEvidenceError> {
    let mut value = serde_json::to_value(record).map_err(InkscapeEvidenceError::Serialization)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| InkscapeEvidenceError::Serialization(serde_json::Error::io(
            std::io::Error::other("record did not serialize to an object"),
        )))?;
    object.insert("record_digest".to_owned(), Value::String(String::new()));
    if canonical_json_sha256(&value)? != record.record_digest {
        return Err(InkscapeEvidenceError::RecordDigestMismatch);
    }
    Ok(())
}

fn validate_request_record_binding(
    request: &SetTextAndExportRequest,
    record: &InkscapeExecutionRecord,
) -> Result<(), InkscapeEvidenceError> {
    if request.schema_version != RECORD_SCHEMA
        || request.request_id != record.request_id
        || request.target_element_id != record.target_element_id
        || request.replacement_text != record.replacement_text
        || request.export_width != record.export_width
        || request.export_height != record.export_height
    {
        return Err(InkscapeEvidenceError::RequestRecordBindingMismatch);
    }
    Ok(())
}

fn validate_material_paths(
    material: &InkscapeExecutionMaterial<'_>,
) -> Result<(), InkscapeEvidenceError> {
    require_same_file(
        &material.request.source_svg,
        material.source_svg,
        "source_svg",
    )?;
    require_same_file(
        &material.request.editable_output_svg,
        material.editable_svg,
        "editable_svg",
    )?;
    require_same_file(
        &material.request.raster_output_png,
        material.raster_png,
        "raster_png",
    )?;
    Ok(())
}

fn require_same_file(
    requested: &Path,
    supplied: &Path,
    field: &'static str,
) -> Result<(), InkscapeEvidenceError> {
    let requested = fs::canonicalize(requested)?;
    let supplied = fs::canonicalize(supplied)?;
    if requested != supplied {
        return Err(InkscapeEvidenceError::MaterialPathMismatch(field));
    }
    Ok(())
}

fn verify_declared_text_change(
    pre: &SvgDocumentSnapshot,
    post: &SvgDocumentSnapshot,
    target_id: &str,
    replacement: &str,
) -> Result<(), InkscapeEvidenceError> {
    if pre.width != post.width
        || pre.height != post.height
        || pre.view_box != post.view_box
        || pre.elements.len() != post.elements.len()
    {
        return Err(InkscapeEvidenceError::UndeclaredSvgChange);
    }
    for (id, before) in &pre.elements {
        let Some(after) = post.elements.get(id) else {
            return Err(InkscapeEvidenceError::UndeclaredSvgChange);
        };
        if id == target_id {
            if before.element_name != after.element_name
                || before.attributes != after.attributes
                || before.has_nested_elements
                || after.has_nested_elements
                || after.direct_text != replacement
            {
                return Err(InkscapeEvidenceError::UndeclaredSvgChange);
            }
        } else if before != after {
            return Err(InkscapeEvidenceError::UndeclaredSvgChange);
        }
    }
    if !pre.elements.contains_key(target_id) {
        return Err(InkscapeEvidenceError::UndeclaredSvgChange);
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn material_paths(material: &InkscapeExecutionMaterial<'_>) -> [PathBuf; 3] {
    [
        material.source_svg.to_path_buf(),
        material.editable_svg.to_path_buf(),
        material.raster_png.to_path_buf(),
    ]
}
