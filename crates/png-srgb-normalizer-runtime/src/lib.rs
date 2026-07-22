#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::io::BufReader;
use std::path::{Component, Path, PathBuf};
use std::str;

use ergaxiom_png_artifact_validator_runtime::{
    PngArtifactError, PngColorProfileEvidence, PngProfileRequirement, PngValidationPolicy,
    inspect_png_bytes, validate_report,
};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const REQUEST_SCHEMA: &str = "0.1.0";
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const MAX_SVG_BYTES: usize = 32 * 1024 * 1024;
const COLOR_SIGNAL_CHUNKS: [&str; 8] = [
    "sRGB", "iCCP", "cICP", "cHRM", "gAMA", "mDCV", "cLLI", "eXIf",
];
const COLOR_PROPERTIES: [&str; 7] = [
    "color",
    "fill",
    "stroke",
    "stop-color",
    "flood-color",
    "lighting-color",
    "background-color",
];
const FORBIDDEN_ELEMENTS: [&str; 8] = [
    "style",
    "image",
    "foreignObject",
    "color-profile",
    "filter",
    "feImage",
    "script",
    "video",
];
const DANGEROUS_COLOR_TOKENS: [&str; 9] = [
    "icc-color(",
    "device-cmyk(",
    "device-gray(",
    "device-rgb(",
    "lab(",
    "lch(",
    "oklab(",
    "oklch(",
    "color(",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SrgbRenderingIntent {
    Perceptual,
    RelativeColorimetric,
    Saturation,
    AbsoluteColorimetric,
}

impl SrgbRenderingIntent {
    pub fn png_value(self) -> u8 {
        match self {
            Self::Perceptual => 0,
            Self::RelativeColorimetric => 1,
            Self::Saturation => 2,
            Self::AbsoluteColorimetric => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrgbSvgEvidence {
    pub schema_version: String,
    pub source_digest: String,
    pub size_bytes: u64,
    pub element_count: u64,
    pub color_declaration_count: u64,
    pub internal_paint_server_reference_count: u64,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PngSrgbNormalizationRequest {
    pub schema_version: String,
    pub request_id: String,
    pub source_svg: PathBuf,
    pub expected_source_svg_digest: String,
    pub input_png: PathBuf,
    pub expected_input_png_digest: String,
    pub output_png: PathBuf,
    pub rendering_intent: SrgbRenderingIntent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PngSrgbNormalizationRecord {
    pub schema_version: String,
    pub request_id: String,
    pub request_digest: String,
    pub source_svg_evidence: SrgbSvgEvidence,
    pub input_png_digest: String,
    pub output_png_digest: String,
    pub input_report_digest: String,
    pub output_report_digest: String,
    pub input_idat_payload_digest: String,
    pub output_idat_payload_digest: String,
    pub rendering_intent: SrgbRenderingIntent,
    pub inserted_srgb_crc32: String,
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    pub verified: bool,
    pub record_digest: String,
}

#[derive(Debug, Error)]
pub enum PngSrgbNormalizationError {
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON failure: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    Png(#[from] PngArtifactError),
    #[error("unsupported normalization request schema {0}")]
    UnsupportedRequestSchema(String),
    #[error("required normalization field is empty: {0}")]
    EmptyField(&'static str),
    #[error("trusted digest must be 64 lowercase hexadecimal characters: {0}")]
    InvalidTrustedDigest(&'static str),
    #[error("source SVG exceeds the {MAX_SVG_BYTES}-byte inspection limit")]
    SvgTooLarge,
    #[error("source SVG digest does not match the trusted digest")]
    SourceSvgDigestMismatch,
    #[error("input PNG digest does not match the trusted digest")]
    InputPngDigestMismatch,
    #[error("source SVG does not contain a root svg element")]
    MissingSvgRoot,
    #[error("source SVG contains a DTD")]
    SvgDocumentTypeForbidden,
    #[error("source SVG contains a forbidden element: {0}")]
    ForbiddenSvgElement(String),
    #[error("source SVG contains an external resource reference")]
    ExternalSvgResource,
    #[error("source SVG contains an unsupported color-space token: {0}")]
    UnsupportedSvgColorSpace(String),
    #[error("source SVG contains an unsupported paint value: {0}")]
    UnsupportedSvgPaint(String),
    #[error("source SVG contains an unsupported style declaration: {0}")]
    UnsupportedSvgStyle(String),
    #[error("source SVG requests a non-sRGB interpolation mode")]
    NonSrgbInterpolation,
    #[error("source SVG contains invalid UTF-8 or XML: {0}")]
    InvalidSvg(String),
    #[error("input PNG already contains color signalling: {0}")]
    ExistingColorSignal(String),
    #[error("input and output PNG paths must be different")]
    PathCollision,
    #[error("output path contains parent traversal")]
    ParentTraversal,
    #[error("output PNG already exists")]
    OutputAlreadyExists,
    #[error("output PNG path has no file name")]
    MissingOutputFileName,
    #[error("PNG IDAT payload is missing")]
    MissingIdat,
    #[error("normalization changed IDAT payload bytes")]
    IdatMutation,
    #[error("normalized PNG did not produce the declared sRGB profile evidence")]
    OutputProfileMismatch,
    #[error("normalized PNG policy verification failed")]
    OutputPolicyRejected,
}

pub fn inspect_svg_srgb(
    path: impl AsRef<Path>,
) -> Result<SrgbSvgEvidence, PngSrgbNormalizationError> {
    let bytes = fs::read(path)?;
    inspect_svg_srgb_bytes(&bytes)
}

pub fn inspect_svg_srgb_bytes(bytes: &[u8]) -> Result<SrgbSvgEvidence, PngSrgbNormalizationError> {
    if bytes.len() > MAX_SVG_BYTES {
        return Err(PngSrgbNormalizationError::SvgTooLarge);
    }
    let mut reader = Reader::from_reader(BufReader::new(bytes));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut root_seen = false;
    let mut depth = 0_u64;
    let mut element_count = 0_u64;
    let mut color_declaration_count = 0_u64;
    let mut internal_paint_server_reference_count = 0_u64;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| PngSrgbNormalizationError::InvalidSvg(error.to_string()))?;
        match event {
            Event::Start(start) => {
                inspect_element(
                    &start,
                    reader.decoder(),
                    &mut color_declaration_count,
                    &mut internal_paint_server_reference_count,
                )?;
                if depth == 0 && local_name_bytes(start.name().as_ref())? == "svg" {
                    root_seen = true;
                }
                depth = depth.saturating_add(1);
                element_count = element_count.saturating_add(1);
            }
            Event::Empty(empty) => {
                inspect_element(
                    &empty,
                    reader.decoder(),
                    &mut color_declaration_count,
                    &mut internal_paint_server_reference_count,
                )?;
                if depth == 0 && local_name_bytes(empty.name().as_ref())? == "svg" {
                    root_seen = true;
                }
                element_count = element_count.saturating_add(1);
            }
            Event::End(_) => {
                depth = depth.saturating_sub(1);
            }
            Event::DocType(_) => {
                return Err(PngSrgbNormalizationError::SvgDocumentTypeForbidden);
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !root_seen {
        return Err(PngSrgbNormalizationError::MissingSvgRoot);
    }

    let mut evidence = SrgbSvgEvidence {
        schema_version: REQUEST_SCHEMA.to_owned(),
        source_digest: format!("{:x}", Sha256::digest(bytes)),
        size_bytes: bytes.len() as u64,
        element_count,
        color_declaration_count,
        internal_paint_server_reference_count,
        evidence_digest: String::new(),
    };
    evidence.evidence_digest = svg_evidence_digest(&evidence)?;
    Ok(evidence)
}

pub fn normalize_png_srgb(
    request: &PngSrgbNormalizationRequest,
) -> Result<PngSrgbNormalizationRecord, PngSrgbNormalizationError> {
    validate_request(request)?;
    let source_svg = fs::canonicalize(&request.source_svg)?;
    let input_png = fs::canonicalize(&request.input_png)?;
    let output_png = resolve_output(&request.output_png)?;
    if input_png == output_png {
        return Err(PngSrgbNormalizationError::PathCollision);
    }

    let source_svg_evidence = inspect_svg_srgb(&source_svg)?;
    if source_svg_evidence.source_digest != request.expected_source_svg_digest {
        return Err(PngSrgbNormalizationError::SourceSvgDigestMismatch);
    }

    let input_bytes = fs::read(&input_png)?;
    let input_png_digest = format!("{:x}", Sha256::digest(&input_bytes));
    if input_png_digest != request.expected_input_png_digest {
        return Err(PngSrgbNormalizationError::InputPngDigestMismatch);
    }
    let input_report = inspect_png_bytes(&input_bytes)?;
    if !matches!(input_report.color_profile, PngColorProfileEvidence::None) {
        return Err(PngSrgbNormalizationError::ExistingColorSignal(
            "sRGB or iCCP".to_owned(),
        ));
    }
    let existing_signals: BTreeSet<&str> = input_report
        .chunks
        .iter()
        .map(|chunk| chunk.chunk_type.as_str())
        .filter(|chunk_type| COLOR_SIGNAL_CHUNKS.contains(chunk_type))
        .collect();
    if let Some(signal) = existing_signals.first() {
        return Err(PngSrgbNormalizationError::ExistingColorSignal(
            (*signal).to_owned(),
        ));
    }

    let input_idat_payload_digest = idat_payload_digest(&input_bytes)?;
    let (output_bytes, inserted_srgb_crc32) =
        insert_srgb_chunk(&input_bytes, request.rendering_intent.png_value())?;
    let output_report = inspect_png_bytes(&output_bytes)?;
    if output_report.color_profile
        != (PngColorProfileEvidence::Srgb {
            rendering_intent: request.rendering_intent.png_value(),
        })
    {
        return Err(PngSrgbNormalizationError::OutputProfileMismatch);
    }
    let output_idat_payload_digest = idat_payload_digest(&output_bytes)?;
    if output_idat_payload_digest != input_idat_payload_digest {
        return Err(PngSrgbNormalizationError::IdatMutation);
    }
    let output_policy = validate_report(
        output_report.clone(),
        &PngValidationPolicy {
            expected_width: input_report.width,
            expected_height: input_report.height,
            expected_bit_depth: Some(input_report.bit_depth),
            allowed_color_types: vec![input_report.color_type],
            profile_requirement: PngProfileRequirement::SrgbChunk,
        },
    )?;
    if !output_policy.accepted {
        return Err(PngSrgbNormalizationError::OutputPolicyRejected);
    }

    fs::write(&output_png, &output_bytes)?;
    let request_digest = canonical_json_sha256(&serde_json::to_value(request)?)?;
    let mut record = PngSrgbNormalizationRecord {
        schema_version: REQUEST_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_digest,
        source_svg_evidence,
        input_png_digest,
        output_png_digest: output_report.artifact_digest.clone(),
        input_report_digest: input_report.report_digest,
        output_report_digest: output_report.report_digest,
        input_idat_payload_digest,
        output_idat_payload_digest,
        rendering_intent: request.rendering_intent,
        inserted_srgb_crc32,
        width: output_report.width,
        height: output_report.height,
        bit_depth: output_report.bit_depth,
        verified: true,
        record_digest: String::new(),
    };
    record.record_digest = normalization_record_digest(&record)?;
    Ok(record)
}

fn inspect_element(
    start: &BytesStart<'_>,
    decoder: quick_xml::encoding::Decoder,
    color_count: &mut u64,
    paint_server_count: &mut u64,
) -> Result<(), PngSrgbNormalizationError> {
    let element_name = local_name_bytes(start.name().as_ref())?;
    if FORBIDDEN_ELEMENTS.contains(&element_name.as_str()) {
        return Err(PngSrgbNormalizationError::ForbiddenSvgElement(element_name));
    }

    for attribute in start.attributes().with_checks(true) {
        let attribute =
            attribute.map_err(|error| PngSrgbNormalizationError::InvalidSvg(error.to_string()))?;
        let key = local_name_bytes(attribute.key.as_ref())?.to_ascii_lowercase();
        let value = attribute
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
            .map_err(|error| PngSrgbNormalizationError::InvalidSvg(error.to_string()))?
            .into_owned();
        let trimmed = value.trim();
        let lower = trimmed.to_ascii_lowercase();

        if lower.split_whitespace().any(|token| {
            DANGEROUS_COLOR_TOKENS
                .iter()
                .any(|danger| token.contains(danger))
        }) {
            return Err(PngSrgbNormalizationError::UnsupportedSvgColorSpace(
                trimmed.to_owned(),
            ));
        }
        if key.contains("profile") || key.contains("icc") {
            return Err(PngSrgbNormalizationError::UnsupportedSvgColorSpace(key));
        }
        match key.as_str() {
            "href" => {
                if !trimmed.starts_with('#') {
                    return Err(PngSrgbNormalizationError::ExternalSvgResource);
                }
            }
            "style" => inspect_style(trimmed, color_count, paint_server_count)?,
            "color-interpolation" | "color-interpolation-filters" => {
                if trimmed != "sRGB" {
                    return Err(PngSrgbNormalizationError::NonSrgbInterpolation);
                }
            }
            "filter" => {
                if lower != "none" {
                    return Err(PngSrgbNormalizationError::UnsupportedSvgStyle(
                        trimmed.to_owned(),
                    ));
                }
            }
            property if COLOR_PROPERTIES.contains(&property) => {
                inspect_paint(property, trimmed, color_count, paint_server_count)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn inspect_style(
    style: &str,
    color_count: &mut u64,
    paint_server_count: &mut u64,
) -> Result<(), PngSrgbNormalizationError> {
    for declaration in style.split(';').filter(|part| !part.trim().is_empty()) {
        let (property, value) = declaration.split_once(':').ok_or_else(|| {
            PngSrgbNormalizationError::UnsupportedSvgStyle(declaration.to_owned())
        })?;
        let property = property.trim().to_ascii_lowercase();
        let value = value.trim();
        let lower = value.to_ascii_lowercase();
        if property.starts_with("--") {
            return Err(PngSrgbNormalizationError::UnsupportedSvgStyle(property));
        }
        if DANGEROUS_COLOR_TOKENS
            .iter()
            .any(|danger| lower.contains(danger))
        {
            return Err(PngSrgbNormalizationError::UnsupportedSvgColorSpace(
                value.to_owned(),
            ));
        }
        match property.as_str() {
            property if COLOR_PROPERTIES.contains(&property) => {
                inspect_paint(property, value, color_count, paint_server_count)?;
            }
            "color-interpolation" | "color-interpolation-filters" => {
                if value != "sRGB" {
                    return Err(PngSrgbNormalizationError::NonSrgbInterpolation);
                }
            }
            "filter" | "mix-blend-mode" | "isolation" | "background"
                if lower != "none" && lower != "normal" =>
            {
                return Err(PngSrgbNormalizationError::UnsupportedSvgStyle(
                    declaration.to_owned(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn inspect_paint(
    property: &str,
    value: &str,
    color_count: &mut u64,
    paint_server_count: &mut u64,
) -> Result<(), PngSrgbNormalizationError> {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    if matches!(lower.as_str(), "none" | "transparent") {
        *color_count = color_count.saturating_add(1);
        return Ok(());
    }
    if is_hex_color(trimmed) || is_rgb_function(&lower) {
        *color_count = color_count.saturating_add(1);
        return Ok(());
    }
    if matches!(property, "fill" | "stroke") && is_internal_paint_server(&lower) {
        *paint_server_count = paint_server_count.saturating_add(1);
        return Ok(());
    }
    Err(PngSrgbNormalizationError::UnsupportedSvgPaint(
        trimmed.to_owned(),
    ))
}

fn is_hex_color(value: &str) -> bool {
    matches!(value.len(), 4 | 5 | 7 | 9)
        && value.starts_with('#')
        && value[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_rgb_function(value: &str) -> bool {
    let (prefix_len, valid_prefix) = if value.starts_with("rgb(") {
        (4, true)
    } else if value.starts_with("rgba(") {
        (5, true)
    } else {
        (0, false)
    };
    valid_prefix
        && value.ends_with(')')
        && value[prefix_len..value.len() - 1].bytes().all(|byte| {
            byte.is_ascii_digit()
                || matches!(
                    byte,
                    b' ' | b'\t' | b'\r' | b'\n' | b',' | b'.' | b'%' | b'/' | b'+' | b'-'
                )
        })
}

fn is_internal_paint_server(value: &str) -> bool {
    value.starts_with("url(#") && value.ends_with(')') && value.len() > 6
}

fn insert_srgb_chunk(
    input: &[u8],
    rendering_intent: u8,
) -> Result<(Vec<u8>, String), PngSrgbNormalizationError> {
    if input.len() < PNG_SIGNATURE.len() + 25 || &input[..8] != PNG_SIGNATURE {
        return Err(PngSrgbNormalizationError::Png(
            PngArtifactError::InvalidSignature,
        ));
    }
    let ihdr_length = u32::from_be_bytes(
        input[8..12]
            .try_into()
            .map_err(|_| PngArtifactError::TruncatedChunk)?,
    );
    let insertion = 8_usize
        .checked_add(12)
        .and_then(|value| value.checked_add(usize::try_from(ihdr_length).ok()?))
        .ok_or(PngArtifactError::TruncatedChunk)?;
    if insertion > input.len() || &input[12..16] != b"IHDR" {
        return Err(PngSrgbNormalizationError::Png(
            PngArtifactError::IhdrNotFirst,
        ));
    }
    let crc = crc32_pair(b"sRGB", &[rendering_intent]);
    let mut output = Vec::with_capacity(input.len() + 13);
    output.extend_from_slice(&input[..insertion]);
    output.extend_from_slice(&1_u32.to_be_bytes());
    output.extend_from_slice(b"sRGB");
    output.push(rendering_intent);
    output.extend_from_slice(&crc.to_be_bytes());
    output.extend_from_slice(&input[insertion..]);
    Ok((output, format!("{crc:08x}")))
}

fn idat_payload_digest(bytes: &[u8]) -> Result<String, PngSrgbNormalizationError> {
    if bytes.len() < 8 || &bytes[..8] != PNG_SIGNATURE {
        return Err(PngSrgbNormalizationError::Png(
            PngArtifactError::InvalidSignature,
        ));
    }
    let mut offset = 8_usize;
    let mut hasher = Sha256::new();
    let mut found = false;
    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err(PngSrgbNormalizationError::Png(
                PngArtifactError::TruncatedChunk,
            ));
        }
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| PngArtifactError::TruncatedChunk)?,
        );
        let data_start = offset + 8;
        let data_end = data_start
            .checked_add(usize::try_from(length).map_err(|_| PngArtifactError::TruncatedChunk)?)
            .ok_or(PngArtifactError::TruncatedChunk)?;
        let chunk_end = data_end
            .checked_add(4)
            .ok_or(PngArtifactError::TruncatedChunk)?;
        if chunk_end > bytes.len() {
            return Err(PngSrgbNormalizationError::Png(
                PngArtifactError::TruncatedChunk,
            ));
        }
        if &bytes[offset + 4..offset + 8] == b"IDAT" {
            found = true;
            hasher.update(&bytes[data_start..data_end]);
        }
        offset = chunk_end;
    }
    if !found {
        return Err(PngSrgbNormalizationError::MissingIdat);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_request(
    request: &PngSrgbNormalizationRequest,
) -> Result<(), PngSrgbNormalizationError> {
    if request.schema_version != REQUEST_SCHEMA {
        return Err(PngSrgbNormalizationError::UnsupportedRequestSchema(
            request.schema_version.clone(),
        ));
    }
    if request.request_id.trim().is_empty() {
        return Err(PngSrgbNormalizationError::EmptyField("request_id"));
    }
    validate_sha256(
        &request.expected_source_svg_digest,
        "expected_source_svg_digest",
    )?;
    validate_sha256(
        &request.expected_input_png_digest,
        "expected_input_png_digest",
    )?;
    Ok(())
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), PngSrgbNormalizationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PngSrgbNormalizationError::InvalidTrustedDigest(field));
    }
    Ok(())
}

fn resolve_output(path: &Path) -> Result<PathBuf, PngSrgbNormalizationError> {
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(PngSrgbNormalizationError::ParentTraversal);
    }
    if path.exists() {
        return Err(PngSrgbNormalizationError::OutputAlreadyExists);
    }
    let file_name = path
        .file_name()
        .ok_or(PngSrgbNormalizationError::MissingOutputFileName)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)?;
    Ok(parent.join(file_name))
}

fn local_name_bytes(bytes: &[u8]) -> Result<String, PngSrgbNormalizationError> {
    let name = str::from_utf8(bytes)
        .map_err(|error| PngSrgbNormalizationError::InvalidSvg(error.to_string()))?;
    Ok(name
        .rsplit_once(':')
        .map_or(name, |(_, local)| local)
        .to_owned())
}

fn svg_evidence_digest(evidence: &SrgbSvgEvidence) -> Result<String, PngSrgbNormalizationError> {
    let mut value = serde_json::to_value(evidence)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| serde_json::Error::io(std::io::Error::other("evidence is not an object")))?;
    object.insert(
        "evidence_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

fn normalization_record_digest(
    record: &PngSrgbNormalizationRecord,
) -> Result<String, PngSrgbNormalizationError> {
    let mut value = serde_json::to_value(record)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| serde_json::Error::io(std::io::Error::other("record is not an object")))?;
    object.insert(
        "record_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

fn crc32_pair(left: &[u8], right: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in left.iter().chain(right) {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
