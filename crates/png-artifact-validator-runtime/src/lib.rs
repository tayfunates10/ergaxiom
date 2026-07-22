#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const MAX_PNG_BYTES: usize = 256 * 1024 * 1024;
const MAX_DIMENSION: u32 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PngColorType {
    Grayscale,
    Truecolor,
    Indexed,
    GrayscaleAlpha,
    TruecolorAlpha,
}

impl PngColorType {
    fn from_byte(value: u8) -> Result<Self, PngArtifactError> {
        match value {
            0 => Ok(Self::Grayscale),
            2 => Ok(Self::Truecolor),
            3 => Ok(Self::Indexed),
            4 => Ok(Self::GrayscaleAlpha),
            6 => Ok(Self::TruecolorAlpha),
            _ => Err(PngArtifactError::InvalidColorType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PngColorProfileEvidence {
    None,
    Srgb { rendering_intent: u8 },
    Icc { profile_name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PngChunkEvidence {
    pub chunk_type: String,
    pub length: u32,
    pub crc32: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PngArtifactReport {
    pub schema_version: String,
    pub artifact_digest: String,
    pub size_bytes: u64,
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    pub color_type: PngColorType,
    pub compression_method: u8,
    pub filter_method: u8,
    pub interlace_method: u8,
    pub color_profile: PngColorProfileEvidence,
    pub idat_chunk_count: u32,
    pub idat_payload_bytes: u64,
    pub chunks: Vec<PngChunkEvidence>,
    pub report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PngProfileRequirement {
    NotRequired,
    AnyEmbedded,
    SrgbChunk,
    IccProfile { profile_name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PngValidationPolicy {
    pub expected_width: u32,
    pub expected_height: u32,
    pub expected_bit_depth: Option<u8>,
    pub allowed_color_types: Vec<PngColorType>,
    pub profile_requirement: PngProfileRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PngPolicyViolation {
    WidthMismatch { expected: u32, actual: u32 },
    HeightMismatch { expected: u32, actual: u32 },
    BitDepthMismatch { expected: u8, actual: u8 },
    ColorTypeNotAllowed { actual: PngColorType },
    MissingColorProfile,
    MissingSrgbChunk,
    IccProfileNameMismatch { expected: String, actual: String },
    IccProfileRequiredButSrgbFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PngValidationResult {
    pub schema_version: String,
    pub accepted: bool,
    pub report: PngArtifactReport,
    pub violations: Vec<PngPolicyViolation>,
    pub decision_digest: String,
}

#[derive(Debug, Error)]
pub enum PngArtifactError {
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("PNG exceeds the {MAX_PNG_BYTES}-byte inspection limit")]
    FileTooLarge,
    #[error("PNG signature is missing")]
    InvalidSignature,
    #[error("PNG chunk is truncated")]
    TruncatedChunk,
    #[error("PNG chunk type is invalid")]
    InvalidChunkType,
    #[error("unknown critical PNG chunk: {0}")]
    UnknownCriticalChunk(String),
    #[error("PNG chunk CRC mismatch for {chunk_type}")]
    CrcMismatch { chunk_type: String },
    #[error("IHDR must be the first PNG chunk")]
    IhdrNotFirst,
    #[error("PNG contains more than one IHDR chunk")]
    DuplicateIhdr,
    #[error("IHDR must contain exactly 13 bytes")]
    InvalidIhdrLength,
    #[error("PNG dimensions are invalid")]
    InvalidDimensions,
    #[error("PNG color type is invalid: {0}")]
    InvalidColorType(u8),
    #[error("bit depth {bit_depth} is invalid for color type {color_type:?}")]
    InvalidBitDepth {
        bit_depth: u8,
        color_type: PngColorType,
    },
    #[error("PNG compression method must be 0")]
    InvalidCompressionMethod,
    #[error("PNG filter method must be 0")]
    InvalidFilterMethod,
    #[error("PNG interlace method must be 0 or 1")]
    InvalidInterlaceMethod,
    #[error("PNG contains more than one PLTE chunk")]
    DuplicatePalette,
    #[error("PLTE appears after IDAT")]
    PaletteAfterImageData,
    #[error("indexed-color PNG requires PLTE")]
    PaletteRequired,
    #[error("grayscale PNG cannot contain PLTE")]
    PaletteForbidden,
    #[error("IDAT chunks must be consecutive")]
    NonConsecutiveImageData,
    #[error("PNG contains no non-empty IDAT payload")]
    MissingImageData,
    #[error("PNG contains more than one IEND chunk")]
    DuplicateIend,
    #[error("IEND must contain zero bytes")]
    InvalidIendLength,
    #[error("PNG is missing IEND")]
    MissingIend,
    #[error("PNG contains bytes after IEND")]
    TrailingBytes,
    #[error("color-profile chunks must precede PLTE and IDAT")]
    ColorProfileAfterImageData,
    #[error("PNG contains more than one sRGB chunk")]
    DuplicateSrgb,
    #[error("sRGB chunk is malformed")]
    InvalidSrgbChunk,
    #[error("PNG contains more than one iCCP chunk")]
    DuplicateIcc,
    #[error("iCCP chunk is malformed")]
    InvalidIccChunk,
    #[error("PNG cannot contain both sRGB and iCCP chunks")]
    ConflictingColorProfiles,
    #[error("validation policy dimensions are invalid")]
    InvalidPolicyDimensions,
    #[error("validation policy has no allowed color type")]
    EmptyAllowedColorTypes,
    #[error("validation policy ICC profile name is empty")]
    EmptyIccProfileName,
    #[error("failed to serialize PNG validation material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn inspect_png(path: impl AsRef<Path>) -> Result<PngArtifactReport, PngArtifactError> {
    let bytes = fs::read(path)?;
    inspect_png_bytes(&bytes)
}

pub fn inspect_png_bytes(bytes: &[u8]) -> Result<PngArtifactReport, PngArtifactError> {
    if bytes.len() > MAX_PNG_BYTES {
        return Err(PngArtifactError::FileTooLarge);
    }
    if bytes.len() < PNG_SIGNATURE.len() || &bytes[..PNG_SIGNATURE.len()] != PNG_SIGNATURE {
        return Err(PngArtifactError::InvalidSignature);
    }

    let mut offset = PNG_SIGNATURE.len();
    let mut chunks = Vec::new();
    let mut ihdr: Option<Ihdr> = None;
    let mut palette_seen = false;
    let mut idat_started = false;
    let mut idat_closed = false;
    let mut idat_chunk_count = 0_u32;
    let mut idat_payload_bytes = 0_u64;
    let mut iend_seen = false;
    let mut srgb_intent = None;
    let mut icc_profile_name = None;

    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err(PngArtifactError::TruncatedChunk);
        }
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| PngArtifactError::TruncatedChunk)?,
        );
        let length_usize = usize::try_from(length).map_err(|_| PngArtifactError::TruncatedChunk)?;
        let data_start = offset + 8;
        let data_end = data_start
            .checked_add(length_usize)
            .ok_or(PngArtifactError::TruncatedChunk)?;
        let chunk_end = data_end
            .checked_add(4)
            .ok_or(PngArtifactError::TruncatedChunk)?;
        if chunk_end > bytes.len() {
            return Err(PngArtifactError::TruncatedChunk);
        }

        let chunk_type_bytes = &bytes[offset + 4..offset + 8];
        if !chunk_type_bytes.iter().all(u8::is_ascii_alphabetic) {
            return Err(PngArtifactError::InvalidChunkType);
        }
        let chunk_type = std::str::from_utf8(chunk_type_bytes)
            .map_err(|_| PngArtifactError::InvalidChunkType)?
            .to_owned();
        let data = &bytes[data_start..data_end];
        let expected_crc = u32::from_be_bytes(
            bytes[data_end..chunk_end]
                .try_into()
                .map_err(|_| PngArtifactError::TruncatedChunk)?,
        );
        let actual_crc = crc32_pair(chunk_type_bytes, data);
        if expected_crc != actual_crc {
            return Err(PngArtifactError::CrcMismatch {
                chunk_type: chunk_type.clone(),
            });
        }

        if chunks.is_empty() && chunk_type != "IHDR" {
            return Err(PngArtifactError::IhdrNotFirst);
        }
        if is_unknown_critical(&chunk_type) {
            return Err(PngArtifactError::UnknownCriticalChunk(chunk_type));
        }

        match chunk_type.as_str() {
            "IHDR" => {
                if ihdr.is_some() {
                    return Err(PngArtifactError::DuplicateIhdr);
                }
                ihdr = Some(parse_ihdr(data)?);
            }
            "PLTE" => {
                if palette_seen {
                    return Err(PngArtifactError::DuplicatePalette);
                }
                if idat_started {
                    return Err(PngArtifactError::PaletteAfterImageData);
                }
                palette_seen = true;
            }
            "IDAT" => {
                if idat_closed {
                    return Err(PngArtifactError::NonConsecutiveImageData);
                }
                idat_started = true;
                idat_chunk_count = idat_chunk_count.saturating_add(1);
                idat_payload_bytes = idat_payload_bytes.saturating_add(u64::from(length));
            }
            "IEND" => {
                if iend_seen {
                    return Err(PngArtifactError::DuplicateIend);
                }
                if length != 0 {
                    return Err(PngArtifactError::InvalidIendLength);
                }
                iend_seen = true;
            }
            "sRGB" => {
                if palette_seen || idat_started {
                    return Err(PngArtifactError::ColorProfileAfterImageData);
                }
                if srgb_intent.is_some() {
                    return Err(PngArtifactError::DuplicateSrgb);
                }
                if data.len() != 1 || data[0] > 3 {
                    return Err(PngArtifactError::InvalidSrgbChunk);
                }
                srgb_intent = Some(data[0]);
            }
            "iCCP" => {
                if palette_seen || idat_started {
                    return Err(PngArtifactError::ColorProfileAfterImageData);
                }
                if icc_profile_name.is_some() {
                    return Err(PngArtifactError::DuplicateIcc);
                }
                icc_profile_name = Some(parse_iccp_name(data)?);
            }
            _ => {
                if idat_started {
                    idat_closed = true;
                }
            }
        }

        chunks.push(PngChunkEvidence {
            chunk_type: chunk_type.clone(),
            length,
            crc32: format!("{expected_crc:08x}"),
        });
        offset = chunk_end;
        if chunk_type == "IEND" {
            if offset != bytes.len() {
                return Err(PngArtifactError::TrailingBytes);
            }
            break;
        }
    }

    if !iend_seen {
        return Err(PngArtifactError::MissingIend);
    }
    if !idat_started || idat_payload_bytes == 0 {
        return Err(PngArtifactError::MissingImageData);
    }
    let ihdr = ihdr.ok_or(PngArtifactError::IhdrNotFirst)?;
    match ihdr.color_type {
        PngColorType::Indexed if !palette_seen => return Err(PngArtifactError::PaletteRequired),
        PngColorType::Grayscale | PngColorType::GrayscaleAlpha if palette_seen => {
            return Err(PngArtifactError::PaletteForbidden);
        }
        _ => {}
    }
    if srgb_intent.is_some() && icc_profile_name.is_some() {
        return Err(PngArtifactError::ConflictingColorProfiles);
    }
    let color_profile = match (srgb_intent, icc_profile_name) {
        (Some(rendering_intent), None) => PngColorProfileEvidence::Srgb { rendering_intent },
        (None, Some(profile_name)) => PngColorProfileEvidence::Icc { profile_name },
        (None, None) => PngColorProfileEvidence::None,
        (Some(_), Some(_)) => return Err(PngArtifactError::ConflictingColorProfiles),
    };

    let mut report = PngArtifactReport {
        schema_version: "0.1.0".to_owned(),
        artifact_digest: format!("{:x}", Sha256::digest(bytes)),
        size_bytes: bytes.len() as u64,
        width: ihdr.width,
        height: ihdr.height,
        bit_depth: ihdr.bit_depth,
        color_type: ihdr.color_type,
        compression_method: ihdr.compression_method,
        filter_method: ihdr.filter_method,
        interlace_method: ihdr.interlace_method,
        color_profile,
        idat_chunk_count,
        idat_payload_bytes,
        chunks,
        report_digest: String::new(),
    };
    report.report_digest = report_digest(&report)?;
    Ok(report)
}

pub fn validate_png(
    path: impl AsRef<Path>,
    policy: &PngValidationPolicy,
) -> Result<PngValidationResult, PngArtifactError> {
    let report = inspect_png(path)?;
    validate_report(report, policy)
}

pub fn validate_report(
    report: PngArtifactReport,
    policy: &PngValidationPolicy,
) -> Result<PngValidationResult, PngArtifactError> {
    validate_policy(policy)?;
    let mut violations = Vec::new();
    if report.width != policy.expected_width {
        violations.push(PngPolicyViolation::WidthMismatch {
            expected: policy.expected_width,
            actual: report.width,
        });
    }
    if report.height != policy.expected_height {
        violations.push(PngPolicyViolation::HeightMismatch {
            expected: policy.expected_height,
            actual: report.height,
        });
    }
    if let Some(expected) = policy.expected_bit_depth
        && report.bit_depth != expected
    {
        violations.push(PngPolicyViolation::BitDepthMismatch {
            expected,
            actual: report.bit_depth,
        });
    }
    if !policy.allowed_color_types.contains(&report.color_type) {
        violations.push(PngPolicyViolation::ColorTypeNotAllowed {
            actual: report.color_type,
        });
    }
    evaluate_profile_requirement(&report.color_profile, &policy.profile_requirement, &mut violations);

    let mut result = PngValidationResult {
        schema_version: "0.1.0".to_owned(),
        accepted: violations.is_empty(),
        report,
        violations,
        decision_digest: String::new(),
    };
    result.decision_digest = validation_digest(&result)?;
    Ok(result)
}

fn evaluate_profile_requirement(
    evidence: &PngColorProfileEvidence,
    requirement: &PngProfileRequirement,
    violations: &mut Vec<PngPolicyViolation>,
) {
    match requirement {
        PngProfileRequirement::NotRequired => {}
        PngProfileRequirement::AnyEmbedded => {
            if matches!(evidence, PngColorProfileEvidence::None) {
                violations.push(PngPolicyViolation::MissingColorProfile);
            }
        }
        PngProfileRequirement::SrgbChunk => {
            if !matches!(evidence, PngColorProfileEvidence::Srgb { .. }) {
                violations.push(PngPolicyViolation::MissingSrgbChunk);
            }
        }
        PngProfileRequirement::IccProfile { profile_name } => match evidence {
            PngColorProfileEvidence::Icc {
                profile_name: actual,
            } if actual == profile_name => {}
            PngColorProfileEvidence::Icc {
                profile_name: actual,
            } => violations.push(PngPolicyViolation::IccProfileNameMismatch {
                expected: profile_name.clone(),
                actual: actual.clone(),
            }),
            PngColorProfileEvidence::Srgb { .. } => {
                violations.push(PngPolicyViolation::IccProfileRequiredButSrgbFound);
            }
            PngColorProfileEvidence::None => {
                violations.push(PngPolicyViolation::MissingColorProfile);
            }
        },
    }
}

fn validate_policy(policy: &PngValidationPolicy) -> Result<(), PngArtifactError> {
    if policy.expected_width == 0
        || policy.expected_height == 0
        || policy.expected_width > MAX_DIMENSION
        || policy.expected_height > MAX_DIMENSION
    {
        return Err(PngArtifactError::InvalidPolicyDimensions);
    }
    if policy.allowed_color_types.is_empty() {
        return Err(PngArtifactError::EmptyAllowedColorTypes);
    }
    if let PngProfileRequirement::IccProfile { profile_name } = &policy.profile_requirement
        && profile_name.trim().is_empty()
    {
        return Err(PngArtifactError::EmptyIccProfileName);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Ihdr {
    width: u32,
    height: u32,
    bit_depth: u8,
    color_type: PngColorType,
    compression_method: u8,
    filter_method: u8,
    interlace_method: u8,
}

fn parse_ihdr(data: &[u8]) -> Result<Ihdr, PngArtifactError> {
    if data.len() != 13 {
        return Err(PngArtifactError::InvalidIhdrLength);
    }
    let width = u32::from_be_bytes(
        data[0..4]
            .try_into()
            .map_err(|_| PngArtifactError::InvalidIhdrLength)?,
    );
    let height = u32::from_be_bytes(
        data[4..8]
            .try_into()
            .map_err(|_| PngArtifactError::InvalidIhdrLength)?,
    );
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err(PngArtifactError::InvalidDimensions);
    }
    let bit_depth = data[8];
    let color_type = PngColorType::from_byte(data[9])?;
    if !valid_bit_depth(bit_depth, color_type) {
        return Err(PngArtifactError::InvalidBitDepth {
            bit_depth,
            color_type,
        });
    }
    let compression_method = data[10];
    if compression_method != 0 {
        return Err(PngArtifactError::InvalidCompressionMethod);
    }
    let filter_method = data[11];
    if filter_method != 0 {
        return Err(PngArtifactError::InvalidFilterMethod);
    }
    let interlace_method = data[12];
    if interlace_method > 1 {
        return Err(PngArtifactError::InvalidInterlaceMethod);
    }
    Ok(Ihdr {
        width,
        height,
        bit_depth,
        color_type,
        compression_method,
        filter_method,
        interlace_method,
    })
}

fn valid_bit_depth(bit_depth: u8, color_type: PngColorType) -> bool {
    match color_type {
        PngColorType::Grayscale => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
        PngColorType::Truecolor
        | PngColorType::GrayscaleAlpha
        | PngColorType::TruecolorAlpha => matches!(bit_depth, 8 | 16),
        PngColorType::Indexed => matches!(bit_depth, 1 | 2 | 4 | 8),
    }
}

fn parse_iccp_name(data: &[u8]) -> Result<String, PngArtifactError> {
    let separator = data
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(PngArtifactError::InvalidIccChunk)?;
    if !(1..=79).contains(&separator) || data.len() <= separator + 2 {
        return Err(PngArtifactError::InvalidIccChunk);
    }
    let name_bytes = &data[..separator];
    if name_bytes
        .iter()
        .any(|byte| *byte < 32 || (127..=160).contains(byte))
    {
        return Err(PngArtifactError::InvalidIccChunk);
    }
    if data[separator + 1] != 0 || data[separator + 2..].is_empty() {
        return Err(PngArtifactError::InvalidIccChunk);
    }
    Ok(String::from_utf8_lossy(name_bytes).into_owned())
}

fn is_unknown_critical(chunk_type: &str) -> bool {
    let known = matches!(chunk_type, "IHDR" | "PLTE" | "IDAT" | "IEND");
    !known
        && chunk_type
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_uppercase)
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

fn report_digest(report: &PngArtifactReport) -> Result<String, PngArtifactError> {
    let mut value = serde_json::to_value(report)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| serde_json::Error::io(std::io::Error::other("report is not an object")))?;
    object.insert(
        "report_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

fn validation_digest(result: &PngValidationResult) -> Result<String, PngArtifactError> {
    let mut value = serde_json::to_value(result)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| serde_json::Error::io(std::io::Error::other("result is not an object")))?;
    object.insert(
        "decision_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

#[cfg(test)]
mod tests {
    use super::crc32_pair;

    #[test]
    fn crc32_matches_png_reference_vector() {
        assert_eq!(crc32_pair(b"IEND", &[]), 0xae42_6082);
    }
}
