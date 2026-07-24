use ergaxiom_png_artifact_validator_runtime::{
    PngArtifactError, PngColorProfileEvidence, inspect_png_bytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::util::{BrandDigestError, canonical_record_digest, sha256_hex};

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const RECORD_SCHEMA: &str = "0.1.0";
const SRGB_RENDERING_INTENT: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandPngNormalizationRecord {
    pub schema_version: String,
    pub input_png_digest: String,
    pub output_png_digest: String,
    pub input_report_digest: String,
    pub output_report_digest: String,
    pub input_idat_payload_digest: String,
    pub output_idat_payload_digest: String,
    pub inserted_srgb_crc32: String,
    pub rendering_intent: u8,
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    pub verified: bool,
    pub record_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandPngNormalization {
    pub png: Vec<u8>,
    pub record: BrandPngNormalizationRecord,
}

#[derive(Debug, Error)]
pub enum BrandPngNormalizationError {
    #[error("input PNG already contains a color-profile signal")]
    ExistingColorProfile,
    #[error("PNG IDAT payload is missing")]
    MissingIdat,
    #[error("normalization changed PNG IDAT payload bytes")]
    IdatMutation,
    #[error("normalized PNG did not contain the expected sRGB signal")]
    OutputProfileMismatch,
    #[error("normalization record is not verified")]
    RecordNotVerified,
    #[error("normalization record digest does not reproduce")]
    RecordDigestMismatch,
    #[error("normalization record does not bind the supplied PNG artifacts")]
    RecordBindingMismatch,
    #[error(transparent)]
    Png(#[from] PngArtifactError),
    #[error(transparent)]
    Digest(#[from] BrandDigestError),
}

pub fn normalize_brand_png_srgb(
    input_png: &[u8],
) -> Result<BrandPngNormalization, BrandPngNormalizationError> {
    let input_report = inspect_png_bytes(input_png)?;
    if !matches!(input_report.color_profile, PngColorProfileEvidence::None) {
        return Err(BrandPngNormalizationError::ExistingColorProfile);
    }
    let input_idat_payload_digest = idat_payload_digest(input_png)?;
    let (output_png, inserted_srgb_crc32) = insert_srgb_chunk(input_png, SRGB_RENDERING_INTENT)?;
    let output_report = inspect_png_bytes(&output_png)?;
    if output_report.color_profile
        != (PngColorProfileEvidence::Srgb {
            rendering_intent: SRGB_RENDERING_INTENT,
        })
    {
        return Err(BrandPngNormalizationError::OutputProfileMismatch);
    }
    let output_idat_payload_digest = idat_payload_digest(&output_png)?;
    if input_idat_payload_digest != output_idat_payload_digest {
        return Err(BrandPngNormalizationError::IdatMutation);
    }
    let mut record = BrandPngNormalizationRecord {
        schema_version: RECORD_SCHEMA.to_owned(),
        input_png_digest: input_report.artifact_digest,
        output_png_digest: output_report.artifact_digest,
        input_report_digest: input_report.report_digest,
        output_report_digest: output_report.report_digest,
        input_idat_payload_digest,
        output_idat_payload_digest,
        inserted_srgb_crc32,
        rendering_intent: SRGB_RENDERING_INTENT,
        width: output_report.width,
        height: output_report.height,
        bit_depth: output_report.bit_depth,
        verified: true,
        record_digest: String::new(),
    };
    record.record_digest = canonical_record_digest(&record, "record_digest")?;
    Ok(BrandPngNormalization {
        png: output_png,
        record,
    })
}

pub fn verify_brand_png_normalization(
    input_png: &[u8],
    output_png: &[u8],
    record: &BrandPngNormalizationRecord,
) -> Result<(), BrandPngNormalizationError> {
    if !record.verified {
        return Err(BrandPngNormalizationError::RecordNotVerified);
    }
    if record.record_digest != canonical_record_digest(record, "record_digest")? {
        return Err(BrandPngNormalizationError::RecordDigestMismatch);
    }
    let recomputed = normalize_brand_png_srgb(input_png)?;
    if recomputed.png != output_png
        || recomputed.record.input_png_digest != record.input_png_digest
        || recomputed.record.output_png_digest != record.output_png_digest
        || recomputed.record.input_report_digest != record.input_report_digest
        || recomputed.record.output_report_digest != record.output_report_digest
        || recomputed.record.input_idat_payload_digest != record.input_idat_payload_digest
        || recomputed.record.output_idat_payload_digest != record.output_idat_payload_digest
        || recomputed.record.inserted_srgb_crc32 != record.inserted_srgb_crc32
        || recomputed.record.rendering_intent != record.rendering_intent
        || recomputed.record.width != record.width
        || recomputed.record.height != record.height
        || recomputed.record.bit_depth != record.bit_depth
        || sha256_hex(input_png) != record.input_png_digest
        || sha256_hex(output_png) != record.output_png_digest
    {
        return Err(BrandPngNormalizationError::RecordBindingMismatch);
    }
    Ok(())
}

fn insert_srgb_chunk(
    input: &[u8],
    rendering_intent: u8,
) -> Result<(Vec<u8>, String), BrandPngNormalizationError> {
    if input.len() < PNG_SIGNATURE.len() + 25 || &input[..8] != PNG_SIGNATURE {
        return Err(PngArtifactError::InvalidSignature.into());
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
        return Err(PngArtifactError::IhdrNotFirst.into());
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

fn idat_payload_digest(bytes: &[u8]) -> Result<String, BrandPngNormalizationError> {
    if bytes.len() < 8 || &bytes[..8] != PNG_SIGNATURE {
        return Err(PngArtifactError::InvalidSignature.into());
    }
    let mut offset = 8_usize;
    let mut hasher = Sha256::new();
    let mut found = false;
    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err(PngArtifactError::TruncatedChunk.into());
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
            return Err(PngArtifactError::TruncatedChunk.into());
        }
        if &bytes[offset + 4..offset + 8] == b"IDAT" {
            found = true;
            hasher.update(&bytes[data_start..data_end]);
        }
        offset = chunk_end;
    }
    if !found {
        return Err(BrandPngNormalizationError::MissingIdat);
    }
    Ok(format!("{:x}", hasher.finalize()))
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
