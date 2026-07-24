use ergaxiom_png_artifact_validator_runtime::{
    PngArtifactError, PngColorProfileEvidence, PngColorType, inspect_png_bytes,
};
use ergaxiom_png_pixel_decoder_runtime::{PngPixelDecodeError, decode_png_bytes};
use serde_json::json;
use thiserror::Error;

use crate::model::{
    BackgroundCleanupExecution, BackgroundCleanupExecutionRecord,
    BackgroundCleanupExecutionRequest, BackgroundCleanupFailure, BackgroundCleanupValidationReport,
    CleanupFailureCode,
};
use crate::png::{RestrictedPngError, decode_restricted_rgba_png, encode_restricted_srgb_rgba_png};
use crate::util::{DigestMaterialError, canonical_digest, canonical_record_digest, sha256_hex};

const EXECUTION_SCHEMA: &str = "0.1.0";
const VALIDATION_SCHEMA: &str = "0.1.0";
const OPERATOR_ID: &str = "cleanup.apply_binary_mask";
const OPERATOR_VERSION: &str = "0.1.0";
const VALIDATOR_VERSION: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum BackgroundCleanupRuntimeError {
    #[error("cleanup request field is invalid: {0}")]
    InvalidRequest(&'static str),
    #[error("source PNG digest does not match the sealed digest")]
    SourceDigestMismatch,
    #[error("approved cleanup-mask digest does not match the sealed digest")]
    MaskDigestMismatch,
    #[error("source PNG dimensions do not match the sealed dimensions")]
    SourceDimensionMismatch,
    #[error("approved cleanup-mask dimensions do not match the source PNG")]
    MaskDimensionMismatch,
    #[error("approved cleanup-mask alpha at pixel {pixel_index} is {alpha}; expected 0 or 255")]
    NonBinaryMask { pixel_index: u64, alpha: u8 },
    #[error("approved cleanup mask must contain at least one foreground and one background pixel")]
    DegenerateMask,
    #[error("cleanup execution record does not bind the supplied source, mask and output bytes")]
    ExecutionBindingMismatch,
    #[error("independent validator observed incompatible pixel-buffer dimensions")]
    ValidatorDimensionMismatch,
    #[error(transparent)]
    RestrictedPng(#[from] RestrictedPngError),
    #[error(transparent)]
    IndependentPng(#[from] PngPixelDecodeError),
    #[error(transparent)]
    PngArtifact(#[from] PngArtifactError),
    #[error(transparent)]
    Digest(#[from] DigestMaterialError),
}

pub fn execute_background_cleanup(
    request: BackgroundCleanupExecutionRequest<'_>,
) -> Result<BackgroundCleanupExecution, BackgroundCleanupRuntimeError> {
    validate_request(&request)?;
    let source_digest = sha256_hex(request.source_png);
    if source_digest != request.expected_source_digest {
        return Err(BackgroundCleanupRuntimeError::SourceDigestMismatch);
    }
    let mask_digest = sha256_hex(request.approved_mask_png);
    if mask_digest != request.expected_mask_digest {
        return Err(BackgroundCleanupRuntimeError::MaskDigestMismatch);
    }

    let pre_state_digest = canonical_digest(&json!({
        "request_id": request.request_id,
        "source_digest": source_digest,
        "mask_digest": mask_digest,
        "expected_width": request.expected_width,
        "expected_height": request.expected_height
    }))?;
    let action_boundary_digest = canonical_digest(&json!({
        "source_digest": sha256_hex(request.source_png),
        "mask_digest": sha256_hex(request.approved_mask_png)
    }))?;

    let source = decode_restricted_rgba_png(request.source_png)?;
    let mask = decode_restricted_rgba_png(request.approved_mask_png)?;
    if !source.has_srgb || !mask.has_srgb {
        return Err(BackgroundCleanupRuntimeError::InvalidRequest(
            "source and mask PNGs must carry the restricted sRGB signal",
        ));
    }
    if source.width != request.expected_width || source.height != request.expected_height {
        return Err(BackgroundCleanupRuntimeError::SourceDimensionMismatch);
    }
    if mask.width != source.width || mask.height != source.height {
        return Err(BackgroundCleanupRuntimeError::MaskDimensionMismatch);
    }

    let mut output_pixels = Vec::with_capacity(source.pixels.len());
    let mut foreground_pixels = 0_u64;
    let mut background_pixels = 0_u64;
    for (index, (source_pixel, mask_pixel)) in source
        .pixels
        .chunks_exact(4)
        .zip(mask.pixels.chunks_exact(4))
        .enumerate()
    {
        match mask_pixel[3] {
            255 => {
                output_pixels.extend_from_slice(source_pixel);
                foreground_pixels = foreground_pixels.saturating_add(1);
            }
            0 => {
                output_pixels.extend_from_slice(&[
                    source_pixel[0],
                    source_pixel[1],
                    source_pixel[2],
                    0,
                ]);
                background_pixels = background_pixels.saturating_add(1);
            }
            alpha => {
                return Err(BackgroundCleanupRuntimeError::NonBinaryMask {
                    pixel_index: u64::try_from(index).unwrap_or(u64::MAX),
                    alpha,
                });
            }
        }
    }
    if foreground_pixels == 0 || background_pixels == 0 {
        return Err(BackgroundCleanupRuntimeError::DegenerateMask);
    }

    let cleaned_png = encode_restricted_srgb_rgba_png(
        request.expected_width,
        request.expected_height,
        &output_pixels,
    )?;
    let output_digest = sha256_hex(&cleaned_png);
    let source_immutable = sha256_hex(request.source_png) == source_digest;
    let post_state_digest = canonical_digest(&json!({
        "output_digest": output_digest,
        "width": request.expected_width,
        "height": request.expected_height,
        "foreground_pixels": foreground_pixels,
        "background_pixels": background_pixels,
        "source_immutable": source_immutable
    }))?;

    let mut record = BackgroundCleanupExecutionRecord {
        schema_version: EXECUTION_SCHEMA.to_owned(),
        request_id: request.request_id.to_owned(),
        operator_id: OPERATOR_ID.to_owned(),
        operator_version: OPERATOR_VERSION.to_owned(),
        source_digest,
        mask_digest,
        output_digest,
        width: request.expected_width,
        height: request.expected_height,
        foreground_pixels,
        background_pixels,
        pre_state_digest,
        action_boundary_digest,
        post_state_digest,
        source_immutable,
        verified: source_immutable,
        record_digest: String::new(),
    };
    record.record_digest = canonical_record_digest(&record, "record_digest")?;
    Ok(BackgroundCleanupExecution {
        cleaned_png,
        record,
    })
}

pub fn validate_background_cleanup(
    source_png: &[u8],
    approved_mask_png: &[u8],
    cleaned_png: &[u8],
    execution_record: &BackgroundCleanupExecutionRecord,
) -> Result<BackgroundCleanupValidationReport, BackgroundCleanupRuntimeError> {
    let source_digest = sha256_hex(source_png);
    let mask_digest = sha256_hex(approved_mask_png);
    let output_digest = sha256_hex(cleaned_png);
    if execution_record.source_digest != source_digest
        || execution_record.mask_digest != mask_digest
        || execution_record.output_digest != output_digest
        || execution_record.record_digest
            != canonical_record_digest(execution_record, "record_digest")?
    {
        return Err(BackgroundCleanupRuntimeError::ExecutionBindingMismatch);
    }

    let source = decode_png_bytes(source_png)?;
    let mask = decode_png_bytes(approved_mask_png)?;
    let output = decode_png_bytes(cleaned_png)?;
    let output_structure = inspect_png_bytes(cleaned_png)?;
    if source.rgba8.len() != mask.rgba8.len() || source.rgba8.len() != output.rgba8.len() {
        return Err(BackgroundCleanupRuntimeError::ValidatorDimensionMismatch);
    }

    let mask_dimensions_match = source.report.width == mask.report.width
        && source.report.height == mask.report.height
        && source.report.width == output.report.width
        && source.report.height == output.report.height
        && output.report.width == execution_record.width
        && output.report.height == execution_record.height;
    let output_media_type_png = output_structure.bit_depth == 8
        && output_structure.color_type == PngColorType::TruecolorAlpha
        && output_structure.interlace_method == 0;
    let output_srgb = matches!(
        output_structure.color_profile,
        PngColorProfileEvidence::Srgb { .. }
    );

    let mut mask_is_binary = true;
    let mut foreground_pixels = 0_u64;
    let mut background_pixels = 0_u64;
    let mut background_alpha_violations = 0_u64;
    let mut foreground_rgba_violations = 0_u64;
    for ((source_pixel, mask_pixel), output_pixel) in source
        .rgba8
        .chunks_exact(4)
        .zip(mask.rgba8.chunks_exact(4))
        .zip(output.rgba8.chunks_exact(4))
    {
        match mask_pixel[3] {
            255 => {
                foreground_pixels = foreground_pixels.saturating_add(1);
                if output_pixel != source_pixel {
                    foreground_rgba_violations = foreground_rgba_violations.saturating_add(1);
                }
            }
            0 => {
                background_pixels = background_pixels.saturating_add(1);
                if output_pixel[3] != 0 {
                    background_alpha_violations = background_alpha_violations.saturating_add(1);
                }
            }
            _ => mask_is_binary = false,
        }
    }

    let source_immutable = execution_record.source_immutable
        && execution_record.verified
        && source_digest == execution_record.source_digest;
    let accepted = output_media_type_png
        && output_srgb
        && mask_dimensions_match
        && mask_is_binary
        && foreground_pixels > 0
        && background_pixels > 0
        && background_alpha_violations == 0
        && foreground_rgba_violations == 0
        && source_immutable;

    let mut report = BackgroundCleanupValidationReport {
        schema_version: VALIDATION_SCHEMA.to_owned(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        source_digest,
        mask_digest,
        output_digest,
        width: output.report.width,
        height: output.report.height,
        output_media_type_png,
        output_srgb,
        mask_dimensions_match,
        mask_is_binary,
        mask_foreground_pixels: foreground_pixels,
        mask_background_pixels: background_pixels,
        background_alpha_violations,
        foreground_rgba_violations,
        source_immutable,
        accepted,
        report_digest: String::new(),
    };
    report.report_digest = canonical_record_digest(&report, "report_digest")?;
    Ok(report)
}

#[must_use]
pub fn background_cleanup_failure_map(
    report: &BackgroundCleanupValidationReport,
    integration_verified: bool,
) -> Vec<BackgroundCleanupFailure> {
    let mut failures = Vec::new();
    if !report.output_media_type_png {
        failures.push(failure(
            CleanupFailureCode::OutputMediaType,
            "The cleaned artifact is not a supported 8-bit RGBA PNG.",
            "Re-export the cleaned artifact as a non-interlaced 8-bit RGBA PNG.",
        ));
    }
    if !report.output_srgb {
        failures.push(failure(
            CleanupFailureCode::OutputColorProfile,
            "The cleaned PNG does not contain the certified sRGB signal.",
            "Normalize the output to the restricted sRGB profile before certification.",
        ));
    }
    if !report.mask_dimensions_match {
        failures.push(failure(
            CleanupFailureCode::MaskDimensions,
            "The approved cleanup mask does not match the source dimensions.",
            "Supply a new digest-bound mask with exactly the source width and height.",
        ));
    }
    if !report.mask_is_binary {
        failures.push(failure(
            CleanupFailureCode::MaskBinary,
            "The approved cleanup mask contains alpha samples other than 0 or 255.",
            "Resolve the mask explicitly to binary background and foreground samples.",
        ));
    }
    if report.mask_foreground_pixels == 0 || report.mask_background_pixels == 0 {
        failures.push(failure(
            CleanupFailureCode::MaskCoverage,
            "The approved cleanup mask does not contain both foreground and background.",
            "Review and approve a non-degenerate mask before execution.",
        ));
    }
    if report.background_alpha_violations != 0 {
        failures.push(failure(
            CleanupFailureCode::BackgroundAlpha,
            "One or more mask-declared background pixels remain visible.",
            "Reapply the exact approved mask and verify background alpha is zero.",
        ));
    }
    if report.foreground_rgba_violations != 0 {
        failures.push(failure(
            CleanupFailureCode::ForegroundPreservation,
            "One or more mask-declared foreground pixels changed.",
            "Restore the source RGBA samples for every approved foreground pixel.",
        ));
    }
    if !report.source_immutable {
        failures.push(failure(
            CleanupFailureCode::SourceImmutability,
            "The execution record cannot prove that source bytes remained immutable.",
            "Restage the original digest-bound source and rerun in a fresh isolated workspace.",
        ));
    }
    if !integration_verified {
        failures.push(failure(
            CleanupFailureCode::InkscapeIntegration,
            "The pinned Inkscape integration probe is missing or failed.",
            "Run the cleaned PNG through the verified Inkscape import/export probe.",
        ));
    }
    failures
}

fn validate_request(
    request: &BackgroundCleanupExecutionRequest<'_>,
) -> Result<(), BackgroundCleanupRuntimeError> {
    if request.request_id.is_empty()
        || !request
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(BackgroundCleanupRuntimeError::InvalidRequest("request_id"));
    }
    if request.expected_width == 0 || request.expected_height == 0 {
        return Err(BackgroundCleanupRuntimeError::InvalidRequest(
            "expected dimensions",
        ));
    }
    if !is_sha256(request.expected_source_digest) || !is_sha256(request.expected_mask_digest) {
        return Err(BackgroundCleanupRuntimeError::InvalidRequest(
            "trusted SHA-256 digest",
        ));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn failure(code: CleanupFailureCode, message: &str, action: &str) -> BackgroundCleanupFailure {
    BackgroundCleanupFailure {
        code,
        message: message.to_owned(),
        action: action.to_owned(),
    }
}
