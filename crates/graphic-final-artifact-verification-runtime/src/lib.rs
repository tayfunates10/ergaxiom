#![forbid(unsafe_code)]

use ergaxiom_png_logo_geometry_runtime::LogoGeometryResult;
use ergaxiom_png_rendered_contrast_runtime::{PixelRect as ContrastRect, RenderedContrastResult};
use ergaxiom_png_rendered_text_bounds_runtime::{PixelRect as TextRect, RenderedTextBoundsResult};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_svg_approved_copy_runtime::ApprovedCopyResult;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalArtifactExpectations {
    pub approved_copy_artifact_digest: String,
    pub approved_logo_artifact_digest: String,
    pub editable_svg_digest: String,
    pub normalized_png_digest: String,
    pub target_element_id: String,
}

pub struct FinalArtifactVerificationRequest<'a> {
    pub expectations: FinalArtifactExpectations,
    pub approved_copy: &'a ApprovedCopyResult,
    pub logo_geometry: &'a LogoGeometryResult,
    pub text_bounds: &'a RenderedTextBoundsResult,
    pub rendered_contrast: &'a RenderedContrastResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalArtifactVerificationBinding {
    pub schema_version: String,
    pub approved_copy_artifact_digest: String,
    pub approved_logo_artifact_digest: String,
    pub editable_svg_digest: String,
    pub normalized_png_digest: String,
    pub target_element_id: String,
    pub approved_copy_report_digest: String,
    pub approved_copy_decision_digest: String,
    pub logo_geometry_report_digest: String,
    pub logo_geometry_decision_digest: String,
    pub text_bounds_report_digest: String,
    pub text_bounds_decision_digest: String,
    pub rendered_contrast_report_digest: String,
    pub rendered_contrast_decision_digest: String,
    pub shared_pixel_report_digest: String,
    pub shared_rgba_pixel_digest: String,
    pub text_analysis_region: EvidenceRect,
    pub text_safe_area: EvidenceRect,
    pub observed_text_bounds: EvidenceRect,
    pub contrast_subject_region: EvidenceRect,
    pub minimum_dominant_contrast_milli: u32,
    pub logo_mask_iou_milli: u16,
    pub logo_aspect_ratio_error_ppm: u32,
    pub clear_space_intrusion_pixel_count: u64,
    pub binding_digest: String,
}

#[derive(Debug, Error)]
pub enum FinalArtifactVerificationError {
    #[error("expected digest field is invalid: {0}")]
    InvalidExpectedDigest(&'static str),
    #[error("target element id must not be empty")]
    EmptyTargetElementId,
    #[error("{0} validator did not accept the artifact")]
    ValidatorRejected(&'static str),
    #[error("{0} validator reports acceptance with non-empty violations")]
    ContradictoryValidatorResult(&'static str),
    #[error("approved-copy evidence is not bound to the expected input, SVG or target")]
    ApprovedCopyBindingMismatch,
    #[error("logo-geometry evidence is not bound to the expected approved logo")]
    ApprovedLogoBindingMismatch,
    #[error("one or more raster validators are not bound to the normalized PNG")]
    RasterArtifactBindingMismatch,
    #[error("raster validators did not consume the same independent pixel decode")]
    PixelDecodeBindingMismatch,
    #[error("rendered contrast and text-bounds validators do not cover the same analysis region")]
    TextRegionBindingMismatch,
    #[error("accepted text-bounds evidence has no observed foreground bounds")]
    MissingObservedTextBounds,
    #[error("failed to serialize final artifact verification material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn verify_final_artifacts(
    request: FinalArtifactVerificationRequest<'_>,
) -> Result<FinalArtifactVerificationBinding, FinalArtifactVerificationError> {
    validate_expectations(&request.expectations)?;
    validate_result(
        "approved_copy",
        request.approved_copy.accepted,
        request.approved_copy.violations.is_empty(),
    )?;
    validate_result(
        "logo_geometry",
        request.logo_geometry.accepted,
        request.logo_geometry.violations.is_empty(),
    )?;
    validate_result(
        "text_bounds",
        request.text_bounds.accepted,
        request.text_bounds.violations.is_empty(),
    )?;
    validate_result(
        "rendered_contrast",
        request.rendered_contrast.accepted,
        request.rendered_contrast.violations.is_empty(),
    )?;

    let expected = &request.expectations;
    let copy = &request.approved_copy.report;
    if copy.approved_copy_digest != expected.approved_copy_artifact_digest
        || copy.svg_artifact_digest != expected.editable_svg_digest
        || copy.target_element_id != expected.target_element_id
        || !copy.exact_match
    {
        return Err(FinalArtifactVerificationError::ApprovedCopyBindingMismatch);
    }

    let logo = &request.logo_geometry.report;
    if logo.approved_artifact_digest != expected.approved_logo_artifact_digest {
        return Err(FinalArtifactVerificationError::ApprovedLogoBindingMismatch);
    }

    let text = &request.text_bounds.report;
    let contrast = &request.rendered_contrast.report;
    if logo.rendered_artifact_digest != expected.normalized_png_digest
        || text.artifact_digest != expected.normalized_png_digest
        || contrast.artifact_digest != expected.normalized_png_digest
    {
        return Err(FinalArtifactVerificationError::RasterArtifactBindingMismatch);
    }

    if logo.rendered_pixel_report_digest != text.pixel_report_digest
        || logo.rendered_pixel_report_digest != contrast.pixel_report_digest
        || logo.rendered_rgba_pixel_digest != text.rgba_pixel_digest
        || logo.rendered_rgba_pixel_digest != contrast.rgba_pixel_digest
    {
        return Err(FinalArtifactVerificationError::PixelDecodeBindingMismatch);
    }

    if rect_from_text(text.analysis_region) != rect_from_contrast(contrast.subject_region) {
        return Err(FinalArtifactVerificationError::TextRegionBindingMismatch);
    }
    let observed_text_bounds = text
        .observed_bounds
        .map(rect_from_text)
        .ok_or(FinalArtifactVerificationError::MissingObservedTextBounds)?;

    validate_evidence_digest(
        &request.approved_copy.report.report_digest,
        "approved_copy.report_digest",
    )?;
    validate_evidence_digest(
        &request.approved_copy.decision_digest,
        "approved_copy.decision_digest",
    )?;
    validate_evidence_digest(
        &request.logo_geometry.report.report_digest,
        "logo_geometry.report_digest",
    )?;
    validate_evidence_digest(
        &request.logo_geometry.decision_digest,
        "logo_geometry.decision_digest",
    )?;
    validate_evidence_digest(
        &request.text_bounds.report.report_digest,
        "text_bounds.report_digest",
    )?;
    validate_evidence_digest(
        &request.text_bounds.decision_digest,
        "text_bounds.decision_digest",
    )?;
    validate_evidence_digest(
        &request.rendered_contrast.report.report_digest,
        "rendered_contrast.report_digest",
    )?;
    validate_evidence_digest(
        &request.rendered_contrast.decision_digest,
        "rendered_contrast.decision_digest",
    )?;

    let mut binding = FinalArtifactVerificationBinding {
        schema_version: SCHEMA_VERSION.to_owned(),
        approved_copy_artifact_digest: expected.approved_copy_artifact_digest.clone(),
        approved_logo_artifact_digest: expected.approved_logo_artifact_digest.clone(),
        editable_svg_digest: expected.editable_svg_digest.clone(),
        normalized_png_digest: expected.normalized_png_digest.clone(),
        target_element_id: expected.target_element_id.clone(),
        approved_copy_report_digest: request.approved_copy.report.report_digest.clone(),
        approved_copy_decision_digest: request.approved_copy.decision_digest.clone(),
        logo_geometry_report_digest: request.logo_geometry.report.report_digest.clone(),
        logo_geometry_decision_digest: request.logo_geometry.decision_digest.clone(),
        text_bounds_report_digest: request.text_bounds.report.report_digest.clone(),
        text_bounds_decision_digest: request.text_bounds.decision_digest.clone(),
        rendered_contrast_report_digest: request.rendered_contrast.report.report_digest.clone(),
        rendered_contrast_decision_digest: request.rendered_contrast.decision_digest.clone(),
        shared_pixel_report_digest: logo.rendered_pixel_report_digest.clone(),
        shared_rgba_pixel_digest: logo.rendered_rgba_pixel_digest.clone(),
        text_analysis_region: rect_from_text(text.analysis_region),
        text_safe_area: rect_from_text(text.safe_area),
        observed_text_bounds,
        contrast_subject_region: rect_from_contrast(contrast.subject_region),
        minimum_dominant_contrast_milli: contrast.minimum_dominant_contrast_milli,
        logo_mask_iou_milli: logo.mask_iou_milli,
        logo_aspect_ratio_error_ppm: logo.aspect_ratio_error_ppm,
        clear_space_intrusion_pixel_count: logo.clear_space_intrusion_pixel_count,
        binding_digest: String::new(),
    };
    binding.binding_digest = binding_digest(&binding)?;
    Ok(binding)
}

fn validate_expectations(
    expectations: &FinalArtifactExpectations,
) -> Result<(), FinalArtifactVerificationError> {
    validate_evidence_digest(
        &expectations.approved_copy_artifact_digest,
        "approved_copy_artifact_digest",
    )?;
    validate_evidence_digest(
        &expectations.approved_logo_artifact_digest,
        "approved_logo_artifact_digest",
    )?;
    validate_evidence_digest(&expectations.editable_svg_digest, "editable_svg_digest")?;
    validate_evidence_digest(&expectations.normalized_png_digest, "normalized_png_digest")?;
    if expectations.target_element_id.trim().is_empty() {
        return Err(FinalArtifactVerificationError::EmptyTargetElementId);
    }
    Ok(())
}

fn validate_result(
    name: &'static str,
    accepted: bool,
    violations_empty: bool,
) -> Result<(), FinalArtifactVerificationError> {
    if !accepted {
        return Err(FinalArtifactVerificationError::ValidatorRejected(name));
    }
    if !violations_empty {
        return Err(FinalArtifactVerificationError::ContradictoryValidatorResult(name));
    }
    Ok(())
}

fn validate_evidence_digest(
    digest: &str,
    field: &'static str,
) -> Result<(), FinalArtifactVerificationError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FinalArtifactVerificationError::InvalidExpectedDigest(field));
    }
    Ok(())
}

fn rect_from_text(rect: TextRect) -> EvidenceRect {
    EvidenceRect {
        x: rect.x,
        y: rect.y,
        width: rect.width,
        height: rect.height,
    }
}

fn rect_from_contrast(rect: ContrastRect) -> EvidenceRect {
    EvidenceRect {
        x: rect.x,
        y: rect.y,
        width: rect.width,
        height: rect.height,
    }
}

fn binding_digest(
    binding: &FinalArtifactVerificationBinding,
) -> Result<String, FinalArtifactVerificationError> {
    let mut value = serde_json::to_value(binding)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other(
            "final artifact binding is not an object",
        ))
    })?;
    object.insert(
        "binding_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

#[cfg(test)]
mod tests {
    use super::{FinalArtifactVerificationError, validate_evidence_digest};

    #[test]
    fn lowercase_sha256_validation_is_fail_closed() {
        assert!(validate_evidence_digest(&"a".repeat(64), "digest").is_ok());
        assert!(matches!(
            validate_evidence_digest(&"A".repeat(64), "digest"),
            Err(FinalArtifactVerificationError::InvalidExpectedDigest(
                "digest"
            ))
        ));
    }
}
