use std::fs;
use std::path::{Path, PathBuf};

use ergaxiom_inkscape_adapter_runtime::{
    ExportMediaType, InkscapeAdapterError, ProofBoundDesignRequest, ProofBoundExportRequest,
    ProofBoundOperation, ProofBoundOperatorError, VerifiedInkscape,
};
use ergaxiom_png_artifact_validator_runtime::{
    PngArtifactError, PngColorProfileEvidence, PngColorType, inspect_png_bytes,
};
use thiserror::Error;

use crate::model::{
    BrandExportExecution, BrandExportExecutionRecord, BrandExportExecutionRequest,
    BrandExportFailure, BrandExportValidationReport, BrandFailureCode, BrandRuleManifest,
};
use crate::normalization::{
    BrandPngNormalizationError, normalize_brand_png_srgb, verify_brand_png_normalization,
};
use crate::svg::{BrandSvgError, validate_brand_source};
use crate::util::{
    BrandDigestError, canonical_record_digest, canonical_value_digest, is_sha256, sha256_hex,
};

const RECORD_SCHEMA: &str = "0.1.0";
const VALIDATION_SCHEMA: &str = "0.1.0";
const VALIDATOR_VERSION: &str = "0.1.0";
const OPERATOR_ID: &str = "brand.export_with_inkscape";
const OPERATOR_VERSION: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum BrandExportRuntimeError {
    #[error("execution request identifier is empty or invalid")]
    InvalidRequestId,
    #[error("expected execution digest is invalid: {0}")]
    InvalidExpectedDigest(&'static str),
    #[error("execution input digest does not match the sealed request: {0}")]
    InputDigestMismatch(&'static str),
    #[error("source SVG does not satisfy the resolved brand manifest")]
    SourceBrandValidationRejected,
    #[error("execution workspace output already exists: {0}")]
    OutputAlreadyExists(String),
    #[error("Inkscape proof-bound record is incomplete or unverified")]
    UnverifiedAdapterRecord,
    #[error("delivery PNG does not satisfy the certified technical profile")]
    UnexpectedPngProfile,
    #[error("source SVG changed during execution")]
    SourceMutated,
    #[error("execution record does not bind the supplied artifacts")]
    RecordBindingMismatch,
    #[error("execution record is not verified and source-immutable")]
    RecordNotVerified,
    #[error("execution record digest does not reproduce")]
    RecordDigestMismatch,
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Svg(#[from] BrandSvgError),
    #[error(transparent)]
    Adapter(#[from] InkscapeAdapterError),
    #[error(transparent)]
    Operator(#[from] ProofBoundOperatorError),
    #[error(transparent)]
    Png(#[from] PngArtifactError),
    #[error(transparent)]
    Normalization(#[from] BrandPngNormalizationError),
    #[error(transparent)]
    Digest(#[from] BrandDigestError),
}

pub fn execute_brand_export(
    inkscape: &VerifiedInkscape,
    request: BrandExportExecutionRequest<'_>,
    workspace: impl AsRef<Path>,
) -> Result<BrandExportExecution, BrandExportRuntimeError> {
    validate_request(&request)?;
    let source_digest = sha256_hex(request.source_svg);
    let manifest_digest = canonical_value_digest(request.manifest)?;
    let logo_digest = sha256_hex(request.approved_logo_png);
    if source_digest != request.expected_source_digest {
        return Err(BrandExportRuntimeError::InputDigestMismatch("source_svg"));
    }
    if manifest_digest != request.expected_manifest_digest {
        return Err(BrandExportRuntimeError::InputDigestMismatch(
            "brand_manifest",
        ));
    }
    if logo_digest != request.expected_logo_digest {
        return Err(BrandExportRuntimeError::InputDigestMismatch(
            "approved_logo",
        ));
    }

    let source_validation = validate_brand_source(
        request.source_svg,
        request.approved_logo_png,
        request.manifest,
    )?;
    if !source_validation.accepted {
        return Err(BrandExportRuntimeError::SourceBrandValidationRejected);
    }

    let workspace = workspace.as_ref();
    fs::create_dir_all(workspace)?;
    let paths = ExportPaths::new(workspace, request.request_id);
    for path in paths.all() {
        if path.exists() {
            return Err(BrandExportRuntimeError::OutputAlreadyExists(
                path.display().to_string(),
            ));
        }
    }
    fs::write(&paths.source_svg, request.source_svg)?;
    let record = inkscape.execute_proof_bound_design(&ProofBoundDesignRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: format!("{}.brand-export", request.request_id),
        source_svg: paths.source_svg.clone(),
        expected_source_digest: source_digest.clone(),
        editable_output_svg: paths.editable_svg.clone(),
        operations: vec![ProofBoundOperation::SetFill {
            target_id: request.manifest.background.element_id.clone(),
            fill: request.manifest.background.color.clone(),
        }],
        exports: vec![ProofBoundExportRequest {
            export_id: "brand-delivery-png".to_owned(),
            media_type: ExportMediaType::Png,
            output_path: paths.raw_export_png.clone(),
            width_px: Some(request.manifest.canvas_width_px),
            height_px: Some(request.manifest.canvas_height_px),
        }],
    })?;
    if !record.verified
        || !record.source_immutable
        || record.operation_receipts.len() != 1
        || record.export_receipts.len() != 1
        || !record.operation_receipts[0].verified
    {
        return Err(BrandExportRuntimeError::UnverifiedAdapterRecord);
    }
    if sha256_hex(&fs::read(&paths.source_svg)?) != source_digest {
        return Err(BrandExportRuntimeError::SourceMutated);
    }
    let editable_svg = fs::read(&paths.editable_svg)?;
    let raw_export_png = fs::read(&paths.raw_export_png)?;
    let raw_png = inspect_png_bytes(&raw_export_png)?;
    if raw_png.width != request.manifest.canvas_width_px
        || raw_png.height != request.manifest.canvas_height_px
        || raw_png.bit_depth != 8
        || !matches!(
            raw_png.color_type,
            PngColorType::Truecolor | PngColorType::TruecolorAlpha
        )
    {
        return Err(BrandExportRuntimeError::UnexpectedPngProfile);
    }
    let normalization = normalize_brand_png_srgb(&raw_export_png)?;
    fs::write(&paths.delivery_png, &normalization.png)?;
    let delivery_png = normalization.png;
    let png = inspect_png_bytes(&delivery_png)?;
    if png.width != request.manifest.canvas_width_px
        || png.height != request.manifest.canvas_height_px
        || png.bit_depth != 8
        || !matches!(
            png.color_type,
            PngColorType::Truecolor | PngColorType::TruecolorAlpha
        )
    {
        return Err(BrandExportRuntimeError::UnexpectedPngProfile);
    }
    let identity = inkscape.identity();
    let mut execution_record = BrandExportExecutionRecord {
        schema_version: RECORD_SCHEMA.to_owned(),
        request_id: request.request_id.to_owned(),
        operator_id: OPERATOR_ID.to_owned(),
        operator_version: OPERATOR_VERSION.to_owned(),
        source_svg_digest: source_digest,
        manifest_digest,
        approved_logo_digest: logo_digest,
        source_validation_report_digest: source_validation.report_digest.clone(),
        editable_svg_digest: sha256_hex(&editable_svg),
        raw_export_png_digest: sha256_hex(&raw_export_png),
        normalization_record: normalization.record,
        delivery_png_digest: sha256_hex(&delivery_png),
        width: png.width,
        height: png.height,
        application_id: identity.application_id.clone(),
        application_version: identity.version_text.clone(),
        executable_digest: identity.executable_digest.clone(),
        adapter_record_digest: record.record_digest,
        source_immutable: true,
        verified: true,
        record_digest: String::new(),
    };
    execution_record.record_digest = canonical_record_digest(&execution_record, "record_digest")?;
    Ok(BrandExportExecution {
        editable_svg,
        raw_export_png,
        delivery_png,
        source_validation,
        record: execution_record,
    })
}

pub fn validate_brand_export(
    source_svg: &[u8],
    approved_logo_png: &[u8],
    manifest: &BrandRuleManifest,
    editable_svg: &[u8],
    raw_export_png: &[u8],
    delivery_png: &[u8],
    execution_record: &BrandExportExecutionRecord,
) -> Result<BrandExportValidationReport, BrandExportRuntimeError> {
    validate_execution_record(execution_record)?;
    let source_validation = validate_brand_source(source_svg, approved_logo_png, manifest)?;
    let manifest_digest = canonical_value_digest(manifest)?;
    let source_digest = sha256_hex(source_svg);
    let logo_digest = sha256_hex(approved_logo_png);
    let editable_digest = sha256_hex(editable_svg);
    let raw_export_digest = sha256_hex(raw_export_png);
    let output_digest = sha256_hex(delivery_png);
    if execution_record.source_svg_digest != source_digest
        || execution_record.manifest_digest != manifest_digest
        || execution_record.approved_logo_digest != logo_digest
        || execution_record.editable_svg_digest != editable_digest
        || execution_record.raw_export_png_digest != raw_export_digest
        || execution_record.delivery_png_digest != output_digest
        || execution_record.source_validation_report_digest != source_validation.report_digest
    {
        return Err(BrandExportRuntimeError::RecordBindingMismatch);
    }
    verify_brand_png_normalization(
        raw_export_png,
        delivery_png,
        &execution_record.normalization_record,
    )?;
    let png = inspect_png_bytes(delivery_png)?;
    let output_media_type_png = png.width == manifest.canvas_width_px
        && png.height == manifest.canvas_height_px
        && png.bit_depth == 8
        && matches!(
            png.color_type,
            PngColorType::Truecolor | PngColorType::TruecolorAlpha
        );
    let output_srgb = matches!(png.color_profile, PngColorProfileEvidence::Srgb { .. });
    let inkscape_export_verified = execution_record.verified
        && execution_record.application_id == "org.inkscape.Inkscape"
        && is_sha256(&execution_record.executable_digest)
        && !execution_record.adapter_record_digest.is_empty();
    let accepted = source_validation.accepted
        && output_media_type_png
        && output_srgb
        && execution_record.source_immutable
        && inkscape_export_verified;
    let mut report = BrandExportValidationReport {
        schema_version: VALIDATION_SCHEMA.to_owned(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        source_svg_digest: source_digest,
        manifest_digest,
        approved_logo_digest: logo_digest,
        editable_svg_digest: editable_digest,
        raw_export_png_digest: raw_export_digest,
        normalization_record: execution_record.normalization_record.clone(),
        delivery_png_digest: output_digest,
        width: png.width,
        height: png.height,
        restricted_svg_profile: source_validation.restricted_svg_profile,
        canvas_dimensions_match: source_validation.canvas_dimensions_match,
        palette_violation_count: source_validation.palette_violation_count,
        logo_digest_matches: source_validation.logo_digest_matches,
        logo_geometry_matches: source_validation.logo_geometry_matches,
        logo_clear_space_satisfied: source_validation.logo_clear_space_satisfied,
        typography_matches: source_validation.typography_matches,
        approved_copy_matches: source_validation.approved_copy_matches,
        output_media_type_png,
        output_srgb,
        source_immutable: execution_record.source_immutable,
        inkscape_export_verified,
        accepted,
        report_digest: String::new(),
    };
    report.report_digest = canonical_record_digest(&report, "report_digest")?;
    Ok(report)
}

pub fn brand_export_failure_map(report: &BrandExportValidationReport) -> Vec<BrandExportFailure> {
    let mut failures = Vec::new();
    if !report.restricted_svg_profile {
        failures.push(failure(
            BrandFailureCode::RestrictedSvgProfile,
            "The SVG contains unsupported structure or brand elements.",
            "Rebuild the source using the certified root, background, embedded-logo and direct-text profile.",
        ));
    }
    if !report.canvas_dimensions_match {
        failures.push(failure(
            BrandFailureCode::CanvasDimensions,
            "Canvas dimensions or viewBox do not match the brand manifest.",
            "Set width, height and viewBox to the exact approved canvas.",
        ));
    }
    if report.palette_violation_count != 0 {
        failures.push(failure(
            BrandFailureCode::PaletteAllowlist,
            "One or more SVG fill colors are outside the approved palette.",
            "Replace every unapproved fill with an exact #rrggbb value from allowed_palette.",
        ));
    }
    if !report.logo_digest_matches {
        failures.push(failure(
            BrandFailureCode::LogoIdentity,
            "The embedded logo bytes do not match the approved logo digest.",
            "Embed the exact approved PNG as a data URI without recompression or alteration.",
        ));
    }
    if !report.logo_geometry_matches {
        failures.push(failure(
            BrandFailureCode::LogoGeometry,
            "Logo position or dimensions differ from the approved rule.",
            "Restore the exact x, y, width and height values from the manifest.",
        ));
    }
    if !report.logo_clear_space_satisfied {
        failures.push(failure(
            BrandFailureCode::LogoClearSpace,
            "Logo clear space is below the approved minimum.",
            "Move or resize the logo so every canvas edge preserves the required clear space.",
        ));
    }
    if !report.typography_matches {
        failures.push(failure(
            BrandFailureCode::Typography,
            "Typography attributes differ from the approved rule.",
            "Restore the exact font family, size, weight, position, color and anchor.",
        ));
    }
    if !report.approved_copy_matches {
        failures.push(failure(
            BrandFailureCode::ApprovedCopy,
            "Direct text differs from the approved copy.",
            "Replace the text with the exact approved UTF-8 copy.",
        ));
    }
    if !report.output_media_type_png {
        failures.push(failure(
            BrandFailureCode::OutputMediaType,
            "The delivery artifact is not a valid 8-bit PNG at the approved dimensions.",
            "Export a PNG with the exact approved width and height.",
        ));
    }
    if !report.output_srgb {
        failures.push(failure(
            BrandFailureCode::OutputColorProfile,
            "The delivery PNG has no certified sRGB chunk.",
            "Re-run the verified IDAT-preserving sRGB normalization after the pinned Inkscape export.",
        ));
    }
    if !report.source_immutable {
        failures.push(failure(
            BrandFailureCode::SourceImmutability,
            "The source SVG changed during execution.",
            "Restart in a fresh isolated workspace from the sealed source digest.",
        ));
    }
    if !report.inkscape_export_verified {
        failures.push(failure(
            BrandFailureCode::InkscapeIntegration,
            "Pinned Inkscape execution evidence is missing or invalid.",
            "Re-run export with the trusted executable and proof-bound adapter.",
        ));
    }
    failures
}

fn validate_request(
    request: &BrandExportExecutionRequest<'_>,
) -> Result<(), BrandExportRuntimeError> {
    if request.request_id.is_empty()
        || !request
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(BrandExportRuntimeError::InvalidRequestId);
    }
    for (field, digest) in [
        ("source_svg", request.expected_source_digest),
        ("brand_manifest", request.expected_manifest_digest),
        ("approved_logo", request.expected_logo_digest),
    ] {
        if !is_sha256(digest) {
            return Err(BrandExportRuntimeError::InvalidExpectedDigest(field));
        }
    }
    Ok(())
}

fn validate_execution_record(
    record: &BrandExportExecutionRecord,
) -> Result<(), BrandExportRuntimeError> {
    if !record.verified || !record.source_immutable {
        return Err(BrandExportRuntimeError::RecordNotVerified);
    }
    if record.record_digest != canonical_record_digest(record, "record_digest")? {
        return Err(BrandExportRuntimeError::RecordDigestMismatch);
    }
    Ok(())
}

fn failure(code: BrandFailureCode, message: &str, action: &str) -> BrandExportFailure {
    BrandExportFailure {
        code,
        message: message.to_owned(),
        action: action.to_owned(),
    }
}

struct ExportPaths {
    source_svg: PathBuf,
    editable_svg: PathBuf,
    raw_export_png: PathBuf,
    delivery_png: PathBuf,
}

impl ExportPaths {
    fn new(workspace: &Path, request_id: &str) -> Self {
        Self {
            source_svg: workspace.join(format!("{request_id}-source.svg")),
            editable_svg: workspace.join(format!("{request_id}-editable.svg")),
            raw_export_png: workspace.join(format!("{request_id}-inkscape-raw.png")),
            delivery_png: workspace.join(format!("{request_id}-delivery.png")),
        }
    }

    fn all(&self) -> [&Path; 4] {
        [
            self.source_svg.as_path(),
            self.editable_svg.as_path(),
            self.raw_export_png.as_path(),
            self.delivery_png.as_path(),
        ]
    }
}
