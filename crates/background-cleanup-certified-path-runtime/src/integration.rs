use std::fs;
use std::path::{Path, PathBuf};

use ergaxiom_inkscape_adapter_runtime::{
    ApprovedAssetMediaType, ExportMediaType, InkscapeAdapterError, ProofBoundDesignRequest,
    ProofBoundExportRequest, ProofBoundOperation, ProofBoundOperatorError, VerifiedInkscape,
};
use ergaxiom_png_artifact_validator_runtime::{
    PngArtifactError, PngColorType, inspect_png_bytes,
};
use thiserror::Error;

use crate::model::InkscapeCleanupIntegrationReport;
use crate::util::{DigestMaterialError, canonical_record_digest, sha256_hex};

const REPORT_SCHEMA: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum CleanupInkscapeIntegrationError {
    #[error("integration request identifier is empty or invalid")]
    InvalidRequestId,
    #[error("integration probe dimensions must be positive")]
    InvalidDimensions,
    #[error("integration workspace output already exists: {0}")]
    OutputAlreadyExists(String),
    #[error("integration probe generated an unexpected PNG profile")]
    UnexpectedProbeProfile,
    #[error("integration probe record is not verified")]
    UnverifiedAdapterRecord,
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Adapter(#[from] InkscapeAdapterError),
    #[error(transparent)]
    Operator(#[from] ProofBoundOperatorError),
    #[error(transparent)]
    Png(#[from] PngArtifactError),
    #[error(transparent)]
    Digest(#[from] DigestMaterialError),
}

pub fn execute_inkscape_cleanup_probe(
    inkscape: &VerifiedInkscape,
    request_id: &str,
    cleaned_png: &[u8],
    width: u32,
    height: u32,
    workspace: impl AsRef<Path>,
) -> Result<InkscapeCleanupIntegrationReport, CleanupInkscapeIntegrationError> {
    validate_request_id(request_id)?;
    if width == 0 || height == 0 {
        return Err(CleanupInkscapeIntegrationError::InvalidDimensions);
    }
    let workspace = workspace.as_ref();
    fs::create_dir_all(workspace)?;
    let paths = ProbePaths::new(workspace, request_id);
    for path in paths.all() {
        if path.exists() {
            return Err(CleanupInkscapeIntegrationError::OutputAlreadyExists(
                path.display().to_string(),
            ));
        }
    }

    fs::write(&paths.cleaned_png, cleaned_png)?;
    let cleaned_png_digest = sha256_hex(cleaned_png);
    let source_svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}"></svg>"#
    );
    fs::write(&paths.source_svg, source_svg.as_bytes())?;
    let source_svg_digest = sha256_hex(source_svg.as_bytes());

    let record = inkscape.execute_proof_bound_design(&ProofBoundDesignRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: format!("{request_id}.inkscape-probe"),
        source_svg: paths.source_svg.clone(),
        expected_source_digest: source_svg_digest,
        editable_output_svg: paths.editable_svg.clone(),
        operations: vec![ProofBoundOperation::PlaceAsset {
            element_id: "cleaned-raster-probe".to_owned(),
            layer_id: None,
            asset_path: paths.cleaned_png.clone(),
            expected_asset_digest: cleaned_png_digest.clone(),
            media_type: ApprovedAssetMediaType::Png,
            x_milli: 0,
            y_milli: 0,
            width_milli: i64::from(width) * 1_000,
            height_milli: i64::from(height) * 1_000,
        }],
        exports: vec![ProofBoundExportRequest {
            export_id: "background-cleanup-probe".to_owned(),
            media_type: ExportMediaType::Png,
            output_path: paths.probe_png.clone(),
            width_px: Some(width),
            height_px: Some(height),
        }],
    })?;
    if !record.verified || !record.source_immutable || record.export_receipts.len() != 1 {
        return Err(CleanupInkscapeIntegrationError::UnverifiedAdapterRecord);
    }

    let probe_bytes = fs::read(&paths.probe_png)?;
    let probe_report = inspect_png_bytes(&probe_bytes)?;
    if probe_report.width != width
        || probe_report.height != height
        || probe_report.bit_depth != 8
        || !matches!(
            probe_report.color_type,
            PngColorType::Truecolor | PngColorType::TruecolorAlpha
        )
    {
        return Err(CleanupInkscapeIntegrationError::UnexpectedProbeProfile);
    }
    let adapter_record_digest = record.record_digest.clone();
    let identity = inkscape.identity();
    let mut report = InkscapeCleanupIntegrationReport {
        schema_version: REPORT_SCHEMA.to_owned(),
        application_id: identity.application_id.clone(),
        application_version: identity.version_text.clone(),
        executable_digest: identity.executable_digest.clone(),
        cleaned_png_digest,
        probe_png_digest: sha256_hex(&probe_bytes),
        probe_width: probe_report.width,
        probe_height: probe_report.height,
        adapter_record_digest,
        verified: true,
        report_digest: String::new(),
    };
    report.report_digest = canonical_record_digest(&report, "report_digest")?;
    Ok(report)
}

fn validate_request_id(request_id: &str) -> Result<(), CleanupInkscapeIntegrationError> {
    if request_id.is_empty()
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err(CleanupInkscapeIntegrationError::InvalidRequestId)
    } else {
        Ok(())
    }
}

struct ProbePaths {
    source_svg: PathBuf,
    cleaned_png: PathBuf,
    editable_svg: PathBuf,
    probe_png: PathBuf,
}

impl ProbePaths {
    fn new(workspace: &Path, request_id: &str) -> Self {
        Self {
            source_svg: workspace.join(format!("{request_id}-probe-source.svg")),
            cleaned_png: workspace.join(format!("{request_id}-cleaned-input.png")),
            editable_svg: workspace.join(format!("{request_id}-probe-editable.svg")),
            probe_png: workspace.join(format!("{request_id}-probe-export.png")),
        }
    }

    fn all(&self) -> [&Path; 4] {
        [
            self.source_svg.as_path(),
            self.cleaned_png.as_path(),
            self.editable_svg.as_path(),
            self.probe_png.as_path(),
        ]
    }
}
