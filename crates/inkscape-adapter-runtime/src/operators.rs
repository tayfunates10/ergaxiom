use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use ergaxiom_proof_kernel::HashingError;

use super::{
    InkscapeAdapterError, InkscapeBinaryIdentity, SvgDocumentSnapshot, SvgElementSnapshot,
    VerifiedInkscape, canonical_json_sha256, decode_attributes, element_id, local_name,
    observe_svg, read_png_info, resolve_new_output, sha256_bytes, sha256_file,
};

const OPERATOR_REQUEST_SCHEMA: &str = "0.1.0";
const OPERATOR_VERSION: &str = "0.1.0";
const MAX_OPERATIONS: usize = 256;
const MAX_EXPORTS: usize = 16;
const MAX_ASSET_BYTES: usize = 32 * 1024 * 1024;
const MAX_CANVAS_EDGE: u32 = 16_384;
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

#[derive(Debug, Error)]
pub enum ProofBoundOperatorError {
    #[error(transparent)]
    Adapter(#[from] InkscapeAdapterError),
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON failure: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("invalid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("operator request uses unsupported schema {0}")]
    UnsupportedSchema(String),
    #[error("required operator request field is empty: {0}")]
    EmptyField(&'static str),
    #[error("operator request identifier contains unsupported characters")]
    InvalidIdentifier,
    #[error("operator request contains too many operations")]
    TooManyOperations,
    #[error("operator request contains too many exports")]
    TooManyExports,
    #[error("operator request must contain at least one operation")]
    MissingOperations,
    #[error("canvas dimensions must be between 1 and {MAX_CANVAS_EDGE} pixels")]
    InvalidCanvasDimensions,
    #[error(
        "numeric geometry must be finite, positive where required and inside the certified range"
    )]
    InvalidGeometry,
    #[error("duplicate declared element id: {0}")]
    DuplicateDeclaredId(String),
    #[error("unsupported or malformed approved asset: {0}")]
    UnsupportedAsset(String),
    #[error("approved asset digest does not match declared digest")]
    AssetDigestMismatch,
    #[error("approved asset exceeds the {MAX_ASSET_BYTES}-byte certified limit")]
    AssetTooLarge,
    #[error("target layer was not found or is not a group: {0}")]
    InvalidLayer(String),
    #[error("target element is not supported by this operator: {0}")]
    UnsupportedTarget(String),
    #[error("operator effect escaped the declared target/property allowlist")]
    UndeclaredMutation,
    #[error("action-boundary state changed before the operator was applied")]
    ActionBoundaryChanged,
    #[error("source material changed during isolated execution")]
    SourceMutated,
    #[error("export profile is malformed: {0}")]
    InvalidExport(String),
    #[error("PDF output is missing or malformed")]
    InvalidPdf,
    #[error("Inkscape PDF export command failed: {0}")]
    PdfExportFailed(String),
    #[error("operation {0} requires at least two target elements")]
    TooFewTargets(&'static str),
    #[error("distribute requires at least three target elements")]
    TooFewDistributionTargets,
    #[error("arithmetic overflow while evaluating geometry")]
    GeometryOverflow,
    #[error("operation receipt did not serialize to a JSON object")]
    InvalidReceiptShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovedAssetMediaType {
    Png,
    Svg,
}

impl ApprovedAssetMediaType {
    fn media_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Svg => "image/svg+xml",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlignmentAxis {
    Horizontal,
    Vertical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlignmentMode {
    Start,
    Center,
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextAnchor {
    Start,
    Middle,
    End,
}

impl TextAnchor {
    fn as_svg(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Middle => "middle",
            Self::End => "end",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operator_id", rename_all = "snake_case")]
pub enum ProofBoundOperation {
    ResizeCanvas {
        width_px: u32,
        height_px: u32,
    },
    CreateLayer {
        layer_id: String,
        label: String,
    },
    PlaceAsset {
        element_id: String,
        layer_id: Option<String>,
        asset_path: PathBuf,
        expected_asset_digest: String,
        media_type: ApprovedAssetMediaType,
        x_milli: i64,
        y_milli: i64,
        width_milli: i64,
        height_milli: i64,
    },
    CreateText {
        element_id: String,
        layer_id: Option<String>,
        text: String,
        x_milli: i64,
        y_milli: i64,
        font_family: String,
        font_size_milli: i64,
        font_weight: u16,
        fill: String,
        anchor: TextAnchor,
    },
    SetFill {
        target_id: String,
        fill: String,
    },
    Transform {
        target_id: String,
        translate_x_milli: i64,
        translate_y_milli: i64,
        rotate_degrees_milli: i64,
        scale_x_milli: i64,
        scale_y_milli: i64,
    },
    Align {
        target_ids: Vec<String>,
        axis: AlignmentAxis,
        mode: AlignmentMode,
    },
    Distribute {
        target_ids: Vec<String>,
        axis: AlignmentAxis,
    },
}

impl ProofBoundOperation {
    fn operator_id(&self) -> &'static str {
        match self {
            Self::ResizeCanvas { .. } => "inkscape.canvas.resize",
            Self::CreateLayer { .. } => "inkscape.layer.create",
            Self::PlaceAsset { .. } => "inkscape.asset.place",
            Self::CreateText { .. } => "inkscape.text.create",
            Self::SetFill { .. } => "inkscape.color.set_fill",
            Self::Transform { .. } => "inkscape.object.transform",
            Self::Align { .. } => "inkscape.object.align",
            Self::Distribute { .. } => "inkscape.object.distribute",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportMediaType {
    Png,
    Svg,
    Pdf,
}

impl ExportMediaType {
    fn media_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Svg => "image/svg+xml",
            Self::Pdf => "application/pdf",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBoundExportRequest {
    pub export_id: String,
    pub media_type: ExportMediaType,
    pub output_path: PathBuf,
    pub width_px: Option<u32>,
    pub height_px: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBoundDesignRequest {
    pub schema_version: String,
    pub request_id: String,
    pub source_svg: PathBuf,
    pub expected_source_digest: String,
    pub editable_output_svg: PathBuf,
    pub operations: Vec<ProofBoundOperation>,
    pub exports: Vec<ProofBoundExportRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBoundOperationReceipt {
    pub operator_id: String,
    pub operator_version: String,
    pub operation_digest: String,
    pub target_ids: Vec<String>,
    pub changed_properties: Vec<String>,
    pub pre_snapshot_digest: String,
    pub action_boundary_snapshot_digest: String,
    pub post_snapshot_digest: String,
    pub verified: bool,
    pub receipt_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBoundExportReceipt {
    pub export_id: String,
    pub media_type: String,
    pub output_digest: String,
    pub command_digest: String,
    pub width_px: Option<u32>,
    pub height_px: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBoundDesignRecord {
    pub schema_version: String,
    pub request_id: String,
    pub request_digest: String,
    pub binary: InkscapeBinaryIdentity,
    pub source_digest: String,
    pub editable_output_digest: String,
    pub operation_receipts: Vec<ProofBoundOperationReceipt>,
    pub export_receipts: Vec<ProofBoundExportReceipt>,
    pub rollback_strategy: String,
    pub source_immutable: bool,
    pub verified: bool,
    pub record_digest: String,
}

#[derive(Debug, Default)]
struct AllowedDelta {
    root_properties: BTreeSet<String>,
    element_properties: BTreeMap<String, BTreeSet<String>>,
    expected_insertions: BTreeMap<String, SvgElementSnapshot>,
}

impl AllowedDelta {
    fn allow_root(&mut self, property: &str) {
        self.root_properties.insert(property.to_owned());
    }

    fn allow_element(&mut self, id: &str, property: &str) {
        self.element_properties
            .entry(id.to_owned())
            .or_default()
            .insert(property.to_owned());
    }

    fn insert_expected(&mut self, id: String, snapshot: SvgElementSnapshot) {
        self.allow_element(&id, "__insert__");
        self.expected_insertions.insert(id, snapshot);
    }

    fn target_ids(&self) -> Vec<String> {
        self.element_properties.keys().cloned().collect()
    }

    fn changed_properties(&self) -> Vec<String> {
        let mut values: Vec<String> = self
            .root_properties
            .iter()
            .map(|property| format!("root:{property}"))
            .collect();
        for (id, properties) in &self.element_properties {
            values.extend(properties.iter().map(|property| format!("{id}:{property}")));
        }
        values
    }
}

impl VerifiedInkscape {
    pub fn execute_proof_bound_design(
        &self,
        request: &ProofBoundDesignRequest,
    ) -> Result<ProofBoundDesignRecord, ProofBoundOperatorError> {
        validate_design_request(request)?;
        let request_digest = canonical_digest(request)?;
        let source = fs::canonicalize(&request.source_svg)?;
        let actual_source_digest = sha256_file(&source)?;
        if actual_source_digest != request.expected_source_digest {
            return Err(InkscapeAdapterError::SourceDigestMismatch.into());
        }

        let editable_output = resolve_new_output(&request.editable_output_svg)?;
        if source == editable_output {
            return Err(InkscapeAdapterError::PathCollision.into());
        }
        let partial = partial_path(&editable_output, &request_digest)?;
        if partial.exists() {
            return Err(
                InkscapeAdapterError::OutputAlreadyExists(partial.display().to_string()).into(),
            );
        }

        let mut resolved_exports = Vec::with_capacity(request.exports.len());
        let mut output_paths = BTreeSet::new();
        output_paths.insert(editable_output.clone());
        for export in &request.exports {
            validate_export_request(export)?;
            let output = resolve_new_output(&export.output_path)?;
            if output == source || !output_paths.insert(output.clone()) {
                return Err(InkscapeAdapterError::PathCollision.into());
            }
            resolved_exports.push((export, output));
        }

        fs::copy(&source, &partial)?;
        let result = (|| {
            let mut receipts = Vec::with_capacity(request.operations.len());
            for operation in &request.operations {
                if sha256_file(&source)? != request.expected_source_digest {
                    return Err(ProofBoundOperatorError::SourceMutated);
                }
                receipts.push(apply_operation(&partial, operation)?);
            }

            let mut export_receipts = Vec::with_capacity(resolved_exports.len());
            for (export, output) in &resolved_exports {
                export_receipts.push(self.execute_export(&partial, export, output)?);
            }

            let editable_output_digest = sha256_file(&partial)?;
            if sha256_file(&source)? != request.expected_source_digest {
                return Err(ProofBoundOperatorError::SourceMutated);
            }
            fs::rename(&partial, &editable_output)?;

            let mut record = ProofBoundDesignRecord {
                schema_version: OPERATOR_REQUEST_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_digest,
                binary: self.identity.clone(),
                source_digest: request.expected_source_digest.clone(),
                editable_output_digest,
                operation_receipts: receipts,
                export_receipts,
                rollback_strategy: "delete isolated partial document and unaccepted exports"
                    .to_owned(),
                source_immutable: true,
                verified: true,
                record_digest: String::new(),
            };
            record.record_digest = canonical_record_digest(&record)?;
            Ok(record)
        })();

        if result.is_err() {
            let _ = fs::remove_file(&partial);
            for (_, output) in resolved_exports {
                let _ = fs::remove_file(output);
            }
        }
        result
    }

    fn execute_export(
        &self,
        editable_svg: &Path,
        request: &ProofBoundExportRequest,
        output: &Path,
    ) -> Result<ProofBoundExportReceipt, ProofBoundOperatorError> {
        let before_digest = sha256_file(editable_svg)?;
        let (output_digest, command_digest, width_px, height_px) = match request.media_type {
            ExportMediaType::Png => {
                let width = request.width_px.ok_or_else(|| {
                    ProofBoundOperatorError::InvalidExport(
                        "PNG export requires width_px".to_owned(),
                    )
                })?;
                let height = request.height_px.ok_or_else(|| {
                    ProofBoundOperatorError::InvalidExport(
                        "PNG export requires height_px".to_owned(),
                    )
                })?;
                let (png, command_digest) = self.export_png(editable_svg, output, width, height)?;
                (
                    png.artifact_digest,
                    command_digest,
                    Some(width),
                    Some(height),
                )
            }
            ExportMediaType::Svg => {
                fs::copy(editable_svg, output)?;
                let snapshot = observe_svg(output)?;
                let command_digest = canonical_json_sha256(&serde_json::json!({
                    "operation": "copy_verified_svg",
                    "input_digest": before_digest,
                    "output_digest": snapshot.source_digest,
                }))?;
                (snapshot.source_digest, command_digest, None, None)
            }
            ExportMediaType::Pdf => {
                if request.width_px.is_some() || request.height_px.is_some() {
                    return Err(ProofBoundOperatorError::InvalidExport(
                        "PDF export does not accept raster dimensions".to_owned(),
                    ));
                }
                let (digest, command_digest) = self.export_pdf(editable_svg, output)?;
                (digest, command_digest, None, None)
            }
        };
        if sha256_file(editable_svg)? != before_digest {
            return Err(ProofBoundOperatorError::ActionBoundaryChanged);
        }
        Ok(ProofBoundExportReceipt {
            export_id: request.export_id.clone(),
            media_type: request.media_type.media_type().to_owned(),
            output_digest,
            command_digest,
            width_px,
            height_px,
        })
    }

    fn export_pdf(
        &self,
        input_svg: &Path,
        output_pdf: &Path,
    ) -> Result<(String, String), ProofBoundOperatorError> {
        let arguments = vec![
            input_svg.to_string_lossy().into_owned(),
            format!("--export-filename={}", output_pdf.to_string_lossy()),
            "--export-area-page".to_owned(),
            "--export-type=pdf".to_owned(),
        ];
        let command_digest = canonical_json_sha256(&serde_json::json!({
            "binary": self.identity,
            "arguments": arguments,
            "input_digest": sha256_file(input_svg)?,
        }))?;
        let output = Command::new(&self.executable)
            .args(&arguments)
            .output()
            .map_err(InkscapeAdapterError::Io)?;
        if !output.status.success() {
            return Err(ProofBoundOperatorError::PdfExportFailed(format!(
                "status={} stdout={:?} stderr={:?}",
                output.status,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let bytes = fs::read(output_pdf)?;
        if bytes.len() < 8 || !bytes.starts_with(b"%PDF-") {
            return Err(ProofBoundOperatorError::InvalidPdf);
        }
        Ok((sha256_bytes(&bytes), command_digest))
    }
}

fn validate_design_request(
    request: &ProofBoundDesignRequest,
) -> Result<(), ProofBoundOperatorError> {
    if request.schema_version != OPERATOR_REQUEST_SCHEMA {
        return Err(ProofBoundOperatorError::UnsupportedSchema(
            request.schema_version.clone(),
        ));
    }
    validate_identifier(&request.request_id, "request_id")?;
    if request.expected_source_digest.is_empty() {
        return Err(ProofBoundOperatorError::EmptyField(
            "expected_source_digest",
        ));
    }
    super::validate_sha256(&request.expected_source_digest)?;
    if request.operations.is_empty() {
        return Err(ProofBoundOperatorError::MissingOperations);
    }
    if request.operations.len() > MAX_OPERATIONS {
        return Err(ProofBoundOperatorError::TooManyOperations);
    }
    if request.exports.len() > MAX_EXPORTS {
        return Err(ProofBoundOperatorError::TooManyExports);
    }

    let mut created_ids = BTreeSet::new();
    let source_snapshot = observe_svg(&request.source_svg)?;
    created_ids.extend(source_snapshot.elements.keys().cloned());
    let mut export_ids = BTreeSet::new();
    for export in &request.exports {
        validate_identifier(&export.export_id, "export_id")?;
        if !export_ids.insert(export.export_id.clone()) {
            return Err(ProofBoundOperatorError::DuplicateDeclaredId(
                export.export_id.clone(),
            ));
        }
    }
    for operation in &request.operations {
        match operation {
            ProofBoundOperation::ResizeCanvas {
                width_px,
                height_px,
            } => validate_canvas(*width_px, *height_px)?,
            ProofBoundOperation::CreateLayer { layer_id, label } => {
                validate_identifier(layer_id, "layer_id")?;
                validate_nonempty(label, "label")?;
                ensure_new_id(&mut created_ids, layer_id)?;
            }
            ProofBoundOperation::PlaceAsset {
                element_id,
                layer_id,
                expected_asset_digest,
                x_milli,
                y_milli,
                width_milli,
                height_milli,
                ..
            } => {
                validate_identifier(element_id, "element_id")?;
                if let Some(layer) = layer_id {
                    validate_identifier(layer, "layer_id")?;
                }
                super::validate_sha256(expected_asset_digest)?;
                validate_box(*x_milli, *y_milli, *width_milli, *height_milli)?;
                ensure_new_id(&mut created_ids, element_id)?;
            }
            ProofBoundOperation::CreateText {
                element_id,
                layer_id,
                text,
                font_family,
                font_size_milli,
                fill,
                ..
            } => {
                validate_identifier(element_id, "element_id")?;
                if let Some(layer) = layer_id {
                    validate_identifier(layer, "layer_id")?;
                }
                validate_nonempty(text, "text")?;
                validate_nonempty(font_family, "font_family")?;
                validate_nonempty(fill, "fill")?;
                if *font_size_milli <= 0 {
                    return Err(ProofBoundOperatorError::InvalidGeometry);
                }
                ensure_new_id(&mut created_ids, element_id)?;
            }
            ProofBoundOperation::SetFill { target_id, fill } => {
                validate_identifier(target_id, "target_id")?;
                validate_nonempty(fill, "fill")?;
            }
            ProofBoundOperation::Transform {
                target_id,
                scale_x_milli,
                scale_y_milli,
                ..
            } => {
                validate_identifier(target_id, "target_id")?;
                if *scale_x_milli <= 0 || *scale_y_milli <= 0 {
                    return Err(ProofBoundOperatorError::InvalidGeometry);
                }
            }
            ProofBoundOperation::Align { target_ids, .. } => {
                validate_target_ids(target_ids, 2, "align")?;
            }
            ProofBoundOperation::Distribute { target_ids, .. } => {
                validate_target_ids(target_ids, 3, "distribute")?;
            }
        }
    }
    Ok(())
}

fn validate_export_request(
    request: &ProofBoundExportRequest,
) -> Result<(), ProofBoundOperatorError> {
    validate_identifier(&request.export_id, "export_id")?;
    match request.media_type {
        ExportMediaType::Png => {
            let Some(width) = request.width_px else {
                return Err(ProofBoundOperatorError::InvalidExport(
                    "PNG width is missing".to_owned(),
                ));
            };
            let Some(height) = request.height_px else {
                return Err(ProofBoundOperatorError::InvalidExport(
                    "PNG height is missing".to_owned(),
                ));
            };
            validate_canvas(width, height)?;
        }
        ExportMediaType::Svg | ExportMediaType::Pdf => {
            if request.width_px.is_some() || request.height_px.is_some() {
                return Err(ProofBoundOperatorError::InvalidExport(
                    "SVG and PDF exports must not declare raster dimensions".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_target_ids(
    target_ids: &[String],
    minimum: usize,
    operation: &'static str,
) -> Result<(), ProofBoundOperatorError> {
    if target_ids.len() < minimum {
        return if operation == "distribute" {
            Err(ProofBoundOperatorError::TooFewDistributionTargets)
        } else {
            Err(ProofBoundOperatorError::TooFewTargets(operation))
        };
    }
    let mut unique = BTreeSet::new();
    for id in target_ids {
        validate_identifier(id, "target_id")?;
        if !unique.insert(id) {
            return Err(ProofBoundOperatorError::DuplicateDeclaredId(id.clone()));
        }
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ProofBoundOperatorError> {
    validate_nonempty(value, field)?;
    if value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(ProofBoundOperatorError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_nonempty(value: &str, field: &'static str) -> Result<(), ProofBoundOperatorError> {
    if value.is_empty() {
        return Err(ProofBoundOperatorError::EmptyField(field));
    }
    if value.contains('\0') {
        return Err(ProofBoundOperatorError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_canvas(width: u32, height: u32) -> Result<(), ProofBoundOperatorError> {
    if width == 0 || height == 0 || width > MAX_CANVAS_EDGE || height > MAX_CANVAS_EDGE {
        return Err(ProofBoundOperatorError::InvalidCanvasDimensions);
    }
    Ok(())
}

fn validate_box(
    x_milli: i64,
    y_milli: i64,
    width_milli: i64,
    height_milli: i64,
) -> Result<(), ProofBoundOperatorError> {
    let limit = i64::from(MAX_CANVAS_EDGE) * 1_000;
    if x_milli.abs() > limit
        || y_milli.abs() > limit
        || width_milli <= 0
        || height_milli <= 0
        || width_milli > limit
        || height_milli > limit
    {
        return Err(ProofBoundOperatorError::InvalidGeometry);
    }
    Ok(())
}

fn ensure_new_id(ids: &mut BTreeSet<String>, id: &str) -> Result<(), ProofBoundOperatorError> {
    if !ids.insert(id.to_owned()) {
        return Err(ProofBoundOperatorError::DuplicateDeclaredId(id.to_owned()));
    }
    Ok(())
}

fn partial_path(output: &Path, request_digest: &str) -> Result<PathBuf, ProofBoundOperatorError> {
    let parent = output
        .parent()
        .ok_or(InkscapeAdapterError::MissingOutputFileName)?;
    let name = output
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(InkscapeAdapterError::MissingOutputFileName)?;
    Ok(parent.join(format!(".{name}.{}.partial.svg", &request_digest[..16])))
}

fn apply_operation(
    working_svg: &Path,
    operation: &ProofBoundOperation,
) -> Result<ProofBoundOperationReceipt, ProofBoundOperatorError> {
    let pre = observe_svg(working_svg)?;
    let action_boundary = observe_svg(working_svg)?;
    if pre.snapshot_digest != action_boundary.snapshot_digest {
        return Err(ProofBoundOperatorError::ActionBoundaryChanged);
    }
    let allowed = mutate_operation(working_svg, &pre, operation)?;
    let post = observe_svg(working_svg)?;
    verify_allowed_delta(&pre, &post, &allowed)?;

    let operation_digest = canonical_digest(operation)?;
    let mut receipt = ProofBoundOperationReceipt {
        operator_id: operation.operator_id().to_owned(),
        operator_version: OPERATOR_VERSION.to_owned(),
        operation_digest,
        target_ids: allowed.target_ids(),
        changed_properties: allowed.changed_properties(),
        pre_snapshot_digest: pre.snapshot_digest,
        action_boundary_snapshot_digest: action_boundary.snapshot_digest,
        post_snapshot_digest: post.snapshot_digest,
        verified: true,
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = canonical_record_digest(&receipt)?;
    Ok(receipt)
}

fn mutate_operation(
    path: &Path,
    pre: &SvgDocumentSnapshot,
    operation: &ProofBoundOperation,
) -> Result<AllowedDelta, ProofBoundOperatorError> {
    match operation {
        ProofBoundOperation::ResizeCanvas {
            width_px,
            height_px,
        } => {
            validate_canvas(*width_px, *height_px)?;
            rewrite_root_canvas(path, *width_px, *height_px)?;
            let mut delta = AllowedDelta::default();
            delta.allow_root("width");
            delta.allow_root("height");
            delta.allow_root("viewBox");
            Ok(delta)
        }
        ProofBoundOperation::CreateLayer { layer_id, label } => {
            let fragment = layer_fragment(layer_id, label)?;
            insert_fragment(path, None, &fragment)?;
            let mut attributes = BTreeMap::new();
            attributes.insert("id".to_owned(), layer_id.clone());
            attributes.insert("inkscape:groupmode".to_owned(), "layer".to_owned());
            attributes.insert("inkscape:label".to_owned(), label.clone());
            let mut delta = AllowedDelta::default();
            delta.insert_expected(
                layer_id.clone(),
                SvgElementSnapshot {
                    element_name: "g".to_owned(),
                    attributes,
                    direct_text: String::new(),
                    has_nested_elements: false,
                },
            );
            Ok(delta)
        }
        ProofBoundOperation::PlaceAsset {
            element_id,
            layer_id,
            asset_path,
            expected_asset_digest,
            media_type,
            x_milli,
            y_milli,
            width_milli,
            height_milli,
        } => {
            if let Some(layer) = layer_id {
                ensure_layer(pre, layer)?;
            }
            let bytes = load_approved_asset(asset_path, expected_asset_digest, *media_type)?;
            let href = format!(
                "data:{};base64,{}",
                media_type.media_type(),
                BASE64_STANDARD.encode(bytes)
            );
            let mut attributes = BTreeMap::new();
            attributes.insert("id".to_owned(), element_id.clone());
            attributes.insert("x".to_owned(), milli_string(*x_milli));
            attributes.insert("y".to_owned(), milli_string(*y_milli));
            attributes.insert("width".to_owned(), milli_string(*width_milli));
            attributes.insert("height".to_owned(), milli_string(*height_milli));
            attributes.insert("href".to_owned(), href);
            attributes.insert("preserveAspectRatio".to_owned(), "xMidYMid meet".to_owned());
            let fragment = empty_element_fragment("image", &attributes)?;
            insert_fragment(path, layer_id.as_deref(), &fragment)?;
            let mut delta = AllowedDelta::default();
            delta.insert_expected(
                element_id.clone(),
                SvgElementSnapshot {
                    element_name: "image".to_owned(),
                    attributes,
                    direct_text: String::new(),
                    has_nested_elements: false,
                },
            );
            if let Some(layer) = layer_id {
                delta.allow_element(layer, "has_nested_elements");
            }
            Ok(delta)
        }
        ProofBoundOperation::CreateText {
            element_id,
            layer_id,
            text,
            x_milli,
            y_milli,
            font_family,
            font_size_milli,
            font_weight,
            fill,
            anchor,
        } => {
            if let Some(layer) = layer_id {
                ensure_layer(pre, layer)?;
            }
            let mut attributes = BTreeMap::new();
            attributes.insert("id".to_owned(), element_id.clone());
            attributes.insert("x".to_owned(), milli_string(*x_milli));
            attributes.insert("y".to_owned(), milli_string(*y_milli));
            attributes.insert("font-family".to_owned(), font_family.clone());
            attributes.insert("font-size".to_owned(), milli_string(*font_size_milli));
            attributes.insert("font-weight".to_owned(), font_weight.to_string());
            attributes.insert("fill".to_owned(), fill.clone());
            attributes.insert("text-anchor".to_owned(), anchor.as_svg().to_owned());
            let fragment = text_element_fragment(&attributes, text)?;
            insert_fragment(path, layer_id.as_deref(), &fragment)?;
            let mut delta = AllowedDelta::default();
            delta.insert_expected(
                element_id.clone(),
                SvgElementSnapshot {
                    element_name: "text".to_owned(),
                    attributes,
                    direct_text: text.clone(),
                    has_nested_elements: false,
                },
            );
            if let Some(layer) = layer_id {
                delta.allow_element(layer, "has_nested_elements");
            }
            Ok(delta)
        }
        ProofBoundOperation::SetFill { target_id, fill } => {
            ensure_supported_target(pre, target_id)?;
            let changes = one_attribute_change(target_id, "fill", fill);
            rewrite_element_attributes(path, &changes)?;
            let mut delta = AllowedDelta::default();
            delta.allow_element(target_id, "attribute:fill");
            Ok(delta)
        }
        ProofBoundOperation::Transform {
            target_id,
            translate_x_milli,
            translate_y_milli,
            rotate_degrees_milli,
            scale_x_milli,
            scale_y_milli,
        } => {
            ensure_supported_target(pre, target_id)?;
            let transform = format!(
                "translate({} {}) rotate({}) scale({} {})",
                milli_string(*translate_x_milli),
                milli_string(*translate_y_milli),
                milli_string(*rotate_degrees_milli),
                milli_string(*scale_x_milli),
                milli_string(*scale_y_milli)
            );
            let changes = one_attribute_change(target_id, "transform", &transform);
            rewrite_element_attributes(path, &changes)?;
            let mut delta = AllowedDelta::default();
            delta.allow_element(target_id, "attribute:transform");
            Ok(delta)
        }
        ProofBoundOperation::Align {
            target_ids,
            axis,
            mode,
        } => {
            let changes = alignment_changes(pre, target_ids, *axis, *mode)?;
            rewrite_element_attributes(path, &changes)?;
            let attribute = axis_position_attribute(*axis);
            let mut delta = AllowedDelta::default();
            for id in target_ids {
                delta.allow_element(id, &format!("attribute:{attribute}"));
            }
            Ok(delta)
        }
        ProofBoundOperation::Distribute { target_ids, axis } => {
            let changes = distribution_changes(pre, target_ids, *axis)?;
            rewrite_element_attributes(path, &changes)?;
            let attribute = axis_position_attribute(*axis);
            let mut delta = AllowedDelta::default();
            for id in target_ids {
                delta.allow_element(id, &format!("attribute:{attribute}"));
            }
            Ok(delta)
        }
    }
}

fn verify_allowed_delta(
    pre: &SvgDocumentSnapshot,
    post: &SvgDocumentSnapshot,
    allowed: &AllowedDelta,
) -> Result<(), ProofBoundOperatorError> {
    verify_root_property("width", &pre.width, &post.width, allowed)?;
    verify_root_property("height", &pre.height, &post.height, allowed)?;
    verify_root_property("viewBox", &pre.view_box, &post.view_box, allowed)?;

    let ids: BTreeSet<&String> = pre.elements.keys().chain(post.elements.keys()).collect();
    for id in ids {
        let permissions = allowed.element_properties.get(id);
        match (pre.elements.get(id), post.elements.get(id)) {
            (None, Some(after)) => {
                if !permissions.is_some_and(|values| values.contains("__insert__"))
                    || allowed.expected_insertions.get(id) != Some(after)
                {
                    return Err(ProofBoundOperatorError::UndeclaredMutation);
                }
            }
            (Some(_), None) => return Err(ProofBoundOperatorError::UndeclaredMutation),
            (Some(before), Some(after)) => {
                if before.element_name != after.element_name {
                    return Err(ProofBoundOperatorError::UndeclaredMutation);
                }
                verify_element_field(
                    "direct_text",
                    &before.direct_text,
                    &after.direct_text,
                    permissions,
                )?;
                verify_element_field(
                    "has_nested_elements",
                    &before.has_nested_elements,
                    &after.has_nested_elements,
                    permissions,
                )?;
                let attribute_keys: BTreeSet<&String> = before
                    .attributes
                    .keys()
                    .chain(after.attributes.keys())
                    .collect();
                for key in attribute_keys {
                    if before.attributes.get(key) != after.attributes.get(key)
                        && !permissions
                            .is_some_and(|values| values.contains(&format!("attribute:{key}")))
                    {
                        return Err(ProofBoundOperatorError::UndeclaredMutation);
                    }
                }
            }
            (None, None) => {}
        }
    }
    Ok(())
}

fn verify_root_property<T: PartialEq>(
    property: &str,
    before: &T,
    after: &T,
    allowed: &AllowedDelta,
) -> Result<(), ProofBoundOperatorError> {
    if before != after && !allowed.root_properties.contains(property) {
        return Err(ProofBoundOperatorError::UndeclaredMutation);
    }
    Ok(())
}

fn verify_element_field<T: PartialEq>(
    property: &str,
    before: &T,
    after: &T,
    permissions: Option<&BTreeSet<String>>,
) -> Result<(), ProofBoundOperatorError> {
    if before != after && !permissions.is_some_and(|values| values.contains(property)) {
        return Err(ProofBoundOperatorError::UndeclaredMutation);
    }
    Ok(())
}

fn ensure_layer(snapshot: &SvgDocumentSnapshot, id: &str) -> Result<(), ProofBoundOperatorError> {
    let Some(element) = snapshot.elements.get(id) else {
        return Err(ProofBoundOperatorError::InvalidLayer(id.to_owned()));
    };
    if local_name(&element.element_name) != "g"
        || element
            .attributes
            .get("inkscape:groupmode")
            .map(String::as_str)
            != Some("layer")
    {
        return Err(ProofBoundOperatorError::InvalidLayer(id.to_owned()));
    }
    Ok(())
}

fn ensure_supported_target(
    snapshot: &SvgDocumentSnapshot,
    id: &str,
) -> Result<(), ProofBoundOperatorError> {
    let Some(element) = snapshot.elements.get(id) else {
        return Err(InkscapeAdapterError::TargetNotFound(id.to_owned()).into());
    };
    if !matches!(
        local_name(&element.element_name),
        "rect" | "image" | "text" | "g" | "path" | "circle" | "ellipse"
    ) {
        return Err(ProofBoundOperatorError::UnsupportedTarget(id.to_owned()));
    }
    Ok(())
}

fn load_approved_asset(
    path: &Path,
    expected_digest: &str,
    media_type: ApprovedAssetMediaType,
) -> Result<Vec<u8>, ProofBoundOperatorError> {
    let bytes = fs::read(path)?;
    if bytes.len() > MAX_ASSET_BYTES {
        return Err(ProofBoundOperatorError::AssetTooLarge);
    }
    if sha256_bytes(&bytes) != expected_digest {
        return Err(ProofBoundOperatorError::AssetDigestMismatch);
    }
    match media_type {
        ApprovedAssetMediaType::Png => {
            if bytes.len() < PNG_SIGNATURE.len() || !bytes.starts_with(PNG_SIGNATURE) {
                return Err(ProofBoundOperatorError::UnsupportedAsset(
                    "PNG signature is missing".to_owned(),
                ));
            }
            let _ = read_png_info(path)?;
        }
        ApprovedAssetMediaType::Svg => validate_restricted_svg_asset(&bytes)?,
    }
    Ok(bytes)
}

fn validate_restricted_svg_asset(bytes: &[u8]) -> Result<(), ProofBoundOperatorError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        ProofBoundOperatorError::UnsupportedAsset(format!("invalid UTF-8: {error}"))
    })?;
    let lowered = text.to_ascii_lowercase();
    for forbidden in [
        "<!doctype",
        "<!entity",
        "<script",
        "<foreignobject",
        "javascript:",
        "href=\"http",
        "href='http",
        "xlink:href=\"http",
        "xlink:href='http",
        "onload=",
        "onclick=",
        "onerror=",
    ] {
        if lowered.contains(forbidden) {
            return Err(ProofBoundOperatorError::UnsupportedAsset(format!(
                "forbidden SVG material: {forbidden}"
            )));
        }
    }
    let mut reader = Reader::from_str(text);
    let mut root_seen = false;
    loop {
        match reader
            .read_event()
            .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?
        {
            Event::Start(start) | Event::Empty(start) if !root_seen => {
                if local_name(std::str::from_utf8(start.name().as_ref()).map_err(|error| {
                    ProofBoundOperatorError::UnsupportedAsset(error.to_string())
                })?) != "svg"
                {
                    return Err(ProofBoundOperatorError::UnsupportedAsset(
                        "root element is not svg".to_owned(),
                    ));
                }
                root_seen = true;
            }
            Event::DocType(_) => {
                return Err(ProofBoundOperatorError::UnsupportedAsset(
                    "DTD is forbidden".to_owned(),
                ));
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !root_seen {
        return Err(ProofBoundOperatorError::UnsupportedAsset(
            "SVG root is missing".to_owned(),
        ));
    }
    Ok(())
}

fn rewrite_root_canvas(
    path: &Path,
    width_px: u32,
    height_px: u32,
) -> Result<(), ProofBoundOperatorError> {
    let source = fs::read(path)?;
    let mut reader = Reader::from_reader(source.as_slice());
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Vec::new());
    let mut buffer = Vec::new();
    let mut root_rewritten = false;
    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
        match event {
            Event::Start(start) if !root_rewritten => {
                let name = std::str::from_utf8(start.name().as_ref())?.to_owned();
                if local_name(&name) != "svg" {
                    return Err(InkscapeAdapterError::MissingSvgRoot.into());
                }
                let mut attributes = decode_attributes(&start, reader.decoder())?;
                attributes.insert("width".to_owned(), width_px.to_string());
                attributes.insert("height".to_owned(), height_px.to_string());
                attributes.insert("viewBox".to_owned(), format!("0 0 {width_px} {height_px}"));
                write_tag(&mut writer, &name, &attributes, false)?;
                root_rewritten = true;
            }
            Event::DocType(_) => return Err(InkscapeAdapterError::DocumentTypeForbidden.into()),
            Event::Eof => break,
            other => write_event(&mut writer, other)?,
        }
        buffer.clear();
    }
    if !root_rewritten {
        return Err(InkscapeAdapterError::MissingSvgRoot.into());
    }
    fs::write(path, writer.into_inner())?;
    Ok(())
}

fn insert_fragment(
    path: &Path,
    parent_id: Option<&str>,
    fragment: &[u8],
) -> Result<(), ProofBoundOperatorError> {
    let source = fs::read(path)?;
    let mut reader = Reader::from_reader(source.as_slice());
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Vec::new());
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    let mut target_depth = None;
    let mut target_count = 0usize;
    let mut root_seen = false;
    let mut inserted = false;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
        match event {
            Event::Start(start) => {
                let name = std::str::from_utf8(start.name().as_ref())?.to_owned();
                let current_depth = depth + 1;
                if current_depth == 1 {
                    if local_name(&name) != "svg" {
                        return Err(InkscapeAdapterError::MissingSvgRoot.into());
                    }
                    root_seen = true;
                }
                if let Some(expected_parent) = parent_id
                    && element_id(&start, reader.decoder())?.as_deref() == Some(expected_parent)
                {
                    target_count += 1;
                    if target_count > 1 {
                        return Err(InkscapeAdapterError::DuplicateElementId(
                            expected_parent.to_owned(),
                        )
                        .into());
                    }
                    target_depth = Some(current_depth);
                }
                writer
                    .write_event(Event::Start(start.into_owned()))
                    .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
                depth = current_depth;
            }
            Event::Empty(empty) => {
                if let Some(expected_parent) = parent_id
                    && element_id(&empty, reader.decoder())?.as_deref() == Some(expected_parent)
                {
                    return Err(ProofBoundOperatorError::InvalidLayer(
                        expected_parent.to_owned(),
                    ));
                }
                writer
                    .write_event(Event::Empty(empty.into_owned()))
                    .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
            }
            Event::End(end) => {
                let should_insert = match parent_id {
                    Some(_) => target_depth == Some(depth),
                    None => depth == 1,
                };
                if should_insert {
                    write_fragment_events(&mut writer, fragment)?;
                    inserted = true;
                    target_depth = None;
                }
                writer
                    .write_event(Event::End(end.into_owned()))
                    .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
                depth = depth.checked_sub(1).ok_or_else(|| {
                    InkscapeAdapterError::Xml("closing element underflow".to_owned())
                })?;
            }
            Event::DocType(_) => return Err(InkscapeAdapterError::DocumentTypeForbidden.into()),
            Event::Eof => break,
            other => write_event(&mut writer, other)?,
        }
        buffer.clear();
    }
    if !root_seen {
        return Err(InkscapeAdapterError::MissingSvgRoot.into());
    }
    if parent_id.is_some() && target_count == 0 {
        return Err(ProofBoundOperatorError::InvalidLayer(
            parent_id.unwrap_or_default().to_owned(),
        ));
    }
    if !inserted {
        return Err(ProofBoundOperatorError::UndeclaredMutation);
    }
    fs::write(path, writer.into_inner())?;
    Ok(())
}

fn rewrite_element_attributes(
    path: &Path,
    changes: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<(), ProofBoundOperatorError> {
    let source = fs::read(path)?;
    let mut reader = Reader::from_reader(source.as_slice());
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Vec::new());
    let mut buffer = Vec::new();
    let mut seen = BTreeSet::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
        match event {
            Event::Start(start) => {
                let attributes = decode_attributes(&start, reader.decoder())?;
                let id = attributes.get("id").cloned();
                if let Some(id) = id
                    && let Some(attribute_changes) = changes.get(&id)
                {
                    if !seen.insert(id.clone()) {
                        return Err(InkscapeAdapterError::DuplicateElementId(id).into());
                    }
                    let mut updated = attributes;
                    for (key, value) in attribute_changes {
                        updated.insert(key.clone(), value.clone());
                    }
                    let name = std::str::from_utf8(start.name().as_ref())?.to_owned();
                    write_tag(&mut writer, &name, &updated, false)?;
                } else {
                    writer
                        .write_event(Event::Start(start.into_owned()))
                        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
                }
            }
            Event::Empty(empty) => {
                let attributes = decode_attributes(&empty, reader.decoder())?;
                let id = attributes.get("id").cloned();
                if let Some(id) = id
                    && let Some(attribute_changes) = changes.get(&id)
                {
                    if !seen.insert(id.clone()) {
                        return Err(InkscapeAdapterError::DuplicateElementId(id).into());
                    }
                    let mut updated = attributes;
                    for (key, value) in attribute_changes {
                        updated.insert(key.clone(), value.clone());
                    }
                    let name = std::str::from_utf8(empty.name().as_ref())?.to_owned();
                    write_tag(&mut writer, &name, &updated, true)?;
                } else {
                    writer
                        .write_event(Event::Empty(empty.into_owned()))
                        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
                }
            }
            Event::DocType(_) => return Err(InkscapeAdapterError::DocumentTypeForbidden.into()),
            Event::Eof => break,
            other => write_event(&mut writer, other)?,
        }
        buffer.clear();
    }

    for id in changes.keys() {
        if !seen.contains(id) {
            return Err(InkscapeAdapterError::TargetNotFound(id.clone()).into());
        }
    }
    fs::write(path, writer.into_inner())?;
    Ok(())
}

fn write_tag(
    writer: &mut Writer<Vec<u8>>,
    name: &str,
    attributes: &BTreeMap<String, String>,
    empty: bool,
) -> Result<(), ProofBoundOperatorError> {
    let mut start = BytesStart::new(name);
    for (key, value) in attributes {
        start.push_attribute((key.as_str(), value.as_str()));
    }
    let event = if empty {
        Event::Empty(start)
    } else {
        Event::Start(start)
    };
    writer
        .write_event(event)
        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
    Ok(())
}

fn write_event(
    writer: &mut Writer<Vec<u8>>,
    event: Event<'_>,
) -> Result<(), ProofBoundOperatorError> {
    writer
        .write_event(event.into_owned())
        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
    Ok(())
}

fn write_fragment_events(
    writer: &mut Writer<Vec<u8>>,
    fragment: &[u8],
) -> Result<(), ProofBoundOperatorError> {
    let mut reader = Reader::from_reader(fragment);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
        match event {
            Event::Eof => break,
            Event::DocType(_) => return Err(InkscapeAdapterError::DocumentTypeForbidden.into()),
            other => write_event(writer, other)?,
        }
        buffer.clear();
    }
    Ok(())
}

fn layer_fragment(id: &str, label: &str) -> Result<Vec<u8>, ProofBoundOperatorError> {
    let mut attributes = BTreeMap::new();
    attributes.insert("id".to_owned(), id.to_owned());
    attributes.insert("inkscape:groupmode".to_owned(), "layer".to_owned());
    attributes.insert("inkscape:label".to_owned(), label.to_owned());
    let mut writer = Writer::new(Vec::new());
    write_tag(&mut writer, "g", &attributes, false)?;
    writer
        .write_event(Event::End(BytesEnd::new("g")))
        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
    Ok(writer.into_inner())
}

fn empty_element_fragment(
    name: &str,
    attributes: &BTreeMap<String, String>,
) -> Result<Vec<u8>, ProofBoundOperatorError> {
    let mut writer = Writer::new(Vec::new());
    write_tag(&mut writer, name, attributes, true)?;
    Ok(writer.into_inner())
}

fn text_element_fragment(
    attributes: &BTreeMap<String, String>,
    text: &str,
) -> Result<Vec<u8>, ProofBoundOperatorError> {
    let mut writer = Writer::new(Vec::new());
    write_tag(&mut writer, "text", attributes, false)?;
    writer
        .write_event(Event::Text(BytesText::new(text)))
        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
    writer
        .write_event(Event::End(BytesEnd::new("text")))
        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
    Ok(writer.into_inner())
}

fn one_attribute_change(
    target_id: &str,
    attribute: &str,
    value: &str,
) -> BTreeMap<String, BTreeMap<String, String>> {
    BTreeMap::from([(
        target_id.to_owned(),
        BTreeMap::from([(attribute.to_owned(), value.to_owned())]),
    )])
}

#[derive(Debug, Clone)]
struct AxisBox {
    id: String,
    start: i64,
    size: i64,
}

fn alignment_changes(
    snapshot: &SvgDocumentSnapshot,
    target_ids: &[String],
    axis: AlignmentAxis,
    mode: AlignmentMode,
) -> Result<BTreeMap<String, BTreeMap<String, String>>, ProofBoundOperatorError> {
    let boxes = axis_boxes(snapshot, target_ids, axis)?;
    let min_start = boxes
        .iter()
        .map(|item| item.start)
        .min()
        .ok_or(ProofBoundOperatorError::TooFewTargets("align"))?;
    let max_end = boxes
        .iter()
        .map(|item| item.start.checked_add(item.size))
        .collect::<Option<Vec<_>>>()
        .ok_or(ProofBoundOperatorError::GeometryOverflow)?
        .into_iter()
        .max()
        .ok_or(ProofBoundOperatorError::TooFewTargets("align"))?;
    let anchor = match mode {
        AlignmentMode::Start => min_start,
        AlignmentMode::Center => {
            min_start
                .checked_add(max_end)
                .ok_or(ProofBoundOperatorError::GeometryOverflow)?
                / 2
        }
        AlignmentMode::End => max_end,
    };
    let attribute = axis_position_attribute(axis).to_owned();
    let mut changes = BTreeMap::new();
    for item in boxes {
        let new_start = match mode {
            AlignmentMode::Start => anchor,
            AlignmentMode::Center => anchor
                .checked_sub(item.size / 2)
                .ok_or(ProofBoundOperatorError::GeometryOverflow)?,
            AlignmentMode::End => anchor
                .checked_sub(item.size)
                .ok_or(ProofBoundOperatorError::GeometryOverflow)?,
        };
        changes.insert(
            item.id,
            BTreeMap::from([(attribute.clone(), milli_string(new_start))]),
        );
    }
    Ok(changes)
}

fn distribution_changes(
    snapshot: &SvgDocumentSnapshot,
    target_ids: &[String],
    axis: AlignmentAxis,
) -> Result<BTreeMap<String, BTreeMap<String, String>>, ProofBoundOperatorError> {
    let mut boxes = axis_boxes(snapshot, target_ids, axis)?;
    if boxes.len() < 3 {
        return Err(ProofBoundOperatorError::TooFewDistributionTargets);
    }
    boxes.sort_by(|left, right| left.start.cmp(&right.start).then(left.id.cmp(&right.id)));
    let first_start = boxes[0].start;
    let last_end = boxes
        .last()
        .and_then(|item| item.start.checked_add(item.size))
        .ok_or(ProofBoundOperatorError::GeometryOverflow)?;
    let total_size = boxes.iter().try_fold(0_i64, |total, item| {
        total
            .checked_add(item.size)
            .ok_or(ProofBoundOperatorError::GeometryOverflow)
    })?;
    let span = last_end
        .checked_sub(first_start)
        .ok_or(ProofBoundOperatorError::GeometryOverflow)?;
    let available = span
        .checked_sub(total_size)
        .ok_or(ProofBoundOperatorError::GeometryOverflow)?;
    let gap = available
        / i64::try_from(boxes.len() - 1).map_err(|_| ProofBoundOperatorError::GeometryOverflow)?;
    let attribute = axis_position_attribute(axis).to_owned();
    let mut cursor = first_start;
    let mut changes = BTreeMap::new();
    for item in boxes {
        changes.insert(
            item.id,
            BTreeMap::from([(attribute.clone(), milli_string(cursor))]),
        );
        cursor = cursor
            .checked_add(item.size)
            .and_then(|value| value.checked_add(gap))
            .ok_or(ProofBoundOperatorError::GeometryOverflow)?;
    }
    Ok(changes)
}

fn axis_boxes(
    snapshot: &SvgDocumentSnapshot,
    target_ids: &[String],
    axis: AlignmentAxis,
) -> Result<Vec<AxisBox>, ProofBoundOperatorError> {
    let mut values = Vec::with_capacity(target_ids.len());
    for id in target_ids {
        let Some(element) = snapshot.elements.get(id) else {
            return Err(InkscapeAdapterError::TargetNotFound(id.clone()).into());
        };
        let (position, size) = match axis {
            AlignmentAxis::Horizontal => ("x", "width"),
            AlignmentAxis::Vertical => ("y", "height"),
        };
        let start = parse_milli_attribute(element, position, id)?;
        let size = parse_milli_attribute(element, size, id)?;
        if size <= 0 {
            return Err(ProofBoundOperatorError::InvalidGeometry);
        }
        values.push(AxisBox {
            id: id.clone(),
            start,
            size,
        });
    }
    Ok(values)
}

fn parse_milli_attribute(
    element: &SvgElementSnapshot,
    attribute: &str,
    id: &str,
) -> Result<i64, ProofBoundOperatorError> {
    let value = element
        .attributes
        .get(attribute)
        .ok_or_else(|| ProofBoundOperatorError::UnsupportedTarget(id.to_owned()))?;
    decimal_to_milli(value).ok_or_else(|| ProofBoundOperatorError::UnsupportedTarget(id.to_owned()))
}

fn decimal_to_milli(value: &str) -> Option<i64> {
    let value = value.trim();
    if value.is_empty() || value.contains('e') || value.contains('E') {
        return None;
    }
    let negative = value.starts_with('-');
    let unsigned = value
        .strip_prefix('-')
        .or_else(|| value.strip_prefix('+'))
        .unwrap_or(value);
    let mut parts = unsigned.split('.');
    let whole = parts.next()?.parse::<i64>().ok()?;
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut padded = fraction.chars().take(3).collect::<String>();
    while padded.len() < 3 {
        padded.push('0');
    }
    let fraction_value = if padded.is_empty() {
        0
    } else {
        padded.parse::<i64>().ok()?
    };
    let magnitude = whole.checked_mul(1_000)?.checked_add(fraction_value)?;
    Some(if negative { -magnitude } else { magnitude })
}

fn axis_position_attribute(axis: AlignmentAxis) -> &'static str {
    match axis {
        AlignmentAxis::Horizontal => "x",
        AlignmentAxis::Vertical => "y",
    }
}

fn milli_string(value: i64) -> String {
    let negative = value < 0;
    let magnitude = value.unsigned_abs();
    let whole = magnitude / 1_000;
    let fraction = magnitude % 1_000;
    let sign = if negative { "-" } else { "" };
    if fraction == 0 {
        format!("{sign}{whole}")
    } else {
        let mut rendered = format!("{fraction:03}");
        while rendered.ends_with('0') {
            rendered.pop();
        }
        format!("{sign}{whole}.{rendered}")
    }
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ProofBoundOperatorError> {
    Ok(canonical_json_sha256(&serde_json::to_value(value)?)?)
}

fn canonical_record_digest<T: Serialize>(value: &T) -> Result<String, ProofBoundOperatorError> {
    let mut serialized = serde_json::to_value(value)?;
    let object = serialized
        .as_object_mut()
        .ok_or(ProofBoundOperatorError::InvalidReceiptShape)?;
    if object.contains_key("record_digest") {
        object.insert("record_digest".to_owned(), Value::String(String::new()));
    } else if object.contains_key("receipt_digest") {
        object.insert("receipt_digest".to_owned(), Value::String(String::new()));
    } else {
        return Err(ProofBoundOperatorError::InvalidReceiptShape);
    }
    Ok(canonical_json_sha256(&serialized)?)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create() -> Result<Self, Box<dyn Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ergaxiom-proof-bound-operators-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn source_svg() -> &'static str {
        r##"<svg xmlns="http://www.w3.org/2000/svg" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" width="200" height="100" viewBox="0 0 200 100"><rect id="a" x="10" y="10" width="20" height="20" fill="#000000"/><rect id="b" x="70" y="30" width="20" height="20" fill="#000000"/><rect id="c" x="150" y="50" width="20" height="20" fill="#000000"/></svg>"##
    }

    #[test]
    fn restricted_operator_sequence_is_digest_bound() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let source = directory.path.join("source.svg");
        let output = directory.path.join("output.svg");
        let svg_export = directory.path.join("delivery.svg");
        fs::write(&source, source_svg())?;
        let source_digest = sha256_file(&source)?;
        let request = ProofBoundDesignRequest {
            schema_version: OPERATOR_REQUEST_SCHEMA.to_owned(),
            request_id: "request.operator-test.0001".to_owned(),
            source_svg: source.clone(),
            expected_source_digest: source_digest.clone(),
            editable_output_svg: output.clone(),
            operations: vec![
                ProofBoundOperation::ResizeCanvas {
                    width_px: 320,
                    height_px: 240,
                },
                ProofBoundOperation::CreateLayer {
                    layer_id: "content-layer".to_owned(),
                    label: "Content".to_owned(),
                },
                ProofBoundOperation::CreateText {
                    element_id: "headline".to_owned(),
                    layer_id: Some("content-layer".to_owned()),
                    text: "ERGAXIOM".to_owned(),
                    x_milli: 24_000,
                    y_milli: 64_000,
                    font_family: "DejaVu Sans".to_owned(),
                    font_size_milli: 18_000,
                    font_weight: 700,
                    fill: "#102040".to_owned(),
                    anchor: TextAnchor::Start,
                },
                ProofBoundOperation::SetFill {
                    target_id: "a".to_owned(),
                    fill: "#336699".to_owned(),
                },
                ProofBoundOperation::Transform {
                    target_id: "b".to_owned(),
                    translate_x_milli: 5_000,
                    translate_y_milli: 2_000,
                    rotate_degrees_milli: 15_000,
                    scale_x_milli: 1_000,
                    scale_y_milli: 1_000,
                },
                ProofBoundOperation::Align {
                    target_ids: vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
                    axis: AlignmentAxis::Vertical,
                    mode: AlignmentMode::Center,
                },
                ProofBoundOperation::Distribute {
                    target_ids: vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
                    axis: AlignmentAxis::Horizontal,
                },
            ],
            exports: vec![ProofBoundExportRequest {
                export_id: "delivery-svg".to_owned(),
                media_type: ExportMediaType::Svg,
                output_path: svg_export.clone(),
                width_px: None,
                height_px: None,
            }],
        };
        let inkscape = VerifiedInkscape {
            executable: PathBuf::from("inkscape-not-invoked"),
            identity: InkscapeBinaryIdentity {
                application_id: "org.inkscape.Inkscape".to_owned(),
                executable_digest: "a".repeat(64),
                version_text: "Inkscape 1.2.2".to_owned(),
                version_major: 1,
                version_minor: 2,
                version_patch: 2,
            },
        };
        let record = inkscape.execute_proof_bound_design(&request)?;
        assert!(record.verified);
        assert!(record.source_immutable);
        assert_eq!(record.operation_receipts.len(), request.operations.len());
        assert_eq!(sha256_file(&source)?, source_digest);
        assert_eq!(sha256_file(&output)?, record.editable_output_digest);
        assert_eq!(
            sha256_file(&svg_export)?,
            record.export_receipts[0].output_digest
        );
        let snapshot = observe_svg(output)?;
        assert_eq!(snapshot.width.as_deref(), Some("320"));
        assert_eq!(snapshot.height.as_deref(), Some("240"));
        assert_eq!(
            snapshot
                .elements
                .get("headline")
                .map(|value| value.direct_text.as_str()),
            Some("ERGAXIOM")
        );
        assert!(record.record_digest.len() == 64);
        Ok(())
    }

    #[test]
    fn malicious_svg_asset_is_rejected() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let asset = directory.path.join("malicious.svg");
        fs::write(
            &asset,
            r##"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"##,
        )?;
        let digest = sha256_file(&asset)?;
        assert!(matches!(
            load_approved_asset(&asset, &digest, ApprovedAssetMediaType::Svg),
            Err(ProofBoundOperatorError::UnsupportedAsset(_))
        ));
        Ok(())
    }

    #[test]
    fn undeclared_snapshot_mutation_fails_closed() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::create()?;
        let before_path = directory.path.join("before.svg");
        let after_path = directory.path.join("after.svg");
        fs::write(&before_path, source_svg())?;
        fs::write(
            &after_path,
            source_svg().replace("fill=\"#000000\"", "fill=\"#ffffff\""),
        )?;
        let before = observe_svg(before_path)?;
        let after = observe_svg(after_path)?;
        assert!(matches!(
            verify_allowed_delta(&before, &after, &AllowedDelta::default()),
            Err(ProofBoundOperatorError::UndeclaredMutation)
        ));
        Ok(())
    }

    #[test]
    fn decimal_milli_round_trip_is_stable() {
        for value in [-12_345, -1_000, -1, 0, 1, 1_250, 999_999] {
            assert_eq!(decimal_to_milli(&milli_string(value)), Some(value));
        }
    }
}
