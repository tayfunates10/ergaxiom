use std::fs;
use std::path::Path;

use ergaxiom_inkscape_adapter_runtime::{
    ExportMediaType, ProofBoundDesignRequest, ProofBoundExportRequest, ProofBoundOperation,
    ProofBoundOperatorError, VerifiedInkscape,
};
use thiserror::Error;

use crate::model::{
    PrintFailureCode, PrintPreflightExecution, PrintPreflightExecutionRecord,
    PrintPreflightExecutionRequest, PrintPreflightFailure, PrintPreflightValidationReport,
    PrintSpecification,
};
use crate::pdf::{
    PrintPdfError, expected_boxes, inspect_print_pdf, normalize_print_pdf,
    verify_pdf_normalization,
};
use crate::svg::{PrintSvgError, validate_print_source};
use crate::util::{
    PrintDigestError, canonical_record_digest, canonical_value_digest, is_sha256, sha256_hex,
};

const EXECUTION_SCHEMA: &str = "0.1.0";
const VALIDATION_SCHEMA: &str = "0.1.0";
const VALIDATOR_VERSION: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum PrintPreflightRuntimeError {
    #[error("required execution field is empty: {0}")]
    EmptyField(&'static str),
    #[error("request identifier contains unsupported characters")]
    InvalidRequestId,
    #[error("input digest is malformed")]
    InvalidDigest,
    #[error("source SVG digest does not match the request")]
    SourceDigestMismatch,
    #[error("print specification digest does not match the request")]
    SpecificationDigestMismatch,
    #[error("source SVG failed certified preflight validation")]
    SourceRejected,
    #[error("execution record digest is invalid")]
    InvalidRecordDigest,
    #[error("execution record does not bind the supplied artifacts")]
    RecordBindingMismatch,
    #[error("Inkscape adapter PDF receipt is missing or inconsistent")]
    AdapterReceiptMismatch,
    #[error("source SVG changed during isolated execution")]
    SourceMutated,
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Adapter(#[from] ProofBoundOperatorError),
    #[error(transparent)]
    Svg(#[from] PrintSvgError),
    #[error(transparent)]
    Pdf(#[from] PrintPdfError),
    #[error(transparent)]
    Digest(#[from] PrintDigestError),
}

pub fn execute_print_preflight(
    inkscape: &VerifiedInkscape,
    request: PrintPreflightExecutionRequest<'_>,
    workspace: &Path,
) -> Result<PrintPreflightExecution, PrintPreflightRuntimeError> {
    validate_request(&request)?;
    fs::create_dir_all(workspace)?;
    let source_digest = sha256_hex(request.source_svg);
    if source_digest != request.expected_source_digest {
        return Err(PrintPreflightRuntimeError::SourceDigestMismatch);
    }
    let specification_digest = canonical_value_digest(request.specification)?;
    if specification_digest != request.expected_specification_digest {
        return Err(PrintPreflightRuntimeError::SpecificationDigestMismatch);
    }
    let source_validation = validate_print_source(request.source_svg, request.specification)?;
    if !source_validation.accepted {
        return Err(PrintPreflightRuntimeError::SourceRejected);
    }

    let source_path = workspace.join(format!("{}-source.svg", request.request_id));
    let editable_path = workspace.join(format!("{}-editable.svg", request.request_id));
    let raw_pdf_path = workspace.join(format!("{}-raw.pdf", request.request_id));
    let delivery_pdf_path = workspace.join(format!("{}-delivery.pdf", request.request_id));
    for path in [&source_path, &editable_path, &raw_pdf_path, &delivery_pdf_path] {
        if path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("isolated output already exists: {}", path.display()),
            )
            .into());
        }
    }
    fs::write(&source_path, request.source_svg)?;
    let adapter_result = inkscape.execute_proof_bound_design(&ProofBoundDesignRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: request.request_id.to_owned(),
        source_svg: source_path.clone(),
        expected_source_digest: source_digest.clone(),
        editable_output_svg: editable_path.clone(),
        operations: vec![ProofBoundOperation::CreateLayer {
            layer_id: "ergaxiom-preflight-layer".to_owned(),
            label: "Ergaxiom Print Preflight".to_owned(),
        }],
        exports: vec![ProofBoundExportRequest {
            export_id: "print-ready-pdf".to_owned(),
            media_type: ExportMediaType::Pdf,
            output_path: raw_pdf_path.clone(),
            width_px: None,
            height_px: None,
        }],
    });
    let adapter_record = match adapter_result {
        Ok(record) => record,
        Err(error) => {
            cleanup(&[&source_path, &editable_path, &raw_pdf_path, &delivery_pdf_path]);
            return Err(error.into());
        }
    };
    let result = (|| {
        let editable_svg = fs::read(&editable_path)?;
        let raw_pdf = fs::read(&raw_pdf_path)?;
        if sha256_hex(&fs::read(&source_path)?) != source_digest {
            return Err(PrintPreflightRuntimeError::SourceMutated);
        }
        let pdf_receipt = adapter_record
            .export_receipts
            .iter()
            .find(|receipt| receipt.export_id == "print-ready-pdf")
            .ok_or(PrintPreflightRuntimeError::AdapterReceiptMismatch)?;
        if pdf_receipt.media_type != "application/pdf"
            || pdf_receipt.output_digest != sha256_hex(&raw_pdf)
        {
            return Err(PrintPreflightRuntimeError::AdapterReceiptMismatch);
        }
        let (delivery_pdf, normalization_record) =
            normalize_print_pdf(&raw_pdf, request.specification)?;
        fs::write(&delivery_pdf_path, &delivery_pdf)?;
        let source_immutable = sha256_hex(request.source_svg) == source_digest
            && sha256_hex(&fs::read(&source_path)?) == source_digest;
        if !source_immutable {
            return Err(PrintPreflightRuntimeError::SourceMutated);
        }
        let mut record = PrintPreflightExecutionRecord {
            schema_version: EXECUTION_SCHEMA.to_owned(),
            request_id: request.request_id.to_owned(),
            operator_id: "print.export_pdf_with_inkscape".to_owned(),
            operator_version: "0.1.0".to_owned(),
            source_svg_digest: source_digest,
            specification_digest,
            source_validation_report_digest: source_validation.report_digest.clone(),
            editable_svg_digest: sha256_hex(&editable_svg),
            raw_pdf_digest: sha256_hex(&raw_pdf),
            normalized_pdf_digest: sha256_hex(&delivery_pdf),
            normalization_record,
            application_id: adapter_record.binary.application_id.clone(),
            application_version: adapter_record.binary.version_text.clone(),
            executable_digest: adapter_record.binary.executable_digest.clone(),
            adapter_record_digest: adapter_record.record_digest.clone(),
            source_immutable,
            verified: adapter_record.verified,
            record_digest: String::new(),
        };
        record.record_digest = canonical_record_digest(&record, "record_digest")?;
        Ok(PrintPreflightExecution {
            editable_svg,
            raw_pdf,
            delivery_pdf,
            source_validation,
            record,
        })
    })();
    if result.is_err() {
        cleanup(&[&source_path, &editable_path, &raw_pdf_path, &delivery_pdf_path]);
    }
    result
}

pub fn validate_print_preflight(
    source_svg: &[u8],
    specification: &PrintSpecification,
    editable_svg: &[u8],
    raw_pdf: &[u8],
    delivery_pdf: &[u8],
    execution_record: &PrintPreflightExecutionRecord,
) -> Result<PrintPreflightValidationReport, PrintPreflightRuntimeError> {
    validate_execution_record(execution_record)?;
    let source_validation = validate_print_source(source_svg, specification)?;
    let source_digest = sha256_hex(source_svg);
    let specification_digest = canonical_value_digest(specification)?;
    let editable_digest = sha256_hex(editable_svg);
    let raw_pdf_digest = sha256_hex(raw_pdf);
    let delivery_pdf_digest = sha256_hex(delivery_pdf);
    if execution_record.source_svg_digest != source_digest
        || execution_record.specification_digest != specification_digest
        || execution_record.source_validation_report_digest != source_validation.report_digest
        || execution_record.editable_svg_digest != editable_digest
        || execution_record.raw_pdf_digest != raw_pdf_digest
        || execution_record.normalized_pdf_digest != delivery_pdf_digest
    {
        return Err(PrintPreflightRuntimeError::RecordBindingMismatch);
    }
    verify_pdf_normalization(
        raw_pdf,
        delivery_pdf,
        &execution_record.normalization_record,
        specification,
    )?;
    let inspection = inspect_print_pdf(delivery_pdf, specification)?;
    let boxes = expected_boxes(specification)?;
    let media_box_match = inspection.media_box.as_ref() == Some(&boxes.0);
    let trim_box_match = inspection.trim_box.as_ref() == Some(&boxes.1);
    let bleed_box_match = inspection.bleed_box.as_ref() == Some(&boxes.2);
    let crop_box_match = inspection.crop_box.as_ref() == Some(&boxes.3);
    let inkscape_export_verified = execution_record.verified
        && execution_record.application_id == "org.inkscape.Inkscape"
        && is_sha256(&execution_record.executable_digest)
        && is_sha256(&execution_record.adapter_record_digest);
    let accepted = source_validation.accepted
        && inspection.page_count == 1
        && inspection.pdf_version == specification.required_pdf_version
        && inspection.vector_only
        && inspection.fonts_outlined
        && media_box_match
        && trim_box_match
        && bleed_box_match
        && crop_box_match
        && inspection.allowed_color_spaces_only
        && inspection.transparency_absent
        && inspection.external_actions_absent
        && execution_record.source_immutable
        && inkscape_export_verified;
    let mut report = PrintPreflightValidationReport {
        schema_version: VALIDATION_SCHEMA.to_owned(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        source_svg_digest: source_digest,
        specification_digest,
        editable_svg_digest: editable_digest,
        raw_pdf_digest,
        delivery_pdf_digest,
        normalization_record: execution_record.normalization_record.clone(),
        page_count: inspection.page_count,
        pdf_version: inspection.pdf_version,
        restricted_svg_profile: source_validation.restricted_svg_profile,
        canvas_dimensions_match: source_validation.canvas_dimensions_match,
        bleed_coverage: source_validation.bleed_coverage,
        safe_area_satisfied: source_validation.safe_area_satisfied,
        palette_violation_count: source_validation.palette_violation_count,
        vector_only: inspection.vector_only,
        fonts_outlined: inspection.fonts_outlined,
        media_box_match,
        trim_box_match,
        bleed_box_match,
        crop_box_match,
        allowed_color_spaces_only: inspection.allowed_color_spaces_only,
        transparency_absent: inspection.transparency_absent,
        external_actions_absent: inspection.external_actions_absent,
        source_immutable: execution_record.source_immutable,
        inkscape_export_verified,
        accepted,
        report_digest: String::new(),
    };
    report.report_digest = canonical_record_digest(&report, "report_digest")?;
    Ok(report)
}

pub fn print_preflight_failure_map(
    report: &PrintPreflightValidationReport,
) -> Vec<PrintPreflightFailure> {
    let mut failures = Vec::new();
    push_if(
        &mut failures,
        !report.restricted_svg_profile,
        PrintFailureCode::RestrictedSvgProfile,
        "The SVG contains unsupported structure or effects.",
        "Use only flat svg/g/rect/path content with absolute M/L/H/V/Z outlined paths.",
    );
    push_if(&mut failures, !report.canvas_dimensions_match, PrintFailureCode::CanvasDimensions, "The bleed canvas does not match the print specification.", "Set width, height and viewBox to trim plus twice the declared bleed.");
    push_if(&mut failures, !report.bleed_coverage, PrintFailureCode::BleedCoverage, "The background does not cover the full bleed canvas.", "Extend the approved background rectangle to every bleed edge.");
    push_if(&mut failures, !report.safe_area_satisfied, PrintFailureCode::SafeArea, "Content crosses the declared safe area.", "Move every non-background vector bound inside bleed plus safe margin.");
    push_if(&mut failures, report.palette_violation_count != 0, PrintFailureCode::PaletteAllowlist, "The source uses colors outside the approved print palette.", "Replace undeclared fills with exact lowercase approved #rrggbb values.");
    push_if(&mut failures, !report.vector_only, PrintFailureCode::VectorOnly, "The PDF contains raster image XObjects.", "Replace raster material with certified vector paths or use a future raster-print profile.");
    push_if(&mut failures, !report.fonts_outlined, PrintFailureCode::FontsOutlined, "The PDF contains live font resources.", "Convert all text to outlined paths before preflight.");
    push_if(&mut failures, report.page_count != 1, PrintFailureCode::PageCount, "The PDF is not exactly one page.", "Export only the declared poster page.");
    push_if(&mut failures, !report.media_box_match, PrintFailureCode::MediaBox, "MediaBox does not match the bleed canvas.", "Regenerate the PDF from the declared page dimensions.");
    push_if(&mut failures, !report.trim_box_match, PrintFailureCode::TrimBox, "TrimBox does not match the trim size and bleed inset.", "Use the deterministic print-box normalizer.");
    push_if(&mut failures, !report.bleed_box_match, PrintFailureCode::BleedBox, "BleedBox is missing or incorrect.", "Set BleedBox equal to the full bleed MediaBox.");
    push_if(&mut failures, !report.crop_box_match, PrintFailureCode::CropBox, "CropBox is missing or incorrect.", "Set CropBox equal to the full bleed MediaBox.");
    push_if(&mut failures, report.pdf_version != "1.5", PrintFailureCode::PdfVersion, "The normalized PDF version is unsupported.", "Regenerate the certified PDF 1.5 delivery.");
    push_if(&mut failures, !report.allowed_color_spaces_only, PrintFailureCode::ColorSpace, "The PDF uses an unapproved color space.", "Use only the color spaces explicitly allowed by the print specification.");
    push_if(&mut failures, !report.transparency_absent, PrintFailureCode::Transparency, "Transparency or graphics-state effects are present.", "Flatten or remove transparency before certification.");
    push_if(&mut failures, !report.external_actions_absent, PrintFailureCode::ExternalAction, "The PDF contains annotations, actions, encryption or embedded material.", "Remove interactive and externally executable PDF features.");
    push_if(&mut failures, !report.source_immutable, PrintFailureCode::SourceImmutability, "The source digest changed during execution.", "Restart from a fresh immutable input workspace.");
    push_if(&mut failures, !report.inkscape_export_verified, PrintFailureCode::InkscapeIntegration, "Pinned Inkscape execution evidence is invalid.", "Re-run with the trusted executable and proof-bound adapter.");
    failures
}

fn validate_request(
    request: &PrintPreflightExecutionRequest<'_>,
) -> Result<(), PrintPreflightRuntimeError> {
    if request.request_id.is_empty() {
        return Err(PrintPreflightRuntimeError::EmptyField("request_id"));
    }
    if !request
        .request_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(PrintPreflightRuntimeError::InvalidRequestId);
    }
    if !is_sha256(request.expected_source_digest)
        || !is_sha256(request.expected_specification_digest)
    {
        return Err(PrintPreflightRuntimeError::InvalidDigest);
    }
    Ok(())
}

fn validate_execution_record(
    record: &PrintPreflightExecutionRecord,
) -> Result<(), PrintPreflightRuntimeError> {
    if record.schema_version != EXECUTION_SCHEMA
        || record.operator_id != "print.export_pdf_with_inkscape"
        || record.operator_version != "0.1.0"
        || record.record_digest != canonical_record_digest(record, "record_digest")?
    {
        return Err(PrintPreflightRuntimeError::InvalidRecordDigest);
    }
    Ok(())
}

fn push_if(
    failures: &mut Vec<PrintPreflightFailure>,
    condition: bool,
    code: PrintFailureCode,
    message: &str,
    action: &str,
) {
    if condition {
        failures.push(PrintPreflightFailure {
            code,
            message: message.to_owned(),
            action: action.to_owned(),
        });
    }
}

fn cleanup(paths: &[&Path]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}
