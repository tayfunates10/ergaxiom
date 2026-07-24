#![forbid(unsafe_code)]

mod certify;
mod compiler;
mod model;
mod pdf;
mod planner;
mod runtime;
mod signing;
mod svg;
mod util;

pub use certify::{
    PrintPreflightCertificationError, PrintPreflightCertificationRequest,
    certify_print_preflight,
};
pub use compiler::{
    GRAPHIC_DESIGNER_CAPSULE_ID, PRINT_PREFLIGHT_JOB_TYPE, PrintPreflightCompileError,
    build_print_preflight_contract, compile_print_preflight_intent,
};
pub use model::{
    CertifiedPrintPreflight, PdfBoxRecord, PdfNormalizationRecord, PrintArtifactIntent,
    PrintCapabilityRequirement, PrintFailureCode, PrintPreflightCompileOutcome,
    PrintPreflightExecution, PrintPreflightExecutionRecord, PrintPreflightExecutionRequest,
    PrintPreflightFailure, PrintPreflightIntent, PrintPreflightPlanIdentity,
    PrintPreflightPlanOutcome, PrintPreflightValidationReport, PrintResolutionRequest,
    PrintSourceValidationReport, PrintSpecification,
};
pub use pdf::{
    PrintPdfError, PrintPdfInspection, expected_boxes, inspect_print_pdf, normalize_print_pdf,
    verify_pdf_normalization,
};
pub use planner::{PrintPreflightPlannerError, synthesize_print_preflight_plan};
pub use runtime::{
    PrintPreflightRuntimeError, execute_print_preflight, print_preflight_failure_map,
    validate_print_preflight,
};
pub use signing::{
    PrintEvidenceKeyRegistry, PrintEvidenceSignature, PrintEvidenceSignatureAlgorithm,
    PrintEvidenceSignatureEncoding, PrintEvidenceSignatureError,
    SignedPrintPreflightExecutionRecord, VerifiedPrintPreflightExecutionEvidence,
    sign_print_preflight_execution_record, verify_print_preflight_execution_record,
};
pub use svg::{
    PrintSvgError, render_restricted_print_svg, validate_print_source,
    validate_print_specification,
};
