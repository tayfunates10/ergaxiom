use ergaxiom_attestation_runtime::{AttestationPackage, VerifiedAttestation};
use ergaxiom_evidence_runtime::EvidenceBundle;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PrintArtifactIntent {
    pub uri: Option<String>,
    pub media_type: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintSpecification {
    pub schema_version: String,
    pub manifest_id: String,
    pub trim_width_milli_mm: u32,
    pub trim_height_milli_mm: u32,
    pub bleed_milli_mm: u32,
    pub safe_margin_milli_mm: u32,
    pub background_element_id: String,
    pub allowed_palette: Vec<String>,
    pub allowed_pdf_color_spaces: Vec<String>,
    pub required_pdf_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PrintPreflightIntent {
    pub contract_id: Option<String>,
    pub created_at: Option<String>,
    pub original_text: Option<String>,
    pub language: Option<String>,
    pub requester_id: Option<String>,
    pub source_svg: PrintArtifactIntent,
    pub print_specification: PrintArtifactIntent,
    pub resolved_specification: Option<PrintSpecification>,
    pub required_application_version: Option<String>,
    pub visual_preference: Option<String>,
    pub require_pre_execution_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintResolutionRequest {
    pub field: String,
    pub question: String,
    pub reason: String,
    pub accepted_sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PrintPreflightCompileOutcome {
    NeedsResolution {
        job_type: String,
        resolution_requests: Vec<PrintResolutionRequest>,
        resolution_digest: String,
    },
    Compiled {
        job_type: String,
        contract: Value,
        contract_digest: String,
        capsule_digest: String,
        proof_obligation_count: usize,
        unresolved_mandatory_unknowns: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PrintPreflightPlanIdentity {
    pub plan_id: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintCapabilityRequirement {
    pub token_id: String,
    pub step_id: String,
    pub capability: String,
    pub resource: String,
    pub access: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PrintPreflightPlanOutcome {
    NeedsResolution {
        job_type: String,
        resolution_requests: Vec<PrintResolutionRequest>,
        resolution_digest: String,
    },
    Planned {
        job_type: String,
        plan: Value,
        plan_digest: String,
        contract_digest: String,
        capsule_digest: String,
        mandatory_step_count: usize,
        capability_requirements: Vec<PrintCapabilityRequirement>,
        capability_requirement_digest: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct PrintPreflightExecutionRequest<'a> {
    pub request_id: &'a str,
    pub source_svg: &'a [u8],
    pub specification: &'a PrintSpecification,
    pub expected_source_digest: &'a str,
    pub expected_specification_digest: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintSourceValidationReport {
    pub schema_version: String,
    pub validator_version: String,
    pub source_svg_digest: String,
    pub specification_digest: String,
    pub restricted_svg_profile: bool,
    pub canvas_dimensions_match: bool,
    pub bleed_coverage: bool,
    pub safe_area_satisfied: bool,
    pub palette_violation_count: u64,
    pub raster_image_count: u64,
    pub live_text_count: u64,
    pub unsupported_path_count: u64,
    pub accepted: bool,
    pub report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfBoxRecord {
    pub left_milli_pt: i64,
    pub bottom_milli_pt: i64,
    pub right_milli_pt: i64,
    pub top_milli_pt: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfNormalizationRecord {
    pub schema_version: String,
    pub raw_pdf_digest: String,
    pub normalized_pdf_digest: String,
    pub page_count: u32,
    pub media_box: PdfBoxRecord,
    pub trim_box: PdfBoxRecord,
    pub bleed_box: PdfBoxRecord,
    pub crop_box: PdfBoxRecord,
    pub record_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintPreflightExecutionRecord {
    pub schema_version: String,
    pub request_id: String,
    pub operator_id: String,
    pub operator_version: String,
    pub source_svg_digest: String,
    pub specification_digest: String,
    pub source_validation_report_digest: String,
    pub editable_svg_digest: String,
    pub raw_pdf_digest: String,
    pub normalized_pdf_digest: String,
    pub normalization_record: PdfNormalizationRecord,
    pub application_id: String,
    pub application_version: String,
    pub executable_digest: String,
    pub adapter_record_digest: String,
    pub source_immutable: bool,
    pub verified: bool,
    pub record_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrintPreflightExecution {
    pub editable_svg: Vec<u8>,
    pub raw_pdf: Vec<u8>,
    pub delivery_pdf: Vec<u8>,
    pub source_validation: PrintSourceValidationReport,
    pub record: PrintPreflightExecutionRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintPreflightValidationReport {
    pub schema_version: String,
    pub validator_version: String,
    pub source_svg_digest: String,
    pub specification_digest: String,
    pub editable_svg_digest: String,
    pub raw_pdf_digest: String,
    pub delivery_pdf_digest: String,
    pub normalization_record: PdfNormalizationRecord,
    pub page_count: u32,
    pub pdf_version: String,
    pub restricted_svg_profile: bool,
    pub canvas_dimensions_match: bool,
    pub bleed_coverage: bool,
    pub safe_area_satisfied: bool,
    pub palette_violation_count: u64,
    pub vector_only: bool,
    pub fonts_outlined: bool,
    pub media_box_match: bool,
    pub trim_box_match: bool,
    pub bleed_box_match: bool,
    pub crop_box_match: bool,
    pub allowed_color_spaces_only: bool,
    pub transparency_absent: bool,
    pub external_actions_absent: bool,
    pub source_immutable: bool,
    pub inkscape_export_verified: bool,
    pub accepted: bool,
    pub report_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrintFailureCode {
    RestrictedSvgProfile,
    CanvasDimensions,
    BleedCoverage,
    SafeArea,
    PaletteAllowlist,
    VectorOnly,
    FontsOutlined,
    PageCount,
    MediaBox,
    TrimBox,
    BleedBox,
    CropBox,
    PdfVersion,
    ColorSpace,
    Transparency,
    ExternalAction,
    SourceImmutability,
    InkscapeIntegration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintPreflightFailure {
    pub code: PrintFailureCode,
    pub message: String,
    pub action: String,
}

#[derive(Debug)]
pub struct CertifiedPrintPreflight {
    pub evidence_bundle: EvidenceBundle,
    pub evidence_bundle_digest: String,
    pub attestation: AttestationPackage,
    pub verified_attestation: VerifiedAttestation,
    pub validation_report: PrintPreflightValidationReport,
}
