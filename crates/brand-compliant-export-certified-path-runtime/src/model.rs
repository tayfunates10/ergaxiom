use ergaxiom_attestation_runtime::{AttestationPackage, VerifiedAttestation};
use ergaxiom_evidence_runtime::EvidenceBundle;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::normalization::BrandPngNormalizationRecord;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BrandArtifactIntent {
    pub uri: Option<String>,
    pub media_type: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandBackgroundRule {
    pub element_id: String,
    pub color: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandLogoRule {
    pub element_id: String,
    pub approved_sha256: String,
    pub x_px: u32,
    pub y_px: u32,
    pub width_px: u32,
    pub height_px: u32,
    pub minimum_clear_space_px: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandTypographyRule {
    pub element_id: String,
    pub approved_copy: String,
    pub x_px: u32,
    pub y_px: u32,
    pub font_family: String,
    pub font_size_px: u32,
    pub font_weight: u16,
    pub color: String,
    pub text_anchor: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandRuleManifest {
    pub schema_version: String,
    pub manifest_id: String,
    pub canvas_width_px: u32,
    pub canvas_height_px: u32,
    pub allowed_palette: Vec<String>,
    pub background: BrandBackgroundRule,
    pub logo: BrandLogoRule,
    pub typography: BrandTypographyRule,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BrandExportIntent {
    pub contract_id: Option<String>,
    pub created_at: Option<String>,
    pub original_text: Option<String>,
    pub language: Option<String>,
    pub requester_id: Option<String>,
    pub source_svg: BrandArtifactIntent,
    pub brand_manifest: BrandArtifactIntent,
    pub approved_logo: BrandArtifactIntent,
    pub resolved_manifest: Option<BrandRuleManifest>,
    pub required_application_version: Option<String>,
    pub visual_preference: Option<String>,
    pub require_pre_execution_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandResolutionRequest {
    pub field: String,
    pub question: String,
    pub reason: String,
    pub accepted_sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BrandExportCompileOutcome {
    NeedsResolution {
        job_type: String,
        resolution_requests: Vec<BrandResolutionRequest>,
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
pub struct BrandExportPlanIdentity {
    pub plan_id: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandCapabilityRequirement {
    pub token_id: String,
    pub step_id: String,
    pub capability: String,
    pub resource: String,
    pub access: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BrandExportPlanOutcome {
    NeedsResolution {
        job_type: String,
        resolution_requests: Vec<BrandResolutionRequest>,
        resolution_digest: String,
    },
    Planned {
        job_type: String,
        plan: Value,
        plan_digest: String,
        contract_digest: String,
        capsule_digest: String,
        mandatory_step_count: usize,
        capability_requirements: Vec<BrandCapabilityRequirement>,
        capability_requirement_digest: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct BrandExportExecutionRequest<'a> {
    pub request_id: &'a str,
    pub source_svg: &'a [u8],
    pub approved_logo_png: &'a [u8],
    pub manifest: &'a BrandRuleManifest,
    pub expected_source_digest: &'a str,
    pub expected_manifest_digest: &'a str,
    pub expected_logo_digest: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandSourceValidationReport {
    pub schema_version: String,
    pub validator_version: String,
    pub source_svg_digest: String,
    pub manifest_digest: String,
    pub approved_logo_digest: String,
    pub restricted_svg_profile: bool,
    pub canvas_dimensions_match: bool,
    pub palette_violation_count: u64,
    pub logo_digest_matches: bool,
    pub logo_geometry_matches: bool,
    pub logo_clear_space_satisfied: bool,
    pub typography_matches: bool,
    pub approved_copy_matches: bool,
    pub accepted: bool,
    pub report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandExportExecutionRecord {
    pub schema_version: String,
    pub request_id: String,
    pub operator_id: String,
    pub operator_version: String,
    pub source_svg_digest: String,
    pub manifest_digest: String,
    pub approved_logo_digest: String,
    pub source_validation_report_digest: String,
    pub editable_svg_digest: String,
    pub raw_export_png_digest: String,
    pub normalization_record: BrandPngNormalizationRecord,
    pub delivery_png_digest: String,
    pub width: u32,
    pub height: u32,
    pub application_id: String,
    pub application_version: String,
    pub executable_digest: String,
    pub adapter_record_digest: String,
    pub source_immutable: bool,
    pub verified: bool,
    pub record_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandExportExecution {
    pub editable_svg: Vec<u8>,
    pub raw_export_png: Vec<u8>,
    pub delivery_png: Vec<u8>,
    pub source_validation: BrandSourceValidationReport,
    pub record: BrandExportExecutionRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandExportValidationReport {
    pub schema_version: String,
    pub validator_version: String,
    pub source_svg_digest: String,
    pub manifest_digest: String,
    pub approved_logo_digest: String,
    pub editable_svg_digest: String,
    pub raw_export_png_digest: String,
    pub normalization_record: BrandPngNormalizationRecord,
    pub delivery_png_digest: String,
    pub width: u32,
    pub height: u32,
    pub restricted_svg_profile: bool,
    pub canvas_dimensions_match: bool,
    pub palette_violation_count: u64,
    pub logo_digest_matches: bool,
    pub logo_geometry_matches: bool,
    pub logo_clear_space_satisfied: bool,
    pub typography_matches: bool,
    pub approved_copy_matches: bool,
    pub output_media_type_png: bool,
    pub output_srgb: bool,
    pub source_immutable: bool,
    pub inkscape_export_verified: bool,
    pub accepted: bool,
    pub report_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BrandFailureCode {
    RestrictedSvgProfile,
    CanvasDimensions,
    PaletteAllowlist,
    LogoIdentity,
    LogoGeometry,
    LogoClearSpace,
    Typography,
    ApprovedCopy,
    OutputMediaType,
    OutputColorProfile,
    SourceImmutability,
    InkscapeIntegration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandExportFailure {
    pub code: BrandFailureCode,
    pub message: String,
    pub action: String,
}

#[derive(Debug)]
pub struct CertifiedBrandExport {
    pub evidence_bundle: EvidenceBundle,
    pub evidence_bundle_digest: String,
    pub attestation: AttestationPackage,
    pub verified_attestation: VerifiedAttestation,
    pub validation_report: BrandExportValidationReport,
}
