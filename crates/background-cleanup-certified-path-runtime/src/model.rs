use ergaxiom_attestation_runtime::{AttestationPackage, VerifiedAttestation};
use ergaxiom_evidence_runtime::EvidenceBundle;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CleanupArtifactIntent {
    pub uri: Option<String>,
    pub media_type: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BackgroundCleanupIntent {
    pub contract_id: Option<String>,
    pub created_at: Option<String>,
    pub original_text: Option<String>,
    pub language: Option<String>,
    pub requester_id: Option<String>,
    pub source_raster: CleanupArtifactIntent,
    pub approved_cleanup_mask: CleanupArtifactIntent,
    pub source_width_px: Option<u32>,
    pub source_height_px: Option<u32>,
    pub required_application_version: Option<String>,
    pub visual_preference: Option<String>,
    pub require_pre_execution_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupResolutionRequest {
    pub field: String,
    pub question: String,
    pub reason: String,
    pub accepted_sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BackgroundCleanupCompileOutcome {
    NeedsResolution {
        job_type: String,
        resolution_requests: Vec<CleanupResolutionRequest>,
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
pub struct BackgroundCleanupPlanIdentity {
    pub plan_id: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupCapabilityRequirement {
    pub token_id: String,
    pub step_id: String,
    pub capability: String,
    pub resource: String,
    pub access: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BackgroundCleanupPlanOutcome {
    NeedsResolution {
        job_type: String,
        resolution_requests: Vec<CleanupResolutionRequest>,
        resolution_digest: String,
    },
    Planned {
        job_type: String,
        plan: Value,
        plan_digest: String,
        contract_digest: String,
        capsule_digest: String,
        mandatory_step_count: usize,
        capability_requirements: Vec<CleanupCapabilityRequirement>,
        capability_requirement_digest: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct BackgroundCleanupExecutionRequest<'a> {
    pub request_id: &'a str,
    pub source_png: &'a [u8],
    pub approved_mask_png: &'a [u8],
    pub expected_source_digest: &'a str,
    pub expected_mask_digest: &'a str,
    pub expected_width: u32,
    pub expected_height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundCleanupExecutionRecord {
    pub schema_version: String,
    pub request_id: String,
    pub operator_id: String,
    pub operator_version: String,
    pub source_digest: String,
    pub mask_digest: String,
    pub output_digest: String,
    pub width: u32,
    pub height: u32,
    pub foreground_pixels: u64,
    pub background_pixels: u64,
    pub pre_state_digest: String,
    pub action_boundary_digest: String,
    pub post_state_digest: String,
    pub source_immutable: bool,
    pub verified: bool,
    pub record_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackgroundCleanupExecution {
    pub cleaned_png: Vec<u8>,
    pub record: BackgroundCleanupExecutionRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundCleanupValidationReport {
    pub schema_version: String,
    pub validator_version: String,
    pub source_digest: String,
    pub mask_digest: String,
    pub output_digest: String,
    pub width: u32,
    pub height: u32,
    pub output_media_type_png: bool,
    pub output_srgb: bool,
    pub mask_dimensions_match: bool,
    pub mask_is_binary: bool,
    pub mask_foreground_pixels: u64,
    pub mask_background_pixels: u64,
    pub background_alpha_violations: u64,
    pub foreground_rgba_violations: u64,
    pub source_immutable: bool,
    pub accepted: bool,
    pub report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InkscapeCleanupIntegrationReport {
    pub schema_version: String,
    pub application_id: String,
    pub application_version: String,
    pub executable_digest: String,
    pub cleaned_png_digest: String,
    pub probe_png_digest: String,
    pub probe_width: u32,
    pub probe_height: u32,
    pub adapter_record_digest: String,
    pub verified: bool,
    pub report_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CleanupFailureCode {
    OutputMediaType,
    OutputColorProfile,
    MaskDimensions,
    MaskBinary,
    MaskCoverage,
    BackgroundAlpha,
    ForegroundPreservation,
    SourceImmutability,
    InkscapeIntegration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundCleanupFailure {
    pub code: CleanupFailureCode,
    pub message: String,
    pub action: String,
}

#[derive(Debug)]
pub struct CertifiedBackgroundCleanup {
    pub evidence_bundle: EvidenceBundle,
    pub evidence_bundle_digest: String,
    pub attestation: AttestationPackage,
    pub verified_attestation: VerifiedAttestation,
    pub validation_report: BackgroundCleanupValidationReport,
    pub integration_report: InkscapeCleanupIntegrationReport,
}
