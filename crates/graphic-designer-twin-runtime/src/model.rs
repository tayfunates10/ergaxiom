use ergaxiom_operator_simulation_runtime::OperatorSimulationReport;
use ergaxiom_proof_kernel::EvidenceRecord;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rgba8 {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
    pub alpha: u8,
}

impl Rgba8 {
    pub const fn opaque(red: u8, green: u8, blue: u8) -> Self {
        Self {
            red,
            green,
            blue,
            alpha: 255,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PixelRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanvasSpecification {
    pub width: u32,
    pub height: u32,
    pub color_profile: String,
    pub background: Rgba8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedLogo {
    pub artifact_id: String,
    pub media_type: String,
    pub content: Vec<u8>,
    pub source_width: u32,
    pub source_height: u32,
    pub primary_color: Rgba8,
    pub secondary_color: Rgba8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedCopy {
    pub artifact_id: String,
    pub media_type: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandProfile {
    pub artifact_id: String,
    pub media_type: String,
    pub minimum_logo_clear_space_px: u32,
    pub minimum_text_contrast_milli: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphicDesignJob {
    pub schema_version: String,
    pub job_id: String,
    pub evaluated_at: String,
    pub canvas: CanvasSpecification,
    pub safe_area: PixelRect,
    pub logo_bounds: PixelRect,
    pub text_origin_x: u32,
    pub text_origin_y: u32,
    pub text_scale: u32,
    pub text_color: Rgba8,
    pub approved_logo: ApprovedLogo,
    pub approved_copy: ApprovedCopy,
    pub brand_profile: BrandProfile,
    pub editable_master_id: String,
    pub delivery_raster_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphicDesignDocument {
    pub schema_version: String,
    pub document_id: String,
    pub canvas: CanvasSpecification,
    pub safe_area: PixelRect,
    pub layers: Vec<DesignLayer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "layer_type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DesignLayer {
    Logo(LogoLayer),
    Text(TextLayer),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoLayer {
    pub layer_id: String,
    pub source_artifact_id: String,
    pub source_width: u32,
    pub source_height: u32,
    pub bounds: PixelRect,
    pub primary_color: Rgba8,
    pub secondary_color: Rgba8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextLayer {
    pub layer_id: String,
    pub source_artifact_id: String,
    pub approved_copy: String,
    pub bounds: PixelRect,
    pub origin_x: u32,
    pub origin_y: u32,
    pub glyph_scale: u32,
    pub color: Rgba8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorObservation {
    pub validator_id: String,
    pub validator_version: String,
    pub claim_id: String,
    pub passed: bool,
    pub observed: Value,
    pub expected: Value,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphicValidationReport {
    pub schema_version: String,
    pub job_id: String,
    pub document_digest: String,
    pub raster_digest: String,
    pub all_mandatory_passed: bool,
    pub observations: Vec<ValidatorObservation>,
    pub report_digest: String,
}

#[derive(Debug, Clone)]
pub struct GraphicDesignTwinRun {
    pub simulation: OperatorSimulationReport,
    pub document: GraphicDesignDocument,
    pub raster_png: Vec<u8>,
    pub validation: GraphicValidationReport,
    pub proof_evidence: Vec<EvidenceRecord>,
}
