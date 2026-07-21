#![forbid(unsafe_code)]

mod model;
mod png;
mod render;
mod runtime;
mod validate;

pub use model::{
    ApprovedCopy, ApprovedLogo, BrandProfile, CanvasSpecification, DesignLayer,
    GraphicDesignDocument, GraphicDesignJob, GraphicDesignTwinRun, GraphicValidationReport,
    LogoLayer, PixelRect, Rgba8, TextLayer, ValidatorObservation,
};
pub use png::{DecodedPng, PngError, decode_rgba_png, encode_rgba_png};
pub use render::{
    ContrastSample, RenderError, RenderedDocument, contrast_ratio_milli, measure_text_bounds,
    render_document,
};
pub use runtime::{
    GraphicTwinError, compile_graphic_design_simulation, execute_graphic_design_twin,
    stage_graphic_design_inputs,
};
pub use validate::{
    ValidationError, proof_evidence_from_report, validate_graphic_artifacts,
    verify_validation_report_digest,
};
