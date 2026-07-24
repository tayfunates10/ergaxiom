#![forbid(unsafe_code)]

mod certify;
mod compiler;
mod model;
mod normalization;
mod planner;
mod runtime;
mod signing;
mod svg;
mod util;

pub use certify::{
    BrandExportCertificationError, BrandExportCertificationRequest, certify_brand_export,
};
pub use compiler::{
    BRAND_EXPORT_JOB_TYPE, BrandExportCompileError, build_brand_export_contract,
    compile_brand_export_intent,
};
pub use model::{
    BrandArtifactIntent, BrandBackgroundRule, BrandCapabilityRequirement,
    BrandExportCompileOutcome, BrandExportExecution, BrandExportExecutionRecord,
    BrandExportExecutionRequest, BrandExportFailure, BrandExportIntent, BrandExportPlanIdentity,
    BrandExportPlanOutcome, BrandExportValidationReport, BrandFailureCode, BrandLogoRule,
    BrandResolutionRequest, BrandRuleManifest, BrandSourceValidationReport, BrandTypographyRule,
    CertifiedBrandExport,
};
pub use normalization::{
    BrandPngNormalization, BrandPngNormalizationError, BrandPngNormalizationRecord,
    normalize_brand_png_srgb, verify_brand_png_normalization,
};
pub use planner::{BrandExportPlannerError, synthesize_brand_export_plan};
pub use runtime::{
    BrandExportRuntimeError, brand_export_failure_map, execute_brand_export, validate_brand_export,
};
pub use signing::{
    BrandEvidenceKeyRegistry, BrandEvidenceSignature, BrandEvidenceSignatureAlgorithm,
    BrandEvidenceSignatureEncoding, BrandEvidenceSignatureError, SignedBrandExportExecutionRecord,
    VerifiedBrandExportExecutionEvidence, sign_brand_export_execution_record,
    verify_brand_export_execution_record,
};
pub use svg::{
    BrandSvgError, render_restricted_brand_svg, validate_brand_source, validate_manifest,
};
