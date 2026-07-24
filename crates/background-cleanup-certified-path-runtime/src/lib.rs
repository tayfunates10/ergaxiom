#![forbid(unsafe_code)]

mod certify;
mod compiler;
mod integration;
mod model;
mod planner;
mod png;
mod runtime;
mod util;

pub use certify::{
    BackgroundCleanupCertificationError, BackgroundCleanupCertificationRequest,
    certify_background_cleanup,
};
pub use compiler::{
    BACKGROUND_CLEANUP_JOB_TYPE, BackgroundCleanupCompileError, compile_background_cleanup_intent,
};
pub use integration::{CleanupInkscapeIntegrationError, execute_inkscape_cleanup_probe};
pub use model::{
    BackgroundCleanupCompileOutcome, BackgroundCleanupExecution, BackgroundCleanupExecutionRecord,
    BackgroundCleanupExecutionRequest, BackgroundCleanupFailure, BackgroundCleanupIntent,
    BackgroundCleanupPlanIdentity, BackgroundCleanupPlanOutcome, BackgroundCleanupValidationReport,
    CertifiedBackgroundCleanup, CleanupArtifactIntent, CleanupCapabilityRequirement,
    CleanupFailureCode, CleanupResolutionRequest, InkscapeCleanupIntegrationReport,
};
pub use planner::{BackgroundCleanupPlannerError, synthesize_background_cleanup_plan};
pub use png::{RestrictedPngError, encode_restricted_srgb_rgba_png};
pub use runtime::{
    BackgroundCleanupRuntimeError, background_cleanup_failure_map, execute_background_cleanup,
    validate_background_cleanup,
};
