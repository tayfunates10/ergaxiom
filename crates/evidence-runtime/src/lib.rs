#![forbid(unsafe_code)]

mod assessor;
mod model;

pub use assessor::{BundleAssessment, EvidenceBundleError, assess_bundle};
pub use model::{
    ApplicationEvidence, ArtifactEvidence, ArtifactRole, BundleBindings, ClaimedDecision,
    DigestAlgorithm, DigestReference, EnvironmentEvidence, EvidenceBundle, ProofResult,
    ProofResultStatus,
};
