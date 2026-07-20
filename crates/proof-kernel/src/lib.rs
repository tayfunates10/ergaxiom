#![forbid(unsafe_code)]

mod engine;
mod hashing;
mod model;
mod truth;

pub use engine::{KernelError, ProofKernel};
pub use hashing::{HashingError, canonical_json_sha256};
pub use model::{
    AcceptanceDecision, AcceptancePolicy, AssuranceLevel, ContractSeal, DecisionReason,
    DecisionStatus, EvidenceRecord, IndependenceClass, ObligationReport, ObligationState,
    ProofObligationRequirement,
};
pub use truth::TruthValue;
