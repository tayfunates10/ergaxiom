use serde::{Deserialize, Serialize};

use crate::TruthValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssuranceLevel {
    E0,
    E1,
    E2,
    E3,
    E4,
    E5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependenceClass {
    Executor,
    Independent,
    Diverse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSeal {
    pub contract_digest: String,
    pub capsule_digest: String,
    pub schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofObligationRequirement {
    pub obligation_id: String,
    pub constraint_id: String,
    pub mandatory: bool,
    pub required_independence: IndependenceClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub obligation_id: String,
    pub constraint_id: String,
    pub contract_digest: String,
    pub subject_digest: String,
    pub validator_id: String,
    pub validator_version: String,
    pub result: TruthValue,
    pub independence: IndependenceClass,
    pub observed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObligationState {
    Pending,
    Satisfied,
    Failed,
    Indeterminate,
    Invalidated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationReport {
    pub obligation_id: String,
    pub constraint_id: String,
    pub mandatory: bool,
    pub required_independence: IndependenceClass,
    pub state: ObligationState,
    pub evidence_ids: Vec<String>,
    pub validator_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionStatus {
    Accepted,
    Blocked,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionReason {
    NoMandatoryObligations,
    UnresolvedUnknowns {
        count: usize,
    },
    AssuranceBelowMinimum {
        actual: AssuranceLevel,
        required: AssuranceLevel,
    },
    MandatoryProofPending {
        obligation_id: String,
    },
    MandatoryProofIndeterminate {
        obligation_id: String,
    },
    MandatoryProofFailed {
        obligation_id: String,
    },
    MandatoryProofInvalidated {
        obligation_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceDecision {
    pub status: DecisionStatus,
    pub reasons: Vec<DecisionReason>,
    pub contract_digest: String,
    pub assurance_level: AssuranceLevel,
    pub obligation_reports: Vec<ObligationReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptancePolicy {
    pub minimum_assurance_level: AssuranceLevel,
    pub unknowns_must_be_empty: bool,
    pub all_mandatory_proofs_must_pass: bool,
    pub validator_conflicts_allowed: bool,
}

impl AcceptancePolicy {
    #[must_use]
    pub const fn strict(minimum_assurance_level: AssuranceLevel) -> Self {
        Self {
            minimum_assurance_level,
            unknowns_must_be_empty: true,
            all_mandatory_proofs_must_pass: true,
            validator_conflicts_allowed: false,
        }
    }
}
