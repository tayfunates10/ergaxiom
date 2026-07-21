use std::collections::BTreeMap;

use ergaxiom_proof_kernel::{AssuranceLevel, IndependenceClass};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkContract {
    pub schema_version: String,
    pub contract_id: String,
    pub profession: ProfessionReference,
    pub job_type: String,
    pub requirements: ContractRequirements,
    pub permissions: Vec<ContractPermission>,
    pub proof_obligations: Vec<ContractProofObligation>,
    pub acceptance: ContractAcceptance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfessionReference {
    pub capsule_id: String,
    pub capsule_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRequirements {
    pub hard: Vec<HardConstraint>,
    pub unknowns: Vec<UnknownRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardConstraint {
    pub id: String,
    pub mandatory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownRequirement {
    pub id: String,
    pub mandatory: bool,
    pub resolution: UnknownResolution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownResolution {
    Unresolved,
    UserAnswer,
    TrustedProfile,
    TrustedSource,
    NotRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractPermission {
    pub capability: String,
    pub resource: String,
    pub access: PermissionAccess,
    #[serde(default)]
    pub constraints: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAccess {
    Read,
    Write,
    Execute,
    Control,
    Network,
    SecretUse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractProofObligation {
    pub id: String,
    pub constraint_id: String,
    pub validator_ids: Vec<String>,
    pub mandatory: bool,
    pub independence_class: IndependenceClass,
    #[serde(default)]
    pub evidence_types: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAcceptance {
    pub minimum_assurance_level: AssuranceLevel,
    pub unknowns_must_be_empty: bool,
    pub all_mandatory_proofs_must_pass: bool,
    pub validator_conflicts_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfessionCapsule {
    pub schema_version: String,
    pub capsule_id: String,
    pub version: String,
    pub job_types: Vec<JobTypeDefinition>,
    pub validators: Vec<ValidatorDefinition>,
    pub policies: ProfessionPolicies,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobTypeDefinition {
    pub id: String,
    pub required_constraints: Vec<String>,
    pub minimum_assurance_level: AssuranceLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorDefinition {
    pub id: String,
    pub version: String,
    pub claims: Vec<String>,
    pub independence_class: IndependenceClass,
    #[serde(default)]
    pub evidence_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfessionPolicies {
    pub minimum_assurance_by_job_type: BTreeMap<String, AssuranceLevel>,
}
