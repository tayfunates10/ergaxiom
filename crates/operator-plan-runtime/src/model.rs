use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorPlan {
    pub schema_version: String,
    pub plan_id: String,
    pub created_at: String,
    pub bindings: PlanBindings,
    pub steps: Vec<PlanStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanBindings {
    pub contract: DigestReference,
    pub profession_capsule: DigestReference,
    pub policy_snapshot: Option<DigestReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestReference {
    pub id: String,
    pub algorithm: String,
    pub digest: String,
    pub uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    pub step_id: String,
    pub sequence: usize,
    pub operator_id: String,
    pub operator_version: String,
    pub depends_on: Vec<String>,
    pub input_artifact_ids: Vec<String>,
    pub output_artifact_ids: Vec<String>,
    pub capability_token_ids: Vec<String>,
    pub mandatory: bool,
    pub rollback_step_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub event_id: String,
    pub step_id: String,
    pub sequence: usize,
    pub timestamp: String,
    pub operator_id: String,
    pub status: TraceStatus,
    pub input_digests: Vec<String>,
    pub output_digests: Vec<String>,
    pub capability_token_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraceStatus {
    Started,
    Succeeded,
    Failed,
    RolledBack,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct CapsulePlanView {
    pub capsule_id: String,
    pub version: String,
    pub operators: Vec<CapsuleOperator>,
    pub job_types: Vec<CapsuleJobType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct CapsuleOperator {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct CapsuleJobType {
    pub id: String,
    pub operator_ids: Vec<String>,
}
