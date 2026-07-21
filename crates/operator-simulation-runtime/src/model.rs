use ergaxiom_occupational_twin_runtime::{OperationReceipt, TypedOperation, WorkspaceSnapshot};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSimulationPlan {
    pub schema_version: String,
    pub simulation_id: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub invocations: Vec<StepInvocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepInvocation {
    pub step_id: String,
    pub operator_id: String,
    pub operator_version: String,
    pub operation: TypedOperation,
    pub fault: Option<FaultInjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fault", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FaultInjection {
    ForcePreconditionFailure { artifact_id: String },
    ForcePostconditionFailure { artifact_id: String },
    CorruptFirstWrite { replacement_base64url: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SimulatedStepStatus {
    Succeeded,
    Rejected,
    RolledBack,
    Blocked,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SimulationViolation {
    DuplicateInvocation { step_id: String },
    UnexpectedInvocation { step_id: String },
    MissingMandatoryInvocation { step_id: String },
    DependencyNotSucceeded { step_id: String, dependency_id: String },
    InvocationOperatorMismatch {
        step_id: String,
        actual: String,
        expected: String,
    },
    InvocationVersionMismatch {
        step_id: String,
        actual: String,
        expected: String,
    },
    OperationOperatorMismatch {
        step_id: String,
        actual: String,
        expected: String,
    },
    DeclaredInputMismatch { step_id: String },
    DeclaredOutputMismatch { step_id: String },
    FaultNotApplicable { step_id: String },
    OperationRejected { step_id: String },
    OperationRolledBack { step_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationStepReport {
    pub step_id: String,
    pub status: SimulatedStepStatus,
    pub before_snapshot_digest: String,
    pub after_snapshot_digest: String,
    pub receipt: Option<OperationReceipt>,
    pub violations: Vec<SimulationViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSimulationReport {
    pub schema_version: String,
    pub simulation_id: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub initial_snapshot_digest: String,
    pub final_snapshot: WorkspaceSnapshot,
    pub steps: Vec<SimulationStepReport>,
    pub violations: Vec<SimulationViolation>,
    pub conforms_to_plan: bool,
    pub workspace_trace_digest: String,
    pub simulation_digest: String,
}
