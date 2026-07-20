use ergaxiom_operator_plan_runtime::TraceEvent;
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, IndependenceClass};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema_version: String,
    pub bundle_id: String,
    pub run_id: String,
    pub created_at: String,
    pub bindings: BundleBindings,
    pub environment: EnvironmentEvidence,
    pub artifacts: Vec<ArtifactEvidence>,
    pub trace: TraceEvidence,
    pub proof_results: Vec<ProofResult>,
    pub claimed_decision: ClaimedDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleBindings {
    pub contract: DigestReference,
    pub profession_capsule: DigestReference,
    pub operator_plan: DigestReference,
    pub policy_snapshot: Option<DigestReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestReference {
    pub id: String,
    pub algorithm: DigestAlgorithm,
    pub digest: String,
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestAlgorithm {
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentEvidence {
    pub os: String,
    pub kernel_version: String,
    pub applications: Vec<ApplicationEvidence>,
    pub clock_source: String,
    pub sandbox_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationEvidence {
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEvidence {
    pub artifact_id: String,
    pub role: ArtifactRole,
    pub uri: String,
    pub media_type: Option<String>,
    pub algorithm: DigestAlgorithm,
    pub digest: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactRole {
    Input,
    Intermediate,
    Output,
    Evidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceEvidence {
    pub events: Vec<TraceEvent>,
    pub claimed_conforms_to_plan: bool,
    #[serde(default)]
    pub deviations: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofResult {
    pub evidence_id: String,
    pub obligation_id: String,
    pub claim_id: String,
    pub subject_artifact_id: String,
    pub validator_id: String,
    pub validator_version: String,
    pub independence_class: IndependenceClass,
    pub status: ProofResultStatus,
    pub mandatory: bool,
    pub observed: Value,
    pub expected: Option<Value>,
    pub unit: Option<String>,
    pub tolerance: Option<f64>,
    pub evidence_artifact_ids: Vec<String>,
    pub evaluated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofResultStatus {
    Passed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimedDecision {
    pub status: DecisionStatus,
    pub assurance_level: AssuranceLevel,
    pub mandatory_passed: usize,
    pub mandatory_failed: usize,
    pub mandatory_unknown: usize,
    pub reason: String,
    pub sealed_at: Option<String>,
    pub signature: Option<String>,
}
