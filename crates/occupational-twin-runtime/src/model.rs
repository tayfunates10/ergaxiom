use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TwinArtifactRole {
    Input,
    Intermediate,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactMutability {
    Immutable,
    Mutable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationIdentity {
    pub application_id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentIdentity {
    pub os: String,
    pub architecture: String,
    pub runtime_id: String,
    pub runtime_version: String,
    pub clock_source: String,
    pub sandbox_id: String,
    pub applications: Vec<ApplicationIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotArtifact {
    pub artifact_id: String,
    pub role: TwinArtifactRole,
    pub mutability: ArtifactMutability,
    pub media_type: String,
    pub digest: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    pub schema_version: String,
    pub workspace_id: String,
    pub revision: u64,
    pub environment_digest: String,
    pub journal_digest: String,
    pub artifacts: Vec<SnapshotArtifact>,
    pub snapshot_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "condition", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StateCondition {
    ArtifactExists { artifact_id: String },
    ArtifactAbsent { artifact_id: String },
    ArtifactDigestEquals { artifact_id: String, digest: String },
    ArtifactImmutable { artifact_id: String },
    ArtifactMutable { artifact_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkspaceCommand {
    WriteArtifact {
        artifact_id: String,
        role: TwinArtifactRole,
        media_type: String,
        content_base64url: String,
    },
    DeleteArtifact {
        artifact_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedOperation {
    pub operation_id: String,
    pub operator_id: String,
    pub declared_input_ids: Vec<String>,
    pub declared_output_ids: Vec<String>,
    pub preconditions: Vec<StateCondition>,
    pub commands: Vec<WorkspaceCommand>,
    pub postconditions: Vec<StateCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationViolation {
    MissingDeclaredInput { artifact_id: String },
    UndeclaredOutputMutation { artifact_id: String },
    ImmutableArtifactMutation { artifact_id: String },
    DuplicateCommandTarget { artifact_id: String },
    InvalidContentEncoding { artifact_id: String },
    ConditionFailed { condition: StateCondition },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationOutcome {
    Succeeded,
    Rejected,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReceipt {
    pub operation_id: String,
    pub operator_id: String,
    pub outcome: OperationOutcome,
    pub before_snapshot_digest: String,
    pub after_snapshot_digest: String,
    pub changed_artifact_ids: Vec<String>,
    pub violations: Vec<OperationViolation>,
    pub operation_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub sequence: u64,
    pub receipt: OperationReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointDescriptor {
    pub checkpoint_id: String,
    pub snapshot_digest: String,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReceipt {
    pub rollback_id: String,
    pub checkpoint_id: String,
    pub before_snapshot_digest: String,
    pub restored_snapshot_digest: String,
    pub new_snapshot_digest: String,
    pub changed_artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TwinTraceEventKind {
    InputStaged,
    OperationEvaluated,
    CheckpointCreated,
    WorkspaceRolledBack,
    ReplayPackageSealed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwinTraceEvent {
    pub sequence: u64,
    pub kind: TwinTraceEventKind,
    pub subject_id: String,
    pub before_snapshot_digest: Option<String>,
    pub after_snapshot_digest: String,
    pub outcome: String,
    pub details_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedWorkspaceManifest {
    pub schema_version: String,
    pub package_id: String,
    pub workspace_id: String,
    pub environment_digest: String,
    pub final_snapshot: WorkspaceSnapshot,
    pub trace_digest: String,
    pub journal_digest: String,
    pub blob_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBlob {
    pub digest: String,
    pub encoding: String,
    pub content_base64url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedWorkspacePackage {
    pub manifest: SealedWorkspaceManifest,
    pub blobs: Vec<SealedBlob>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReproducedArtifact {
    pub metadata: SnapshotArtifact,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReproducedWorkspace {
    pub snapshot: WorkspaceSnapshot,
    pub artifacts: Vec<ReproducedArtifact>,
}
