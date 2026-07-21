#![forbid(unsafe_code)]

mod model;
mod runtime;

pub use model::{
    ApplicationIdentity, ArtifactMutability, CheckpointDescriptor, EnvironmentIdentity,
    JournalEntry, JournalRecord, OperationOutcome, OperationReceipt, OperationViolation,
    ReproducedArtifact, ReproducedWorkspace, RollbackReceipt, SealedBlob,
    SealedWorkspaceManifest, SealedWorkspacePackage, SnapshotArtifact, StateCondition,
    TwinArtifactRole, TwinTraceEvent, TwinTraceEventKind, TypedOperation, WorkspaceCommand,
    WorkspaceSnapshot,
};
pub use runtime::{TwinRuntimeError, TwinWorkspace, reproduce_final_workspace};
