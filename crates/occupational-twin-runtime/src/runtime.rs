use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{
    ApplicationIdentity, ArtifactMutability, CheckpointDescriptor, EnvironmentIdentity,
    JournalEntry, JournalRecord, OperationOutcome, OperationReceipt, OperationViolation,
    ReproducedArtifact, ReproducedWorkspace, RollbackReceipt, SealedBlob,
    SealedWorkspaceManifest, SealedWorkspacePackage, SnapshotArtifact, StateCondition,
    TwinArtifactRole, TwinTraceEvent, TwinTraceEventKind, TypedOperation, WorkspaceCommand,
    WorkspaceSnapshot,
};

const SNAPSHOT_SCHEMA: &str = "0.1.0";
const SEALED_RUN_SCHEMA: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum TwinRuntimeError {
    #[error("required field is empty: {0}")]
    EmptyField(&'static str),
    #[error("artifact already exists: {0}")]
    ArtifactAlreadyExists(String),
    #[error("immutable input digest mismatch: expected {expected}, actual {actual}")]
    InputDigestMismatch { expected: String, actual: String },
    #[error("operation ID was already evaluated: {0}")]
    DuplicateOperationId(String),
    #[error("checkpoint already exists: {0}")]
    DuplicateCheckpoint(String),
    #[error("unknown checkpoint: {0}")]
    UnknownCheckpoint(String),
    #[error("rollback ID was already used: {0}")]
    DuplicateRollbackId(String),
    #[error("unsupported sealed workspace schema: {0}")]
    UnsupportedSealedRunSchema(String),
    #[error("sealed blob encoding is unsupported: {0}")]
    UnsupportedBlobEncoding(String),
    #[error("duplicate sealed blob digest: {0}")]
    DuplicateBlob(String),
    #[error("sealed blob is not valid base64url: {0}")]
    InvalidBlobEncoding(String),
    #[error("sealed blob digest mismatch: declared {declared}, actual {actual}")]
    BlobDigestMismatch { declared: String, actual: String },
    #[error("sealed package blob inventory does not match manifest")]
    BlobInventoryMismatch,
    #[error("final artifact references missing blob {0}")]
    MissingBlob(String),
    #[error("reproduced artifact size mismatch: {0}")]
    ArtifactSizeMismatch(String),
    #[error("final snapshot digest does not reproduce")]
    SnapshotDigestMismatch,
    #[error("manifest and final snapshot environment digests differ")]
    EnvironmentDigestMismatch,
    #[error("manifest and final snapshot journal digests differ")]
    JournalDigestMismatch,
    #[error("failed to serialize twin state: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactRecord {
    role: TwinArtifactRole,
    mutability: ArtifactMutability,
    media_type: String,
    content: Vec<u8>,
}

impl ArtifactRecord {
    fn metadata(&self, artifact_id: &str) -> SnapshotArtifact {
        SnapshotArtifact {
            artifact_id: artifact_id.to_owned(),
            role: self.role,
            mutability: self.mutability,
            media_type: self.media_type.clone(),
            digest: sha256_hex(&self.content),
            size_bytes: self.content.len() as u64,
        }
    }
}

#[derive(Debug, Clone)]
struct CheckpointState {
    descriptor: CheckpointDescriptor,
    artifacts: BTreeMap<String, ArtifactRecord>,
}

#[derive(Debug, Clone)]
enum PreparedCommand {
    Write {
        artifact_id: String,
        record: ArtifactRecord,
    },
    Delete {
        artifact_id: String,
    },
}

#[derive(Debug, Clone)]
pub struct TwinWorkspace {
    workspace_id: String,
    environment: EnvironmentIdentity,
    artifacts: BTreeMap<String, ArtifactRecord>,
    checkpoints: BTreeMap<String, CheckpointState>,
    journal: Vec<JournalEntry>,
    trace: Vec<TwinTraceEvent>,
    operation_ids: BTreeSet<String>,
    rollback_ids: BTreeSet<String>,
    revision: u64,
}

impl TwinWorkspace {
    pub fn new(
        workspace_id: impl Into<String>,
        mut environment: EnvironmentIdentity,
    ) -> Result<Self, TwinRuntimeError> {
        let workspace_id = workspace_id.into();
        require_non_empty("workspace_id", &workspace_id)?;
        validate_environment(&environment)?;
        environment.applications.sort_by(|left, right| {
            left.application_id
                .cmp(&right.application_id)
                .then(left.version.cmp(&right.version))
                .then(left.digest.cmp(&right.digest))
        });
        Ok(Self {
            workspace_id,
            environment,
            artifacts: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            journal: Vec::new(),
            trace: Vec::new(),
            operation_ids: BTreeSet::new(),
            rollback_ids: BTreeSet::new(),
            revision: 0,
        })
    }

    #[must_use]
    pub const fn environment(&self) -> &EnvironmentIdentity {
        &self.environment
    }

    #[must_use]
    pub fn journal(&self) -> &[JournalEntry] {
        &self.journal
    }

    #[must_use]
    pub fn trace(&self) -> &[TwinTraceEvent] {
        &self.trace
    }

    #[must_use]
    pub fn artifact_content(&self, artifact_id: &str) -> Option<&[u8]> {
        self.artifacts
            .get(artifact_id)
            .map(|record| record.content.as_slice())
    }

    pub fn current_snapshot(&self) -> Result<WorkspaceSnapshot, TwinRuntimeError> {
        create_snapshot(
            &self.workspace_id,
            self.revision,
            &self.environment,
            &self.artifacts,
            &self.journal,
        )
    }

    pub fn stage_immutable_input(
        &mut self,
        artifact_id: impl Into<String>,
        media_type: impl Into<String>,
        content: Vec<u8>,
        expected_sha256: &str,
    ) -> Result<WorkspaceSnapshot, TwinRuntimeError> {
        let artifact_id = artifact_id.into();
        let media_type = media_type.into();
        require_non_empty("artifact_id", &artifact_id)?;
        require_non_empty("media_type", &media_type)?;
        if self.artifacts.contains_key(&artifact_id) {
            return Err(TwinRuntimeError::ArtifactAlreadyExists(artifact_id));
        }
        let actual = sha256_hex(&content);
        if actual != expected_sha256 {
            return Err(TwinRuntimeError::InputDigestMismatch {
                expected: expected_sha256.to_owned(),
                actual,
            });
        }

        let before = self.current_snapshot()?;
        let record = ArtifactRecord {
            role: TwinArtifactRole::Input,
            mutability: ArtifactMutability::Immutable,
            media_type,
            content,
        };
        let details = record.metadata(&artifact_id);
        self.artifacts.insert(artifact_id.clone(), record);
        self.revision += 1;
        let after = self.current_snapshot()?;
        self.push_trace(
            TwinTraceEventKind::InputStaged,
            artifact_id,
            Some(before.snapshot_digest),
            after.snapshot_digest.clone(),
            "SUCCEEDED",
            &details,
        )?;
        Ok(after)
    }

    pub fn apply_operation(
        &mut self,
        operation: TypedOperation,
    ) -> Result<OperationReceipt, TwinRuntimeError> {
        require_non_empty("operation_id", &operation.operation_id)?;
        require_non_empty("operator_id", &operation.operator_id)?;
        if !self.operation_ids.insert(operation.operation_id.clone()) {
            return Err(TwinRuntimeError::DuplicateOperationId(
                operation.operation_id,
            ));
        }

        let operation_value =
            serde_json::to_value(&operation).map_err(TwinRuntimeError::Serialization)?;
        let operation_digest = canonical_json_sha256(&operation_value)?;
        let before = self.current_snapshot()?;
        let mut violations = validate_declared_inputs(&self.artifacts, &operation);
        violations.extend(evaluate_conditions(&self.artifacts, &operation.preconditions));
        let (prepared_commands, command_violations, changed_artifact_ids) =
            prepare_commands(&self.artifacts, &operation);
        violations.extend(command_violations);

        if !violations.is_empty() {
            return self.finish_operation(
                operation,
                OperationOutcome::Rejected,
                before.snapshot_digest.clone(),
                before.snapshot_digest,
                Vec::new(),
                violations,
                operation_digest,
            );
        }

        let mut candidate = self.artifacts.clone();
        apply_prepared_commands(&mut candidate, prepared_commands);
        let postcondition_violations = evaluate_conditions(&candidate, &operation.postconditions);
        if !postcondition_violations.is_empty() {
            return self.finish_operation(
                operation,
                OperationOutcome::RolledBack,
                before.snapshot_digest.clone(),
                before.snapshot_digest,
                changed_artifact_ids,
                postcondition_violations,
                operation_digest,
            );
        }

        self.artifacts = candidate;
        self.revision += 1;
        let after = self.current_snapshot()?;
        self.finish_operation(
            operation,
            OperationOutcome::Succeeded,
            before.snapshot_digest,
            after.snapshot_digest,
            changed_artifact_ids,
            Vec::new(),
            operation_digest,
        )
    }

    pub fn create_checkpoint(
        &mut self,
        checkpoint_id: impl Into<String>,
    ) -> Result<CheckpointDescriptor, TwinRuntimeError> {
        let checkpoint_id = checkpoint_id.into();
        require_non_empty("checkpoint_id", &checkpoint_id)?;
        if self.checkpoints.contains_key(&checkpoint_id) {
            return Err(TwinRuntimeError::DuplicateCheckpoint(checkpoint_id));
        }
        let snapshot = self.current_snapshot()?;
        let descriptor = CheckpointDescriptor {
            checkpoint_id: checkpoint_id.clone(),
            snapshot_digest: snapshot.snapshot_digest.clone(),
            revision: snapshot.revision,
        };
        self.checkpoints.insert(
            checkpoint_id.clone(),
            CheckpointState {
                descriptor: descriptor.clone(),
                artifacts: self.artifacts.clone(),
            },
        );
        self.push_trace(
            TwinTraceEventKind::CheckpointCreated,
            checkpoint_id,
            Some(snapshot.snapshot_digest.clone()),
            snapshot.snapshot_digest,
            "SUCCEEDED",
            &descriptor,
        )?;
        Ok(descriptor)
    }

    pub fn rollback_to_checkpoint(
        &mut self,
        rollback_id: impl Into<String>,
        checkpoint_id: &str,
    ) -> Result<RollbackReceipt, TwinRuntimeError> {
        let rollback_id = rollback_id.into();
        require_non_empty("rollback_id", &rollback_id)?;
        if !self.rollback_ids.insert(rollback_id.clone()) {
            return Err(TwinRuntimeError::DuplicateRollbackId(rollback_id));
        }
        let checkpoint = self
            .checkpoints
            .get(checkpoint_id)
            .cloned()
            .ok_or_else(|| TwinRuntimeError::UnknownCheckpoint(checkpoint_id.to_owned()))?;
        let before = self.current_snapshot()?;
        let changed_artifact_ids = changed_artifacts(&self.artifacts, &checkpoint.artifacts);
        self.artifacts = checkpoint.artifacts;
        self.revision += 1;
        let after = self.current_snapshot()?;
        let receipt = RollbackReceipt {
            rollback_id: rollback_id.clone(),
            checkpoint_id: checkpoint_id.to_owned(),
            before_snapshot_digest: before.snapshot_digest.clone(),
            restored_snapshot_digest: checkpoint.descriptor.snapshot_digest,
            new_snapshot_digest: after.snapshot_digest.clone(),
            changed_artifact_ids,
        };
        self.push_journal(JournalRecord::Rollback {
            receipt: receipt.clone(),
        });
        self.push_trace(
            TwinTraceEventKind::WorkspaceRolledBack,
            rollback_id,
            Some(before.snapshot_digest),
            after.snapshot_digest,
            "SUCCEEDED",
            &receipt,
        )?;
        Ok(receipt)
    }

    pub fn seal_final_state(
        &mut self,
        package_id: impl Into<String>,
    ) -> Result<SealedWorkspacePackage, TwinRuntimeError> {
        let package_id = package_id.into();
        require_non_empty("package_id", &package_id)?;
        let snapshot = self.current_snapshot()?;
        let details = json!({"package_id": package_id});
        self.push_trace(
            TwinTraceEventKind::ReplayPackageSealed,
            package_id.clone(),
            Some(snapshot.snapshot_digest.clone()),
            snapshot.snapshot_digest.clone(),
            "SEALED",
            &details,
        )?;

        let mut blobs_by_digest = BTreeMap::new();
        for record in self.artifacts.values() {
            let digest = sha256_hex(&record.content);
            blobs_by_digest
                .entry(digest)
                .or_insert_with(|| record.content.clone());
        }
        let blob_digests: Vec<_> = blobs_by_digest.keys().cloned().collect();
        let blobs = blobs_by_digest
            .into_iter()
            .map(|(digest, content)| SealedBlob {
                digest,
                encoding: "base64url".to_owned(),
                content_base64url: URL_SAFE_NO_PAD.encode(content),
            })
            .collect();
        let final_snapshot = self.current_snapshot()?;
        let manifest = SealedWorkspaceManifest {
            schema_version: SEALED_RUN_SCHEMA.to_owned(),
            package_id,
            workspace_id: self.workspace_id.clone(),
            environment_digest: environment_digest(&self.environment)?,
            final_snapshot,
            trace_digest: digest_serializable(&self.trace)?,
            journal_digest: digest_serializable(&self.journal)?,
            blob_digests,
        };
        Ok(SealedWorkspacePackage { manifest, blobs })
    }

    fn finish_operation(
        &mut self,
        operation: TypedOperation,
        outcome: OperationOutcome,
        before_snapshot_digest: String,
        after_snapshot_digest: String,
        mut changed_artifact_ids: Vec<String>,
        violations: Vec<OperationViolation>,
        operation_digest: String,
    ) -> Result<OperationReceipt, TwinRuntimeError> {
        changed_artifact_ids.sort();
        changed_artifact_ids.dedup();
        let receipt = OperationReceipt {
            operation_id: operation.operation_id.clone(),
            operator_id: operation.operator_id,
            outcome,
            before_snapshot_digest: before_snapshot_digest.clone(),
            after_snapshot_digest: after_snapshot_digest.clone(),
            changed_artifact_ids,
            violations,
            operation_digest,
        };
        self.push_journal(JournalRecord::Operation {
            receipt: receipt.clone(),
        });
        self.push_trace(
            TwinTraceEventKind::OperationEvaluated,
            operation.operation_id,
            Some(before_snapshot_digest),
            after_snapshot_digest,
            match outcome {
                OperationOutcome::Succeeded => "SUCCEEDED",
                OperationOutcome::Rejected => "REJECTED",
                OperationOutcome::RolledBack => "ROLLED_BACK",
            },
            &receipt,
        )?;
        Ok(receipt)
    }

    fn push_journal(&mut self, record: JournalRecord) {
        self.journal.push(JournalEntry {
            sequence: self.journal.len() as u64,
            record,
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn push_trace<T: Serialize>(
        &mut self,
        kind: TwinTraceEventKind,
        subject_id: String,
        before_snapshot_digest: Option<String>,
        after_snapshot_digest: String,
        outcome: &str,
        details: &T,
    ) -> Result<(), TwinRuntimeError> {
        let details_value =
            serde_json::to_value(details).map_err(TwinRuntimeError::Serialization)?;
        self.trace.push(TwinTraceEvent {
            sequence: self.trace.len() as u64,
            kind,
            subject_id,
            before_snapshot_digest,
            after_snapshot_digest,
            outcome: outcome.to_owned(),
            details_digest: canonical_json_sha256(&details_value)?,
        });
        Ok(())
    }
}

pub fn reproduce_final_workspace(
    package: &SealedWorkspacePackage,
) -> Result<ReproducedWorkspace, TwinRuntimeError> {
    if package.manifest.schema_version != SEALED_RUN_SCHEMA {
        return Err(TwinRuntimeError::UnsupportedSealedRunSchema(
            package.manifest.schema_version.clone(),
        ));
    }
    if package.manifest.environment_digest != package.manifest.final_snapshot.environment_digest {
        return Err(TwinRuntimeError::EnvironmentDigestMismatch);
    }
    if package.manifest.journal_digest != package.manifest.final_snapshot.journal_digest {
        return Err(TwinRuntimeError::JournalDigestMismatch);
    }

    let mut blobs = BTreeMap::new();
    for sealed_blob in &package.blobs {
        if sealed_blob.encoding != "base64url" {
            return Err(TwinRuntimeError::UnsupportedBlobEncoding(
                sealed_blob.encoding.clone(),
            ));
        }
        let content = URL_SAFE_NO_PAD
            .decode(&sealed_blob.content_base64url)
            .map_err(|_| TwinRuntimeError::InvalidBlobEncoding(sealed_blob.digest.clone()))?;
        let actual = sha256_hex(&content);
        if actual != sealed_blob.digest {
            return Err(TwinRuntimeError::BlobDigestMismatch {
                declared: sealed_blob.digest.clone(),
                actual,
            });
        }
        if blobs.insert(sealed_blob.digest.clone(), content).is_some() {
            return Err(TwinRuntimeError::DuplicateBlob(
                sealed_blob.digest.clone(),
            ));
        }
    }
    let actual_blob_digests: Vec<_> = blobs.keys().cloned().collect();
    if actual_blob_digests != package.manifest.blob_digests {
        return Err(TwinRuntimeError::BlobInventoryMismatch);
    }

    let mut artifacts = Vec::new();
    for metadata in &package.manifest.final_snapshot.artifacts {
        let content = blobs
            .get(&metadata.digest)
            .cloned()
            .ok_or_else(|| TwinRuntimeError::MissingBlob(metadata.digest.clone()))?;
        if content.len() as u64 != metadata.size_bytes {
            return Err(TwinRuntimeError::ArtifactSizeMismatch(
                metadata.artifact_id.clone(),
            ));
        }
        artifacts.push(ReproducedArtifact {
            metadata: metadata.clone(),
            content,
        });
    }

    let expected_snapshot_digest = snapshot_state_digest(
        &package.manifest.final_snapshot.workspace_id,
        package.manifest.final_snapshot.revision,
        &package.manifest.final_snapshot.environment_digest,
        &package.manifest.final_snapshot.artifacts,
    )?;
    if expected_snapshot_digest != package.manifest.final_snapshot.snapshot_digest {
        return Err(TwinRuntimeError::SnapshotDigestMismatch);
    }

    Ok(ReproducedWorkspace {
        snapshot: package.manifest.final_snapshot.clone(),
        artifacts,
    })
}

fn validate_declared_inputs(
    artifacts: &BTreeMap<String, ArtifactRecord>,
    operation: &TypedOperation,
) -> Vec<OperationViolation> {
    operation
        .declared_input_ids
        .iter()
        .filter(|artifact_id| !artifacts.contains_key(*artifact_id))
        .map(|artifact_id| OperationViolation::MissingDeclaredInput {
            artifact_id: artifact_id.clone(),
        })
        .collect()
}

fn prepare_commands(
    artifacts: &BTreeMap<String, ArtifactRecord>,
    operation: &TypedOperation,
) -> (Vec<PreparedCommand>, Vec<OperationViolation>, Vec<String>) {
    let declared_outputs: BTreeSet<_> = operation.declared_output_ids.iter().collect();
    let mut targets = BTreeSet::new();
    let mut prepared = Vec::new();
    let mut violations = Vec::new();
    let mut changed = Vec::new();

    for command in &operation.commands {
        let artifact_id = match command {
            WorkspaceCommand::WriteArtifact { artifact_id, .. }
            | WorkspaceCommand::DeleteArtifact { artifact_id } => artifact_id,
        };
        if !targets.insert(artifact_id.clone()) {
            violations.push(OperationViolation::DuplicateCommandTarget {
                artifact_id: artifact_id.clone(),
            });
            continue;
        }
        if !declared_outputs.contains(artifact_id) {
            violations.push(OperationViolation::UndeclaredOutputMutation {
                artifact_id: artifact_id.clone(),
            });
        }
        if artifacts
            .get(artifact_id)
            .is_some_and(|record| record.mutability == ArtifactMutability::Immutable)
        {
            violations.push(OperationViolation::ImmutableArtifactMutation {
                artifact_id: artifact_id.clone(),
            });
        }

        match command {
            WorkspaceCommand::WriteArtifact {
                artifact_id,
                role,
                media_type,
                content_base64url,
            } => match URL_SAFE_NO_PAD.decode(content_base64url) {
                Ok(content) => prepared.push(PreparedCommand::Write {
                    artifact_id: artifact_id.clone(),
                    record: ArtifactRecord {
                        role: *role,
                        mutability: ArtifactMutability::Mutable,
                        media_type: media_type.clone(),
                        content,
                    },
                }),
                Err(_) => violations.push(OperationViolation::InvalidContentEncoding {
                    artifact_id: artifact_id.clone(),
                }),
            },
            WorkspaceCommand::DeleteArtifact { artifact_id } => {
                if !artifacts.contains_key(artifact_id) {
                    violations.push(OperationViolation::ConditionFailed {
                        condition: StateCondition::ArtifactExists {
                            artifact_id: artifact_id.clone(),
                        },
                    });
                }
                prepared.push(PreparedCommand::Delete {
                    artifact_id: artifact_id.clone(),
                });
            }
        }
        changed.push(artifact_id.clone());
    }
    (prepared, violations, changed)
}

fn apply_prepared_commands(
    artifacts: &mut BTreeMap<String, ArtifactRecord>,
    commands: Vec<PreparedCommand>,
) {
    for command in commands {
        match command {
            PreparedCommand::Write {
                artifact_id,
                record,
            } => {
                artifacts.insert(artifact_id, record);
            }
            PreparedCommand::Delete { artifact_id } => {
                artifacts.remove(&artifact_id);
            }
        }
    }
}

fn evaluate_conditions(
    artifacts: &BTreeMap<String, ArtifactRecord>,
    conditions: &[StateCondition],
) -> Vec<OperationViolation> {
    conditions
        .iter()
        .filter(|condition| !condition_matches(artifacts, condition))
        .cloned()
        .map(|condition| OperationViolation::ConditionFailed { condition })
        .collect()
}

fn condition_matches(
    artifacts: &BTreeMap<String, ArtifactRecord>,
    condition: &StateCondition,
) -> bool {
    match condition {
        StateCondition::ArtifactExists { artifact_id } => artifacts.contains_key(artifact_id),
        StateCondition::ArtifactAbsent { artifact_id } => !artifacts.contains_key(artifact_id),
        StateCondition::ArtifactDigestEquals {
            artifact_id,
            digest,
        } => artifacts
            .get(artifact_id)
            .is_some_and(|record| sha256_hex(&record.content) == *digest),
        StateCondition::ArtifactImmutable { artifact_id } => artifacts
            .get(artifact_id)
            .is_some_and(|record| record.mutability == ArtifactMutability::Immutable),
        StateCondition::ArtifactMutable { artifact_id } => artifacts
            .get(artifact_id)
            .is_some_and(|record| record.mutability == ArtifactMutability::Mutable),
    }
}

fn changed_artifacts(
    before: &BTreeMap<String, ArtifactRecord>,
    after: &BTreeMap<String, ArtifactRecord>,
) -> Vec<String> {
    let identifiers: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
    identifiers
        .into_iter()
        .filter(|identifier| before.get(identifier) != after.get(identifier))
        .collect()
}

fn create_snapshot(
    workspace_id: &str,
    revision: u64,
    environment: &EnvironmentIdentity,
    artifacts: &BTreeMap<String, ArtifactRecord>,
    journal: &[JournalEntry],
) -> Result<WorkspaceSnapshot, TwinRuntimeError> {
    let snapshot_artifacts: Vec<_> = artifacts
        .iter()
        .map(|(artifact_id, record)| record.metadata(artifact_id))
        .collect();
    let environment_digest = environment_digest(environment)?;
    let journal_digest = digest_serializable(journal)?;
    let snapshot_digest = snapshot_state_digest(
        workspace_id,
        revision,
        &environment_digest,
        &snapshot_artifacts,
    )?;
    Ok(WorkspaceSnapshot {
        schema_version: SNAPSHOT_SCHEMA.to_owned(),
        workspace_id: workspace_id.to_owned(),
        revision,
        environment_digest,
        journal_digest,
        artifacts: snapshot_artifacts,
        snapshot_digest,
    })
}

fn snapshot_state_digest(
    workspace_id: &str,
    revision: u64,
    environment_digest: &str,
    artifacts: &[SnapshotArtifact],
) -> Result<String, TwinRuntimeError> {
    let value = json!({
        "schema_version": SNAPSHOT_SCHEMA,
        "workspace_id": workspace_id,
        "revision": revision,
        "environment_digest": environment_digest,
        "artifacts": artifacts,
    });
    Ok(canonical_json_sha256(&value)?)
}

fn environment_digest(environment: &EnvironmentIdentity) -> Result<String, TwinRuntimeError> {
    digest_serializable(environment)
}

fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Result<String, TwinRuntimeError> {
    let json_value = serde_json::to_value(value).map_err(TwinRuntimeError::Serialization)?;
    Ok(canonical_json_sha256(&json_value)?)
}

fn sha256_hex(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    format!("{digest:x}")
}

fn validate_environment(environment: &EnvironmentIdentity) -> Result<(), TwinRuntimeError> {
    require_non_empty("environment.os", &environment.os)?;
    require_non_empty("environment.architecture", &environment.architecture)?;
    require_non_empty("environment.runtime_id", &environment.runtime_id)?;
    require_non_empty("environment.runtime_version", &environment.runtime_version)?;
    require_non_empty("environment.clock_source", &environment.clock_source)?;
    require_non_empty("environment.sandbox_id", &environment.sandbox_id)?;
    for application in &environment.applications {
        validate_application(application)?;
    }
    Ok(())
}

fn validate_application(application: &ApplicationIdentity) -> Result<(), TwinRuntimeError> {
    require_non_empty("application_id", &application.application_id)?;
    require_non_empty("application.version", &application.version)?;
    require_non_empty("application.digest", &application.digest)
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), TwinRuntimeError> {
    if value.trim().is_empty() {
        Err(TwinRuntimeError::EmptyField(field))
    } else {
        Ok(())
    }
}
