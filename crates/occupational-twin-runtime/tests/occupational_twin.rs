use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_occupational_twin_runtime::{
    ApplicationIdentity, EnvironmentIdentity, OperationOutcome, OperationViolation, StateCondition,
    TwinArtifactRole, TwinRuntimeError, TwinWorkspace, TypedOperation, WorkspaceCommand,
    reproduce_final_workspace,
};
use sha2::{Digest, Sha256};

fn environment(applications: Vec<ApplicationIdentity>) -> EnvironmentIdentity {
    EnvironmentIdentity {
        os: "windows".to_owned(),
        architecture: "x86_64".to_owned(),
        runtime_id: "ergaxiom-twin".to_owned(),
        runtime_version: "0.1.0".to_owned(),
        clock_source: "trusted-test-clock".to_owned(),
        sandbox_id: "sandbox-test".to_owned(),
        applications,
    }
}

fn application(id: &str, version: &str, digest: &str) -> ApplicationIdentity {
    ApplicationIdentity {
        application_id: id.to_owned(),
        version: version.to_owned(),
        digest: digest.to_owned(),
    }
}

fn sha256(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    format!("{digest:x}")
}

fn workspace() -> Result<TwinWorkspace, TwinRuntimeError> {
    TwinWorkspace::new(
        "workspace.test",
        environment(vec![
            application("editor", "2.0.0", "editor-digest"),
            application("decoder", "1.0.0", "decoder-digest"),
        ]),
    )
}

fn stage_input(workspace: &mut TwinWorkspace) -> Result<(), TwinRuntimeError> {
    let content = b"approved-input".to_vec();
    workspace.stage_immutable_input(
        "input",
        "application/octet-stream",
        content.clone(),
        &sha256(&content),
    )?;
    Ok(())
}

fn write_operation(
    operation_id: &str,
    artifact_id: &str,
    content: &[u8],
    expected_post_digest: &str,
) -> TypedOperation {
    TypedOperation {
        operation_id: operation_id.to_owned(),
        operator_id: "operator.write".to_owned(),
        declared_input_ids: vec!["input".to_owned()],
        declared_output_ids: vec![artifact_id.to_owned()],
        preconditions: vec![
            StateCondition::ArtifactExists {
                artifact_id: "input".to_owned(),
            },
            StateCondition::ArtifactImmutable {
                artifact_id: "input".to_owned(),
            },
        ],
        commands: vec![WorkspaceCommand::WriteArtifact {
            artifact_id: artifact_id.to_owned(),
            role: TwinArtifactRole::Output,
            media_type: "application/octet-stream".to_owned(),
            content_base64url: URL_SAFE_NO_PAD.encode(content),
        }],
        postconditions: vec![StateCondition::ArtifactDigestEquals {
            artifact_id: artifact_id.to_owned(),
            digest: expected_post_digest.to_owned(),
        }],
    }
}

#[test]
fn environment_identity_is_canonicalized() -> Result<(), Box<dyn Error>> {
    let left = TwinWorkspace::new(
        "workspace.same",
        environment(vec![
            application("z-app", "1", "z"),
            application("a-app", "1", "a"),
        ]),
    )?;
    let right = TwinWorkspace::new(
        "workspace.same",
        environment(vec![
            application("a-app", "1", "a"),
            application("z-app", "1", "z"),
        ]),
    )?;

    assert_eq!(left.current_snapshot()?, right.current_snapshot()?);
    assert_eq!(left.environment().applications[0].application_id, "a-app");
    Ok(())
}

#[test]
fn immutable_input_requires_exact_digest() -> Result<(), Box<dyn Error>> {
    let mut workspace = workspace()?;
    let result = workspace.stage_immutable_input(
        "input",
        "application/octet-stream",
        b"approved-input".to_vec(),
        "wrong-digest",
    );

    assert!(matches!(result, Err(TwinRuntimeError::InputDigestMismatch { .. })));
    assert!(workspace.current_snapshot()?.artifacts.is_empty());
    Ok(())
}

#[test]
fn immutable_input_cannot_be_overwritten() -> Result<(), Box<dyn Error>> {
    let mut workspace = workspace()?;
    stage_input(&mut workspace)?;
    let before = workspace.current_snapshot()?;
    let operation = TypedOperation {
        operation_id: "operation.overwrite-input".to_owned(),
        operator_id: "operator.write".to_owned(),
        declared_input_ids: vec!["input".to_owned()],
        declared_output_ids: vec!["input".to_owned()],
        preconditions: vec![],
        commands: vec![WorkspaceCommand::WriteArtifact {
            artifact_id: "input".to_owned(),
            role: TwinArtifactRole::Input,
            media_type: "application/octet-stream".to_owned(),
            content_base64url: URL_SAFE_NO_PAD.encode(b"tampered"),
        }],
        postconditions: vec![],
    };

    let receipt = workspace.apply_operation(operation)?;
    let after = workspace.current_snapshot()?;
    assert_eq!(receipt.outcome, OperationOutcome::Rejected);
    assert_eq!(before.snapshot_digest, after.snapshot_digest);
    assert_eq!(workspace.artifact_content("input"), Some(b"approved-input".as_slice()));
    assert!(receipt.violations.iter().any(|violation| matches!(
        violation,
        OperationViolation::ImmutableArtifactMutation { .. }
    )));
    assert_eq!(workspace.journal().len(), 1);
    assert_eq!(workspace.trace().len(), 2);
    Ok(())
}

#[test]
fn successful_operation_commits_atomically() -> Result<(), Box<dyn Error>> {
    let mut workspace = workspace()?;
    stage_input(&mut workspace)?;
    let output = b"generated-output";
    let receipt = workspace.apply_operation(write_operation(
        "operation.success",
        "output",
        output,
        &sha256(output),
    ))?;

    assert_eq!(receipt.outcome, OperationOutcome::Succeeded);
    assert!(receipt.violations.is_empty());
    assert_eq!(workspace.artifact_content("output"), Some(output.as_slice()));
    assert_ne!(receipt.before_snapshot_digest, receipt.after_snapshot_digest);
    Ok(())
}

#[test]
fn failed_postcondition_rolls_candidate_state_back() -> Result<(), Box<dyn Error>> {
    let mut workspace = workspace()?;
    stage_input(&mut workspace)?;
    let before = workspace.current_snapshot()?;
    let receipt = workspace.apply_operation(write_operation(
        "operation.bad-postcondition",
        "output",
        b"generated-output",
        "incorrect-output-digest",
    ))?;
    let after = workspace.current_snapshot()?;

    assert_eq!(receipt.outcome, OperationOutcome::RolledBack);
    assert_eq!(before.snapshot_digest, after.snapshot_digest);
    assert!(workspace.artifact_content("output").is_none());
    assert!(receipt.violations.iter().any(|violation| matches!(
        violation,
        OperationViolation::ConditionFailed {
            condition: StateCondition::ArtifactDigestEquals { .. }
        }
    )));
    Ok(())
}

#[test]
fn undeclared_output_mutation_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut workspace = workspace()?;
    stage_input(&mut workspace)?;
    let mut operation = write_operation(
        "operation.undeclared",
        "output",
        b"generated-output",
        &sha256(b"generated-output"),
    );
    operation.declared_output_ids.clear();

    let receipt = workspace.apply_operation(operation)?;
    assert_eq!(receipt.outcome, OperationOutcome::Rejected);
    assert!(receipt.violations.iter().any(|violation| matches!(
        violation,
        OperationViolation::UndeclaredOutputMutation { .. }
    )));
    assert!(workspace.artifact_content("output").is_none());
    Ok(())
}

#[test]
fn checkpoint_rollback_restores_artifacts_and_records_journal() -> Result<(), Box<dyn Error>> {
    let mut workspace = workspace()?;
    stage_input(&mut workspace)?;
    workspace.apply_operation(write_operation(
        "operation.v1",
        "output",
        b"version-one",
        &sha256(b"version-one"),
    ))?;
    let checkpoint = workspace.create_checkpoint("checkpoint.v1")?;
    workspace.apply_operation(write_operation(
        "operation.v2",
        "output",
        b"version-two",
        &sha256(b"version-two"),
    ))?;

    let receipt = workspace.rollback_to_checkpoint("rollback.v1", "checkpoint.v1")?;
    assert_eq!(workspace.artifact_content("output"), Some(b"version-one".as_slice()));
    assert_eq!(receipt.restored_snapshot_digest, checkpoint.snapshot_digest);
    assert_ne!(receipt.before_snapshot_digest, receipt.new_snapshot_digest);
    assert_eq!(workspace.journal().len(), 3);
    Ok(())
}

#[test]
fn sealed_package_reproduces_final_artifacts() -> Result<(), Box<dyn Error>> {
    let mut workspace = workspace()?;
    stage_input(&mut workspace)?;
    workspace.apply_operation(write_operation(
        "operation.seal",
        "output",
        b"sealed-output",
        &sha256(b"sealed-output"),
    ))?;

    let package = workspace.seal_final_state("package.test")?;
    let reproduced = reproduce_final_workspace(&package)?;
    assert_eq!(reproduced.snapshot, package.manifest.final_snapshot);
    assert!(reproduced.artifacts.iter().any(|artifact| {
        artifact.metadata.artifact_id == "output" && artifact.content == b"sealed-output"
    }));
    Ok(())
}

#[test]
fn tampered_sealed_blob_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut workspace = workspace()?;
    stage_input(&mut workspace)?;
    let mut package = workspace.seal_final_state("package.tampered")?;
    package.blobs[0].content_base64url = URL_SAFE_NO_PAD.encode(b"tampered-content");

    assert!(matches!(
        reproduce_final_workspace(&package),
        Err(TwinRuntimeError::BlobDigestMismatch { .. })
    ));
    Ok(())
}

#[test]
fn operation_identifier_cannot_be_replayed() -> Result<(), Box<dyn Error>> {
    let mut workspace = workspace()?;
    stage_input(&mut workspace)?;
    let operation = write_operation(
        "operation.once",
        "output",
        b"output",
        &sha256(b"output"),
    );
    workspace.apply_operation(operation.clone())?;

    assert!(matches!(
        workspace.apply_operation(operation),
        Err(TwinRuntimeError::DuplicateOperationId(_))
    ));
    Ok(())
}
