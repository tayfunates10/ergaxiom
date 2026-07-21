use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_contract_runtime::{CompiledContract, compile_contract};
use ergaxiom_occupational_twin_runtime::{
    EnvironmentIdentity, StateCondition, TwinArtifactRole, TwinWorkspace, TypedOperation,
    WorkspaceCommand,
};
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_operator_simulation_runtime::{
    FaultInjection, OperatorSimulationPlan, SimulatedStepStatus, SimulationRuntimeError,
    SimulationViolation, StepInvocation, simulate_operator_plan, verify_simulation_digest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Context {
    plan: CompiledPlan,
    workspace: TwinWorkspace,
    simulation: OperatorSimulationPlan,
}

fn context() -> Result<Context, Box<dyn Error>> {
    let contract_value = contract_value();
    let capsule_value = capsule_value();
    let contract = compile_contract(&contract_value, &capsule_value)?;
    let plan = compile_plan(&plan_value(&contract), &capsule_value, &contract)?;
    let mut workspace = TwinWorkspace::new("workspace.simulation", environment())?;
    let input = b"approved-input".to_vec();
    workspace.stage_immutable_input(
        "input",
        "application/octet-stream",
        input.clone(),
        &sha256(&input),
    )?;
    let simulation = simulation_plan(&plan);
    Ok(Context {
        plan,
        workspace,
        simulation,
    })
}

fn environment() -> EnvironmentIdentity {
    EnvironmentIdentity {
        os: "test-os".to_owned(),
        architecture: "x86_64".to_owned(),
        runtime_id: "ergaxiom-twin".to_owned(),
        runtime_version: "0.1.0".to_owned(),
        clock_source: "trusted-test-clock".to_owned(),
        sandbox_id: "sandbox-simulation".to_owned(),
        applications: vec![],
    }
}

fn contract_value() -> Value {
    json!({
        "schema_version": "0.2.0",
        "contract_id": "contract.simulation.0001",
        "profession": {
            "capsule_id": "ergaxiom.profession.simulation-test",
            "capsule_version": "0.1.0"
        },
        "job_type": "simulation_job",
        "requirements": {
            "hard": [{"id": "final_output", "mandatory": true}],
            "unknowns": []
        },
        "permissions": [],
        "proof_obligations": [{
            "id": "proof.final_output",
            "constraint_id": "final_output",
            "validator_ids": ["validator.final"],
            "mandatory": true,
            "independence_class": "independent",
            "evidence_types": ["measurement"]
        }],
        "acceptance": {
            "minimum_assurance_level": "E1",
            "unknowns_must_be_empty": true,
            "all_mandatory_proofs_must_pass": true,
            "validator_conflicts_allowed": false
        }
    })
}

fn capsule_value() -> Value {
    json!({
        "schema_version": "0.1.0",
        "capsule_id": "ergaxiom.profession.simulation-test",
        "version": "0.1.0",
        "job_types": [{
            "id": "simulation_job",
            "required_constraints": ["final_output"],
            "minimum_assurance_level": "E1",
            "operator_ids": ["operator.prepare", "operator.finish"]
        }],
        "operators": [
            {"id": "operator.prepare", "version": "1.0.0"},
            {"id": "operator.finish", "version": "1.0.0"}
        ],
        "validators": [{
            "id": "validator.final",
            "version": "1.0.0",
            "claims": ["final_output"],
            "independence_class": "independent",
            "evidence_types": ["measurement"]
        }],
        "policies": {
            "minimum_assurance_by_job_type": {"simulation_job": "E1"}
        }
    })
}

fn plan_value(contract: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.simulation.0001",
        "created_at": "2026-07-21T11:00:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.simulation-test",
                "algorithm": "sha256",
                "digest": contract.seal.capsule_digest
            }
        },
        "steps": [
            {
                "step_id": "step.prepare",
                "sequence": 0,
                "operator_id": "operator.prepare",
                "operator_version": "1.0.0",
                "depends_on": [],
                "input_artifact_ids": ["input"],
                "output_artifact_ids": ["intermediate"],
                "capability_token_ids": [],
                "mandatory": true,
                "rollback_step_id": null
            },
            {
                "step_id": "step.finish",
                "sequence": 1,
                "operator_id": "operator.finish",
                "operator_version": "1.0.0",
                "depends_on": ["step.prepare"],
                "input_artifact_ids": ["intermediate"],
                "output_artifact_ids": ["output"],
                "capability_token_ids": [],
                "mandatory": true,
                "rollback_step_id": null
            }
        ]
    })
}

fn simulation_plan(plan: &CompiledPlan) -> OperatorSimulationPlan {
    OperatorSimulationPlan {
        schema_version: "0.1.0".to_owned(),
        simulation_id: "simulation.0001".to_owned(),
        plan_id: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        invocations: vec![
            invocation(
                "step.prepare",
                "operator.prepare",
                operation(
                    "operation.prepare",
                    "operator.prepare",
                    "input",
                    "intermediate",
                    b"prepared-content",
                ),
            ),
            invocation(
                "step.finish",
                "operator.finish",
                operation(
                    "operation.finish",
                    "operator.finish",
                    "intermediate",
                    "output",
                    b"final-content",
                ),
            ),
        ],
    }
}

fn invocation(step_id: &str, operator_id: &str, operation: TypedOperation) -> StepInvocation {
    StepInvocation {
        step_id: step_id.to_owned(),
        operator_id: operator_id.to_owned(),
        operator_version: "1.0.0".to_owned(),
        operation,
        fault: None,
    }
}

fn operation(
    operation_id: &str,
    operator_id: &str,
    input_id: &str,
    output_id: &str,
    content: &[u8],
) -> TypedOperation {
    TypedOperation {
        operation_id: operation_id.to_owned(),
        operator_id: operator_id.to_owned(),
        declared_input_ids: vec![input_id.to_owned()],
        declared_output_ids: vec![output_id.to_owned()],
        preconditions: vec![StateCondition::ArtifactExists {
            artifact_id: input_id.to_owned(),
        }],
        commands: vec![WorkspaceCommand::WriteArtifact {
            artifact_id: output_id.to_owned(),
            role: TwinArtifactRole::Output,
            media_type: "application/octet-stream".to_owned(),
            content_base64url: URL_SAFE_NO_PAD.encode(content),
        }],
        postconditions: vec![StateCondition::ArtifactDigestEquals {
            artifact_id: output_id.to_owned(),
            digest: sha256(content),
        }],
    }
}

fn sha256(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    format!("{digest:x}")
}

#[test]
fn identical_simulations_are_deterministic() -> Result<(), Box<dyn Error>> {
    let mut left = context()?;
    let mut right = context()?;
    let left_report = simulate_operator_plan(&mut left.workspace, &left.plan, &left.simulation)?;
    let right_report =
        simulate_operator_plan(&mut right.workspace, &right.plan, &right.simulation)?;

    assert!(left_report.conforms_to_plan);
    assert_eq!(left_report, right_report);
    assert!(verify_simulation_digest(&left_report)?);
    assert_eq!(
        left.workspace.artifact_content("output"),
        Some(b"final-content".as_slice())
    );
    Ok(())
}

#[test]
fn missing_mandatory_invocation_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.simulation.invocations.pop();
    let report =
        simulate_operator_plan(&mut context.workspace, &context.plan, &context.simulation)?;

    assert!(!report.conforms_to_plan);
    assert_eq!(report.steps[1].status, SimulatedStepStatus::Missing);
    assert!(report.violations.iter().any(|violation| matches!(
        violation,
        SimulationViolation::MissingMandatoryInvocation { .. }
    )));
    Ok(())
}

#[test]
fn operator_identity_mismatch_blocks_before_workspace_mutation() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.simulation.invocations[0].operator_id = "operator.other".to_owned();
    let initial = context.workspace.current_snapshot()?;
    let report =
        simulate_operator_plan(&mut context.workspace, &context.plan, &context.simulation)?;

    assert_eq!(report.steps[0].status, SimulatedStepStatus::Blocked);
    assert_eq!(
        initial.snapshot_digest,
        report.final_snapshot.snapshot_digest
    );
    assert!(context.workspace.artifact_content("intermediate").is_none());
    assert!(report.violations.iter().any(|violation| matches!(
        violation,
        SimulationViolation::InvocationOperatorMismatch { .. }
    )));
    Ok(())
}

#[test]
fn declared_artifact_mismatch_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.simulation.invocations[0]
        .operation
        .declared_output_ids = vec!["other-output".to_owned()];
    let report =
        simulate_operator_plan(&mut context.workspace, &context.plan, &context.simulation)?;

    assert_eq!(report.steps[0].status, SimulatedStepStatus::Blocked);
    assert!(report.violations.iter().any(|violation| matches!(
        violation,
        SimulationViolation::DeclaredOutputMismatch { .. }
    )));
    Ok(())
}

#[test]
fn forced_postcondition_failure_rolls_back_and_blocks_dependency() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.simulation.invocations[0].fault = Some(FaultInjection::ForcePostconditionFailure {
        artifact_id: "intermediate".to_owned(),
    });
    let report =
        simulate_operator_plan(&mut context.workspace, &context.plan, &context.simulation)?;

    assert_eq!(report.steps[0].status, SimulatedStepStatus::RolledBack);
    assert_eq!(report.steps[1].status, SimulatedStepStatus::Blocked);
    assert!(context.workspace.artifact_content("intermediate").is_none());
    assert!(report.violations.iter().any(|violation| matches!(
        violation,
        SimulationViolation::DependencyNotSucceeded { .. }
    )));
    Ok(())
}

#[test]
fn corrupt_write_fault_is_detected_by_postcondition() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.simulation.invocations[0].fault = Some(FaultInjection::CorruptFirstWrite {
        replacement_base64url: URL_SAFE_NO_PAD.encode(b"corrupted"),
    });
    let report =
        simulate_operator_plan(&mut context.workspace, &context.plan, &context.simulation)?;

    assert_eq!(report.steps[0].status, SimulatedStepStatus::RolledBack);
    assert!(!report.conforms_to_plan);
    Ok(())
}

#[test]
fn unexpected_invocation_is_reported() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.simulation.invocations.push(invocation(
        "step.unknown",
        "operator.prepare",
        operation(
            "operation.unknown",
            "operator.prepare",
            "input",
            "unknown-output",
            b"unknown",
        ),
    ));
    let report =
        simulate_operator_plan(&mut context.workspace, &context.plan, &context.simulation)?;

    assert!(!report.conforms_to_plan);
    assert!(
        report
            .violations
            .iter()
            .any(|violation| matches!(violation, SimulationViolation::UnexpectedInvocation { .. }))
    );
    Ok(())
}

#[test]
fn simulation_is_bound_to_exact_plan_digest() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.simulation.plan_digest = "another-plan".to_owned();

    assert!(matches!(
        simulate_operator_plan(&mut context.workspace, &context.plan, &context.simulation),
        Err(SimulationRuntimeError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn simulation_report_digest_detects_mutation() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    let mut report =
        simulate_operator_plan(&mut context.workspace, &context.plan, &context.simulation)?;
    assert!(verify_simulation_digest(&report)?);
    report.conforms_to_plan = false;
    assert!(!verify_simulation_digest(&report)?);
    Ok(())
}
