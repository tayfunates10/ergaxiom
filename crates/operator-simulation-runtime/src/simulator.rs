use std::collections::{BTreeMap, BTreeSet};

use ergaxiom_occupational_twin_runtime::{
    OperationOutcome, StateCondition, TwinRuntimeError, TwinWorkspace, TypedOperation,
    WorkspaceCommand,
};
use ergaxiom_operator_plan_runtime::{CompiledPlan, PlanStep};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde_json::{Value, json};
use thiserror::Error;

use crate::model::{
    FaultInjection, OperatorSimulationPlan, OperatorSimulationReport, SimulatedStepStatus,
    SimulationStepReport, SimulationViolation, StepInvocation,
};

const SIMULATION_PLAN_SCHEMA: &str = "0.1.0";
const SIMULATION_REPORT_SCHEMA: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum SimulationRuntimeError {
    #[error("unsupported simulation-plan schema {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        actual: String,
        expected: &'static str,
    },
    #[error("required simulation field is empty: {0}")]
    EmptyField(&'static str),
    #[error("simulation plan ID {actual} does not match compiled plan {expected}")]
    PlanIdMismatch { actual: String, expected: String },
    #[error("simulation plan digest does not match compiled plan")]
    PlanDigestMismatch,
    #[error(transparent)]
    Twin(#[from] TwinRuntimeError),
    #[error("failed to serialize simulation state: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn simulate_operator_plan(
    workspace: &mut TwinWorkspace,
    compiled_plan: &CompiledPlan,
    simulation: &OperatorSimulationPlan,
) -> Result<OperatorSimulationReport, SimulationRuntimeError> {
    validate_simulation_binding(compiled_plan, simulation)?;
    let initial_snapshot = workspace.current_snapshot()?;
    let plan_step_ids: BTreeSet<_> = compiled_plan
        .steps
        .iter()
        .map(|step| step.step_id.as_str())
        .collect();
    let mut indexed_invocations = BTreeMap::new();
    let mut global_violations = Vec::new();

    for invocation in &simulation.invocations {
        if !plan_step_ids.contains(invocation.step_id.as_str()) {
            global_violations.push(SimulationViolation::UnexpectedInvocation {
                step_id: invocation.step_id.clone(),
            });
            continue;
        }
        if indexed_invocations
            .insert(invocation.step_id.clone(), invocation)
            .is_some()
        {
            global_violations.push(SimulationViolation::DuplicateInvocation {
                step_id: invocation.step_id.clone(),
            });
        }
    }

    let mut succeeded_steps = BTreeSet::new();
    let mut step_reports = Vec::with_capacity(compiled_plan.steps.len());

    for step in &compiled_plan.steps {
        let before = workspace.current_snapshot()?;
        let Some(invocation) = indexed_invocations.get(&step.step_id) else {
            let violations = if step.mandatory {
                vec![SimulationViolation::MissingMandatoryInvocation {
                    step_id: step.step_id.clone(),
                }]
            } else {
                Vec::new()
            };
            global_violations.extend(violations.clone());
            step_reports.push(SimulationStepReport {
                step_id: step.step_id.clone(),
                status: SimulatedStepStatus::Missing,
                before_snapshot_digest: before.snapshot_digest.clone(),
                after_snapshot_digest: before.snapshot_digest,
                receipt: None,
                violations,
            });
            continue;
        };

        let mut violations = validate_dependencies(step, &succeeded_steps);
        violations.extend(validate_invocation(step, invocation));
        if !violations.is_empty() {
            global_violations.extend(violations.clone());
            step_reports.push(SimulationStepReport {
                step_id: step.step_id.clone(),
                status: SimulatedStepStatus::Blocked,
                before_snapshot_digest: before.snapshot_digest.clone(),
                after_snapshot_digest: before.snapshot_digest,
                receipt: None,
                violations,
            });
            continue;
        }

        let mut operation = invocation.operation.clone();
        if let Some(fault) = &invocation.fault {
            if !apply_fault(&mut operation, fault) {
                let violations = vec![SimulationViolation::FaultNotApplicable {
                    step_id: step.step_id.clone(),
                }];
                global_violations.extend(violations.clone());
                step_reports.push(SimulationStepReport {
                    step_id: step.step_id.clone(),
                    status: SimulatedStepStatus::Blocked,
                    before_snapshot_digest: before.snapshot_digest.clone(),
                    after_snapshot_digest: before.snapshot_digest,
                    receipt: None,
                    violations,
                });
                continue;
            }
        }

        let receipt = workspace.apply_operation(operation)?;
        let status = match receipt.outcome {
            OperationOutcome::Succeeded => {
                succeeded_steps.insert(step.step_id.clone());
                SimulatedStepStatus::Succeeded
            }
            OperationOutcome::Rejected => {
                let violation = SimulationViolation::OperationRejected {
                    step_id: step.step_id.clone(),
                };
                violations.push(violation.clone());
                global_violations.push(violation);
                SimulatedStepStatus::Rejected
            }
            OperationOutcome::RolledBack => {
                let violation = SimulationViolation::OperationRolledBack {
                    step_id: step.step_id.clone(),
                };
                violations.push(violation.clone());
                global_violations.push(violation);
                SimulatedStepStatus::RolledBack
            }
        };
        step_reports.push(SimulationStepReport {
            step_id: step.step_id.clone(),
            status,
            before_snapshot_digest: receipt.before_snapshot_digest.clone(),
            after_snapshot_digest: receipt.after_snapshot_digest.clone(),
            receipt: Some(receipt),
            violations,
        });
    }

    let final_snapshot = workspace.current_snapshot()?;
    let workspace_trace_value =
        serde_json::to_value(workspace.trace()).map_err(SimulationRuntimeError::Serialization)?;
    let conforms_to_plan = global_violations.is_empty()
        && compiled_plan
            .steps
            .iter()
            .filter(|step| step.mandatory)
            .all(|step| succeeded_steps.contains(&step.step_id));
    let mut report = OperatorSimulationReport {
        schema_version: SIMULATION_REPORT_SCHEMA.to_owned(),
        simulation_id: simulation.simulation_id.clone(),
        plan_id: compiled_plan.plan_id.clone(),
        plan_digest: compiled_plan.plan_digest.clone(),
        initial_snapshot_digest: initial_snapshot.snapshot_digest,
        final_snapshot,
        steps: step_reports,
        violations: global_violations,
        conforms_to_plan,
        workspace_trace_digest: canonical_json_sha256(&workspace_trace_value)?,
        simulation_digest: String::new(),
    };
    report.simulation_digest = compute_simulation_digest(&report)?;
    Ok(report)
}

pub fn verify_simulation_digest(
    report: &OperatorSimulationReport,
) -> Result<bool, SimulationRuntimeError> {
    Ok(compute_simulation_digest(report)? == report.simulation_digest)
}

fn validate_simulation_binding(
    compiled_plan: &CompiledPlan,
    simulation: &OperatorSimulationPlan,
) -> Result<(), SimulationRuntimeError> {
    if simulation.schema_version != SIMULATION_PLAN_SCHEMA {
        return Err(SimulationRuntimeError::UnsupportedSchemaVersion {
            actual: simulation.schema_version.clone(),
            expected: SIMULATION_PLAN_SCHEMA,
        });
    }
    require_non_empty("simulation_id", &simulation.simulation_id)?;
    if simulation.plan_id != compiled_plan.plan_id {
        return Err(SimulationRuntimeError::PlanIdMismatch {
            actual: simulation.plan_id.clone(),
            expected: compiled_plan.plan_id.clone(),
        });
    }
    if simulation.plan_digest != compiled_plan.plan_digest {
        return Err(SimulationRuntimeError::PlanDigestMismatch);
    }
    Ok(())
}

fn validate_dependencies(
    step: &PlanStep,
    succeeded_steps: &BTreeSet<String>,
) -> Vec<SimulationViolation> {
    step.depends_on
        .iter()
        .filter(|dependency_id| !succeeded_steps.contains(*dependency_id))
        .map(|dependency_id| SimulationViolation::DependencyNotSucceeded {
            step_id: step.step_id.clone(),
            dependency_id: dependency_id.clone(),
        })
        .collect()
}

fn validate_invocation(
    step: &PlanStep,
    invocation: &StepInvocation,
) -> Vec<SimulationViolation> {
    let mut violations = Vec::new();
    if invocation.operator_id != step.operator_id {
        violations.push(SimulationViolation::InvocationOperatorMismatch {
            step_id: step.step_id.clone(),
            actual: invocation.operator_id.clone(),
            expected: step.operator_id.clone(),
        });
    }
    if invocation.operator_version != step.operator_version {
        violations.push(SimulationViolation::InvocationVersionMismatch {
            step_id: step.step_id.clone(),
            actual: invocation.operator_version.clone(),
            expected: step.operator_version.clone(),
        });
    }
    if invocation.operation.operator_id != step.operator_id {
        violations.push(SimulationViolation::OperationOperatorMismatch {
            step_id: step.step_id.clone(),
            actual: invocation.operation.operator_id.clone(),
            expected: step.operator_id.clone(),
        });
    }
    if !exact_identifier_set(
        &invocation.operation.declared_input_ids,
        &step.input_artifact_ids,
    ) {
        violations.push(SimulationViolation::DeclaredInputMismatch {
            step_id: step.step_id.clone(),
        });
    }
    if !exact_identifier_set(
        &invocation.operation.declared_output_ids,
        &step.output_artifact_ids,
    ) {
        violations.push(SimulationViolation::DeclaredOutputMismatch {
            step_id: step.step_id.clone(),
        });
    }
    violations
}

fn exact_identifier_set(actual: &[String], expected: &[String]) -> bool {
    let actual_set: BTreeSet<_> = actual.iter().collect();
    let expected_set: BTreeSet<_> = expected.iter().collect();
    actual.len() == actual_set.len()
        && expected.len() == expected_set.len()
        && actual_set == expected_set
}

fn apply_fault(operation: &mut TypedOperation, fault: &FaultInjection) -> bool {
    match fault {
        FaultInjection::ForcePreconditionFailure { artifact_id } => {
            operation
                .preconditions
                .push(StateCondition::ArtifactDigestEquals {
                    artifact_id: artifact_id.clone(),
                    digest: "fault-impossible-digest".to_owned(),
                });
            true
        }
        FaultInjection::ForcePostconditionFailure { artifact_id } => {
            operation
                .postconditions
                .push(StateCondition::ArtifactDigestEquals {
                    artifact_id: artifact_id.clone(),
                    digest: "fault-impossible-digest".to_owned(),
                });
            true
        }
        FaultInjection::CorruptFirstWrite {
            replacement_base64url,
        } => operation.commands.iter_mut().find_map(|command| match command {
            WorkspaceCommand::WriteArtifact {
                content_base64url,
                ..
            } => {
                *content_base64url = replacement_base64url.clone();
                Some(())
            }
            WorkspaceCommand::DeleteArtifact { .. } => None,
        }).is_some(),
    }
}

fn compute_simulation_digest(
    report: &OperatorSimulationReport,
) -> Result<String, SimulationRuntimeError> {
    let value: Value = json!({
        "schema_version": report.schema_version,
        "simulation_id": report.simulation_id,
        "plan_id": report.plan_id,
        "plan_digest": report.plan_digest,
        "initial_snapshot_digest": report.initial_snapshot_digest,
        "final_snapshot": report.final_snapshot,
        "steps": report.steps,
        "violations": report.violations,
        "conforms_to_plan": report.conforms_to_plan,
        "workspace_trace_digest": report.workspace_trace_digest,
    });
    Ok(canonical_json_sha256(&value)?)
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), SimulationRuntimeError> {
    if value.trim().is_empty() {
        Err(SimulationRuntimeError::EmptyField(field))
    } else {
        Ok(())
    }
}
