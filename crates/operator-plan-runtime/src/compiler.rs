use std::collections::{BTreeMap, BTreeSet};

use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde_json::Value;
use thiserror::Error;

use crate::model::{CapsulePlanView, OperatorPlan, PlanStep};

const SUPPORTED_PLAN_SCHEMA: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum PlanCompileError {
    #[error("failed to decode Operator Plan: {0}")]
    PlanDecode(#[source] serde_json::Error),
    #[error("failed to decode operator registry from Profession Capsule: {0}")]
    CapsuleDecode(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("unsupported Operator Plan schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        actual: String,
        expected: &'static str,
    },
    #[error("binding {0} must use sha256")]
    UnsupportedBindingAlgorithm(&'static str),
    #[error("plan contract ID {actual} does not match compiled contract {expected}")]
    ContractIdMismatch { actual: String, expected: String },
    #[error("plan contract digest does not match compiled contract")]
    ContractDigestMismatch,
    #[error("plan capsule ID {actual} does not match loaded capsule {expected}")]
    CapsuleIdMismatch { actual: String, expected: String },
    #[error("plan capsule digest does not match compiled capsule")]
    CapsuleDigestMismatch,
    #[error("unsupported job type in capsule: {0}")]
    UnsupportedJobType(String),
    #[error("duplicate {kind} identifier: {id}")]
    DuplicateIdentifier { kind: &'static str, id: String },
    #[error("duplicate plan sequence: {0}")]
    DuplicateSequence(usize),
    #[error("plan sequence is not contiguous: expected {expected}, found {actual}")]
    NonContiguousSequence { expected: usize, actual: usize },
    #[error("step {step_id} uses operator {operator_id} outside the job-type allowlist")]
    OperatorNotAllowed {
        step_id: String,
        operator_id: String,
    },
    #[error("step {step_id} references unknown operator {operator_id}")]
    UnknownOperator {
        step_id: String,
        operator_id: String,
    },
    #[error("step {step_id} operator version {actual} does not match capsule version {expected}")]
    OperatorVersionMismatch {
        step_id: String,
        actual: String,
        expected: String,
    },
    #[error("step {step_id} references unknown dependency {dependency_id}")]
    UnknownDependency {
        step_id: String,
        dependency_id: String,
    },
    #[error("step {step_id} dependency {dependency_id} is not earlier in the plan")]
    DependencyNotEarlier {
        step_id: String,
        dependency_id: String,
    },
    #[error("step {step_id} references unknown rollback step {rollback_step_id}")]
    UnknownRollbackStep {
        step_id: String,
        rollback_step_id: String,
    },
    #[error("step {step_id} repeats {field} value {value}")]
    DuplicateStepValue {
        step_id: String,
        field: &'static str,
        value: String,
    },
    #[error("operator plan contains no mandatory step")]
    NoMandatorySteps,
}

#[derive(Debug, Clone)]
pub struct CompiledPlan {
    pub plan_id: String,
    pub plan_digest: String,
    pub contract_digest: String,
    pub capsule_digest: String,
    pub steps: Vec<PlanStep>,
}

impl CompiledPlan {
    #[must_use]
    pub fn mandatory_step_count(&self) -> usize {
        self.steps.iter().filter(|step| step.mandatory).count()
    }
}

pub fn compile_plan(
    plan_value: &Value,
    capsule_value: &Value,
    compiled_contract: &CompiledContract,
) -> Result<CompiledPlan, PlanCompileError> {
    let plan: OperatorPlan =
        serde_json::from_value(plan_value.clone()).map_err(PlanCompileError::PlanDecode)?;
    let capsule: CapsulePlanView =
        serde_json::from_value(capsule_value.clone()).map_err(PlanCompileError::CapsuleDecode)?;

    if plan.schema_version != SUPPORTED_PLAN_SCHEMA {
        return Err(PlanCompileError::UnsupportedSchemaVersion {
            actual: plan.schema_version,
            expected: SUPPORTED_PLAN_SCHEMA,
        });
    }
    validate_bindings(&plan, &capsule, compiled_contract)?;

    let operators = index_operators(&capsule)?;
    let job_type = capsule
        .job_types
        .iter()
        .find(|job_type| job_type.id == compiled_contract.job_type)
        .ok_or_else(|| PlanCompileError::UnsupportedJobType(compiled_contract.job_type.clone()))?;
    let allowed_operators: BTreeSet<_> = job_type.operator_ids.iter().map(String::as_str).collect();

    let mut step_ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut sequences = BTreeSet::new();
    for step in &plan.steps {
        if step_ids
            .insert(step.step_id.clone(), step.sequence)
            .is_some()
        {
            return Err(PlanCompileError::DuplicateIdentifier {
                kind: "step",
                id: step.step_id.clone(),
            });
        }
        if !sequences.insert(step.sequence) {
            return Err(PlanCompileError::DuplicateSequence(step.sequence));
        }
        validate_unique_step_values(step)?;
    }

    let OperatorPlan {
        plan_id,
        mut steps,
        ..
    } = plan;
    steps.sort_by_key(|step| step.sequence);
    for (expected, step) in steps.iter().enumerate() {
        if step.sequence != expected {
            return Err(PlanCompileError::NonContiguousSequence {
                expected,
                actual: step.sequence,
            });
        }
        if !allowed_operators.contains(step.operator_id.as_str()) {
            return Err(PlanCompileError::OperatorNotAllowed {
                step_id: step.step_id.clone(),
                operator_id: step.operator_id.clone(),
            });
        }
        let operator = operators.get(step.operator_id.as_str()).ok_or_else(|| {
            PlanCompileError::UnknownOperator {
                step_id: step.step_id.clone(),
                operator_id: step.operator_id.clone(),
            }
        })?;
        if step.operator_version != operator.version {
            return Err(PlanCompileError::OperatorVersionMismatch {
                step_id: step.step_id.clone(),
                actual: step.operator_version.clone(),
                expected: operator.version.clone(),
            });
        }
        for dependency_id in &step.depends_on {
            let dependency_sequence =
                step_ids
                    .get(dependency_id)
                    .ok_or_else(|| PlanCompileError::UnknownDependency {
                        step_id: step.step_id.clone(),
                        dependency_id: dependency_id.clone(),
                    })?;
            if *dependency_sequence >= step.sequence {
                return Err(PlanCompileError::DependencyNotEarlier {
                    step_id: step.step_id.clone(),
                    dependency_id: dependency_id.clone(),
                });
            }
        }
        if let Some(rollback_step_id) = &step.rollback_step_id {
            if !step_ids.contains_key(rollback_step_id) {
                return Err(PlanCompileError::UnknownRollbackStep {
                    step_id: step.step_id.clone(),
                    rollback_step_id: rollback_step_id.clone(),
                });
            }
        }
    }

    if !steps.iter().any(|step| step.mandatory) {
        return Err(PlanCompileError::NoMandatorySteps);
    }

    Ok(CompiledPlan {
        plan_id,
        plan_digest: canonical_json_sha256(plan_value)?,
        contract_digest: compiled_contract.seal.contract_digest.clone(),
        capsule_digest: compiled_contract.seal.capsule_digest.clone(),
        steps,
    })
}

fn validate_bindings(
    plan: &OperatorPlan,
    capsule: &CapsulePlanView,
    compiled_contract: &CompiledContract,
) -> Result<(), PlanCompileError> {
    if plan.bindings.contract.algorithm != "sha256" {
        return Err(PlanCompileError::UnsupportedBindingAlgorithm("contract"));
    }
    if plan.bindings.profession_capsule.algorithm != "sha256" {
        return Err(PlanCompileError::UnsupportedBindingAlgorithm(
            "profession_capsule",
        ));
    }
    if plan.bindings.contract.id != compiled_contract.contract_id {
        return Err(PlanCompileError::ContractIdMismatch {
            actual: plan.bindings.contract.id.clone(),
            expected: compiled_contract.contract_id.clone(),
        });
    }
    if plan.bindings.contract.digest != compiled_contract.seal.contract_digest {
        return Err(PlanCompileError::ContractDigestMismatch);
    }
    if plan.bindings.profession_capsule.id != capsule.capsule_id {
        return Err(PlanCompileError::CapsuleIdMismatch {
            actual: plan.bindings.profession_capsule.id.clone(),
            expected: capsule.capsule_id.clone(),
        });
    }
    if plan.bindings.profession_capsule.digest != compiled_contract.seal.capsule_digest {
        return Err(PlanCompileError::CapsuleDigestMismatch);
    }
    Ok(())
}

fn index_operators(
    capsule: &CapsulePlanView,
) -> Result<BTreeMap<&str, &crate::model::CapsuleOperator>, PlanCompileError> {
    let mut index = BTreeMap::new();
    for operator in &capsule.operators {
        if index.insert(operator.id.as_str(), operator).is_some() {
            return Err(PlanCompileError::DuplicateIdentifier {
                kind: "operator",
                id: operator.id.clone(),
            });
        }
    }
    Ok(index)
}

fn validate_unique_step_values(step: &PlanStep) -> Result<(), PlanCompileError> {
    validate_unique_values(step, "depends_on", &step.depends_on)?;
    validate_unique_values(step, "input_artifact_ids", &step.input_artifact_ids)?;
    validate_unique_values(step, "output_artifact_ids", &step.output_artifact_ids)?;
    validate_unique_values(step, "capability_token_ids", &step.capability_token_ids)
}

fn validate_unique_values(
    step: &PlanStep,
    field: &'static str,
    values: &[String],
) -> Result<(), PlanCompileError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(PlanCompileError::DuplicateStepValue {
                step_id: step.step_id.clone(),
                field,
                value: value.clone(),
            });
        }
    }
    Ok(())
}
