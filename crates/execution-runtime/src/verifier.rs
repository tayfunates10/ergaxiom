use std::collections::{BTreeMap, BTreeSet};

use ergaxiom_capability_runtime::AuthorizationReceipt;
use ergaxiom_operator_plan_runtime::{CompiledPlan, TraceStatus, verify_trace};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use thiserror::Error;

use crate::model::{
    AuthorizationTraceViolation, AuthorizedExecutionTrace, ExecutionTraceAssessment,
};

const SUPPORTED_EXECUTION_TRACE_SCHEMA: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum ExecutionRuntimeError {
    #[error("unsupported authorized-execution-trace schema {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        actual: String,
        expected: &'static str,
    },
    #[error("execution trace plan ID {actual} does not match compiled plan {expected}")]
    PlanIdMismatch { actual: String, expected: String },
    #[error("execution trace plan digest does not match the compiled plan")]
    PlanDigestMismatch,
    #[error("failed to serialize authorization receipt: {0}")]
    ReceiptSerialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn verify_authorized_trace(
    plan: &CompiledPlan,
    trace: &AuthorizedExecutionTrace,
) -> Result<ExecutionTraceAssessment, ExecutionRuntimeError> {
    validate_trace_binding(plan, trace)?;

    let mut violations = Vec::new();
    let mut receipts: BTreeMap<String, &AuthorizationReceipt> = BTreeMap::new();

    for record in &trace.authorization_receipts {
        let receipt_value = serde_json::to_value(&record.receipt)
            .map_err(ExecutionRuntimeError::ReceiptSerialization)?;
        let actual_digest = canonical_json_sha256(&receipt_value)?;
        if actual_digest != record.receipt_digest {
            violations.push(AuthorizationTraceViolation::ReceiptDigestMismatch {
                declared: record.receipt_digest.clone(),
                actual: actual_digest,
            });
            continue;
        }
        if receipts
            .insert(record.receipt_digest.clone(), &record.receipt)
            .is_some()
        {
            violations.push(AuthorizationTraceViolation::DuplicateReceiptDigest {
                receipt_digest: record.receipt_digest.clone(),
            });
        }
        if record.receipt.use_number == 0
            || record.receipt.max_uses == 0
            || record.receipt.use_number > record.receipt.max_uses
        {
            violations.push(AuthorizationTraceViolation::InvalidReceiptUseNumber {
                receipt_digest: record.receipt_digest.clone(),
                use_number: record.receipt.use_number,
                max_uses: record.receipt.max_uses,
            });
        }
        if record.receipt.contract_digest != plan.contract_digest {
            violations.push(AuthorizationTraceViolation::ReceiptContractDigestMismatch {
                receipt_digest: record.receipt_digest.clone(),
            });
        }
        if record.receipt.capsule_digest != plan.capsule_digest {
            violations.push(AuthorizationTraceViolation::ReceiptCapsuleDigestMismatch {
                receipt_digest: record.receipt_digest.clone(),
            });
        }
        if record.receipt.plan_id != plan.plan_id {
            violations.push(AuthorizationTraceViolation::ReceiptPlanIdMismatch {
                receipt_digest: record.receipt_digest.clone(),
                actual: record.receipt.plan_id.clone(),
                expected: plan.plan_id.clone(),
            });
        }
        if record.receipt.plan_digest != plan.plan_digest {
            violations.push(AuthorizationTraceViolation::ReceiptPlanDigestMismatch {
                receipt_digest: record.receipt_digest.clone(),
            });
        }
    }

    let steps: BTreeMap<_, _> = plan
        .steps
        .iter()
        .map(|step| (step.step_id.as_str(), step))
        .collect();
    let mut used_receipts = BTreeSet::new();
    let mut step_receipts: BTreeMap<String, String> = BTreeMap::new();
    let mut receipt_steps: BTreeMap<String, String> = BTreeMap::new();

    for bound_event in &trace.events {
        let event = &bound_event.event;
        let Some(step) = steps.get(event.step_id.as_str()) else {
            continue;
        };
        let authorization_required =
            !step.capability_token_ids.is_empty() && event.status != TraceStatus::Skipped;

        let Some(receipt_digest) = bound_event.authorization_receipt_digest.as_ref() else {
            if authorization_required {
                violations.push(AuthorizationTraceViolation::MissingAuthorizationReceipt {
                    event_id: event.event_id.clone(),
                    step_id: event.step_id.clone(),
                });
            }
            continue;
        };

        if !authorization_required {
            violations.push(
                AuthorizationTraceViolation::UnexpectedAuthorizationReceipt {
                    event_id: event.event_id.clone(),
                    step_id: event.step_id.clone(),
                },
            );
            continue;
        }

        let Some(receipt) = receipts.get(receipt_digest) else {
            violations.push(AuthorizationTraceViolation::UnknownAuthorizationReceipt {
                event_id: event.event_id.clone(),
                receipt_digest: receipt_digest.clone(),
            });
            continue;
        };
        used_receipts.insert(receipt_digest.clone());

        if receipt.step_id != event.step_id {
            violations.push(AuthorizationTraceViolation::ReceiptStepMismatch {
                event_id: event.event_id.clone(),
                actual: receipt.step_id.clone(),
                expected: event.step_id.clone(),
            });
        }
        if receipt.operator_id != event.operator_id {
            violations.push(AuthorizationTraceViolation::ReceiptOperatorMismatch {
                event_id: event.event_id.clone(),
                actual: receipt.operator_id.clone(),
                expected: event.operator_id.clone(),
            });
        }
        if let Some(event_token_id) = event.capability_token_id.as_ref() {
            if receipt.token_id != *event_token_id {
                violations.push(AuthorizationTraceViolation::ReceiptTokenMismatch {
                    event_id: event.event_id.clone(),
                    actual: receipt.token_id.clone(),
                    expected: event_token_id.clone(),
                });
            }
        }

        if let Some(first_digest) = step_receipts.get(&event.step_id) {
            if first_digest != receipt_digest {
                violations.push(AuthorizationTraceViolation::InconsistentStepReceipt {
                    step_id: event.step_id.clone(),
                    first_digest: first_digest.clone(),
                    later_digest: receipt_digest.clone(),
                });
            }
        } else {
            step_receipts.insert(event.step_id.clone(), receipt_digest.clone());
        }

        if let Some(first_step_id) = receipt_steps.get(receipt_digest) {
            if first_step_id != &event.step_id {
                violations.push(AuthorizationTraceViolation::ReceiptReusedAcrossSteps {
                    receipt_digest: receipt_digest.clone(),
                    first_step_id: first_step_id.clone(),
                    later_step_id: event.step_id.clone(),
                });
            }
        } else {
            receipt_steps.insert(receipt_digest.clone(), event.step_id.clone());
        }
    }

    for receipt_digest in receipts.keys() {
        if !used_receipts.contains(receipt_digest) {
            violations.push(AuthorizationTraceViolation::UnusedAuthorizationReceipt {
                receipt_digest: receipt_digest.clone(),
            });
        }
    }

    let events: Vec<_> = trace
        .events
        .iter()
        .map(|bound_event| bound_event.event.clone())
        .collect();
    let plan_trace = verify_trace(plan, &events, trace.claimed_conforms_to_authorized_plan);
    let conforms_to_authorized_plan = plan_trace.conforms_to_plan && violations.is_empty();

    Ok(ExecutionTraceAssessment {
        trace_id: trace.trace_id.clone(),
        conforms_to_authorized_plan,
        claimed_conforms_to_authorized_plan: trace.claimed_conforms_to_authorized_plan,
        claim_matches: trace.claimed_conforms_to_authorized_plan == conforms_to_authorized_plan,
        plan_trace,
        authorization_violations: violations,
    })
}

fn validate_trace_binding(
    plan: &CompiledPlan,
    trace: &AuthorizedExecutionTrace,
) -> Result<(), ExecutionRuntimeError> {
    if trace.schema_version != SUPPORTED_EXECUTION_TRACE_SCHEMA {
        return Err(ExecutionRuntimeError::UnsupportedSchemaVersion {
            actual: trace.schema_version.clone(),
            expected: SUPPORTED_EXECUTION_TRACE_SCHEMA,
        });
    }
    if trace.plan_id != plan.plan_id {
        return Err(ExecutionRuntimeError::PlanIdMismatch {
            actual: trace.plan_id.clone(),
            expected: plan.plan_id.clone(),
        });
    }
    if trace.plan_digest != plan.plan_digest {
        return Err(ExecutionRuntimeError::PlanDigestMismatch);
    }
    Ok(())
}
