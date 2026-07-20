use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{CompiledPlan, TraceEvent, TraceStatus};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraceViolation {
    DuplicateEventId {
        event_id: String,
    },
    NonContiguousEventSequence {
        expected: usize,
        actual: usize,
    },
    UnknownStep {
        step_id: String,
    },
    OperatorMismatch {
        step_id: String,
        actual: String,
        expected: String,
    },
    DependencyIncomplete {
        step_id: String,
        dependency_id: String,
    },
    InvalidTransition {
        step_id: String,
        previous: StepState,
        event: TraceStatus,
    },
    MissingCapabilityToken {
        step_id: String,
    },
    UnauthorizedCapabilityToken {
        step_id: String,
        token_id: String,
    },
    FailedStep {
        step_id: String,
    },
    RolledBackStep {
        step_id: String,
    },
    MandatoryStepSkipped {
        step_id: String,
    },
    MandatoryStepNotSucceeded {
        step_id: String,
        final_state: StepState,
    },
    IncompleteStartedStep {
        step_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StepState {
    NotStarted,
    Started,
    Succeeded,
    Failed,
    RolledBack,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceAssessment {
    pub conforms_to_plan: bool,
    pub claimed_conforms_to_plan: bool,
    pub claim_matches: bool,
    pub violations: Vec<TraceViolation>,
}

#[must_use]
pub fn verify_trace(
    plan: &CompiledPlan,
    events: &[TraceEvent],
    claimed_conforms_to_plan: bool,
) -> TraceAssessment {
    let steps: BTreeMap<String, _> = plan
        .steps
        .iter()
        .map(|step| (step.step_id.clone(), step))
        .collect();
    let mut states: BTreeMap<String, StepState> = plan
        .steps
        .iter()
        .map(|step| (step.step_id.clone(), StepState::NotStarted))
        .collect();
    let mut event_ids = BTreeSet::new();
    let mut violations = Vec::new();

    for (expected_sequence, event) in events.iter().enumerate() {
        if !event_ids.insert(event.event_id.as_str()) {
            violations.push(TraceViolation::DuplicateEventId {
                event_id: event.event_id.clone(),
            });
        }
        if event.sequence != expected_sequence {
            violations.push(TraceViolation::NonContiguousEventSequence {
                expected: expected_sequence,
                actual: event.sequence,
            });
        }

        let Some(step) = steps.get(&event.step_id) else {
            violations.push(TraceViolation::UnknownStep {
                step_id: event.step_id.clone(),
            });
            continue;
        };
        if event.operator_id != step.operator_id {
            violations.push(TraceViolation::OperatorMismatch {
                step_id: event.step_id.clone(),
                actual: event.operator_id.clone(),
                expected: step.operator_id.clone(),
            });
        }
        validate_capability_token(step, event, &mut violations);

        let previous = states
            .get(&event.step_id)
            .copied()
            .unwrap_or(StepState::NotStarted);
        match event.status {
            TraceStatus::Started => {
                if previous != StepState::NotStarted {
                    violations.push(TraceViolation::InvalidTransition {
                        step_id: event.step_id.clone(),
                        previous,
                        event: event.status,
                    });
                }
                for dependency_id in &step.depends_on {
                    if states.get(dependency_id) != Some(&StepState::Succeeded) {
                        violations.push(TraceViolation::DependencyIncomplete {
                            step_id: event.step_id.clone(),
                            dependency_id: dependency_id.clone(),
                        });
                    }
                }
                states.insert(event.step_id.clone(), StepState::Started);
            }
            TraceStatus::Succeeded => {
                if previous != StepState::Started {
                    violations.push(TraceViolation::InvalidTransition {
                        step_id: event.step_id.clone(),
                        previous,
                        event: event.status,
                    });
                }
                states.insert(event.step_id.clone(), StepState::Succeeded);
            }
            TraceStatus::Failed => {
                if previous != StepState::Started {
                    violations.push(TraceViolation::InvalidTransition {
                        step_id: event.step_id.clone(),
                        previous,
                        event: event.status,
                    });
                }
                states.insert(event.step_id.clone(), StepState::Failed);
                violations.push(TraceViolation::FailedStep {
                    step_id: event.step_id.clone(),
                });
            }
            TraceStatus::RolledBack => {
                if previous != StepState::Failed && previous != StepState::Succeeded {
                    violations.push(TraceViolation::InvalidTransition {
                        step_id: event.step_id.clone(),
                        previous,
                        event: event.status,
                    });
                }
                states.insert(event.step_id.clone(), StepState::RolledBack);
                violations.push(TraceViolation::RolledBackStep {
                    step_id: event.step_id.clone(),
                });
            }
            TraceStatus::Skipped => {
                if previous != StepState::NotStarted {
                    violations.push(TraceViolation::InvalidTransition {
                        step_id: event.step_id.clone(),
                        previous,
                        event: event.status,
                    });
                }
                states.insert(event.step_id.clone(), StepState::Skipped);
                if step.mandatory {
                    violations.push(TraceViolation::MandatoryStepSkipped {
                        step_id: event.step_id.clone(),
                    });
                }
            }
        }
    }

    for step in &plan.steps {
        let final_state = states
            .get(&step.step_id)
            .copied()
            .unwrap_or(StepState::NotStarted);
        if final_state == StepState::Started {
            violations.push(TraceViolation::IncompleteStartedStep {
                step_id: step.step_id.clone(),
            });
        }
        if step.mandatory && final_state != StepState::Succeeded {
            violations.push(TraceViolation::MandatoryStepNotSucceeded {
                step_id: step.step_id.clone(),
                final_state,
            });
        }
    }

    let conforms_to_plan = violations.is_empty();
    TraceAssessment {
        conforms_to_plan,
        claimed_conforms_to_plan,
        claim_matches: claimed_conforms_to_plan == conforms_to_plan,
        violations,
    }
}

fn validate_capability_token(
    step: &crate::PlanStep,
    event: &TraceEvent,
    violations: &mut Vec<TraceViolation>,
) {
    match (&event.capability_token_id, step.capability_token_ids.is_empty()) {
        (None, false) => violations.push(TraceViolation::MissingCapabilityToken {
            step_id: step.step_id.clone(),
        }),
        (Some(token_id), _) if !step.capability_token_ids.contains(token_id) => {
            violations.push(TraceViolation::UnauthorizedCapabilityToken {
                step_id: step.step_id.clone(),
                token_id: token_id.clone(),
            });
        }
        _ => {}
    }
}
