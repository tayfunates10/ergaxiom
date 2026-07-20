use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::{
    AcceptanceDecision, AcceptancePolicy, AssuranceLevel, ContractSeal, DecisionReason,
    DecisionStatus, EvidenceRecord, IndependenceClass, ObligationReport, ObligationState,
    ProofObligationRequirement, TruthValue,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KernelError {
    #[error("{field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("duplicate proof obligation: {0}")]
    DuplicateObligation(String),
    #[error("unknown proof obligation: {0}")]
    UnknownObligation(String),
    #[error("duplicate evidence record: {0}")]
    DuplicateEvidence(String),
    #[error("evidence contract digest does not match the sealed contract")]
    ContractDigestMismatch,
    #[error("evidence constraint does not match its proof obligation")]
    ConstraintMismatch,
    #[error("unsafe acceptance policy: {0}")]
    UnsafePolicy(&'static str),
}

#[derive(Debug, Clone)]
struct ObligationAccumulator {
    requirement: ProofObligationRequirement,
    evidence: Vec<EvidenceRecord>,
}

/// Deterministic acceptance engine for proof-carrying professional work.
#[derive(Debug, Clone)]
pub struct ProofKernel {
    seal: ContractSeal,
    policy: AcceptancePolicy,
    declared_unknowns: usize,
    assurance_level: AssuranceLevel,
    obligations: BTreeMap<String, ObligationAccumulator>,
    evidence_ids: BTreeSet<String>,
}

impl ProofKernel {
    /// Creates a kernel with immutable contract/capsule bindings.
    pub fn new(
        seal: ContractSeal,
        policy: AcceptancePolicy,
        declared_unknowns: usize,
        assurance_level: AssuranceLevel,
        requirements: impl IntoIterator<Item = ProofObligationRequirement>,
    ) -> Result<Self, KernelError> {
        require_non_empty("contract_digest", &seal.contract_digest)?;
        require_non_empty("capsule_digest", &seal.capsule_digest)?;
        require_non_empty("schema_version", &seal.schema_version)?;
        validate_policy(policy)?;

        let mut obligations = BTreeMap::new();
        for requirement in requirements {
            require_non_empty("obligation_id", &requirement.obligation_id)?;
            require_non_empty("constraint_id", &requirement.constraint_id)?;
            let key = requirement.obligation_id.clone();
            if obligations
                .insert(
                    key.clone(),
                    ObligationAccumulator {
                        requirement,
                        evidence: Vec::new(),
                    },
                )
                .is_some()
            {
                return Err(KernelError::DuplicateObligation(key));
            }
        }

        Ok(Self {
            seal,
            policy,
            declared_unknowns,
            assurance_level,
            obligations,
            evidence_ids: BTreeSet::new(),
        })
    }

    /// Adds immutable evidence after checking its contract and obligation bindings.
    pub fn ingest_evidence(
        &mut self,
        evidence: EvidenceRecord,
    ) -> Result<ObligationState, KernelError> {
        validate_evidence_fields(&evidence)?;

        if self.evidence_ids.contains(&evidence.evidence_id) {
            return Err(KernelError::DuplicateEvidence(evidence.evidence_id));
        }
        if evidence.contract_digest != self.seal.contract_digest {
            return Err(KernelError::ContractDigestMismatch);
        }

        let Some(requirement) = self
            .obligations
            .get(&evidence.obligation_id)
            .map(|entry| entry.requirement.clone())
        else {
            return Err(KernelError::UnknownObligation(evidence.obligation_id));
        };

        if evidence.constraint_id != requirement.constraint_id {
            return Err(KernelError::ConstraintMismatch);
        }

        self.evidence_ids.insert(evidence.evidence_id.clone());
        let Some(accumulator) = self.obligations.get_mut(&evidence.obligation_id) else {
            return Err(KernelError::UnknownObligation(evidence.obligation_id));
        };
        accumulator.evidence.push(evidence);
        Ok(state_for(accumulator))
    }

    /// Updates the externally established assurance level.
    pub const fn set_assurance_level(&mut self, assurance_level: AssuranceLevel) {
        self.assurance_level = assurance_level;
    }

    /// Updates the number of unresolved contract unknowns.
    pub const fn set_declared_unknowns(&mut self, declared_unknowns: usize) {
        self.declared_unknowns = declared_unknowns;
    }

    /// Evaluates all mandatory proof obligations without model judgement.
    #[must_use]
    pub fn evaluate(&self) -> AcceptanceDecision {
        let reports = self.obligation_reports();
        let mandatory_reports: Vec<_> = reports.iter().filter(|report| report.mandatory).collect();
        let mut reasons = Vec::new();
        let mut rejected = false;

        if mandatory_reports.is_empty() {
            reasons.push(DecisionReason::NoMandatoryObligations);
        }
        if self.policy.unknowns_must_be_empty && self.declared_unknowns > 0 {
            reasons.push(DecisionReason::UnresolvedUnknowns {
                count: self.declared_unknowns,
            });
        }
        if self.assurance_level < self.policy.minimum_assurance_level {
            reasons.push(DecisionReason::AssuranceBelowMinimum {
                actual: self.assurance_level,
                required: self.policy.minimum_assurance_level,
            });
        }

        for report in mandatory_reports {
            match report.state {
                ObligationState::Pending => reasons.push(DecisionReason::MandatoryProofPending {
                    obligation_id: report.obligation_id.clone(),
                }),
                ObligationState::Indeterminate => {
                    reasons.push(DecisionReason::MandatoryProofIndeterminate {
                        obligation_id: report.obligation_id.clone(),
                    });
                }
                ObligationState::Failed => {
                    rejected = true;
                    reasons.push(DecisionReason::MandatoryProofFailed {
                        obligation_id: report.obligation_id.clone(),
                    });
                }
                ObligationState::Invalidated => {
                    rejected = true;
                    reasons.push(DecisionReason::MandatoryProofInvalidated {
                        obligation_id: report.obligation_id.clone(),
                    });
                }
                ObligationState::Satisfied => {}
            }
        }

        let status = if rejected {
            DecisionStatus::Rejected
        } else if reasons.is_empty() {
            DecisionStatus::Accepted
        } else {
            DecisionStatus::Blocked
        };

        AcceptanceDecision {
            status,
            reasons,
            contract_digest: self.seal.contract_digest.clone(),
            assurance_level: self.assurance_level,
            obligation_reports: reports,
        }
    }

    /// Returns a stable, obligation-id ordered report.
    #[must_use]
    pub fn obligation_reports(&self) -> Vec<ObligationReport> {
        self.obligations
            .values()
            .map(|accumulator| {
                let evidence_ids = accumulator
                    .evidence
                    .iter()
                    .map(|evidence| evidence.evidence_id.clone())
                    .collect();
                let validator_ids = accumulator
                    .evidence
                    .iter()
                    .map(|evidence| evidence.validator_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();

                ObligationReport {
                    obligation_id: accumulator.requirement.obligation_id.clone(),
                    constraint_id: accumulator.requirement.constraint_id.clone(),
                    mandatory: accumulator.requirement.mandatory,
                    required_independence: accumulator.requirement.required_independence,
                    state: state_for(accumulator),
                    evidence_ids,
                    validator_ids,
                }
            })
            .collect()
    }
}

fn validate_policy(policy: AcceptancePolicy) -> Result<(), KernelError> {
    if !policy.unknowns_must_be_empty {
        return Err(KernelError::UnsafePolicy(
            "unresolved unknowns must block acceptance",
        ));
    }
    if !policy.all_mandatory_proofs_must_pass {
        return Err(KernelError::UnsafePolicy("all mandatory proofs must pass"));
    }
    if policy.validator_conflicts_allowed {
        return Err(KernelError::UnsafePolicy(
            "validator conflicts cannot be accepted",
        ));
    }
    Ok(())
}

fn validate_evidence_fields(evidence: &EvidenceRecord) -> Result<(), KernelError> {
    require_non_empty("evidence_id", &evidence.evidence_id)?;
    require_non_empty("obligation_id", &evidence.obligation_id)?;
    require_non_empty("constraint_id", &evidence.constraint_id)?;
    require_non_empty("contract_digest", &evidence.contract_digest)?;
    require_non_empty("subject_digest", &evidence.subject_digest)?;
    require_non_empty("validator_id", &evidence.validator_id)?;
    require_non_empty("validator_version", &evidence.validator_version)?;
    require_non_empty("observed_at", &evidence.observed_at)
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), KernelError> {
    if value.trim().is_empty() {
        Err(KernelError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn state_for(accumulator: &ObligationAccumulator) -> ObligationState {
    if accumulator.evidence.is_empty() {
        return ObligationState::Pending;
    }

    let has_true = accumulator
        .evidence
        .iter()
        .any(|evidence| evidence.result == TruthValue::True);
    let has_false = accumulator
        .evidence
        .iter()
        .any(|evidence| evidence.result == TruthValue::False);
    let has_unknown = accumulator
        .evidence
        .iter()
        .any(|evidence| evidence.result == TruthValue::Unknown);

    if has_true && has_false {
        return ObligationState::Invalidated;
    }
    if has_false {
        return ObligationState::Failed;
    }
    if !has_true && has_unknown {
        return ObligationState::Indeterminate;
    }

    let satisfied = match accumulator.requirement.required_independence {
        IndependenceClass::Executor => has_true,
        IndependenceClass::Independent => accumulator.evidence.iter().any(|evidence| {
            evidence.result == TruthValue::True
                && evidence.independence >= IndependenceClass::Independent
        }),
        IndependenceClass::Diverse => {
            accumulator
                .evidence
                .iter()
                .filter(|evidence| {
                    evidence.result == TruthValue::True
                        && evidence.independence >= IndependenceClass::Independent
                })
                .map(|evidence| evidence.validator_id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                >= 2
        }
    };

    if satisfied {
        ObligationState::Satisfied
    } else {
        ObligationState::Indeterminate
    }
}
