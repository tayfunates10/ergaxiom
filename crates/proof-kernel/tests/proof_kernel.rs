use std::error::Error;

use ergaxiom_proof_kernel::{
    AcceptancePolicy, AssuranceLevel, ContractSeal, DecisionReason, DecisionStatus, EvidenceRecord,
    IndependenceClass, KernelError, ObligationState, ProofKernel, ProofObligationRequirement,
    TruthValue, canonical_json_sha256,
};
use serde_json::json;

fn seal() -> ContractSeal {
    ContractSeal {
        contract_digest: "contract-sha256".to_owned(),
        capsule_digest: "capsule-sha256".to_owned(),
        schema_version: "0.1.0".to_owned(),
    }
}

fn requirement(independence: IndependenceClass) -> ProofObligationRequirement {
    ProofObligationRequirement {
        obligation_id: "proof.canvas.width".to_owned(),
        constraint_id: "constraint.canvas.width".to_owned(),
        mandatory: true,
        required_independence: independence,
    }
}

fn evidence(
    evidence_id: &str,
    validator_id: &str,
    result: TruthValue,
    independence: IndependenceClass,
) -> EvidenceRecord {
    EvidenceRecord {
        evidence_id: evidence_id.to_owned(),
        obligation_id: "proof.canvas.width".to_owned(),
        constraint_id: "constraint.canvas.width".to_owned(),
        contract_digest: "contract-sha256".to_owned(),
        subject_digest: "output-sha256".to_owned(),
        validator_id: validator_id.to_owned(),
        validator_version: "1.0.0".to_owned(),
        result,
        independence,
        observed_at: "2026-07-20T20:30:00Z".to_owned(),
    }
}

#[test]
fn strong_kleene_truth_tables_preserve_unknown() {
    assert_eq!(TruthValue::Unknown.not(), TruthValue::Unknown);
    assert_eq!(
        TruthValue::True.and(TruthValue::Unknown),
        TruthValue::Unknown
    );
    assert_eq!(
        TruthValue::False.and(TruthValue::Unknown),
        TruthValue::False
    );
    assert_eq!(TruthValue::True.or(TruthValue::Unknown), TruthValue::True);
    assert_eq!(
        TruthValue::False.or(TruthValue::Unknown),
        TruthValue::Unknown
    );
}

#[test]
fn canonical_hash_is_independent_of_object_key_order() -> Result<(), Box<dyn Error>> {
    let left = json!({"b": 2, "a": {"y": 4, "x": 3}});
    let right = json!({"a": {"x": 3, "y": 4}, "b": 2});

    assert_eq!(
        canonical_json_sha256(&left)?,
        canonical_json_sha256(&right)?
    );
    Ok(())
}

#[test]
fn canonical_hash_changes_when_contract_content_changes() -> Result<(), Box<dyn Error>> {
    let original = json!({"width": 1080, "height": 1350});
    let modified = json!({"width": 1081, "height": 1350});

    assert_ne!(
        canonical_json_sha256(&original)?,
        canonical_json_sha256(&modified)?
    );
    Ok(())
}

#[test]
fn unresolved_contract_unknown_blocks_acceptance() -> Result<(), Box<dyn Error>> {
    let mut kernel = ProofKernel::new(
        seal(),
        AcceptancePolicy::strict(AssuranceLevel::E2),
        1,
        AssuranceLevel::E2,
        [requirement(IndependenceClass::Independent)],
    )?;
    kernel.ingest_evidence(evidence(
        "evidence-1",
        "validator-a",
        TruthValue::True,
        IndependenceClass::Independent,
    ))?;

    let decision = kernel.evaluate();
    assert_eq!(decision.status, DecisionStatus::Blocked);
    assert!(
        decision
            .reasons
            .contains(&DecisionReason::UnresolvedUnknowns { count: 1 })
    );
    Ok(())
}

#[test]
fn missing_mandatory_evidence_blocks_acceptance() -> Result<(), Box<dyn Error>> {
    let kernel = ProofKernel::new(
        seal(),
        AcceptancePolicy::strict(AssuranceLevel::E2),
        0,
        AssuranceLevel::E2,
        [requirement(IndependenceClass::Independent)],
    )?;

    let decision = kernel.evaluate();
    assert_eq!(decision.status, DecisionStatus::Blocked);
    assert!(
        decision
            .reasons
            .contains(&DecisionReason::MandatoryProofPending {
                obligation_id: "proof.canvas.width".to_owned()
            })
    );
    Ok(())
}

#[test]
fn false_mandatory_evidence_rejects_work() -> Result<(), Box<dyn Error>> {
    let mut kernel = ProofKernel::new(
        seal(),
        AcceptancePolicy::strict(AssuranceLevel::E2),
        0,
        AssuranceLevel::E2,
        [requirement(IndependenceClass::Independent)],
    )?;
    kernel.ingest_evidence(evidence(
        "evidence-1",
        "validator-a",
        TruthValue::False,
        IndependenceClass::Independent,
    ))?;

    let decision = kernel.evaluate();
    assert_eq!(decision.status, DecisionStatus::Rejected);
    assert_eq!(
        decision.obligation_reports[0].state,
        ObligationState::Failed
    );
    Ok(())
}

#[test]
fn complete_independent_evidence_accepts_work() -> Result<(), Box<dyn Error>> {
    let mut kernel = ProofKernel::new(
        seal(),
        AcceptancePolicy::strict(AssuranceLevel::E2),
        0,
        AssuranceLevel::E2,
        [requirement(IndependenceClass::Independent)],
    )?;
    kernel.ingest_evidence(evidence(
        "evidence-1",
        "validator-a",
        TruthValue::True,
        IndependenceClass::Independent,
    ))?;

    let decision = kernel.evaluate();
    assert_eq!(decision.status, DecisionStatus::Accepted);
    assert!(decision.reasons.is_empty());
    Ok(())
}

#[test]
fn diverse_proof_requires_two_distinct_independent_validators() -> Result<(), Box<dyn Error>> {
    let mut kernel = ProofKernel::new(
        seal(),
        AcceptancePolicy::strict(AssuranceLevel::E4),
        0,
        AssuranceLevel::E4,
        [requirement(IndependenceClass::Diverse)],
    )?;

    let state = kernel.ingest_evidence(evidence(
        "evidence-1",
        "validator-a",
        TruthValue::True,
        IndependenceClass::Independent,
    ))?;
    assert_eq!(state, ObligationState::Indeterminate);
    assert_eq!(kernel.evaluate().status, DecisionStatus::Blocked);

    let state = kernel.ingest_evidence(evidence(
        "evidence-2",
        "validator-b",
        TruthValue::True,
        IndependenceClass::Independent,
    ))?;
    assert_eq!(state, ObligationState::Satisfied);
    assert_eq!(kernel.evaluate().status, DecisionStatus::Accepted);
    Ok(())
}

#[test]
fn contradictory_validator_results_invalidate_the_obligation() -> Result<(), Box<dyn Error>> {
    let mut kernel = ProofKernel::new(
        seal(),
        AcceptancePolicy::strict(AssuranceLevel::E4),
        0,
        AssuranceLevel::E4,
        [requirement(IndependenceClass::Diverse)],
    )?;
    kernel.ingest_evidence(evidence(
        "evidence-1",
        "validator-a",
        TruthValue::True,
        IndependenceClass::Independent,
    ))?;
    let state = kernel.ingest_evidence(evidence(
        "evidence-2",
        "validator-b",
        TruthValue::False,
        IndependenceClass::Independent,
    ))?;

    assert_eq!(state, ObligationState::Invalidated);
    assert_eq!(kernel.evaluate().status, DecisionStatus::Rejected);
    Ok(())
}

#[test]
fn evidence_for_another_contract_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut kernel = ProofKernel::new(
        seal(),
        AcceptancePolicy::strict(AssuranceLevel::E2),
        0,
        AssuranceLevel::E2,
        [requirement(IndependenceClass::Independent)],
    )?;
    let mut stale = evidence(
        "evidence-1",
        "validator-a",
        TruthValue::True,
        IndependenceClass::Independent,
    );
    stale.contract_digest = "another-contract".to_owned();

    assert_eq!(
        kernel.ingest_evidence(stale),
        Err(KernelError::ContractDigestMismatch)
    );
    Ok(())
}

#[test]
fn unsafe_policy_cannot_disable_fail_closed_invariants() {
    let unsafe_policy = AcceptancePolicy {
        minimum_assurance_level: AssuranceLevel::E0,
        unknowns_must_be_empty: false,
        all_mandatory_proofs_must_pass: true,
        validator_conflicts_allowed: false,
    };

    assert!(matches!(
        ProofKernel::new(
            seal(),
            unsafe_policy,
            0,
            AssuranceLevel::E0,
            [requirement(IndependenceClass::Executor)]
        ),
        Err(KernelError::UnsafePolicy(_))
    ));
}
