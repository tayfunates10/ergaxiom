use std::collections::BTreeSet;

use ergaxiom_proof_kernel::{
    AcceptancePolicy, AssuranceLevel, ContractSeal, DecisionReason, DecisionStatus, EvidenceRecord,
    IndependenceClass, KernelError, ObligationState, ProofKernel, ProofObligationRequirement,
    TruthValue,
};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

fn seal() -> ContractSeal {
    ContractSeal {
        contract_digest: "contract-sha256".to_owned(),
        capsule_digest: "capsule-sha256".to_owned(),
        schema_version: "0.2.0".to_owned(),
    }
}

fn assurance(value: u8) -> AssuranceLevel {
    match value % 6 {
        0 => AssuranceLevel::E0,
        1 => AssuranceLevel::E1,
        2 => AssuranceLevel::E2,
        3 => AssuranceLevel::E3,
        4 => AssuranceLevel::E4,
        _ => AssuranceLevel::E5,
    }
}

fn independence(value: u8) -> IndependenceClass {
    match value % 3 {
        0 => IndependenceClass::Executor,
        1 => IndependenceClass::Independent,
        _ => IndependenceClass::Diverse,
    }
}

fn truth(value: u8) -> TruthValue {
    match value % 3 {
        0 => TruthValue::True,
        1 => TruthValue::False,
        _ => TruthValue::Unknown,
    }
}

fn requirement(
    index: usize,
    mandatory: bool,
    required_independence: IndependenceClass,
) -> ProofObligationRequirement {
    ProofObligationRequirement {
        obligation_id: format!("proof.{index}"),
        constraint_id: format!("constraint.{index}"),
        mandatory,
        required_independence,
    }
}

fn evidence(
    obligation_index: usize,
    evidence_index: usize,
    validator_slot: u8,
    result: TruthValue,
    evidence_independence: IndependenceClass,
    contract_digest: &str,
) -> EvidenceRecord {
    EvidenceRecord {
        evidence_id: format!("evidence.{obligation_index}.{evidence_index}"),
        obligation_id: format!("proof.{obligation_index}"),
        constraint_id: format!("constraint.{obligation_index}"),
        contract_digest: contract_digest.to_owned(),
        subject_digest: format!("subject.{obligation_index}"),
        validator_id: format!("validator.{}", validator_slot % 5),
        validator_version: "1.0.0".to_owned(),
        result,
        independence: evidence_independence,
        observed_at: "2026-07-21T10:00:00Z".to_owned(),
    }
}

fn build_kernel(
    requirements: Vec<ProofObligationRequirement>,
    unknowns: usize,
    minimum: AssuranceLevel,
    actual: AssuranceLevel,
) -> Result<ProofKernel, KernelError> {
    ProofKernel::new(
        seal(),
        AcceptancePolicy::strict(minimum),
        unknowns,
        actual,
        requirements,
    )
}

fn obligation_scenarios()
-> impl Strategy<Value = Vec<(u8, Vec<(u8, u8, u8)>)>> {
    prop::collection::vec(
        (
            0_u8..3,
            prop::collection::vec((0_u8..3, 0_u8..3, 0_u8..8), 0..5),
        ),
        1..9,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn acceptance_is_equivalent_to_all_fail_closed_conditions(
        scenarios in obligation_scenarios(),
        unknowns in 0_usize..4,
        minimum_value in 0_u8..6,
        actual_value in 0_u8..6,
    ) {
        let minimum = assurance(minimum_value);
        let actual = assurance(actual_value);
        let requirements = scenarios
            .iter()
            .enumerate()
            .map(|(index, (required, _))| requirement(index, true, independence(*required)))
            .collect();
        let mut kernel = match build_kernel(requirements, unknowns, minimum, actual) {
            Ok(kernel) => kernel,
            Err(error) => return Err(TestCaseError::fail(format!("valid kernel rejected: {error}"))),
        };

        for (obligation_index, (_, records)) in scenarios.iter().enumerate() {
            for (evidence_index, (result, evidence_class, validator_slot)) in records.iter().enumerate() {
                let ingestion = kernel.ingest_evidence(evidence(
                    obligation_index,
                    evidence_index,
                    *validator_slot,
                    truth(*result),
                    independence(*evidence_class),
                    "contract-sha256",
                ));
                prop_assert!(ingestion.is_ok(), "valid evidence ingestion failed: {ingestion:?}");
            }
        }

        let decision = kernel.evaluate();
        let every_mandatory_proof_satisfied = decision
            .obligation_reports
            .iter()
            .filter(|report| report.mandatory)
            .all(|report| report.state == ObligationState::Satisfied);
        let should_accept = unknowns == 0 && actual >= minimum && every_mandatory_proof_satisfied;

        prop_assert_eq!(decision.status == DecisionStatus::Accepted, should_accept);
        if decision.status == DecisionStatus::Accepted {
            prop_assert!(decision.reasons.is_empty());
            prop_assert!(decision.obligation_reports.iter().all(|report| {
                !report.mandatory || report.state == ObligationState::Satisfied
            }));
        }
    }

    #[test]
    fn one_missing_mandatory_proof_can_never_be_accepted(
        obligation_count in 1_usize..16,
        missing_seed in any::<usize>(),
    ) {
        let missing_index = missing_seed % obligation_count;
        let requirements = (0..obligation_count)
            .map(|index| requirement(index, true, IndependenceClass::Independent))
            .collect();
        let mut kernel = match build_kernel(
            requirements,
            0,
            AssuranceLevel::E0,
            AssuranceLevel::E5,
        ) {
            Ok(kernel) => kernel,
            Err(error) => return Err(TestCaseError::fail(format!("valid kernel rejected: {error}"))),
        };

        for index in 0..obligation_count {
            if index == missing_index {
                continue;
            }
            let ingestion = kernel.ingest_evidence(evidence(
                index,
                0,
                index as u8,
                TruthValue::True,
                IndependenceClass::Independent,
                "contract-sha256",
            ));
            prop_assert!(ingestion.is_ok());
        }

        let decision = kernel.evaluate();
        prop_assert_ne!(decision.status, DecisionStatus::Accepted);
        prop_assert!(decision.reasons.contains(&DecisionReason::MandatoryProofPending {
            obligation_id: format!("proof.{missing_index}"),
        }));
    }

    #[test]
    fn diverse_proof_accepts_only_two_distinct_independent_validators(
        validator_slots in prop::collection::vec(0_u8..5, 0..12),
    ) {
        let mut kernel = match build_kernel(
            vec![requirement(0, true, IndependenceClass::Diverse)],
            0,
            AssuranceLevel::E0,
            AssuranceLevel::E5,
        ) {
            Ok(kernel) => kernel,
            Err(error) => return Err(TestCaseError::fail(format!("valid kernel rejected: {error}"))),
        };

        for (index, validator_slot) in validator_slots.iter().enumerate() {
            let ingestion = kernel.ingest_evidence(evidence(
                0,
                index,
                *validator_slot,
                TruthValue::True,
                IndependenceClass::Independent,
                "contract-sha256",
            ));
            prop_assert!(ingestion.is_ok());
        }

        let distinct_validators = validator_slots
            .iter()
            .map(|slot| slot % 5)
            .collect::<BTreeSet<_>>()
            .len();
        let decision = kernel.evaluate();
        prop_assert_eq!(
            decision.status == DecisionStatus::Accepted,
            distinct_validators >= 2,
        );
    }

    #[test]
    fn any_false_mandatory_evidence_forces_rejection(
        true_evidence_count in 0_usize..8,
        false_validator_slot in 0_u8..5,
    ) {
        let mut kernel = match build_kernel(
            vec![requirement(0, true, IndependenceClass::Independent)],
            0,
            AssuranceLevel::E0,
            AssuranceLevel::E5,
        ) {
            Ok(kernel) => kernel,
            Err(error) => return Err(TestCaseError::fail(format!("valid kernel rejected: {error}"))),
        };

        for index in 0..true_evidence_count {
            let ingestion = kernel.ingest_evidence(evidence(
                0,
                index,
                index as u8,
                TruthValue::True,
                IndependenceClass::Independent,
                "contract-sha256",
            ));
            prop_assert!(ingestion.is_ok());
        }
        let false_ingestion = kernel.ingest_evidence(evidence(
            0,
            true_evidence_count,
            false_validator_slot,
            TruthValue::False,
            IndependenceClass::Independent,
            "contract-sha256",
        ));
        prop_assert!(false_ingestion.is_ok());

        let decision = kernel.evaluate();
        prop_assert_eq!(decision.status, DecisionStatus::Rejected);
        prop_assert!(decision.obligation_reports[0].state == ObligationState::Failed
            || decision.obligation_reports[0].state == ObligationState::Invalidated);
    }

    #[test]
    fn unresolved_unknowns_block_otherwise_complete_work(unknowns in 1_usize..32) {
        let mut kernel = match build_kernel(
            vec![requirement(0, true, IndependenceClass::Independent)],
            unknowns,
            AssuranceLevel::E0,
            AssuranceLevel::E5,
        ) {
            Ok(kernel) => kernel,
            Err(error) => return Err(TestCaseError::fail(format!("valid kernel rejected: {error}"))),
        };
        let ingestion = kernel.ingest_evidence(evidence(
            0,
            0,
            0,
            TruthValue::True,
            IndependenceClass::Independent,
            "contract-sha256",
        ));
        prop_assert!(ingestion.is_ok());

        let decision = kernel.evaluate();
        prop_assert_eq!(decision.status, DecisionStatus::Blocked);
        prop_assert!(decision.reasons.contains(&DecisionReason::UnresolvedUnknowns {
            count: unknowns,
        }));
    }

    #[test]
    fn assurance_below_policy_minimum_blocks_complete_work(
        minimum_value in 1_u8..6,
        actual_seed in any::<u8>(),
    ) {
        let minimum_rank = minimum_value % 6;
        prop_assume!(minimum_rank > 0);
        let actual_rank = actual_seed % minimum_rank;
        let minimum = assurance(minimum_rank);
        let actual = assurance(actual_rank);
        let mut kernel = match build_kernel(
            vec![requirement(0, true, IndependenceClass::Independent)],
            0,
            minimum,
            actual,
        ) {
            Ok(kernel) => kernel,
            Err(error) => return Err(TestCaseError::fail(format!("valid kernel rejected: {error}"))),
        };
        let ingestion = kernel.ingest_evidence(evidence(
            0,
            0,
            0,
            TruthValue::True,
            IndependenceClass::Independent,
            "contract-sha256",
        ));
        prop_assert!(ingestion.is_ok());

        let decision = kernel.evaluate();
        prop_assert_eq!(decision.status, DecisionStatus::Blocked);
        prop_assert!(decision.reasons.contains(&DecisionReason::AssuranceBelowMinimum {
            actual,
            required: minimum,
        }));
    }

    #[test]
    fn evidence_bound_to_a_mutated_contract_is_rejected_without_state_change(
        mutation_suffix in "[a-z0-9]{1,16}",
    ) {
        let mut kernel = match build_kernel(
            vec![requirement(0, true, IndependenceClass::Independent)],
            0,
            AssuranceLevel::E0,
            AssuranceLevel::E5,
        ) {
            Ok(kernel) => kernel,
            Err(error) => return Err(TestCaseError::fail(format!("valid kernel rejected: {error}"))),
        };
        let before = kernel.obligation_reports();
        let result = kernel.ingest_evidence(evidence(
            0,
            0,
            0,
            TruthValue::True,
            IndependenceClass::Independent,
            &format!("contract-sha256-{mutation_suffix}"),
        ));

        prop_assert_eq!(result, Err(KernelError::ContractDigestMismatch));
        prop_assert_eq!(kernel.obligation_reports(), before);
        prop_assert_ne!(kernel.evaluate().status, DecisionStatus::Accepted);
    }

    #[test]
    fn optional_only_contracts_never_produce_acceptance(optional_count in 0_usize..12) {
        let requirements = (0..optional_count)
            .map(|index| requirement(index, false, IndependenceClass::Executor))
            .collect();
        let mut kernel = match build_kernel(
            requirements,
            0,
            AssuranceLevel::E0,
            AssuranceLevel::E5,
        ) {
            Ok(kernel) => kernel,
            Err(error) => return Err(TestCaseError::fail(format!("valid kernel rejected: {error}"))),
        };

        for index in 0..optional_count {
            let ingestion = kernel.ingest_evidence(evidence(
                index,
                0,
                index as u8,
                TruthValue::True,
                IndependenceClass::Executor,
                "contract-sha256",
            ));
            prop_assert!(ingestion.is_ok());
        }

        let decision = kernel.evaluate();
        prop_assert_eq!(decision.status, DecisionStatus::Blocked);
        prop_assert!(decision.reasons.contains(&DecisionReason::NoMandatoryObligations));
    }
}
