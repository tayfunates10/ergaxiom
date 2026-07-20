use std::collections::{BTreeMap, BTreeSet};

use ergaxiom_proof_kernel::{
    AcceptancePolicy, AssuranceLevel, ContractSeal, HashingError, IndependenceClass,
    ProofObligationRequirement, canonical_json_sha256,
};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    ContractProofObligation, JobTypeDefinition, ProfessionCapsule, UnknownResolution,
    ValidatorDefinition, WorkContract,
};

const SUPPORTED_CONTRACT_SCHEMA: &str = "0.2.0";
const SUPPORTED_CAPSULE_SCHEMA: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum ContractCompileError {
    #[error("failed to decode Work Contract: {0}")]
    ContractDecode(#[source] serde_json::Error),
    #[error("failed to decode Profession Capsule: {0}")]
    CapsuleDecode(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("unsupported {document} schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        document: &'static str,
        actual: String,
        expected: &'static str,
    },
    #[error("contract capsule ID {contract} does not match loaded capsule {capsule}")]
    CapsuleIdMismatch { contract: String, capsule: String },
    #[error("contract capsule version {contract} does not match loaded capsule {capsule}")]
    CapsuleVersionMismatch { contract: String, capsule: String },
    #[error("duplicate {kind} identifier: {id}")]
    DuplicateIdentifier { kind: &'static str, id: String },
    #[error("empty {kind} identifier")]
    EmptyIdentifier { kind: &'static str },
    #[error("unsupported job type: {0}")]
    UnsupportedJobType(String),
    #[error("required constraint is missing from the contract: {0}")]
    MissingRequiredConstraint(String),
    #[error("job-type constraint is not mandatory: {0}")]
    RequiredConstraintNotMandatory(String),
    #[error("proof obligation {obligation_id} references unknown constraint {constraint_id}")]
    UnknownConstraint {
        obligation_id: String,
        constraint_id: String,
    },
    #[error("proof obligation {0} has no validator")]
    EmptyValidatorSet(String),
    #[error("proof obligation {obligation_id} repeats validator {validator_id}")]
    DuplicateObligationValidator {
        obligation_id: String,
        validator_id: String,
    },
    #[error("proof obligation {obligation_id} references unknown validator {validator_id}")]
    UnknownValidator {
        obligation_id: String,
        validator_id: String,
    },
    #[error("validator {validator_id} does not support constraint {constraint_id}")]
    ValidatorClaimMismatch {
        validator_id: String,
        constraint_id: String,
    },
    #[error("proof obligation {obligation_id} does not meet {required:?} independence")]
    InsufficientValidatorIndependence {
        obligation_id: String,
        required: IndependenceClass,
    },
    #[error("proof obligation {obligation_id} declares unsupported evidence type {evidence_type}")]
    UnsupportedEvidenceType {
        obligation_id: String,
        evidence_type: String,
    },
    #[error("mandatory constraint has no mandatory proof obligation: {0}")]
    MissingMandatoryProof(String),
    #[error("contract has no mandatory proof obligations")]
    NoMandatoryProofObligations,
    #[error("unsafe acceptance policy: {0}")]
    UnsafeAcceptancePolicy(&'static str),
    #[error("contract assurance {contract:?} is below capsule minimum {capsule:?}")]
    AssuranceBelowCapsule {
        contract: AssuranceLevel,
        capsule: AssuranceLevel,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatorBinding {
    pub version: String,
    pub independence: IndependenceClass,
}

#[derive(Debug, Clone)]
pub struct CompiledContract {
    pub contract_id: String,
    pub job_type: String,
    pub seal: ContractSeal,
    pub policy: AcceptancePolicy,
    pub minimum_assurance_level: AssuranceLevel,
    pub unresolved_mandatory_unknowns: usize,
    pub proof_requirements: Vec<ProofObligationRequirement>,
    pub(crate) validator_bindings: BTreeMap<String, BTreeMap<String, ValidatorBinding>>,
}

impl CompiledContract {
    #[must_use]
    pub fn proof_obligation_count(&self) -> usize {
        self.proof_requirements.len()
    }
}

pub fn compile_contract(
    contract_value: &Value,
    capsule_value: &Value,
) -> Result<CompiledContract, ContractCompileError> {
    let contract: WorkContract = serde_json::from_value(contract_value.clone())
        .map_err(ContractCompileError::ContractDecode)?;
    let capsule: ProfessionCapsule = serde_json::from_value(capsule_value.clone())
        .map_err(ContractCompileError::CapsuleDecode)?;

    validate_schema_versions(&contract, &capsule)?;
    validate_capsule_binding(&contract, &capsule)?;
    validate_acceptance_policy(&contract)?;

    let job_types = index_job_types(&capsule.job_types)?;
    let validators = index_validators(&capsule.validators)?;
    let constraints = index_constraints(&contract)?;
    let obligations = index_obligations(&contract.proof_obligations)?;

    let job_type = job_types
        .get(contract.job_type.as_str())
        .ok_or_else(|| ContractCompileError::UnsupportedJobType(contract.job_type.clone()))?;

    validate_required_constraints(job_type, &constraints)?;

    let mut proof_requirements = Vec::with_capacity(obligations.len());
    let mut validator_bindings = BTreeMap::new();
    let mut proven_mandatory_constraints = BTreeSet::new();
    let mut mandatory_obligation_count = 0_usize;

    for obligation in obligations.values() {
        let constraint = constraints.get(obligation.constraint_id.as_str()).ok_or_else(|| {
            ContractCompileError::UnknownConstraint {
                obligation_id: obligation.id.clone(),
                constraint_id: obligation.constraint_id.clone(),
            }
        })?;

        let bindings = validate_obligation(obligation, &validators)?;
        validator_bindings.insert(obligation.id.clone(), bindings);

        if obligation.mandatory {
            mandatory_obligation_count += 1;
            if constraint.mandatory {
                proven_mandatory_constraints.insert(obligation.constraint_id.as_str());
            }
        }

        proof_requirements.push(ProofObligationRequirement {
            obligation_id: obligation.id.clone(),
            constraint_id: obligation.constraint_id.clone(),
            mandatory: obligation.mandatory,
            required_independence: obligation.independence_class,
        });
    }

    if mandatory_obligation_count == 0 {
        return Err(ContractCompileError::NoMandatoryProofObligations);
    }

    for (constraint_id, constraint) in &constraints {
        if constraint.mandatory && !proven_mandatory_constraints.contains(constraint_id) {
            return Err(ContractCompileError::MissingMandatoryProof(
                (*constraint_id).to_owned(),
            ));
        }
    }

    let capsule_minimum = capsule
        .policies
        .minimum_assurance_by_job_type
        .get(&contract.job_type)
        .copied()
        .unwrap_or(job_type.minimum_assurance_level);
    let contract_minimum = contract.acceptance.minimum_assurance_level;
    if contract_minimum < capsule_minimum {
        return Err(ContractCompileError::AssuranceBelowCapsule {
            contract: contract_minimum,
            capsule: capsule_minimum,
        });
    }

    let unresolved_mandatory_unknowns = contract
        .requirements
        .unknowns
        .iter()
        .filter(|unknown| {
            unknown.mandatory && unknown.resolution == UnknownResolution::Unresolved
        })
        .count();

    proof_requirements.sort_by(|left, right| left.obligation_id.cmp(&right.obligation_id));

    Ok(CompiledContract {
        contract_id: contract.contract_id,
        job_type: contract.job_type,
        seal: ContractSeal {
            contract_digest: canonical_json_sha256(contract_value)?,
            capsule_digest: canonical_json_sha256(capsule_value)?,
            schema_version: contract.schema_version,
        },
        policy: AcceptancePolicy {
            minimum_assurance_level: contract_minimum,
            unknowns_must_be_empty: contract.acceptance.unknowns_must_be_empty,
            all_mandatory_proofs_must_pass: contract
                .acceptance
                .all_mandatory_proofs_must_pass,
            validator_conflicts_allowed: contract.acceptance.validator_conflicts_allowed,
        },
        minimum_assurance_level: contract_minimum,
        unresolved_mandatory_unknowns,
        proof_requirements,
        validator_bindings,
    })
}

fn validate_schema_versions(
    contract: &WorkContract,
    capsule: &ProfessionCapsule,
) -> Result<(), ContractCompileError> {
    if contract.schema_version != SUPPORTED_CONTRACT_SCHEMA {
        return Err(ContractCompileError::UnsupportedSchemaVersion {
            document: "Work Contract",
            actual: contract.schema_version.clone(),
            expected: SUPPORTED_CONTRACT_SCHEMA,
        });
    }
    if capsule.schema_version != SUPPORTED_CAPSULE_SCHEMA {
        return Err(ContractCompileError::UnsupportedSchemaVersion {
            document: "Profession Capsule",
            actual: capsule.schema_version.clone(),
            expected: SUPPORTED_CAPSULE_SCHEMA,
        });
    }
    Ok(())
}

fn validate_capsule_binding(
    contract: &WorkContract,
    capsule: &ProfessionCapsule,
) -> Result<(), ContractCompileError> {
    if contract.profession.capsule_id != capsule.capsule_id {
        return Err(ContractCompileError::CapsuleIdMismatch {
            contract: contract.profession.capsule_id.clone(),
            capsule: capsule.capsule_id.clone(),
        });
    }
    if contract.profession.capsule_version != capsule.version {
        return Err(ContractCompileError::CapsuleVersionMismatch {
            contract: contract.profession.capsule_version.clone(),
            capsule: capsule.version.clone(),
        });
    }
    Ok(())
}

fn validate_acceptance_policy(contract: &WorkContract) -> Result<(), ContractCompileError> {
    if !contract.acceptance.unknowns_must_be_empty {
        return Err(ContractCompileError::UnsafeAcceptancePolicy(
            "unresolved unknowns must block acceptance",
        ));
    }
    if !contract.acceptance.all_mandatory_proofs_must_pass {
        return Err(ContractCompileError::UnsafeAcceptancePolicy(
            "all mandatory proofs must pass",
        ));
    }
    if contract.acceptance.validator_conflicts_allowed {
        return Err(ContractCompileError::UnsafeAcceptancePolicy(
            "validator conflicts cannot be accepted",
        ));
    }
    Ok(())
}

fn validate_required_constraints(
    job_type: &JobTypeDefinition,
    constraints: &BTreeMap<&str, &crate::model::HardConstraint>,
) -> Result<(), ContractCompileError> {
    for required in &job_type.required_constraints {
        let Some(constraint) = constraints.get(required.as_str()) else {
            return Err(ContractCompileError::MissingRequiredConstraint(
                required.clone(),
            ));
        };
        if !constraint.mandatory {
            return Err(ContractCompileError::RequiredConstraintNotMandatory(
                required.clone(),
            ));
        }
    }
    Ok(())
}

fn validate_obligation(
    obligation: &ContractProofObligation,
    validators: &BTreeMap<&str, &ValidatorDefinition>,
) -> Result<BTreeMap<String, ValidatorBinding>, ContractCompileError> {
    if obligation.validator_ids.is_empty() {
        return Err(ContractCompileError::EmptyValidatorSet(
            obligation.id.clone(),
        ));
    }

    let mut selected = BTreeMap::new();
    let mut supported_evidence_types = BTreeSet::new();
    let mut independent_validator_count = 0_usize;

    for validator_id in &obligation.validator_ids {
        if selected.contains_key(validator_id) {
            return Err(ContractCompileError::DuplicateObligationValidator {
                obligation_id: obligation.id.clone(),
                validator_id: validator_id.clone(),
            });
        }

        let validator = validators.get(validator_id.as_str()).ok_or_else(|| {
            ContractCompileError::UnknownValidator {
                obligation_id: obligation.id.clone(),
                validator_id: validator_id.clone(),
            }
        })?;

        if !validator.claims.iter().any(|claim| claim == &obligation.constraint_id) {
            return Err(ContractCompileError::ValidatorClaimMismatch {
                validator_id: validator_id.clone(),
                constraint_id: obligation.constraint_id.clone(),
            });
        }

        if validator.independence_class >= IndependenceClass::Independent {
            independent_validator_count += 1;
        }
        supported_evidence_types.extend(validator.evidence_types.iter().cloned());
        selected.insert(
            validator_id.clone(),
            ValidatorBinding {
                version: validator.version.clone(),
                independence: validator.independence_class,
            },
        );
    }

    let independence_satisfied = match obligation.independence_class {
        IndependenceClass::Executor => !selected.is_empty(),
        IndependenceClass::Independent => independent_validator_count >= 1,
        IndependenceClass::Diverse => independent_validator_count >= 2,
    };
    if !independence_satisfied {
        return Err(ContractCompileError::InsufficientValidatorIndependence {
            obligation_id: obligation.id.clone(),
            required: obligation.independence_class,
        });
    }

    for evidence_type in &obligation.evidence_types {
        if !supported_evidence_types.contains(evidence_type) {
            return Err(ContractCompileError::UnsupportedEvidenceType {
                obligation_id: obligation.id.clone(),
                evidence_type: evidence_type.clone(),
            });
        }
    }

    Ok(selected)
}

fn index_job_types(
    values: &[JobTypeDefinition],
) -> Result<BTreeMap<&str, &JobTypeDefinition>, ContractCompileError> {
    index_by_id(values, "job type", |value| value.id.as_str())
}

fn index_validators(
    values: &[ValidatorDefinition],
) -> Result<BTreeMap<&str, &ValidatorDefinition>, ContractCompileError> {
    index_by_id(values, "validator", |value| value.id.as_str())
}

fn index_constraints(
    contract: &WorkContract,
) -> Result<BTreeMap<&str, &crate::model::HardConstraint>, ContractCompileError> {
    index_by_id(&contract.requirements.hard, "constraint", |value| {
        value.id.as_str()
    })
}

fn index_obligations(
    values: &[ContractProofObligation],
) -> Result<BTreeMap<&str, &ContractProofObligation>, ContractCompileError> {
    index_by_id(values, "proof obligation", |value| value.id.as_str())
}

fn index_by_id<'a, T, F>(
    values: &'a [T],
    kind: &'static str,
    id: F,
) -> Result<BTreeMap<&'a str, &'a T>, ContractCompileError>
where
    F: Fn(&'a T) -> &'a str,
{
    let mut index = BTreeMap::new();
    for value in values {
        let identifier = id(value);
        if identifier.trim().is_empty() {
            return Err(ContractCompileError::EmptyIdentifier { kind });
        }
        if index.insert(identifier, value).is_some() {
            return Err(ContractCompileError::DuplicateIdentifier {
                kind,
                id: identifier.to_owned(),
            });
        }
    }
    Ok(index)
}
