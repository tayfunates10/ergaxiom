use ergaxiom_proof_kernel::{
    AcceptanceDecision, AssuranceLevel, EvidenceRecord, KernelError, ObligationState, ProofKernel,
};
use thiserror::Error;

use crate::CompiledContract;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractRuntimeError {
    #[error("evidence references unknown proof obligation {0}")]
    UnknownObligation(String),
    #[error("validator {validator_id} is not authorized for obligation {obligation_id}")]
    UnauthorizedValidator {
        obligation_id: String,
        validator_id: String,
    },
    #[error(
        "validator {validator_id} version {actual} does not match capsule version {expected}"
    )]
    ValidatorVersionMismatch {
        validator_id: String,
        actual: String,
        expected: String,
    },
    #[error(
        "validator {validator_id} independence {actual:?} does not match capsule class {expected:?}"
    )]
    ValidatorIndependenceMismatch {
        validator_id: String,
        actual: ergaxiom_proof_kernel::IndependenceClass,
        expected: ergaxiom_proof_kernel::IndependenceClass,
    },
    #[error(transparent)]
    Kernel(#[from] KernelError),
}

#[derive(Debug, Clone)]
pub struct ContractSession {
    compiled: CompiledContract,
    kernel: ProofKernel,
}

impl ContractSession {
    pub fn new(
        compiled: CompiledContract,
        achieved_assurance_level: AssuranceLevel,
    ) -> Result<Self, ContractRuntimeError> {
        let kernel = ProofKernel::new(
            compiled.seal.clone(),
            compiled.policy,
            compiled.unresolved_mandatory_unknowns,
            achieved_assurance_level,
            compiled.proof_requirements.clone(),
        )?;

        Ok(Self { compiled, kernel })
    }

    pub fn ingest_evidence(
        &mut self,
        evidence: EvidenceRecord,
    ) -> Result<ObligationState, ContractRuntimeError> {
        let validators = self
            .compiled
            .validator_bindings
            .get(&evidence.obligation_id)
            .ok_or_else(|| {
                ContractRuntimeError::UnknownObligation(evidence.obligation_id.clone())
            })?;
        let binding = validators.get(&evidence.validator_id).ok_or_else(|| {
            ContractRuntimeError::UnauthorizedValidator {
                obligation_id: evidence.obligation_id.clone(),
                validator_id: evidence.validator_id.clone(),
            }
        })?;

        if evidence.validator_version != binding.version {
            return Err(ContractRuntimeError::ValidatorVersionMismatch {
                validator_id: evidence.validator_id,
                actual: evidence.validator_version,
                expected: binding.version.clone(),
            });
        }
        if evidence.independence != binding.independence {
            return Err(ContractRuntimeError::ValidatorIndependenceMismatch {
                validator_id: evidence.validator_id,
                actual: evidence.independence,
                expected: binding.independence,
            });
        }

        Ok(self.kernel.ingest_evidence(evidence)?)
    }

    #[must_use]
    pub fn evaluate(&self) -> AcceptanceDecision {
        self.kernel.evaluate()
    }

    #[must_use]
    pub const fn compiled_contract(&self) -> &CompiledContract {
        &self.compiled
    }
}
