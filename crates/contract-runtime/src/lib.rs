#![forbid(unsafe_code)]

mod compiler;
mod model;
mod runtime;

pub use compiler::{CompiledContract, ContractCompileError, compile_contract};
pub use model::{
    ContractAcceptance, ContractProofObligation, ContractRequirements, HardConstraint,
    JobTypeDefinition, ProfessionCapsule, ProfessionPolicies, ProfessionReference,
    UnknownRequirement, UnknownResolution, ValidatorDefinition, WorkContract,
};
pub use runtime::{ContractRuntimeError, ContractSession};
