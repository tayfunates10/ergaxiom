#![forbid(unsafe_code)]

mod compiler;
mod model;
mod runtime;

pub use compiler::{CompiledContract, ContractCompileError, compile_contract};
pub use model::{
    ContractAcceptance, ContractPermission, ContractProofObligation, ContractRequirements,
    HardConstraint, JobTypeDefinition, PermissionAccess, ProfessionCapsule, ProfessionPolicies,
    ProfessionReference, UnknownRequirement, UnknownResolution, ValidatorDefinition, WorkContract,
};
pub use runtime::{ContractRuntimeError, ContractSession};
