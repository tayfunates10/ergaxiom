#![forbid(unsafe_code)]

mod model;
mod simulator;

pub use model::{
    FaultInjection, OperatorSimulationPlan, OperatorSimulationReport, SimulatedStepStatus,
    SimulationStepReport, SimulationViolation, StepInvocation,
};
pub use simulator::{SimulationRuntimeError, simulate_operator_plan, verify_simulation_digest};
