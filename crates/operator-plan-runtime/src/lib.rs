#![forbid(unsafe_code)]

mod compiler;
mod model;
mod trace;

pub use compiler::{CompiledPlan, PlanCompileError, compile_plan};
pub use model::{DigestReference, OperatorPlan, PlanBindings, PlanStep, TraceEvent, TraceStatus};
pub use trace::{StepState, TraceAssessment, TraceViolation, verify_trace};
