#![forbid(unsafe_code)]

mod model;
mod verifier;

pub use model::{
    AuthorizationReceiptRecord, AuthorizationTraceViolation, AuthorizedExecutionTrace,
    ExecutionTraceAssessment, ReceiptBoundTraceEvent,
};
pub use verifier::{ExecutionRuntimeError, verify_authorized_trace};
