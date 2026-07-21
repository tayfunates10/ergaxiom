#![forbid(unsafe_code)]

mod model;
mod runtime;
mod verifier;

pub use model::{
    ObservedWindowsState, SignedWindowsBridgeRecord, VerifiedWindowsBridgeRecord,
    WindowsAdapterTransition, WindowsApplicationIdentity, WindowsBridgeAction,
    WindowsBridgePackage, WindowsBridgeRecordPayload, WindowsBridgeRequest, WindowsBridgeSignature,
    WindowsBridgeSignatureAlgorithm, WindowsBridgeSignatureEncoding, WindowsBridgeStatus,
    WindowsBridgeViolation, WindowsControlMethod, WindowsStateAssertion, WindowsTargetSelector,
};
pub use runtime::{
    WindowsBridgeAdapter, WindowsBridgeError, WindowsBridgeExecutionContext,
    execute_windows_bridge, seal_observed_state,
};
pub use verifier::{
    WindowsBridgeKeyRegistry, WindowsBridgeVerifyError, verify_windows_bridge_package,
};
