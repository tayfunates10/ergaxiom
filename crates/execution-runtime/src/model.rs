use ergaxiom_capability_runtime::AuthorizationReceipt;
use ergaxiom_operator_plan_runtime::{TraceAssessment, TraceEvent};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedExecutionTrace {
    pub schema_version: String,
    pub trace_id: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub claimed_conforms_to_authorized_plan: bool,
    pub authorization_receipts: Vec<AuthorizationReceiptRecord>,
    pub events: Vec<ReceiptBoundTraceEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationReceiptRecord {
    pub receipt_digest: String,
    pub receipt: AuthorizationReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBoundTraceEvent {
    pub event: TraceEvent,
    pub authorization_receipt_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorizationTraceViolation {
    DuplicateReceiptDigest {
        receipt_digest: String,
    },
    ReceiptDigestMismatch {
        declared: String,
        actual: String,
    },
    InvalidReceiptUseNumber {
        receipt_digest: String,
        use_number: u32,
        max_uses: u32,
    },
    MissingAuthorizationReceipt {
        event_id: String,
        step_id: String,
    },
    UnexpectedAuthorizationReceipt {
        event_id: String,
        step_id: String,
    },
    UnknownAuthorizationReceipt {
        event_id: String,
        receipt_digest: String,
    },
    UnusedAuthorizationReceipt {
        receipt_digest: String,
    },
    ReceiptContractDigestMismatch {
        receipt_digest: String,
    },
    ReceiptCapsuleDigestMismatch {
        receipt_digest: String,
    },
    ReceiptPlanIdMismatch {
        receipt_digest: String,
        actual: String,
        expected: String,
    },
    ReceiptPlanDigestMismatch {
        receipt_digest: String,
    },
    ReceiptStepMismatch {
        event_id: String,
        actual: String,
        expected: String,
    },
    ReceiptOperatorMismatch {
        event_id: String,
        actual: String,
        expected: String,
    },
    ReceiptTokenMismatch {
        event_id: String,
        actual: String,
        expected: String,
    },
    InconsistentStepReceipt {
        step_id: String,
        first_digest: String,
        later_digest: String,
    },
    ReceiptReusedAcrossSteps {
        receipt_digest: String,
        first_step_id: String,
        later_step_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionTraceAssessment {
    pub trace_id: String,
    pub conforms_to_authorized_plan: bool,
    pub claimed_conforms_to_authorized_plan: bool,
    pub claim_matches: bool,
    pub plan_trace: TraceAssessment,
    pub authorization_violations: Vec<AuthorizationTraceViolation>,
}
