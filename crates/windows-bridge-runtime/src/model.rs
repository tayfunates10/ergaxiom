use std::collections::BTreeMap;

use ergaxiom_capability_runtime::CapabilityGrant;
use ergaxiom_execution_runtime::AuthorizationReceiptRecord;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WindowsControlMethod {
    NativeModel,
    ApplicationApi,
    SignedPlugin,
    Cli,
    UiAutomation,
    Accessibility,
    VisuallyConfirmed,
    CoordinateFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsApplicationIdentity {
    pub application_id: String,
    pub version: String,
    pub executable_digest: String,
    pub instance_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "selector", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WindowsTargetSelector {
    NativeObject {
        object_id: String,
    },
    ApplicationObject {
        object_id: String,
    },
    PluginObject {
        plugin_id: String,
        object_id: String,
    },
    CliEndpoint {
        executable_id: String,
    },
    UiAutomation {
        automation_id: String,
        control_type: String,
    },
    Accessibility {
        role: String,
        name: String,
    },
    VisualRegion {
        region_id: String,
    },
    Coordinates {
        x: i32,
        y: i32,
        confirmation_region_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WindowsBridgeAction {
    SetValue {
        value: String,
    },
    Invoke,
    Select {
        option_id: String,
    },
    Export {
        destination_artifact_id: String,
        media_type: String,
    },
    RunCli {
        executable_digest: String,
        arguments: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "assertion", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WindowsStateAssertion {
    PropertyEquals {
        key: String,
        value: String,
    },
    ArtifactDigestEquals {
        artifact_id: String,
        digest: String,
    },
    TargetStableIdEquals {
        stable_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsBridgeRequest {
    pub schema_version: String,
    pub request_id: String,
    pub bridge_id: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub step_id: String,
    pub operator_id: String,
    pub executor_id: String,
    pub device_id: Option<String>,
    pub control_method: WindowsControlMethod,
    pub application: WindowsApplicationIdentity,
    pub selector: WindowsTargetSelector,
    pub action: WindowsBridgeAction,
    pub required_grant: CapabilityGrant,
    pub expected_pre_state_digest: String,
    pub postconditions: Vec<WindowsStateAssertion>,
    pub authorization_receipt_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedWindowsState {
    pub application: WindowsApplicationIdentity,
    pub target_stable_id: String,
    pub properties: BTreeMap<String, String>,
    pub artifact_digests: BTreeMap<String, String>,
    pub observed_at_epoch_ms: u64,
    pub state_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsAdapterTransition {
    pub consumed_pre_state_digest: String,
    pub adapter_event_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WindowsBridgeStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WindowsBridgeViolation {
    PostconditionFailed {
        index: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsBridgeRecordPayload {
    pub schema_version: String,
    pub record_id: String,
    pub bridge_id: String,
    pub request_digest: String,
    pub authorization_receipt_digest: String,
    pub pre_state_digest: String,
    pub consumed_pre_state_digest: String,
    pub post_state_digest: String,
    pub adapter_event_digest: String,
    pub status: WindowsBridgeStatus,
    pub violations: Vec<WindowsBridgeViolation>,
    pub recorded_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowsBridgeSignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowsBridgeSignatureEncoding {
    Base64url,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsBridgeSignature {
    pub issuer_id: String,
    pub key_id: String,
    pub algorithm: WindowsBridgeSignatureAlgorithm,
    pub encoding: WindowsBridgeSignatureEncoding,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWindowsBridgeRecord {
    pub payload: WindowsBridgeRecordPayload,
    pub signature: WindowsBridgeSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowsBridgePackage {
    pub request: WindowsBridgeRequest,
    pub authorization: AuthorizationReceiptRecord,
    pub pre_state: ObservedWindowsState,
    pub post_state: ObservedWindowsState,
    pub record: SignedWindowsBridgeRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedWindowsBridgeRecord {
    pub record_id: String,
    pub record_digest: String,
    pub request_digest: String,
    pub pre_state_digest: String,
    pub post_state_digest: String,
    pub status: WindowsBridgeStatus,
}
