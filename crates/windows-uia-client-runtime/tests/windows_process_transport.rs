#![cfg(windows)]

use std::env;
use std::error::Error;

use ergaxiom_windows_bridge_runtime::WindowsBridgeRequest;
use ergaxiom_windows_uia_client_runtime::{
    ChildJsonLineTransport, WindowsUiaClient, WindowsUiaClientError,
};
use serde_json::json;

#[test]
fn digest_pinned_child_transport_preserves_host_error() -> Result<(), Box<dyn Error>> {
    let host_path = env::var("ERGAXIOM_WINDOWS_UIA_HOST")?;
    let host_digest = env::var("ERGAXIOM_WINDOWS_UIA_HOST_SHA256")?;
    let transport = ChildJsonLineTransport::spawn(host_path, &host_digest)?;
    let mut client = WindowsUiaClient::new(transport);

    assert!(matches!(
        client.prime(&request()),
        Err(WindowsUiaClientError::HostRejected { code, .. })
            if code == "PROCESS_NOT_FOUND"
    ));
    Ok(())
}

#[test]
fn wrong_host_digest_blocks_process_start() -> Result<(), Box<dyn Error>> {
    let host_path = env::var("ERGAXIOM_WINDOWS_UIA_HOST")?;
    assert!(matches!(
        ChildJsonLineTransport::spawn(
            host_path,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        Err(WindowsUiaClientError::HostDigestMismatch)
    ));
    Ok(())
}

fn request() -> WindowsBridgeRequest {
    serde_json::from_value(json!({
        "schema_version": "0.1.0",
        "request_id": "request.windows-process-test",
        "bridge_id": "bridge.windows-process-test",
        "plan_id": "plan.windows-process-test",
        "plan_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "step_id": "step.windows-process-test",
        "operator_id": "design.compose_text",
        "executor_id": "executor.windows-process-test",
        "device_id": null,
        "control_method": "UI_AUTOMATION",
        "application": {
            "application_id": "missing-process",
            "version": "1.0.0",
            "executable_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "instance_id": "pid:2147483647"
        },
        "selector": {
            "selector": "UI_AUTOMATION",
            "automation_id": "copy-field",
            "control_type": "Edit"
        },
        "action": {
            "action": "SET_VALUE",
            "value": "APPROVED"
        },
        "required_grant": {
            "capability": "design-editor",
            "resource": "isolated-workspace",
            "access": "control",
            "constraints": {"network": false}
        },
        "expected_pre_state_digest": "placeholder",
        "postconditions": [{
            "assertion": "PROPERTY_EQUALS",
            "key": "value",
            "value": "APPROVED"
        }],
        "authorization_receipt_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }))
    .unwrap_or_else(|error| panic!("test request must deserialize: {error}"))
}
