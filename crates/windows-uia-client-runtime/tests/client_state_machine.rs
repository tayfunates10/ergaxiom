use std::collections::VecDeque;
use std::error::Error;

use ergaxiom_windows_bridge_runtime::{
    ObservedWindowsState, WindowsBridgeAdapter, WindowsBridgeRequest, WindowsControlMethod,
};
use ergaxiom_windows_uia_client_runtime::{
    JsonLineTransport, WindowsUiaClient, WindowsUiaClientError,
};
use serde_json::{Value, json};

#[derive(Default)]
struct FakeTransport {
    responses: VecDeque<Result<Value, String>>,
    commands: Vec<Value>,
}

impl FakeTransport {
    fn with_responses(responses: Vec<Result<Value, String>>) -> Self {
        Self {
            responses: responses.into(),
            commands: Vec::new(),
        }
    }
}

impl JsonLineTransport for FakeTransport {
    fn exchange(&mut self, command: &Value) -> Result<Value, String> {
        self.commands.push(command.clone());
        self.responses
            .pop_front()
            .ok_or_else(|| "no fake response remains".to_owned())?
    }
}

#[test]
fn primed_observation_is_delivered_once_before_execute() -> Result<(), Box<dyn Error>> {
    let pre = observed_state("pre-digest", "BEFORE");
    let post = observed_state("post-digest", "APPROVED");
    let transport = FakeTransport::with_responses(vec![
        Ok(success_observe(&pre)),
        Ok(success_execute("pre-digest", "event-digest")),
        Ok(success_observe(&post)),
    ]);
    let mut client = WindowsUiaClient::new(transport);
    let mut request = request();

    let primed = client.prime(&request)?;
    request.expected_pre_state_digest = primed.state_digest.clone();
    let runtime_pre = WindowsBridgeAdapter::observe(&mut client, &request)?;
    let transition =
        WindowsBridgeAdapter::execute(&mut client, &request, &runtime_pre.state_digest)?;
    let runtime_post = WindowsBridgeAdapter::observe(&mut client, &request)?;
    let transport = client.into_transport();

    assert_eq!(runtime_pre, pre);
    assert_eq!(transition.consumed_pre_state_digest, "pre-digest");
    assert_eq!(runtime_post, post);
    assert_eq!(transport.commands.len(), 3);
    assert_eq!(transport.commands[0]["kind"], json!("observe"));
    assert_eq!(transport.commands[1]["kind"], json!("execute"));
    assert_eq!(transport.commands[2]["kind"], json!("observe"));
    Ok(())
}

#[test]
fn runtime_observe_without_prime_fails_without_transport_use() {
    let transport = FakeTransport::default();
    let mut client = WindowsUiaClient::new(transport);
    let error = WindowsBridgeAdapter::observe(&mut client, &request());

    assert!(matches!(
        error,
        Err(message) if message.contains("has not been primed")
    ));
    assert!(client.into_transport().commands.is_empty());
}

#[test]
fn request_identity_change_after_prime_fails_closed() -> Result<(), Box<dyn Error>> {
    let pre = observed_state("pre-digest", "BEFORE");
    let transport = FakeTransport::with_responses(vec![Ok(success_observe(&pre))]);
    let mut client = WindowsUiaClient::new(transport);
    let mut request = request();
    let primed = client.prime(&request)?;
    request.expected_pre_state_digest = primed.state_digest;
    request.request_id = "request.other".to_owned();

    let error = WindowsBridgeAdapter::observe(&mut client, &request);
    assert!(matches!(
        error,
        Err(message) if message.contains("identity changed")
    ));
    Ok(())
}

#[test]
fn host_rejection_is_preserved_as_typed_error() {
    let transport = FakeTransport::with_responses(vec![Ok(json!({
        "ok": false,
        "kind": "observe",
        "error": {
            "code": "PROCESS_NOT_FOUND",
            "message": "target process does not exist"
        }
    }))]);
    let mut client = WindowsUiaClient::new(transport);

    assert_eq!(
        client.prime(&request()),
        Err(WindowsUiaClientError::HostRejected {
            kind: "observe".to_owned(),
            code: "PROCESS_NOT_FOUND".to_owned(),
            message: "target process does not exist".to_owned(),
        })
    );
}

#[test]
fn host_consuming_another_digest_fails_closed() -> Result<(), Box<dyn Error>> {
    let pre = observed_state("pre-digest", "BEFORE");
    let transport = FakeTransport::with_responses(vec![
        Ok(success_observe(&pre)),
        Ok(success_execute("another-digest", "event-digest")),
    ]);
    let mut client = WindowsUiaClient::new(transport);
    let mut request = request();
    let primed = client.prime(&request)?;
    request.expected_pre_state_digest = primed.state_digest.clone();
    WindowsBridgeAdapter::observe(&mut client, &request)?;

    let error = WindowsBridgeAdapter::execute(&mut client, &request, &primed.state_digest);
    assert!(matches!(
        error,
        Err(message) if message.contains("consumed a different")
    ));
    Ok(())
}

#[test]
fn non_uia_request_is_rejected_before_transport_use() {
    let transport = FakeTransport::default();
    let mut client = WindowsUiaClient::new(transport);
    let mut request = request();
    request.control_method = WindowsControlMethod::Cli;

    assert_eq!(
        client.prime(&request),
        Err(WindowsUiaClientError::UnsupportedControlMethod)
    );
    assert!(client.into_transport().commands.is_empty());
}

fn request() -> WindowsBridgeRequest {
    serde_json::from_value(json!({
        "schema_version": "0.1.0",
        "request_id": "request.client-test",
        "bridge_id": "bridge.client-test",
        "plan_id": "plan.client-test",
        "plan_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "step_id": "step.client-test",
        "operator_id": "design.compose_text",
        "executor_id": "executor.client-test",
        "device_id": "device.client-test",
        "control_method": "UI_AUTOMATION",
        "application": {
            "application_id": "editor",
            "version": "1.0.0",
            "executable_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "instance_id": "pid:100"
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

fn observed_state(digest: &str, value: &str) -> ObservedWindowsState {
    serde_json::from_value(json!({
        "application": {
            "application_id": "editor",
            "version": "1.0.0",
            "executable_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "instance_id": "pid:100"
        },
        "target_stable_id": "Edit/copy-field",
        "properties": {"value": value},
        "artifact_digests": {},
        "observed_at_epoch_ms": 1000,
        "state_digest": digest
    }))
    .unwrap_or_else(|error| panic!("test state must deserialize: {error}"))
}

fn success_observe(state: &ObservedWindowsState) -> Value {
    json!({
        "ok": true,
        "kind": "observe",
        "state": state
    })
}

fn success_execute(consumed_digest: &str, event_digest: &str) -> Value {
    json!({
        "ok": true,
        "kind": "execute",
        "transition": {
            "consumed_pre_state_digest": consumed_digest,
            "adapter_event_digest": event_digest
        }
    })
}
