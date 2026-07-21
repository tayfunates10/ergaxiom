#![cfg(windows)]

use std::env;
use std::error::Error;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[test]
fn rust_client_exchanges_jsonl_with_windows_uia_host() -> Result<(), Box<dyn Error>> {
    let host_path = env::var("ERGAXIOM_WINDOWS_UIA_HOST")?;
    let mut child = Command::new(host_path)
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let command = json!({
        "kind": "unsupported",
        "request": {
            "schema_version": "0.1.0",
            "request_id": "request.process-test",
            "bridge_id": "bridge.process-test",
            "plan_id": "plan.process-test",
            "plan_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "step_id": "step.process-test",
            "operator_id": "design.compose_text",
            "executor_id": "executor.process-test",
            "device_id": null,
            "control_method": "UI_AUTOMATION",
            "application": {
                "application_id": "editor",
                "version": "1.0.0",
                "executable_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "instance_id": "pid:1"
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
            "expected_pre_state_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "postconditions": [],
            "authorization_receipt_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        },
        "expected_pre_state_digest": null
    });

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("Windows UIA host stdin is unavailable"))?;
        writeln!(stdin, "{}", serde_json::to_string(&command)?)?;
        stdin.flush()?;
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Windows UIA host stdout is unavailable"))?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response: Value = serde_json::from_str(line.trim_end())?;

    assert_eq!(response.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(
        response.get("kind").and_then(Value::as_str),
        Some("unsupported")
    );
    assert_eq!(
        response
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str),
        Some("UNSUPPORTED_COMMAND")
    );

    child.kill()?;
    child.wait()?;
    Ok(())
}
