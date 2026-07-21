use std::error::Error;

use ergaxiom_windows_bridge_runtime::{
    WindowsBridgeError, WindowsBridgeStatus, verify_windows_bridge_package,
};

use super::support::{MockAdapter, application, bridge_keys, context, request, run_bridge, state};

#[test]
fn ui_automation_success_is_signed_and_verified() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let bridge_request = request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);
    let package = run_bridge(&context, &mut adapter, bridge_request)?;

    assert_eq!(adapter.execute_calls, 1);
    assert_eq!(
        package.record.payload.status,
        WindowsBridgeStatus::Succeeded
    );
    let verified = verify_windows_bridge_package(
        &package,
        &bridge_keys(&context)?,
        &context.contract,
        &context.plan,
    )?;
    assert_eq!(verified.status, WindowsBridgeStatus::Succeeded);
    assert_eq!(verified.record_digest.len(), 64);
    Ok(())
}

#[test]
fn stale_expected_pre_state_blocks_before_action() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let bridge_request = request(&context, "stale-pre-state-digest");
    let mut adapter = MockAdapter::new(pre, post);

    assert!(matches!(
        run_bridge(&context, &mut adapter, bridge_request),
        Err(WindowsBridgeError::TimeOfCheckTimeOfUseMismatch)
    ));
    assert_eq!(adapter.execute_calls, 0);
    Ok(())
}

#[test]
fn adapter_consuming_another_pre_state_is_rejected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let bridge_request = request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);
    adapter.consumed_pre_state_digest = "changed-before-action".to_owned();

    assert!(matches!(
        run_bridge(&context, &mut adapter, bridge_request),
        Err(WindowsBridgeError::TimeOfCheckTimeOfUseMismatch)
    ));
    assert_eq!(adapter.execute_calls, 1);
    assert_eq!(adapter.observe_calls, 1);
    Ok(())
}

#[test]
fn application_identity_mismatch_blocks_before_action() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut wrong_app = application();
    wrong_app.executable_digest = "another-executable".to_owned();
    let pre = state(wrong_app, "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let bridge_request = request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);

    assert!(matches!(
        run_bridge(&context, &mut adapter, bridge_request),
        Err(WindowsBridgeError::ApplicationIdentityMismatch)
    ));
    assert_eq!(adapter.execute_calls, 0);
    Ok(())
}
