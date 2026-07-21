use std::error::Error;

use ergaxiom_windows_bridge_runtime::{
    WindowsBridgeStatus, WindowsBridgeVerifyError, verify_windows_bridge_package,
};

use super::support::{MockAdapter, application, bridge_keys, context, request, run_bridge, state};

#[test]
fn failed_postcondition_produces_a_signed_failed_record() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "WRONG", 2_000)?;
    let bridge_request = request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);
    let package = run_bridge(&context, &mut adapter, bridge_request)?;

    assert_eq!(package.record.payload.status, WindowsBridgeStatus::Failed);
    assert_eq!(package.record.payload.violations.len(), 1);
    assert_eq!(
        verify_windows_bridge_package(
            &package,
            &bridge_keys(&context)?,
            &context.contract,
            &context.plan,
        )?
        .status,
        WindowsBridgeStatus::Failed
    );
    Ok(())
}

#[test]
fn signed_record_payload_mutation_invalidates_signature() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let bridge_request = request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);
    let mut package = run_bridge(&context, &mut adapter, bridge_request)?;
    package.record.payload.recorded_at_epoch_ms += 1;

    assert!(matches!(
        verify_windows_bridge_package(
            &package,
            &bridge_keys(&context)?,
            &context.contract,
            &context.plan,
        ),
        Err(WindowsBridgeVerifyError::SignatureVerificationFailed)
    ));
    Ok(())
}

#[test]
fn post_state_mutation_is_detected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let bridge_request = request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);
    let mut package = run_bridge(&context, &mut adapter, bridge_request)?;
    package
        .post_state
        .properties
        .insert("text".to_owned(), "TAMPERED".to_owned());

    assert!(
        verify_windows_bridge_package(
            &package,
            &bridge_keys(&context)?,
            &context.contract,
            &context.plan,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn identical_inputs_produce_identical_signed_packages() -> Result<(), Box<dyn Error>> {
    let left = context()?;
    let right = context()?;
    let left_pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let left_post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let right_pre = left_pre.clone();
    let right_post = left_post.clone();
    let left_request = request(&left, &left_pre.state_digest);
    let right_request = request(&right, &right_pre.state_digest);
    let mut left_adapter = MockAdapter::new(left_pre, left_post);
    let mut right_adapter = MockAdapter::new(right_pre, right_post);

    let left_package = run_bridge(&left, &mut left_adapter, left_request)?;
    let right_package = run_bridge(&right, &mut right_adapter, right_request)?;
    assert_eq!(left_package, right_package);
    Ok(())
}
