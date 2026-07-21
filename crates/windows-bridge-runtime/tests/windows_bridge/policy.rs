use std::error::Error;

use ergaxiom_windows_bridge_runtime::{
    WindowsBridgeError, WindowsBridgeStatus, WindowsControlMethod, WindowsStateAssertion,
    WindowsTargetSelector, verify_windows_bridge_package,
};

use super::support::{MockAdapter, application, bridge_keys, context, request, run_bridge, state};

#[test]
fn grant_mismatch_blocks_before_observation() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let mut bridge_request = request(&context, &pre.state_digest);
    bridge_request.required_grant.resource = "host://unsealed".to_owned();
    let mut adapter = MockAdapter::new(pre, post);

    assert!(matches!(
        run_bridge(&context, &mut adapter, bridge_request),
        Err(WindowsBridgeError::AuthorizationGrantMismatch)
    ));
    assert_eq!(adapter.observe_calls, 0);
    Ok(())
}

#[test]
fn method_selector_mismatch_blocks_before_observation() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let mut bridge_request = request(&context, &pre.state_digest);
    bridge_request.control_method = WindowsControlMethod::Cli;
    let mut adapter = MockAdapter::new(pre, post);

    assert!(matches!(
        run_bridge(&context, &mut adapter, bridge_request),
        Err(WindowsBridgeError::SelectorMethodMismatch)
    ));
    assert_eq!(adapter.observe_calls, 0);
    Ok(())
}

#[test]
fn coordinate_fallback_without_effect_assertion_is_rejected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "region.copy", "BEFORE", 1_000)?;
    let post = state(application(), "region.copy", "APPROVED", 2_000)?;
    let mut bridge_request = request(&context, &pre.state_digest);
    bridge_request.control_method = WindowsControlMethod::CoordinateFallback;
    bridge_request.selector = WindowsTargetSelector::Coordinates {
        x: 300,
        y: 200,
        confirmation_region_id: "region.copy".to_owned(),
    };
    bridge_request.postconditions = vec![WindowsStateAssertion::TargetStableIdEquals {
        stable_id: "region.copy".to_owned(),
    }];
    let mut adapter = MockAdapter::new(pre, post);

    assert!(matches!(
        run_bridge(&context, &mut adapter, bridge_request),
        Err(WindowsBridgeError::MissingIndependentEffectPostcondition)
    ));
    assert_eq!(adapter.observe_calls, 0);
    Ok(())
}

#[test]
fn coordinate_fallback_succeeds_only_with_observed_effect() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "region.copy", "BEFORE", 1_000)?;
    let post = state(application(), "region.copy", "APPROVED", 2_000)?;
    let mut bridge_request = request(&context, &pre.state_digest);
    bridge_request.control_method = WindowsControlMethod::CoordinateFallback;
    bridge_request.selector = WindowsTargetSelector::Coordinates {
        x: 300,
        y: 200,
        confirmation_region_id: "region.copy".to_owned(),
    };
    let mut adapter = MockAdapter::new(pre, post);
    let package = run_bridge(&context, &mut adapter, bridge_request)?;

    assert_eq!(
        package.record.payload.status,
        WindowsBridgeStatus::Succeeded
    );
    assert_eq!(
        verify_windows_bridge_package(
            &package,
            &bridge_keys(&context)?,
            &context.contract,
            &context.plan,
        )?
        .status,
        WindowsBridgeStatus::Succeeded
    );
    Ok(())
}
