use std::collections::BTreeMap;
use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding, SignedCapabilityToken,
    TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_execution_runtime::AuthorizationReceiptRecord;
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::{canonical_json_bytes, canonical_json_sha256};
use ergaxiom_windows_bridge_runtime::{
    ObservedWindowsState, WindowsAdapterTransition, WindowsApplicationIdentity,
    WindowsBridgeAction, WindowsBridgeAdapter, WindowsBridgeError,
    WindowsBridgeExecutionContext, WindowsBridgeKeyRegistry, WindowsBridgeRequest,
    WindowsBridgeStatus, WindowsBridgeVerifyError, WindowsControlMethod,
    WindowsStateAssertion, WindowsTargetSelector, execute_windows_bridge,
    seal_observed_state, verify_windows_bridge_package,
};
use serde_json::{Value, json};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str =
    include_str!("../../../professions/graphic-designer/profession.json");
const POLICY_ISSUER: &str = "ergaxiom.policy-authority";
const POLICY_KEY_ID: &str = "windows-bridge-policy-key";
const BRIDGE_ISSUER: &str = "ergaxiom.windows-bridge-authority";
const BRIDGE_KEY_ID: &str = "windows-bridge-key-01";
const EXECUTOR_ID: &str = "executor.windows-bridge-test";
const DEVICE_ID: &str = "device.windows-bridge-test";
const NOW: u64 = 2_000;

struct Context {
    contract: CompiledContract,
    plan: CompiledPlan,
    authorization: AuthorizationReceiptRecord,
    bridge_key: SigningKey,
}

fn context() -> Result<Context, Box<dyn Error>> {
    let contract_value: Value = serde_json::from_str(CONTRACT_SOURCE)?;
    let capsule_value: Value = serde_json::from_str(CAPSULE_SOURCE)?;
    let contract = compile_contract(&contract_value, &capsule_value)?;
    let plan = compile_plan(&plan_value(&contract), &capsule_value, &contract)?;
    let policy_key = SigningKey::from_bytes(&[53_u8; 32]);
    let token = signed_token(&contract, &plan, &policy_key)?;
    let mut keys = TrustedKeyRegistry::default();
    keys.insert_ed25519(
        POLICY_ISSUER,
        POLICY_KEY_ID,
        policy_key.verifying_key().to_bytes(),
    )?;
    let mut authorizer = CapabilityAuthorizer::new(keys);
    let receipt = authorizer.authorize(
        &token,
        &contract,
        &plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?;
    let receipt_value = serde_json::to_value(&receipt)?;
    Ok(Context {
        contract,
        plan,
        authorization: AuthorizationReceiptRecord {
            receipt_digest: canonical_json_sha256(&receipt_value)?,
            receipt,
        },
        bridge_key: SigningKey::from_bytes(&[71_u8; 32]),
    })
}

fn plan_value(contract: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.windows-bridge-test.0001",
        "created_at": "2026-07-21T14:00:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest,
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.graphic-designer",
                "algorithm": "sha256",
                "digest": contract.seal.capsule_digest,
            }
        },
        "steps": [
            step("step.canvas", 0, "design.create_canvas", &[], "token.canvas"),
            step(
                "step.logo",
                1,
                "design.place_asset",
                &["step.canvas"],
                "token.logo"
            ),
            step(
                "step.text",
                2,
                "design.compose_text",
                &["step.logo"],
                "token.text.bridge"
            ),
            step(
                "step.export",
                3,
                "design.export_raster",
                &["step.text"],
                "token.export"
            )
        ]
    })
}

fn step(
    step_id: &str,
    sequence: usize,
    operator_id: &str,
    depends_on: &[&str],
    token_id: &str,
) -> Value {
    json!({
        "step_id": step_id,
        "sequence": sequence,
        "operator_id": operator_id,
        "operator_version": "0.1.0",
        "depends_on": depends_on,
        "input_artifact_ids": [],
        "output_artifact_ids": [],
        "capability_token_ids": [token_id],
        "mandatory": true,
        "rollback_step_id": null,
    })
}

fn signed_token(
    contract: &CompiledContract,
    plan: &CompiledPlan,
    signing_key: &SigningKey,
) -> Result<Value, Box<dyn Error>> {
    let payload = CapabilityTokenPayload {
        schema_version: "0.1.0".to_owned(),
        token_id: "token.text.bridge".to_owned(),
        issuer_id: POLICY_ISSUER.to_owned(),
        key_id: POLICY_KEY_ID.to_owned(),
        subject: CapabilitySubject {
            executor_id: EXECUTOR_ID.to_owned(),
            device_id: Some(DEVICE_ID.to_owned()),
        },
        issued_at_epoch_s: NOW - 100,
        not_before_epoch_s: NOW - 50,
        expires_at_epoch_s: NOW + 100,
        max_uses: 1,
        nonce: "windows-bridge-nonce-0001".to_owned(),
        bindings: CapabilityBindings {
            contract_digest: contract.seal.contract_digest.clone(),
            capsule_digest: contract.seal.capsule_digest.clone(),
            plan_id: plan.plan_id.clone(),
            plan_digest: plan.plan_digest.clone(),
            step_id: "step.text".to_owned(),
            operator_id: "design.compose_text".to_owned(),
        },
        grant: design_editor_grant(),
    };
    let payload_value = serde_json::to_value(&payload)?;
    let signature = signing_key.sign(&canonical_json_bytes(&payload_value)?);
    Ok(serde_json::to_value(SignedCapabilityToken {
        payload,
        signature: TokenSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            encoding: SignatureEncoding::Base64url,
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })?)
}

fn design_editor_grant() -> CapabilityGrant {
    CapabilityGrant {
        capability: "design-editor".to_owned(),
        resource: "isolated-workspace".to_owned(),
        access: PermissionAccess::Control,
        constraints: json!({"network": false}),
    }
}

fn application() -> WindowsApplicationIdentity {
    WindowsApplicationIdentity {
        application_id: "ergaxiom.mock-design-editor".to_owned(),
        version: "1.0.0".to_owned(),
        executable_digest: "mock-editor-executable-digest".to_owned(),
        instance_id: "process-4242".to_owned(),
    }
}

fn state(
    app: WindowsApplicationIdentity,
    stable_id: &str,
    text: &str,
    observed_at_epoch_ms: u64,
) -> Result<ObservedWindowsState, Box<dyn Error>> {
    Ok(seal_observed_state(ObservedWindowsState {
        application: app,
        target_stable_id: stable_id.to_owned(),
        properties: BTreeMap::from([("text".to_owned(), text.to_owned())]),
        artifact_digests: BTreeMap::new(),
        observed_at_epoch_ms,
        state_digest: String::new(),
    })?)
}

fn uia_request(
    context: &Context,
    pre_state_digest: &str,
) -> WindowsBridgeRequest {
    WindowsBridgeRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.windows-bridge-test.0001".to_owned(),
        bridge_id: "bridge.windows.mock-01".to_owned(),
        plan_id: context.plan.plan_id.clone(),
        plan_digest: context.plan.plan_digest.clone(),
        step_id: "step.text".to_owned(),
        operator_id: "design.compose_text".to_owned(),
        executor_id: EXECUTOR_ID.to_owned(),
        device_id: Some(DEVICE_ID.to_owned()),
        control_method: WindowsControlMethod::UiAutomation,
        application: application(),
        selector: WindowsTargetSelector::UiAutomation {
            automation_id: "copy-field".to_owned(),
            control_type: "Edit".to_owned(),
        },
        action: WindowsBridgeAction::SetValue {
            value: "APPROVED".to_owned(),
        },
        required_grant: design_editor_grant(),
        expected_pre_state_digest: pre_state_digest.to_owned(),
        postconditions: vec![WindowsStateAssertion::PropertyEquals {
            key: "text".to_owned(),
            value: "APPROVED".to_owned(),
        }],
        authorization_receipt_digest: context.authorization.receipt_digest.clone(),
    }
}

fn bridge_context<'a>(context: &'a Context) -> WindowsBridgeExecutionContext<'a> {
    WindowsBridgeExecutionContext {
        compiled_contract: &context.contract,
        compiled_plan: &context.plan,
        signing_key: &context.bridge_key,
        issuer_id: BRIDGE_ISSUER,
        key_id: BRIDGE_KEY_ID,
        record_id: "record.windows-bridge-test.0001",
        recorded_at_epoch_ms: 3_000,
    }
}

fn bridge_keys(context: &Context) -> Result<WindowsBridgeKeyRegistry, Box<dyn Error>> {
    let mut keys = WindowsBridgeKeyRegistry::default();
    keys.insert_ed25519(
        BRIDGE_ISSUER,
        BRIDGE_KEY_ID,
        context.bridge_key.verifying_key().to_bytes(),
    )?;
    Ok(keys)
}

struct MockAdapter {
    pre_state: ObservedWindowsState,
    post_state: ObservedWindowsState,
    consumed_pre_state_digest: String,
    adapter_event_digest: String,
    observe_calls: usize,
    execute_calls: usize,
}

impl MockAdapter {
    fn new(pre_state: ObservedWindowsState, post_state: ObservedWindowsState) -> Self {
        Self {
            consumed_pre_state_digest: pre_state.state_digest.clone(),
            pre_state,
            post_state,
            adapter_event_digest: "adapter-event-digest".to_owned(),
            observe_calls: 0,
            execute_calls: 0,
        }
    }
}

impl WindowsBridgeAdapter for MockAdapter {
    fn observe(
        &mut self,
        _request: &WindowsBridgeRequest,
    ) -> Result<ObservedWindowsState, String> {
        let state = if self.observe_calls == 0 {
            self.pre_state.clone()
        } else {
            self.post_state.clone()
        };
        self.observe_calls += 1;
        Ok(state)
    }

    fn execute(
        &mut self,
        _request: &WindowsBridgeRequest,
        _expected_pre_state_digest: &str,
    ) -> Result<WindowsAdapterTransition, String> {
        self.execute_calls += 1;
        Ok(WindowsAdapterTransition {
            consumed_pre_state_digest: self.consumed_pre_state_digest.clone(),
            adapter_event_digest: self.adapter_event_digest.clone(),
        })
    }
}

#[test]
fn ui_automation_success_is_signed_and_independently_verified() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let request = uia_request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);

    let package = execute_windows_bridge(
        &mut adapter,
        bridge_context(&context),
        request,
        context.authorization.clone(),
    )?;
    assert_eq!(adapter.execute_calls, 1);
    assert_eq!(package.record.payload.status, WindowsBridgeStatus::Succeeded);
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
    let request = uia_request(&context, "stale-pre-state-digest");
    let mut adapter = MockAdapter::new(pre, post);

    assert!(matches!(
        execute_windows_bridge(
            &mut adapter,
            bridge_context(&context),
            request,
            context.authorization,
        ),
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
    let request = uia_request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);
    adapter.consumed_pre_state_digest = "changed-before-action".to_owned();

    assert!(matches!(
        execute_windows_bridge(
            &mut adapter,
            bridge_context(&context),
            request,
            context.authorization,
        ),
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
    let request = uia_request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);

    assert!(matches!(
        execute_windows_bridge(
            &mut adapter,
            bridge_context(&context),
            request,
            context.authorization,
        ),
        Err(WindowsBridgeError::ApplicationIdentityMismatch)
    ));
    assert_eq!(adapter.execute_calls, 0);
    Ok(())
}

#[test]
fn grant_mismatch_blocks_before_observation() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let mut request = uia_request(&context, &pre.state_digest);
    request.required_grant.resource = "host://unsealed".to_owned();
    let mut adapter = MockAdapter::new(pre, post);

    assert!(matches!(
        execute_windows_bridge(
            &mut adapter,
            bridge_context(&context),
            request,
            context.authorization,
        ),
        Err(WindowsBridgeError::AuthorizationGrantMismatch)
    ));
    assert_eq!(adapter.observe_calls, 0);
    assert_eq!(adapter.execute_calls, 0);
    Ok(())
}

#[test]
fn method_selector_mismatch_blocks_before_observation() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let mut request = uia_request(&context, &pre.state_digest);
    request.control_method = WindowsControlMethod::Cli;
    let mut adapter = MockAdapter::new(pre, post);

    assert!(matches!(
        execute_windows_bridge(
            &mut adapter,
            bridge_context(&context),
            request,
            context.authorization,
        ),
        Err(WindowsBridgeError::SelectorMethodMismatch)
    ));
    assert_eq!(adapter.observe_calls, 0);
    Ok(())
}

#[test]
fn failed_postcondition_produces_signed_failed_record_not_success() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "WRONG", 2_000)?;
    let request = uia_request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);

    let package = execute_windows_bridge(
        &mut adapter,
        bridge_context(&context),
        request,
        context.authorization.clone(),
    )?;
    assert_eq!(package.record.payload.status, WindowsBridgeStatus::Failed);
    assert_eq!(package.record.payload.violations.len(), 1);
    let verified = verify_windows_bridge_package(
        &package,
        &bridge_keys(&context)?,
        &context.contract,
        &context.plan,
    )?;
    assert_eq!(verified.status, WindowsBridgeStatus::Failed);
    Ok(())
}

#[test]
fn coordinate_fallback_without_effect_assertion_is_rejected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "region.copy", "BEFORE", 1_000)?;
    let post = state(application(), "region.copy", "APPROVED", 2_000)?;
    let mut request = uia_request(&context, &pre.state_digest);
    request.control_method = WindowsControlMethod::CoordinateFallback;
    request.selector = WindowsTargetSelector::Coordinates {
        x: 300,
        y: 200,
        confirmation_region_id: "region.copy".to_owned(),
    };
    request.postconditions = vec![WindowsStateAssertion::TargetStableIdEquals {
        stable_id: "region.copy".to_owned(),
    }];
    let mut adapter = MockAdapter::new(pre, post);

    assert!(matches!(
        execute_windows_bridge(
            &mut adapter,
            bridge_context(&context),
            request,
            context.authorization,
        ),
        Err(WindowsBridgeError::MissingIndependentEffectPostcondition)
    ));
    assert_eq!(adapter.observe_calls, 0);
    Ok(())
}

#[test]
fn coordinate_fallback_can_succeed_only_with_observed_effect() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "region.copy", "BEFORE", 1_000)?;
    let post = state(application(), "region.copy", "APPROVED", 2_000)?;
    let mut request = uia_request(&context, &pre.state_digest);
    request.control_method = WindowsControlMethod::CoordinateFallback;
    request.selector = WindowsTargetSelector::Coordinates {
        x: 300,
        y: 200,
        confirmation_region_id: "region.copy".to_owned(),
    };
    let mut adapter = MockAdapter::new(pre, post);

    let package = execute_windows_bridge(
        &mut adapter,
        bridge_context(&context),
        request,
        context.authorization.clone(),
    )?;
    assert_eq!(package.record.payload.status, WindowsBridgeStatus::Succeeded);
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

#[test]
fn signed_record_payload_mutation_invalidates_signature() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let request = uia_request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);
    let mut package = execute_windows_bridge(
        &mut adapter,
        bridge_context(&context),
        request,
        context.authorization.clone(),
    )?;
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
fn post_state_mutation_is_detected_even_when_record_is_unchanged() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let request = uia_request(&context, &pre.state_digest);
    let mut adapter = MockAdapter::new(pre, post);
    let mut package = execute_windows_bridge(
        &mut adapter,
        bridge_context(&context),
        request,
        context.authorization.clone(),
    )?;
    package
        .post_state
        .properties
        .insert("text".to_owned(), "TAMPERED".to_owned());

    assert!(verify_windows_bridge_package(
        &package,
        &bridge_keys(&context)?,
        &context.contract,
        &context.plan,
    )
    .is_err());
    Ok(())
}

#[test]
fn identical_inputs_produce_identical_signed_bridge_packages() -> Result<(), Box<dyn Error>> {
    let left = context()?;
    let right = context()?;
    let left_pre = state(application(), "Edit/copy-field", "BEFORE", 1_000)?;
    let left_post = state(application(), "Edit/copy-field", "APPROVED", 2_000)?;
    let right_pre = left_pre.clone();
    let right_post = left_post.clone();
    let left_request = uia_request(&left, &left_pre.state_digest);
    let right_request = uia_request(&right, &right_pre.state_digest);
    let mut left_adapter = MockAdapter::new(left_pre, left_post);
    let mut right_adapter = MockAdapter::new(right_pre, right_post);

    let left_package = execute_windows_bridge(
        &mut left_adapter,
        bridge_context(&left),
        left_request,
        left.authorization,
    )?;
    let right_package = execute_windows_bridge(
        &mut right_adapter,
        bridge_context(&right),
        right_request,
        right.authorization,
    )?;
    assert_eq!(left_package, right_package);
    Ok(())
}
