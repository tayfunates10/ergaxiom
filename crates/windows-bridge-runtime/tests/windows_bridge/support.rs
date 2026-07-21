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
    WindowsBridgeExecutionContext, WindowsBridgeKeyRegistry, WindowsBridgePackage,
    WindowsBridgeRequest, WindowsControlMethod, WindowsStateAssertion, WindowsTargetSelector,
    execute_windows_bridge, seal_observed_state,
};
use serde_json::{Value, json};

const CONTRACT_SOURCE: &str =
    include_str!("../../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str =
    include_str!("../../../../professions/graphic-designer/profession.json");
const POLICY_ISSUER: &str = "ergaxiom.policy-authority";
const POLICY_KEY_ID: &str = "windows-bridge-policy-key";
pub(crate) const BRIDGE_ISSUER: &str = "ergaxiom.windows-bridge-authority";
pub(crate) const BRIDGE_KEY_ID: &str = "windows-bridge-key-01";
const EXECUTOR_ID: &str = "executor.windows-bridge-test";
const DEVICE_ID: &str = "device.windows-bridge-test";
const NOW: u64 = 2_000;

pub(crate) struct Context {
    pub(crate) contract: CompiledContract,
    pub(crate) plan: CompiledPlan,
    pub(crate) authorization: AuthorizationReceiptRecord,
    pub(crate) bridge_key: SigningKey,
}

pub(crate) fn context() -> Result<Context, Box<dyn Error>> {
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
    let receipt =
        authorizer.authorize(&token, &contract, &plan, NOW, EXECUTOR_ID, Some(DEVICE_ID))?;
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
            step("step.logo", 1, "design.place_asset", &["step.canvas"], "token.logo"),
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

pub(crate) fn design_editor_grant() -> CapabilityGrant {
    CapabilityGrant {
        capability: "design-editor".to_owned(),
        resource: "isolated-workspace".to_owned(),
        access: PermissionAccess::Control,
        constraints: json!({"network": false}),
    }
}

pub(crate) fn application() -> WindowsApplicationIdentity {
    WindowsApplicationIdentity {
        application_id: "ergaxiom.mock-design-editor".to_owned(),
        version: "1.0.0".to_owned(),
        executable_digest: "mock-editor-executable-digest".to_owned(),
        instance_id: "process-4242".to_owned(),
    }
}

pub(crate) fn state(
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

pub(crate) fn request(context: &Context, pre_state_digest: &str) -> WindowsBridgeRequest {
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

fn execution_context(context: &Context) -> WindowsBridgeExecutionContext<'_> {
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

pub(crate) fn bridge_keys(
    context: &Context,
) -> Result<WindowsBridgeKeyRegistry, Box<dyn Error>> {
    let mut keys = WindowsBridgeKeyRegistry::default();
    keys.insert_ed25519(
        BRIDGE_ISSUER,
        BRIDGE_KEY_ID,
        context.bridge_key.verifying_key().to_bytes(),
    )?;
    Ok(keys)
}

pub(crate) fn run_bridge(
    context: &Context,
    adapter: &mut MockAdapter,
    request: WindowsBridgeRequest,
) -> Result<WindowsBridgePackage, WindowsBridgeError> {
    let authorization = context.authorization.clone();
    execute_windows_bridge(adapter, execution_context(context), request, authorization)
}

pub(crate) struct MockAdapter {
    pre_state: ObservedWindowsState,
    post_state: ObservedWindowsState,
    pub(crate) consumed_pre_state_digest: String,
    pub(crate) observe_calls: usize,
    pub(crate) execute_calls: usize,
}

impl MockAdapter {
    pub(crate) fn new(
        pre_state: ObservedWindowsState,
        post_state: ObservedWindowsState,
    ) -> Self {
        Self {
            consumed_pre_state_digest: pre_state.state_digest.clone(),
            pre_state,
            post_state,
            observe_calls: 0,
            execute_calls: 0,
        }
    }
}

impl WindowsBridgeAdapter for MockAdapter {
    fn observe(&mut self, _request: &WindowsBridgeRequest) -> Result<ObservedWindowsState, String> {
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
            adapter_event_digest: "adapter-event-digest".to_owned(),
        })
    }
}
