use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_execution_runtime::AuthorizationReceiptRecord;
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{HashingError, canonical_json_bytes, canonical_json_sha256};
use serde_json::json;
use thiserror::Error;

use crate::model::{
    ObservedWindowsState, SignedWindowsBridgeRecord, WindowsAdapterTransition,
    WindowsBridgePackage, WindowsBridgeRecordPayload, WindowsBridgeRequest, WindowsBridgeSignature,
    WindowsBridgeSignatureAlgorithm, WindowsBridgeSignatureEncoding, WindowsBridgeStatus,
    WindowsBridgeViolation, WindowsControlMethod, WindowsStateAssertion, WindowsTargetSelector,
};

const REQUEST_SCHEMA: &str = "0.1.0";
const RECORD_SCHEMA: &str = "0.1.0";

pub trait WindowsBridgeAdapter {
    fn observe(&mut self, request: &WindowsBridgeRequest) -> Result<ObservedWindowsState, String>;

    fn execute(
        &mut self,
        request: &WindowsBridgeRequest,
        expected_pre_state_digest: &str,
    ) -> Result<WindowsAdapterTransition, String>;
}

pub struct WindowsBridgeExecutionContext<'a> {
    pub compiled_contract: &'a CompiledContract,
    pub compiled_plan: &'a CompiledPlan,
    pub signing_key: &'a SigningKey,
    pub issuer_id: &'a str,
    pub key_id: &'a str,
    pub record_id: &'a str,
    pub recorded_at_epoch_ms: u64,
}

#[derive(Debug, Error)]
pub enum WindowsBridgeError {
    #[error("unsupported Windows Bridge request schema {actual}; expected {expected}")]
    UnsupportedRequestSchema {
        actual: String,
        expected: &'static str,
    },
    #[error("required Windows Bridge field is empty: {0}")]
    EmptyField(&'static str),
    #[error("Windows Bridge request does not match compiled plan")]
    PlanBindingMismatch,
    #[error("Windows Bridge request references unknown plan step {0}")]
    UnknownStep(String),
    #[error("Windows Bridge request operator does not match plan step")]
    OperatorMismatch,
    #[error("authorization receipt digest does not reproduce")]
    AuthorizationReceiptDigestMismatch,
    #[error("authorization receipt does not match request, plan, contract or subject")]
    AuthorizationBindingMismatch,
    #[error("authorization receipt grant does not match request or sealed contract")]
    AuthorizationGrantMismatch,
    #[error("control method and target selector are incompatible")]
    SelectorMethodMismatch,
    #[error("every Windows action requires independently observed postconditions")]
    MissingPostconditions,
    #[error("visual or coordinate fallback requires an effect postcondition")]
    MissingIndependentEffectPostcondition,
    #[error("observed state digest does not reproduce")]
    ObservedStateDigestMismatch,
    #[error("observed application identity does not match request")]
    ApplicationIdentityMismatch,
    #[error("observed target identity does not match selector")]
    TargetIdentityMismatch,
    #[error("observed pre-state changed before the adapter action")]
    TimeOfCheckTimeOfUseMismatch,
    #[error("adapter failed: {0}")]
    Adapter(String),
    #[error("failed to serialize Windows Bridge material: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn seal_observed_state(
    mut state: ObservedWindowsState,
) -> Result<ObservedWindowsState, WindowsBridgeError> {
    state.state_digest = observed_state_digest(&state)?;
    Ok(state)
}

pub fn execute_windows_bridge<A: WindowsBridgeAdapter>(
    adapter: &mut A,
    context: WindowsBridgeExecutionContext<'_>,
    request: WindowsBridgeRequest,
    authorization: AuthorizationReceiptRecord,
) -> Result<WindowsBridgePackage, WindowsBridgeError> {
    validate_request(&request, &authorization, &context)?;

    let pre_state = adapter
        .observe(&request)
        .map_err(WindowsBridgeError::Adapter)?;
    validate_observed_state(&pre_state, &request)?;
    if pre_state.state_digest != request.expected_pre_state_digest {
        return Err(WindowsBridgeError::TimeOfCheckTimeOfUseMismatch);
    }

    let transition = adapter
        .execute(&request, &pre_state.state_digest)
        .map_err(WindowsBridgeError::Adapter)?;
    if transition.consumed_pre_state_digest != pre_state.state_digest {
        return Err(WindowsBridgeError::TimeOfCheckTimeOfUseMismatch);
    }

    let post_state = adapter
        .observe(&request)
        .map_err(WindowsBridgeError::Adapter)?;
    validate_observed_state(&post_state, &request)?;
    let violations = evaluate_postconditions(&request.postconditions, &post_state);
    let status = if violations.is_empty() {
        WindowsBridgeStatus::Succeeded
    } else {
        WindowsBridgeStatus::Failed
    };
    let request_value =
        serde_json::to_value(&request).map_err(WindowsBridgeError::Serialization)?;
    let payload = WindowsBridgeRecordPayload {
        schema_version: RECORD_SCHEMA.to_owned(),
        record_id: context.record_id.to_owned(),
        bridge_id: request.bridge_id.clone(),
        request_digest: canonical_json_sha256(&request_value)?,
        authorization_receipt_digest: authorization.receipt_digest.clone(),
        pre_state_digest: pre_state.state_digest.clone(),
        consumed_pre_state_digest: transition.consumed_pre_state_digest,
        post_state_digest: post_state.state_digest.clone(),
        adapter_event_digest: transition.adapter_event_digest,
        status,
        violations,
        recorded_at_epoch_ms: context.recorded_at_epoch_ms,
    };
    let payload_value =
        serde_json::to_value(&payload).map_err(WindowsBridgeError::Serialization)?;
    let signature = context
        .signing_key
        .sign(&canonical_json_bytes(&payload_value)?);

    Ok(WindowsBridgePackage {
        request,
        authorization,
        pre_state,
        post_state,
        record: SignedWindowsBridgeRecord {
            payload,
            signature: WindowsBridgeSignature {
                issuer_id: context.issuer_id.to_owned(),
                key_id: context.key_id.to_owned(),
                algorithm: WindowsBridgeSignatureAlgorithm::Ed25519,
                encoding: WindowsBridgeSignatureEncoding::Base64url,
                value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        },
    })
}

pub(crate) fn validate_request(
    request: &WindowsBridgeRequest,
    authorization: &AuthorizationReceiptRecord,
    context: &WindowsBridgeExecutionContext<'_>,
) -> Result<(), WindowsBridgeError> {
    if request.schema_version != REQUEST_SCHEMA {
        return Err(WindowsBridgeError::UnsupportedRequestSchema {
            actual: request.schema_version.clone(),
            expected: REQUEST_SCHEMA,
        });
    }
    for (field, value) in [
        ("request_id", request.request_id.as_str()),
        ("bridge_id", request.bridge_id.as_str()),
        ("plan_id", request.plan_id.as_str()),
        ("plan_digest", request.plan_digest.as_str()),
        ("step_id", request.step_id.as_str()),
        ("operator_id", request.operator_id.as_str()),
        ("executor_id", request.executor_id.as_str()),
        (
            "application_id",
            request.application.application_id.as_str(),
        ),
        ("application.version", request.application.version.as_str()),
        (
            "application.executable_digest",
            request.application.executable_digest.as_str(),
        ),
        (
            "application.instance_id",
            request.application.instance_id.as_str(),
        ),
        (
            "expected_pre_state_digest",
            request.expected_pre_state_digest.as_str(),
        ),
        (
            "authorization_receipt_digest",
            request.authorization_receipt_digest.as_str(),
        ),
        ("issuer_id", context.issuer_id),
        ("key_id", context.key_id),
        ("record_id", context.record_id),
    ] {
        if value.trim().is_empty() {
            return Err(WindowsBridgeError::EmptyField(field));
        }
    }
    if request.plan_id != context.compiled_plan.plan_id
        || request.plan_digest != context.compiled_plan.plan_digest
        || context.compiled_plan.contract_digest != context.compiled_contract.seal.contract_digest
    {
        return Err(WindowsBridgeError::PlanBindingMismatch);
    }
    let step = context
        .compiled_plan
        .steps
        .iter()
        .find(|step| step.step_id == request.step_id)
        .ok_or_else(|| WindowsBridgeError::UnknownStep(request.step_id.clone()))?;
    if step.operator_id != request.operator_id {
        return Err(WindowsBridgeError::OperatorMismatch);
    }

    let receipt_value =
        serde_json::to_value(&authorization.receipt).map_err(WindowsBridgeError::Serialization)?;
    if canonical_json_sha256(&receipt_value)? != authorization.receipt_digest
        || request.authorization_receipt_digest != authorization.receipt_digest
    {
        return Err(WindowsBridgeError::AuthorizationReceiptDigestMismatch);
    }
    let receipt = &authorization.receipt;
    let subject_matches = receipt.executor_id == request.executor_id
        && receipt.device_id.as_deref() == request.device_id.as_deref();
    if receipt.contract_digest != context.compiled_contract.seal.contract_digest
        || receipt.capsule_digest != context.compiled_contract.seal.capsule_digest
        || receipt.plan_id != request.plan_id
        || receipt.plan_digest != request.plan_digest
        || receipt.step_id != request.step_id
        || receipt.operator_id != request.operator_id
        || !step.capability_token_ids.contains(&receipt.token_id)
        || !subject_matches
    {
        return Err(WindowsBridgeError::AuthorizationBindingMismatch);
    }
    if receipt.grant != request.required_grant
        || !context
            .compiled_contract
            .permissions
            .iter()
            .any(|permission| {
                permission.capability == request.required_grant.capability
                    && permission.resource == request.required_grant.resource
                    && permission.access == request.required_grant.access
                    && permission.constraints == request.required_grant.constraints
            })
    {
        return Err(WindowsBridgeError::AuthorizationGrantMismatch);
    }
    if !selector_matches_method(request.control_method, &request.selector) {
        return Err(WindowsBridgeError::SelectorMethodMismatch);
    }
    if request.postconditions.is_empty() {
        return Err(WindowsBridgeError::MissingPostconditions);
    }
    if matches!(
        request.control_method,
        WindowsControlMethod::VisuallyConfirmed | WindowsControlMethod::CoordinateFallback
    ) && !request.postconditions.iter().any(|assertion| {
        matches!(
            assertion,
            WindowsStateAssertion::PropertyEquals { .. }
                | WindowsStateAssertion::ArtifactDigestEquals { .. }
        )
    }) {
        return Err(WindowsBridgeError::MissingIndependentEffectPostcondition);
    }
    Ok(())
}

pub(crate) fn validate_observed_state(
    state: &ObservedWindowsState,
    request: &WindowsBridgeRequest,
) -> Result<(), WindowsBridgeError> {
    if observed_state_digest(state)? != state.state_digest {
        return Err(WindowsBridgeError::ObservedStateDigestMismatch);
    }
    if state.application != request.application {
        return Err(WindowsBridgeError::ApplicationIdentityMismatch);
    }
    if state.target_stable_id != selector_stable_id(&request.selector) {
        return Err(WindowsBridgeError::TargetIdentityMismatch);
    }
    Ok(())
}

pub(crate) fn evaluate_postconditions(
    assertions: &[WindowsStateAssertion],
    state: &ObservedWindowsState,
) -> Vec<WindowsBridgeViolation> {
    assertions
        .iter()
        .enumerate()
        .filter_map(|(index, assertion)| {
            let passed = match assertion {
                WindowsStateAssertion::PropertyEquals { key, value } => {
                    state.properties.get(key) == Some(value)
                }
                WindowsStateAssertion::ArtifactDigestEquals {
                    artifact_id,
                    digest,
                } => state.artifact_digests.get(artifact_id) == Some(digest),
                WindowsStateAssertion::TargetStableIdEquals { stable_id } => {
                    state.target_stable_id == *stable_id
                }
            };
            (!passed).then_some(WindowsBridgeViolation::PostconditionFailed { index })
        })
        .collect()
}

pub(crate) fn observed_state_digest(
    state: &ObservedWindowsState,
) -> Result<String, WindowsBridgeError> {
    let value = json!({
        "application": state.application,
        "target_stable_id": state.target_stable_id,
        "properties": state.properties,
        "artifact_digests": state.artifact_digests,
        "observed_at_epoch_ms": state.observed_at_epoch_ms,
    });
    Ok(canonical_json_sha256(&value)?)
}

pub(crate) fn selector_stable_id(selector: &WindowsTargetSelector) -> String {
    match selector {
        WindowsTargetSelector::NativeObject { object_id }
        | WindowsTargetSelector::ApplicationObject { object_id } => object_id.clone(),
        WindowsTargetSelector::PluginObject {
            plugin_id,
            object_id,
        } => format!("{plugin_id}/{object_id}"),
        WindowsTargetSelector::CliEndpoint { executable_id } => executable_id.clone(),
        WindowsTargetSelector::UiAutomation {
            automation_id,
            control_type,
        } => format!("{control_type}/{automation_id}"),
        WindowsTargetSelector::Accessibility { role, name } => format!("{role}/{name}"),
        WindowsTargetSelector::VisualRegion { region_id } => region_id.clone(),
        WindowsTargetSelector::Coordinates {
            confirmation_region_id,
            ..
        } => confirmation_region_id.clone(),
    }
}

fn selector_matches_method(method: WindowsControlMethod, selector: &WindowsTargetSelector) -> bool {
    matches!(
        (method, selector),
        (
            WindowsControlMethod::NativeModel,
            WindowsTargetSelector::NativeObject { .. }
        ) | (
            WindowsControlMethod::ApplicationApi,
            WindowsTargetSelector::ApplicationObject { .. }
        ) | (
            WindowsControlMethod::SignedPlugin,
            WindowsTargetSelector::PluginObject { .. }
        ) | (
            WindowsControlMethod::Cli,
            WindowsTargetSelector::CliEndpoint { .. }
        ) | (
            WindowsControlMethod::UiAutomation,
            WindowsTargetSelector::UiAutomation { .. }
        ) | (
            WindowsControlMethod::Accessibility,
            WindowsTargetSelector::Accessibility { .. }
        ) | (
            WindowsControlMethod::VisuallyConfirmed,
            WindowsTargetSelector::VisualRegion { .. }
        ) | (
            WindowsControlMethod::CoordinateFallback,
            WindowsTargetSelector::Coordinates { .. }
        )
    )
}
