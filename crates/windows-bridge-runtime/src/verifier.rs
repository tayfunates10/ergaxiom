use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{HashingError, canonical_json_bytes, canonical_json_sha256};
use thiserror::Error;

use crate::model::{
    VerifiedWindowsBridgeRecord, WindowsBridgePackage, WindowsBridgeStatus,
    WindowsBridgeViolation,
};
use crate::runtime::{
    evaluate_postconditions, observed_state_digest, selector_stable_id, validate_observed_state,
};

const RECORD_SCHEMA: &str = "0.1.0";

#[derive(Debug, Clone, Default)]
pub struct WindowsBridgeKeyRegistry {
    keys: BTreeMap<(String, String), VerifyingKey>,
}

impl WindowsBridgeKeyRegistry {
    pub fn insert_ed25519(
        &mut self,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<(), WindowsBridgeVerifyError> {
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| WindowsBridgeVerifyError::InvalidTrustedKey)?;
        self.keys.insert((issuer_id.into(), key_id.into()), key);
        Ok(())
    }

    fn get(&self, issuer_id: &str, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(&(issuer_id.to_owned(), key_id.to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum WindowsBridgeVerifyError {
    #[error("unsupported Windows Bridge record schema {0}")]
    UnsupportedRecordSchema(String),
    #[error("trusted Windows Bridge key is invalid")]
    InvalidTrustedKey,
    #[error("unknown Windows Bridge key {issuer_id}/{key_id}")]
    UnknownTrustedKey { issuer_id: String, key_id: String },
    #[error("Windows Bridge signature is not valid base64url")]
    InvalidSignatureEncoding,
    #[error("Windows Bridge signature has an invalid Ed25519 length")]
    InvalidSignatureLength,
    #[error("Windows Bridge signature verification failed")]
    SignatureVerificationFailed,
    #[error("failed to serialize Windows Bridge package: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("request digest does not match signed record")]
    RequestDigestMismatch,
    #[error("authorization receipt digest does not reproduce")]
    AuthorizationReceiptDigestMismatch,
    #[error("authorization receipt or request does not match sealed plan and contract")]
    AuthorizationBindingMismatch,
    #[error("observed pre-state digest does not reproduce")]
    PreStateDigestMismatch,
    #[error("observed post-state digest does not reproduce")]
    PostStateDigestMismatch,
    #[error("observed state does not match requested application or target")]
    ObservedIdentityMismatch,
    #[error("signed record reports a time-of-check/time-of-use mismatch")]
    TimeOfCheckTimeOfUseMismatch,
    #[error("signed record status or violations do not match independently evaluated postconditions")]
    PostconditionAssessmentMismatch,
    #[error("signed record bridge or authorization binding does not match package")]
    RecordBindingMismatch,
}

pub fn verify_windows_bridge_package(
    package: &WindowsBridgePackage,
    trusted_keys: &WindowsBridgeKeyRegistry,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
) -> Result<VerifiedWindowsBridgeRecord, WindowsBridgeVerifyError> {
    let payload = &package.record.payload;
    if payload.schema_version != RECORD_SCHEMA {
        return Err(WindowsBridgeVerifyError::UnsupportedRecordSchema(
            payload.schema_version.clone(),
        ));
    }

    let key = trusted_keys
        .get(
            &package.record.signature.issuer_id,
            &package.record.signature.key_id,
        )
        .ok_or_else(|| WindowsBridgeVerifyError::UnknownTrustedKey {
            issuer_id: package.record.signature.issuer_id.clone(),
            key_id: package.record.signature.key_id.clone(),
        })?;
    let payload_value =
        serde_json::to_value(payload).map_err(WindowsBridgeVerifyError::Serialization)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&package.record.signature.value)
        .map_err(|_| WindowsBridgeVerifyError::InvalidSignatureEncoding)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| WindowsBridgeVerifyError::InvalidSignatureLength)?;
    key.verify_strict(&canonical_json_bytes(&payload_value)?, &signature)
        .map_err(|_| WindowsBridgeVerifyError::SignatureVerificationFailed)?;

    let request_value =
        serde_json::to_value(&package.request).map_err(WindowsBridgeVerifyError::Serialization)?;
    let request_digest = canonical_json_sha256(&request_value)?;
    if request_digest != payload.request_digest {
        return Err(WindowsBridgeVerifyError::RequestDigestMismatch);
    }
    let receipt_value = serde_json::to_value(&package.authorization.receipt)
        .map_err(WindowsBridgeVerifyError::Serialization)?;
    let receipt_digest = canonical_json_sha256(&receipt_value)?;
    if receipt_digest != package.authorization.receipt_digest
        || receipt_digest != package.request.authorization_receipt_digest
    {
        return Err(WindowsBridgeVerifyError::AuthorizationReceiptDigestMismatch);
    }

    validate_package_bindings(package, compiled_contract, compiled_plan)?;
    validate_observed_state(&package.pre_state, &package.request)
        .map_err(|_| WindowsBridgeVerifyError::ObservedIdentityMismatch)?;
    validate_observed_state(&package.post_state, &package.request)
        .map_err(|_| WindowsBridgeVerifyError::ObservedIdentityMismatch)?;
    if observed_state_digest(&package.pre_state)? != package.pre_state.state_digest
        || package.pre_state.state_digest != payload.pre_state_digest
        || package.request.expected_pre_state_digest != payload.pre_state_digest
    {
        return Err(WindowsBridgeVerifyError::PreStateDigestMismatch);
    }
    if observed_state_digest(&package.post_state)? != package.post_state.state_digest
        || package.post_state.state_digest != payload.post_state_digest
    {
        return Err(WindowsBridgeVerifyError::PostStateDigestMismatch);
    }
    if payload.consumed_pre_state_digest != payload.pre_state_digest {
        return Err(WindowsBridgeVerifyError::TimeOfCheckTimeOfUseMismatch);
    }

    let violations = evaluate_postconditions(&package.request.postconditions, &package.post_state);
    let status = if violations.is_empty() {
        WindowsBridgeStatus::Succeeded
    } else {
        WindowsBridgeStatus::Failed
    };
    if payload.status != status || payload.violations != violations {
        return Err(WindowsBridgeVerifyError::PostconditionAssessmentMismatch);
    }
    if payload.bridge_id != package.request.bridge_id
        || payload.authorization_receipt_digest != receipt_digest
    {
        return Err(WindowsBridgeVerifyError::RecordBindingMismatch);
    }

    let record_value =
        serde_json::to_value(&package.record).map_err(WindowsBridgeVerifyError::Serialization)?;
    Ok(VerifiedWindowsBridgeRecord {
        record_id: payload.record_id.clone(),
        record_digest: canonical_json_sha256(&record_value)?,
        request_digest,
        pre_state_digest: payload.pre_state_digest.clone(),
        post_state_digest: payload.post_state_digest.clone(),
        status,
    })
}

fn validate_package_bindings(
    package: &WindowsBridgePackage,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
) -> Result<(), WindowsBridgeVerifyError> {
    let request = &package.request;
    let receipt = &package.authorization.receipt;
    let step = compiled_plan
        .steps
        .iter()
        .find(|step| step.step_id == request.step_id)
        .ok_or(WindowsBridgeVerifyError::AuthorizationBindingMismatch)?;
    let valid = request.plan_id == compiled_plan.plan_id
        && request.plan_digest == compiled_plan.plan_digest
        && compiled_plan.contract_digest == compiled_contract.seal.contract_digest
        && request.operator_id == step.operator_id
        && receipt.contract_digest == compiled_contract.seal.contract_digest
        && receipt.capsule_digest == compiled_contract.seal.capsule_digest
        && receipt.plan_id == request.plan_id
        && receipt.plan_digest == request.plan_digest
        && receipt.step_id == request.step_id
        && receipt.operator_id == request.operator_id
        && receipt.executor_id == request.executor_id
        && receipt.device_id == request.device_id
        && step.capability_token_ids.contains(&receipt.token_id)
        && receipt.grant == request.required_grant
        && compiled_contract.permissions.iter().any(|permission| {
            permission.capability == receipt.grant.capability
                && permission.resource == receipt.grant.resource
                && permission.access == receipt.grant.access
                && permission.constraints == receipt.grant.constraints
        })
        && package.pre_state.target_stable_id == selector_stable_id(&request.selector)
        && package.post_state.target_stable_id == selector_stable_id(&request.selector);
    if valid {
        Ok(())
    } else {
        Err(WindowsBridgeVerifyError::AuthorizationBindingMismatch)
    }
}

#[allow(dead_code)]
fn _assert_violation_type_is_stable(violation: &WindowsBridgeViolation) -> usize {
    match violation {
        WindowsBridgeViolation::PostconditionFailed { index } => *index,
    }
}
