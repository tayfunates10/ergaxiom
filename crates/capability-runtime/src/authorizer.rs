use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use ergaxiom_contract_runtime::{CompiledContract, ContractPermission};
use ergaxiom_operator_plan_runtime::{CompiledPlan, PlanStep};
use ergaxiom_proof_kernel::{HashingError, canonical_json_bytes, canonical_json_sha256};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    AuthorizationReceipt, CapabilityGrant, CapabilityTokenPayload, SignedCapabilityToken,
};

const SUPPORTED_TOKEN_SCHEMA: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("failed to decode capability token: {0}")]
    TokenDecode(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("unsupported capability-token schema {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        actual: String,
        expected: &'static str,
    },
    #[error("trusted Ed25519 public key is invalid")]
    InvalidTrustedKey,
    #[error("unknown trusted key {issuer_id}/{key_id}")]
    UnknownTrustedKey { issuer_id: String, key_id: String },
    #[error("signature is not valid base64url")]
    InvalidSignatureEncoding,
    #[error("signature has an invalid Ed25519 length")]
    InvalidSignatureLength,
    #[error("Ed25519 signature verification failed")]
    SignatureVerificationFailed,
    #[error("token temporal bounds are invalid")]
    InvalidTemporalBounds,
    #[error("token was issued in the future")]
    IssuedInFuture,
    #[error("token is not valid yet")]
    NotYetValid,
    #[error("token has expired")]
    Expired,
    #[error("token max_uses must be greater than zero")]
    InvalidMaxUses,
    #[error("token nonce is too short")]
    NonceTooShort,
    #[error("token contract digest does not match the compiled contract")]
    ContractDigestMismatch,
    #[error("token capsule digest does not match the compiled capsule")]
    CapsuleDigestMismatch,
    #[error("token plan ID does not match the compiled plan")]
    PlanIdMismatch,
    #[error("token plan digest does not match the compiled plan")]
    PlanDigestMismatch,
    #[error("token references unknown plan step {0}")]
    UnknownPlanStep(String),
    #[error("token operator does not match the sealed plan step")]
    OperatorMismatch,
    #[error("token ID is not allowed by the sealed plan step")]
    TokenNotDeclaredByStep,
    #[error("token executor {actual} does not match active executor {expected}")]
    ExecutorMismatch { actual: String, expected: String },
    #[error("token device binding does not match the active device")]
    DeviceMismatch,
    #[error("token grant is not present in the sealed Work Contract permissions")]
    GrantExceedsContract,
    #[error("token usage limit has been exhausted")]
    UsageLimitExceeded,
    #[error("issuer reused token ID {token_id} with a different signed payload")]
    TokenIdCollision { token_id: String },
}

#[derive(Debug, Clone, Default)]
pub struct TrustedKeyRegistry {
    keys: BTreeMap<(String, String), VerifyingKey>,
}

impl TrustedKeyRegistry {
    pub fn insert_ed25519(
        &mut self,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<(), CapabilityError> {
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| CapabilityError::InvalidTrustedKey)?;
        self.keys.insert((issuer_id.into(), key_id.into()), key);
        Ok(())
    }

    fn get(&self, issuer_id: &str, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(&(issuer_id.to_owned(), key_id.to_owned()))
    }
}

#[derive(Debug, Clone)]
struct UsageRecord {
    token_digest: String,
    uses: u32,
}

#[derive(Debug, Clone, Default)]
pub struct CapabilityAuthorizer {
    trusted_keys: TrustedKeyRegistry,
    usage: BTreeMap<(String, String), UsageRecord>,
}

impl CapabilityAuthorizer {
    #[must_use]
    pub const fn new(trusted_keys: TrustedKeyRegistry) -> Self {
        Self {
            trusted_keys,
            usage: BTreeMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &mut self,
        token_value: &Value,
        compiled_contract: &CompiledContract,
        compiled_plan: &CompiledPlan,
        trusted_now_epoch_s: u64,
        expected_executor_id: &str,
        expected_device_id: Option<&str>,
    ) -> Result<AuthorizationReceipt, CapabilityError> {
        let token: SignedCapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(CapabilityError::TokenDecode)?;
        validate_payload_shape(&token.payload)?;
        verify_signature(&self.trusted_keys, &token)?;
        validate_time(&token.payload, trusted_now_epoch_s)?;
        let step = validate_bindings(&token, compiled_contract, compiled_plan)?;
        validate_subject(&token.payload, expected_executor_id, expected_device_id)?;
        validate_grant(&token.payload.grant, &compiled_contract.permissions)?;

        let token_digest = canonical_json_sha256(token_value)?;
        let payload_value =
            serde_json::to_value(&token.payload).map_err(CapabilityError::TokenDecode)?;
        let payload_digest = canonical_json_sha256(&payload_value)?;
        let usage_key = (
            token.payload.issuer_id.clone(),
            token.payload.token_id.clone(),
        );
        let usage_record = self.usage.entry(usage_key).or_insert_with(|| UsageRecord {
            token_digest: token_digest.clone(),
            uses: 0,
        });
        if usage_record.token_digest != token_digest {
            return Err(CapabilityError::TokenIdCollision {
                token_id: token.payload.token_id,
            });
        }
        if usage_record.uses >= token.payload.max_uses {
            return Err(CapabilityError::UsageLimitExceeded);
        }
        usage_record.uses += 1;

        Ok(AuthorizationReceipt {
            token_id: token.payload.token_id,
            token_digest,
            payload_digest,
            issuer_id: token.payload.issuer_id,
            key_id: token.payload.key_id,
            executor_id: token.payload.subject.executor_id,
            device_id: token.payload.subject.device_id,
            plan_id: compiled_plan.plan_id.clone(),
            step_id: step.step_id.clone(),
            operator_id: step.operator_id.clone(),
            grant: token.payload.grant,
            authorized_at_epoch_s: trusted_now_epoch_s,
            use_number: usage_record.uses,
            max_uses: token.payload.max_uses,
        })
    }

    #[must_use]
    pub fn usage_count(&self, issuer_id: &str, token_id: &str) -> u32 {
        self.usage
            .get(&(issuer_id.to_owned(), token_id.to_owned()))
            .map_or(0, |record| record.uses)
    }
}

fn validate_payload_shape(payload: &CapabilityTokenPayload) -> Result<(), CapabilityError> {
    if payload.schema_version != SUPPORTED_TOKEN_SCHEMA {
        return Err(CapabilityError::UnsupportedSchemaVersion {
            actual: payload.schema_version.clone(),
            expected: SUPPORTED_TOKEN_SCHEMA,
        });
    }
    if payload.max_uses == 0 {
        return Err(CapabilityError::InvalidMaxUses);
    }
    if payload.nonce.len() < 16 {
        return Err(CapabilityError::NonceTooShort);
    }
    Ok(())
}

fn verify_signature(
    keys: &TrustedKeyRegistry,
    token: &SignedCapabilityToken,
) -> Result<(), CapabilityError> {
    let key = keys
        .get(&token.payload.issuer_id, &token.payload.key_id)
        .ok_or_else(|| CapabilityError::UnknownTrustedKey {
            issuer_id: token.payload.issuer_id.clone(),
            key_id: token.payload.key_id.clone(),
        })?;
    let payload_value =
        serde_json::to_value(&token.payload).map_err(CapabilityError::TokenDecode)?;
    let message = canonical_json_bytes(&payload_value)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&token.signature.value)
        .map_err(|_| CapabilityError::InvalidSignatureEncoding)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| CapabilityError::InvalidSignatureLength)?;
    key.verify_strict(&message, &signature)
        .map_err(|_| CapabilityError::SignatureVerificationFailed)
}

fn validate_time(
    payload: &CapabilityTokenPayload,
    trusted_now_epoch_s: u64,
) -> Result<(), CapabilityError> {
    if payload.issued_at_epoch_s > payload.not_before_epoch_s
        || payload.not_before_epoch_s >= payload.expires_at_epoch_s
        || payload.issued_at_epoch_s >= payload.expires_at_epoch_s
    {
        return Err(CapabilityError::InvalidTemporalBounds);
    }
    if payload.issued_at_epoch_s > trusted_now_epoch_s {
        return Err(CapabilityError::IssuedInFuture);
    }
    if trusted_now_epoch_s < payload.not_before_epoch_s {
        return Err(CapabilityError::NotYetValid);
    }
    if trusted_now_epoch_s >= payload.expires_at_epoch_s {
        return Err(CapabilityError::Expired);
    }
    Ok(())
}

fn validate_bindings<'a>(
    token: &SignedCapabilityToken,
    compiled_contract: &CompiledContract,
    compiled_plan: &'a CompiledPlan,
) -> Result<&'a PlanStep, CapabilityError> {
    let bindings = &token.payload.bindings;
    if bindings.contract_digest != compiled_contract.seal.contract_digest {
        return Err(CapabilityError::ContractDigestMismatch);
    }
    if bindings.capsule_digest != compiled_contract.seal.capsule_digest {
        return Err(CapabilityError::CapsuleDigestMismatch);
    }
    if bindings.plan_id != compiled_plan.plan_id {
        return Err(CapabilityError::PlanIdMismatch);
    }
    if bindings.plan_digest != compiled_plan.plan_digest {
        return Err(CapabilityError::PlanDigestMismatch);
    }
    let step = compiled_plan
        .steps
        .iter()
        .find(|step| step.step_id == bindings.step_id)
        .ok_or_else(|| CapabilityError::UnknownPlanStep(bindings.step_id.clone()))?;
    if step.operator_id != bindings.operator_id {
        return Err(CapabilityError::OperatorMismatch);
    }
    if !step.capability_token_ids.contains(&token.payload.token_id) {
        return Err(CapabilityError::TokenNotDeclaredByStep);
    }
    Ok(step)
}

fn validate_subject(
    payload: &CapabilityTokenPayload,
    expected_executor_id: &str,
    expected_device_id: Option<&str>,
) -> Result<(), CapabilityError> {
    if payload.subject.executor_id != expected_executor_id {
        return Err(CapabilityError::ExecutorMismatch {
            actual: payload.subject.executor_id.clone(),
            expected: expected_executor_id.to_owned(),
        });
    }
    if payload.subject.device_id.as_deref() != expected_device_id {
        return Err(CapabilityError::DeviceMismatch);
    }
    Ok(())
}

fn validate_grant(
    grant: &CapabilityGrant,
    permissions: &[ContractPermission],
) -> Result<(), CapabilityError> {
    let permitted = permissions.iter().any(|permission| {
        permission.capability == grant.capability
            && permission.resource == grant.resource
            && permission.access == grant.access
            && permission.constraints == grant.constraints
    });
    if permitted {
        Ok(())
    } else {
        Err(CapabilityError::GrantExceedsContract)
    }
}
