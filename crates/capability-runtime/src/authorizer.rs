use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use ergaxiom_contract_runtime::{CompiledContract, ContractPermission};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_operator_plan_runtime::{CompiledPlan, PlanStep};
use ergaxiom_proof_kernel::{HashingError, canonical_json_bytes, canonical_json_sha256};
use ergaxiom_windows_signer_protocol_runtime::{
    SignerProtocolError, SignerResponse, SignerSuccess, decode_hex_32,
};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    AuthorizationReceipt, CapabilityGrant, CapabilityTokenPayload, SignedCapabilityToken,
    SignerBoundCapabilityToken,
};

const SUPPORTED_TOKEN_SCHEMA: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("failed to decode capability token: {0}")]
    TokenDecode(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    SignerProtocol(#[from] SignerProtocolError),
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
    #[error("signer-bound token was not signed with the Capability issuer role")]
    SignerRoleMismatch,
    #[error("signer-bound token issuer does not match the payload issuer")]
    SignerIssuerMismatch,
    #[error("signer-bound token key ID does not match the payload key ID")]
    SignerKeyMismatch,
    #[error("signer-bound token digest does not match the canonical payload digest")]
    SignerDigestMismatch,
    #[error("signer response public key does not match the trusted registry key")]
    SignerPublicKeyMismatch,
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
        self.authorize_verified_payload(
            token_value,
            token.payload,
            compiled_contract,
            compiled_plan,
            trusted_now_epoch_s,
            expected_executor_id,
            expected_device_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_signer_bound(
        &mut self,
        token_value: &Value,
        compiled_contract: &CompiledContract,
        compiled_plan: &CompiledPlan,
        trusted_now_epoch_s: u64,
        expected_executor_id: &str,
        expected_device_id: Option<&str>,
    ) -> Result<AuthorizationReceipt, CapabilityError> {
        let token: SignerBoundCapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(CapabilityError::TokenDecode)?;
        validate_payload_shape(&token.payload)?;
        self.verify_signer_bound_signature(&token)?;
        self.authorize_verified_payload(
            token_value,
            token.payload,
            compiled_contract,
            compiled_plan,
            trusted_now_epoch_s,
            expected_executor_id,
            expected_device_id,
        )
    }

    pub fn verify_signer_bound_signature(
        &self,
        token: &SignerBoundCapabilityToken,
    ) -> Result<(), CapabilityError> {
        let key = self
            .trusted_keys
            .get(&token.payload.issuer_id, &token.payload.key_id)
            .ok_or_else(|| CapabilityError::UnknownTrustedKey {
                issuer_id: token.payload.issuer_id.clone(),
                key_id: token.payload.key_id.clone(),
            })?;
        let envelope = token.signer_response.verify_digest_signature()?;
        if envelope.role != IssuerRole::Capability {
            return Err(CapabilityError::SignerRoleMismatch);
        }
        if envelope.issuer_id != token.payload.issuer_id {
            return Err(CapabilityError::SignerIssuerMismatch);
        }
        if envelope.key_id != token.payload.key_id {
            return Err(CapabilityError::SignerKeyMismatch);
        }
        let payload_value =
            serde_json::to_value(&token.payload).map_err(CapabilityError::TokenDecode)?;
        if envelope.digest != canonical_json_sha256(&payload_value)? {
            return Err(CapabilityError::SignerDigestMismatch);
        }
        let response_public_key = match &token.signer_response {
            SignerResponse::Success {
                result: SignerSuccess::DigestSigned { public_key_hex, .. },
                ..
            } => decode_hex_32(public_key_hex)?,
            SignerResponse::Error { .. }
            | SignerResponse::Success {
                result: SignerSuccess::KeyInitialized { .. } | SignerSuccess::PublicKey { .. },
                ..
            } => {
                return Err(CapabilityError::SignerProtocol(
                    SignerProtocolError::ResponseDoesNotContainSignature,
                ));
            }
        };
        if response_public_key != key.to_bytes() {
            return Err(CapabilityError::SignerPublicKeyMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn usage_count(&self, issuer_id: &str, token_id: &str) -> u32 {
        self.usage
            .get(&(issuer_id.to_owned(), token_id.to_owned()))
            .map_or(0, |record| record.uses)
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_verified_payload(
        &mut self,
        token_value: &Value,
        payload: CapabilityTokenPayload,
        compiled_contract: &CompiledContract,
        compiled_plan: &CompiledPlan,
        trusted_now_epoch_s: u64,
        expected_executor_id: &str,
        expected_device_id: Option<&str>,
    ) -> Result<AuthorizationReceipt, CapabilityError> {
        validate_time(&payload, trusted_now_epoch_s)?;
        let step = validate_bindings(&payload, compiled_contract, compiled_plan)?;
        validate_subject(&payload, expected_executor_id, expected_device_id)?;
        validate_grant(&payload.grant, &compiled_contract.permissions)?;

        let token_digest = canonical_json_sha256(token_value)?;
        let payload_value =
            serde_json::to_value(&payload).map_err(CapabilityError::TokenDecode)?;
        let payload_digest = canonical_json_sha256(&payload_value)?;
        let usage_key = (payload.issuer_id.clone(), payload.token_id.clone());
        let usage_record = self.usage.entry(usage_key).or_insert_with(|| UsageRecord {
            token_digest: token_digest.clone(),
            uses: 0,
        });
        if usage_record.token_digest != token_digest {
            return Err(CapabilityError::TokenIdCollision {
                token_id: payload.token_id,
            });
        }
        if usage_record.uses >= payload.max_uses {
            return Err(CapabilityError::UsageLimitExceeded);
        }
        usage_record.uses += 1;

        Ok(AuthorizationReceipt {
            token_id: payload.token_id,
            token_digest,
            payload_digest,
            issuer_id: payload.issuer_id,
            key_id: payload.key_id,
            executor_id: payload.subject.executor_id,
            device_id: payload.subject.device_id,
            contract_digest: compiled_plan.contract_digest.clone(),
            capsule_digest: compiled_plan.capsule_digest.clone(),
            plan_id: compiled_plan.plan_id.clone(),
            plan_digest: compiled_plan.plan_digest.clone(),
            step_id: step.step_id.clone(),
            operator_id: step.operator_id.clone(),
            grant: payload.grant,
            authorized_at_epoch_s: trusted_now_epoch_s,
            use_number: usage_record.uses,
            max_uses: payload.max_uses,
        })
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
    payload: &CapabilityTokenPayload,
    compiled_contract: &CompiledContract,
    compiled_plan: &'a CompiledPlan,
) -> Result<&'a PlanStep, CapabilityError> {
    let bindings = &payload.bindings;
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
    if !step.capability_token_ids.contains(&payload.token_id) {
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
