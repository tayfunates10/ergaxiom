use ergaxiom_contract_runtime::PermissionAccess;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedCapabilityToken {
    pub payload: CapabilityTokenPayload,
    pub signature: TokenSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityTokenPayload {
    pub schema_version: String,
    pub token_id: String,
    pub issuer_id: String,
    pub key_id: String,
    pub subject: CapabilitySubject,
    pub issued_at_epoch_s: u64,
    pub not_before_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub max_uses: u32,
    pub nonce: String,
    pub bindings: CapabilityBindings,
    pub grant: CapabilityGrant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySubject {
    pub executor_id: String,
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityBindings {
    pub contract_digest: String,
    pub capsule_digest: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub step_id: String,
    pub operator_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub capability: String,
    pub resource: String,
    pub access: PermissionAccess,
    pub constraints: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSignature {
    pub algorithm: SignatureAlgorithm,
    pub encoding: SignatureEncoding,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureEncoding {
    Base64url,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationReceipt {
    pub token_id: String,
    pub token_digest: String,
    pub payload_digest: String,
    pub issuer_id: String,
    pub key_id: String,
    pub executor_id: String,
    pub device_id: Option<String>,
    pub contract_digest: String,
    pub capsule_digest: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub step_id: String,
    pub operator_id: String,
    pub grant: CapabilityGrant,
    pub authorized_at_epoch_s: u64,
    pub use_number: u32,
    pub max_uses: u32,
}
