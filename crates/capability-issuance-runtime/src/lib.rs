#![forbid(unsafe_code)]

use ergaxiom_capability_runtime::{
    CapabilityBindings, CapabilityGrant, CapabilitySubject, CapabilityTokenPayload,
    ProductionSignerBoundCapabilityToken, SignerBoundCapabilityToken,
};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_production_signer_protocol_runtime::{
    ProductionSignerProtocolError, ProductionSignerRequest,
};
use ergaxiom_windows_production_signer_runtime::ProductionKeyPolicy;
use ergaxiom_windows_production_signer_service_runtime::{
    AuthorizedProductionSignerPackage, ProductionSignerServiceError, ProductionSignerTrustSnapshot,
};
use ergaxiom_windows_production_signer_transport_runtime::{
    ProductionSignerPipeClient, ProductionSignerTransportError,
};
use ergaxiom_windows_signer_client_runtime::{SignerClientError, SignerProcessClient};
use ergaxiom_windows_signer_protocol_runtime::{
    SignerProtocolError, SignerRequest, SignerResponse, SignerSuccess, decode_hex_32,
    validate_identifier, validate_sha256,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CAPABILITY_TOKEN_SCHEMA: &str = "0.1.0";
pub const CAPABILITY_ISSUER_ID: &str = "ergaxiom.policy-authority";
pub const CAPABILITY_KEY_ID: &str = "capability-key-v1";
const REQUEST_ID_PREFIX: &str = "capability.issue.";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityTokenDraft {
    pub token_id: String,
    pub subject: CapabilitySubject,
    pub issued_at_epoch_s: u64,
    pub not_before_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub max_uses: u32,
    pub nonce: String,
    pub bindings: CapabilityBindings,
    pub grant: CapabilityGrant,
}

pub trait CapabilitySignerTransport {
    fn invoke(&self, request: &SignerRequest) -> Result<SignerResponse, CapabilityIssuanceError>;
}

impl CapabilitySignerTransport for SignerProcessClient {
    fn invoke(&self, request: &SignerRequest) -> Result<SignerResponse, CapabilityIssuanceError> {
        SignerProcessClient::invoke(self, request).map_err(CapabilityIssuanceError::SignerClient)
    }
}

pub trait ProductionCapabilitySignerTransport {
    fn invoke(
        &self,
        request: &ProductionSignerRequest,
    ) -> Result<AuthorizedProductionSignerPackage, CapabilityIssuanceError>;
}

impl ProductionCapabilitySignerTransport for ProductionSignerPipeClient {
    fn invoke(
        &self,
        request: &ProductionSignerRequest,
    ) -> Result<AuthorizedProductionSignerPackage, CapabilityIssuanceError> {
        ProductionSignerPipeClient::invoke(self, request)
            .map_err(CapabilityIssuanceError::ProductionTransport)
    }
}

#[derive(Debug, Clone)]
pub struct CapabilityIssuanceAuthority<T> {
    transport: T,
    expected_public_key: [u8; 32],
}

impl<T> CapabilityIssuanceAuthority<T>
where
    T: CapabilitySignerTransport,
{
    #[must_use]
    pub const fn new(transport: T, expected_public_key: [u8; 32]) -> Self {
        Self {
            transport,
            expected_public_key,
        }
    }

    pub fn issue(
        &self,
        draft: CapabilityTokenDraft,
    ) -> Result<SignerBoundCapabilityToken, CapabilityIssuanceError> {
        let payload = payload_from_draft(draft)?;
        let payload_digest = payload_digest(&payload)?;
        let request_id = request_id_for_payload(&payload_digest)?;
        let request = SignerRequest::sign_digest(
            request_id.clone(),
            IssuerRole::Capability,
            CAPABILITY_ISSUER_ID,
            CAPABILITY_KEY_ID,
            payload_digest.clone(),
        );
        let signer_response = self.transport.invoke(&request)?;
        let envelope = signer_response.verify_digest_signature()?;
        if envelope.request_id != request_id {
            return Err(CapabilityIssuanceError::SignerRequestIdMismatch);
        }
        if envelope.role != IssuerRole::Capability {
            return Err(CapabilityIssuanceError::SignerRoleMismatch);
        }
        if envelope.issuer_id != CAPABILITY_ISSUER_ID {
            return Err(CapabilityIssuanceError::SignerIssuerMismatch);
        }
        if envelope.key_id != CAPABILITY_KEY_ID {
            return Err(CapabilityIssuanceError::SignerKeyMismatch);
        }
        if envelope.digest != payload_digest {
            return Err(CapabilityIssuanceError::SignerDigestMismatch);
        }
        let response_public_key = response_public_key(&signer_response)?;
        if response_public_key != self.expected_public_key {
            return Err(CapabilityIssuanceError::SignerPublicKeyMismatch);
        }
        Ok(SignerBoundCapabilityToken {
            payload,
            signer_response,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProductionCapabilityIssuanceAuthority<T> {
    transport: T,
    trust: ProductionSignerTrustSnapshot,
}

impl<T> ProductionCapabilityIssuanceAuthority<T>
where
    T: ProductionCapabilitySignerTransport,
{
    pub fn new(
        transport: T,
        trust: ProductionSignerTrustSnapshot,
    ) -> Result<Self, CapabilityIssuanceError> {
        trust.validate_for(&ProductionKeyPolicy::capability())?;
        Ok(Self { transport, trust })
    }

    pub fn issue(
        &self,
        draft: CapabilityTokenDraft,
    ) -> Result<ProductionSignerBoundCapabilityToken, CapabilityIssuanceError> {
        let payload = payload_from_draft(draft)?;
        let payload_digest = payload_digest(&payload)?;
        let request_id = request_id_for_payload(&payload_digest)?;
        let policy = ProductionKeyPolicy::capability();
        let request = ProductionSignerRequest::sign_digest(
            request_id.clone(),
            &policy,
            payload_digest.clone(),
        )?;
        let signer_package = self.transport.invoke(&request)?;
        let envelope = signer_package.verify_trusted(&self.trust)?;
        if envelope.request.request_id != request_id {
            return Err(CapabilityIssuanceError::SignerRequestIdMismatch);
        }
        if envelope.request.identity.role != IssuerRole::Capability {
            return Err(CapabilityIssuanceError::SignerRoleMismatch);
        }
        if envelope.request.identity.issuer_id != CAPABILITY_ISSUER_ID {
            return Err(CapabilityIssuanceError::SignerIssuerMismatch);
        }
        if envelope.request.identity.key_id != CAPABILITY_KEY_ID {
            return Err(CapabilityIssuanceError::SignerKeyMismatch);
        }
        if envelope.request.digest != payload_digest {
            return Err(CapabilityIssuanceError::SignerDigestMismatch);
        }
        Ok(ProductionSignerBoundCapabilityToken {
            payload,
            signer_package,
        })
    }

    #[must_use]
    pub const fn trust(&self) -> &ProductionSignerTrustSnapshot {
        &self.trust
    }
}

pub fn request_id_for_payload(payload_digest: &str) -> Result<String, CapabilityIssuanceError> {
    validate_sha256(payload_digest)?;
    Ok(format!("{REQUEST_ID_PREFIX}{}", &payload_digest[..48]))
}

fn payload_from_draft(
    draft: CapabilityTokenDraft,
) -> Result<CapabilityTokenPayload, CapabilityIssuanceError> {
    validate_draft(&draft)?;
    Ok(CapabilityTokenPayload {
        schema_version: CAPABILITY_TOKEN_SCHEMA.to_owned(),
        token_id: draft.token_id,
        issuer_id: CAPABILITY_ISSUER_ID.to_owned(),
        key_id: CAPABILITY_KEY_ID.to_owned(),
        subject: draft.subject,
        issued_at_epoch_s: draft.issued_at_epoch_s,
        not_before_epoch_s: draft.not_before_epoch_s,
        expires_at_epoch_s: draft.expires_at_epoch_s,
        max_uses: draft.max_uses,
        nonce: draft.nonce,
        bindings: draft.bindings,
        grant: draft.grant,
    })
}

fn payload_digest(payload: &CapabilityTokenPayload) -> Result<String, CapabilityIssuanceError> {
    let payload_value =
        serde_json::to_value(payload).map_err(CapabilityIssuanceError::Serialization)?;
    Ok(canonical_json_sha256(&payload_value)?)
}

fn validate_draft(draft: &CapabilityTokenDraft) -> Result<(), CapabilityIssuanceError> {
    validate_identifier("token_id", &draft.token_id)?;
    validate_identifier("executor_id", &draft.subject.executor_id)?;
    if let Some(device_id) = &draft.subject.device_id {
        validate_identifier("device_id", device_id)?;
    }
    validate_identifier("plan_id", &draft.bindings.plan_id)?;
    validate_identifier("step_id", &draft.bindings.step_id)?;
    validate_identifier("operator_id", &draft.bindings.operator_id)?;
    validate_sha256(&draft.bindings.contract_digest)?;
    validate_sha256(&draft.bindings.capsule_digest)?;
    validate_sha256(&draft.bindings.plan_digest)?;
    if draft.issued_at_epoch_s > draft.not_before_epoch_s
        || draft.not_before_epoch_s >= draft.expires_at_epoch_s
        || draft.issued_at_epoch_s >= draft.expires_at_epoch_s
    {
        return Err(CapabilityIssuanceError::InvalidTemporalBounds);
    }
    if draft.max_uses == 0 {
        return Err(CapabilityIssuanceError::InvalidMaxUses);
    }
    if draft.nonce.len() < 16 {
        return Err(CapabilityIssuanceError::NonceTooShort);
    }
    Ok(())
}

fn response_public_key(response: &SignerResponse) -> Result<[u8; 32], CapabilityIssuanceError> {
    match response {
        SignerResponse::Success {
            result: SignerSuccess::DigestSigned { public_key_hex, .. },
            ..
        } => Ok(decode_hex_32(public_key_hex)?),
        SignerResponse::Error { .. }
        | SignerResponse::Success {
            result: SignerSuccess::KeyInitialized { .. } | SignerSuccess::PublicKey { .. },
            ..
        } => Err(CapabilityIssuanceError::SignerProtocol(
            SignerProtocolError::ResponseDoesNotContainSignature,
        )),
    }
}

#[derive(Debug, Error)]
pub enum CapabilityIssuanceError {
    #[error("signer process rejected capability issuance: {0}")]
    SignerClient(#[source] SignerClientError),
    #[error("production signer transport rejected capability issuance: {0}")]
    ProductionTransport(#[source] ProductionSignerTransportError),
    #[error("capability draft temporal bounds are invalid")]
    InvalidTemporalBounds,
    #[error("capability draft max_uses must be greater than zero")]
    InvalidMaxUses,
    #[error("capability draft nonce is too short")]
    NonceTooShort,
    #[error("signer response request ID does not match the internally derived request ID")]
    SignerRequestIdMismatch,
    #[error("signer response was not issued under the Capability role")]
    SignerRoleMismatch,
    #[error("signer response issuer does not match the fixed capability issuer")]
    SignerIssuerMismatch,
    #[error("signer response key ID does not match the fixed capability key")]
    SignerKeyMismatch,
    #[error("signer response digest does not match the canonical payload digest")]
    SignerDigestMismatch,
    #[error("signer response public key does not match the provisioned capability key")]
    SignerPublicKeyMismatch,
    #[error("failed to serialize capability payload: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    SignerProtocol(#[from] SignerProtocolError),
    #[error(transparent)]
    ProductionProtocol(#[from] ProductionSignerProtocolError),
    #[error(transparent)]
    ProductionSigner(#[from] ProductionSignerServiceError),
}
