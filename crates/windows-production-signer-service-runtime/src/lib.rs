#![forbid(unsafe_code)]

use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_production_key_governance_runtime::{
    ProductionKeyGovernanceError, ProductionKeyRegistry, ProductionKeyTrustBinding,
};
use ergaxiom_windows_production_signer_protocol_runtime::{
    ProductionSignerEnvelope, ProductionSignerProtocolError, ProductionSignerRequest,
    ProductionSignerResponse, ProductionSignerSuccess,
};
use ergaxiom_windows_production_signer_runtime::{
    AuthenticatedCallerIdentity, HardwareKeyDescriptor, HardwareSignature, ProductionKeyIdentity,
    ProductionKeyPolicy, ProductionSignerError, SignerRequestBinding, SignerServiceIdentity,
    validate_identifier, validate_sha256,
};
use ergaxiom_windows_signer_service_identity_runtime::{
    CALLER_AUTHORIZATION_RECEIPT_SCHEMA, CallerAuthorizationReceipt, SignerCallerAllowlist,
    SignerIdentityAuthorizer, SignerIdentityError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSignerTrustSnapshot {
    pub identity: ProductionKeyIdentity,
    pub public_key_digest: String,
    pub allowlist_revision: u64,
    pub allowlist_digest: String,
    pub caller_identity_digest: String,
    pub signer_service_identity_digest: String,
}

impl ProductionSignerTrustSnapshot {
    pub fn validate_for(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<(), ProductionSignerServiceError> {
        policy.validate()?;
        self.identity.validate()?;
        if self.identity != policy.identity {
            return Err(ProductionSignerServiceError::TrustIdentityMismatch);
        }
        validate_sha256(&self.public_key_digest)?;
        validate_sha256(&self.allowlist_digest)?;
        validate_sha256(&self.caller_identity_digest)?;
        validate_sha256(&self.signer_service_identity_digest)?;
        if self.allowlist_revision == 0 {
            return Err(ProductionSignerServiceError::InvalidTrustAllowlistRevision);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedProductionSignerTrustSnapshot {
    pub signer: ProductionSignerTrustSnapshot,
    pub key: ProductionKeyTrustBinding,
}

impl GovernedProductionSignerTrustSnapshot {
    pub fn validate_for(
        &self,
        policy: &ProductionKeyPolicy,
        registry: &ProductionKeyRegistry,
        signed_at_epoch_s: u64,
    ) -> Result<(), ProductionSignerServiceError> {
        self.signer.validate_for(policy)?;
        self.key.validate_shape()?;
        if self.key.identity != self.signer.identity || self.key.identity != policy.identity {
            return Err(ProductionSignerServiceError::TrustIdentityMismatch);
        }
        if self.key.public_key_digest != self.signer.public_key_digest {
            return Err(ProductionSignerServiceError::TrustPublicKeyDigestMismatch);
        }
        let record = registry.verify_binding(&self.key, signed_at_epoch_s)?;
        if record.public_key_digest != self.signer.public_key_digest {
            return Err(ProductionSignerServiceError::TrustPublicKeyDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedProductionSignerPackage {
    pub caller_authorization: CallerAuthorizationReceipt,
    pub signer_response: ProductionSignerResponse,
}

impl AuthorizedProductionSignerPackage {
    pub fn verify(
        &self,
        caller: &AuthenticatedCallerIdentity,
        service_identity: &SignerServiceIdentity,
        allowlist: &SignerCallerAllowlist,
    ) -> Result<(), ProductionSignerServiceError> {
        let policy = policy_for_identity(response_identity(&self.signer_response)?)?;
        self.caller_authorization
            .validate(caller, service_identity, allowlist)?;
        let envelope = self.signer_response.verify_production_eligible(&policy)?;
        validate_authorization_response_binding(&self.caller_authorization, &envelope, &policy)?;
        Ok(())
    }

    pub fn verify_trusted(
        &self,
        trust: &ProductionSignerTrustSnapshot,
    ) -> Result<ProductionSignerEnvelope, ProductionSignerServiceError> {
        let identity = response_identity(&self.signer_response)?;
        let policy = policy_for_identity(identity)?;
        trust.validate_for(&policy)?;
        validate_authorization_receipt_seal(&self.caller_authorization)?;
        if identity != &trust.identity {
            return Err(ProductionSignerServiceError::TrustIdentityMismatch);
        }
        let descriptor = response_descriptor(&self.signer_response)?;
        if descriptor.public_key_digest != trust.public_key_digest {
            return Err(ProductionSignerServiceError::TrustPublicKeyDigestMismatch);
        }
        if self.caller_authorization.allowlist_revision != trust.allowlist_revision
            || self.caller_authorization.allowlist_digest != trust.allowlist_digest
        {
            return Err(ProductionSignerServiceError::TrustAllowlistMismatch);
        }
        if self.caller_authorization.caller_identity_digest != trust.caller_identity_digest {
            return Err(ProductionSignerServiceError::TrustCallerIdentityMismatch);
        }
        if self.caller_authorization.signer_service_identity_digest
            != trust.signer_service_identity_digest
        {
            return Err(ProductionSignerServiceError::TrustServiceIdentityMismatch);
        }
        let envelope = self.signer_response.verify_production_eligible(&policy)?;
        validate_authorization_response_binding(&self.caller_authorization, &envelope, &policy)?;
        if envelope.binding.caller_identity_digest != trust.caller_identity_digest {
            return Err(ProductionSignerServiceError::TrustCallerIdentityMismatch);
        }
        if envelope.binding.signer_service_identity_digest != trust.signer_service_identity_digest {
            return Err(ProductionSignerServiceError::TrustServiceIdentityMismatch);
        }
        Ok(envelope)
    }

    pub fn verify_governed(
        &self,
        trust: &GovernedProductionSignerTrustSnapshot,
        registry: &ProductionKeyRegistry,
        signed_at_epoch_s: u64,
    ) -> Result<ProductionSignerEnvelope, ProductionSignerServiceError> {
        let envelope = self.verify_trusted(&trust.signer)?;
        let policy = policy_for_identity(&envelope.request.identity)?;
        trust.validate_for(&policy, registry, signed_at_epoch_s)?;
        let descriptor = response_descriptor(&self.signer_response)?;
        if descriptor.public_key_digest != trust.key.public_key_digest {
            return Err(ProductionSignerServiceError::TrustPublicKeyDigestMismatch);
        }
        Ok(envelope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("hardware signer backend rejected operation with code {code}")]
pub struct HardwareSignerBackendError {
    pub code: &'static str,
}

impl HardwareSignerBackendError {
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

pub trait HardwareSignerBackend {
    fn descriptor(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError>;

    fn sign_sha256_digest(
        &self,
        policy: &ProductionKeyPolicy,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, HardwareSignerBackendError>;
}

#[derive(Debug)]
pub struct ProductionSignerService<B> {
    backend: B,
    service_identity: SignerServiceIdentity,
    allowlist: SignerCallerAllowlist,
    identity_authorizer: SignerIdentityAuthorizer,
}

impl<B> ProductionSignerService<B>
where
    B: HardwareSignerBackend,
{
    pub fn new(
        backend: B,
        service_identity: SignerServiceIdentity,
        allowlist: SignerCallerAllowlist,
    ) -> Result<Self, ProductionSignerServiceError> {
        service_identity.validate()?;
        allowlist.validate()?;
        Ok(Self {
            backend,
            service_identity,
            allowlist,
            identity_authorizer: SignerIdentityAuthorizer::default(),
        })
    }

    pub fn handle_authenticated(
        &mut self,
        request: &ProductionSignerRequest,
        caller: &AuthenticatedCallerIdentity,
        trusted_now_epoch_s: u64,
    ) -> Result<AuthorizedProductionSignerPackage, ProductionSignerServiceError> {
        let policy = policy_for_identity(&request.identity)?;
        request.validate_for(&policy)?;
        let request_digest = request.digest_for(&policy)?;

        // Consume caller authorization and replay state before any backend operation.
        // A backend failure must not make the same request replayable.
        let caller_authorization = self.identity_authorizer.authorize(
            caller,
            &self.service_identity,
            &self.allowlist,
            &request_digest,
            trusted_now_epoch_s,
        )?;

        let binding =
            SignerRequestBinding::build(request_digest, caller, &self.service_identity, &policy)?;
        let envelope = request.envelope(&policy, binding.clone())?;
        let envelope_digest = envelope.digest_for(&policy)?;

        let descriptor = self.backend.descriptor(&policy)?;
        descriptor.validate_for(&policy)?;
        let signature =
            self.backend
                .sign_sha256_digest(&policy, &descriptor, &binding, &envelope_digest)?;
        signature.validate_for(&descriptor, &binding)?;

        let signer_response = ProductionSignerResponse::success(
            request.request_id.clone(),
            ProductionSignerSuccess {
                descriptor,
                envelope,
                envelope_digest,
                signature,
            },
        );
        signer_response.verify_production_eligible(&policy)?;
        let package = AuthorizedProductionSignerPackage {
            caller_authorization,
            signer_response,
        };
        package.verify(caller, &self.service_identity, &self.allowlist)?;
        Ok(package)
    }

    #[must_use]
    pub const fn service_identity(&self) -> &SignerServiceIdentity {
        &self.service_identity
    }

    #[must_use]
    pub const fn allowlist(&self) -> &SignerCallerAllowlist {
        &self.allowlist
    }
}

pub fn policy_for_identity(
    identity: &ProductionKeyIdentity,
) -> Result<ProductionKeyPolicy, ProductionSignerServiceError> {
    identity.validate()?;
    match identity.role {
        IssuerRole::Capability => Ok(ProductionKeyPolicy::capability()),
        IssuerRole::Attestation => Ok(ProductionKeyPolicy::attestation()),
        IssuerRole::Execution | IssuerRole::Normalization | IssuerRole::Release => {
            Err(ProductionSignerServiceError::UnsupportedIdentity)
        }
    }
}

fn validate_authorization_receipt_seal(
    authorization: &CallerAuthorizationReceipt,
) -> Result<(), ProductionSignerServiceError> {
    if authorization.schema_version != CALLER_AUTHORIZATION_RECEIPT_SCHEMA {
        return Err(ProductionSignerServiceError::Identity(
            SignerIdentityError::UnsupportedReceiptSchema,
        ));
    }
    validate_identifier("caller_id", &authorization.caller_id)?;
    validate_sha256(&authorization.request_digest)?;
    validate_sha256(&authorization.caller_identity_digest)?;
    validate_sha256(&authorization.signer_service_identity_digest)?;
    validate_sha256(&authorization.allowlist_digest)?;
    validate_sha256(&authorization.receipt_digest)?;
    if authorization.allowlist_revision == 0 {
        return Err(ProductionSignerServiceError::InvalidTrustAllowlistRevision);
    }
    if authorization.authorized_at_epoch_s == 0 {
        return Err(ProductionSignerServiceError::Identity(
            SignerIdentityError::InvalidAuthorizationTime,
        ));
    }
    let mut value = serde_json::to_value(authorization)?;
    let object = value
        .as_object_mut()
        .ok_or(ProductionSignerServiceError::InvalidCanonicalObject)?;
    object.insert(
        "receipt_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    if authorization.receipt_digest != canonical_json_sha256(&value)? {
        return Err(ProductionSignerServiceError::Identity(
            SignerIdentityError::AuthorizationReceiptDigestMismatch,
        ));
    }
    Ok(())
}

fn validate_authorization_response_binding(
    authorization: &CallerAuthorizationReceipt,
    envelope: &ProductionSignerEnvelope,
    policy: &ProductionKeyPolicy,
) -> Result<(), ProductionSignerServiceError> {
    if envelope.request.digest_for(policy)? != authorization.request_digest
        || envelope.binding.caller_identity_digest != authorization.caller_identity_digest
        || envelope.binding.signer_service_identity_digest
            != authorization.signer_service_identity_digest
    {
        return Err(ProductionSignerServiceError::AuthorizationResponseBindingMismatch);
    }
    Ok(())
}

fn response_identity(
    response: &ProductionSignerResponse,
) -> Result<&ProductionKeyIdentity, ProductionSignerServiceError> {
    Ok(&response_descriptor(response)?.identity)
}

fn response_descriptor(
    response: &ProductionSignerResponse,
) -> Result<&HardwareKeyDescriptor, ProductionSignerServiceError> {
    match response {
        ProductionSignerResponse::Success { result, .. } => Ok(&result.descriptor),
        ProductionSignerResponse::Error { .. } => {
            Err(ProductionSignerServiceError::ResponseDoesNotContainSignature)
        }
    }
}

#[derive(Debug, Error)]
pub enum ProductionSignerServiceError {
    #[error("production signer identity is not supported by the service")]
    UnsupportedIdentity,
    #[error("production signer response does not contain a signature")]
    ResponseDoesNotContainSignature,
    #[error("caller authorization and signer response bindings do not match")]
    AuthorizationResponseBindingMismatch,
    #[error("production signer trust identity does not match the fixed policy")]
    TrustIdentityMismatch,
    #[error("production signer trust public-key digest does not match")]
    TrustPublicKeyDigestMismatch,
    #[error("production signer trust allowlist revision is invalid")]
    InvalidTrustAllowlistRevision,
    #[error("production signer trust allowlist binding does not match")]
    TrustAllowlistMismatch,
    #[error("production signer trusted caller identity does not match")]
    TrustCallerIdentityMismatch,
    #[error("production signer trusted service identity does not match")]
    TrustServiceIdentityMismatch,
    #[error("production signer canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("production signer JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    Backend(#[from] HardwareSignerBackendError),
    #[error(transparent)]
    Protocol(#[from] ProductionSignerProtocolError),
    #[error(transparent)]
    Production(#[from] ProductionSignerError),
    #[error(transparent)]
    Governance(#[from] ProductionKeyGovernanceError),
    #[error(transparent)]
    Identity(#[from] SignerIdentityError),
}
