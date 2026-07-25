#![forbid(unsafe_code)]

use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_windows_production_signer_protocol_runtime::{
    ProductionSignerProtocolError, ProductionSignerRequest, ProductionSignerResponse,
    ProductionSignerSuccess,
};
use ergaxiom_windows_production_signer_runtime::{
    AuthenticatedCallerIdentity, HardwareKeyDescriptor, HardwareSignature, ProductionKeyIdentity,
    ProductionKeyPolicy, ProductionSignerError, SignerRequestBinding, SignerServiceIdentity,
};
use ergaxiom_windows_signer_service_identity_runtime::{
    CallerAuthorizationReceipt, SignerCallerAllowlist, SignerIdentityAuthorizer,
    SignerIdentityError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
        let envelope = self
            .signer_response
            .verify_production_eligible(&policy)?;
        if envelope.request.digest_for(&policy)? != self.caller_authorization.request_digest
            || envelope.binding.caller_identity_digest
                != self.caller_authorization.caller_identity_digest
            || envelope.binding.signer_service_identity_digest
                != self.caller_authorization.signer_service_identity_digest
        {
            return Err(ProductionSignerServiceError::AuthorizationResponseBindingMismatch);
        }
        Ok(())
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

        let binding = SignerRequestBinding::build(
            request_digest,
            caller,
            &self.service_identity,
            &policy,
        )?;
        let envelope = request.envelope(&policy, binding.clone())?;
        let envelope_digest = envelope.digest_for(&policy)?;

        let descriptor = self.backend.descriptor(&policy)?;
        descriptor.validate_for(&policy)?;
        let signature = self.backend.sign_sha256_digest(
            &policy,
            &descriptor,
            &binding,
            &envelope_digest,
        )?;
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

fn response_identity(
    response: &ProductionSignerResponse,
) -> Result<&ProductionKeyIdentity, ProductionSignerServiceError> {
    match response {
        ProductionSignerResponse::Success { result, .. } => Ok(&result.descriptor.identity),
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
    #[error(transparent)]
    Backend(#[from] HardwareSignerBackendError),
    #[error(transparent)]
    Protocol(#[from] ProductionSignerProtocolError),
    #[error(transparent)]
    Production(#[from] ProductionSignerError),
    #[error(transparent)]
    Identity(#[from] SignerIdentityError),
}
