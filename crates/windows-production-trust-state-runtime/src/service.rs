use ergaxiom_proof_kernel::canonical_json_sha256;
use ergaxiom_windows_production_key_governance_runtime::ProductionKeyStatus;
use ergaxiom_windows_production_signer_protocol_runtime::{
    ProductionSignerEnvelope, ProductionSignerRequest, ProductionSignerResponse,
};
use ergaxiom_windows_production_signer_runtime::{
    AuthenticatedCallerIdentity, HardwareKeyDescriptor, ProductionKeyIdentity, ProductionKeyPolicy,
    ProductionSignerError, SignerServiceIdentity, validate_identifier, validate_sha256,
};
use ergaxiom_windows_production_signer_service_runtime::{
    AuthorizedProductionSignerPackage, GovernedProductionSignerTrustSnapshot,
    HardwareSignerBackend, ProductionSignerService, ProductionSignerServiceError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{ProductionTrustStateBinding, ProductionTrustStateError, VerifiedProductionTrustState};

pub const PRODUCTION_SIGNER_DEPLOYMENT_POLICY_SCHEMA: &str = "0.1.0";
pub const TRUST_BOUND_SIGNER_SERVICE_IDENTITY_SCHEMA: &str = "0.1.0";
pub const DEPLOYED_PRODUCTION_SIGNER_PACKAGE_SCHEMA: &str = "0.1.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSignerDeploymentPolicy {
    pub schema_version: String,
    pub deployment_id: String,
    pub revision: u64,
    pub service_id: String,
    pub transport_id: String,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub enabled_identities: Vec<ProductionKeyIdentity>,
    pub policy_digest: String,
}

impl ProductionSignerDeploymentPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment_id: impl Into<String>,
        revision: u64,
        service_id: impl Into<String>,
        transport_id: impl Into<String>,
        max_request_bytes: u32,
        max_response_bytes: u32,
        mut enabled_identities: Vec<ProductionKeyIdentity>,
    ) -> Result<Self, DeployedProductionSignerError> {
        enabled_identities.sort_by(|left, right| {
            (left.role, left.issuer_id.as_str(), left.key_id.as_str()).cmp(&(
                right.role,
                right.issuer_id.as_str(),
                right.key_id.as_str(),
            ))
        });
        let mut policy = Self {
            schema_version: PRODUCTION_SIGNER_DEPLOYMENT_POLICY_SCHEMA.to_owned(),
            deployment_id: deployment_id.into(),
            revision,
            service_id: service_id.into(),
            transport_id: transport_id.into(),
            max_request_bytes,
            max_response_bytes,
            enabled_identities,
            policy_digest: String::new(),
        };
        policy.policy_digest = policy.expected_digest()?;
        policy.validate_seal()?;
        Ok(policy)
    }

    pub fn validate_seal(&self) -> Result<(), DeployedProductionSignerError> {
        if self.schema_version != PRODUCTION_SIGNER_DEPLOYMENT_POLICY_SCHEMA {
            return Err(DeployedProductionSignerError::UnsupportedDeploymentPolicySchema);
        }
        validate_identifier("deployment_id", &self.deployment_id)?;
        validate_identifier("service_id", &self.service_id)?;
        validate_identifier("transport_id", &self.transport_id)?;
        if self.revision == 0
            || self.max_request_bytes == 0
            || self.max_response_bytes == 0
            || self.max_request_bytes > 64 * 1024
            || self.max_response_bytes > 128 * 1024
            || self.enabled_identities.is_empty()
        {
            return Err(DeployedProductionSignerError::InvalidDeploymentPolicy);
        }
        let mut previous: Option<&ProductionKeyIdentity> = None;
        for identity in &self.enabled_identities {
            identity.validate()?;
            if previous.is_some_and(|previous| {
                (
                    previous.role,
                    previous.issuer_id.as_str(),
                    previous.key_id.as_str(),
                ) >= (
                    identity.role,
                    identity.issuer_id.as_str(),
                    identity.key_id.as_str(),
                )
            }) {
                return Err(DeployedProductionSignerError::DeploymentIdentitiesNotCanonical);
            }
            previous = Some(identity);
        }
        validate_sha256(&self.policy_digest)?;
        if self.policy_digest != self.expected_digest()? {
            return Err(DeployedProductionSignerError::DeploymentPolicyDigestMismatch);
        }
        Ok(())
    }

    pub fn permits(&self, identity: &ProductionKeyIdentity) -> bool {
        self.enabled_identities
            .binary_search_by(|candidate| {
                (
                    candidate.role,
                    candidate.issuer_id.as_str(),
                    candidate.key_id.as_str(),
                )
                    .cmp(&(
                        identity.role,
                        identity.issuer_id.as_str(),
                        identity.key_id.as_str(),
                    ))
            })
            .is_ok()
    }

    fn expected_digest(&self) -> Result<String, DeployedProductionSignerError> {
        digest_with_blank_field(self, "policy_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustBoundSignerServiceIdentity {
    pub schema_version: String,
    pub base_service_identity_digest: String,
    pub trust_state_binding_digest: String,
    pub deployment_policy_digest: String,
    pub identity_digest: String,
}

impl TrustBoundSignerServiceIdentity {
    fn build(
        base: &SignerServiceIdentity,
        trust_state: &ProductionTrustStateBinding,
        deployment_policy: &ProductionSignerDeploymentPolicy,
    ) -> Result<Self, DeployedProductionSignerError> {
        base.validate()?;
        trust_state.validate_seal()?;
        deployment_policy.validate_seal()?;
        if base.service_id != deployment_policy.service_id
            || trust_state.deployment_id != deployment_policy.deployment_id
            || trust_state.service_policy_revision != deployment_policy.revision
            || trust_state.service_policy_digest != deployment_policy.policy_digest
            || trust_state.signer_service_executable_digest != base.executable_sha256
        {
            return Err(DeployedProductionSignerError::ServiceTrustStateMismatch);
        }
        let mut identity = Self {
            schema_version: TRUST_BOUND_SIGNER_SERVICE_IDENTITY_SCHEMA.to_owned(),
            base_service_identity_digest: base.digest()?,
            trust_state_binding_digest: trust_state.binding_digest.clone(),
            deployment_policy_digest: deployment_policy.policy_digest.clone(),
            identity_digest: String::new(),
        };
        identity.identity_digest = identity.expected_digest()?;
        identity.validate_seal()?;
        Ok(identity)
    }

    pub fn validate_seal(&self) -> Result<(), DeployedProductionSignerError> {
        if self.schema_version != TRUST_BOUND_SIGNER_SERVICE_IDENTITY_SCHEMA {
            return Err(DeployedProductionSignerError::UnsupportedBoundServiceIdentitySchema);
        }
        validate_sha256(&self.base_service_identity_digest)?;
        validate_sha256(&self.trust_state_binding_digest)?;
        validate_sha256(&self.deployment_policy_digest)?;
        validate_sha256(&self.identity_digest)?;
        if self.identity_digest != self.expected_digest()? {
            return Err(DeployedProductionSignerError::BoundServiceIdentityDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, DeployedProductionSignerError> {
        digest_with_blank_field(self, "identity_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployedAuthorizedProductionSignerPackage {
    pub schema_version: String,
    pub trust_state: ProductionTrustStateBinding,
    pub signer_service_identity: TrustBoundSignerServiceIdentity,
    pub key_generation: u64,
    pub signer_package: AuthorizedProductionSignerPackage,
    pub package_digest: String,
}

impl DeployedAuthorizedProductionSignerPackage {
    fn build(
        accepted: &VerifiedProductionTrustState,
        signer_service_identity: TrustBoundSignerServiceIdentity,
        key_generation: u64,
        signer_package: AuthorizedProductionSignerPackage,
    ) -> Result<Self, DeployedProductionSignerError> {
        let mut package = Self {
            schema_version: DEPLOYED_PRODUCTION_SIGNER_PACKAGE_SCHEMA.to_owned(),
            trust_state: accepted.binding().clone(),
            signer_service_identity,
            key_generation,
            signer_package,
            package_digest: String::new(),
        };
        package.package_digest = package.expected_digest()?;
        package.validate_seal()?;
        Ok(package)
    }

    pub fn validate_seal(&self) -> Result<(), DeployedProductionSignerError> {
        if self.schema_version != DEPLOYED_PRODUCTION_SIGNER_PACKAGE_SCHEMA {
            return Err(DeployedProductionSignerError::UnsupportedDeployedPackageSchema);
        }
        self.trust_state.validate_seal()?;
        self.signer_service_identity.validate_seal()?;
        if self.key_generation == 0 {
            return Err(DeployedProductionSignerError::KeyGenerationMismatch);
        }
        let ProductionSignerResponse::Success { result, .. } = &self.signer_package.signer_response
        else {
            return Err(DeployedProductionSignerError::SignedTrustStateBindingMismatch);
        };
        if result
            .envelope
            .binding
            .trust_state_binding_digest
            .as_deref()
            != Some(self.trust_state.binding_digest.as_str())
        {
            return Err(DeployedProductionSignerError::SignedTrustStateBindingMismatch);
        }
        if self.package_digest != self.expected_digest()? {
            return Err(DeployedProductionSignerError::DeployedPackageDigestMismatch);
        }
        Ok(())
    }

    pub fn verify_deployed(
        &self,
        accepted: &VerifiedProductionTrustState,
        deployment_policy: &ProductionSignerDeploymentPolicy,
        base_service_identity: &SignerServiceIdentity,
        governed_trust: &GovernedProductionSignerTrustSnapshot,
        signed_at_epoch_s: u64,
    ) -> Result<ProductionSignerEnvelope, DeployedProductionSignerError> {
        self.validate_seal()?;
        deployment_policy.validate_seal()?;
        if self.trust_state != *accepted.binding() {
            return Err(DeployedProductionSignerError::TrustStateDivergence);
        }
        let expected_identity = TrustBoundSignerServiceIdentity::build(
            base_service_identity,
            accepted.binding(),
            deployment_policy,
        )?;
        if self.signer_service_identity != expected_identity {
            return Err(DeployedProductionSignerError::ServiceTrustStateMismatch);
        }
        if self.key_generation == 0 || self.key_generation != governed_trust.key.generation {
            return Err(DeployedProductionSignerError::KeyGenerationMismatch);
        }
        if governed_trust.key.registry_revision != accepted.binding().registry_revision
            || governed_trust.key.registry_digest != accepted.binding().registry_digest
        {
            return Err(DeployedProductionSignerError::TrustStateDivergence);
        }
        let envelope = self.signer_package.verify_governed(
            governed_trust,
            accepted.registry(),
            signed_at_epoch_s,
        )?;
        if envelope.request.identity != governed_trust.key.identity {
            return Err(DeployedProductionSignerError::KeyGenerationMismatch);
        }
        if envelope.binding.trust_state_binding_digest.as_deref()
            != Some(accepted.binding().binding_digest.as_str())
        {
            return Err(DeployedProductionSignerError::SignedTrustStateBindingMismatch);
        }
        if self.package_digest != self.expected_digest()? {
            return Err(DeployedProductionSignerError::DeployedPackageDigestMismatch);
        }
        Ok(envelope)
    }

    fn expected_digest(&self) -> Result<String, DeployedProductionSignerError> {
        digest_with_blank_field(self, "package_digest")
    }
}

#[derive(Debug)]
pub struct TrustBoundProductionSignerService<B> {
    inner: ProductionSignerService<B>,
    accepted: VerifiedProductionTrustState,
    deployment_policy: ProductionSignerDeploymentPolicy,
    service_identity: TrustBoundSignerServiceIdentity,
}

impl<B> TrustBoundProductionSignerService<B>
where
    B: HardwareSignerBackend,
{
    pub fn new(
        inner: ProductionSignerService<B>,
        accepted: VerifiedProductionTrustState,
        deployment_policy: ProductionSignerDeploymentPolicy,
    ) -> Result<Self, DeployedProductionSignerError> {
        deployment_policy.validate_seal()?;
        validate_runtime_state(&inner, &accepted, &deployment_policy)?;
        let service_identity = TrustBoundSignerServiceIdentity::build(
            inner.service_identity(),
            accepted.binding(),
            &deployment_policy,
        )?;
        for identity in &deployment_policy.enabled_identities {
            let record = accepted
                .registry()
                .active_record(identity, inner.service_identity().started_at_epoch_s)?;
            if record.status != ProductionKeyStatus::Active {
                return Err(DeployedProductionSignerError::ActiveGenerationUnavailable);
            }
            let descriptor = inner.validate_backend_generation(identity, record.generation)?;
            validate_descriptor_record_binding(&descriptor, record)?;
        }
        Ok(Self {
            inner,
            accepted,
            deployment_policy,
            service_identity,
        })
    }

    pub fn handle_authenticated(
        &mut self,
        request: &ProductionSignerRequest,
        caller: &AuthenticatedCallerIdentity,
        trusted_now_epoch_s: u64,
    ) -> Result<DeployedAuthorizedProductionSignerPackage, DeployedProductionSignerError> {
        let body = self.accepted.body();
        if trusted_now_epoch_s < body.not_before_epoch_s
            || trusted_now_epoch_s >= body.not_after_epoch_s
        {
            return Err(DeployedProductionSignerError::TrustState(
                ProductionTrustStateError::TrustStateOutsideValidityWindow,
            ));
        }
        if !self.deployment_policy.permits(&request.identity) {
            return Err(DeployedProductionSignerError::IdentityNotEnabled);
        }
        let record = self
            .accepted
            .registry()
            .active_record(&request.identity, trusted_now_epoch_s)?;
        let signer_package = self
            .inner
            .handle_authenticated_generation_with_trust_state(
                request,
                caller,
                trusted_now_epoch_s,
                record.generation,
                Some(&self.accepted.binding().binding_digest),
            )?;
        DeployedAuthorizedProductionSignerPackage::build(
            &self.accepted,
            self.service_identity.clone(),
            record.generation,
            signer_package,
        )
    }

    #[must_use]
    pub const fn accepted_trust_state(&self) -> &VerifiedProductionTrustState {
        &self.accepted
    }

    #[must_use]
    pub const fn deployment_policy(&self) -> &ProductionSignerDeploymentPolicy {
        &self.deployment_policy
    }

    #[must_use]
    pub const fn service_identity(&self) -> &TrustBoundSignerServiceIdentity {
        &self.service_identity
    }
}

fn validate_runtime_state<B>(
    service: &ProductionSignerService<B>,
    accepted: &VerifiedProductionTrustState,
    deployment_policy: &ProductionSignerDeploymentPolicy,
) -> Result<(), DeployedProductionSignerError>
where
    B: HardwareSignerBackend,
{
    let body = accepted.body();
    service.service_identity().validate()?;
    service.allowlist().validate()?;
    if body.deployment_id != deployment_policy.deployment_id
        || body.signer_service_executable_digest != service.service_identity().executable_sha256
        || body.caller_allowlist_revision != service.allowlist().revision
        || body.caller_allowlist_digest != service.allowlist().allowlist_digest
        || body.service_policy_revision != deployment_policy.revision
        || body.service_policy_digest != deployment_policy.policy_digest
        || service.service_identity().service_id != deployment_policy.service_id
    {
        return Err(DeployedProductionSignerError::ServiceTrustStateMismatch);
    }
    Ok(())
}

fn validate_descriptor_record_binding(
    descriptor: &HardwareKeyDescriptor,
    record: &ergaxiom_windows_production_key_governance_runtime::ProductionKeyRecord,
) -> Result<(), DeployedProductionSignerError> {
    let policy = ProductionKeyPolicy::for_identity(record.identity.clone());
    descriptor.validate_for(&policy)?;
    if descriptor.identity != record.identity
        || descriptor.public_key_digest != record.public_key_digest
        || descriptor.policy_digest != record.policy_digest
        || descriptor.provider != record.provider
        || descriptor.algorithm != record.algorithm
        || descriptor.public_key_encoding != record.public_key_encoding
        || descriptor.signature_encoding != record.signature_encoding
        || descriptor.export_policy != record.export_policy
    {
        return Err(DeployedProductionSignerError::BackendRegistryMismatch);
    }
    Ok(())
}

fn digest_with_blank_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, DeployedProductionSignerError> {
    let mut value = serde_json::to_value(value)?;
    let object = value
        .as_object_mut()
        .ok_or(DeployedProductionSignerError::InvalidCanonicalObject)?;
    object.insert(field.to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

#[derive(Debug, Error)]
pub enum DeployedProductionSignerError {
    #[error("production signer deployment policy schema is unsupported")]
    UnsupportedDeploymentPolicySchema,
    #[error("production signer deployment policy is invalid")]
    InvalidDeploymentPolicy,
    #[error("production signer deployment identities are not canonical and unique")]
    DeploymentIdentitiesNotCanonical,
    #[error("production signer deployment policy digest does not match")]
    DeploymentPolicyDigestMismatch,
    #[error("trust-bound signer-service identity schema is unsupported")]
    UnsupportedBoundServiceIdentitySchema,
    #[error("trust-bound signer-service identity digest does not match")]
    BoundServiceIdentityDigestMismatch,
    #[error("deployed production signer package schema is unsupported")]
    UnsupportedDeployedPackageSchema,
    #[error("deployed production signer package digest does not match")]
    DeployedPackageDigestMismatch,
    #[error("signer service or policy does not match the accepted trust state")]
    ServiceTrustStateMismatch,
    #[error("backend key descriptor does not match the active registry record")]
    BackendRegistryMismatch,
    #[error("accepted backend and signer trust states diverge")]
    TrustStateDivergence,
    #[error("production signer key generation does not match governed trust")]
    KeyGenerationMismatch,
    #[error("hardware-signed request does not bind the accepted production trust state")]
    SignedTrustStateBindingMismatch,
    #[error("production signing identity is not enabled by deployment policy")]
    IdentityNotEnabled,
    #[error("no unambiguous active production key generation is available")]
    ActiveGenerationUnavailable,
    #[error("deployed production signer canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("deployed production signer JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    TrustState(#[from] ProductionTrustStateError),
    #[error(transparent)]
    Service(#[from] ProductionSignerServiceError),
    #[error(transparent)]
    ProductionSigner(#[from] ProductionSignerError),
    #[error(transparent)]
    ProductionKeyGovernance(
        #[from] ergaxiom_windows_production_key_governance_runtime::ProductionKeyGovernanceError,
    ),
    #[error(transparent)]
    SignerIdentity(#[from] ergaxiom_windows_signer_service_identity_runtime::SignerIdentityError),
    #[error(transparent)]
    Hashing(#[from] ergaxiom_proof_kernel::HashingError),
}
