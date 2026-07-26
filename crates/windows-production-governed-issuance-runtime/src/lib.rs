#![forbid(unsafe_code)]

use ergaxiom_attestation_issuance_runtime::{
    AttestationCertificateDraft, AttestationIssuanceError, ProductionAttestationIssuanceAuthority,
    ProductionAttestationSignerTransport,
};
use ergaxiom_attestation_runtime::{
    ProductionAttestationVerifyError, ProductionSignerBoundAttestationPackage, VerifiedAttestation,
    verify_production_signer_bound_attestation,
    verify_production_signer_bound_attestation_against_bundle,
};
use ergaxiom_capability_issuance_runtime::{
    CapabilityIssuanceError, CapabilityTokenDraft, ProductionCapabilityIssuanceAuthority,
    ProductionCapabilitySignerTransport,
};
use ergaxiom_capability_runtime::{
    AuthorizationReceipt, CapabilityAuthorizer, CapabilityError,
    ProductionSignerBoundCapabilityToken, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::AssuranceLevel;
use ergaxiom_windows_production_key_governance_runtime::{
    ProductionKeyGovernanceError, ProductionKeyRegistry,
};
use ergaxiom_windows_production_signer_runtime::ProductionKeyPolicy;
use ergaxiom_windows_production_signer_service_runtime::{
    GovernedProductionSignerTrustSnapshot, ProductionSignerServiceError,
};
use serde_json::Value;
use thiserror::Error;

pub struct GovernedProductionCapabilityIssuanceAuthority<T> {
    inner: ProductionCapabilityIssuanceAuthority<T>,
    trust: GovernedProductionSignerTrustSnapshot,
    registry: ProductionKeyRegistry,
}

impl<T> GovernedProductionCapabilityIssuanceAuthority<T>
where
    T: ProductionCapabilitySignerTransport,
{
    pub fn new(
        transport: T,
        trust: GovernedProductionSignerTrustSnapshot,
        registry: ProductionKeyRegistry,
    ) -> Result<Self, GovernedProductionIssuanceError> {
        validate_trust_contract(&trust, &registry, &ProductionKeyPolicy::capability())?;
        let inner = ProductionCapabilityIssuanceAuthority::new(transport, trust.signer.clone())?;
        Ok(Self {
            inner,
            trust,
            registry,
        })
    }

    pub fn issue(
        &self,
        draft: CapabilityTokenDraft,
    ) -> Result<ProductionSignerBoundCapabilityToken, GovernedProductionIssuanceError> {
        let issued_at_epoch_s = draft.issued_at_epoch_s;
        let token = self.inner.issue(draft)?;
        token.signer_package.verify_governed(
            &self.trust,
            &self.registry,
            issued_at_epoch_s,
        )?;
        Ok(token)
    }

    #[must_use]
    pub const fn trust(&self) -> &GovernedProductionSignerTrustSnapshot {
        &self.trust
    }

    #[must_use]
    pub const fn registry(&self) -> &ProductionKeyRegistry {
        &self.registry
    }
}

pub struct GovernedCapabilityAuthorizer {
    inner: CapabilityAuthorizer,
    trust: GovernedProductionSignerTrustSnapshot,
    registry: ProductionKeyRegistry,
}

impl GovernedCapabilityAuthorizer {
    pub fn new(
        trust: GovernedProductionSignerTrustSnapshot,
        registry: ProductionKeyRegistry,
    ) -> Result<Self, GovernedProductionIssuanceError> {
        validate_trust_contract(&trust, &registry, &ProductionKeyPolicy::capability())?;
        Ok(Self {
            inner: CapabilityAuthorizer::new(TrustedKeyRegistry::default()),
            trust,
            registry,
        })
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
    ) -> Result<AuthorizationReceipt, GovernedProductionIssuanceError> {
        let token: ProductionSignerBoundCapabilityToken =
            serde_json::from_value(token_value.clone())?;
        token.signer_package.verify_governed(
            &self.trust,
            &self.registry,
            token.payload.issued_at_epoch_s,
        )?;
        Ok(self.inner.authorize_production_signer_bound(
            token_value,
            &self.trust.signer,
            compiled_contract,
            compiled_plan,
            trusted_now_epoch_s,
            expected_executor_id,
            expected_device_id,
        )?)
    }

    #[must_use]
    pub const fn trust(&self) -> &GovernedProductionSignerTrustSnapshot {
        &self.trust
    }

    #[must_use]
    pub const fn registry(&self) -> &ProductionKeyRegistry {
        &self.registry
    }
}

pub struct GovernedProductionAttestationIssuanceAuthority<T> {
    inner: ProductionAttestationIssuanceAuthority<T>,
    trust: GovernedProductionSignerTrustSnapshot,
    registry: ProductionKeyRegistry,
}

impl<T> GovernedProductionAttestationIssuanceAuthority<T>
where
    T: ProductionAttestationSignerTransport,
{
    pub fn new(
        transport: T,
        trust: GovernedProductionSignerTrustSnapshot,
        registry: ProductionKeyRegistry,
    ) -> Result<Self, GovernedProductionIssuanceError> {
        validate_trust_contract(&trust, &registry, &ProductionKeyPolicy::attestation())?;
        let inner = ProductionAttestationIssuanceAuthority::new(transport, trust.signer.clone())?;
        Ok(Self {
            inner,
            trust,
            registry,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        compiled_contract: CompiledContract,
        compiled_plan: &CompiledPlan,
        bundle_value: &Value,
        verified_assurance_level: AssuranceLevel,
        draft: AttestationCertificateDraft,
    ) -> Result<ProductionSignerBoundAttestationPackage, GovernedProductionIssuanceError> {
        let issued_at_epoch_s = draft.issued_at_epoch_s;
        let package = self.inner.issue(
            compiled_contract,
            compiled_plan,
            bundle_value,
            verified_assurance_level,
            draft,
        )?;
        package.certificate.signer_package.verify_governed(
            &self.trust,
            &self.registry,
            issued_at_epoch_s,
        )?;
        Ok(package)
    }

    #[must_use]
    pub const fn trust(&self) -> &GovernedProductionSignerTrustSnapshot {
        &self.trust
    }

    #[must_use]
    pub const fn registry(&self) -> &ProductionKeyRegistry {
        &self.registry
    }
}

pub fn verify_governed_production_attestation(
    package: &ProductionSignerBoundAttestationPackage,
    trust: &GovernedProductionSignerTrustSnapshot,
    registry: &ProductionKeyRegistry,
) -> Result<VerifiedAttestation, GovernedProductionIssuanceError> {
    package.certificate.signer_package.verify_governed(
        trust,
        registry,
        package.certificate.payload.issued_at_epoch_s,
    )?;
    Ok(verify_production_signer_bound_attestation(
        package,
        &trust.signer,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_governed_production_attestation_against_bundle(
    package: &ProductionSignerBoundAttestationPackage,
    trust: &GovernedProductionSignerTrustSnapshot,
    registry: &ProductionKeyRegistry,
    compiled_contract: CompiledContract,
    compiled_plan: &CompiledPlan,
    bundle_value: &Value,
    verified_assurance_level: AssuranceLevel,
) -> Result<VerifiedAttestation, GovernedProductionIssuanceError> {
    package.certificate.signer_package.verify_governed(
        trust,
        registry,
        package.certificate.payload.issued_at_epoch_s,
    )?;
    Ok(verify_production_signer_bound_attestation_against_bundle(
        package,
        &trust.signer,
        compiled_contract,
        compiled_plan,
        bundle_value,
        verified_assurance_level,
    )?)
}

fn validate_trust_contract(
    trust: &GovernedProductionSignerTrustSnapshot,
    registry: &ProductionKeyRegistry,
    policy: &ProductionKeyPolicy,
) -> Result<(), GovernedProductionIssuanceError> {
    trust.signer.validate_for(policy)?;
    trust.key.validate_shape()?;
    if trust.key.identity != trust.signer.identity || trust.key.identity != policy.identity {
        return Err(GovernedProductionIssuanceError::TrustRegistryMismatch);
    }
    if trust.key.public_key_digest != trust.signer.public_key_digest {
        return Err(GovernedProductionIssuanceError::TrustRegistryMismatch);
    }
    if trust.key.registry_revision != registry.revision()
        || trust.key.registry_digest != registry.registry_digest()?
    {
        return Err(GovernedProductionIssuanceError::TrustRegistryMismatch);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum GovernedProductionIssuanceError {
    #[error("governed production trust does not match the supplied registry snapshot")]
    TrustRegistryMismatch,
    #[error("failed to decode governed production artifact: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    CapabilityIssuance(#[from] CapabilityIssuanceError),
    #[error(transparent)]
    CapabilityAuthorization(#[from] CapabilityError),
    #[error(transparent)]
    AttestationIssuance(#[from] AttestationIssuanceError),
    #[error(transparent)]
    AttestationVerification(#[from] ProductionAttestationVerifyError),
    #[error(transparent)]
    Signer(#[from] ProductionSignerServiceError),
    #[error(transparent)]
    Governance(#[from] ProductionKeyGovernanceError),
}
