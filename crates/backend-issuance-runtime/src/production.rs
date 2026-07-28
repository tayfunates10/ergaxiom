include!("deployment.rs");

use ergaxiom_attestation_issuance_runtime::{
    AttestationCertificateDraft, ProductionAttestationSignerTransport,
};
use ergaxiom_attestation_runtime::ProductionSignerBoundAttestationPackage;
use ergaxiom_capability_issuance_runtime::{
    CapabilityTokenDraft, ProductionCapabilitySignerTransport,
};
use ergaxiom_capability_runtime::ProductionSignerBoundCapabilityToken;
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_desktop_shell_runtime::{
    DesktopApprovalRecord, DesktopCommandReceipt, DesktopShellSnapshot,
};
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::AssuranceLevel;
use ergaxiom_windows_production_governed_issuance_runtime::{
    GovernedProductionAttestationIssuanceAuthority, GovernedProductionCapabilityIssuanceAuthority,
    GovernedProductionIssuanceError,
};
use ergaxiom_windows_production_key_governance_runtime::ProductionKeyRegistry;
use ergaxiom_windows_production_signer_service_runtime::GovernedProductionSignerTrustSnapshot;
use serde_json::Value as JsonValue;
use thiserror::Error as ThisError;

use crate::{
    BackendIssuanceAuthorization, BackendIssuanceError, BackendIssuanceKind, BackendIssuancePolicy,
};

#[derive(Debug)]
pub struct AuthorizedProductionCapabilityIssuance {
    pub authorization: BackendIssuanceAuthorization,
    pub token: ProductionSignerBoundCapabilityToken,
}

#[derive(Debug)]
pub struct AuthorizedProductionAttestationIssuance {
    pub authorization: BackendIssuanceAuthorization,
    pub package: ProductionSignerBoundAttestationPackage,
}

pub struct BackendAuthorizedProductionIssuanceAuthority<C, A> {
    policy: BackendIssuancePolicy,
    capability_authority: GovernedProductionCapabilityIssuanceAuthority<C>,
    attestation_authority: GovernedProductionAttestationIssuanceAuthority<A>,
    executor_id: String,
    device_id: Option<String>,
}

impl<C, A> BackendAuthorizedProductionIssuanceAuthority<C, A>
where
    C: ProductionCapabilitySignerTransport,
    A: ProductionAttestationSignerTransport,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability_transport: C,
        capability_trust: GovernedProductionSignerTrustSnapshot,
        attestation_transport: A,
        attestation_trust: GovernedProductionSignerTrustSnapshot,
        registry: ProductionKeyRegistry,
        executor_id: impl Into<String>,
        device_id: Option<String>,
    ) -> Result<Self, BackendProductionIssuanceError> {
        let capability_authority = GovernedProductionCapabilityIssuanceAuthority::new(
            capability_transport,
            capability_trust,
            registry.clone(),
        )?;
        let attestation_authority = GovernedProductionAttestationIssuanceAuthority::new(
            attestation_transport,
            attestation_trust,
            registry,
        )?;
        Ok(Self {
            policy: BackendIssuancePolicy::default(),
            capability_authority,
            attestation_authority,
            executor_id: executor_id.into(),
            device_id,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_capability(
        &mut self,
        snapshot: &DesktopShellSnapshot,
        approval: &DesktopApprovalRecord,
        approve_receipt: &DesktopCommandReceipt,
        compiled_contract: &CompiledContract,
        compiled_plan: &CompiledPlan,
        draft: CapabilityTokenDraft,
        trusted_now_epoch_s: u64,
        authorization_ttl_s: u64,
    ) -> Result<AuthorizedProductionCapabilityIssuance, BackendProductionIssuanceError> {
        let authorization = self.policy.authorize_capability(
            snapshot,
            approval,
            approve_receipt,
            compiled_contract,
            compiled_plan,
            &draft,
            &self.executor_id,
            self.device_id.as_deref(),
            trusted_now_epoch_s,
            authorization_ttl_s,
        )?;
        self.policy.consume_authorization(
            &authorization,
            BackendIssuanceKind::Capability,
            trusted_now_epoch_s,
        )?;
        let token = self.capability_authority.issue(draft)?;
        Ok(AuthorizedProductionCapabilityIssuance {
            authorization,
            token,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_attestation(
        &mut self,
        snapshot: &DesktopShellSnapshot,
        approval: &DesktopApprovalRecord,
        execute_receipt: &DesktopCommandReceipt,
        compiled_contract: CompiledContract,
        compiled_plan: &CompiledPlan,
        bundle_value: &JsonValue,
        verified_assurance_level: AssuranceLevel,
        draft: AttestationCertificateDraft,
        trusted_now_epoch_s: u64,
        authorization_ttl_s: u64,
    ) -> Result<AuthorizedProductionAttestationIssuance, BackendProductionIssuanceError> {
        let authorization = self.policy.authorize_attestation(
            snapshot,
            approval,
            execute_receipt,
            compiled_contract.clone(),
            compiled_plan,
            bundle_value,
            verified_assurance_level,
            &draft,
            trusted_now_epoch_s,
            authorization_ttl_s,
        )?;
        self.policy.consume_authorization(
            &authorization,
            BackendIssuanceKind::Attestation,
            trusted_now_epoch_s,
        )?;
        let package = self.attestation_authority.issue(
            compiled_contract,
            compiled_plan,
            bundle_value,
            verified_assurance_level,
            draft,
        )?;
        Ok(AuthorizedProductionAttestationIssuance {
            authorization,
            package,
        })
    }
}

#[derive(Debug, ThisError)]
pub enum BackendProductionIssuanceError {
    #[error(transparent)]
    Authorization(#[from] BackendIssuanceError),
    #[error(transparent)]
    Governed(#[from] GovernedProductionIssuanceError),
}
