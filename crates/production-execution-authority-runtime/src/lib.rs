#![forbid(unsafe_code)]

use std::path::Path;

use ergaxiom_attestation_issuance_runtime::{
    AttestationCertificateDraft, ProductionAttestationSignerTransport,
};
use ergaxiom_backend_issuance_runtime::{
    AuthorizedProductionAttestationIssuance, AuthorizedProductionCapabilityIssuance,
    BackendIssuanceError, BackendIssuanceKind, BackendIssuancePolicy, BackendIssuancePolicyState,
    BackendIssuancePolicyStore, BackendIssuancePolicyStoreError,
};
use ergaxiom_capability_issuance_runtime::{
    CapabilityTokenDraft, ProductionCapabilitySignerTransport,
};
use ergaxiom_capability_runtime::AuthorizationReceipt;
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_desktop_shell_runtime::{
    DesktopApprovalRecord, DesktopCommandReceipt, DesktopShellSnapshot,
};
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_production_execution_runtime::{
    ProductionExecutionChainState, ProductionExecutionChainStore, ProductionExecutionStoreError,
};
use ergaxiom_proof_kernel::AssuranceLevel;
use ergaxiom_windows_production_governed_issuance_runtime::{
    GovernedCapabilityAuthorizer, GovernedProductionAttestationIssuanceAuthority,
    GovernedProductionCapabilityIssuanceAuthority, GovernedProductionIssuanceError,
};
use ergaxiom_windows_production_trust_state_runtime::{
    ProductionSignerDeploymentPolicy, ProductionSignerIdentityProofError,
    VerifiedProductionSignerTrustLease, VerifiedProductionTrustState,
};
use serde_json::Value;
use thiserror::Error;

/// Backend-owned persistent authority for one production execution chain.
///
/// The authority deliberately owns both the issuance-policy store and execution-chain store so a
/// caller cannot obtain a usable production token or attestation without the corresponding durable
/// state transition. No software/development signer is accepted by this API.
pub struct PersistentProductionExecutionAuthority {
    policy: BackendIssuancePolicy,
    policy_store: BackendIssuancePolicyStore,
    chain_store: ProductionExecutionChainStore,
    executor_id: String,
    device_id: Option<String>,
}

impl PersistentProductionExecutionAuthority {
    pub fn load_or_create(
        policy_store_root: impl AsRef<Path>,
        chain_store_root: impl AsRef<Path>,
        job_id: impl Into<String>,
        executor_id: impl Into<String>,
        device_id: Option<String>,
    ) -> Result<Self, PersistentProductionExecutionAuthorityError> {
        let (policy_store, policy) = BackendIssuancePolicyStore::load_or_create(policy_store_root)?;
        let chain_store = ProductionExecutionChainStore::load_or_create(chain_store_root, job_id)?;
        Ok(Self {
            policy,
            policy_store,
            chain_store,
            executor_id: executor_id.into(),
            device_id,
        })
    }

    pub fn record_approval(
        &mut self,
        approved_snapshot: DesktopShellSnapshot,
        approval: DesktopApprovalRecord,
        approve_receipt: DesktopCommandReceipt,
    ) -> Result<(), PersistentProductionExecutionAuthorityError> {
        self.chain_store
            .record_approval(approved_snapshot, approval, approve_receipt)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_capability<C>(
        &mut self,
        transport: C,
        lease: &VerifiedProductionSignerTrustLease,
        accepted: &VerifiedProductionTrustState,
        deployment_policy: &ProductionSignerDeploymentPolicy,
        snapshot: &DesktopShellSnapshot,
        approval: &DesktopApprovalRecord,
        approve_receipt: &DesktopCommandReceipt,
        compiled_contract: &CompiledContract,
        compiled_plan: &CompiledPlan,
        draft: CapabilityTokenDraft,
        trusted_now_epoch_s: u64,
        authorization_ttl_s: u64,
    ) -> Result<AuthorizedProductionCapabilityIssuance, PersistentProductionExecutionAuthorityError>
    where
        C: ProductionCapabilitySignerTransport,
    {
        lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
        let capability_authority = GovernedProductionCapabilityIssuanceAuthority::new(
            transport,
            lease.capability_trust().clone(),
            lease.registry().clone(),
        )?;
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
        self.policy_store.commit(&self.policy)?;
        let token = capability_authority.issue(draft)?;
        self.chain_store
            .record_capability_issuance(authorization.clone(), token.clone())?;
        Ok(AuthorizedProductionCapabilityIssuance {
            authorization,
            token,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn consume_capability(
        &mut self,
        token_id: &str,
        lease: &VerifiedProductionSignerTrustLease,
        accepted: &VerifiedProductionTrustState,
        deployment_policy: &ProductionSignerDeploymentPolicy,
        compiled_contract: &CompiledContract,
        compiled_plan: &CompiledPlan,
        trusted_now_epoch_s: u64,
    ) -> Result<AuthorizationReceipt, PersistentProductionExecutionAuthorityError> {
        lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
        let persisted = self
            .chain_store
            .current()
            .capabilities
            .iter()
            .find(|capability| capability.token.payload.token_id == token_id)
            .ok_or(PersistentProductionExecutionAuthorityError::UnknownCapability)?;
        if persisted.consumption_receipt.is_some() {
            return Err(PersistentProductionExecutionAuthorityError::CapabilityAlreadyConsumed);
        }
        let token = persisted.token.clone();
        let token_value = serde_json::to_value(&token)?;
        let mut authorizer = GovernedCapabilityAuthorizer::new(
            lease.capability_trust().clone(),
            lease.registry().clone(),
        )?;
        let receipt = authorizer.authorize(
            &token_value,
            compiled_contract,
            compiled_plan,
            trusted_now_epoch_s,
            &self.executor_id,
            self.device_id.as_deref(),
        )?;
        self.chain_store
            .record_capability_consumption(token_id, receipt.clone())?;
        Ok(receipt)
    }

    pub fn record_execution(
        &mut self,
        executed_snapshot: DesktopShellSnapshot,
        execute_receipt: DesktopCommandReceipt,
        evidence_bundle: Value,
        replay_manifest: ergaxiom_attestation_runtime::ReplayManifest,
    ) -> Result<(), PersistentProductionExecutionAuthorityError> {
        self.chain_store.record_execution(
            executed_snapshot,
            execute_receipt,
            evidence_bundle,
            replay_manifest,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_attestation<A>(
        &mut self,
        transport: A,
        lease: &VerifiedProductionSignerTrustLease,
        accepted: &VerifiedProductionTrustState,
        deployment_policy: &ProductionSignerDeploymentPolicy,
        snapshot: &DesktopShellSnapshot,
        approval: &DesktopApprovalRecord,
        execute_receipt: &DesktopCommandReceipt,
        compiled_contract: CompiledContract,
        compiled_plan: &CompiledPlan,
        bundle_value: &Value,
        verified_assurance_level: AssuranceLevel,
        draft: AttestationCertificateDraft,
        trusted_now_epoch_s: u64,
        authorization_ttl_s: u64,
    ) -> Result<AuthorizedProductionAttestationIssuance, PersistentProductionExecutionAuthorityError>
    where
        A: ProductionAttestationSignerTransport,
    {
        lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
        let attestation_authority = GovernedProductionAttestationIssuanceAuthority::new(
            transport,
            lease.attestation_trust().clone(),
            lease.registry().clone(),
        )?;
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
        self.policy_store.commit(&self.policy)?;
        let package = attestation_authority.issue(
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

    pub fn record_certificate(
        &mut self,
        issuance: AuthorizedProductionAttestationIssuance,
        final_snapshot: DesktopShellSnapshot,
    ) -> Result<(), PersistentProductionExecutionAuthorityError> {
        self.chain_store.record_certificate(
            issuance.authorization,
            issuance.package,
            final_snapshot,
        )?;
        Ok(())
    }

    pub fn record_cancellation(
        &mut self,
        receipt: DesktopCommandReceipt,
    ) -> Result<(), PersistentProductionExecutionAuthorityError> {
        self.chain_store.record_cancellation(receipt)?;
        Ok(())
    }

    pub fn record_rollback(
        &mut self,
        receipt: DesktopCommandReceipt,
    ) -> Result<(), PersistentProductionExecutionAuthorityError> {
        self.chain_store.record_rollback(receipt)?;
        Ok(())
    }

    #[must_use]
    pub const fn chain_state(&self) -> &ProductionExecutionChainState {
        self.chain_store.current()
    }

    #[must_use]
    pub const fn policy_state(&self) -> &BackendIssuancePolicyState {
        self.policy_store.current_state()
    }

    #[must_use]
    pub fn executor_id(&self) -> &str {
        &self.executor_id
    }

    #[must_use]
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }
}

#[derive(Debug, Error)]
pub enum PersistentProductionExecutionAuthorityError {
    #[error(transparent)]
    PolicyStore(#[from] BackendIssuancePolicyStoreError),
    #[error(transparent)]
    Authorization(#[from] BackendIssuanceError),
    #[error(transparent)]
    ExecutionStore(#[from] ProductionExecutionStoreError),
    #[error(transparent)]
    Lease(#[from] ProductionSignerIdentityProofError),
    #[error(transparent)]
    Governed(#[from] GovernedProductionIssuanceError),
    #[error("production Capability token is unknown to the persisted execution chain")]
    UnknownCapability,
    #[error("production Capability token was already durably consumed")]
    CapabilityAlreadyConsumed,
    #[error("failed to encode production execution authority material: {0}")]
    Json(#[from] serde_json::Error),
}
