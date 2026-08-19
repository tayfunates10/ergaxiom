#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
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
    DesktopApprovalRecord, DesktopCommandReceipt, DesktopShellSnapshot, StageStatus,
};
use ergaxiom_evidence_runtime::{ArtifactRole, DigestAlgorithm, EvidenceBundle};
use ergaxiom_occupational_twin_runtime::{OperationOutcome, OperationReceipt};
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_production_execution_runtime::{
    ProductionExecutionChainState, ProductionExecutionChainStore, ProductionExecutionStage,
    ProductionExecutionStoreError,
};
use ergaxiom_proof_kernel::{AssuranceLevel, HashingError, canonical_json_sha256};
use ergaxiom_windows_production_governed_issuance_runtime::{
    GovernedCapabilityAuthorizer, GovernedProductionAttestationIssuanceAuthority,
    GovernedProductionCapabilityIssuanceAuthority, GovernedProductionIssuanceError,
};
use ergaxiom_windows_production_trust_state_runtime::{
    ProductionSignerDeploymentPolicy, ProductionSignerIdentityProofError,
    VerifiedProductionSignerTrustLease, VerifiedProductionTrustState,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const INLINE_OPERATION_RECEIPT_PREFIX: &str = "ergaxiom-inline-hex:";
const OPERATION_RECEIPT_ARTIFACT_PREFIX: &str = "execution_receipt.";

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

    fn require_stage(
        &self,
        allowed: &[ProductionExecutionStage],
    ) -> Result<(), PersistentProductionExecutionAuthorityError> {
        if allowed.contains(&self.chain_store.current().stage) {
            Ok(())
        } else {
            Err(ProductionExecutionStoreError::InvalidTransition.into())
        }
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
        self.require_stage(&[
            ProductionExecutionStage::Approved,
            ProductionExecutionStage::CapabilitiesIssued,
        ])?;
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

        // Persist the terminal intent reservation before the signer side effect. A rejected signer
        // request can never be retried through a software/development fallback after restart.
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
        self.require_stage(&[
            ProductionExecutionStage::CapabilitiesIssued,
            ProductionExecutionStage::CapabilitiesConsumed,
        ])?;
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

        // Receipt persistence precedes returning authorization to the executor. If this commit is
        // not durable, the caller never receives a receipt and execution must not begin.
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
        self.verify_execution_evidence_binding(&evidence_bundle, &executed_snapshot)?;
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
        self.require_stage(&[ProductionExecutionStage::Executed])?;
        lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
        self.verify_execution_evidence_binding(bundle_value, snapshot)?;
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

        // Production attestation follows the same terminal-before-side-effect persistence rule.
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

    /// Cross-binds persisted production Capability consumption receipts to the exact Evidence
    /// Bundle trace, then decodes and validates every real Twin OperationReceipt embedded in the
    /// bundle against the executed desktop step summaries.
    pub fn verify_execution_evidence_binding(
        &self,
        bundle_value: &Value,
        executed_snapshot: &DesktopShellSnapshot,
    ) -> Result<(), PersistentProductionExecutionAuthorityError> {
        let bundle: EvidenceBundle = serde_json::from_value(bundle_value.clone())?;
        self.verify_capability_receipt_binding(&bundle)?;
        verify_operation_receipt_artifacts(&bundle, executed_snapshot)?;
        Ok(())
    }

    fn verify_capability_receipt_binding(
        &self,
        bundle: &EvidenceBundle,
    ) -> Result<(), PersistentProductionExecutionAuthorityError> {
        let capabilities = &self.chain_store.current().capabilities;
        if bundle.trace.authorization_receipts.len() != capabilities.len() {
            return Err(
                PersistentProductionExecutionAuthorityError::EvidenceReceiptBindingMismatch,
            );
        }
        let mut bundle_by_token = BTreeMap::new();
        for record in &bundle.trace.authorization_receipts {
            if canonical_json_sha256(&serde_json::to_value(&record.receipt)?)?
                != record.receipt_digest
                || bundle_by_token
                    .insert(record.receipt.token_id.as_str(), record)
                    .is_some()
            {
                return Err(
                    PersistentProductionExecutionAuthorityError::EvidenceReceiptBindingMismatch,
                );
            }
        }
        for capability in capabilities {
            let persisted_receipt = capability.consumption_receipt.as_ref().ok_or(
                PersistentProductionExecutionAuthorityError::EvidenceReceiptBindingMismatch,
            )?;
            let persisted_digest = capability.consumption_receipt_digest.as_deref().ok_or(
                PersistentProductionExecutionAuthorityError::EvidenceReceiptBindingMismatch,
            )?;
            let bundled = bundle_by_token
                .get(persisted_receipt.token_id.as_str())
                .ok_or(
                    PersistentProductionExecutionAuthorityError::EvidenceReceiptBindingMismatch,
                )?;
            if &bundled.receipt != persisted_receipt
                || bundled.receipt_digest != persisted_digest
                || persisted_receipt.token_digest != capability.token_digest
            {
                return Err(
                    PersistentProductionExecutionAuthorityError::EvidenceReceiptBindingMismatch,
                );
            }
        }
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

fn verify_operation_receipt_artifacts(
    bundle: &EvidenceBundle,
    executed_snapshot: &DesktopShellSnapshot,
) -> Result<(), PersistentProductionExecutionAuthorityError> {
    let artifacts = bundle
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact
                .artifact_id
                .starts_with(OPERATION_RECEIPT_ARTIFACT_PREFIX)
        })
        .collect::<Vec<_>>();
    if artifacts.len() != executed_snapshot.steps.len() || artifacts.is_empty() {
        return Err(PersistentProductionExecutionAuthorityError::OperationReceiptBindingMismatch);
    }

    let mut matched_steps = BTreeSet::new();
    for artifact in artifacts {
        if artifact.role != ArtifactRole::Evidence
            || artifact.algorithm != DigestAlgorithm::Sha256
            || artifact.media_type.as_deref() != Some("application/json")
        {
            return Err(
                PersistentProductionExecutionAuthorityError::OperationReceiptBindingMismatch,
            );
        }
        let encoded = artifact
            .uri
            .strip_prefix(INLINE_OPERATION_RECEIPT_PREFIX)
            .ok_or(PersistentProductionExecutionAuthorityError::OperationReceiptBindingMismatch)?;
        let bytes = decode_hex(encoded)?;
        if bytes.len() as u64 != artifact.size_bytes || sha256_hex(&bytes) != artifact.digest {
            return Err(
                PersistentProductionExecutionAuthorityError::OperationReceiptBindingMismatch,
            );
        }
        let receipt: OperationReceipt = serde_json::from_slice(&bytes)?;
        if artifact.artifact_id
            != format!(
                "{OPERATION_RECEIPT_ARTIFACT_PREFIX}{}",
                receipt.operation_id
            )
            || receipt.outcome != OperationOutcome::Succeeded
            || !receipt.violations.is_empty()
        {
            return Err(
                PersistentProductionExecutionAuthorityError::OperationReceiptBindingMismatch,
            );
        }
        let step = executed_snapshot
            .steps
            .iter()
            .find(|step| step.operator_id == receipt.operator_id)
            .ok_or(PersistentProductionExecutionAuthorityError::OperationReceiptBindingMismatch)?;
        if step.status != StageStatus::Passed
            || step.before_digest.as_deref() != Some(receipt.before_snapshot_digest.as_str())
            || step.after_digest.as_deref() != Some(receipt.after_snapshot_digest.as_str())
            || !matched_steps.insert(step.step_id.as_str())
        {
            return Err(
                PersistentProductionExecutionAuthorityError::OperationReceiptBindingMismatch,
            );
        }
    }
    if matched_steps.len() != executed_snapshot.steps.len() {
        return Err(PersistentProductionExecutionAuthorityError::OperationReceiptBindingMismatch);
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, PersistentProductionExecutionAuthorityError> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PersistentProductionExecutionAuthorityError::OperationReceiptBindingMismatch);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = hex_nibble(chunk[0])?;
            let low = hex_nibble(chunk[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, PersistentProductionExecutionAuthorityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(PersistentProductionExecutionAuthorityError::OperationReceiptBindingMismatch),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("production Capability token is unknown to the persisted execution chain")]
    UnknownCapability,
    #[error("production Capability token was already durably consumed")]
    CapabilityAlreadyConsumed,
    #[error(
        "Evidence Bundle authorization receipts do not exactly match persisted production consumption receipts"
    )]
    EvidenceReceiptBindingMismatch,
    #[error("Evidence Bundle operation receipts do not exactly match the executed Twin steps")]
    OperationReceiptBindingMismatch,
    #[error("failed to encode or decode production execution authority material: {0}")]
    Json(#[from] serde_json::Error),
}
