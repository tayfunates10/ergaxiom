#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ergaxiom_attestation_runtime::{
    ProductionSignerBoundAttestationPackage, ReplayManifest, VerifiedAttestation,
};
use ergaxiom_backend_issuance_runtime::{BackendIssuanceAuthorization, BackendIssuanceKind};
use ergaxiom_capability_runtime::{AuthorizationReceipt, ProductionSignerBoundCapabilityToken};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_desktop_shell_runtime::{
    AuthorityStatus, DesktopApprovalRecord, DesktopCommandAction, DesktopCommandReceipt,
    DesktopControlError, DesktopControlStatus, DesktopShellError, DesktopShellSnapshot,
    control_status_from_snapshot, verify_desktop_approval_binding, verify_desktop_command_receipt,
    verify_desktop_shell_snapshot,
};
use ergaxiom_evidence_runtime::{EvidenceBundleError, assess_bundle};
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, HashingError, canonical_json_bytes, canonical_json_sha256,
};
use ergaxiom_windows_production_governed_issuance_runtime::{
    GovernedCapabilityAuthorizer, GovernedProductionIssuanceError,
    verify_governed_production_attestation_against_bundle,
};
use ergaxiom_windows_production_trust_state_runtime::{
    ProductionSignerDeploymentPolicy, ProductionSignerIdentityProofError,
    VerifiedProductionSignerTrustLease, VerifiedProductionTrustState,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const CHAIN_SCHEMA: &str = "0.1.0";
const RECORD_PREFIX: &str = "production-execution-state-";
const RECORD_SUFFIX: &str = ".json";
const PENDING_PREFIX: &str = ".production-execution-pending-";
const PENDING_SUFFIX: &str = ".tmp";
const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionExecutionStage {
    Initial,
    Approved,
    CapabilitiesIssued,
    CapabilitiesConsumed,
    Executed,
    Certified,
    Cancelled,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedProductionCapability {
    pub authorization: BackendIssuanceAuthorization,
    pub token: ProductionSignerBoundCapabilityToken,
    pub token_digest: String,
    pub consumption_receipt: Option<AuthorizationReceipt>,
    pub consumption_receipt_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductionExecutionChainState {
    pub schema_version: String,
    pub revision: u64,
    pub previous_state_digest: Option<String>,
    pub job_id: String,
    pub stage: ProductionExecutionStage,
    pub approved_snapshot: Option<DesktopShellSnapshot>,
    pub approval: Option<DesktopApprovalRecord>,
    pub approve_receipt: Option<DesktopCommandReceipt>,
    pub capabilities: Vec<PersistedProductionCapability>,
    pub executed_snapshot: Option<DesktopShellSnapshot>,
    pub execute_receipt: Option<DesktopCommandReceipt>,
    pub evidence_bundle: Option<Value>,
    pub evidence_bundle_digest: Option<String>,
    pub replay_manifest: Option<ReplayManifest>,
    pub replay_manifest_digest: Option<String>,
    pub attestation_authorization: Option<BackendIssuanceAuthorization>,
    pub acceptance_package: Option<ProductionSignerBoundAttestationPackage>,
    pub final_snapshot: Option<DesktopShellSnapshot>,
    pub cancel_receipt: Option<DesktopCommandReceipt>,
    pub rollback_receipt: Option<DesktopCommandReceipt>,
    pub state_digest: String,
}

impl ProductionExecutionChainState {
    fn initial(job_id: String) -> Result<Self, ProductionExecutionStoreError> {
        validate_identifier(&job_id)?;
        let mut state = Self {
            schema_version: CHAIN_SCHEMA.to_owned(),
            revision: 0,
            previous_state_digest: None,
            job_id,
            stage: ProductionExecutionStage::Initial,
            approved_snapshot: None,
            approval: None,
            approve_receipt: None,
            capabilities: Vec::new(),
            executed_snapshot: None,
            execute_receipt: None,
            evidence_bundle: None,
            evidence_bundle_digest: None,
            replay_manifest: None,
            replay_manifest_digest: None,
            attestation_authorization: None,
            acceptance_package: None,
            final_snapshot: None,
            cancel_receipt: None,
            rollback_receipt: None,
            state_digest: String::new(),
        };
        state.state_digest = state.expected_digest()?;
        state.validate_seal()?;
        Ok(state)
    }

    pub fn validate_seal(&self) -> Result<(), ProductionExecutionStoreError> {
        if self.schema_version != CHAIN_SCHEMA {
            return Err(ProductionExecutionStoreError::UnsupportedSchema);
        }
        validate_identifier(&self.job_id)?;
        if self.revision == 0 {
            if self.previous_state_digest.is_some()
                || self.stage != ProductionExecutionStage::Initial
            {
                return Err(ProductionExecutionStoreError::InvalidInitialState);
            }
        } else {
            let previous = self
                .previous_state_digest
                .as_deref()
                .ok_or(ProductionExecutionStoreError::MissingPreviousDigest)?;
            validate_sha256(previous)?;
        }
        validate_sha256(&self.state_digest)?;
        if self.state_digest != self.expected_digest()? {
            return Err(ProductionExecutionStoreError::StateDigestMismatch);
        }
        self.validate_approval_material()?;
        self.validate_capabilities()?;
        self.validate_execution_material()?;
        self.validate_certificate_material()?;
        self.validate_terminal_receipts()
    }

    fn expected_digest(&self) -> Result<String, ProductionExecutionStoreError> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(ProductionExecutionStoreError::InvalidCanonicalObject)?;
        object.insert("state_digest".to_owned(), Value::String(String::new()));
        Ok(canonical_json_sha256(&value)?)
    }

    fn validate_approval_material(&self) -> Result<(), ProductionExecutionStoreError> {
        let approved_present = self.approved_snapshot.is_some()
            && self.approval.is_some()
            && self.approve_receipt.is_some();
        if self.stage != ProductionExecutionStage::Initial && !approved_present {
            return Err(ProductionExecutionStoreError::MissingApprovalMaterial);
        }
        let (Some(snapshot), Some(approval), Some(receipt)) = (
            self.approved_snapshot.as_ref(),
            self.approval.as_ref(),
            self.approve_receipt.as_ref(),
        ) else {
            return Ok(());
        };
        if snapshot.job_id.as_deref() != Some(self.job_id.as_str())
            || !verify_desktop_shell_snapshot(snapshot)?
            || control_status_from_snapshot(snapshot)? != DesktopControlStatus::Approved
            || !verify_desktop_command_receipt(receipt)?
            || receipt.action != DesktopCommandAction::Approve
            || receipt.post_snapshot_digest != snapshot.snapshot_digest
            || receipt.approval_digest.as_deref() != Some(approval.approval_digest.as_str())
        {
            return Err(ProductionExecutionStoreError::ApprovalMaterialMismatch);
        }
        verify_desktop_approval_binding(snapshot, approval, &approval.approval_digest)?;
        Ok(())
    }

    fn validate_capabilities(&self) -> Result<(), ProductionExecutionStoreError> {
        let mut token_ids = BTreeSet::new();
        for capability in &self.capabilities {
            if capability.authorization.kind != BackendIssuanceKind::Capability
                || capability.authorization.job_id != self.job_id
                || !token_ids.insert(capability.token.payload.token_id.as_str())
            {
                return Err(ProductionExecutionStoreError::CapabilityMaterialMismatch);
            }
            let token_value = serde_json::to_value(&capability.token)?;
            if capability.token_digest != canonical_json_sha256(&token_value)? {
                return Err(ProductionExecutionStoreError::CapabilityMaterialMismatch);
            }
            validate_sha256(&capability.token_digest)?;
            match (
                capability.consumption_receipt.as_ref(),
                capability.consumption_receipt_digest.as_ref(),
            ) {
                (None, None) => {}
                (Some(receipt), Some(digest)) => {
                    let receipt_value = serde_json::to_value(receipt)?;
                    if digest != &canonical_json_sha256(&receipt_value)?
                        || receipt.token_id != capability.token.payload.token_id
                        || receipt.token_digest != capability.token_digest
                        || receipt.use_number == 0
                        || receipt.use_number > receipt.max_uses
                    {
                        return Err(ProductionExecutionStoreError::CapabilityConsumptionMismatch);
                    }
                    validate_sha256(digest)?;
                }
                _ => {
                    return Err(ProductionExecutionStoreError::CapabilityConsumptionMismatch);
                }
            }
        }
        if self.requires_consumed_capabilities()
            && (self.capabilities.is_empty()
                || self
                    .capabilities
                    .iter()
                    .any(|capability| capability.consumption_receipt.is_none()))
        {
            return Err(ProductionExecutionStoreError::UnconsumedCapability);
        }
        Ok(())
    }

    fn requires_consumed_capabilities(&self) -> bool {
        matches!(
            self.stage,
            ProductionExecutionStage::CapabilitiesConsumed
                | ProductionExecutionStage::Executed
                | ProductionExecutionStage::Certified
                | ProductionExecutionStage::RolledBack
        )
    }

    fn validate_execution_material(&self) -> Result<(), ProductionExecutionStoreError> {
        let execution_present = self.executed_snapshot.is_some()
            && self.execute_receipt.is_some()
            && self.evidence_bundle.is_some()
            && self.evidence_bundle_digest.is_some()
            && self.replay_manifest.is_some()
            && self.replay_manifest_digest.is_some();
        if self.requires_execution_material() && !execution_present {
            return Err(ProductionExecutionStoreError::MissingExecutionMaterial);
        }
        let (
            Some(snapshot),
            Some(receipt),
            Some(bundle),
            Some(bundle_digest),
            Some(replay),
            Some(replay_digest),
        ) = (
            self.executed_snapshot.as_ref(),
            self.execute_receipt.as_ref(),
            self.evidence_bundle.as_ref(),
            self.evidence_bundle_digest.as_ref(),
            self.replay_manifest.as_ref(),
            self.replay_manifest_digest.as_ref(),
        )
        else {
            return Ok(());
        };
        if !verify_desktop_shell_snapshot(snapshot)?
            || control_status_from_snapshot(snapshot)? != DesktopControlStatus::Executed
            || !verify_desktop_command_receipt(receipt)?
            || receipt.action != DesktopCommandAction::Execute
            || receipt.post_snapshot_digest != snapshot.snapshot_digest
            || snapshot
                .evidence_bundle
                .as_ref()
                .map(|item| item.digest.as_str())
                != Some(bundle_digest.as_str())
            || snapshot
                .replay_manifest
                .as_ref()
                .map(|item| item.digest.as_str())
                != Some(replay_digest.as_str())
            || canonical_json_sha256(bundle)? != *bundle_digest
            || canonical_json_sha256(&serde_json::to_value(replay)?)? != *replay_digest
        {
            return Err(ProductionExecutionStoreError::ExecutionMaterialMismatch);
        }
        Ok(())
    }

    fn requires_execution_material(&self) -> bool {
        matches!(
            self.stage,
            ProductionExecutionStage::Executed
                | ProductionExecutionStage::Certified
                | ProductionExecutionStage::RolledBack
        )
    }

    fn validate_certificate_material(&self) -> Result<(), ProductionExecutionStoreError> {
        let certified_present = self.attestation_authorization.is_some()
            && self.acceptance_package.is_some()
            && self.final_snapshot.is_some();
        if matches!(
            self.stage,
            ProductionExecutionStage::Certified | ProductionExecutionStage::RolledBack
        ) && !certified_present
        {
            return Err(ProductionExecutionStoreError::MissingCertificateMaterial);
        }
        let (Some(auth), Some(package), Some(snapshot)) = (
            self.attestation_authorization.as_ref(),
            self.acceptance_package.as_ref(),
            self.final_snapshot.as_ref(),
        ) else {
            return Ok(());
        };
        let replay = self
            .replay_manifest
            .as_ref()
            .ok_or(ProductionExecutionStoreError::MissingExecutionMaterial)?;
        let certificate = snapshot
            .certificate
            .as_ref()
            .ok_or(ProductionExecutionStoreError::MissingCertificateMaterial)?;
        if auth.kind != BackendIssuanceKind::Attestation
            || auth.job_id != self.job_id
            || package.replay_manifest != *replay
            || snapshot.authority_status != AuthorityStatus::VerifiedAccepted
            || !verify_desktop_shell_snapshot(snapshot)?
            || !certificate.signature_verified
            || !certificate.bundle_verified
            || !certificate.decision_accepted
            || certificate.mandatory_failures != 0
            || certificate.mandatory_unknowns != 0
        {
            return Err(ProductionExecutionStoreError::CertificateMaterialMismatch);
        }
        Ok(())
    }

    fn validate_terminal_receipts(&self) -> Result<(), ProductionExecutionStoreError> {
        if self.stage == ProductionExecutionStage::Cancelled {
            let receipt = self
                .cancel_receipt
                .as_ref()
                .ok_or(ProductionExecutionStoreError::MissingCancellationReceipt)?;
            if !verify_desktop_command_receipt(receipt)?
                || receipt.action != DesktopCommandAction::Cancel
            {
                return Err(ProductionExecutionStoreError::CancellationMaterialMismatch);
            }
        }
        if self.stage == ProductionExecutionStage::RolledBack {
            let receipt = self
                .rollback_receipt
                .as_ref()
                .ok_or(ProductionExecutionStoreError::MissingRollbackReceipt)?;
            if !verify_desktop_command_receipt(receipt)?
                || receipt.action != DesktopCommandAction::Rollback
            {
                return Err(ProductionExecutionStoreError::RollbackMaterialMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ProductionExecutionChainStore {
    root: PathBuf,
    current: ProductionExecutionChainState,
}

impl ProductionExecutionChainStore {
    pub fn load_or_create(
        root: impl AsRef<Path>,
        job_id: impl Into<String>,
    ) -> Result<Self, ProductionExecutionStoreError> {
        let root = root.as_ref().to_path_buf();
        prepare_root(&root)?;
        let job_id = job_id.into();
        let current = match scan_chain(&root)? {
            Some(state) => {
                if state.job_id != job_id {
                    return Err(ProductionExecutionStoreError::JobMismatch);
                }
                state
            }
            None => {
                let state = ProductionExecutionChainState::initial(job_id)?;
                write_state(&root, &state)?;
                state
            }
        };
        current.validate_seal()?;
        Ok(Self { root, current })
    }

    #[must_use]
    pub const fn current(&self) -> &ProductionExecutionChainState {
        &self.current
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn record_approval(
        &mut self,
        approved_snapshot: DesktopShellSnapshot,
        approval: DesktopApprovalRecord,
        approve_receipt: DesktopCommandReceipt,
    ) -> Result<(), ProductionExecutionStoreError> {
        if self.current.stage != ProductionExecutionStage::Initial {
            return Err(ProductionExecutionStoreError::InvalidTransition);
        }
        let mut next = self.current.clone();
        next.stage = ProductionExecutionStage::Approved;
        next.approved_snapshot = Some(approved_snapshot);
        next.approval = Some(approval);
        next.approve_receipt = Some(approve_receipt);
        self.commit(next)
    }

    pub fn record_capability_issuance(
        &mut self,
        authorization: BackendIssuanceAuthorization,
        token: ProductionSignerBoundCapabilityToken,
    ) -> Result<(), ProductionExecutionStoreError> {
        if !matches!(
            self.current.stage,
            ProductionExecutionStage::Approved | ProductionExecutionStage::CapabilitiesIssued
        ) {
            return Err(ProductionExecutionStoreError::InvalidTransition);
        }
        let token_value = serde_json::to_value(&token)?;
        let token_digest = canonical_json_sha256(&token_value)?;
        if self.current.capabilities.iter().any(|existing| {
            existing.token.payload.token_id == token.payload.token_id
                || existing.token_digest == token_digest
        }) {
            return Err(ProductionExecutionStoreError::DuplicateCapability);
        }
        let mut next = self.current.clone();
        next.stage = ProductionExecutionStage::CapabilitiesIssued;
        next.capabilities.push(PersistedProductionCapability {
            authorization,
            token,
            token_digest,
            consumption_receipt: None,
            consumption_receipt_digest: None,
        });
        self.commit(next)
    }

    pub fn record_capability_consumption(
        &mut self,
        token_id: &str,
        receipt: AuthorizationReceipt,
    ) -> Result<(), ProductionExecutionStoreError> {
        if !matches!(
            self.current.stage,
            ProductionExecutionStage::CapabilitiesIssued
                | ProductionExecutionStage::CapabilitiesConsumed
        ) {
            return Err(ProductionExecutionStoreError::InvalidTransition);
        }
        let mut next = self.current.clone();
        let capability = next
            .capabilities
            .iter_mut()
            .find(|capability| capability.token.payload.token_id == token_id)
            .ok_or(ProductionExecutionStoreError::UnknownCapability)?;
        if capability.consumption_receipt.is_some() {
            return Err(ProductionExecutionStoreError::CapabilityAlreadyConsumed);
        }
        let receipt_digest = canonical_json_sha256(&serde_json::to_value(&receipt)?)?;
        capability.consumption_receipt = Some(receipt);
        capability.consumption_receipt_digest = Some(receipt_digest);
        if next
            .capabilities
            .iter()
            .all(|capability| capability.consumption_receipt.is_some())
        {
            next.stage = ProductionExecutionStage::CapabilitiesConsumed;
        }
        self.commit(next)
    }

    pub fn record_execution(
        &mut self,
        executed_snapshot: DesktopShellSnapshot,
        execute_receipt: DesktopCommandReceipt,
        evidence_bundle: Value,
        replay_manifest: ReplayManifest,
    ) -> Result<(), ProductionExecutionStoreError> {
        if self.current.stage != ProductionExecutionStage::CapabilitiesConsumed {
            return Err(ProductionExecutionStoreError::InvalidTransition);
        }
        let evidence_bundle_digest = canonical_json_sha256(&evidence_bundle)?;
        let replay_manifest_digest =
            canonical_json_sha256(&serde_json::to_value(&replay_manifest)?)?;
        let mut next = self.current.clone();
        next.stage = ProductionExecutionStage::Executed;
        next.executed_snapshot = Some(executed_snapshot);
        next.execute_receipt = Some(execute_receipt);
        next.evidence_bundle = Some(evidence_bundle);
        next.evidence_bundle_digest = Some(evidence_bundle_digest);
        next.replay_manifest = Some(replay_manifest);
        next.replay_manifest_digest = Some(replay_manifest_digest);
        self.commit(next)
    }

    pub fn record_certificate(
        &mut self,
        attestation_authorization: BackendIssuanceAuthorization,
        package: ProductionSignerBoundAttestationPackage,
        final_snapshot: DesktopShellSnapshot,
    ) -> Result<(), ProductionExecutionStoreError> {
        if self.current.stage != ProductionExecutionStage::Executed {
            return Err(ProductionExecutionStoreError::InvalidTransition);
        }
        let mut next = self.current.clone();
        next.stage = ProductionExecutionStage::Certified;
        next.attestation_authorization = Some(attestation_authorization);
        next.acceptance_package = Some(package);
        next.final_snapshot = Some(final_snapshot);
        self.commit(next)
    }

    pub fn record_cancellation(
        &mut self,
        receipt: DesktopCommandReceipt,
    ) -> Result<(), ProductionExecutionStoreError> {
        if self.current.stage != ProductionExecutionStage::Approved
            || !self.current.capabilities.is_empty()
        {
            return Err(ProductionExecutionStoreError::InvalidTransition);
        }
        let mut next = self.current.clone();
        next.stage = ProductionExecutionStage::Cancelled;
        next.cancel_receipt = Some(receipt);
        self.commit(next)
    }

    pub fn record_rollback(
        &mut self,
        receipt: DesktopCommandReceipt,
    ) -> Result<(), ProductionExecutionStoreError> {
        if self.current.stage != ProductionExecutionStage::Certified {
            return Err(ProductionExecutionStoreError::InvalidTransition);
        }
        let mut next = self.current.clone();
        next.stage = ProductionExecutionStage::RolledBack;
        next.rollback_receipt = Some(receipt);
        self.commit(next)
    }

    fn commit(
        &mut self,
        mut next: ProductionExecutionChainState,
    ) -> Result<(), ProductionExecutionStoreError> {
        let observed =
            scan_chain(&self.root)?.ok_or(ProductionExecutionStoreError::MissingCurrentState)?;
        if observed.state_digest != self.current.state_digest
            || observed.revision != self.current.revision
        {
            return Err(ProductionExecutionStoreError::ConcurrentMutation);
        }
        next.revision = self
            .current
            .revision
            .checked_add(1)
            .ok_or(ProductionExecutionStoreError::RevisionOverflow)?;
        next.previous_state_digest = Some(self.current.state_digest.clone());
        next.state_digest.clear();
        next.state_digest = next.expected_digest()?;
        next.validate_seal()?;
        write_state(&self.root, &next)?;
        self.current = next;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn consume_governed_capability(
    token: &ProductionSignerBoundCapabilityToken,
    lease: &VerifiedProductionSignerTrustLease,
    accepted: &VerifiedProductionTrustState,
    deployment_policy: &ProductionSignerDeploymentPolicy,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    trusted_now_epoch_s: u64,
    expected_executor_id: &str,
    expected_device_id: Option<&str>,
) -> Result<AuthorizationReceipt, ProductionExecutionVerifyError> {
    lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
    let mut authorizer = GovernedCapabilityAuthorizer::new(
        lease.capability_trust().clone(),
        lease.registry().clone(),
    )?;
    let token_value = serde_json::to_value(token)?;
    Ok(authorizer.authorize(
        &token_value,
        compiled_contract,
        compiled_plan,
        trusted_now_epoch_s,
        expected_executor_id,
        expected_device_id,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_recovered_certified_chain(
    state: &ProductionExecutionChainState,
    lease: &VerifiedProductionSignerTrustLease,
    accepted: &VerifiedProductionTrustState,
    deployment_policy: &ProductionSignerDeploymentPolicy,
    trusted_now_epoch_s: u64,
    compiled_contract: CompiledContract,
    compiled_plan: &CompiledPlan,
    verified_assurance_level: AssuranceLevel,
    expected_executor_id: &str,
    expected_device_id: Option<&str>,
) -> Result<VerifiedAttestation, ProductionExecutionVerifyError> {
    lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
    state.validate_seal()?;
    if state.stage != ProductionExecutionStage::Certified {
        return Err(ProductionExecutionVerifyError::NotCertified);
    }
    let bundle =
        state
            .evidence_bundle
            .as_ref()
            .ok_or(ProductionExecutionVerifyError::MissingMaterial(
                "evidence_bundle",
            ))?;
    let assessment = assess_bundle(
        compiled_contract.clone(),
        compiled_plan,
        bundle,
        verified_assurance_level,
    )?;
    if assessment.decision.status != DecisionStatus::Accepted
        || assessment.mandatory_failed != 0
        || assessment.mandatory_unknown != 0
    {
        return Err(ProductionExecutionVerifyError::EvidenceNotAccepted);
    }
    let package = state.acceptance_package.as_ref().ok_or(
        ProductionExecutionVerifyError::MissingMaterial("acceptance_package"),
    )?;
    let verified = verify_governed_production_attestation_against_bundle(
        package,
        lease.attestation_trust(),
        lease.registry(),
        compiled_contract.clone(),
        compiled_plan,
        bundle,
        verified_assurance_level,
    )?;
    verify_final_snapshot(state, &verified)?;
    verify_capability_receipts(
        state,
        lease,
        &compiled_contract,
        compiled_plan,
        expected_executor_id,
        expected_device_id,
    )?;
    Ok(verified)
}

fn verify_final_snapshot(
    state: &ProductionExecutionChainState,
    verified: &VerifiedAttestation,
) -> Result<(), ProductionExecutionVerifyError> {
    let snapshot =
        state
            .final_snapshot
            .as_ref()
            .ok_or(ProductionExecutionVerifyError::MissingMaterial(
                "final_snapshot",
            ))?;
    let certificate =
        snapshot
            .certificate
            .as_ref()
            .ok_or(ProductionExecutionVerifyError::MissingMaterial(
                "certificate_verification",
            ))?;
    if snapshot.authority_status != AuthorityStatus::VerifiedAccepted
        || !verify_desktop_shell_snapshot(snapshot)?
        || certificate.certificate_id != verified.certificate_id
        || certificate.certificate_digest != verified.certificate_digest
        || certificate.evidence_bundle_digest != verified.evidence_bundle_digest
        || !certificate.signature_verified
        || !certificate.bundle_verified
        || !certificate.decision_accepted
        || certificate.mandatory_failures != 0
        || certificate.mandatory_unknowns != 0
    {
        return Err(ProductionExecutionVerifyError::PersistedVerificationMismatch);
    }
    Ok(())
}

fn verify_capability_receipts(
    state: &ProductionExecutionChainState,
    lease: &VerifiedProductionSignerTrustLease,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    expected_executor_id: &str,
    expected_device_id: Option<&str>,
) -> Result<(), ProductionExecutionVerifyError> {
    for capability in &state.capabilities {
        let persisted_receipt = capability.consumption_receipt.as_ref().ok_or(
            ProductionExecutionVerifyError::MissingMaterial("capability_consumption"),
        )?;
        let mut authorizer = GovernedCapabilityAuthorizer::new(
            lease.capability_trust().clone(),
            lease.registry().clone(),
        )?;
        let token_value = serde_json::to_value(&capability.token)?;
        let verified_receipt = authorizer.authorize(
            &token_value,
            compiled_contract,
            compiled_plan,
            persisted_receipt.authorized_at_epoch_s,
            expected_executor_id,
            expected_device_id,
        )?;
        if &verified_receipt != persisted_receipt {
            return Err(ProductionExecutionVerifyError::CapabilityReceiptMismatch);
        }
        let receipt_digest = canonical_json_sha256(&serde_json::to_value(persisted_receipt)?)?;
        if capability.consumption_receipt_digest.as_deref() != Some(receipt_digest.as_str()) {
            return Err(ProductionExecutionVerifyError::CapabilityReceiptMismatch);
        }
    }
    Ok(())
}

fn prepare_root(root: &Path) -> Result<(), ProductionExecutionStoreError> {
    if !root.is_absolute() {
        return Err(ProductionExecutionStoreError::PathNotAbsolute(
            root.to_path_buf(),
        ));
    }
    if root.exists() {
        let metadata = fs::symlink_metadata(root)
            .map_err(|source| io_error("inspect store root", root, source))?;
        if metadata.file_type().is_symlink() {
            return Err(ProductionExecutionStoreError::DirectSymbolicLink(
                root.to_path_buf(),
            ));
        }
        if !metadata.is_dir() {
            return Err(ProductionExecutionStoreError::StoreRootNotDirectory(
                root.to_path_buf(),
            ));
        }
    } else {
        fs::create_dir_all(root).map_err(|source| io_error("create store root", root, source))?;
    }
    Ok(())
}

fn scan_chain(
    root: &Path,
) -> Result<Option<ProductionExecutionChainState>, ProductionExecutionStoreError> {
    let mut states = BTreeMap::<String, ProductionExecutionChainState>::new();
    for entry in fs::read_dir(root).map_err(|source| io_error("read store root", root, source))? {
        let entry = entry.map_err(|source| io_error("read store entry", root, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ProductionExecutionStoreError::NonUtf8Entry)?;
        if name.starts_with(PENDING_PREFIX) && name.ends_with(PENDING_SUFFIX) {
            continue;
        }
        if !name.starts_with(RECORD_PREFIX) || !name.ends_with(RECORD_SUFFIX) {
            return Err(ProductionExecutionStoreError::UnexpectedEntry(name));
        }
        if states.len() >= MAX_RECORDS {
            return Err(ProductionExecutionStoreError::TooManyRecords);
        }
        let state = read_state(&entry.path())?;
        if name != state_filename(&state) {
            return Err(ProductionExecutionStoreError::FilenameBindingMismatch);
        }
        if states.insert(state.state_digest.clone(), state).is_some() {
            return Err(ProductionExecutionStoreError::DuplicateStateDigest);
        }
    }
    if states.is_empty() {
        return Ok(None);
    }
    let roots = states
        .values()
        .filter(|state| state.revision == 0 && state.previous_state_digest.is_none())
        .cloned()
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(ProductionExecutionStoreError::InvalidChainRoot);
    }
    let mut current = roots[0].clone();
    let mut visited = BTreeSet::from([current.state_digest.clone()]);
    loop {
        let children = states
            .values()
            .filter(|state| {
                state.previous_state_digest.as_deref() == Some(current.state_digest.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        match children.as_slice() {
            [] => break,
            [child] => {
                if child.revision != current.revision.saturating_add(1) {
                    return Err(ProductionExecutionStoreError::InvalidRevisionChain);
                }
                if !visited.insert(child.state_digest.clone()) {
                    return Err(ProductionExecutionStoreError::CycleDetected);
                }
                current = child.clone();
            }
            _ => return Err(ProductionExecutionStoreError::DivergentHistory),
        }
    }
    if visited.len() != states.len() {
        return Err(ProductionExecutionStoreError::OrphanedHistory);
    }
    Ok(Some(current))
}

fn read_state(path: &Path) -> Result<ProductionExecutionChainState, ProductionExecutionStoreError> {
    let before =
        fs::symlink_metadata(path).map_err(|source| io_error("inspect state", path, source))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(ProductionExecutionStoreError::InvalidRecordType(
            path.to_path_buf(),
        ));
    }
    if before.len() > MAX_RECORD_BYTES {
        return Err(ProductionExecutionStoreError::RecordTooLarge);
    }
    let before_modified = before.modified().ok();
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
    File::open(path)
        .map_err(|source| io_error("open state", path, source))?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read state", path, source))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECORD_BYTES {
        return Err(ProductionExecutionStoreError::RecordTooLarge);
    }
    let after =
        fs::symlink_metadata(path).map_err(|source| io_error("reinspect state", path, source))?;
    if before.len() != after.len()
        || before_modified != after.modified().ok()
        || before.file_type() != after.file_type()
    {
        return Err(ProductionExecutionStoreError::UnstableRead);
    }
    let state: ProductionExecutionChainState = serde_json::from_slice(&bytes)?;
    state.validate_seal()?;
    Ok(state)
}

fn write_state(
    root: &Path,
    state: &ProductionExecutionChainState,
) -> Result<(), ProductionExecutionStoreError> {
    state.validate_seal()?;
    let final_path = root.join(state_filename(state));
    if final_path.exists() {
        return Err(ProductionExecutionStoreError::StateAlreadyExists);
    }
    let temp_path = root.join(format!(
        "{PENDING_PREFIX}{:020}-{}{PENDING_SUFFIX}",
        state.revision, state.state_digest
    ));
    let bytes = canonical_json_bytes(&serde_json::to_value(state)?)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECORD_BYTES {
        return Err(ProductionExecutionStoreError::RecordTooLarge);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|source| io_error("create pending state", &temp_path, source))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("write pending state", &temp_path, source))?;
    fs::hard_link(&temp_path, &final_path)
        .map_err(|source| io_error("publish immutable state", &final_path, source))?;
    fs::remove_file(&temp_path)
        .map_err(|source| io_error("remove pending state", &temp_path, source))?;
    Ok(())
}

fn state_filename(state: &ProductionExecutionChainState) -> String {
    format!(
        "{RECORD_PREFIX}{:020}-{}{RECORD_SUFFIX}",
        state.revision, state.state_digest
    )
}

fn validate_identifier(value: &str) -> Result<(), ProductionExecutionStoreError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ProductionExecutionStoreError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ProductionExecutionStoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProductionExecutionStoreError::InvalidSha256);
    }
    Ok(())
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> ProductionExecutionStoreError {
    ProductionExecutionStoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Error)]
pub enum ProductionExecutionVerifyError {
    #[error(transparent)]
    Store(#[from] ProductionExecutionStoreError),
    #[error(transparent)]
    Evidence(#[from] EvidenceBundleError),
    #[error(transparent)]
    Governed(#[from] GovernedProductionIssuanceError),
    #[error(transparent)]
    Lease(#[from] ProductionSignerIdentityProofError),
    #[error(transparent)]
    DesktopShell(#[from] DesktopShellError),
    #[error("production execution chain is not certified")]
    NotCertified,
    #[error("production execution chain is missing {0}")]
    MissingMaterial(&'static str),
    #[error("production Evidence Bundle is not independently ACCEPTED")]
    EvidenceNotAccepted,
    #[error("persisted certificate verification does not match independent verification")]
    PersistedVerificationMismatch,
    #[error("persisted Capability consumption receipt does not independently verify")]
    CapabilityReceiptMismatch,
    #[error("failed to serialize production execution verification material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

#[derive(Debug, Error)]
pub enum ProductionExecutionStoreError {
    #[error("production execution store path must be absolute: {0}")]
    PathNotAbsolute(PathBuf),
    #[error("production execution store path is a direct symbolic link: {0}")]
    DirectSymbolicLink(PathBuf),
    #[error("production execution store root is not a directory: {0}")]
    StoreRootNotDirectory(PathBuf),
    #[error("production execution state record is not a regular file: {0}")]
    InvalidRecordType(PathBuf),
    #[error("production execution store contains a non-UTF-8 entry")]
    NonUtf8Entry,
    #[error("production execution store contains an unexpected entry: {0}")]
    UnexpectedEntry(String),
    #[error("production execution store contains too many records")]
    TooManyRecords,
    #[error("production execution record exceeds the bounded size")]
    RecordTooLarge,
    #[error("production execution record changed while it was read")]
    UnstableRead,
    #[error("production execution state schema is unsupported")]
    UnsupportedSchema,
    #[error("production execution initial state is invalid")]
    InvalidInitialState,
    #[error("production execution state is missing its previous digest")]
    MissingPreviousDigest,
    #[error("production execution state digest does not match")]
    StateDigestMismatch,
    #[error("production execution state is not a canonical object")]
    InvalidCanonicalObject,
    #[error("production execution state filename does not bind revision and digest")]
    FilenameBindingMismatch,
    #[error("production execution store contains a duplicate state digest")]
    DuplicateStateDigest,
    #[error("production execution chain must contain exactly one initial root")]
    InvalidChainRoot,
    #[error("production execution revision chain is invalid")]
    InvalidRevisionChain,
    #[error("production execution history contains a cycle")]
    CycleDetected,
    #[error("production execution history diverged")]
    DivergentHistory,
    #[error("production execution history contains orphaned records")]
    OrphanedHistory,
    #[error("production execution current state is missing")]
    MissingCurrentState,
    #[error("production execution store changed concurrently")]
    ConcurrentMutation,
    #[error("production execution revision overflowed")]
    RevisionOverflow,
    #[error("production execution state already exists")]
    StateAlreadyExists,
    #[error("production execution job does not match the persisted chain")]
    JobMismatch,
    #[error("production execution transition is not allowed")]
    InvalidTransition,
    #[error("production execution chain identifier is invalid")]
    InvalidIdentifier,
    #[error("production execution chain SHA-256 value is invalid")]
    InvalidSha256,
    #[error("production execution chain is missing approval material")]
    MissingApprovalMaterial,
    #[error("production execution approval material does not match")]
    ApprovalMaterialMismatch,
    #[error("production execution Capability material does not match")]
    CapabilityMaterialMismatch,
    #[error("production execution Capability token is duplicated")]
    DuplicateCapability,
    #[error("production execution Capability token is unknown")]
    UnknownCapability,
    #[error("production execution Capability token was already consumed")]
    CapabilityAlreadyConsumed,
    #[error("production execution Capability consumption receipt does not match")]
    CapabilityConsumptionMismatch,
    #[error("production execution chain contains an unconsumed Capability token")]
    UnconsumedCapability,
    #[error("production execution chain is missing execution material")]
    MissingExecutionMaterial,
    #[error("production execution material does not match")]
    ExecutionMaterialMismatch,
    #[error("production execution chain is missing certificate material")]
    MissingCertificateMaterial,
    #[error("production execution certificate material does not match")]
    CertificateMaterialMismatch,
    #[error("production execution chain is missing cancellation receipt")]
    MissingCancellationReceipt,
    #[error("production execution cancellation material does not match")]
    CancellationMaterialMismatch,
    #[error("production execution chain is missing rollback receipt")]
    MissingRollbackReceipt,
    #[error("production execution rollback material does not match")]
    RollbackMaterialMismatch,
    #[error(transparent)]
    Desktop(#[from] DesktopControlError),
    #[error(transparent)]
    Shell(#[from] DesktopShellError),
    #[error("failed to decode production execution state: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("failed to {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "ergaxiom-production-execution-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn initial_chain_is_digest_addressed_and_restart_stable()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("restart");
        let first = ProductionExecutionChainStore::load_or_create(&root, "job.test.0001")?;
        assert_eq!(first.current().revision, 0);
        assert_eq!(first.current().stage, ProductionExecutionStage::Initial);
        let digest = first.current().state_digest.clone();
        drop(first);

        let recovered = ProductionExecutionChainStore::load_or_create(&root, "job.test.0001")?;
        assert_eq!(recovered.current().state_digest, digest);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn unexpected_or_corrupt_history_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("corrupt");
        let store = ProductionExecutionChainStore::load_or_create(&root, "job.test.0002")?;
        let state_path = root.join(state_filename(store.current()));
        drop(store);
        fs::write(&state_path, b"{}")?;
        assert!(ProductionExecutionChainStore::load_or_create(&root, "job.test.0002").is_err());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn pending_temp_is_ignored_but_unexpected_file_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("entries");
        let _ = ProductionExecutionChainStore::load_or_create(&root, "job.test.0003")?;
        fs::write(
            root.join(".production-execution-pending-test.tmp"),
            b"partial",
        )?;
        assert!(ProductionExecutionChainStore::load_or_create(&root, "job.test.0003").is_ok());
        fs::write(root.join("evil.json"), b"{}")?;
        assert!(matches!(
            ProductionExecutionChainStore::load_or_create(&root, "job.test.0003"),
            Err(ProductionExecutionStoreError::UnexpectedEntry(_))
        ));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}
