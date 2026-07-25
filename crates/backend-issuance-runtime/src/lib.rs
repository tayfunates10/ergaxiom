#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use ergaxiom_attestation_issuance_runtime::{
    AttestationCertificateDraft, AttestationIssuanceAuthority, AttestationIssuanceError,
    AttestationSignerTransport,
};
use ergaxiom_attestation_runtime::{
    AttestationIssueError, SignerBoundAttestationPackage, build_replay_manifest,
};
use ergaxiom_capability_issuance_runtime::{
    CapabilityIssuanceAuthority, CapabilityIssuanceError, CapabilitySignerTransport,
    CapabilityTokenDraft,
};
use ergaxiom_capability_runtime::SignerBoundCapabilityToken;
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_desktop_shell_runtime::{
    DesktopApprovalRecord, DesktopCommandAction, DesktopCommandReceipt, DesktopControlError,
    DesktopControlStatus, DesktopShellSnapshot, StageStatus, control_status_from_snapshot,
    verify_desktop_approval, verify_desktop_approval_binding,
    verify_desktop_approval_for_execution, verify_desktop_command_receipt,
    verify_desktop_shell_snapshot,
};
use ergaxiom_evidence_runtime::{EvidenceBundle, EvidenceBundleError, assess_bundle};
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const AUTHORIZATION_SCHEMA: &str = "0.1.0";
const MAX_AUTHORIZATION_TTL_S: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendIssuanceKind {
    Capability,
    Attestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendIssuanceAuthorization {
    pub schema_version: String,
    pub authorization_id: String,
    pub kind: BackendIssuanceKind,
    pub job_id: String,
    pub actor_id: String,
    pub snapshot_digest: String,
    pub approval_digest: String,
    pub command_receipt_digest: String,
    pub contract_digest: String,
    pub capsule_digest: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub permission_digest: String,
    pub intent_digest: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub authorization_digest: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizedCapabilityIssuance {
    pub authorization: BackendIssuanceAuthorization,
    pub token: SignerBoundCapabilityToken,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizedAttestationIssuance {
    pub authorization: BackendIssuanceAuthorization,
    pub package: SignerBoundAttestationPackage,
}

#[derive(Debug, Default)]
pub struct BackendIssuancePolicy {
    pending: BTreeMap<String, String>,
    consumed: BTreeSet<String>,
    authorized_intents: BTreeSet<String>,
}

impl BackendIssuancePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_capability(
        &mut self,
        snapshot: &DesktopShellSnapshot,
        approval: &DesktopApprovalRecord,
        approve_receipt: &DesktopCommandReceipt,
        compiled_contract: &CompiledContract,
        compiled_plan: &CompiledPlan,
        draft: &CapabilityTokenDraft,
        expected_executor_id: &str,
        expected_device_id: Option<&str>,
        trusted_now_epoch_s: u64,
        ttl_s: u64,
    ) -> Result<BackendIssuanceAuthorization, BackendIssuanceError> {
        let bindings = validate_common_bindings(
            snapshot,
            approval,
            approve_receipt,
            compiled_contract,
            compiled_plan,
            DesktopControlStatus::Approved,
            DesktopCommandAction::Approve,
            trusted_now_epoch_s,
        )?;
        verify_desktop_approval_for_execution(
            snapshot,
            approval,
            &approval.approval_digest,
            trusted_now_epoch_s,
        )?;
        validate_capability_intent(
            draft,
            compiled_contract,
            compiled_plan,
            expected_executor_id,
            expected_device_id,
            approval,
            trusted_now_epoch_s,
        )?;
        let intent_value = serde_json::to_value(draft)?;
        let intent_digest = canonical_json_sha256(&intent_value)?;
        self.register_authorization(
            BackendIssuanceKind::Capability,
            bindings,
            intent_digest,
            trusted_now_epoch_s,
            ttl_s,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_attestation(
        &mut self,
        snapshot: &DesktopShellSnapshot,
        approval: &DesktopApprovalRecord,
        execute_receipt: &DesktopCommandReceipt,
        compiled_contract: CompiledContract,
        compiled_plan: &CompiledPlan,
        bundle_value: &Value,
        verified_assurance_level: AssuranceLevel,
        draft: &AttestationCertificateDraft,
        trusted_now_epoch_s: u64,
        ttl_s: u64,
    ) -> Result<BackendIssuanceAuthorization, BackendIssuanceError> {
        let bindings = validate_common_bindings(
            snapshot,
            approval,
            execute_receipt,
            &compiled_contract,
            compiled_plan,
            DesktopControlStatus::Executed,
            DesktopCommandAction::Execute,
            trusted_now_epoch_s,
        )?;
        if execute_receipt.issued_at_epoch_s > approval.expires_at_epoch_s {
            return Err(BackendIssuanceError::ExecutionOutsideApprovalWindow);
        }
        if draft.issued_at_epoch_s != trusted_now_epoch_s {
            return Err(BackendIssuanceError::AttestationIssuedAtMismatch);
        }
        let assessment = assess_bundle(
            compiled_contract,
            compiled_plan,
            bundle_value,
            verified_assurance_level,
        )?;
        if assessment.decision.status != DecisionStatus::Accepted
            || assessment.mandatory_failed > 0
            || assessment.mandatory_unknown > 0
        {
            return Err(BackendIssuanceError::EvidenceNotAccepted);
        }
        let evidence_item = snapshot.evidence_bundle.as_ref().ok_or(
            BackendIssuanceError::MissingAttestationSource("evidence_bundle"),
        )?;
        if evidence_item.status != StageStatus::Passed
            || evidence_item.digest != assessment.bundle_digest
        {
            return Err(BackendIssuanceError::AttestationSourceMismatch(
                "evidence_bundle",
            ));
        }
        let bundle: EvidenceBundle = serde_json::from_value(bundle_value.clone())
            .map_err(BackendIssuanceError::BundleDecode)?;
        let replay_manifest = build_replay_manifest(
            &draft.manifest_id,
            compiled_plan,
            &bundle,
            &assessment.bundle_digest,
            assessment.decision.status,
            verified_assurance_level,
            assessment.mandatory_passed,
            assessment.mandatory_failed,
            assessment.mandatory_unknown,
        )?;
        let replay_value = serde_json::to_value(&replay_manifest)?;
        let replay_digest = canonical_json_sha256(&replay_value)?;
        let replay_item = snapshot.replay_manifest.as_ref().ok_or(
            BackendIssuanceError::MissingAttestationSource("replay_manifest"),
        )?;
        if replay_item.status != StageStatus::Passed || replay_item.digest != replay_digest {
            return Err(BackendIssuanceError::AttestationSourceMismatch(
                "replay_manifest",
            ));
        }
        let intent_value = serde_json::json!({
            "assurance_level": verified_assurance_level,
            "bundle_digest": assessment.bundle_digest,
            "draft": draft,
            "replay_manifest_digest": replay_digest,
        });
        let intent_digest = canonical_json_sha256(&intent_value)?;
        self.register_authorization(
            BackendIssuanceKind::Attestation,
            bindings,
            intent_digest,
            trusted_now_epoch_s,
            ttl_s,
        )
    }

    pub fn consume_authorization(
        &mut self,
        authorization: &BackendIssuanceAuthorization,
        expected_kind: BackendIssuanceKind,
        trusted_now_epoch_s: u64,
    ) -> Result<(), BackendIssuanceError> {
        if authorization.schema_version != AUTHORIZATION_SCHEMA
            || authorization.authorization_digest != authorization_digest(authorization)?
        {
            return Err(BackendIssuanceError::AuthorizationDigestMismatch);
        }
        if authorization.kind != expected_kind {
            return Err(BackendIssuanceError::AuthorizationKindMismatch);
        }
        if trusted_now_epoch_s > authorization.expires_at_epoch_s {
            return Err(BackendIssuanceError::AuthorizationExpired);
        }
        if self.consumed.contains(&authorization.authorization_id) {
            return Err(BackendIssuanceError::AuthorizationAlreadyConsumed);
        }
        let Some(expected_digest) = self.pending.get(&authorization.authorization_id) else {
            return Err(BackendIssuanceError::AuthorizationUnknown);
        };
        if expected_digest != &authorization.authorization_digest {
            return Err(BackendIssuanceError::AuthorizationDigestMismatch);
        }
        self.pending.remove(&authorization.authorization_id);
        self.consumed.insert(authorization.authorization_id.clone());
        Ok(())
    }

    fn register_authorization(
        &mut self,
        kind: BackendIssuanceKind,
        bindings: CommonBindings,
        intent_digest: String,
        trusted_now_epoch_s: u64,
        ttl_s: u64,
    ) -> Result<BackendIssuanceAuthorization, BackendIssuanceError> {
        if ttl_s == 0 || ttl_s > MAX_AUTHORIZATION_TTL_S {
            return Err(BackendIssuanceError::InvalidAuthorizationTtl);
        }
        let expires_at_epoch_s = trusted_now_epoch_s
            .checked_add(ttl_s)
            .ok_or(BackendIssuanceError::InvalidAuthorizationTtl)?;
        let intent_scope_value = serde_json::json!({
            "approval_digest": &bindings.approval_digest,
            "intent_digest": &intent_digest,
            "kind": kind,
        });
        let intent_scope_digest = canonical_json_sha256(&intent_scope_value)?;
        if !self.authorized_intents.insert(intent_scope_digest) {
            return Err(BackendIssuanceError::IntentAlreadyAuthorized);
        }
        let identity_value = serde_json::json!({
            "command_receipt_digest": &bindings.command_receipt_digest,
            "intent_digest": &intent_digest,
            "issued_at_epoch_s": trusted_now_epoch_s,
            "kind": kind,
            "snapshot_digest": &bindings.snapshot_digest,
        });
        let identity_digest = canonical_json_sha256(&identity_value)?;
        let mut authorization = BackendIssuanceAuthorization {
            schema_version: AUTHORIZATION_SCHEMA.to_owned(),
            authorization_id: format!("authorization.issuance.{}", &identity_digest[..24]),
            kind,
            job_id: bindings.job_id,
            actor_id: bindings.actor_id,
            snapshot_digest: bindings.snapshot_digest,
            approval_digest: bindings.approval_digest,
            command_receipt_digest: bindings.command_receipt_digest,
            contract_digest: bindings.contract_digest,
            capsule_digest: bindings.capsule_digest,
            plan_id: bindings.plan_id,
            plan_digest: bindings.plan_digest,
            permission_digest: bindings.permission_digest,
            intent_digest,
            issued_at_epoch_s: trusted_now_epoch_s,
            expires_at_epoch_s,
            authorization_digest: String::new(),
        };
        authorization.authorization_digest = authorization_digest(&authorization)?;
        self.pending.insert(
            authorization.authorization_id.clone(),
            authorization.authorization_digest.clone(),
        );
        Ok(authorization)
    }
}

#[derive(Debug)]
pub struct BackendAuthorizedIssuanceAuthority<C, A> {
    policy: BackendIssuancePolicy,
    capability_authority: CapabilityIssuanceAuthority<C>,
    attestation_authority: AttestationIssuanceAuthority<A>,
    executor_id: String,
    device_id: Option<String>,
}

impl<C, A> BackendAuthorizedIssuanceAuthority<C, A>
where
    C: CapabilitySignerTransport,
    A: AttestationSignerTransport,
{
    #[must_use]
    pub fn new(
        capability_transport: C,
        capability_public_key: [u8; 32],
        attestation_transport: A,
        attestation_public_key: [u8; 32],
        executor_id: impl Into<String>,
        device_id: Option<String>,
    ) -> Self {
        Self {
            policy: BackendIssuancePolicy::default(),
            capability_authority: CapabilityIssuanceAuthority::new(
                capability_transport,
                capability_public_key,
            ),
            attestation_authority: AttestationIssuanceAuthority::new(
                attestation_transport,
                attestation_public_key,
            ),
            executor_id: executor_id.into(),
            device_id,
        }
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
    ) -> Result<AuthorizedCapabilityIssuance, BackendIssuanceError> {
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
        Ok(AuthorizedCapabilityIssuance {
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
        bundle_value: &Value,
        verified_assurance_level: AssuranceLevel,
        draft: AttestationCertificateDraft,
        trusted_now_epoch_s: u64,
        authorization_ttl_s: u64,
    ) -> Result<AuthorizedAttestationIssuance, BackendIssuanceError> {
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
        Ok(AuthorizedAttestationIssuance {
            authorization,
            package,
        })
    }
}

#[derive(Debug)]
struct CommonBindings {
    job_id: String,
    actor_id: String,
    snapshot_digest: String,
    approval_digest: String,
    command_receipt_digest: String,
    contract_digest: String,
    capsule_digest: String,
    plan_id: String,
    plan_digest: String,
    permission_digest: String,
}

#[allow(clippy::too_many_arguments)]
fn validate_common_bindings(
    snapshot: &DesktopShellSnapshot,
    approval: &DesktopApprovalRecord,
    receipt: &DesktopCommandReceipt,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    expected_status: DesktopControlStatus,
    expected_action: DesktopCommandAction,
    trusted_now_epoch_s: u64,
) -> Result<CommonBindings, BackendIssuanceError> {
    if !verify_desktop_shell_snapshot(snapshot).map_err(DesktopControlError::Shell)? {
        return Err(BackendIssuanceError::SnapshotVerificationFailed);
    }
    if !verify_desktop_approval(approval)? {
        return Err(BackendIssuanceError::ApprovalVerificationFailed);
    }
    if !verify_desktop_command_receipt(receipt)? {
        return Err(BackendIssuanceError::ReceiptVerificationFailed);
    }
    if control_status_from_snapshot(snapshot)? != expected_status {
        return Err(BackendIssuanceError::SnapshotStatusMismatch);
    }
    if receipt.action != expected_action {
        return Err(BackendIssuanceError::ReceiptActionMismatch);
    }
    if receipt.issued_at_epoch_s > trusted_now_epoch_s {
        return Err(BackendIssuanceError::ReceiptFromFuture);
    }
    verify_desktop_approval_binding(snapshot, approval, &approval.approval_digest)?;
    let job_id = snapshot
        .job_id
        .as_ref()
        .ok_or(BackendIssuanceError::MissingSnapshotBinding("job_id"))?;
    let contract = snapshot
        .contract
        .as_ref()
        .ok_or(BackendIssuanceError::MissingSnapshotBinding("contract"))?;
    let plan = snapshot
        .plan
        .as_ref()
        .ok_or(BackendIssuanceError::MissingSnapshotBinding("plan"))?;
    let approval_summary = snapshot
        .approval
        .as_ref()
        .ok_or(BackendIssuanceError::MissingSnapshotBinding("approval"))?;
    let receipt_approval = receipt
        .approval_digest
        .as_ref()
        .ok_or(BackendIssuanceError::ReceiptBindingMismatch)?;
    if receipt.job_id != *job_id
        || receipt.actor_id != approval.actor_id
        || receipt.post_snapshot_digest != snapshot.snapshot_digest
        || receipt_approval != &approval.approval_digest
        || contract.status != StageStatus::Passed
        || plan.status != StageStatus::Passed
        || approval_summary.status != StageStatus::Passed
        || contract.digest != compiled_contract.seal.contract_digest
        || plan.id != compiled_plan.plan_id
        || plan.digest != compiled_plan.plan_digest
        || compiled_plan.contract_digest != compiled_contract.seal.contract_digest
        || compiled_plan.capsule_digest != compiled_contract.seal.capsule_digest
        || approval.contract_digest != compiled_contract.seal.contract_digest
        || approval.plan_digest != compiled_plan.plan_digest
    {
        return Err(BackendIssuanceError::ReceiptBindingMismatch);
    }
    if !snapshot
        .profession_capsules
        .iter()
        .any(|component| component.trusted && component.digest == compiled_plan.capsule_digest)
    {
        return Err(BackendIssuanceError::CapsuleTrustMismatch);
    }
    Ok(CommonBindings {
        job_id: job_id.clone(),
        actor_id: approval.actor_id.clone(),
        snapshot_digest: snapshot.snapshot_digest.clone(),
        approval_digest: approval.approval_digest.clone(),
        command_receipt_digest: receipt.receipt_digest.clone(),
        contract_digest: compiled_contract.seal.contract_digest.clone(),
        capsule_digest: compiled_contract.seal.capsule_digest.clone(),
        plan_id: compiled_plan.plan_id.clone(),
        plan_digest: compiled_plan.plan_digest.clone(),
        permission_digest: approval.permission_digest.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_capability_intent(
    draft: &CapabilityTokenDraft,
    compiled_contract: &CompiledContract,
    compiled_plan: &CompiledPlan,
    expected_executor_id: &str,
    expected_device_id: Option<&str>,
    approval: &DesktopApprovalRecord,
    trusted_now_epoch_s: u64,
) -> Result<(), BackendIssuanceError> {
    if draft.subject.executor_id != expected_executor_id
        || draft.subject.device_id.as_deref() != expected_device_id
    {
        return Err(BackendIssuanceError::CapabilitySubjectMismatch);
    }
    if draft.issued_at_epoch_s != trusted_now_epoch_s
        || draft.not_before_epoch_s < trusted_now_epoch_s
        || draft.expires_at_epoch_s > approval.expires_at_epoch_s
        || draft.expires_at_epoch_s <= draft.not_before_epoch_s
    {
        return Err(BackendIssuanceError::CapabilityTemporalMismatch);
    }
    if draft.max_uses != 1 {
        return Err(BackendIssuanceError::CapabilityMaxUsesMismatch);
    }
    if draft.bindings.contract_digest != compiled_contract.seal.contract_digest
        || draft.bindings.capsule_digest != compiled_contract.seal.capsule_digest
        || draft.bindings.plan_id != compiled_plan.plan_id
        || draft.bindings.plan_digest != compiled_plan.plan_digest
    {
        return Err(BackendIssuanceError::CapabilityBindingMismatch);
    }
    let Some(step) = compiled_plan
        .steps
        .iter()
        .find(|step| step.step_id == draft.bindings.step_id)
    else {
        return Err(BackendIssuanceError::CapabilityStepMismatch);
    };
    if step.operator_id != draft.bindings.operator_id
        || !step.capability_token_ids.contains(&draft.token_id)
    {
        return Err(BackendIssuanceError::CapabilityStepMismatch);
    }
    let grant_is_declared = compiled_contract.permissions.iter().any(|permission| {
        permission.capability == draft.grant.capability
            && permission.resource == draft.grant.resource
            && permission.access == draft.grant.access
            && permission.constraints == draft.grant.constraints
    });
    if !grant_is_declared {
        return Err(BackendIssuanceError::CapabilityPermissionEscalation);
    }
    Ok(())
}

fn authorization_digest(
    authorization: &BackendIssuanceAuthorization,
) -> Result<String, BackendIssuanceError> {
    let mut value = serde_json::to_value(authorization)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other("authorization is not an object"))
    })?;
    object.insert(
        "authorization_digest".to_owned(),
        Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

#[derive(Debug, Error)]
pub enum BackendIssuanceError {
    #[error(transparent)]
    Desktop(#[from] DesktopControlError),
    #[error(transparent)]
    Capability(#[from] CapabilityIssuanceError),
    #[error(transparent)]
    Attestation(#[from] AttestationIssuanceError),
    #[error(transparent)]
    Evidence(#[from] EvidenceBundleError),
    #[error(transparent)]
    Manifest(#[from] AttestationIssueError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("failed to serialize backend issuance material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("failed to decode independently accepted Evidence Bundle: {0}")]
    BundleDecode(#[source] serde_json::Error),
    #[error("backend issuance authorization TTL is invalid")]
    InvalidAuthorizationTtl,
    #[error("desktop snapshot failed independent verification")]
    SnapshotVerificationFailed,
    #[error("desktop approval failed independent verification")]
    ApprovalVerificationFailed,
    #[error("desktop command receipt failed independent verification")]
    ReceiptVerificationFailed,
    #[error("desktop snapshot is in the wrong control state for this issuance kind")]
    SnapshotStatusMismatch,
    #[error("desktop command receipt action does not authorize this issuance kind")]
    ReceiptActionMismatch,
    #[error("desktop command receipt binding does not match authoritative backend state")]
    ReceiptBindingMismatch,
    #[error("desktop command receipt timestamp is in the future")]
    ReceiptFromFuture,
    #[error("executed command occurred outside the approval validity window")]
    ExecutionOutsideApprovalWindow,
    #[error("snapshot is missing required backend binding {0}")]
    MissingSnapshotBinding(&'static str),
    #[error("trusted profession capsule binding does not match the compiled plan")]
    CapsuleTrustMismatch,
    #[error("capability subject does not match backend-owned executor identity")]
    CapabilitySubjectMismatch,
    #[error("capability temporal bounds are not backend-current or exceed approval validity")]
    CapabilityTemporalMismatch,
    #[error("backend-authorized capability tokens must be single-use")]
    CapabilityMaxUsesMismatch,
    #[error("capability draft does not match the compiled contract and plan")]
    CapabilityBindingMismatch,
    #[error("capability token is not assigned to the exact compiled plan step and operator")]
    CapabilityStepMismatch,
    #[error("capability grant exceeds the exact compiled Work Contract permission")]
    CapabilityPermissionEscalation,
    #[error("attestation draft issued_at does not match the trusted backend clock")]
    AttestationIssuedAtMismatch,
    #[error("attestation source is missing from executed backend state: {0}")]
    MissingAttestationSource(&'static str),
    #[error("attestation source does not match independently recomputed material: {0}")]
    AttestationSourceMismatch(&'static str),
    #[error("Evidence Bundle is not independently accepted")]
    EvidenceNotAccepted,
    #[error("this exact issuance intent was already authorized under the approval")]
    IntentAlreadyAuthorized,
    #[error("backend issuance authorization digest is invalid")]
    AuthorizationDigestMismatch,
    #[error("backend issuance authorization kind is invalid for this operation")]
    AuthorizationKindMismatch,
    #[error("backend issuance authorization is unknown or was never pending")]
    AuthorizationUnknown,
    #[error("backend issuance authorization was already consumed")]
    AuthorizationAlreadyConsumed,
    #[error("backend issuance authorization has expired")]
    AuthorizationExpired,
}
