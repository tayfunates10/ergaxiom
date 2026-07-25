#![forbid(unsafe_code)]

use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const SNAPSHOT_SCHEMA: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityStatus {
    Unresolved,
    Ready,
    Running,
    VerifiedAccepted,
    VerifiedRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Blocked,
    Pending,
    Active,
    Passed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestItem {
    pub id: String,
    pub media_type: Option<String>,
    pub digest: String,
    pub status: StageStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionItem {
    pub field: String,
    pub question: String,
    pub mandatory: bool,
    pub status: StageStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSummary {
    pub approval_id: String,
    pub contract_digest: String,
    pub plan_digest: String,
    pub permission_digest: String,
    pub expires_at_epoch_s: u64,
    pub status: StageStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStepSummary {
    pub step_id: String,
    pub operator_id: String,
    pub status: StageStatus,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSummary {
    pub validator_id: String,
    pub claim_id: String,
    pub report_digest: String,
    pub status: StageStatus,
    pub actionable_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateVerification {
    pub certificate_id: String,
    pub certificate_digest: String,
    pub evidence_bundle_digest: String,
    pub signature_verified: bool,
    pub bundle_verified: bool,
    pub decision_accepted: bool,
    pub mandatory_unknowns: usize,
    pub mandatory_failures: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustComponentStatus {
    pub component_id: String,
    pub version: String,
    pub digest: String,
    pub trusted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DesktopShellMaterial {
    pub generated_at: String,
    pub job_id: Option<String>,
    pub unresolved: Vec<ResolutionItem>,
    pub staged_inputs: Vec<DigestItem>,
    pub contract: Option<DigestItem>,
    pub approval: Option<ApprovalSummary>,
    pub plan: Option<DigestItem>,
    pub steps: Vec<PlanStepSummary>,
    pub validators: Vec<ValidatorSummary>,
    pub evidence_bundle: Option<DigestItem>,
    pub replay_manifest: Option<DigestItem>,
    pub certificate: Option<CertificateVerification>,
    pub profession_capsules: Vec<TrustComponentStatus>,
    pub adapters: Vec<TrustComponentStatus>,
    pub trusted_keys: Vec<TrustComponentStatus>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DesktopShellSnapshot {
    pub schema_version: String,
    pub authority_status: AuthorityStatus,
    pub generated_at: String,
    pub job_id: Option<String>,
    pub unresolved: Vec<ResolutionItem>,
    pub staged_inputs: Vec<DigestItem>,
    pub contract: Option<DigestItem>,
    pub approval: Option<ApprovalSummary>,
    pub plan: Option<DigestItem>,
    pub steps: Vec<PlanStepSummary>,
    pub validators: Vec<ValidatorSummary>,
    pub evidence_bundle: Option<DigestItem>,
    pub replay_manifest: Option<DigestItem>,
    pub certificate: Option<CertificateVerification>,
    pub profession_capsules: Vec<TrustComponentStatus>,
    pub adapters: Vec<TrustComponentStatus>,
    pub trusted_keys: Vec<TrustComponentStatus>,
    pub metadata: Value,
    pub snapshot_digest: String,
}

#[derive(Debug, Error)]
pub enum DesktopShellError {
    #[error("required desktop snapshot field is empty: {0}")]
    EmptyField(&'static str),
    #[error("invalid lowercase SHA-256 field: {0}")]
    InvalidDigest(&'static str),
    #[error("certificate claims acceptance without complete independent verification")]
    ContradictoryAcceptedCertificate,
    #[error("failed to serialize desktop shell snapshot: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn build_desktop_shell_snapshot(
    material: DesktopShellMaterial,
) -> Result<DesktopShellSnapshot, DesktopShellError> {
    if material.generated_at.trim().is_empty() {
        return Err(DesktopShellError::EmptyField("generated_at"));
    }
    validate_material_digests(&material)?;
    if let Some(certificate) = &material.certificate {
        validate_certificate(certificate)?;
    }

    let authority_status = derive_authority_status(&material);
    let mut snapshot = DesktopShellSnapshot {
        schema_version: SNAPSHOT_SCHEMA.to_owned(),
        authority_status,
        generated_at: material.generated_at,
        job_id: material.job_id,
        unresolved: material.unresolved,
        staged_inputs: material.staged_inputs,
        contract: material.contract,
        approval: material.approval,
        plan: material.plan,
        steps: material.steps,
        validators: material.validators,
        evidence_bundle: material.evidence_bundle,
        replay_manifest: material.replay_manifest,
        certificate: material.certificate,
        profession_capsules: material.profession_capsules,
        adapters: material.adapters,
        trusted_keys: material.trusted_keys,
        metadata: material.metadata,
        snapshot_digest: String::new(),
    };
    snapshot.snapshot_digest = snapshot_digest(&snapshot)?;
    Ok(snapshot)
}

pub fn verify_desktop_shell_snapshot(
    snapshot: &DesktopShellSnapshot,
) -> Result<bool, DesktopShellError> {
    if !is_sha256(&snapshot.snapshot_digest) {
        return Err(DesktopShellError::InvalidDigest("snapshot_digest"));
    }
    if let Some(certificate) = &snapshot.certificate {
        validate_certificate(certificate)?;
    }
    Ok(snapshot.snapshot_digest == snapshot_digest(snapshot)?)
}

fn derive_authority_status(material: &DesktopShellMaterial) -> AuthorityStatus {
    if !material.unresolved.is_empty() {
        return AuthorityStatus::Unresolved;
    }
    if let Some(certificate) = &material.certificate {
        if certificate.signature_verified
            && certificate.bundle_verified
            && certificate.decision_accepted
            && certificate.mandatory_unknowns == 0
            && certificate.mandatory_failures == 0
        {
            return AuthorityStatus::VerifiedAccepted;
        }
        return AuthorityStatus::VerifiedRejected;
    }
    if material
        .steps
        .iter()
        .any(|step| step.status == StageStatus::Active)
    {
        AuthorityStatus::Running
    } else {
        AuthorityStatus::Ready
    }
}

fn validate_certificate(certificate: &CertificateVerification) -> Result<(), DesktopShellError> {
    if certificate.certificate_id.trim().is_empty() {
        return Err(DesktopShellError::EmptyField("certificate_id"));
    }
    validate_digest("certificate_digest", &certificate.certificate_digest)?;
    validate_digest(
        "evidence_bundle_digest",
        &certificate.evidence_bundle_digest,
    )?;
    if certificate.decision_accepted
        && (!certificate.signature_verified
            || !certificate.bundle_verified
            || certificate.mandatory_unknowns != 0
            || certificate.mandatory_failures != 0)
    {
        return Err(DesktopShellError::ContradictoryAcceptedCertificate);
    }
    Ok(())
}

fn validate_material_digests(material: &DesktopShellMaterial) -> Result<(), DesktopShellError> {
    for item in &material.staged_inputs {
        validate_digest("staged_input.digest", &item.digest)?;
    }
    for (field, item) in [
        ("contract.digest", material.contract.as_ref()),
        ("plan.digest", material.plan.as_ref()),
        ("evidence_bundle.digest", material.evidence_bundle.as_ref()),
        ("replay_manifest.digest", material.replay_manifest.as_ref()),
    ] {
        if let Some(item) = item {
            validate_digest(field, &item.digest)?;
        }
    }
    if let Some(approval) = &material.approval {
        validate_digest("approval.contract_digest", &approval.contract_digest)?;
        validate_digest("approval.plan_digest", &approval.plan_digest)?;
        validate_digest("approval.permission_digest", &approval.permission_digest)?;
    }
    for validator in &material.validators {
        validate_digest("validator.report_digest", &validator.report_digest)?;
    }
    for component in material
        .profession_capsules
        .iter()
        .chain(&material.adapters)
        .chain(&material.trusted_keys)
    {
        validate_digest("trust_component.digest", &component.digest)?;
    }
    Ok(())
}

fn validate_digest(field: &'static str, digest: &str) -> Result<(), DesktopShellError> {
    if is_sha256(digest) {
        Ok(())
    } else {
        Err(DesktopShellError::InvalidDigest(field))
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn snapshot_digest(snapshot: &DesktopShellSnapshot) -> Result<String, DesktopShellError> {
    let mut value = serde_json::to_value(snapshot)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| serde_json::Error::io(std::io::Error::other("snapshot is not an object")))?;
    object.insert("snapshot_digest".to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

const CONTROL_SCHEMA: &str = "0.1.0";
const MAX_APPROVAL_TTL_S: u64 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopControlStatus {
    AwaitingApproval,
    Approved,
    Executed,
    Cancelled,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopCommandAction {
    Approve,
    Execute,
    Cancel,
    Rollback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopApprovalRequest {
    pub expected_snapshot_digest: String,
    pub contract_digest: String,
    pub plan_digest: String,
    pub permission_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopApprovalRecord {
    pub schema_version: String,
    pub approval_id: String,
    pub job_id: String,
    pub actor_id: String,
    pub pre_snapshot_digest: String,
    pub contract_digest: String,
    pub plan_digest: String,
    pub permission_digest: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub approval_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopCommandReceipt {
    pub schema_version: String,
    pub command_id: String,
    pub action: DesktopCommandAction,
    pub job_id: String,
    pub actor_id: String,
    pub pre_snapshot_digest: String,
    pub post_snapshot_digest: String,
    pub approval_digest: Option<String>,
    pub issued_at_epoch_s: u64,
    pub applied: bool,
    pub receipt_digest: String,
}

#[derive(Debug, Error)]
pub enum DesktopControlError {
    #[error(transparent)]
    Shell(#[from] DesktopShellError),
    #[error("desktop snapshot failed independent digest verification")]
    SnapshotVerificationFailed,
    #[error("desktop control request contains an invalid identifier: {0}")]
    InvalidIdentifier(&'static str),
    #[error("desktop control request contains an invalid digest: {0}")]
    InvalidControlDigest(&'static str),
    #[error("desktop control request targets a stale snapshot")]
    StaleSnapshot,
    #[error("desktop snapshot is missing required contract, plan, approval or job binding")]
    MissingBinding,
    #[error("desktop approval binding does not match the authoritative snapshot")]
    ApprovalBindingMismatch,
    #[error("desktop approval time-to-live is invalid")]
    InvalidApprovalTtl,
    #[error("desktop approval has expired")]
    ApprovalExpired,
    #[error("desktop control metadata is missing or invalid")]
    InvalidControlMetadata,
    #[error("desktop control transition is not allowed from the current state")]
    InvalidTransition,
    #[error("desktop command receipt is not an applied authoritative transition")]
    ReceiptNotApplied,
    #[error("failed to serialize desktop control material: {0}")]
    ControlSerialization(#[from] serde_json::Error),
    #[error(transparent)]
    ControlHashing(#[from] HashingError),
}

pub fn issue_desktop_approval(
    snapshot: &DesktopShellSnapshot,
    request: &DesktopApprovalRequest,
    actor_id: &str,
    issued_at_epoch_s: u64,
    ttl_s: u64,
) -> Result<DesktopApprovalRecord, DesktopControlError> {
    verify_authoritative_snapshot(snapshot)?;
    validate_control_identifier("actor_id", actor_id)?;
    validate_control_digest(
        "expected_snapshot_digest",
        &request.expected_snapshot_digest,
    )?;
    validate_control_digest("contract_digest", &request.contract_digest)?;
    validate_control_digest("plan_digest", &request.plan_digest)?;
    validate_control_digest("permission_digest", &request.permission_digest)?;
    if request.expected_snapshot_digest != snapshot.snapshot_digest {
        return Err(DesktopControlError::StaleSnapshot);
    }
    if control_status_from_snapshot(snapshot)? != DesktopControlStatus::AwaitingApproval {
        return Err(DesktopControlError::InvalidTransition);
    }
    if ttl_s == 0 || ttl_s > MAX_APPROVAL_TTL_S {
        return Err(DesktopControlError::InvalidApprovalTtl);
    }
    let expires_at_epoch_s = issued_at_epoch_s
        .checked_add(ttl_s)
        .ok_or(DesktopControlError::InvalidApprovalTtl)?;
    let job_id = snapshot
        .job_id
        .as_ref()
        .ok_or(DesktopControlError::MissingBinding)?;
    let contract = snapshot
        .contract
        .as_ref()
        .ok_or(DesktopControlError::MissingBinding)?;
    let plan = snapshot
        .plan
        .as_ref()
        .ok_or(DesktopControlError::MissingBinding)?;
    let approval = snapshot
        .approval
        .as_ref()
        .ok_or(DesktopControlError::MissingBinding)?;
    if !snapshot.unresolved.is_empty()
        || contract.status != StageStatus::Passed
        || plan.status != StageStatus::Passed
        || approval.status != StageStatus::Pending
        || contract.digest != request.contract_digest
        || plan.digest != request.plan_digest
        || approval.contract_digest != request.contract_digest
        || approval.plan_digest != request.plan_digest
        || approval.permission_digest != request.permission_digest
    {
        return Err(DesktopControlError::ApprovalBindingMismatch);
    }
    let identity_seed = serde_json::json!({
        "actor_id": actor_id,
        "issued_at_epoch_s": issued_at_epoch_s,
        "job_id": job_id,
        "request": request,
    });
    let identity_digest = canonical_json_sha256(&identity_seed)?;
    let mut record = DesktopApprovalRecord {
        schema_version: CONTROL_SCHEMA.to_owned(),
        approval_id: format!("approval.desktop.{}", &identity_digest[..16]),
        job_id: job_id.clone(),
        actor_id: actor_id.to_owned(),
        pre_snapshot_digest: snapshot.snapshot_digest.clone(),
        contract_digest: request.contract_digest.clone(),
        plan_digest: request.plan_digest.clone(),
        permission_digest: request.permission_digest.clone(),
        issued_at_epoch_s,
        expires_at_epoch_s,
        approval_digest: String::new(),
    };
    record.approval_digest = desktop_control_record_digest(&record, "approval_digest")?;
    Ok(record)
}

pub fn verify_desktop_approval(
    record: &DesktopApprovalRecord,
) -> Result<bool, DesktopControlError> {
    if record.schema_version != CONTROL_SCHEMA {
        return Ok(false);
    }
    validate_control_identifier("approval_id", &record.approval_id)?;
    validate_control_identifier("job_id", &record.job_id)?;
    validate_control_identifier("actor_id", &record.actor_id)?;
    validate_control_digest("pre_snapshot_digest", &record.pre_snapshot_digest)?;
    validate_control_digest("contract_digest", &record.contract_digest)?;
    validate_control_digest("plan_digest", &record.plan_digest)?;
    validate_control_digest("permission_digest", &record.permission_digest)?;
    validate_control_digest("approval_digest", &record.approval_digest)?;
    if record.expires_at_epoch_s <= record.issued_at_epoch_s {
        return Ok(false);
    }
    Ok(record.approval_digest == desktop_control_record_digest(record, "approval_digest")?)
}

pub fn verify_desktop_approval_binding(
    snapshot: &DesktopShellSnapshot,
    record: &DesktopApprovalRecord,
    presented_approval_digest: &str,
) -> Result<(), DesktopControlError> {
    verify_authoritative_snapshot(snapshot)?;
    if !verify_desktop_approval(record)? {
        return Err(DesktopControlError::ApprovalBindingMismatch);
    }
    validate_control_digest("presented_approval_digest", presented_approval_digest)?;
    let job_id = snapshot
        .job_id
        .as_ref()
        .ok_or(DesktopControlError::MissingBinding)?;
    let contract = snapshot
        .contract
        .as_ref()
        .ok_or(DesktopControlError::MissingBinding)?;
    let plan = snapshot
        .plan
        .as_ref()
        .ok_or(DesktopControlError::MissingBinding)?;
    let approval = snapshot
        .approval
        .as_ref()
        .ok_or(DesktopControlError::MissingBinding)?;
    let metadata_approval_digest = snapshot
        .metadata
        .get("approval_digest")
        .and_then(Value::as_str)
        .ok_or(DesktopControlError::InvalidControlMetadata)?;
    if presented_approval_digest != record.approval_digest
        || metadata_approval_digest != record.approval_digest
        || job_id != &record.job_id
        || contract.digest != record.contract_digest
        || plan.digest != record.plan_digest
        || approval.contract_digest != record.contract_digest
        || approval.plan_digest != record.plan_digest
        || approval.permission_digest != record.permission_digest
        || approval.status != StageStatus::Passed
    {
        return Err(DesktopControlError::ApprovalBindingMismatch);
    }
    Ok(())
}

pub fn verify_desktop_approval_for_execution(
    snapshot: &DesktopShellSnapshot,
    record: &DesktopApprovalRecord,
    presented_approval_digest: &str,
    now_epoch_s: u64,
) -> Result<(), DesktopControlError> {
    verify_desktop_approval_binding(snapshot, record, presented_approval_digest)?;
    if control_status_from_snapshot(snapshot)? != DesktopControlStatus::Approved {
        return Err(DesktopControlError::InvalidTransition);
    }
    if now_epoch_s > record.expires_at_epoch_s {
        return Err(DesktopControlError::ApprovalExpired);
    }
    Ok(())
}

pub fn issue_desktop_command_receipt(
    action: DesktopCommandAction,
    actor_id: &str,
    pre_snapshot: &DesktopShellSnapshot,
    post_snapshot: &DesktopShellSnapshot,
    approval_digest: Option<&str>,
    issued_at_epoch_s: u64,
) -> Result<DesktopCommandReceipt, DesktopControlError> {
    verify_authoritative_snapshot(pre_snapshot)?;
    verify_authoritative_snapshot(post_snapshot)?;
    validate_control_identifier("actor_id", actor_id)?;
    if let Some(digest) = approval_digest {
        validate_control_digest("approval_digest", digest)?;
    }
    let job_id = post_snapshot
        .job_id
        .as_ref()
        .ok_or(DesktopControlError::MissingBinding)?;
    if pre_snapshot.job_id.as_ref() != Some(job_id) {
        return Err(DesktopControlError::ApprovalBindingMismatch);
    }
    let identity_seed = serde_json::json!({
        "action": action,
        "actor_id": actor_id,
        "approval_digest": approval_digest,
        "issued_at_epoch_s": issued_at_epoch_s,
        "post_snapshot_digest": post_snapshot.snapshot_digest,
        "pre_snapshot_digest": pre_snapshot.snapshot_digest,
    });
    let identity_digest = canonical_json_sha256(&identity_seed)?;
    let mut receipt = DesktopCommandReceipt {
        schema_version: CONTROL_SCHEMA.to_owned(),
        command_id: format!("command.desktop.{}", &identity_digest[..16]),
        action,
        job_id: job_id.clone(),
        actor_id: actor_id.to_owned(),
        pre_snapshot_digest: pre_snapshot.snapshot_digest.clone(),
        post_snapshot_digest: post_snapshot.snapshot_digest.clone(),
        approval_digest: approval_digest.map(str::to_owned),
        issued_at_epoch_s,
        applied: true,
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = desktop_control_record_digest(&receipt, "receipt_digest")?;
    Ok(receipt)
}

pub fn verify_desktop_command_receipt(
    receipt: &DesktopCommandReceipt,
) -> Result<bool, DesktopControlError> {
    if receipt.schema_version != CONTROL_SCHEMA || !receipt.applied {
        return Ok(false);
    }
    validate_control_identifier("command_id", &receipt.command_id)?;
    validate_control_identifier("job_id", &receipt.job_id)?;
    validate_control_identifier("actor_id", &receipt.actor_id)?;
    validate_control_digest("pre_snapshot_digest", &receipt.pre_snapshot_digest)?;
    validate_control_digest("post_snapshot_digest", &receipt.post_snapshot_digest)?;
    if let Some(digest) = &receipt.approval_digest {
        validate_control_digest("approval_digest", digest)?;
    }
    validate_control_digest("receipt_digest", &receipt.receipt_digest)?;
    Ok(receipt.receipt_digest == desktop_control_record_digest(receipt, "receipt_digest")?)
}

pub fn control_status_from_snapshot(
    snapshot: &DesktopShellSnapshot,
) -> Result<DesktopControlStatus, DesktopControlError> {
    let status = snapshot
        .metadata
        .get("control_status")
        .and_then(Value::as_str)
        .ok_or(DesktopControlError::InvalidControlMetadata)?;
    match status {
        "awaiting_approval" => Ok(DesktopControlStatus::AwaitingApproval),
        "approved" => Ok(DesktopControlStatus::Approved),
        "executed" => Ok(DesktopControlStatus::Executed),
        "cancelled" => Ok(DesktopControlStatus::Cancelled),
        "rolled_back" => Ok(DesktopControlStatus::RolledBack),
        _ => Err(DesktopControlError::InvalidControlMetadata),
    }
}

fn verify_authoritative_snapshot(
    snapshot: &DesktopShellSnapshot,
) -> Result<(), DesktopControlError> {
    if verify_desktop_shell_snapshot(snapshot)? {
        Ok(())
    } else {
        Err(DesktopControlError::SnapshotVerificationFailed)
    }
}

fn validate_control_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), DesktopControlError> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
    {
        Err(DesktopControlError::InvalidIdentifier(field))
    } else {
        Ok(())
    }
}

fn validate_control_digest(field: &'static str, value: &str) -> Result<(), DesktopControlError> {
    if is_sha256(value) {
        Ok(())
    } else {
        Err(DesktopControlError::InvalidControlDigest(field))
    }
}

fn desktop_control_record_digest<T: Serialize>(
    record: &T,
    digest_field: &str,
) -> Result<String, DesktopControlError> {
    let mut value = serde_json::to_value(record)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other("control record is not an object"))
    })?;
    object.insert(digest_field.to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}
