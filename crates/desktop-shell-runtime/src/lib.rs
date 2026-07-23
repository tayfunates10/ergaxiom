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

fn validate_certificate(
    certificate: &CertificateVerification,
) -> Result<(), DesktopShellError> {
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
    object.insert(
        "snapshot_digest".to_owned(),
        Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}
