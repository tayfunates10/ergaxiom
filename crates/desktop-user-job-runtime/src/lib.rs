#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ergaxiom_desktop_shell_runtime::{
    DesktopApprovalRecord, DesktopCommandAction, DesktopCommandReceipt, DesktopControlStatus,
    DesktopShellSnapshot, control_status_from_snapshot, verify_desktop_approval,
    verify_desktop_approval_binding, verify_desktop_command_receipt, verify_desktop_shell_snapshot,
};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const JOB_SCHEMA: &str = "0.2.0";
const PROFESSION_ID: &str = "ergaxiom.profession.graphic-designer";
const JOBS_DIR: &str = "jobs";
const BLOBS_DIR: &str = "immutable-inputs";
const STATE_PREFIX: &str = "state-";
const STATE_SUFFIX: &str = ".json";
const PENDING_PREFIX: &str = ".pending-state-";
const PENDING_SUFFIX: &str = ".tmp";
const BLOB_SUFFIX: &str = ".bin";
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STATES: usize = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphicDesignerJobKind {
    StaticSocialPost,
    ImageBackgroundCleanup,
    BrandCompliantImageExport,
    PrintReadyPosterPreflight,
}

impl GraphicDesignerJobKind {
    #[must_use]
    pub const fn required_input_roles(self) -> &'static [&'static str] {
        match self {
            Self::StaticSocialPost => &[
                "intent_manifest",
                "approved_logo",
                "brand_profile",
                "approved_copy",
            ],
            Self::ImageBackgroundCleanup => &[
                "intent_manifest",
                "source_raster",
                "approved_cleanup_mask",
            ],
            Self::BrandCompliantImageExport => &[
                "intent_manifest",
                "source_svg",
                "brand_manifest",
                "approved_logo",
            ],
            Self::PrintReadyPosterPreflight => &[
                "intent_manifest",
                "source_svg",
                "print_specification",
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserJobPhase {
    Draft,
    UnresolvedIntent,
    ReadyForApproval,
    PermissionRequired,
    Approved,
    ApprovalExpired,
    ProductionSignerUnavailable,
    Executing,
    ExecutionFailed,
    EvidenceRejected,
    RecoveryRequired,
    Accepted,
    Cancelled,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImmutableInput {
    pub role: String,
    pub file_name: String,
    pub media_type: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Canonical approval material is issued and verified by `desktop-shell-runtime`.
/// The persistent job layer stores this tuple but never mints or re-hashes approval authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalAuthorityBinding {
    #[serde(flatten)]
    pub record: DesktopApprovalRecord,
    pub approved_snapshot: DesktopShellSnapshot,
    pub approve_receipt: DesktopCommandReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionBinding {
    pub chain_state_digest: String,
    pub stage: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBinding {
    pub evidence_bundle: Value,
    pub evidence_bundle_digest: String,
    pub replay_manifest: Value,
    pub replay_manifest_digest: String,
    pub validator_results: Vec<Value>,
    pub failure_map: Option<Value>,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificateBinding {
    pub certificate_id: String,
    pub certificate_digest: String,
    pub production_state_digest: String,
    pub acceptance_certificate: Value,
    pub signature_verified: bool,
    pub bundle_verified: bool,
    pub decision_accepted: bool,
    pub mandatory_failed: usize,
    pub mandatory_unknown: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledJobMaterial {
    pub resolved_intent: Value,
    pub work_contract: Value,
    pub contract_digest: String,
    pub operator_plan: Value,
    pub plan_digest: String,
    pub permission_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserJobRecord {
    pub schema_version: String,
    pub revision: u64,
    pub previous_state_digest: Option<String>,
    pub state_digest: String,
    pub job_id: String,
    pub profession_id: String,
    pub job_kind: GraphicDesignerJobKind,
    pub created_at: String,
    pub original_text: String,
    pub phase: UserJobPhase,
    pub inputs: BTreeMap<String, ImmutableInput>,
    pub resolved_intent: Option<Value>,
    pub intent_digest: Option<String>,
    pub work_contract: Option<Value>,
    pub contract_digest: Option<String>,
    pub operator_plan: Option<Value>,
    pub plan_digest: Option<String>,
    pub permission_digest: Option<String>,
    pub approval: Option<ApprovalAuthorityBinding>,
    pub production: Option<ProductionBinding>,
    pub evidence: Option<EvidenceBinding>,
    pub certificate: Option<CertificateBinding>,
    pub status_detail: Option<String>,
}

impl UserJobRecord {
    fn initial(
        job_id: String,
        job_kind: GraphicDesignerJobKind,
        created_at: String,
        original_text: String,
    ) -> Result<Self, UserJobError> {
        validate_identifier(&job_id)?;
        if created_at.trim().is_empty() || created_at.len() > 128 {
            return Err(UserJobError::InvalidCreatedAt);
        }
        if original_text.trim().is_empty() || original_text.len() > 16_384 {
            return Err(UserJobError::InvalidOriginalText);
        }
        let mut record = Self {
            schema_version: JOB_SCHEMA.to_owned(),
            revision: 0,
            previous_state_digest: None,
            state_digest: String::new(),
            job_id,
            profession_id: PROFESSION_ID.to_owned(),
            job_kind,
            created_at,
            original_text,
            phase: UserJobPhase::Draft,
            inputs: BTreeMap::new(),
            resolved_intent: None,
            intent_digest: None,
            work_contract: None,
            contract_digest: None,
            operator_plan: None,
            plan_digest: None,
            permission_digest: None,
            approval: None,
            production: None,
            evidence: None,
            certificate: None,
            status_detail: None,
        };
        record.state_digest = record.expected_digest()?;
        record.validate_seal()?;
        Ok(record)
    }

    pub fn validate_seal(&self) -> Result<(), UserJobError> {
        if self.schema_version != JOB_SCHEMA || self.profession_id != PROFESSION_ID {
            return Err(UserJobError::UnsupportedSchema);
        }
        validate_identifier(&self.job_id)?;
        validate_sha256(&self.state_digest)?;
        if self.revision == 0 {
            if self.previous_state_digest.is_some() {
                return Err(UserJobError::InvalidHistoryRoot);
            }
        } else {
            validate_sha256(
                self.previous_state_digest
                    .as_deref()
                    .ok_or(UserJobError::MissingPreviousStateDigest)?,
            )?;
        }
        if self.state_digest != self.expected_digest()? {
            return Err(UserJobError::StateDigestMismatch);
        }
        self.validate_inputs()?;
        self.validate_compiled_material()?;
        self.validate_approval()?;
        self.validate_production()?;
        self.validate_evidence()?;
        self.validate_certificate()?;
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, UserJobError> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(UserJobError::InvalidCanonicalObject)?;
        object.insert("state_digest".to_owned(), Value::String(String::new()));
        Ok(canonical_json_sha256(&value)?)
    }

    fn validate_inputs(&self) -> Result<(), UserJobError> {
        for (role, input) in &self.inputs {
            validate_role(role)?;
            if role != &input.role || !self.job_kind.required_input_roles().contains(&role.as_str()) {
                return Err(UserJobError::InputRoleMismatch(role.clone()));
            }
            validate_file_name(&input.file_name)?;
            validate_media_type(&input.media_type)?;
            validate_sha256(&input.sha256)?;
            if input.size_bytes == 0 || input.size_bytes > MAX_INPUT_BYTES {
                return Err(UserJobError::InvalidInputSize(input.size_bytes));
            }
        }
        if self.requires_all_inputs() {
            for role in self.job_kind.required_input_roles() {
                if !self.inputs.contains_key(*role) {
                    return Err(UserJobError::MissingRequiredInput((*role).to_owned()));
                }
            }
        }
        Ok(())
    }

    fn requires_all_inputs(&self) -> bool {
        !matches!(
            self.phase,
            UserJobPhase::Draft | UserJobPhase::UnresolvedIntent | UserJobPhase::Cancelled
        )
    }

    fn validate_compiled_material(&self) -> Result<(), UserJobError> {
        let compiled_required = !matches!(
            self.phase,
            UserJobPhase::Draft | UserJobPhase::UnresolvedIntent | UserJobPhase::Cancelled
        );
        let complete = self.resolved_intent.is_some()
            && self.intent_digest.is_some()
            && self.work_contract.is_some()
            && self.contract_digest.is_some()
            && self.operator_plan.is_some()
            && self.plan_digest.is_some()
            && self.permission_digest.is_some();
        if compiled_required && !complete {
            return Err(UserJobError::MissingCompiledMaterial);
        }
        if let (Some(intent), Some(digest)) = (&self.resolved_intent, &self.intent_digest) {
            validate_sha256(digest)?;
            if canonical_json_sha256(intent)? != *digest {
                return Err(UserJobError::IntentDigestMismatch);
            }
        }
        if let (Some(contract), Some(digest)) = (&self.work_contract, &self.contract_digest) {
            validate_sha256(digest)?;
            if canonical_json_sha256(contract)? != *digest {
                return Err(UserJobError::ContractDigestMismatch);
            }
        }
        if let (Some(plan), Some(digest)) = (&self.operator_plan, &self.plan_digest) {
            validate_sha256(digest)?;
            if canonical_json_sha256(plan)? != *digest {
                return Err(UserJobError::PlanDigestMismatch);
            }
        }
        if let Some(permission_digest) = &self.permission_digest {
            validate_sha256(permission_digest)?;
        }
        Ok(())
    }

    fn validate_approval(&self) -> Result<(), UserJobError> {
        let approval_required = matches!(
            self.phase,
            UserJobPhase::Approved
                | UserJobPhase::ApprovalExpired
                | UserJobPhase::ProductionSignerUnavailable
                | UserJobPhase::Executing
                | UserJobPhase::ExecutionFailed
                | UserJobPhase::EvidenceRejected
                | UserJobPhase::RecoveryRequired
                | UserJobPhase::Accepted
                | UserJobPhase::RolledBack
        );
        if approval_required && self.approval.is_none() {
            return Err(UserJobError::MissingApproval);
        }
        let Some(binding) = &self.approval else {
            return Ok(());
        };
        let record = &binding.record;
        if !verify_desktop_approval(record).map_err(canonical_control_error)? {
            return Err(UserJobError::CanonicalApprovalRejected);
        }
        if !verify_desktop_shell_snapshot(&binding.approved_snapshot)
            .map_err(canonical_shell_error)?
        {
            return Err(UserJobError::CanonicalApprovalSnapshotRejected);
        }
        if !verify_desktop_command_receipt(&binding.approve_receipt)
            .map_err(canonical_control_error)?
        {
            return Err(UserJobError::CanonicalApprovalReceiptRejected);
        }
        verify_desktop_approval_binding(
            &binding.approved_snapshot,
            record,
            &record.approval_digest,
        )
        .map_err(canonical_control_error)?;
        if control_status_from_snapshot(&binding.approved_snapshot)
            .map_err(canonical_control_error)?
            != DesktopControlStatus::Approved
            || binding.approve_receipt.action != DesktopCommandAction::Approve
            || binding.approve_receipt.job_id != self.job_id
            || binding.approve_receipt.post_snapshot_digest
                != binding.approved_snapshot.snapshot_digest
            || binding.approve_receipt.pre_snapshot_digest != record.pre_snapshot_digest
            || binding.approve_receipt.approval_digest.as_deref()
                != Some(record.approval_digest.as_str())
            || record.job_id != self.job_id
            || Some(record.contract_digest.as_str()) != self.contract_digest.as_deref()
            || Some(record.plan_digest.as_str()) != self.plan_digest.as_deref()
            || Some(record.permission_digest.as_str()) != self.permission_digest.as_deref()
        {
            return Err(UserJobError::CanonicalApprovalBindingMismatch);
        }
        Ok(())
    }

    fn validate_production(&self) -> Result<(), UserJobError> {
        if let Some(binding) = &self.production {
            validate_sha256(&binding.chain_state_digest)?;
            if binding.stage.trim().is_empty() || binding.stage.len() > 64 {
                return Err(UserJobError::InvalidProductionStage);
            }
        }
        if matches!(
            self.phase,
            UserJobPhase::Executing
                | UserJobPhase::ExecutionFailed
                | UserJobPhase::EvidenceRejected
                | UserJobPhase::RecoveryRequired
                | UserJobPhase::Accepted
                | UserJobPhase::RolledBack
        ) && self.production.is_none()
        {
            return Err(UserJobError::MissingProductionBinding);
        }
        Ok(())
    }

    fn validate_evidence(&self) -> Result<(), UserJobError> {
        let Some(evidence) = &self.evidence else {
            if matches!(
                self.phase,
                UserJobPhase::EvidenceRejected | UserJobPhase::RecoveryRequired | UserJobPhase::Accepted
            ) {
                return Err(UserJobError::MissingEvidence);
            }
            return Ok(());
        };
        validate_sha256(&evidence.evidence_bundle_digest)?;
        validate_sha256(&evidence.replay_manifest_digest)?;
        if canonical_json_sha256(&evidence.evidence_bundle)? != evidence.evidence_bundle_digest
            || canonical_json_sha256(&evidence.replay_manifest)? != evidence.replay_manifest_digest
        {
            return Err(UserJobError::EvidenceDigestMismatch);
        }
        if self.phase == UserJobPhase::EvidenceRejected && evidence.accepted {
            return Err(UserJobError::EvidenceStateMismatch);
        }
        Ok(())
    }

    fn validate_certificate(&self) -> Result<(), UserJobError> {
        let Some(certificate) = &self.certificate else {
            if matches!(self.phase, UserJobPhase::RecoveryRequired | UserJobPhase::Accepted) {
                return Err(UserJobError::MissingCertificate);
            }
            return Ok(());
        };
        validate_identifier(&certificate.certificate_id)?;
        validate_sha256(&certificate.certificate_digest)?;
        validate_sha256(&certificate.production_state_digest)?;
        if Some(certificate.production_state_digest.as_str())
            != self.production.as_ref().map(|value| value.chain_state_digest.as_str())
        {
            return Err(UserJobError::CertificateProductionBindingMismatch);
        }
        if matches!(self.phase, UserJobPhase::Accepted | UserJobPhase::RecoveryRequired) {
            let evidence = self.evidence.as_ref().ok_or(UserJobError::MissingEvidence)?;
            if !evidence.accepted
                || !certificate.signature_verified
                || !certificate.bundle_verified
                || !certificate.decision_accepted
                || certificate.mandatory_failed != 0
                || certificate.mandatory_unknown != 0
            {
                return Err(UserJobError::AcceptanceInvariantFailed);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHistoryEntry {
    pub revision: u64,
    pub phase: UserJobPhase,
    pub state_digest: String,
    pub previous_state_digest: Option<String>,
}

#[derive(Debug)]
pub struct UserJobStore {
    product_root: PathBuf,
    job_root: PathBuf,
    current: UserJobRecord,
}

impl UserJobStore {
    pub fn create(
        product_root: impl AsRef<Path>,
        job_id: impl Into<String>,
        job_kind: GraphicDesignerJobKind,
        created_at: impl Into<String>,
        original_text: impl Into<String>,
    ) -> Result<Self, UserJobError> {
        let product_root = product_root.as_ref().to_path_buf();
        prepare_product_root(&product_root)?;
        let job_id = job_id.into();
        validate_identifier(&job_id)?;
        let job_root = jobs_root(&product_root).join(&job_id);
        if job_root.exists() {
            return Err(UserJobError::JobAlreadyExists);
        }
        fs::create_dir(&job_root).map_err(|source| io_error("create job root", &job_root, source))?;
        reject_symlink(&job_root)?;
        let current = UserJobRecord::initial(job_id, job_kind, created_at.into(), original_text.into())?;
        write_state(&job_root, &current)?;
        Ok(Self {
            product_root,
            job_root,
            current,
        })
    }

    pub fn open(product_root: impl AsRef<Path>, job_id: &str) -> Result<Self, UserJobError> {
        let product_root = product_root.as_ref().to_path_buf();
        prepare_product_root(&product_root)?;
        validate_identifier(job_id)?;
        let job_root = jobs_root(&product_root).join(job_id);
        reject_existing_directory(&job_root)?;
        let (_, current) = load_history(&job_root)?;
        if current.job_id != job_id {
            return Err(UserJobError::JobIdentityMismatch);
        }
        let mut store = Self {
            product_root,
            job_root,
            current,
        };
        if store.current.phase == UserJobPhase::Accepted {
            let mut next = store.current.clone();
            next.phase = UserJobPhase::RecoveryRequired;
            next.status_detail = Some("restart_reverification_required".to_owned());
            store.commit(next)?;
        }
        Ok(store)
    }

    #[must_use]
    pub const fn current(&self) -> &UserJobRecord {
        &self.current
    }

    pub fn history(&self) -> Result<Vec<JobHistoryEntry>, UserJobError> {
        let (states, _) = load_history(&self.job_root)?;
        Ok(states
            .into_iter()
            .map(|state| JobHistoryEntry {
                revision: state.revision,
                phase: state.phase,
                state_digest: state.state_digest,
                previous_state_digest: state.previous_state_digest,
            })
            .collect())
    }

    pub fn import_input(
        &mut self,
        expected_state_digest: &str,
        role: &str,
        file_name: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if !matches!(self.current.phase, UserJobPhase::Draft | UserJobPhase::UnresolvedIntent) {
            return Err(UserJobError::InvalidTransition);
        }
        validate_role(role)?;
        if !self.current.job_kind.required_input_roles().contains(&role) {
            return Err(UserJobError::InputRoleMismatch(role.to_owned()));
        }
        validate_file_name(file_name)?;
        validate_media_type(media_type)?;
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| UserJobError::InputTooLarge)?;
        if bytes.is_empty() || size_bytes > MAX_INPUT_BYTES {
            return Err(UserJobError::InputTooLarge);
        }
        let digest = sha256_hex(bytes);
        persist_blob(&self.product_root, &digest, bytes)?;
        let mut next = self.current.clone();
        next.inputs.insert(
            role.to_owned(),
            ImmutableInput {
                role: role.to_owned(),
                file_name: file_name.to_owned(),
                media_type: media_type.to_owned(),
                sha256: digest,
                size_bytes,
            },
        );
        clear_derived_material(&mut next);
        next.phase = UserJobPhase::Draft;
        next.status_detail = None;
        self.commit(next)
    }

    pub fn input_bytes(&self, role: &str) -> Result<Vec<u8>, UserJobError> {
        let input = self
            .current
            .inputs
            .get(role)
            .ok_or_else(|| UserJobError::MissingRequiredInput(role.to_owned()))?;
        read_blob(&self.product_root, input)
    }

    pub fn record_unresolved(
        &mut self,
        expected_state_digest: &str,
        resolved_intent: Value,
        detail: impl Into<String>,
    ) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if !matches!(self.current.phase, UserJobPhase::Draft | UserJobPhase::UnresolvedIntent) {
            return Err(UserJobError::InvalidTransition);
        }
        let mut next = self.current.clone();
        clear_compiled_material(&mut next);
        next.intent_digest = Some(canonical_json_sha256(&resolved_intent)?);
        next.resolved_intent = Some(resolved_intent);
        next.phase = UserJobPhase::UnresolvedIntent;
        next.status_detail = Some(detail.into());
        self.commit(next)
    }

    pub fn record_compiled(
        &mut self,
        expected_state_digest: &str,
        material: CompiledJobMaterial,
    ) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if !matches!(self.current.phase, UserJobPhase::Draft | UserJobPhase::UnresolvedIntent) {
            return Err(UserJobError::InvalidTransition);
        }
        for role in self.current.job_kind.required_input_roles() {
            if !self.current.inputs.contains_key(*role) {
                return Err(UserJobError::MissingRequiredInput((*role).to_owned()));
            }
        }
        validate_sha256(&material.contract_digest)?;
        validate_sha256(&material.plan_digest)?;
        validate_sha256(&material.permission_digest)?;
        if canonical_json_sha256(&material.work_contract)? != material.contract_digest {
            return Err(UserJobError::ContractDigestMismatch);
        }
        if canonical_json_sha256(&material.operator_plan)? != material.plan_digest {
            return Err(UserJobError::PlanDigestMismatch);
        }
        let mut next = self.current.clone();
        next.intent_digest = Some(canonical_json_sha256(&material.resolved_intent)?);
        next.resolved_intent = Some(material.resolved_intent);
        next.work_contract = Some(material.work_contract);
        next.contract_digest = Some(material.contract_digest);
        next.operator_plan = Some(material.operator_plan);
        next.plan_digest = Some(material.plan_digest);
        next.permission_digest = Some(material.permission_digest);
        next.approval = None;
        next.production = None;
        next.evidence = None;
        next.certificate = None;
        next.phase = UserJobPhase::PermissionRequired;
        next.status_detail = Some("exact_permission_digest_requires_user_approval".to_owned());
        self.commit(next)
    }

    pub fn record_canonical_approval(
        &mut self,
        expected_state_digest: &str,
        binding: ApprovalAuthorityBinding,
    ) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if !matches!(
            self.current.phase,
            UserJobPhase::PermissionRequired | UserJobPhase::ReadyForApproval | UserJobPhase::ApprovalExpired
        ) {
            return Err(UserJobError::InvalidTransition);
        }
        let mut next = self.current.clone();
        next.approval = Some(binding);
        next.phase = UserJobPhase::Approved;
        next.status_detail = None;
        next.validate_approval()?;
        self.commit(next)
    }

    pub fn record_approval_expired(&mut self, expected_state_digest: &str) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if self.current.phase != UserJobPhase::Approved {
            return Err(UserJobError::InvalidTransition);
        }
        let mut next = self.current.clone();
        next.phase = UserJobPhase::ApprovalExpired;
        next.status_detail = Some("approval_expired".to_owned());
        self.commit(next)
    }

    pub fn record_signer_unavailable(
        &mut self,
        expected_state_digest: &str,
        detail: impl Into<String>,
    ) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if !matches!(
            self.current.phase,
            UserJobPhase::Approved | UserJobPhase::ProductionSignerUnavailable
        ) {
            return Err(UserJobError::InvalidTransition);
        }
        let mut next = self.current.clone();
        next.phase = UserJobPhase::ProductionSignerUnavailable;
        next.status_detail = Some(detail.into());
        self.commit(next)
    }

    pub fn record_production_observation(
        &mut self,
        expected_state_digest: &str,
        binding: ProductionBinding,
    ) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if !matches!(
            self.current.phase,
            UserJobPhase::Approved
                | UserJobPhase::ProductionSignerUnavailable
                | UserJobPhase::Executing
                | UserJobPhase::ExecutionFailed
                | UserJobPhase::EvidenceRejected
                | UserJobPhase::RecoveryRequired
        ) {
            return Err(UserJobError::InvalidTransition);
        }
        validate_sha256(&binding.chain_state_digest)?;
        if binding.stage.trim().is_empty() || binding.stage.len() > 64 {
            return Err(UserJobError::InvalidProductionStage);
        }
        let mut next = self.current.clone();
        next.production = Some(binding);
        if next.phase != UserJobPhase::RecoveryRequired {
            next.phase = UserJobPhase::Executing;
            next.status_detail = None;
        }
        self.commit(next)
    }

    pub fn record_execution_failed(
        &mut self,
        expected_state_digest: &str,
        detail: impl Into<String>,
    ) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if self.current.production.is_none()
            || !matches!(self.current.phase, UserJobPhase::Executing | UserJobPhase::ExecutionFailed)
        {
            return Err(UserJobError::InvalidTransition);
        }
        let mut next = self.current.clone();
        next.phase = UserJobPhase::ExecutionFailed;
        next.status_detail = Some(detail.into());
        self.commit(next)
    }

    pub fn record_evidence(
        &mut self,
        expected_state_digest: &str,
        evidence: EvidenceBinding,
    ) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if self.current.production.is_none()
            || !matches!(
                self.current.phase,
                UserJobPhase::Executing | UserJobPhase::ExecutionFailed | UserJobPhase::RecoveryRequired
            )
        {
            return Err(UserJobError::InvalidTransition);
        }
        validate_evidence_binding(&evidence)?;
        let accepted = evidence.accepted;
        let mut next = self.current.clone();
        next.evidence = Some(evidence);
        if next.phase != UserJobPhase::RecoveryRequired {
            if accepted {
                next.phase = UserJobPhase::Executing;
                next.status_detail = Some("evidence_verified_waiting_for_certificate".to_owned());
            } else {
                next.phase = UserJobPhase::EvidenceRejected;
                next.status_detail = Some("validator_or_evidence_rejected".to_owned());
            }
        }
        self.commit(next)
    }

    pub fn record_certificate(
        &mut self,
        expected_state_digest: &str,
        certificate: CertificateBinding,
    ) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if self.current.phase != UserJobPhase::Executing {
            return Err(UserJobError::InvalidTransition);
        }
        let evidence = self.current.evidence.as_ref().ok_or(UserJobError::MissingEvidence)?;
        if !evidence.accepted
            || !certificate.signature_verified
            || !certificate.bundle_verified
            || !certificate.decision_accepted
            || certificate.mandatory_failed != 0
            || certificate.mandatory_unknown != 0
        {
            return Err(UserJobError::AcceptanceInvariantFailed);
        }
        let production = self.current.production.as_ref().ok_or(UserJobError::MissingProductionBinding)?;
        if certificate.production_state_digest != production.chain_state_digest {
            return Err(UserJobError::CertificateProductionBindingMismatch);
        }
        validate_identifier(&certificate.certificate_id)?;
        validate_sha256(&certificate.certificate_digest)?;
        validate_sha256(&certificate.production_state_digest)?;
        let mut next = self.current.clone();
        next.certificate = Some(certificate);
        next.phase = UserJobPhase::Accepted;
        next.status_detail = None;
        self.commit(next)
    }

    pub fn record_recovery_verified(
        &mut self,
        expected_state_digest: &str,
        production_state_digest: &str,
        certificate_digest: &str,
    ) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if self.current.phase != UserJobPhase::RecoveryRequired {
            return Err(UserJobError::InvalidTransition);
        }
        let production = self.current.production.as_ref().ok_or(UserJobError::MissingProductionBinding)?;
        let certificate = self.current.certificate.as_ref().ok_or(UserJobError::MissingCertificate)?;
        if production.chain_state_digest != production_state_digest
            || certificate.production_state_digest != production_state_digest
            || certificate.certificate_digest != certificate_digest
        {
            return Err(UserJobError::RecoveryBindingMismatch);
        }
        let mut next = self.current.clone();
        next.phase = UserJobPhase::Accepted;
        next.status_detail = None;
        self.commit(next)
    }

    pub fn cancel_before_execution(&mut self, expected_state_digest: &str) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        if self.current.production.is_some()
            || matches!(
                self.current.phase,
                UserJobPhase::Executing
                    | UserJobPhase::ExecutionFailed
                    | UserJobPhase::EvidenceRejected
                    | UserJobPhase::RecoveryRequired
                    | UserJobPhase::Accepted
                    | UserJobPhase::RolledBack
            )
        {
            return Err(UserJobError::AuthoritativeProductionReceiptRequired);
        }
        let mut next = self.current.clone();
        next.phase = UserJobPhase::Cancelled;
        next.status_detail = Some("cancelled_before_production_execution".to_owned());
        self.commit(next)
    }

    pub fn record_rollback_observed(
        &mut self,
        expected_state_digest: &str,
        production_state_digest: &str,
    ) -> Result<(), UserJobError> {
        self.verify_expected_state(expected_state_digest)?;
        let production = self.current.production.as_ref().ok_or(UserJobError::MissingProductionBinding)?;
        if production.chain_state_digest != production_state_digest {
            return Err(UserJobError::RecoveryBindingMismatch);
        }
        let mut next = self.current.clone();
        next.phase = UserJobPhase::RolledBack;
        next.status_detail = Some("production_rollback_receipt_observed".to_owned());
        self.commit(next)
    }

    fn verify_expected_state(&self, expected_state_digest: &str) -> Result<(), UserJobError> {
        validate_sha256(expected_state_digest)?;
        if self.current.state_digest != expected_state_digest {
            return Err(UserJobError::StaleState);
        }
        Ok(())
    }

    fn commit(&mut self, mut next: UserJobRecord) -> Result<(), UserJobError> {
        let (_, observed) = load_history(&self.job_root)?;
        if observed.revision != self.current.revision || observed.state_digest != self.current.state_digest {
            return Err(UserJobError::ConcurrentMutation);
        }
        next.revision = self.current.revision.checked_add(1).ok_or(UserJobError::RevisionOverflow)?;
        next.previous_state_digest = Some(self.current.state_digest.clone());
        next.state_digest.clear();
        next.state_digest = next.expected_digest()?;
        next.validate_seal()?;
        write_state(&self.job_root, &next)?;
        self.current = next;
        Ok(())
    }
}

pub fn list_job_ids(product_root: impl AsRef<Path>) -> Result<Vec<String>, UserJobError> {
    let root = product_root.as_ref();
    prepare_product_root(root)?;
    let jobs = jobs_root(root);
    let mut ids = Vec::new();
    for entry in fs::read_dir(&jobs).map_err(|source| io_error("read jobs root", &jobs, source))? {
        let entry = entry.map_err(|source| io_error("read job entry", &jobs, source))?;
        let file_type = entry.file_type().map_err(|source| io_error("inspect job entry", &entry.path(), source))?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(UserJobError::UnexpectedJobEntry);
        }
        let id = entry.file_name().into_string().map_err(|_| UserJobError::NonUtf8Entry)?;
        validate_identifier(&id)?;
        ids.push(id);
    }
    ids.sort();
    Ok(ids)
}

fn validate_evidence_binding(evidence: &EvidenceBinding) -> Result<(), UserJobError> {
    validate_sha256(&evidence.evidence_bundle_digest)?;
    validate_sha256(&evidence.replay_manifest_digest)?;
    if canonical_json_sha256(&evidence.evidence_bundle)? != evidence.evidence_bundle_digest
        || canonical_json_sha256(&evidence.replay_manifest)? != evidence.replay_manifest_digest
    {
        return Err(UserJobError::EvidenceDigestMismatch);
    }
    Ok(())
}

fn clear_derived_material(record: &mut UserJobRecord) {
    clear_compiled_material(record);
    record.resolved_intent = None;
    record.intent_digest = None;
}

fn clear_compiled_material(record: &mut UserJobRecord) {
    record.work_contract = None;
    record.contract_digest = None;
    record.operator_plan = None;
    record.plan_digest = None;
    record.permission_digest = None;
    record.approval = None;
    record.production = None;
    record.evidence = None;
    record.certificate = None;
}

fn prepare_product_root(root: &Path) -> Result<(), UserJobError> {
    if !root.is_absolute() {
        return Err(UserJobError::PathNotAbsolute(root.to_path_buf()));
    }
    if root.exists() {
        reject_existing_directory(root)?;
    } else {
        fs::create_dir_all(root).map_err(|source| io_error("create product root", root, source))?;
        reject_symlink(root)?;
    }
    ensure_directory(&jobs_root(root))?;
    ensure_directory(&blobs_root(root))?;
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<(), UserJobError> {
    if path.exists() {
        reject_existing_directory(path)
    } else {
        fs::create_dir(path).map_err(|source| io_error("create directory", path, source))?;
        reject_symlink(path)
    }
}

fn reject_existing_directory(path: &Path) -> Result<(), UserJobError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error("inspect directory", path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(UserJobError::SymbolicLinkRejected(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(UserJobError::ExpectedDirectory(path.to_path_buf()));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), UserJobError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error("inspect path", path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(UserJobError::SymbolicLinkRejected(path.to_path_buf()));
    }
    Ok(())
}

fn jobs_root(root: &Path) -> PathBuf {
    root.join(JOBS_DIR)
}

fn blobs_root(root: &Path) -> PathBuf {
    root.join(BLOBS_DIR)
}

fn persist_blob(root: &Path, digest: &str, bytes: &[u8]) -> Result<(), UserJobError> {
    validate_sha256(digest)?;
    let blob_path = blobs_root(root).join(format!("{digest}{BLOB_SUFFIX}"));
    if blob_path.exists() {
        let existing = read_stable_file(&blob_path, MAX_INPUT_BYTES)?;
        if sha256_hex(&existing) != digest || existing != bytes {
            return Err(UserJobError::ExistingBlobMismatch);
        }
        return Ok(());
    }
    let pending = blobs_root(root).join(format!(".{digest}.pending"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .map_err(|source| io_error("create pending blob", &pending, source))?;
    file.write_all(bytes).map_err(|source| io_error("write pending blob", &pending, source))?;
    file.sync_all().map_err(|source| io_error("sync pending blob", &pending, source))?;
    drop(file);
    fs::rename(&pending, &blob_path).map_err(|source| io_error("commit immutable blob", &blob_path, source))?;
    let persisted = read_stable_file(&blob_path, MAX_INPUT_BYTES)?;
    if sha256_hex(&persisted) != digest || persisted != bytes {
        return Err(UserJobError::ExistingBlobMismatch);
    }
    Ok(())
}

fn read_blob(root: &Path, input: &ImmutableInput) -> Result<Vec<u8>, UserJobError> {
    validate_sha256(&input.sha256)?;
    let path = blobs_root(root).join(format!("{}{BLOB_SUFFIX}", input.sha256));
    let bytes = read_stable_file(&path, MAX_INPUT_BYTES)?;
    let size = u64::try_from(bytes.len()).map_err(|_| UserJobError::InputTooLarge)?;
    if size != input.size_bytes || sha256_hex(&bytes) != input.sha256 {
        return Err(UserJobError::BlobDigestMismatch);
    }
    Ok(bytes)
}

fn load_history(job_root: &Path) -> Result<(Vec<UserJobRecord>, UserJobRecord), UserJobError> {
    reject_existing_directory(job_root)?;
    let mut by_digest = BTreeMap::<String, UserJobRecord>::new();
    for entry in fs::read_dir(job_root).map_err(|source| io_error("read job history", job_root, source))? {
        let entry = entry.map_err(|source| io_error("read history entry", job_root, source))?;
        let name = entry.file_name().into_string().map_err(|_| UserJobError::NonUtf8Entry)?;
        if name.starts_with(PENDING_PREFIX) && name.ends_with(PENDING_SUFFIX) {
            continue;
        }
        if !name.starts_with(STATE_PREFIX) || !name.ends_with(STATE_SUFFIX) {
            return Err(UserJobError::UnexpectedHistoryEntry(name));
        }
        if by_digest.len() >= MAX_STATES {
            return Err(UserJobError::TooManyStates);
        }
        let state = read_state(&entry.path())?;
        if state_filename(&state) != name {
            return Err(UserJobError::FilenameBindingMismatch);
        }
        if by_digest.insert(state.state_digest.clone(), state).is_some() {
            return Err(UserJobError::DuplicateStateDigest);
        }
    }
    if by_digest.is_empty() {
        return Err(UserJobError::MissingHistory);
    }
    let roots = by_digest
        .values()
        .filter(|state| state.revision == 0 && state.previous_state_digest.is_none())
        .cloned()
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(UserJobError::InvalidHistoryRoot);
    }
    let mut ordered = vec![roots[0].clone()];
    let mut current = roots[0].clone();
    let mut visited = BTreeSet::from([current.state_digest.clone()]);
    loop {
        let children = by_digest
            .values()
            .filter(|state| state.previous_state_digest.as_deref() == Some(current.state_digest.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        match children.as_slice() {
            [] => break,
            [child] => {
                if child.revision != current.revision.checked_add(1).ok_or(UserJobError::RevisionOverflow)? {
                    return Err(UserJobError::InvalidRevisionChain);
                }
                if !visited.insert(child.state_digest.clone()) {
                    return Err(UserJobError::HistoryCycle);
                }
                current = child.clone();
                ordered.push(child.clone());
            }
            _ => return Err(UserJobError::DivergentHistory),
        }
    }
    if visited.len() != by_digest.len() {
        return Err(UserJobError::OrphanedHistory);
    }
    Ok((ordered, current))
}

fn read_state(path: &Path) -> Result<UserJobRecord, UserJobError> {
    let bytes = read_stable_file(path, MAX_STATE_BYTES)?;
    let state: UserJobRecord = serde_json::from_slice(&bytes)?;
    state.validate_seal()?;
    Ok(state)
}

fn write_state(job_root: &Path, state: &UserJobRecord) -> Result<(), UserJobError> {
    state.validate_seal()?;
    let final_path = job_root.join(state_filename(state));
    if final_path.exists() {
        return Err(UserJobError::StateAlreadyExists);
    }
    let pending = job_root.join(format!(
        "{PENDING_PREFIX}{:020}-{}{PENDING_SUFFIX}",
        state.revision, state.state_digest
    ));
    let bytes = serde_json::to_vec(state)?;
    let byte_len = u64::try_from(bytes.len()).map_err(|_| UserJobError::StateTooLarge)?;
    if byte_len > MAX_STATE_BYTES {
        return Err(UserJobError::StateTooLarge);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .map_err(|source| io_error("create pending state", &pending, source))?;
    file.write_all(&bytes).map_err(|source| io_error("write pending state", &pending, source))?;
    file.sync_all().map_err(|source| io_error("sync pending state", &pending, source))?;
    drop(file);
    fs::rename(&pending, &final_path).map_err(|source| io_error("commit state", &final_path, source))?;
    Ok(())
}

fn read_stable_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, UserJobError> {
    let before = fs::symlink_metadata(path).map_err(|source| io_error("inspect file", path, source))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(UserJobError::InvalidFileType(path.to_path_buf()));
    }
    if before.len() == 0 || before.len() > max_bytes {
        return Err(UserJobError::FileSizeRejected(before.len()));
    }
    let before_modified = before.modified().ok();
    let capacity = usize::try_from(before.len()).map_err(|_| UserJobError::FileSizeRejected(before.len()))?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .map_err(|source| io_error("open file", path, source))?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read file", path, source))?;
    let length = u64::try_from(bytes.len()).map_err(|_| UserJobError::FileSizeRejected(u64::MAX))?;
    if length > max_bytes {
        return Err(UserJobError::FileSizeRejected(length));
    }
    let after = fs::symlink_metadata(path).map_err(|source| io_error("reinspect file", path, source))?;
    if before.len() != after.len()
        || before_modified != after.modified().ok()
        || before.file_type() != after.file_type()
    {
        return Err(UserJobError::UnstableRead(path.to_path_buf()));
    }
    Ok(bytes)
}

fn state_filename(state: &UserJobRecord) -> String {
    format!("{STATE_PREFIX}{:020}-{}{STATE_SUFFIX}", state.revision, state.state_digest)
}

fn validate_identifier(value: &str) -> Result<(), UserJobError> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(UserJobError::InvalidIdentifier(value.to_owned()));
    }
    Ok(())
}

fn validate_role(value: &str) -> Result<(), UserJobError> {
    if value.is_empty()
        || value.len() > 80
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-'))
    {
        return Err(UserJobError::InvalidRole(value.to_owned()));
    }
    Ok(())
}

fn validate_file_name(value: &str) -> Result<(), UserJobError> {
    if value.is_empty()
        || value.len() > 255
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || matches!(value, "." | "..")
    {
        return Err(UserJobError::InvalidFileName);
    }
    Ok(())
}

fn validate_media_type(value: &str) -> Result<(), UserJobError> {
    if value.is_empty()
        || value.len() > 255
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(UserJobError::InvalidMediaType);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), UserJobError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(UserJobError::InvalidSha256(value.to_owned()));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn canonical_control_error(error: impl ToString) -> UserJobError {
    UserJobError::CanonicalControl(error.to_string())
}

fn canonical_shell_error(error: impl ToString) -> UserJobError {
    UserJobError::CanonicalShell(error.to_string())
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> UserJobError {
    UserJobError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Error)]
pub enum UserJobError {
    #[error("unsupported persistent user-job schema or profession identity")]
    UnsupportedSchema,
    #[error("path must be absolute: {0}")]
    PathNotAbsolute(PathBuf),
    #[error("symbolic link is rejected: {0}")]
    SymbolicLinkRejected(PathBuf),
    #[error("expected directory: {0}")]
    ExpectedDirectory(PathBuf),
    #[error("invalid file type: {0}")]
    InvalidFileType(PathBuf),
    #[error("unstable file read detected: {0}")]
    UnstableRead(PathBuf),
    #[error("file size rejected: {0}")]
    FileSizeRejected(u64),
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("invalid input role: {0}")]
    InvalidRole(String),
    #[error("input role mismatch: {0}")]
    InputRoleMismatch(String),
    #[error("invalid file name")]
    InvalidFileName,
    #[error("invalid media type")]
    InvalidMediaType,
    #[error("invalid SHA-256 digest: {0}")]
    InvalidSha256(String),
    #[error("input size is invalid: {0}")]
    InvalidInputSize(u64),
    #[error("input is empty or exceeds the immutable import limit")]
    InputTooLarge,
    #[error("required immutable input is missing: {0}")]
    MissingRequiredInput(String),
    #[error("existing digest-addressed blob does not match imported bytes")]
    ExistingBlobMismatch,
    #[error("digest-addressed blob failed re-verification")]
    BlobDigestMismatch,
    #[error("job already exists")]
    JobAlreadyExists,
    #[error("persistent job identity does not match requested job")]
    JobIdentityMismatch,
    #[error("created_at is invalid")]
    InvalidCreatedAt,
    #[error("original user request is empty or too large")]
    InvalidOriginalText,
    #[error("missing persistent history")]
    MissingHistory,
    #[error("history root is invalid")]
    InvalidHistoryRoot,
    #[error("previous state digest is missing")]
    MissingPreviousStateDigest,
    #[error("state digest mismatch")]
    StateDigestMismatch,
    #[error("duplicate state digest")]
    DuplicateStateDigest,
    #[error("state filename does not bind its digest and revision")]
    FilenameBindingMismatch,
    #[error("history revision chain is invalid")]
    InvalidRevisionChain,
    #[error("history fork detected")]
    DivergentHistory,
    #[error("orphaned history detected")]
    OrphanedHistory,
    #[error("history cycle detected")]
    HistoryCycle,
    #[error("unexpected history entry: {0}")]
    UnexpectedHistoryEntry(String),
    #[error("unexpected job-root entry")]
    UnexpectedJobEntry,
    #[error("non-UTF8 persistent entry")]
    NonUtf8Entry,
    #[error("too many state records")]
    TooManyStates,
    #[error("state already exists")]
    StateAlreadyExists,
    #[error("state is too large")]
    StateTooLarge,
    #[error("revision overflow")]
    RevisionOverflow,
    #[error("renderer supplied a stale state digest")]
    StaleState,
    #[error("concurrent persistent mutation detected")]
    ConcurrentMutation,
    #[error("invalid lifecycle transition")]
    InvalidTransition,
    #[error("canonical state must be a JSON object")]
    InvalidCanonicalObject,
    #[error("compiled contract, plan or permission material is missing")]
    MissingCompiledMaterial,
    #[error("resolved intent digest mismatch")]
    IntentDigestMismatch,
    #[error("Work Contract digest mismatch")]
    ContractDigestMismatch,
    #[error("Operator Plan digest mismatch")]
    PlanDigestMismatch,
    #[error("canonical desktop approval is missing")]
    MissingApproval,
    #[error("canonical desktop approval failed verification")]
    CanonicalApprovalRejected,
    #[error("canonical approved DesktopShellSnapshot failed verification")]
    CanonicalApprovalSnapshotRejected,
    #[error("canonical Approve receipt failed verification")]
    CanonicalApprovalReceiptRejected,
    #[error("canonical approval tuple does not bind this persistent job")]
    CanonicalApprovalBindingMismatch,
    #[error("desktop control authority rejected approval material: {0}")]
    CanonicalControl(String),
    #[error("desktop shell authority rejected snapshot material: {0}")]
    CanonicalShell(String),
    #[error("production binding is missing")]
    MissingProductionBinding,
    #[error("production stage is invalid")]
    InvalidProductionStage,
    #[error("evidence bundle is missing")]
    MissingEvidence,
    #[error("evidence or replay-manifest digest mismatch")]
    EvidenceDigestMismatch,
    #[error("evidence state does not match validator decision")]
    EvidenceStateMismatch,
    #[error("Acceptance Certificate is missing")]
    MissingCertificate,
    #[error("Acceptance Certificate production binding mismatch")]
    CertificateProductionBindingMismatch,
    #[error("acceptance invariant failed")]
    AcceptanceInvariantFailed,
    #[error("restart recovery binding mismatch")]
    RecoveryBindingMismatch,
    #[error("authoritative production cancellation or rollback receipt is required")]
    AuthoritativeProductionReceiptRequired,
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("canonical hashing failed: {0}")]
    Hashing(#[from] HashingError),
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use ergaxiom_desktop_shell_runtime::{
        ApprovalSummary, DesktopApprovalRequest, DesktopShellMaterial, DigestItem, StageStatus,
        build_desktop_shell_snapshot, issue_desktop_approval, issue_desktop_command_receipt,
    };
    use serde_json::json;

    use super::*;

    fn test_root(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!(
            "ergaxiom-user-job-{name}-{}-{nonce}",
            std::process::id()
        )))
    }

    fn fake_digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn create_filled_store(root: &Path) -> Result<UserJobStore, Box<dyn std::error::Error>> {
        let mut store = UserJobStore::create(
            root,
            "job.test.0001",
            GraphicDesignerJobKind::ImageBackgroundCleanup,
            "2026-08-14T07:00:00Z",
            "Remove the approved background using the supplied mask.",
        )?;
        for (role, name, media, bytes) in [
            ("intent_manifest", "intent.json", "application/json", b"{}".as_slice()),
            ("source_raster", "source.png", "image/png", b"source".as_slice()),
            ("approved_cleanup_mask", "mask.png", "image/png", b"mask".as_slice()),
        ] {
            let expected = store.current().state_digest.clone();
            store.import_input(&expected, role, name, media, bytes)?;
        }
        Ok(store)
    }

    fn compile_test_material(store: &mut UserJobStore) -> Result<(), Box<dyn std::error::Error>> {
        let contract = json!({"contract_id": "contract.test"});
        let plan = json!({"plan_id": "plan.test"});
        let expected = store.current().state_digest.clone();
        store.record_compiled(
            &expected,
            CompiledJobMaterial {
                resolved_intent: json!({"kind": "cleanup"}),
                contract_digest: canonical_json_sha256(&contract)?,
                work_contract: contract,
                plan_digest: canonical_json_sha256(&plan)?,
                operator_plan: plan,
                permission_digest: fake_digest('a'),
            },
        )?;
        Ok(())
    }

    fn approval_snapshot(
        store: &UserJobStore,
        status: DesktopControlStatus,
        approval: Option<&DesktopApprovalRecord>,
    ) -> Result<DesktopShellSnapshot, Box<dyn std::error::Error>> {
        let contract_digest = store.current().contract_digest.clone().ok_or("contract")?;
        let plan_digest = store.current().plan_digest.clone().ok_or("plan")?;
        let permission_digest = store.current().permission_digest.clone().ok_or("permission")?;
        let (approval_id, expires_at_epoch_s, approval_status, approval_digest) = match approval {
            Some(record) => (
                record.approval_id.clone(),
                record.expires_at_epoch_s,
                StageStatus::Passed,
                Some(record.approval_digest.clone()),
            ),
            None => (
                "approval.pending".to_owned(),
                0,
                StageStatus::Pending,
                None,
            ),
        };
        build_desktop_shell_snapshot(DesktopShellMaterial {
            generated_at: "2026-08-14T07:00:00Z".to_owned(),
            job_id: Some(store.current().job_id.clone()),
            unresolved: Vec::new(),
            staged_inputs: store
                .current()
                .inputs
                .values()
                .map(|input| DigestItem {
                    id: input.role.clone(),
                    media_type: Some(input.media_type.clone()),
                    digest: input.sha256.clone(),
                    status: StageStatus::Passed,
                })
                .collect(),
            contract: Some(DigestItem {
                id: "contract.test".to_owned(),
                media_type: Some("application/json".to_owned()),
                digest: contract_digest.clone(),
                status: StageStatus::Passed,
            }),
            approval: Some(ApprovalSummary {
                approval_id,
                contract_digest,
                plan_digest: plan_digest.clone(),
                permission_digest,
                expires_at_epoch_s,
                status: approval_status,
            }),
            plan: Some(DigestItem {
                id: "plan.test".to_owned(),
                media_type: Some("application/json".to_owned()),
                digest: plan_digest,
                status: StageStatus::Passed,
            }),
            steps: Vec::new(),
            validators: Vec::new(),
            evidence_bundle: None,
            replay_manifest: None,
            certificate: None,
            profession_capsules: Vec::new(),
            adapters: Vec::new(),
            trusted_keys: Vec::new(),
            metadata: json!({
                "control_status": match status {
                    DesktopControlStatus::AwaitingApproval => "awaiting_approval",
                    DesktopControlStatus::Approved => "approved",
                    DesktopControlStatus::Executed => "executed",
                    DesktopControlStatus::Cancelled => "cancelled",
                    DesktopControlStatus::RolledBack => "rolled_back",
                },
                "approval_digest": approval_digest,
            }),
        })
        .map_err(Into::into)
    }

    fn install_canonical_approval(store: &mut UserJobStore) -> Result<(), Box<dyn std::error::Error>> {
        let awaiting = approval_snapshot(store, DesktopControlStatus::AwaitingApproval, None)?;
        let record = issue_desktop_approval(
            &awaiting,
            &DesktopApprovalRequest {
                expected_snapshot_digest: awaiting.snapshot_digest.clone(),
                contract_digest: store.current().contract_digest.clone().ok_or("contract")?,
                plan_digest: store.current().plan_digest.clone().ok_or("plan")?,
                permission_digest: store.current().permission_digest.clone().ok_or("permission")?,
            },
            "ergaxiom.local.operator",
            100,
            60,
        )?;
        let approved = approval_snapshot(store, DesktopControlStatus::Approved, Some(&record))?;
        let receipt = issue_desktop_command_receipt(
            DesktopCommandAction::Approve,
            "ergaxiom.local.operator",
            &awaiting,
            &approved,
            Some(&record.approval_digest),
            100,
        )?;
        let expected = store.current().state_digest.clone();
        store.record_canonical_approval(
            &expected,
            ApprovalAuthorityBinding {
                record,
                approved_snapshot: approved,
                approve_receipt: receipt,
            },
        )?;
        Ok(())
    }

    #[test]
    fn all_four_jobs_require_an_immutable_intent_manifest() {
        for kind in [
            GraphicDesignerJobKind::StaticSocialPost,
            GraphicDesignerJobKind::ImageBackgroundCleanup,
            GraphicDesignerJobKind::BrandCompliantImageExport,
            GraphicDesignerJobKind::PrintReadyPosterPreflight,
        ] {
            assert!(kind.required_input_roles().contains(&"intent_manifest"));
            assert!(kind.required_input_roles().len() >= 3);
        }
    }

    #[test]
    fn imported_bytes_are_digest_addressed_without_trusted_paths() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("immutable")?;
        let mut store = UserJobStore::create(
            &root,
            "job.test.immutable",
            GraphicDesignerJobKind::PrintReadyPosterPreflight,
            "2026-08-14T07:00:00Z",
            "Prepare this poster for print.",
        )?;
        let expected = store.current().state_digest.clone();
        store.import_input(&expected, "intent_manifest", "intent.json", "application/json", b"manifest")?;
        let input = store.current().inputs.get("intent_manifest").ok_or("missing input")?;
        assert_eq!(input.sha256, sha256_hex(b"manifest"));
        assert!(!input.file_name.contains('/'));
        assert!(!input.file_name.contains('\\'));
        assert_eq!(store.input_bytes("intent_manifest")?, b"manifest");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn incomplete_draft_can_cancel_without_fake_inputs() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("cancel")?;
        let mut store = UserJobStore::create(
            &root,
            "job.test.cancel",
            GraphicDesignerJobKind::BrandCompliantImageExport,
            "2026-08-14T07:00:00Z",
            "Cancel this before execution.",
        )?;
        let expected = store.current().state_digest.clone();
        store.cancel_before_execution(&expected)?;
        assert_eq!(store.current().phase, UserJobPhase::Cancelled);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stale_renderer_digest_and_history_corruption_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("stale")?;
        let mut store = create_filled_store(&root)?;
        let stale = store.current().previous_state_digest.clone().ok_or("missing previous digest")?;
        let error = store.record_unresolved(&stale, json!({"intent": "x"}), "missing field");
        assert!(matches!(error, Err(UserJobError::StaleState)));
        fs::write(store.job_root.join("forged.json"), b"{}")?;
        let reopened = UserJobStore::open(&root, "job.test.0001");
        assert!(matches!(reopened, Err(UserJobError::UnexpectedHistoryEntry(_))));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn canonical_desktop_approval_is_required_and_persisted() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("approval")?;
        let mut store = create_filled_store(&root)?;
        compile_test_material(&mut store)?;
        install_canonical_approval(&mut store)?;
        assert_eq!(store.current().phase, UserJobPhase::Approved);
        let binding = store.current().approval.as_ref().ok_or("approval")?;
        assert!(verify_desktop_approval(&binding.record)?);
        assert!(verify_desktop_command_receipt(&binding.approve_receipt)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn accepted_job_reopens_as_recovery_required() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("recovery")?;
        let mut store = create_filled_store(&root)?;
        compile_test_material(&mut store)?;
        install_canonical_approval(&mut store)?;
        let production_digest = fake_digest('b');
        let expected = store.current().state_digest.clone();
        store.record_production_observation(
            &expected,
            ProductionBinding {
                chain_state_digest: production_digest.clone(),
                stage: "certified".to_owned(),
            },
        )?;
        let bundle = json!({"schema_version": "test", "claims": []});
        let replay = json!({"schema_version": "test", "steps": []});
        let expected = store.current().state_digest.clone();
        store.record_evidence(
            &expected,
            EvidenceBinding {
                evidence_bundle_digest: canonical_json_sha256(&bundle)?,
                evidence_bundle: bundle,
                replay_manifest_digest: canonical_json_sha256(&replay)?,
                replay_manifest: replay,
                validator_results: Vec::new(),
                failure_map: None,
                accepted: true,
            },
        )?;
        let expected = store.current().state_digest.clone();
        store.record_certificate(
            &expected,
            CertificateBinding {
                certificate_id: "certificate.test.0001".to_owned(),
                certificate_digest: fake_digest('c'),
                production_state_digest: production_digest,
                acceptance_certificate: json!({"certificate": "real-backend-package"}),
                signature_verified: true,
                bundle_verified: true,
                decision_accepted: true,
                mandatory_failed: 0,
                mandatory_unknown: 0,
            },
        )?;
        assert_eq!(store.current().phase, UserJobPhase::Accepted);
        drop(store);
        let reopened = UserJobStore::open(&root, "job.test.0001")?;
        assert_eq!(reopened.current().phase, UserJobPhase::RecoveryRequired);
        assert_eq!(reopened.current().status_detail.as_deref(), Some("restart_reverification_required"));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
