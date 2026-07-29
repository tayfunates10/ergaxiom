use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ergaxiom_capability_issuance_runtime::{
    CapabilityTokenDraft, ProductionCapabilitySignerTransport,
};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_desktop_shell_runtime::{
    DesktopApprovalRecord, DesktopCommandReceipt, DesktopShellSnapshot,
};
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{HashingError, canonical_json_bytes, canonical_json_sha256};
use ergaxiom_windows_production_governed_issuance_runtime::{
    GovernedProductionCapabilityIssuanceAuthority, GovernedProductionIssuanceError,
};
use ergaxiom_windows_production_trust_state_runtime::{
    ProductionSignerDeploymentPolicy, ProductionSignerIdentityProofError,
    VerifiedProductionSignerTrustLease, VerifiedProductionTrustState,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AuthorizedProductionCapabilityIssuance, BackendIssuanceError, BackendIssuanceKind,
    BackendIssuancePolicy,
};

const POLICY_STATE_SCHEMA: &str = "0.1.0";
const POLICY_STATE_PREFIX: &str = "policy-state-";
const POLICY_STATE_SUFFIX: &str = ".json";
const POLICY_PENDING_PREFIX: &str = ".pending-policy-state-";
const POLICY_PENDING_SUFFIX: &str = ".tmp";
const MAX_POLICY_STATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_POLICY_STATE_RECORDS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendIssuancePolicyState {
    schema_version: String,
    revision: u64,
    previous_state_digest: Option<String>,
    pending: BTreeMap<String, String>,
    consumed: BTreeSet<String>,
    authorized_intents: BTreeSet<String>,
    state_digest: String,
}

impl BackendIssuancePolicyState {
    fn initial() -> Result<Self, BackendIssuancePolicyStoreError> {
        Self::from_policy(&BackendIssuancePolicy::default(), 0, None)
    }

    fn from_policy(
        policy: &BackendIssuancePolicy,
        revision: u64,
        previous_state_digest: Option<String>,
    ) -> Result<Self, BackendIssuancePolicyStoreError> {
        let mut state = Self {
            schema_version: POLICY_STATE_SCHEMA.to_owned(),
            revision,
            previous_state_digest,
            pending: policy.pending.clone(),
            consumed: policy.consumed.clone(),
            authorized_intents: policy.authorized_intents.clone(),
            state_digest: String::new(),
        };
        state.state_digest = state.expected_digest()?;
        state.validate_seal()?;
        Ok(state)
    }

    fn to_policy(&self) -> BackendIssuancePolicy {
        BackendIssuancePolicy {
            pending: self.pending.clone(),
            consumed: self.consumed.clone(),
            authorized_intents: self.authorized_intents.clone(),
        }
    }

    pub fn validate_seal(&self) -> Result<(), BackendIssuancePolicyStoreError> {
        if self.schema_version != POLICY_STATE_SCHEMA {
            return Err(BackendIssuancePolicyStoreError::UnsupportedSchema);
        }
        if self.revision == 0 {
            if self.previous_state_digest.is_some()
                || !self.pending.is_empty()
                || !self.consumed.is_empty()
                || !self.authorized_intents.is_empty()
            {
                return Err(BackendIssuancePolicyStoreError::InvalidInitialState);
            }
        } else {
            let previous = self
                .previous_state_digest
                .as_deref()
                .ok_or(BackendIssuancePolicyStoreError::MissingPreviousDigest)?;
            validate_sha256(previous)?;
        }
        for (authorization_id, authorization_digest) in &self.pending {
            validate_authorization_id(authorization_id)?;
            validate_sha256(authorization_digest)?;
            if self.consumed.contains(authorization_id) {
                return Err(BackendIssuancePolicyStoreError::PendingConsumedOverlap);
            }
        }
        for authorization_id in &self.consumed {
            validate_authorization_id(authorization_id)?;
        }
        for intent_digest in &self.authorized_intents {
            validate_sha256(intent_digest)?;
        }
        validate_sha256(&self.state_digest)?;
        if self.state_digest != self.expected_digest()? {
            return Err(BackendIssuancePolicyStoreError::StateDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, BackendIssuancePolicyStoreError> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(BackendIssuancePolicyStoreError::InvalidCanonicalObject)?;
        object.insert("state_digest".to_owned(), Value::String(String::new()));
        Ok(canonical_json_sha256(&value)?)
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn state_digest(&self) -> &str {
        &self.state_digest
    }

    #[must_use]
    pub fn previous_state_digest(&self) -> Option<&str> {
        self.previous_state_digest.as_deref()
    }

    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }

    #[must_use]
    pub fn authorized_intent_count(&self) -> usize {
        self.authorized_intents.len()
    }
}

#[derive(Debug)]
pub struct BackendIssuancePolicyStore {
    root: PathBuf,
    current: BackendIssuancePolicyState,
}

impl BackendIssuancePolicyStore {
    pub fn load_or_create(
        root: impl AsRef<Path>,
    ) -> Result<(Self, BackendIssuancePolicy), BackendIssuancePolicyStoreError> {
        let root = root.as_ref().to_path_buf();
        prepare_store_root(&root)?;
        let current = match scan_policy_chain(&root)? {
            Some(state) => state,
            None => {
                let initial = BackendIssuancePolicyState::initial()?;
                write_policy_state(&root, &initial)?;
                initial
            }
        };
        let policy = current.to_policy();
        Ok((Self { root, current }, policy))
    }

    pub fn commit(
        &mut self,
        policy: &BackendIssuancePolicy,
    ) -> Result<&BackendIssuancePolicyState, BackendIssuancePolicyStoreError> {
        let observed = scan_policy_chain(&self.root)?
            .ok_or(BackendIssuancePolicyStoreError::MissingCurrentState)?;
        if observed.revision != self.current.revision
            || observed.state_digest != self.current.state_digest
        {
            return Err(BackendIssuancePolicyStoreError::ConcurrentMutation);
        }
        let revision = self
            .current
            .revision
            .checked_add(1)
            .ok_or(BackendIssuancePolicyStoreError::RevisionOverflow)?;
        let next = BackendIssuancePolicyState::from_policy(
            policy,
            revision,
            Some(self.current.state_digest.clone()),
        )?;
        write_policy_state(&self.root, &next)?;
        self.current = next;
        Ok(&self.current)
    }

    #[must_use]
    pub const fn current_state(&self) -> &BackendIssuancePolicyState {
        &self.current
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug)]
pub struct PersistentBackendProductionCapabilityAuthority {
    policy: BackendIssuancePolicy,
    store: BackendIssuancePolicyStore,
    executor_id: String,
    device_id: Option<String>,
}

impl PersistentBackendProductionCapabilityAuthority {
    pub fn load_or_create(
        store_root: impl AsRef<Path>,
        executor_id: impl Into<String>,
        device_id: Option<String>,
    ) -> Result<Self, PersistentBackendProductionIssuanceError> {
        let (store, policy) = BackendIssuancePolicyStore::load_or_create(store_root)?;
        Ok(Self {
            policy,
            store,
            executor_id: executor_id.into(),
            device_id,
        })
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
    ) -> Result<AuthorizedProductionCapabilityIssuance, PersistentBackendProductionIssuanceError>
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

        // Persist the consumed authorization and intent reservation before the signer side effect.
        // A signer rejection therefore remains terminal and cannot be replayed after a restart.
        self.store.commit(&self.policy)?;
        let token = capability_authority.issue(draft)?;
        Ok(AuthorizedProductionCapabilityIssuance {
            authorization,
            token,
        })
    }

    #[must_use]
    pub const fn policy_state(&self) -> &BackendIssuancePolicyState {
        self.store.current_state()
    }

    #[must_use]
    pub fn store_root(&self) -> &Path {
        self.store.root()
    }
}

fn prepare_store_root(root: &Path) -> Result<(), BackendIssuancePolicyStoreError> {
    if !root.is_absolute() {
        return Err(BackendIssuancePolicyStoreError::PathNotAbsolute(
            root.to_path_buf(),
        ));
    }
    if root.exists() {
        let metadata = symlink_metadata(root, "inspect policy store root")?;
        if metadata.file_type().is_symlink() {
            return Err(BackendIssuancePolicyStoreError::DirectSymbolicLink(
                root.to_path_buf(),
            ));
        }
        if !metadata.is_dir() {
            return Err(BackendIssuancePolicyStoreError::StoreRootNotDirectory(
                root.to_path_buf(),
            ));
        }
    } else {
        fs::create_dir_all(root).map_err(|source| BackendIssuancePolicyStoreError::Io {
            operation: "create policy store root",
            path: root.to_path_buf(),
            source,
        })?;
    }
    let metadata = symlink_metadata(root, "reinspect policy store root")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackendIssuancePolicyStoreError::StoreRootNotDirectory(
            root.to_path_buf(),
        ));
    }
    Ok(())
}

fn scan_policy_chain(
    root: &Path,
) -> Result<Option<BackendIssuancePolicyState>, BackendIssuancePolicyStoreError> {
    let mut states = BTreeMap::<String, BackendIssuancePolicyState>::new();
    let entries = fs::read_dir(root).map_err(|source| BackendIssuancePolicyStoreError::Io {
        operation: "read policy store root",
        path: root.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| BackendIssuancePolicyStoreError::Io {
            operation: "read policy store entry",
            path: root.to_path_buf(),
            source,
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| BackendIssuancePolicyStoreError::NonUtf8Entry)?;
        if name.starts_with(POLICY_PENDING_PREFIX) && name.ends_with(POLICY_PENDING_SUFFIX) {
            continue;
        }
        if !name.starts_with(POLICY_STATE_PREFIX) || !name.ends_with(POLICY_STATE_SUFFIX) {
            return Err(BackendIssuancePolicyStoreError::UnexpectedEntry(name));
        }
        if states.len() >= MAX_POLICY_STATE_RECORDS {
            return Err(BackendIssuancePolicyStoreError::TooManyRecords);
        }
        let path = entry.path();
        let state = read_policy_state(&path)?;
        let expected_name = policy_state_filename(&state);
        if name != expected_name {
            return Err(BackendIssuancePolicyStoreError::FilenameBindingMismatch);
        }
        if states.insert(state.state_digest.clone(), state).is_some() {
            return Err(BackendIssuancePolicyStoreError::DuplicateStateDigest);
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
        return Err(BackendIssuancePolicyStoreError::InvalidChainRoot);
    }
    let mut current = roots[0].clone();
    let mut visited = BTreeSet::from([current.state_digest.clone()]);
    loop {
        let children = states
            .values()
            .filter(|state| state.previous_state_digest.as_deref() == Some(&current.state_digest))
            .cloned()
            .collect::<Vec<_>>();
        match children.as_slice() {
            [] => break,
            [child] => {
                if child.revision != current.revision.saturating_add(1) {
                    return Err(BackendIssuancePolicyStoreError::InvalidRevisionChain);
                }
                if !visited.insert(child.state_digest.clone()) {
                    return Err(BackendIssuancePolicyStoreError::CycleDetected);
                }
                current = child.clone();
            }
            _ => return Err(BackendIssuancePolicyStoreError::DivergentHistory),
        }
    }
    if visited.len() != states.len() {
        return Err(BackendIssuancePolicyStoreError::OrphanedHistory);
    }
    Ok(Some(current))
}

fn read_policy_state(
    path: &Path,
) -> Result<BackendIssuancePolicyState, BackendIssuancePolicyStoreError> {
    let before = symlink_metadata(path, "inspect policy state")?;
    if before.file_type().is_symlink() {
        return Err(BackendIssuancePolicyStoreError::DirectSymbolicLink(
            path.to_path_buf(),
        ));
    }
    if !before.is_file() {
        return Err(BackendIssuancePolicyStoreError::UnexpectedEntry(
            path.display().to_string(),
        ));
    }
    if before.len() > MAX_POLICY_STATE_BYTES {
        return Err(BackendIssuancePolicyStoreError::RecordTooLarge);
    }
    let before_modified = before.modified().ok();
    let mut file = File::open(path).map_err(|source| BackendIssuancePolicyStoreError::Io {
        operation: "open policy state",
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
    file.take(MAX_POLICY_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| BackendIssuancePolicyStoreError::Io {
            operation: "read policy state",
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_POLICY_STATE_BYTES {
        return Err(BackendIssuancePolicyStoreError::RecordTooLarge);
    }
    let after = symlink_metadata(path, "reinspect policy state")?;
    if before.len() != after.len()
        || before_modified != after.modified().ok()
        || before.file_type() != after.file_type()
    {
        return Err(BackendIssuancePolicyStoreError::UnstableRead);
    }
    let state: BackendIssuancePolicyState = serde_json::from_slice(&bytes)?;
    state.validate_seal()?;
    Ok(state)
}

fn write_policy_state(
    root: &Path,
    state: &BackendIssuancePolicyState,
) -> Result<PathBuf, BackendIssuancePolicyStoreError> {
    state.validate_seal()?;
    let final_path = root.join(policy_state_filename(state));
    if final_path.exists() {
        return Err(BackendIssuancePolicyStoreError::StateAlreadyExists);
    }
    let temp_path = root.join(format!(
        "{POLICY_PENDING_PREFIX}{:020}-{}{POLICY_PENDING_SUFFIX}",
        state.revision, state.state_digest
    ));
    let bytes = canonical_json_bytes(&serde_json::to_value(state)?)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_POLICY_STATE_BYTES {
        return Err(BackendIssuancePolicyStoreError::RecordTooLarge);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|source| BackendIssuancePolicyStoreError::Io {
            operation: "create pending policy state",
            path: temp_path.clone(),
            source,
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| BackendIssuancePolicyStoreError::Io {
            operation: "write pending policy state",
            path: temp_path.clone(),
            source,
        })?;
    if let Err(source) = fs::hard_link(&temp_path, &final_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(BackendIssuancePolicyStoreError::Io {
            operation: "publish immutable policy state",
            path: final_path,
            source,
        });
    }
    fs::remove_file(&temp_path).map_err(|source| BackendIssuancePolicyStoreError::Io {
        operation: "remove pending policy state",
        path: temp_path,
        source,
    })?;
    Ok(final_path)
}

fn policy_state_filename(state: &BackendIssuancePolicyState) -> String {
    format!(
        "{POLICY_STATE_PREFIX}{:020}-{}{POLICY_STATE_SUFFIX}",
        state.revision, state.state_digest
    )
}

fn symlink_metadata(
    path: &Path,
    operation: &'static str,
) -> Result<fs::Metadata, BackendIssuancePolicyStoreError> {
    fs::symlink_metadata(path).map_err(|source| BackendIssuancePolicyStoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    })
}

fn validate_authorization_id(value: &str) -> Result<(), BackendIssuancePolicyStoreError> {
    let Some(suffix) = value.strip_prefix("authorization.issuance.") else {
        return Err(BackendIssuancePolicyStoreError::InvalidAuthorizationId);
    };
    if suffix.len() != 24 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BackendIssuancePolicyStoreError::InvalidAuthorizationId);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), BackendIssuancePolicyStoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BackendIssuancePolicyStoreError::InvalidSha256);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum PersistentBackendProductionIssuanceError {
    #[error(transparent)]
    Store(#[from] BackendIssuancePolicyStoreError),
    #[error(transparent)]
    Lease(#[from] ProductionSignerIdentityProofError),
    #[error(transparent)]
    Authorization(#[from] BackendIssuanceError),
    #[error(transparent)]
    Governed(#[from] GovernedProductionIssuanceError),
}

#[derive(Debug, Error)]
pub enum BackendIssuancePolicyStoreError {
    #[error("backend issuance policy store path must be absolute: {0}")]
    PathNotAbsolute(PathBuf),
    #[error("backend issuance policy store path is a direct symbolic link: {0}")]
    DirectSymbolicLink(PathBuf),
    #[error("backend issuance policy store root is not a directory: {0}")]
    StoreRootNotDirectory(PathBuf),
    #[error("backend issuance policy store contains a non-UTF-8 entry")]
    NonUtf8Entry,
    #[error("backend issuance policy store contains an unexpected entry: {0}")]
    UnexpectedEntry(String),
    #[error("backend issuance policy store contains too many records")]
    TooManyRecords,
    #[error("backend issuance policy record exceeds the bounded size")]
    RecordTooLarge,
    #[error("backend issuance policy record changed while it was read")]
    UnstableRead,
    #[error("backend issuance policy state schema is unsupported")]
    UnsupportedSchema,
    #[error("backend issuance policy initial state is invalid")]
    InvalidInitialState,
    #[error("backend issuance policy state is missing its previous digest")]
    MissingPreviousDigest,
    #[error("backend issuance policy pending and consumed authorization sets overlap")]
    PendingConsumedOverlap,
    #[error("backend issuance policy authorization ID is invalid")]
    InvalidAuthorizationId,
    #[error("backend issuance policy SHA-256 value is invalid")]
    InvalidSha256,
    #[error("backend issuance policy state digest does not match")]
    StateDigestMismatch,
    #[error("backend issuance policy state is not a canonical object")]
    InvalidCanonicalObject,
    #[error("backend issuance policy state filename does not bind its revision and digest")]
    FilenameBindingMismatch,
    #[error("backend issuance policy store contains a duplicate state digest")]
    DuplicateStateDigest,
    #[error("backend issuance policy chain must contain exactly one initial root")]
    InvalidChainRoot,
    #[error("backend issuance policy revision chain is invalid")]
    InvalidRevisionChain,
    #[error("backend issuance policy history contains a cycle")]
    CycleDetected,
    #[error("backend issuance policy history diverged")]
    DivergentHistory,
    #[error("backend issuance policy history contains orphaned records")]
    OrphanedHistory,
    #[error("backend issuance policy current state is missing")]
    MissingCurrentState,
    #[error("backend issuance policy store changed concurrently")]
    ConcurrentMutation,
    #[error("backend issuance policy revision overflowed")]
    RevisionOverflow,
    #[error("backend issuance policy state already exists")]
    StateAlreadyExists,
    #[error("failed to serialize backend issuance policy state: {0}")]
    Serialization(#[from] serde_json::Error),
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
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "ergaxiom-backend-policy-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn policy_state_survives_restart_and_preserves_replay_sets() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("restart");
        let (mut store, mut policy) = BackendIssuancePolicyStore::load_or_create(&root)?;
        policy.consumed.insert(
            "authorization.issuance.0123456789abcdef01234567".to_owned(),
        );
        policy.authorized_intents.insert("a".repeat(64));
        let committed = store.commit(&policy)?.clone();
        assert_eq!(committed.revision(), 1);
        drop(store);

        let (reloaded, recovered) = BackendIssuancePolicyStore::load_or_create(&root)?;
        assert_eq!(reloaded.current_state(), &committed);
        assert_eq!(recovered.consumed, policy.consumed);
        assert_eq!(recovered.authorized_intents, policy.authorized_intents);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn corrupted_published_record_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("corrupt");
        let (mut store, mut policy) = BackendIssuancePolicyStore::load_or_create(&root)?;
        policy.authorized_intents.insert("b".repeat(64));
        store.commit(&policy)?;
        let current_path = root.join(policy_state_filename(store.current_state()));
        fs::write(&current_path, b"{}")?;
        assert!(BackendIssuancePolicyStore::load_or_create(&root).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn abandoned_pending_record_is_ignored_during_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_root("pending");
        let (store, _) = BackendIssuancePolicyStore::load_or_create(&root)?;
        fs::write(
            root.join(format!(
                "{POLICY_PENDING_PREFIX}00000000000000000001-{}{POLICY_PENDING_SUFFIX}",
                "c".repeat(64)
            )),
            b"partial",
        )?;
        let (reloaded, _) = BackendIssuancePolicyStore::load_or_create(&root)?;
        assert_eq!(
            reloaded.current_state().state_digest(),
            store.current_state().state_digest()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
