from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    target = Path(path)
    text = target.read_text()
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"{label} anchor missing in {path}")
    target.write_text(text.replace(old, new, 1))


authority = "crates/production-execution-authority-runtime/src/lib.rs"
replace_once(
    authority,
    '''use ergaxiom_production_execution_runtime::{
    ProductionExecutionChainState, ProductionExecutionChainStore, ProductionExecutionStoreError,
};
''',
    '''use ergaxiom_production_execution_runtime::{
    ProductionExecutionChainState, ProductionExecutionChainStore, ProductionExecutionStage,
    ProductionExecutionStoreError,
};
''',
    "authority stage import",
)
replace_once(
    authority,
    '''    pub fn record_approval(
''',
    '''    fn require_stage(
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
''',
    "authority stage guard helper",
)
replace_once(
    authority,
    '''    {
        lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
        let capability_authority = GovernedProductionCapabilityIssuanceAuthority::new(
''',
    '''    {
        self.require_stage(&[
            ProductionExecutionStage::Approved,
            ProductionExecutionStage::CapabilitiesIssued,
        ])?;
        lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
        let capability_authority = GovernedProductionCapabilityIssuanceAuthority::new(
''',
    "capability signer-before-stage guard",
)
replace_once(
    authority,
    '''    ) -> Result<AuthorizationReceipt, PersistentProductionExecutionAuthorityError> {
        lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
        let persisted = self
''',
    '''    ) -> Result<AuthorizationReceipt, PersistentProductionExecutionAuthorityError> {
        self.require_stage(&[
            ProductionExecutionStage::CapabilitiesIssued,
            ProductionExecutionStage::CapabilitiesConsumed,
        ])?;
        lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
        let persisted = self
''',
    "capability consumption stage guard",
)
replace_once(
    authority,
    '''    {
        lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
        self.verify_execution_evidence_binding(bundle_value, snapshot)?;
        let attestation_authority = GovernedProductionAttestationIssuanceAuthority::new(
''',
    '''    {
        self.require_stage(&[ProductionExecutionStage::Executed])?;
        lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
        self.verify_execution_evidence_binding(bundle_value, snapshot)?;
        let attestation_authority = GovernedProductionAttestationIssuanceAuthority::new(
''',
    "attestation signer-before-stage guard",
)

runtime = "crates/production-execution-runtime/src/lib.rs"
replace_once(
    runtime,
    '''    if state.stage != ProductionExecutionStage::Certified {
        return Err(ProductionExecutionVerifyError::NotCertified);
    }
''',
    '''    if !matches!(
        state.stage,
        ProductionExecutionStage::Certified | ProductionExecutionStage::RolledBack
    ) {
        return Err(ProductionExecutionVerifyError::NotCertified);
    }
''',
    "rolled-back certified-chain verification",
)

test = Path("crates/production-execution-authority-runtime/tests/persistent_chain.rs")
text = test.read_text()
text = text.replace(
    '''use ergaxiom_production_execution_runtime::{
    ProductionExecutionStage, verify_recovered_certified_chain,
};
''',
    '''use ergaxiom_production_execution_runtime::{
    ProductionExecutionStage, ProductionExecutionStoreError, verify_recovered_certified_chain,
};
''',
    1,
)
anchor = '''#[test]
fn unified_authority_never_retries_after_production_signer_rejection() -> Result<(), Box<dyn Error>>
'''
cancellation_test = '''#[test]
fn cancellation_survives_restart_and_blocks_capability_signing_before_signer()
-> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = capability_chain_at(&context, live::LIVE_NOW - 20, 200)?;
    let (policy_root, chain_root) = unified_store_roots("cancel-restart");
    let cleanup_root = policy_root
        .parent()
        .ok_or("missing cancellation test parent")?
        .to_path_buf();

    let mut authority = PersistentProductionExecutionAuthority::load_or_create(
        &policy_root,
        &chain_root,
        JOB_ID,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    authority.record_approval(
        chain.approved.clone(),
        chain.approval.clone(),
        chain.approve_receipt.clone(),
    )?;
    let cancelled = snapshot(
        &context,
        DesktopControlStatus::Cancelled,
        Some(&chain.approval),
        &chain.approval.permission_digest,
        None,
        None,
    )?;
    let cancel_receipt = issue_desktop_command_receipt(
        DesktopCommandAction::Cancel,
        ACTOR_ID,
        &chain.approved,
        &cancelled,
        Some(&chain.approval.approval_digest),
        live::LIVE_NOW,
    )?;
    authority.record_cancellation(cancel_receipt.clone())?;
    assert_eq!(authority.chain_state().stage, ProductionExecutionStage::Cancelled);
    let cancelled_digest = authority.chain_state().state_digest.clone();

    let blocked = live::harness(false)?;
    assert!(matches!(
        authority.issue_capability(
            blocked.transport,
            &blocked.lease,
            &blocked.accepted,
            &blocked.deployment_policy,
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &context.contract,
            &context.plan,
            capability_draft_at(&context, live::LIVE_NOW),
            live::LIVE_NOW,
            60,
        ),
        Err(PersistentProductionExecutionAuthorityError::ExecutionStore(
            ProductionExecutionStoreError::InvalidTransition
        ))
    ));
    assert_eq!(blocked.calls.get(), 0);
    drop(authority);

    let recovered = PersistentProductionExecutionAuthority::load_or_create(
        &policy_root,
        &chain_root,
        JOB_ID,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    assert_eq!(recovered.chain_state().stage, ProductionExecutionStage::Cancelled);
    assert_eq!(recovered.chain_state().state_digest, cancelled_digest);
    assert_eq!(
        recovered.chain_state().cancel_receipt.as_ref(),
        Some(&cancel_receipt)
    );

    fs::remove_dir_all(cleanup_root)?;
    Ok(())
}

#[test]
fn unified_authority_never_retries_after_production_signer_rejection() -> Result<(), Box<dyn Error>>
'''
if cancellation_test not in text:
    if anchor not in text:
        raise SystemExit("cancellation test insertion anchor missing")
    text = text.replace(anchor, cancellation_test, 1)

text = text.replace(
    '''    let recovered = PersistentProductionExecutionAuthority::load_or_create(
        &policy_root,
        &chain_root,
        JOB_ID,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    assert_eq!(recovered.chain_state().state_digest, certified_digest);
''',
    '''    let mut recovered = PersistentProductionExecutionAuthority::load_or_create(
        &policy_root,
        &chain_root,
        JOB_ID,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    assert_eq!(recovered.chain_state().state_digest, certified_digest);
''',
    1,
)
text = text.replace(
    '''        context.contract,
        &context.plan,
        AssuranceLevel::E1,
''',
    '''        context.contract.clone(),
        &context.plan,
        AssuranceLevel::E1,
''',
    1,
)
end_anchor = '''    assert_eq!(
        recovered_verified.certificate_id,
        "certificate.production-execution.e2e"
    );

    fs::remove_dir_all(cleanup_root)?;
'''
rollback_block = '''    assert_eq!(
        recovered_verified.certificate_id,
        "certificate.production-execution.e2e"
    );

    let certified = recovered
        .chain_state()
        .final_snapshot
        .as_ref()
        .ok_or("certified snapshot missing before rollback")?
        .clone();
    let rolled_back = rolled_back_snapshot(&certified)?;
    let rollback_receipt = issue_desktop_command_receipt(
        DesktopCommandAction::Rollback,
        ACTOR_ID,
        &certified,
        &rolled_back,
        Some(&chain.approval.approval_digest),
        attestation_live::LIVE_NOW,
    )?;
    recovered.record_rollback(rollback_receipt.clone())?;
    assert_eq!(
        recovered.chain_state().stage,
        ProductionExecutionStage::RolledBack
    );
    let rolled_back_digest = recovered.chain_state().state_digest.clone();
    drop(recovered);

    let rollback_recovery = attestation_live::harness(false)?;
    let rolled_back_recovered = PersistentProductionExecutionAuthority::load_or_create(
        &policy_root,
        &chain_root,
        JOB_ID,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    assert_eq!(
        rolled_back_recovered.chain_state().stage,
        ProductionExecutionStage::RolledBack
    );
    assert_eq!(
        rolled_back_recovered.chain_state().state_digest,
        rolled_back_digest
    );
    assert_eq!(
        rolled_back_recovered.chain_state().rollback_receipt.as_ref(),
        Some(&rollback_receipt)
    );
    let rollback_verified = verify_recovered_certified_chain(
        rolled_back_recovered.chain_state(),
        &rollback_recovery.lease,
        &rollback_recovery.accepted,
        &rollback_recovery.deployment_policy,
        attestation_live::LIVE_NOW,
        context.contract.clone(),
        &context.plan,
        AssuranceLevel::E1,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?;
    assert_eq!(rollback_verified.decision, DecisionStatus::Accepted);
    assert_eq!(
        rollback_verified.certificate_id,
        "certificate.production-execution.e2e"
    );

    fs::remove_dir_all(cleanup_root)?;
'''
if rollback_block not in text:
    if end_anchor not in text:
        raise SystemExit("rollback extension anchor missing")
    text = text.replace(end_anchor, rollback_block, 1)

helper_anchor = '''fn encode_hex_bytes(bytes: &[u8]) -> String {
'''
helper = '''fn rolled_back_snapshot(
    certified: &DesktopShellSnapshot,
) -> Result<DesktopShellSnapshot, Box<dyn Error>> {
    let mut steps = certified.steps.clone();
    for step in &mut steps {
        step.status = StageStatus::Blocked;
    }
    Ok(build_desktop_shell_snapshot(DesktopShellMaterial {
        generated_at: certified.generated_at.clone(),
        job_id: certified.job_id.clone(),
        unresolved: certified.unresolved.clone(),
        staged_inputs: certified.staged_inputs.clone(),
        contract: certified.contract.clone(),
        approval: certified.approval.clone(),
        plan: certified.plan.clone(),
        steps,
        validators: certified.validators.clone(),
        evidence_bundle: certified.evidence_bundle.clone(),
        replay_manifest: certified.replay_manifest.clone(),
        certificate: certified.certificate.clone(),
        profession_capsules: certified.profession_capsules.clone(),
        adapters: certified.adapters.clone(),
        trusted_keys: certified.trusted_keys.clone(),
        metadata: json!({
            "control_status": DesktopControlStatus::RolledBack,
            "approval_digest": certified.metadata.get("approval_digest").cloned(),
            "terminal_transition": true,
            "certified_evidence_preserved": certified.certificate.is_some(),
        }),
    })?)
}

fn encode_hex_bytes(bytes: &[u8]) -> String {
'''
if helper not in text:
    if helper_anchor not in text:
        raise SystemExit("rollback helper anchor missing")
    text = text.replace(helper_anchor, helper, 1)

test.write_text(text)
