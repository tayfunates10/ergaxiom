include!("../../backend-issuance-runtime/tests/persistent_production_capability.rs");

use ergaxiom_production_execution_authority_runtime::{
    PersistentProductionExecutionAuthority, PersistentProductionExecutionAuthorityError,
};
use ergaxiom_production_execution_runtime::ProductionExecutionStage;

fn unified_store_roots(name: &str) -> (PathBuf, PathBuf) {
    let base = store_root(name);
    (base.join("policy"), base.join("chain"))
}

#[test]
fn unified_authority_persists_token_consumption_across_restart() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = capability_chain_at(&context, live::LIVE_NOW - 20, 200)?;
    let draft = capability_draft_at(&context, live::LIVE_NOW);
    let token_id = draft.token_id.clone();
    let (policy_root, chain_root) = unified_store_roots("unified-restart");
    let cleanup_root = policy_root
        .parent()
        .ok_or("missing unified test parent")?
        .to_path_buf();

    let first = live::harness(false)?;
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
    authority.issue_capability(
        first.transport,
        &first.lease,
        &first.accepted,
        &first.deployment_policy,
        &chain.approved,
        &chain.approval,
        &chain.approve_receipt,
        &context.contract,
        &context.plan,
        draft,
        live::LIVE_NOW,
        60,
    )?;
    let receipt = authority.consume_capability(
        &token_id,
        &first.lease,
        &first.accepted,
        &first.deployment_policy,
        &context.contract,
        &context.plan,
        live::LIVE_NOW,
    )?;
    assert_eq!(receipt.token_id, token_id);
    assert_eq!(receipt.use_number, 1);
    assert_eq!(receipt.max_uses, 1);
    assert_eq!(
        authority.chain_state().stage,
        ProductionExecutionStage::CapabilitiesConsumed
    );
    let chain_digest = authority.chain_state().state_digest.clone();
    drop(authority);

    let second = live::harness(false)?;
    let mut recovered = PersistentProductionExecutionAuthority::load_or_create(
        &policy_root,
        &chain_root,
        JOB_ID,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    assert_eq!(recovered.chain_state().state_digest, chain_digest);
    assert_eq!(
        recovered.chain_state().stage,
        ProductionExecutionStage::CapabilitiesConsumed
    );
    assert!(matches!(
        recovered.consume_capability(
            &token_id,
            &second.lease,
            &second.accepted,
            &second.deployment_policy,
            &context.contract,
            &context.plan,
            live::LIVE_NOW,
        ),
        Err(PersistentProductionExecutionAuthorityError::CapabilityAlreadyConsumed)
    ));
    assert_eq!(second.calls.get(), 0);

    fs::remove_dir_all(cleanup_root)?;
    Ok(())
}

#[test]
fn unified_authority_never_retries_after_production_signer_rejection()
-> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = capability_chain_at(&context, live::LIVE_NOW - 20, 200)?;
    let draft = capability_draft_at(&context, live::LIVE_NOW);
    let (policy_root, chain_root) = unified_store_roots("unified-rejection");
    let cleanup_root = policy_root
        .parent()
        .ok_or("missing unified test parent")?
        .to_path_buf();

    let rejected = live::harness(true)?;
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
    assert!(matches!(
        authority.issue_capability(
            rejected.transport,
            &rejected.lease,
            &rejected.accepted,
            &rejected.deployment_policy,
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &context.contract,
            &context.plan,
            draft.clone(),
            live::LIVE_NOW,
            60,
        ),
        Err(PersistentProductionExecutionAuthorityError::Governed(_))
    ));
    assert_eq!(rejected.calls.get(), 1);
    assert_eq!(authority.chain_state().stage, ProductionExecutionStage::Approved);
    drop(authority);

    let retry = live::harness(false)?;
    let mut recovered = PersistentProductionExecutionAuthority::load_or_create(
        &policy_root,
        &chain_root,
        JOB_ID,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    assert!(matches!(
        recovered.issue_capability(
            retry.transport,
            &retry.lease,
            &retry.accepted,
            &retry.deployment_policy,
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &context.contract,
            &context.plan,
            draft,
            live::LIVE_NOW,
            60,
        ),
        Err(PersistentProductionExecutionAuthorityError::Authorization(
            BackendIssuanceError::IntentAlreadyAuthorized
        ))
    ));
    assert_eq!(retry.calls.get(), 0);

    fs::remove_dir_all(cleanup_root)?;
    Ok(())
}
