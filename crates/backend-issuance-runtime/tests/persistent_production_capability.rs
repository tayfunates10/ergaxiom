include!("authorization.rs");

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_backend_issuance_runtime::{
    PersistentBackendProductionCapabilityAuthority, PersistentBackendProductionIssuanceError,
};

mod live {
    include!("../../windows-production-trust-state-runtime/tests/deployed_service.rs");

    use std::cell::RefCell;

    use ergaxiom_capability_issuance_runtime::{
        CapabilityIssuanceError, ProductionCapabilitySignerTransport,
    };
    use ergaxiom_windows_production_signer_service_runtime::AuthorizedProductionSignerPackage;
    use ergaxiom_windows_production_trust_state_runtime::{
        ProductionSignerIdentityChallenge, VerifiedProductionSignerTrustLease,
        VerifiedProductionTrustState,
    };

    pub(super) const LIVE_NOW: u64 = ACTIVATION + 4;
    pub(super) const LEASE_EXPIRES_AT: u64 = ACTIVATION + 22;

    pub(super) struct LiveTransport {
        service: RefCell<TrustBoundProductionSignerService<GenerationBackend>>,
        caller: ergaxiom_windows_production_signer_runtime::AuthenticatedCallerIdentity,
        calls: Rc<Cell<u32>>,
        reject: bool,
    }

    impl ProductionCapabilitySignerTransport for LiveTransport {
        fn invoke(
            &self,
            request: &ProductionSignerRequest,
        ) -> Result<AuthorizedProductionSignerPackage, CapabilityIssuanceError> {
            self.calls.set(self.calls.get().saturating_add(1));
            let mut caller = self.caller.clone();
            if self.reject {
                caller.executable_sha256 = "f".repeat(64);
            }
            self.service
                .borrow_mut()
                .handle_authenticated(request, &caller, LIVE_NOW)
                .map(|package| package.signer_package)
                .map_err(|error| {
                    CapabilityIssuanceError::Serialization(serde_json::Error::io(
                        std::io::Error::other(error.to_string()),
                    ))
                })
        }
    }

    pub(super) struct LiveHarness {
        pub(super) transport: LiveTransport,
        pub(super) lease: VerifiedProductionSignerTrustLease,
        pub(super) accepted: VerifiedProductionTrustState,
        pub(super) deployment_policy: ProductionSignerDeploymentPolicy,
        pub(super) calls: Rc<Cell<u32>>,
    }

    pub(super) fn harness(reject: bool) -> Result<LiveHarness, Box<dyn Error>> {
        let fixture = Fixture::build(GenerationBackend::production()?)?;
        let accepted = fixture.accepted.clone();
        let deployment_policy = fixture.deployment_policy.clone();
        let caller = fixture.caller.clone();
        let challenge = ProductionSignerIdentityChallenge::build(
            "identity-proof-persistent-capability",
            "d".repeat(64),
            &accepted,
            &deployment_policy,
            ACTIVATION + 2,
            LEASE_EXPIRES_AT,
        )?;
        let mut service = TrustBoundProductionSignerService::new(
            fixture.service,
            accepted.clone(),
            deployment_policy.clone(),
        )?;
        let proof = service.handle_identity_challenge(&challenge, &caller, ACTIVATION + 3)?;
        let lease =
            proof.verify_trust_lease(&challenge, &accepted, &deployment_policy, LIVE_NOW)?;
        let calls = Rc::new(Cell::new(0));
        Ok(LiveHarness {
            transport: LiveTransport {
                service: RefCell::new(service),
                caller,
                calls: calls.clone(),
                reject,
            },
            lease,
            accepted,
            deployment_policy,
            calls,
        })
    }
}

struct CapabilityControlChain {
    approved: DesktopShellSnapshot,
    approval: DesktopApprovalRecord,
    approve_receipt: DesktopCommandReceipt,
}

fn capability_chain_at(
    context: &Context,
    approval_at_epoch_s: u64,
    approval_ttl_s: u64,
) -> Result<CapabilityControlChain, Box<dyn Error>> {
    let permission_value = serde_json::to_value(&context.contract.permissions)?;
    let permission_digest = canonical_json_sha256(&permission_value)?;
    let pending = snapshot(
        context,
        DesktopControlStatus::AwaitingApproval,
        None,
        &permission_digest,
        None,
        None,
    )?;
    let approval = issue_desktop_approval(
        &pending,
        &DesktopApprovalRequest {
            expected_snapshot_digest: pending.snapshot_digest.clone(),
            contract_digest: context.contract.seal.contract_digest.clone(),
            plan_digest: context.plan.plan_digest.clone(),
            permission_digest: permission_digest.clone(),
        },
        ACTOR_ID,
        approval_at_epoch_s,
        approval_ttl_s,
    )?;
    let approved = snapshot(
        context,
        DesktopControlStatus::Approved,
        Some(&approval),
        &permission_digest,
        None,
        None,
    )?;
    let approve_receipt = issue_desktop_command_receipt(
        DesktopCommandAction::Approve,
        ACTOR_ID,
        &pending,
        &approved,
        Some(&approval.approval_digest),
        approval_at_epoch_s,
    )?;
    Ok(CapabilityControlChain {
        approved,
        approval,
        approve_receipt,
    })
}

fn capability_draft_at(context: &Context, issued_at_epoch_s: u64) -> CapabilityTokenDraft {
    let mut draft = capability_draft(context);
    draft.issued_at_epoch_s = issued_at_epoch_s;
    draft.not_before_epoch_s = issued_at_epoch_s;
    draft.expires_at_epoch_s = issued_at_epoch_s + 10;
    draft
}

fn store_root(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "ergaxiom-persistent-capability-{name}-{}-{nonce}",
        std::process::id()
    ))
}

#[test]
fn consumed_capability_intent_survives_authority_and_lease_restart() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = capability_chain_at(&context, live::LIVE_NOW - 20, 200)?;
    let draft = capability_draft_at(&context, live::LIVE_NOW);
    let root = store_root("restart");

    let first = live::harness(false)?;
    let mut authority = PersistentBackendProductionCapabilityAuthority::load_or_create(
        &root,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    let issued = authority.issue_capability(
        first.transport,
        &first.lease,
        &first.accepted,
        &first.deployment_policy,
        &chain.approved,
        &chain.approval,
        &chain.approve_receipt,
        &context.contract,
        &context.plan,
        draft.clone(),
        live::LIVE_NOW,
        60,
    )?;
    assert_eq!(issued.authorization.kind, BackendIssuanceKind::Capability);
    assert_eq!(first.calls.get(), 1);
    assert_eq!(authority.policy_state().revision(), 1);
    assert_eq!(authority.policy_state().consumed_count(), 1);
    assert_eq!(authority.policy_state().authorized_intent_count(), 1);
    drop(authority);

    let second = live::harness(false)?;
    let mut recovered = PersistentBackendProductionCapabilityAuthority::load_or_create(
        &root,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    assert!(matches!(
        recovered.issue_capability(
            second.transport,
            &second.lease,
            &second.accepted,
            &second.deployment_policy,
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &context.contract,
            &context.plan,
            draft,
            live::LIVE_NOW,
            60,
        ),
        Err(PersistentBackendProductionIssuanceError::Authorization(
            BackendIssuanceError::IntentAlreadyAuthorized
        ))
    ));
    assert_eq!(second.calls.get(), 0);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn signer_rejection_is_persisted_as_terminal_before_restart() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = capability_chain_at(&context, live::LIVE_NOW - 20, 200)?;
    let draft = capability_draft_at(&context, live::LIVE_NOW);
    let root = store_root("rejection");

    let rejected = live::harness(true)?;
    let mut authority = PersistentBackendProductionCapabilityAuthority::load_or_create(
        &root,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
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
        Err(PersistentBackendProductionIssuanceError::Governed(_))
    ));
    assert_eq!(rejected.calls.get(), 1);
    assert_eq!(authority.policy_state().revision(), 1);
    drop(authority);

    let retry = live::harness(false)?;
    let mut recovered = PersistentBackendProductionCapabilityAuthority::load_or_create(
        &root,
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
        Err(PersistentBackendProductionIssuanceError::Authorization(
            BackendIssuanceError::IntentAlreadyAuthorized
        ))
    ));
    assert_eq!(retry.calls.get(), 0);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn expired_live_lease_fails_before_policy_mutation_or_signer_call() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = capability_chain_at(&context, live::LIVE_NOW - 20, 200)?;
    let root = store_root("expired");
    let harness = live::harness(false)?;
    let mut authority = PersistentBackendProductionCapabilityAuthority::load_or_create(
        &root,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    assert!(matches!(
        authority.issue_capability(
            harness.transport,
            &harness.lease,
            &harness.accepted,
            &harness.deployment_policy,
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &context.contract,
            &context.plan,
            capability_draft_at(&context, live::LEASE_EXPIRES_AT),
            live::LEASE_EXPIRES_AT,
            60,
        ),
        Err(PersistentBackendProductionIssuanceError::Lease(_))
    ));
    assert_eq!(harness.calls.get(), 0);
    assert_eq!(authority.policy_state().revision(), 0);
    assert_eq!(authority.policy_state().authorized_intent_count(), 0);
    fs::remove_dir_all(root)?;
    Ok(())
}
