include!("../../backend-issuance-runtime/tests/persistent_production_capability.rs");

use ergaxiom_capability_runtime::AuthorizationReceipt;
use ergaxiom_desktop_shell_runtime::CertificateVerification;
use ergaxiom_graphic_designer_twin_runtime::{
    ApprovedCopy, ApprovedLogo, BrandProfile, CanvasSpecification, GraphicDesignJob, PixelRect,
    Rgba8,
};
use ergaxiom_graphic_production_evidence_runtime::{
    ProductionGraphicEvidenceRequest, build_production_graphic_evidence,
};
use ergaxiom_occupational_twin_runtime::{ApplicationIdentity, EnvironmentIdentity, TwinWorkspace};
use ergaxiom_proof_kernel::DecisionStatus;
use ergaxiom_windows_production_governed_issuance_runtime::verify_governed_production_attestation_against_bundle;
use sha2::{Digest as _, Sha256};

use ergaxiom_production_execution_authority_runtime::{
    PersistentProductionExecutionAuthority, PersistentProductionExecutionAuthorityError,
};
use ergaxiom_production_execution_runtime::{
    ProductionExecutionStage, ProductionExecutionStoreError, verify_recovered_certified_chain,
};

mod attestation_live {
    include!("../../windows-production-trust-state-runtime/tests/deployed_service.rs");

    use std::cell::RefCell;

    use ergaxiom_attestation_issuance_runtime::{
        AttestationIssuanceError, ProductionAttestationSignerTransport,
    };
    use ergaxiom_windows_production_signer_service_runtime::AuthorizedProductionSignerPackage;
    use ergaxiom_windows_production_trust_state_runtime::{
        ProductionSignerIdentityChallenge, VerifiedProductionSignerTrustLease,
        VerifiedProductionTrustState,
    };

    pub(super) const LIVE_NOW: u64 = ACTIVATION + 4;
    const LEASE_EXPIRES_AT: u64 = ACTIVATION + 22;

    pub(super) struct LiveTransport {
        service: RefCell<TrustBoundProductionSignerService<GenerationBackend>>,
        caller: ergaxiom_windows_production_signer_runtime::AuthenticatedCallerIdentity,
        calls: Rc<Cell<u32>>,
        reject: bool,
    }

    impl ProductionAttestationSignerTransport for LiveTransport {
        fn invoke(
            &self,
            request: &ProductionSignerRequest,
        ) -> Result<AuthorizedProductionSignerPackage, AttestationIssuanceError> {
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
                    AttestationIssuanceError::Serialization(serde_json::Error::io(
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
            "identity-proof-production-execution-attestation",
            "e".repeat(64),
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
    assert_eq!(
        authority.chain_state().stage,
        ProductionExecutionStage::Cancelled
    );
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
    assert_eq!(
        recovered.chain_state().stage,
        ProductionExecutionStage::Cancelled
    );
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
{
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
    assert_eq!(
        authority.chain_state().stage,
        ProductionExecutionStage::Approved
    );
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

#[test]
fn full_production_chain_certifies_and_recovers_without_fallback() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = capability_chain_at(&context, live::LIVE_NOW - 20, 200)?;
    let draft = capability_draft_at(&context, live::LIVE_NOW);
    let token_id = draft.token_id.clone();
    let (policy_root, chain_root) = unified_store_roots("full-chain");
    let cleanup_root = policy_root
        .parent()
        .ok_or("missing unified test parent")?
        .to_path_buf();

    let capability = live::harness(false)?;
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
        capability.transport,
        &capability.lease,
        &capability.accepted,
        &capability.deployment_policy,
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
        &capability.lease,
        &capability.accepted,
        &capability.deployment_policy,
        &context.contract,
        &context.plan,
        live::LIVE_NOW,
    )?;
    let receipt_digest = canonical_json_sha256(&serde_json::to_value(&receipt)?)?;
    let bundle = production_bound_bundle(&context, &receipt, &receipt_digest)?;
    let assessment = assess_bundle(
        context.contract.clone(),
        &context.plan,
        &bundle,
        AssuranceLevel::E1,
    )?;
    assert_eq!(assessment.decision.status, DecisionStatus::Accepted);
    assert_eq!(assessment.mandatory_failed, 0);
    assert_eq!(assessment.mandatory_unknown, 0);

    let evidence_bundle: EvidenceBundle = serde_json::from_value(bundle.clone())?;
    let replay = build_replay_manifest(
        "manifest.production-execution.e2e",
        &context.plan,
        &evidence_bundle,
        &assessment.bundle_digest,
        assessment.decision.status,
        AssuranceLevel::E1,
        assessment.mandatory_passed,
        assessment.mandatory_failed,
        assessment.mandatory_unknown,
    )?;
    let replay_digest = canonical_json_sha256(&serde_json::to_value(&replay)?)?;
    let executed = snapshot(
        &context,
        DesktopControlStatus::Executed,
        Some(&chain.approval),
        &chain.approval.permission_digest,
        Some(&assessment.bundle_digest),
        Some(&replay_digest),
    )?;
    authority.verify_execution_evidence_binding(&bundle, &executed)?;

    let mut tampered = bundle.clone();
    tampered["trace"]["authorization_receipts"][0]["receipt"]["operator_id"] =
        json!("operator.substituted");
    assert!(
        authority
            .verify_execution_evidence_binding(&tampered, &executed)
            .is_err()
    );

    let execute_receipt = issue_desktop_command_receipt(
        DesktopCommandAction::Execute,
        ACTOR_ID,
        &chain.approved,
        &executed,
        Some(&chain.approval.approval_digest),
        live::LIVE_NOW,
    )?;
    authority.record_execution(
        executed.clone(),
        execute_receipt.clone(),
        bundle.clone(),
        replay.clone(),
    )?;
    assert_eq!(
        authority.chain_state().stage,
        ProductionExecutionStage::Executed
    );

    let attestation = attestation_live::harness(false)?;
    let issuance = authority.issue_attestation(
        attestation.transport,
        &attestation.lease,
        &attestation.accepted,
        &attestation.deployment_policy,
        &executed,
        &chain.approval,
        &execute_receipt,
        context.contract.clone(),
        &context.plan,
        &bundle,
        AssuranceLevel::E1,
        AttestationCertificateDraft {
            manifest_id: "manifest.production-execution.e2e".to_owned(),
            certificate_id: "certificate.production-execution.e2e".to_owned(),
            issued_at_epoch_s: attestation_live::LIVE_NOW,
        },
        attestation_live::LIVE_NOW,
        60,
    )?;
    assert_eq!(attestation.calls.get(), 1);
    let verified = verify_governed_production_attestation_against_bundle(
        &issuance.package,
        attestation.lease.attestation_trust(),
        attestation.lease.registry(),
        context.contract.clone(),
        &context.plan,
        &bundle,
        AssuranceLevel::E1,
    )?;
    assert_eq!(verified.decision, DecisionStatus::Accepted);
    assert_eq!(verified.evidence_bundle_digest, assessment.bundle_digest);

    let final_snapshot = certified_snapshot(&executed, &verified)?;
    authority.record_certificate(issuance, final_snapshot)?;
    assert_eq!(
        authority.chain_state().stage,
        ProductionExecutionStage::Certified
    );
    let certified_digest = authority.chain_state().state_digest.clone();
    drop(authority);

    let recovery = attestation_live::harness(false)?;
    let mut recovered = PersistentProductionExecutionAuthority::load_or_create(
        &policy_root,
        &chain_root,
        JOB_ID,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    assert_eq!(recovered.chain_state().state_digest, certified_digest);
    recovered.verify_execution_evidence_binding(
        recovered
            .chain_state()
            .evidence_bundle
            .as_ref()
            .ok_or("recovered bundle missing")?,
        recovered
            .chain_state()
            .executed_snapshot
            .as_ref()
            .ok_or("recovered executed snapshot missing")?,
    )?;
    let recovered_verified = verify_recovered_certified_chain(
        recovered.chain_state(),
        &recovery.lease,
        &recovery.accepted,
        &recovery.deployment_policy,
        attestation_live::LIVE_NOW,
        context.contract.clone(),
        &context.plan,
        AssuranceLevel::E1,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?;
    assert_eq!(recovered_verified.decision, DecisionStatus::Accepted);
    assert_eq!(
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
        rolled_back_recovered
            .chain_state()
            .rollback_receipt
            .as_ref(),
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
    Ok(())
}

const GRAPHIC_CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const GRAPHIC_CAPSULE_SOURCE: &str =
    include_str!("../../../professions/graphic-designer/profession.json");

struct GraphicProductionContext {
    contract_value: Value,
    compiled_contract: CompiledContract,
    compiled_plan: CompiledPlan,
    job: GraphicDesignJob,
}

struct GraphicApprovalChain {
    approved: DesktopShellSnapshot,
    approval: DesktopApprovalRecord,
    approve_receipt: DesktopCommandReceipt,
}

#[test]
fn graphic_designer_e3_production_chain_certifies_and_recovers_with_four_real_tokens()
-> Result<(), Box<dyn Error>> {
    let graphic = graphic_production_context()?;
    let chain = graphic_approval_chain(&graphic)?;
    let (policy_root, chain_root) = unified_store_roots("graphic-e3-full-chain");
    let cleanup_root = policy_root
        .parent()
        .ok_or("missing graphic E3 test parent")?
        .to_path_buf();
    let mut authority = PersistentProductionExecutionAuthority::load_or_create(
        &policy_root,
        &chain_root,
        &graphic.job.job_id,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    authority.record_approval(
        chain.approved.clone(),
        chain.approval.clone(),
        chain.approve_receipt.clone(),
    )?;

    let mut token_ids = Vec::with_capacity(graphic.compiled_plan.steps.len());
    for (index, step) in graphic.compiled_plan.steps.iter().enumerate() {
        let harness = live::harness(false)?;
        let permission = graphic_permission_for_step(&graphic, &step.operator_id)?;
        let token_id = step
            .capability_token_ids
            .first()
            .ok_or("graphic production step is missing Capability token ID")?
            .clone();
        let draft = CapabilityTokenDraft {
            token_id: token_id.clone(),
            subject: CapabilitySubject {
                executor_id: EXECUTOR_ID.to_owned(),
                device_id: Some(DEVICE_ID.to_owned()),
            },
            issued_at_epoch_s: live::LIVE_NOW,
            not_before_epoch_s: live::LIVE_NOW,
            expires_at_epoch_s: chain.approval.expires_at_epoch_s,
            max_uses: 1,
            nonce: format!("graphic-production-capability-nonce-{index:02}"),
            bindings: CapabilityBindings {
                contract_digest: graphic.compiled_contract.seal.contract_digest.clone(),
                capsule_digest: graphic.compiled_contract.seal.capsule_digest.clone(),
                plan_id: graphic.compiled_plan.plan_id.clone(),
                plan_digest: graphic.compiled_plan.plan_digest.clone(),
                step_id: step.step_id.clone(),
                operator_id: step.operator_id.clone(),
            },
            grant: CapabilityGrant {
                capability: permission.capability.clone(),
                resource: permission.resource.clone(),
                access: permission.access,
                constraints: permission.constraints.clone(),
            },
        };
        authority.issue_capability(
            harness.transport,
            &harness.lease,
            &harness.accepted,
            &harness.deployment_policy,
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &graphic.compiled_contract,
            &graphic.compiled_plan,
            draft,
            live::LIVE_NOW,
            60,
        )?;
        token_ids.push(token_id);
    }
    assert_eq!(authority.chain_state().capabilities.len(), 4);
    assert_eq!(
        authority.chain_state().stage,
        ProductionExecutionStage::CapabilitiesIssued
    );

    let mut receipts = Vec::with_capacity(token_ids.len());
    for token_id in &token_ids {
        let harness = live::harness(false)?;
        let receipt = authority.consume_capability(
            token_id,
            &harness.lease,
            &harness.accepted,
            &harness.deployment_policy,
            &graphic.compiled_contract,
            &graphic.compiled_plan,
            live::LIVE_NOW,
        )?;
        assert_eq!(receipt.use_number, 1);
        assert_eq!(receipt.max_uses, 1);
        receipts.push(receipt);
    }
    assert_eq!(receipts.len(), 4);
    assert_eq!(
        authority.chain_state().stage,
        ProductionExecutionStage::CapabilitiesConsumed
    );

    let mut workspace = graphic_workspace()?;
    let evidence = build_production_graphic_evidence(ProductionGraphicEvidenceRequest {
        workspace: &mut workspace,
        compiled_contract: &graphic.compiled_contract,
        contract_value: &graphic.contract_value,
        compiled_plan: &graphic.compiled_plan,
        job: &graphic.job,
        authorization_receipts: &receipts,
        assurance_level: AssuranceLevel::E3,
        bundle_id: "bundle.graphic-production-authority.e3",
        run_id: "run.graphic-production-authority.e3",
        trace_id: "trace.graphic-production-authority.e3",
    })?;
    assert_eq!(evidence.operation_receipts.len(), 4);
    assert_eq!(
        evidence.evidence_bundle.trace.authorization_receipts.len(),
        4
    );
    assert_eq!(evidence.evidence_bundle.trace.events.len(), 8);

    let bundle = graphic_bundle_with_operation_receipts(&evidence)?;
    let assessment = assess_bundle(
        graphic.compiled_contract.clone(),
        &graphic.compiled_plan,
        &bundle,
        AssuranceLevel::E3,
    )?;
    assert_eq!(assessment.decision.status, DecisionStatus::Accepted);
    assert_eq!(assessment.mandatory_failed, 0);
    assert_eq!(assessment.mandatory_unknown, 0);
    let evidence_bundle: EvidenceBundle = serde_json::from_value(bundle.clone())?;
    let replay = build_replay_manifest(
        "manifest.graphic-production-authority.e3",
        &graphic.compiled_plan,
        &evidence_bundle,
        &assessment.bundle_digest,
        assessment.decision.status,
        AssuranceLevel::E3,
        assessment.mandatory_passed,
        assessment.mandatory_failed,
        assessment.mandatory_unknown,
    )?;
    let replay_digest = canonical_json_sha256(&serde_json::to_value(&replay)?)?;
    let executed = graphic_executed_snapshot(
        &graphic,
        &chain.approval,
        &evidence,
        &assessment.bundle_digest,
        &replay_digest,
    )?;
    authority.verify_execution_evidence_binding(&bundle, &executed)?;
    let execute_receipt = issue_desktop_command_receipt(
        DesktopCommandAction::Execute,
        ACTOR_ID,
        &chain.approved,
        &executed,
        Some(&chain.approval.approval_digest),
        live::LIVE_NOW,
    )?;
    authority.record_execution(
        executed.clone(),
        execute_receipt.clone(),
        bundle.clone(),
        replay,
    )?;

    let attestation = attestation_live::harness(false)?;
    let issuance = authority.issue_attestation(
        attestation.transport,
        &attestation.lease,
        &attestation.accepted,
        &attestation.deployment_policy,
        &executed,
        &chain.approval,
        &execute_receipt,
        graphic.compiled_contract.clone(),
        &graphic.compiled_plan,
        &bundle,
        AssuranceLevel::E3,
        AttestationCertificateDraft {
            manifest_id: "manifest.graphic-production-authority.e3".to_owned(),
            certificate_id: "certificate.graphic-production-authority.e3".to_owned(),
            issued_at_epoch_s: attestation_live::LIVE_NOW,
        },
        attestation_live::LIVE_NOW,
        60,
    )?;
    let verified = verify_governed_production_attestation_against_bundle(
        &issuance.package,
        attestation.lease.attestation_trust(),
        attestation.lease.registry(),
        graphic.compiled_contract.clone(),
        &graphic.compiled_plan,
        &bundle,
        AssuranceLevel::E3,
    )?;
    assert_eq!(verified.decision, DecisionStatus::Accepted);
    let final_snapshot = certified_snapshot(&executed, &verified)?;
    authority.record_certificate(issuance, final_snapshot)?;
    let certified_digest = authority.chain_state().state_digest.clone();
    drop(authority);

    let recovery = attestation_live::harness(false)?;
    let recovered = PersistentProductionExecutionAuthority::load_or_create(
        &policy_root,
        &chain_root,
        &graphic.job.job_id,
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )?;
    assert_eq!(recovered.chain_state().state_digest, certified_digest);
    assert_eq!(recovered.chain_state().capabilities.len(), 4);
    assert!(
        recovered
            .chain_state()
            .capabilities
            .iter()
            .all(|capability| {
                capability.consumption_receipt.is_some()
                    && capability.consumption_receipt_digest.is_some()
            })
    );
    recovered.verify_execution_evidence_binding(
        recovered
            .chain_state()
            .evidence_bundle
            .as_ref()
            .ok_or("recovered E3 Evidence Bundle missing")?,
        recovered
            .chain_state()
            .executed_snapshot
            .as_ref()
            .ok_or("recovered E3 executed snapshot missing")?,
    )?;
    let recovered_verified = verify_recovered_certified_chain(
        recovered.chain_state(),
        &recovery.lease,
        &recovery.accepted,
        &recovery.deployment_policy,
        attestation_live::LIVE_NOW,
        graphic.compiled_contract,
        &graphic.compiled_plan,
        AssuranceLevel::E3,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?;
    assert_eq!(recovered_verified.decision, DecisionStatus::Accepted);
    assert_eq!(
        recovered_verified.certificate_id,
        "certificate.graphic-production-authority.e3"
    );

    fs::remove_dir_all(cleanup_root)?;
    Ok(())
}

fn graphic_production_context() -> Result<GraphicProductionContext, Box<dyn Error>> {
    let job = graphic_job();
    let mut contract_value: Value = serde_json::from_str(GRAPHIC_CONTRACT_SOURCE)?;
    graphic_set_constraint_expected(&mut contract_value, "canvas_width", json!(240))?;
    graphic_set_constraint_expected(&mut contract_value, "canvas_height", json!(300))?;
    graphic_set_constraint_expected(&mut contract_value, "logo_clear_space", json!(16))?;
    graphic_set_input_digest(
        &mut contract_value,
        &job.approved_logo.artifact_id,
        &graphic_sha256_hex(&job.approved_logo.content),
    )?;
    graphic_set_input_digest(
        &mut contract_value,
        &job.approved_copy.artifact_id,
        &graphic_sha256_hex(job.approved_copy.text.as_bytes()),
    )?;
    let brand_profile_bytes = serde_json::to_vec(&job.brand_profile)?;
    graphic_set_input_digest(
        &mut contract_value,
        &job.brand_profile.artifact_id,
        &graphic_sha256_hex(&brand_profile_bytes),
    )?;
    let capsule_value: Value = serde_json::from_str(GRAPHIC_CAPSULE_SOURCE)?;
    let compiled_contract = compile_contract(&contract_value, &capsule_value)?;
    let compiled_plan = compile_plan(
        &graphic_plan_value(&compiled_contract),
        &capsule_value,
        &compiled_contract,
    )?;
    Ok(GraphicProductionContext {
        contract_value,
        compiled_contract,
        compiled_plan,
        job,
    })
}

fn graphic_approval_chain(
    graphic: &GraphicProductionContext,
) -> Result<GraphicApprovalChain, Box<dyn Error>> {
    let permission_value = serde_json::to_value(&graphic.compiled_contract.permissions)?;
    let permission_digest = canonical_json_sha256(&permission_value)?;
    let pending = graphic_snapshot(
        graphic,
        DesktopControlStatus::AwaitingApproval,
        None,
        &permission_digest,
        None,
        None,
        None,
    )?;
    let approval = issue_desktop_approval(
        &pending,
        &DesktopApprovalRequest {
            expected_snapshot_digest: pending.snapshot_digest.clone(),
            contract_digest: graphic.compiled_contract.seal.contract_digest.clone(),
            plan_digest: graphic.compiled_plan.plan_digest.clone(),
            permission_digest: permission_digest.clone(),
        },
        ACTOR_ID,
        live::LIVE_NOW - 20,
        200,
    )?;
    let approved = graphic_snapshot(
        graphic,
        DesktopControlStatus::Approved,
        Some(&approval),
        &permission_digest,
        None,
        None,
        None,
    )?;
    let approve_receipt = issue_desktop_command_receipt(
        DesktopCommandAction::Approve,
        ACTOR_ID,
        &pending,
        &approved,
        Some(&approval.approval_digest),
        live::LIVE_NOW - 20,
    )?;
    Ok(GraphicApprovalChain {
        approved,
        approval,
        approve_receipt,
    })
}

fn graphic_snapshot(
    graphic: &GraphicProductionContext,
    status: DesktopControlStatus,
    approval: Option<&DesktopApprovalRecord>,
    permission_digest: &str,
    evidence_bundle_digest: Option<&str>,
    replay_manifest_digest: Option<&str>,
    steps: Option<Vec<PlanStepSummary>>,
) -> Result<DesktopShellSnapshot, Box<dyn Error>> {
    let approval_status = if approval.is_some() {
        StageStatus::Passed
    } else {
        StageStatus::Pending
    };
    let default_steps = graphic
        .compiled_plan
        .steps
        .iter()
        .map(|step| PlanStepSummary {
            step_id: step.step_id.clone(),
            operator_id: step.operator_id.clone(),
            status: StageStatus::Pending,
            before_digest: None,
            after_digest: None,
        })
        .collect();
    Ok(build_desktop_shell_snapshot(DesktopShellMaterial {
        generated_at: graphic.job.evaluated_at.clone(),
        job_id: Some(graphic.job.job_id.clone()),
        unresolved: Vec::new(),
        staged_inputs: Vec::new(),
        contract: Some(DigestItem {
            id: graphic.compiled_contract.contract_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: graphic.compiled_contract.seal.contract_digest.clone(),
            status: StageStatus::Passed,
        }),
        approval: Some(ApprovalSummary {
            approval_id: approval
                .map(|record| record.approval_id.clone())
                .unwrap_or_else(|| "approval.graphic-production.pending".to_owned()),
            contract_digest: graphic.compiled_contract.seal.contract_digest.clone(),
            plan_digest: graphic.compiled_plan.plan_digest.clone(),
            permission_digest: permission_digest.to_owned(),
            expires_at_epoch_s: approval.map_or(0, |record| record.expires_at_epoch_s),
            status: approval_status,
        }),
        plan: Some(DigestItem {
            id: graphic.compiled_plan.plan_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: graphic.compiled_plan.plan_digest.clone(),
            status: StageStatus::Passed,
        }),
        steps: steps.unwrap_or(default_steps),
        validators: Vec::new(),
        evidence_bundle: evidence_bundle_digest.map(|digest| DigestItem {
            id: "bundle.graphic-production-authority.e3".to_owned(),
            media_type: Some("application/json".to_owned()),
            digest: digest.to_owned(),
            status: StageStatus::Passed,
        }),
        replay_manifest: replay_manifest_digest.map(|digest| DigestItem {
            id: "manifest.graphic-production-authority.e3".to_owned(),
            media_type: Some("application/json".to_owned()),
            digest: digest.to_owned(),
            status: StageStatus::Passed,
        }),
        certificate: None,
        profession_capsules: vec![TrustComponentStatus {
            component_id: "ergaxiom.profession.graphic-designer".to_owned(),
            version: "0.1.0".to_owned(),
            digest: graphic.compiled_contract.seal.capsule_digest.clone(),
            trusted: true,
        }],
        adapters: Vec::new(),
        trusted_keys: Vec::new(),
        metadata: json!({
            "control_status": status,
            "approval_digest": approval.map(|record| record.approval_digest.clone()),
        }),
    })?)
}

fn graphic_executed_snapshot(
    graphic: &GraphicProductionContext,
    approval: &DesktopApprovalRecord,
    evidence: &ergaxiom_graphic_production_evidence_runtime::ProductionGraphicEvidence,
    bundle_digest: &str,
    replay_digest: &str,
) -> Result<DesktopShellSnapshot, Box<dyn Error>> {
    let permission_digest = approval.permission_digest.clone();
    let steps = evidence
        .twin_run
        .simulation
        .steps
        .iter()
        .map(|step| {
            let planned = graphic
                .compiled_plan
                .steps
                .iter()
                .find(|planned| planned.step_id == step.step_id)
                .ok_or("graphic executed step not present in compiled plan")?;
            Ok(PlanStepSummary {
                step_id: step.step_id.clone(),
                operator_id: planned.operator_id.clone(),
                status: StageStatus::Passed,
                before_digest: Some(step.before_snapshot_digest.clone()),
                after_digest: Some(step.after_snapshot_digest.clone()),
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    graphic_snapshot(
        graphic,
        DesktopControlStatus::Executed,
        Some(approval),
        &permission_digest,
        Some(bundle_digest),
        Some(replay_digest),
        Some(steps),
    )
}

fn graphic_bundle_with_operation_receipts(
    evidence: &ergaxiom_graphic_production_evidence_runtime::ProductionGraphicEvidence,
) -> Result<Value, Box<dyn Error>> {
    let mut value = serde_json::to_value(&evidence.evidence_bundle)?;
    let artifacts = value
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .ok_or("graphic Evidence Bundle artifacts missing")?;
    for receipt in &evidence.operation_receipts {
        let bytes = serde_json::to_vec(receipt)?;
        artifacts.push(json!({
            "artifact_id": format!("execution_receipt.{}", receipt.operation_id),
            "role": "evidence",
            "uri": format!("ergaxiom-inline-hex:{}", encode_hex_bytes(&bytes)),
            "media_type": "application/json",
            "algorithm": "sha256",
            "digest": graphic_sha256_hex(&bytes),
            "size_bytes": bytes.len() as u64,
        }));
    }
    Ok(value)
}

fn graphic_permission_for_step<'a>(
    graphic: &'a GraphicProductionContext,
    operator_id: &str,
) -> Result<&'a ergaxiom_contract_runtime::ContractPermission, Box<dyn Error>> {
    graphic
        .compiled_contract
        .permissions
        .iter()
        .find(|permission| match operator_id {
            "design.create_canvas" | "design.compose_text" => {
                permission.capability == "design-editor"
                    && permission.resource == "isolated-workspace"
                    && permission.access == PermissionAccess::Control
            }
            "design.place_asset" => {
                permission.capability == "filesystem"
                    && permission.resource == "contract://inputs/*"
                    && permission.access == PermissionAccess::Read
            }
            "design.export_raster" => {
                permission.capability == "filesystem"
                    && permission.resource == "contract://outputs/*"
                    && permission.access == PermissionAccess::Write
            }
            _ => false,
        })
        .ok_or_else(|| "graphic production permission missing".into())
}

fn graphic_job() -> GraphicDesignJob {
    GraphicDesignJob {
        schema_version: "0.1.0".to_owned(),
        job_id: "job.graphic-production-authority.e3".to_owned(),
        evaluated_at: "2026-08-14T10:00:00Z".to_owned(),
        canvas: CanvasSpecification {
            width: 240,
            height: 300,
            color_profile: "sRGB IEC61966-2.1".to_owned(),
            background: Rgba8::opaque(255, 255, 255),
        },
        safe_area: PixelRect {
            x: 12,
            y: 12,
            width: 216,
            height: 276,
        },
        logo_bounds: PixelRect {
            x: 24,
            y: 24,
            width: 80,
            height: 40,
        },
        text_origin_x: 24,
        text_origin_y: 100,
        text_scale: 3,
        text_color: Rgba8::opaque(0, 0, 0),
        approved_logo: ApprovedLogo {
            artifact_id: "approved_logo".to_owned(),
            media_type: "image/svg+xml".to_owned(),
            content: b"<svg viewBox='0 0 200 100'>approved</svg>".to_vec(),
            source_width: 200,
            source_height: 100,
            primary_color: Rgba8::opaque(20, 40, 80),
            secondary_color: Rgba8::opaque(40, 120, 220),
        },
        approved_copy: ApprovedCopy {
            artifact_id: "approved_copy".to_owned(),
            media_type: "text/plain".to_owned(),
            text: "ERGAXIOM\nPRODUCTION".to_owned(),
        },
        brand_profile: BrandProfile {
            artifact_id: "brand_profile".to_owned(),
            media_type: "application/json".to_owned(),
            minimum_logo_clear_space_px: 16,
            minimum_text_contrast_milli: 4_500,
        },
        editable_master_id: "editable_master".to_owned(),
        delivery_raster_id: "delivery_raster".to_owned(),
    }
}

fn graphic_plan_value(contract: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.graphic-production-authority.e3",
        "created_at": "2026-08-14T10:00:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest,
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.graphic-designer",
                "algorithm": "sha256",
                "digest": contract.seal.capsule_digest,
            }
        },
        "steps": [
            graphic_step("step.canvas", 0, "design.create_canvas", &[], &["brand_profile"], &["editable_master"], "token.canvas"),
            graphic_step("step.logo", 1, "design.place_asset", &["step.canvas"], &["editable_master", "approved_logo"], &["editable_master"], "token.logo"),
            graphic_step("step.text", 2, "design.compose_text", &["step.logo"], &["editable_master", "approved_copy"], &["editable_master"], "token.text"),
            graphic_step("step.export", 3, "design.export_raster", &["step.text"], &["editable_master"], &["delivery_raster"], "token.export"),
        ]
    })
}

fn graphic_step(
    step_id: &str,
    sequence: usize,
    operator_id: &str,
    depends_on: &[&str],
    inputs: &[&str],
    outputs: &[&str],
    token_id: &str,
) -> Value {
    json!({
        "step_id": step_id,
        "sequence": sequence,
        "operator_id": operator_id,
        "operator_version": "0.1.0",
        "depends_on": depends_on,
        "input_artifact_ids": inputs,
        "output_artifact_ids": outputs,
        "capability_token_ids": [token_id],
        "mandatory": true,
        "rollback_step_id": null,
    })
}

fn graphic_workspace() -> Result<TwinWorkspace, Box<dyn Error>> {
    Ok(TwinWorkspace::new(
        "workspace.graphic-production-authority.e3",
        EnvironmentIdentity {
            os: "windows".to_owned(),
            architecture: "x86_64".to_owned(),
            runtime_id: "ergaxiom.graphic-production-authority".to_owned(),
            runtime_version: "0.1.0".to_owned(),
            clock_source: "production-test-clock".to_owned(),
            sandbox_id: "sandbox.graphic-production-authority.e3".to_owned(),
            applications: vec![ApplicationIdentity {
                application_id: "ergaxiom.design-document-model".to_owned(),
                version: "0.1.0".to_owned(),
                digest: graphic_sha256_hex(b"ergaxiom.design-document-model@0.1.0"),
            }],
        },
    )?)
}

fn graphic_set_constraint_expected(
    contract: &mut Value,
    constraint_id: &str,
    expected: Value,
) -> Result<(), Box<dyn Error>> {
    let constraints = contract
        .get_mut("requirements")
        .and_then(|value| value.get_mut("hard"))
        .and_then(Value::as_array_mut)
        .ok_or("graphic hard requirements missing")?;
    let constraint = constraints
        .iter_mut()
        .find(|constraint| constraint.get("id").and_then(Value::as_str) == Some(constraint_id))
        .ok_or("graphic constraint missing")?;
    constraint["expected"] = expected;
    Ok(())
}

fn graphic_set_input_digest(
    contract: &mut Value,
    artifact_id: &str,
    digest: &str,
) -> Result<(), Box<dyn Error>> {
    let inputs = contract
        .get_mut("inputs")
        .and_then(Value::as_array_mut)
        .ok_or("graphic contract inputs missing")?;
    let input = inputs
        .iter_mut()
        .find(|input| input.get("id").and_then(Value::as_str) == Some(artifact_id))
        .ok_or("graphic contract input missing")?;
    input["integrity"]["digest"] = json!(digest);
    Ok(())
}

fn graphic_sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn production_bound_bundle(
    context: &Context,
    receipt: &AuthorizationReceipt,
    receipt_digest: &str,
) -> Result<Value, Box<dyn Error>> {
    let mut bundle = context.bundle.clone();
    bundle["trace"]["authorization_receipts"] = json!([{
        "receipt_digest": receipt_digest,
        "receipt": receipt,
    }]);
    let events = bundle["trace"]["events"]
        .as_array_mut()
        .ok_or("trace events missing")?;
    for event in events {
        event["authorization_receipt_digest"] = json!(receipt_digest);
    }

    let operation = ergaxiom_occupational_twin_runtime::OperationReceipt {
        operation_id: "operation.production-execution.e2e".to_owned(),
        operator_id: "operator.test".to_owned(),
        outcome: ergaxiom_occupational_twin_runtime::OperationOutcome::Succeeded,
        before_snapshot_digest: "a".repeat(64),
        after_snapshot_digest: "b".repeat(64),
        changed_artifact_ids: vec!["output".to_owned()],
        violations: Vec::new(),
        operation_digest: canonical_json_sha256(&json!({
            "operator_id": "operator.test",
            "step_id": "step.test",
        }))?,
    };
    let operation_bytes = serde_json::to_vec(&operation)?;
    let operation_digest = format!("{:x}", Sha256::digest(&operation_bytes));
    let artifacts = bundle["artifacts"]
        .as_array_mut()
        .ok_or("bundle artifacts missing")?;
    artifacts.push(json!({
        "artifact_id": format!("execution_receipt.{}", operation.operation_id),
        "role": "evidence",
        "uri": format!("ergaxiom-inline-hex:{}", encode_hex_bytes(&operation_bytes)),
        "media_type": "application/json",
        "algorithm": "sha256",
        "digest": operation_digest,
        "size_bytes": operation_bytes.len() as u64,
    }));
    Ok(bundle)
}

fn certified_snapshot(
    executed: &DesktopShellSnapshot,
    verified: &ergaxiom_attestation_runtime::VerifiedAttestation,
) -> Result<DesktopShellSnapshot, Box<dyn Error>> {
    Ok(build_desktop_shell_snapshot(DesktopShellMaterial {
        generated_at: executed.generated_at.clone(),
        job_id: executed.job_id.clone(),
        unresolved: executed.unresolved.clone(),
        staged_inputs: executed.staged_inputs.clone(),
        contract: executed.contract.clone(),
        approval: executed.approval.clone(),
        plan: executed.plan.clone(),
        steps: executed.steps.clone(),
        validators: executed.validators.clone(),
        evidence_bundle: executed.evidence_bundle.clone(),
        replay_manifest: executed.replay_manifest.clone(),
        certificate: Some(CertificateVerification {
            certificate_id: verified.certificate_id.clone(),
            certificate_digest: verified.certificate_digest.clone(),
            evidence_bundle_digest: verified.evidence_bundle_digest.clone(),
            signature_verified: true,
            bundle_verified: true,
            decision_accepted: true,
            mandatory_unknowns: 0,
            mandatory_failures: 0,
        }),
        profession_capsules: executed.profession_capsules.clone(),
        adapters: executed.adapters.clone(),
        trusted_keys: executed.trusted_keys.clone(),
        metadata: executed.metadata.clone(),
    })?)
}

fn rolled_back_snapshot(
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
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
