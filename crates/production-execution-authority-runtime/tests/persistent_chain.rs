include!("../../backend-issuance-runtime/tests/persistent_production_capability.rs");

use ergaxiom_capability_runtime::AuthorizationReceipt;
use ergaxiom_desktop_shell_runtime::CertificateVerification;
use ergaxiom_proof_kernel::DecisionStatus;
use ergaxiom_windows_production_governed_issuance_runtime::verify_governed_production_attestation_against_bundle;
use sha2::{Digest as _, Sha256};

use ergaxiom_production_execution_authority_runtime::{
    PersistentProductionExecutionAuthority, PersistentProductionExecutionAuthorityError,
};
use ergaxiom_production_execution_runtime::{
    ProductionExecutionStage, verify_recovered_certified_chain,
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
    let recovered = PersistentProductionExecutionAuthority::load_or_create(
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
        context.contract,
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

    fs::remove_dir_all(cleanup_root)?;
    Ok(())
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

fn encode_hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
