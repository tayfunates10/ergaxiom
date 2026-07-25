use std::cell::Cell;
use std::error::Error;
use std::rc::Rc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_attestation_issuance_runtime::{
    AttestationCertificateDraft, AttestationIssuanceError, AttestationSignerTransport,
};
use ergaxiom_attestation_runtime::build_replay_manifest;
use ergaxiom_backend_issuance_runtime::{
    BackendAuthorizedIssuanceAuthority, BackendIssuanceError, BackendIssuanceKind,
    BackendIssuancePolicy,
};
use ergaxiom_capability_issuance_runtime::{
    CapabilityIssuanceError, CapabilitySignerTransport, CapabilityTokenDraft,
};
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding, SignedCapabilityToken,
    TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_desktop_shell_runtime::{
    ApprovalSummary, DesktopApprovalRecord, DesktopApprovalRequest, DesktopCommandAction,
    DesktopCommandReceipt, DesktopControlStatus, DesktopShellMaterial, DesktopShellSnapshot,
    DigestItem, PlanStepSummary, StageStatus, TrustComponentStatus, ValidatorSummary,
    build_desktop_shell_snapshot, issue_desktop_approval, issue_desktop_command_receipt,
};
use ergaxiom_evidence_runtime::{EvidenceBundle, assess_bundle};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::{AssuranceLevel, canonical_json_bytes, canonical_json_sha256};
use ergaxiom_windows_signer_protocol_runtime::{
    SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ENCODING_BASE64URL, SignerRequest, SignerResponse,
    SignerSuccess, encode_hex,
};
use serde_json::{Value, json};

const POLICY_ISSUER: &str = "ergaxiom.policy-authority";
const POLICY_KEY_ID: &str = "policy-key-01";
const EXECUTOR_ID: &str = "executor.backend-issuance.0001";
const DEVICE_ID: &str = "device.backend-issuance.0001";
const ACTOR_ID: &str = "ergaxiom.local.operator";
const JOB_ID: &str = "job.backend-issuance.0001";
const APPROVAL_AT: u64 = 3_000;
const CAPABILITY_AT: u64 = 3_050;
const EXECUTION_AT: u64 = 3_100;
const ATTESTATION_AT: u64 = 3_150;
const APPROVAL_TTL_S: u64 = 600;

#[derive(Clone)]
struct TestTransport {
    signing_key: SigningKey,
    calls: Rc<Cell<u32>>,
    reject: bool,
}

impl TestTransport {
    fn sign(&self, request: &SignerRequest) -> Result<SignerResponse, Box<dyn Error>> {
        self.calls.set(self.calls.get().saturating_add(1));
        if self.reject {
            return Ok(SignerResponse::rejected(
                Some(request.request_id.clone()),
                "TEST_REJECTED",
            ));
        }
        let envelope = request.signing_envelope()?;
        let signature = self.signing_key.sign(&envelope.canonical_bytes()?);
        Ok(SignerResponse::success(
            request.request_id.clone(),
            SignerSuccess::DigestSigned {
                public_key_hex: encode_hex(&self.signing_key.verifying_key().to_bytes()),
                envelope_digest: envelope.digest()?,
                envelope,
                signature_algorithm: SIGNATURE_ALGORITHM_ED25519.to_owned(),
                signature_encoding: SIGNATURE_ENCODING_BASE64URL.to_owned(),
                signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        ))
    }
}

impl CapabilitySignerTransport for TestTransport {
    fn invoke(&self, request: &SignerRequest) -> Result<SignerResponse, CapabilityIssuanceError> {
        self.sign(request)
            .map_err(|error| CapabilityIssuanceError::Serialization(serde_json::Error::io(
                std::io::Error::other(error.to_string()),
            )))
    }
}

impl AttestationSignerTransport for TestTransport {
    fn invoke(&self, request: &SignerRequest) -> Result<SignerResponse, AttestationIssuanceError> {
        self.sign(request)
            .map_err(|error| AttestationIssuanceError::Serialization(serde_json::Error::io(
                std::io::Error::other(error.to_string()),
            )))
    }
}

struct Context {
    contract: CompiledContract,
    plan: CompiledPlan,
    bundle: Value,
}

struct ControlChain {
    pending: DesktopShellSnapshot,
    approved: DesktopShellSnapshot,
    executed: DesktopShellSnapshot,
    approval: DesktopApprovalRecord,
    approve_receipt: DesktopCommandReceipt,
    execute_receipt: DesktopCommandReceipt,
    attestation_draft: AttestationCertificateDraft,
}

fn context() -> Result<Context, Box<dyn Error>> {
    let contract_value = contract_value();
    let capsule_value = capsule_value();
    let contract = compile_contract(&contract_value, &capsule_value)?;
    let plan = compile_plan(&plan_value(&contract), &capsule_value, &contract)?;
    let policy_key = SigningKey::from_bytes(&[17_u8; 32]);
    let bundle = bundle_value(&contract, &plan, &policy_key)?;
    Ok(Context {
        contract,
        plan,
        bundle,
    })
}

fn control_chain(context: &Context) -> Result<ControlChain, Box<dyn Error>> {
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
        APPROVAL_AT,
        APPROVAL_TTL_S,
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
        APPROVAL_AT,
    )?;

    let attestation_draft = AttestationCertificateDraft {
        manifest_id: "manifest.backend-issuance.0001".to_owned(),
        certificate_id: "certificate.backend-issuance.0001".to_owned(),
        issued_at_epoch_s: ATTESTATION_AT,
    };
    let assessment = assess_bundle(
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
    )?;
    let bundle: EvidenceBundle = serde_json::from_value(context.bundle.clone())?;
    let replay_manifest = build_replay_manifest(
        &attestation_draft.manifest_id,
        &context.plan,
        &bundle,
        &assessment.bundle_digest,
        assessment.decision.status,
        AssuranceLevel::E1,
        assessment.mandatory_passed,
        assessment.mandatory_failed,
        assessment.mandatory_unknown,
    )?;
    let replay_digest = canonical_json_sha256(&serde_json::to_value(&replay_manifest)?)?;
    let executed = snapshot(
        context,
        DesktopControlStatus::Executed,
        Some(&approval),
        &permission_digest,
        Some(&assessment.bundle_digest),
        Some(&replay_digest),
    )?;
    let execute_receipt = issue_desktop_command_receipt(
        DesktopCommandAction::Execute,
        ACTOR_ID,
        &approved,
        &executed,
        Some(&approval.approval_digest),
        EXECUTION_AT,
    )?;
    Ok(ControlChain {
        pending,
        approved,
        executed,
        approval,
        approve_receipt,
        execute_receipt,
        attestation_draft,
    })
}

fn snapshot(
    context: &Context,
    status: DesktopControlStatus,
    approval: Option<&DesktopApprovalRecord>,
    permission_digest: &str,
    evidence_bundle_digest: Option<&str>,
    replay_manifest_digest: Option<&str>,
) -> Result<DesktopShellSnapshot, Box<dyn Error>> {
    let approval_status = if approval.is_some() {
        StageStatus::Passed
    } else {
        StageStatus::Pending
    };
    let executed = status == DesktopControlStatus::Executed;
    Ok(build_desktop_shell_snapshot(DesktopShellMaterial {
        generated_at: "2026-07-25T19:00:00Z".to_owned(),
        job_id: Some(JOB_ID.to_owned()),
        unresolved: Vec::new(),
        staged_inputs: Vec::new(),
        contract: Some(DigestItem {
            id: context.contract.contract_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: context.contract.seal.contract_digest.clone(),
            status: StageStatus::Passed,
        }),
        approval: Some(ApprovalSummary {
            approval_id: approval
                .map(|record| record.approval_id.clone())
                .unwrap_or_else(|| "approval.backend-issuance.pending".to_owned()),
            contract_digest: context.contract.seal.contract_digest.clone(),
            plan_digest: context.plan.plan_digest.clone(),
            permission_digest: permission_digest.to_owned(),
            expires_at_epoch_s: approval.map_or(0, |record| record.expires_at_epoch_s),
            status: approval_status,
        }),
        plan: Some(DigestItem {
            id: context.plan.plan_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: context.plan.plan_digest.clone(),
            status: StageStatus::Passed,
        }),
        steps: context
            .plan
            .steps
            .iter()
            .map(|step| PlanStepSummary {
                step_id: step.step_id.clone(),
                operator_id: step.operator_id.clone(),
                status: if executed {
                    StageStatus::Passed
                } else {
                    StageStatus::Pending
                },
                before_digest: executed.then(|| "a".repeat(64)),
                after_digest: executed.then(|| "b".repeat(64)),
            })
            .collect(),
        validators: if executed {
            vec![ValidatorSummary {
                validator_id: "validator.output".to_owned(),
                claim_id: "output_ok".to_owned(),
                report_digest: "c".repeat(64),
                status: StageStatus::Passed,
                actionable_message: None,
            }]
        } else {
            Vec::new()
        },
        evidence_bundle: evidence_bundle_digest.map(|digest| DigestItem {
            id: "bundle.backend-issuance.0001".to_owned(),
            media_type: Some("application/json".to_owned()),
            digest: digest.to_owned(),
            status: StageStatus::Passed,
        }),
        replay_manifest: replay_manifest_digest.map(|digest| DigestItem {
            id: "manifest.backend-issuance.0001".to_owned(),
            media_type: Some("application/json".to_owned()),
            digest: digest.to_owned(),
            status: StageStatus::Passed,
        }),
        certificate: None,
        profession_capsules: vec![TrustComponentStatus {
            component_id: "ergaxiom.profession.backend-issuance-test".to_owned(),
            version: "0.1.0".to_owned(),
            digest: context.contract.seal.capsule_digest.clone(),
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

fn capability_draft(context: &Context) -> CapabilityTokenDraft {
    CapabilityTokenDraft {
        token_id: "token.test".to_owned(),
        subject: CapabilitySubject {
            executor_id: EXECUTOR_ID.to_owned(),
            device_id: Some(DEVICE_ID.to_owned()),
        },
        issued_at_epoch_s: CAPABILITY_AT,
        not_before_epoch_s: CAPABILITY_AT,
        expires_at_epoch_s: APPROVAL_AT + APPROVAL_TTL_S,
        max_uses: 1,
        nonce: "backend-issuance-capability-nonce-0001".to_owned(),
        bindings: CapabilityBindings {
            contract_digest: context.contract.seal.contract_digest.clone(),
            capsule_digest: context.contract.seal.capsule_digest.clone(),
            plan_id: context.plan.plan_id.clone(),
            plan_digest: context.plan.plan_digest.clone(),
            step_id: "step.test".to_owned(),
            operator_id: "operator.test".to_owned(),
        },
        grant: CapabilityGrant {
            capability: "filesystem".to_owned(),
            resource: "contract://inputs/*".to_owned(),
            access: PermissionAccess::Read,
            constraints: json!({"immutable": true}),
        },
    }
}

fn authority(
    capability_calls: Rc<Cell<u32>>,
    attestation_calls: Rc<Cell<u32>>,
    reject_capability: bool,
) -> BackendAuthorizedIssuanceAuthority<TestTransport, TestTransport> {
    let capability_key = SigningKey::from_bytes(&[71_u8; 32]);
    let attestation_key = SigningKey::from_bytes(&[72_u8; 32]);
    BackendAuthorizedIssuanceAuthority::new(
        TestTransport {
            signing_key: capability_key.clone(),
            calls: capability_calls,
            reject: reject_capability,
        },
        capability_key.verifying_key().to_bytes(),
        TestTransport {
            signing_key: attestation_key.clone(),
            calls: attestation_calls,
            reject: false,
        },
        attestation_key.verifying_key().to_bytes(),
        EXECUTOR_ID,
        Some(DEVICE_ID.to_owned()),
    )
}

#[test]
fn exact_backend_flow_issues_capability_and_attestation() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = control_chain(&context)?;
    let capability_calls = Rc::new(Cell::new(0));
    let attestation_calls = Rc::new(Cell::new(0));
    let mut authority = authority(capability_calls.clone(), attestation_calls.clone(), false);

    let capability = authority.issue_capability(
        &chain.approved,
        &chain.approval,
        &chain.approve_receipt,
        &context.contract,
        &context.plan,
        capability_draft(&context),
        CAPABILITY_AT,
        60,
    )?;
    assert_eq!(
        capability.authorization.kind,
        BackendIssuanceKind::Capability
    );
    assert_eq!(capability.token.payload.subject.executor_id, EXECUTOR_ID);
    assert_eq!(capability_calls.get(), 1);

    let attestation = authority.issue_attestation(
        &chain.executed,
        &chain.approval,
        &chain.execute_receipt,
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        chain.attestation_draft.clone(),
        ATTESTATION_AT,
        60,
    )?;
    assert_eq!(
        attestation.authorization.kind,
        BackendIssuanceKind::Attestation
    );
    assert_eq!(
        attestation.package.certificate.payload.decision,
        ergaxiom_proof_kernel::DecisionStatus::Accepted
    );
    assert_eq!(attestation_calls.get(), 1);
    Ok(())
}

#[test]
fn capability_step_subject_and_permission_substitution_fail_before_signer() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = control_chain(&context)?;
    let cases = ["step", "subject", "permission"];
    for case in cases {
        let calls = Rc::new(Cell::new(0));
        let mut authority = authority(calls.clone(), Rc::new(Cell::new(0)), false);
        let mut draft = capability_draft(&context);
        match case {
            "step" => draft.bindings.step_id = "step.substituted".to_owned(),
            "subject" => draft.subject.executor_id = "executor.substituted".to_owned(),
            "permission" => draft.grant.access = PermissionAccess::Write,
            _ => unreachable!(),
        }
        assert!(authority
            .issue_capability(
                &chain.approved,
                &chain.approval,
                &chain.approve_receipt,
                &context.contract,
                &context.plan,
                draft,
                CAPABILITY_AT,
                60,
            )
            .is_err());
        assert_eq!(calls.get(), 0);
    }
    Ok(())
}

#[test]
fn wrong_receipt_and_mutated_evidence_fail_before_signer() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = control_chain(&context)?;
    let attestation_calls = Rc::new(Cell::new(0));
    let mut authority = authority(Rc::new(Cell::new(0)), attestation_calls.clone(), false);
    assert!(matches!(
        authority.issue_attestation(
            &chain.executed,
            &chain.approval,
            &chain.approve_receipt,
            context.contract.clone(),
            &context.plan,
            &context.bundle,
            AssuranceLevel::E1,
            chain.attestation_draft.clone(),
            ATTESTATION_AT,
            60,
        ),
        Err(BackendIssuanceError::ReceiptActionMismatch)
    ));
    assert_eq!(attestation_calls.get(), 0);

    let mut mutated_bundle = context.bundle.clone();
    mutated_bundle["artifacts"][0]["digest"] = json!("mutated-output-digest");
    assert!(authority
        .issue_attestation(
            &chain.executed,
            &chain.approval,
            &chain.execute_receipt,
            context.contract,
            &context.plan,
            &mutated_bundle,
            AssuranceLevel::E1,
            chain.attestation_draft,
            ATTESTATION_AT,
            60,
        )
        .is_err());
    assert_eq!(attestation_calls.get(), 0);
    Ok(())
}

#[test]
fn authorization_is_one_shot_and_same_intent_cannot_be_reauthorized() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = control_chain(&context)?;
    let draft = capability_draft(&context);
    let mut policy = BackendIssuancePolicy::default();
    let authorization = policy.authorize_capability(
        &chain.approved,
        &chain.approval,
        &chain.approve_receipt,
        &context.contract,
        &context.plan,
        &draft,
        EXECUTOR_ID,
        Some(DEVICE_ID),
        CAPABILITY_AT,
        60,
    )?;
    policy.consume_authorization(
        &authorization,
        BackendIssuanceKind::Capability,
        CAPABILITY_AT,
    )?;
    assert!(matches!(
        policy.consume_authorization(
            &authorization,
            BackendIssuanceKind::Capability,
            CAPABILITY_AT,
        ),
        Err(BackendIssuanceError::AuthorizationAlreadyConsumed)
    ));
    assert!(matches!(
        policy.authorize_capability(
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &context.contract,
            &context.plan,
            &draft,
            EXECUTOR_ID,
            Some(DEVICE_ID),
            CAPABILITY_AT,
            60,
        ),
        Err(BackendIssuanceError::IntentAlreadyAuthorized)
    ));
    Ok(())
}

#[test]
fn signer_failure_consumes_intent_fail_closed() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = control_chain(&context)?;
    let calls = Rc::new(Cell::new(0));
    let mut authority = authority(calls.clone(), Rc::new(Cell::new(0)), true);
    let first = authority.issue_capability(
        &chain.approved,
        &chain.approval,
        &chain.approve_receipt,
        &context.contract,
        &context.plan,
        capability_draft(&context),
        CAPABILITY_AT,
        60,
    );
    assert!(first.is_err());
    assert_eq!(calls.get(), 1);
    assert!(matches!(
        authority.issue_capability(
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &context.contract,
            &context.plan,
            capability_draft(&context),
            CAPABILITY_AT,
            60,
        ),
        Err(BackendIssuanceError::IntentAlreadyAuthorized)
    ));
    assert_eq!(calls.get(), 1);
    Ok(())
}

#[test]
fn expired_approval_and_stale_snapshot_fail_closed() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let chain = control_chain(&context)?;
    let calls = Rc::new(Cell::new(0));
    let mut authority = authority(calls.clone(), Rc::new(Cell::new(0)), false);
    let mut stale = chain.approved.clone();
    stale.snapshot_digest = "f".repeat(64);
    assert!(authority
        .issue_capability(
            &stale,
            &chain.approval,
            &chain.approve_receipt,
            &context.contract,
            &context.plan,
            capability_draft(&context),
            CAPABILITY_AT,
            60,
        )
        .is_err());
    let mut expired_draft = capability_draft(&context);
    expired_draft.issued_at_epoch_s = APPROVAL_AT + APPROVAL_TTL_S + 1;
    expired_draft.not_before_epoch_s = expired_draft.issued_at_epoch_s;
    expired_draft.expires_at_epoch_s = expired_draft.issued_at_epoch_s + 1;
    assert!(authority
        .issue_capability(
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &context.contract,
            &context.plan,
            expired_draft,
            APPROVAL_AT + APPROVAL_TTL_S + 1,
            60,
        )
        .is_err());
    assert_eq!(calls.get(), 0);
    Ok(())
}

fn contract_value() -> Value {
    json!({
        "schema_version": "0.2.0",
        "contract_id": "contract.backend-issuance.0001",
        "profession": {
            "capsule_id": "ergaxiom.profession.backend-issuance-test",
            "capsule_version": "0.1.0"
        },
        "job_type": "backend_issuance_test_job",
        "requirements": {
            "hard": [{"id": "output_ok", "mandatory": true}],
            "unknowns": []
        },
        "permissions": [{
            "capability": "filesystem",
            "resource": "contract://inputs/*",
            "access": "read",
            "constraints": {"immutable": true}
        }],
        "proof_obligations": [{
            "id": "proof.output_ok",
            "constraint_id": "output_ok",
            "validator_ids": ["validator.output"],
            "mandatory": true,
            "independence_class": "independent",
            "evidence_types": ["measurement"]
        }],
        "acceptance": {
            "minimum_assurance_level": "E1",
            "unknowns_must_be_empty": true,
            "all_mandatory_proofs_must_pass": true,
            "validator_conflicts_allowed": false
        }
    })
}

fn capsule_value() -> Value {
    json!({
        "schema_version": "0.1.0",
        "capsule_id": "ergaxiom.profession.backend-issuance-test",
        "version": "0.1.0",
        "job_types": [{
            "id": "backend_issuance_test_job",
            "required_constraints": ["output_ok"],
            "minimum_assurance_level": "E1",
            "operator_ids": ["operator.test"]
        }],
        "operators": [{"id": "operator.test", "version": "1.0.0"}],
        "validators": [{
            "id": "validator.output",
            "version": "1.0.0",
            "claims": ["output_ok"],
            "independence_class": "independent",
            "evidence_types": ["measurement"]
        }],
        "policies": {
            "minimum_assurance_by_job_type": {"backend_issuance_test_job": "E1"}
        }
    })
}

fn plan_value(contract: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.backend-issuance.0001",
        "created_at": "2026-07-25T19:00:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.backend-issuance-test",
                "algorithm": "sha256",
                "digest": contract.seal.capsule_digest
            }
        },
        "steps": [{
            "step_id": "step.test",
            "sequence": 0,
            "operator_id": "operator.test",
            "operator_version": "1.0.0",
            "depends_on": [],
            "input_artifact_ids": ["input"],
            "output_artifact_ids": ["output"],
            "capability_token_ids": ["token.test"],
            "mandatory": true,
            "rollback_step_id": null
        }]
    })
}

fn bundle_value(
    contract: &CompiledContract,
    plan: &CompiledPlan,
    policy_key: &SigningKey,
) -> Result<Value, Box<dyn Error>> {
    let token = signed_capability_token(contract, plan, policy_key)?;
    let mut trusted_keys = TrustedKeyRegistry::default();
    trusted_keys.insert_ed25519(
        POLICY_ISSUER,
        POLICY_KEY_ID,
        policy_key.verifying_key().to_bytes(),
    )?;
    let mut authorizer = CapabilityAuthorizer::new(trusted_keys);
    let receipt = authorizer.authorize(&token, contract, plan, 2_000, EXECUTOR_ID, Some(DEVICE_ID))?;
    let receipt_value = serde_json::to_value(&receipt)?;
    let receipt_digest = canonical_json_sha256(&receipt_value)?;
    Ok(json!({
        "schema_version": "0.4.0",
        "bundle_id": "bundle.backend-issuance.0001",
        "run_id": "run.backend-issuance.0001",
        "created_at": "2026-07-25T19:05:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.backend-issuance-test",
                "algorithm": "sha256",
                "digest": contract.seal.capsule_digest
            },
            "operator_plan": {
                "id": plan.plan_id,
                "algorithm": "sha256",
                "digest": plan.plan_digest
            }
        },
        "environment": {
            "os": "test-os",
            "kernel_version": "ergaxiom-proof-kernel/0.1.0",
            "applications": [{
                "id": "test-application",
                "version": "1.0.0",
                "digest": "application-digest"
            }],
            "clock_source": "trusted-test-clock",
            "sandbox_id": "sandbox-backend-issuance"
        },
        "artifacts": [
            {
                "artifact_id": "output",
                "role": "output",
                "uri": "bundle://artifacts/output",
                "media_type": "application/octet-stream",
                "algorithm": "sha256",
                "digest": "output-digest",
                "size_bytes": 42
            },
            {
                "artifact_id": "evidence.output",
                "role": "evidence",
                "uri": "bundle://artifacts/evidence.output",
                "media_type": "application/json",
                "algorithm": "sha256",
                "digest": "evidence-digest",
                "size_bytes": 21
            }
        ],
        "trace": {
            "schema_version": "0.1.0",
            "trace_id": "trace.backend-issuance.0001",
            "plan_id": plan.plan_id,
            "plan_digest": plan.plan_digest,
            "claimed_conforms_to_authorized_plan": true,
            "authorization_receipts": [{
                "receipt_digest": receipt_digest,
                "receipt": receipt_value
            }],
            "events": [
                {
                    "event": trace_event(0, "STARTED"),
                    "authorization_receipt_digest": receipt_digest
                },
                {
                    "event": trace_event(1, "SUCCEEDED"),
                    "authorization_receipt_digest": receipt_digest
                }
            ]
        },
        "proof_results": [{
            "evidence_id": "evidence.output-ok",
            "obligation_id": "proof.output_ok",
            "claim_id": "output_ok",
            "subject_artifact_id": "output",
            "validator_id": "validator.output",
            "validator_version": "1.0.0",
            "independence_class": "independent",
            "status": "PASSED",
            "mandatory": true,
            "observed": true,
            "expected": true,
            "unit": null,
            "tolerance": null,
            "evidence_artifact_ids": ["evidence.output"],
            "evaluated_at": "2026-07-25T19:05:00Z"
        }],
        "claimed_decision": {
            "status": "ACCEPTED",
            "assurance_level": "E1",
            "mandatory_passed": 1,
            "mandatory_failed": 0,
            "mandatory_unknown": 0,
            "reason": "Mandatory output proof passed.",
            "sealed_at": null,
            "signature": null
        }
    }))
}

fn signed_capability_token(
    contract: &CompiledContract,
    plan: &CompiledPlan,
    policy_key: &SigningKey,
) -> Result<Value, Box<dyn Error>> {
    let payload = CapabilityTokenPayload {
        schema_version: "0.1.0".to_owned(),
        token_id: "token.test".to_owned(),
        issuer_id: POLICY_ISSUER.to_owned(),
        key_id: POLICY_KEY_ID.to_owned(),
        subject: CapabilitySubject {
            executor_id: EXECUTOR_ID.to_owned(),
            device_id: Some(DEVICE_ID.to_owned()),
        },
        issued_at_epoch_s: 1_900,
        not_before_epoch_s: 1_950,
        expires_at_epoch_s: 2_100,
        max_uses: 1,
        nonce: "backend-issuance-evidence-nonce-0001".to_owned(),
        bindings: CapabilityBindings {
            contract_digest: contract.seal.contract_digest.clone(),
            capsule_digest: contract.seal.capsule_digest.clone(),
            plan_id: plan.plan_id.clone(),
            plan_digest: plan.plan_digest.clone(),
            step_id: "step.test".to_owned(),
            operator_id: "operator.test".to_owned(),
        },
        grant: CapabilityGrant {
            capability: "filesystem".to_owned(),
            resource: "contract://inputs/*".to_owned(),
            access: PermissionAccess::Read,
            constraints: json!({"immutable": true}),
        },
    };
    let payload_value = serde_json::to_value(&payload)?;
    let signature = policy_key.sign(&canonical_json_bytes(&payload_value)?);
    Ok(serde_json::to_value(SignedCapabilityToken {
        payload,
        signature: TokenSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            encoding: SignatureEncoding::Base64url,
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })?)
}

fn trace_event(sequence: usize, status: &str) -> Value {
    json!({
        "event_id": format!("event.{sequence}"),
        "step_id": "step.test",
        "sequence": sequence,
        "timestamp": format!("2026-07-25T19:02:{sequence:02}Z"),
        "operator_id": "operator.test",
        "status": status,
        "input_digests": ["input-digest"],
        "output_digests": ["output-digest"],
        "capability_token_id": "token.test"
    })
}
