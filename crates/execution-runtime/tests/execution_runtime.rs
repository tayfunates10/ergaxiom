use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_capability_runtime::{
    AuthorizationReceipt, CapabilityAuthorizer, CapabilityBindings, CapabilityGrant,
    CapabilitySubject, CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding,
    SignedCapabilityToken, TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_execution_runtime::{
    AuthorizationReceiptRecord, AuthorizationTraceViolation, AuthorizedExecutionTrace,
    ReceiptBoundTraceEvent, verify_authorized_trace,
};
use ergaxiom_operator_plan_runtime::{CompiledPlan, TraceEvent, TraceStatus, compile_plan};
use ergaxiom_proof_kernel::{canonical_json_bytes, canonical_json_sha256};
use serde_json::{Value, json};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");
const ISSUER_ID: &str = "ergaxiom.policy-authority";
const KEY_ID: &str = "execution-test-key";
const EXECUTOR_ID: &str = "executor.windows-01";
const DEVICE_ID: &str = "device.execution-01";
const TOKEN_ID: &str = "token.logo.signed";
const NOW: u64 = 1_000;

struct Context {
    contract: CompiledContract,
    plan: CompiledPlan,
    signing_key: SigningKey,
}

fn context() -> Result<Context, Box<dyn Error>> {
    let contract_value: Value = serde_json::from_str(CONTRACT_SOURCE)?;
    let capsule_value: Value = serde_json::from_str(CAPSULE_SOURCE)?;
    let contract = compile_contract(&contract_value, &capsule_value)?;
    let plan_value = json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.execution-test.0001",
        "created_at": "2026-07-21T09:10:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.graphic-designer",
                "algorithm": "sha256",
                "digest": contract.seal.capsule_digest
            }
        },
        "steps": [{
            "step_id": "step.logo",
            "sequence": 0,
            "operator_id": "design.place_asset",
            "operator_version": "0.1.0",
            "depends_on": [],
            "input_artifact_ids": ["approved_logo"],
            "output_artifact_ids": ["editable_master"],
            "capability_token_ids": [TOKEN_ID],
            "mandatory": true,
            "rollback_step_id": null
        }]
    });
    let plan = compile_plan(&plan_value, &capsule_value, &contract)?;
    Ok(Context {
        contract,
        plan,
        signing_key: SigningKey::from_bytes(&[9_u8; 32]),
    })
}

fn token_payload(context: &Context, max_uses: u32) -> CapabilityTokenPayload {
    CapabilityTokenPayload {
        schema_version: "0.1.0".to_owned(),
        token_id: TOKEN_ID.to_owned(),
        issuer_id: ISSUER_ID.to_owned(),
        key_id: KEY_ID.to_owned(),
        subject: CapabilitySubject {
            executor_id: EXECUTOR_ID.to_owned(),
            device_id: Some(DEVICE_ID.to_owned()),
        },
        issued_at_epoch_s: 900,
        not_before_epoch_s: 950,
        expires_at_epoch_s: 1_100,
        max_uses,
        nonce: "execution-nonce-00000001".to_owned(),
        bindings: CapabilityBindings {
            contract_digest: context.contract.seal.contract_digest.clone(),
            capsule_digest: context.contract.seal.capsule_digest.clone(),
            plan_id: context.plan.plan_id.clone(),
            plan_digest: context.plan.plan_digest.clone(),
            step_id: "step.logo".to_owned(),
            operator_id: "design.place_asset".to_owned(),
        },
        grant: CapabilityGrant {
            capability: "filesystem".to_owned(),
            resource: "contract://inputs/*".to_owned(),
            access: PermissionAccess::Read,
            constraints: json!({"immutable": true}),
        },
    }
}

fn signed_token(
    payload: CapabilityTokenPayload,
    signing_key: &SigningKey,
) -> Result<Value, Box<dyn Error>> {
    let payload_value = serde_json::to_value(&payload)?;
    let signature = signing_key.sign(&canonical_json_bytes(&payload_value)?);
    Ok(serde_json::to_value(SignedCapabilityToken {
        payload,
        signature: TokenSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            encoding: SignatureEncoding::Base64url,
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })?)
}

fn authorizer(context: &Context) -> Result<CapabilityAuthorizer, Box<dyn Error>> {
    let mut keys = TrustedKeyRegistry::default();
    keys.insert_ed25519(
        ISSUER_ID,
        KEY_ID,
        context.signing_key.verifying_key().to_bytes(),
    )?;
    Ok(CapabilityAuthorizer::new(keys))
}

fn receipt_record(
    receipt: AuthorizationReceipt,
) -> Result<AuthorizationReceiptRecord, Box<dyn Error>> {
    let receipt_value = serde_json::to_value(&receipt)?;
    Ok(AuthorizationReceiptRecord {
        receipt_digest: canonical_json_sha256(&receipt_value)?,
        receipt,
    })
}

fn event(sequence: usize, status: TraceStatus) -> TraceEvent {
    TraceEvent {
        event_id: format!("event.{sequence}"),
        step_id: "step.logo".to_owned(),
        sequence,
        timestamp: format!("2026-07-21T09:10:{sequence:02}Z"),
        operator_id: "design.place_asset".to_owned(),
        status,
        input_digests: vec!["approved-logo-digest".to_owned()],
        output_digests: vec!["editable-master-digest".to_owned()],
        capability_token_id: Some(TOKEN_ID.to_owned()),
    }
}

fn trace(
    context: &Context,
    receipts: Vec<AuthorizationReceiptRecord>,
    event_receipt_digests: &[Option<String>],
    claimed: bool,
) -> AuthorizedExecutionTrace {
    let statuses = [TraceStatus::Started, TraceStatus::Succeeded];
    let events = statuses
        .into_iter()
        .enumerate()
        .map(|(sequence, status)| ReceiptBoundTraceEvent {
            event: event(sequence, status),
            authorization_receipt_digest: event_receipt_digests.get(sequence).cloned().flatten(),
        })
        .collect();
    AuthorizedExecutionTrace {
        schema_version: "0.1.0".to_owned(),
        trace_id: "trace.execution-test.0001".to_owned(),
        plan_id: context.plan.plan_id.clone(),
        plan_digest: context.plan.plan_digest.clone(),
        claimed_conforms_to_authorized_plan: claimed,
        authorization_receipts: receipts,
        events,
    }
}

fn one_receipt(context: &Context) -> Result<AuthorizationReceiptRecord, Box<dyn Error>> {
    let token = signed_token(token_payload(context, 1), &context.signing_key)?;
    let mut authorizer = authorizer(context)?;
    receipt_record(authorizer.authorize(
        &token,
        &context.contract,
        &context.plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?)
}

#[test]
fn valid_receipt_bound_trace_conforms() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let receipt = one_receipt(&context)?;
    let digest = receipt.receipt_digest.clone();
    let assessment = verify_authorized_trace(
        &context.plan,
        &trace(
            &context,
            vec![receipt],
            &[Some(digest.clone()), Some(digest)],
            true,
        ),
    )?;

    assert!(assessment.conforms_to_authorized_plan);
    assert!(assessment.claim_matches);
    assert!(assessment.authorization_violations.is_empty());
    assert!(assessment.plan_trace.conforms_to_plan);
    Ok(())
}

#[test]
fn forged_receipt_digest_is_rejected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut receipt = one_receipt(&context)?;
    receipt.receipt_digest = "forged-receipt-digest".to_owned();
    let assessment = verify_authorized_trace(
        &context.plan,
        &trace(
            &context,
            vec![receipt],
            &[
                Some("forged-receipt-digest".to_owned()),
                Some("forged-receipt-digest".to_owned()),
            ],
            true,
        ),
    )?;

    assert!(!assessment.conforms_to_authorized_plan);
    assert!(
        assessment
            .authorization_violations
            .iter()
            .any(|violation| matches!(
                violation,
                AuthorizationTraceViolation::ReceiptDigestMismatch { .. }
            ))
    );
    Ok(())
}

#[test]
fn missing_event_receipt_is_rejected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let receipt = one_receipt(&context)?;
    let digest = receipt.receipt_digest.clone();
    let assessment = verify_authorized_trace(
        &context.plan,
        &trace(&context, vec![receipt], &[Some(digest), None], true),
    )?;

    assert!(!assessment.conforms_to_authorized_plan);
    assert!(
        assessment
            .authorization_violations
            .iter()
            .any(|violation| matches!(
                violation,
                AuthorizationTraceViolation::MissingAuthorizationReceipt { .. }
            ))
    );
    Ok(())
}

#[test]
fn receipt_is_bound_to_the_exact_plan_digest() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut receipt = one_receipt(&context)?;
    receipt.receipt.plan_digest = "another-plan-digest".to_owned();
    receipt = receipt_record(receipt.receipt)?;
    let digest = receipt.receipt_digest.clone();
    let assessment = verify_authorized_trace(
        &context.plan,
        &trace(
            &context,
            vec![receipt],
            &[Some(digest.clone()), Some(digest)],
            true,
        ),
    )?;

    assert!(
        assessment
            .authorization_violations
            .iter()
            .any(|violation| matches!(
                violation,
                AuthorizationTraceViolation::ReceiptPlanDigestMismatch { .. }
            ))
    );
    Ok(())
}

#[test]
fn receipt_token_must_match_the_trace_event() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let receipt = one_receipt(&context)?;
    let digest = receipt.receipt_digest.clone();
    let mut authorized_trace = trace(
        &context,
        vec![receipt],
        &[Some(digest.clone()), Some(digest)],
        true,
    );
    authorized_trace.events[1].event.capability_token_id = Some("token.other".to_owned());
    let assessment = verify_authorized_trace(&context.plan, &authorized_trace)?;

    assert!(
        assessment
            .authorization_violations
            .iter()
            .any(|violation| matches!(
                violation,
                AuthorizationTraceViolation::ReceiptTokenMismatch { .. }
            ))
    );
    Ok(())
}

#[test]
fn one_step_cannot_switch_receipts_mid_execution() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let token = signed_token(token_payload(&context, 2), &context.signing_key)?;
    let mut authorizer = authorizer(&context)?;
    let first = receipt_record(authorizer.authorize(
        &token,
        &context.contract,
        &context.plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?)?;
    let second = receipt_record(authorizer.authorize(
        &token,
        &context.contract,
        &context.plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?)?;
    let assessment = verify_authorized_trace(
        &context.plan,
        &trace(
            &context,
            vec![first.clone(), second.clone()],
            &[
                Some(first.receipt_digest.clone()),
                Some(second.receipt_digest.clone()),
            ],
            true,
        ),
    )?;

    assert!(
        assessment
            .authorization_violations
            .iter()
            .any(|violation| matches!(
                violation,
                AuthorizationTraceViolation::InconsistentStepReceipt { .. }
            ))
    );
    Ok(())
}

#[test]
fn unused_receipt_is_rejected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let token = signed_token(token_payload(&context, 2), &context.signing_key)?;
    let mut authorizer = authorizer(&context)?;
    let used = receipt_record(authorizer.authorize(
        &token,
        &context.contract,
        &context.plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?)?;
    let unused = receipt_record(authorizer.authorize(
        &token,
        &context.contract,
        &context.plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?)?;
    let digest = used.receipt_digest.clone();
    let assessment = verify_authorized_trace(
        &context.plan,
        &trace(
            &context,
            vec![used, unused],
            &[Some(digest.clone()), Some(digest)],
            true,
        ),
    )?;

    assert!(
        assessment
            .authorization_violations
            .iter()
            .any(|violation| matches!(
                violation,
                AuthorizationTraceViolation::UnusedAuthorizationReceipt { .. }
            ))
    );
    Ok(())
}

#[test]
fn plan_state_machine_failure_still_blocks_authorized_trace() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let receipt = one_receipt(&context)?;
    let digest = receipt.receipt_digest.clone();
    let mut authorized_trace = trace(
        &context,
        vec![receipt],
        &[Some(digest.clone()), Some(digest)],
        true,
    );
    authorized_trace.events.remove(0);
    authorized_trace.events[0].event.sequence = 0;
    let assessment = verify_authorized_trace(&context.plan, &authorized_trace)?;

    assert!(!assessment.plan_trace.conforms_to_plan);
    assert!(!assessment.conforms_to_authorized_plan);
    Ok(())
}
