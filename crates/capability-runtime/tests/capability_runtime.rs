use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityError, CapabilityGrant,
    CapabilitySubject, CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding,
    SignedCapabilityToken, TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::canonical_json_bytes;
use serde_json::{Value, json};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");
const ISSUER_ID: &str = "ergaxiom.policy-authority";
const KEY_ID: &str = "test-ed25519-01";
const EXECUTOR_ID: &str = "executor.windows-01";
const DEVICE_ID: &str = "device.test-01";
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
    let plan = compile_plan(&plan_value(&contract), &capsule_value, &contract)?;
    Ok(Context {
        contract,
        plan,
        signing_key: SigningKey::from_bytes(&[7_u8; 32]),
    })
}

fn plan_value(compiled: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.capability-test.0001",
        "created_at": "2026-07-20T21:30:00Z",
        "bindings": {
            "contract": {
                "id": compiled.contract_id,
                "algorithm": "sha256",
                "digest": compiled.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.graphic-designer",
                "algorithm": "sha256",
                "digest": compiled.seal.capsule_digest
            }
        },
        "steps": [
            step("step.canvas", 0, "design.create_canvas", &[], "token.canvas"),
            step(
                "step.logo",
                1,
                "design.place_asset",
                &["step.canvas"],
                "token.logo.signed"
            ),
            step(
                "step.text",
                2,
                "design.compose_text",
                &["step.logo"],
                "token.text"
            ),
            step(
                "step.export",
                3,
                "design.export_raster",
                &["step.text"],
                "token.export"
            )
        ]
    })
}

fn step(
    step_id: &str,
    sequence: usize,
    operator_id: &str,
    depends_on: &[&str],
    token_id: &str,
) -> Value {
    json!({
        "step_id": step_id,
        "sequence": sequence,
        "operator_id": operator_id,
        "operator_version": "0.1.0",
        "depends_on": depends_on,
        "input_artifact_ids": [],
        "output_artifact_ids": [],
        "capability_token_ids": [token_id],
        "mandatory": true,
        "rollback_step_id": null
    })
}

fn payload(context: &Context) -> CapabilityTokenPayload {
    CapabilityTokenPayload {
        schema_version: "0.1.0".to_owned(),
        token_id: "token.logo.signed".to_owned(),
        issuer_id: ISSUER_ID.to_owned(),
        key_id: KEY_ID.to_owned(),
        subject: CapabilitySubject {
            executor_id: EXECUTOR_ID.to_owned(),
            device_id: Some(DEVICE_ID.to_owned()),
        },
        issued_at_epoch_s: 900,
        not_before_epoch_s: 950,
        expires_at_epoch_s: 1_100,
        max_uses: 1,
        nonce: "nonce-0000000000000001".to_owned(),
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

fn sign(
    payload: CapabilityTokenPayload,
    signing_key: &SigningKey,
) -> Result<Value, Box<dyn Error>> {
    let payload_value = serde_json::to_value(&payload)?;
    let signature = signing_key.sign(&canonical_json_bytes(&payload_value)?);
    let token = SignedCapabilityToken {
        payload,
        signature: TokenSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            encoding: SignatureEncoding::Base64url,
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    };
    Ok(serde_json::to_value(token)?)
}

fn authorizer(context: &Context) -> Result<CapabilityAuthorizer, CapabilityError> {
    let mut keys = TrustedKeyRegistry::default();
    keys.insert_ed25519(
        ISSUER_ID,
        KEY_ID,
        context.signing_key.verifying_key().to_bytes(),
    )?;
    Ok(CapabilityAuthorizer::new(keys))
}

#[test]
fn authorizes_a_valid_contract_scoped_signed_token() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let token = sign(payload(&context), &context.signing_key)?;
    let mut authorizer = authorizer(&context)?;

    let receipt = authorizer.authorize(
        &token,
        &context.contract,
        &context.plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?;

    assert_eq!(receipt.token_id, "token.logo.signed");
    assert_eq!(receipt.step_id, "step.logo");
    assert_eq!(receipt.operator_id, "design.place_asset");
    assert_eq!(receipt.use_number, 1);
    assert_eq!(receipt.max_uses, 1);
    assert_eq!(receipt.token_digest.len(), 64);
    assert_eq!(receipt.payload_digest.len(), 64);
    Ok(())
}

#[test]
fn tampered_payload_fails_signature_verification() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut token = sign(payload(&context), &context.signing_key)?;
    token["payload"]["grant"]["resource"] = json!("contract://outputs/*");
    let mut authorizer = authorizer(&context)?;

    assert!(matches!(
        authorizer.authorize(
            &token,
            &context.contract,
            &context.plan,
            NOW,
            EXECUTOR_ID,
            Some(DEVICE_ID)
        ),
        Err(CapabilityError::SignatureVerificationFailed)
    ));
    Ok(())
}

#[test]
fn correctly_signed_grant_cannot_exceed_the_contract() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut token_payload = payload(&context);
    token_payload.grant.resource = "contract://secret/*".to_owned();
    let token = sign(token_payload, &context.signing_key)?;
    let mut authorizer = authorizer(&context)?;

    assert!(matches!(
        authorizer.authorize(
            &token,
            &context.contract,
            &context.plan,
            NOW,
            EXECUTOR_ID,
            Some(DEVICE_ID)
        ),
        Err(CapabilityError::GrantExceedsContract)
    ));
    Ok(())
}

#[test]
fn token_is_bound_to_the_exact_plan_digest() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut token_payload = payload(&context);
    token_payload.bindings.plan_digest = "another-plan".to_owned();
    let token = sign(token_payload, &context.signing_key)?;
    let mut authorizer = authorizer(&context)?;

    assert!(matches!(
        authorizer.authorize(
            &token,
            &context.contract,
            &context.plan,
            NOW,
            EXECUTOR_ID,
            Some(DEVICE_ID)
        ),
        Err(CapabilityError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn expired_token_is_rejected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut token_payload = payload(&context);
    token_payload.expires_at_epoch_s = NOW;
    let token = sign(token_payload, &context.signing_key)?;
    let mut authorizer = authorizer(&context)?;

    assert!(matches!(
        authorizer.authorize(
            &token,
            &context.contract,
            &context.plan,
            NOW,
            EXECUTOR_ID,
            Some(DEVICE_ID)
        ),
        Err(CapabilityError::Expired)
    ));
    Ok(())
}

#[test]
fn max_use_limit_prevents_replay() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let token = sign(payload(&context), &context.signing_key)?;
    let mut authorizer = authorizer(&context)?;

    authorizer.authorize(
        &token,
        &context.contract,
        &context.plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?;
    assert!(matches!(
        authorizer.authorize(
            &token,
            &context.contract,
            &context.plan,
            NOW,
            EXECUTOR_ID,
            Some(DEVICE_ID)
        ),
        Err(CapabilityError::UsageLimitExceeded)
    ));
    assert_eq!(authorizer.usage_count(ISSUER_ID, "token.logo.signed"), 1);
    Ok(())
}

#[test]
fn issuer_cannot_reuse_token_id_for_a_different_payload() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut first_payload = payload(&context);
    first_payload.max_uses = 2;
    let first = sign(first_payload, &context.signing_key)?;

    let mut second_payload = payload(&context);
    second_payload.max_uses = 2;
    second_payload.nonce = "nonce-0000000000000002".to_owned();
    let second = sign(second_payload, &context.signing_key)?;
    let mut authorizer = authorizer(&context)?;

    authorizer.authorize(
        &first,
        &context.contract,
        &context.plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?;
    assert!(matches!(
        authorizer.authorize(
            &second,
            &context.contract,
            &context.plan,
            NOW,
            EXECUTOR_ID,
            Some(DEVICE_ID)
        ),
        Err(CapabilityError::TokenIdCollision { .. })
    ));
    Ok(())
}

#[test]
fn token_subject_is_bound_to_the_active_executor_and_device() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let token = sign(payload(&context), &context.signing_key)?;
    let mut authorizer = authorizer(&context)?;

    assert!(matches!(
        authorizer.authorize(
            &token,
            &context.contract,
            &context.plan,
            NOW,
            "another-executor",
            Some(DEVICE_ID)
        ),
        Err(CapabilityError::ExecutorMismatch { .. })
    ));
    assert!(matches!(
        authorizer.authorize(
            &token,
            &context.contract,
            &context.plan,
            NOW,
            EXECUTOR_ID,
            Some("another-device")
        ),
        Err(CapabilityError::DeviceMismatch)
    ));
    Ok(())
}
