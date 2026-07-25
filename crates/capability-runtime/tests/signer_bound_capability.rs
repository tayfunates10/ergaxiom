use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityError, CapabilityGrant, CapabilitySubject,
    CapabilityTokenPayload, SignerBoundCapabilityToken, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::canonical_json_sha256;
use ergaxiom_windows_signer_protocol_runtime::{
    SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ENCODING_BASE64URL, SignerRequest, SignerResponse,
    SignerSuccess, encode_hex,
};
use serde_json::{Value, json};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");
const ISSUER_ID: &str = "ergaxiom.policy-authority";
const KEY_ID: &str = "capability-key-v1";
const EXECUTOR_ID: &str = "executor.windows-01";
const DEVICE_ID: &str = "device.test-01";
const NOW: u64 = 1_000;

struct Context {
    contract: CompiledContract,
    plan: CompiledPlan,
}

fn context() -> Result<Context, Box<dyn Error>> {
    let contract_value: Value = serde_json::from_str(CONTRACT_SOURCE)?;
    let capsule_value: Value = serde_json::from_str(CAPSULE_SOURCE)?;
    let contract = compile_contract(&contract_value, &capsule_value)?;
    let plan = compile_plan(&plan_value(&contract), &capsule_value, &contract)?;
    Ok(Context { contract, plan })
}

fn plan_value(compiled: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.signer-bound.0001",
        "created_at": "2026-07-25T14:00:00Z",
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
                "token.logo.signer-bound"
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
        token_id: "token.logo.signer-bound".to_owned(),
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
        nonce: "nonce-signer-bound-000001".to_owned(),
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

fn signer_bound_token(
    payload: CapabilityTokenPayload,
    signing_key: &SigningKey,
    role: IssuerRole,
) -> Result<Value, Box<dyn Error>> {
    let payload_value = serde_json::to_value(&payload)?;
    let request = SignerRequest::sign_digest(
        "capability.issue.test.0001",
        role,
        payload.issuer_id.clone(),
        payload.key_id.clone(),
        canonical_json_sha256(&payload_value)?,
    );
    let envelope = request.signing_envelope()?;
    let signature = signing_key.sign(&envelope.canonical_bytes()?);
    let token = SignerBoundCapabilityToken {
        payload,
        signer_response: SignerResponse::success(
            request.request_id,
            SignerSuccess::DigestSigned {
                public_key_hex: encode_hex(&signing_key.verifying_key().to_bytes()),
                envelope_digest: envelope.digest()?,
                envelope,
                signature_algorithm: SIGNATURE_ALGORITHM_ED25519.to_owned(),
                signature_encoding: SIGNATURE_ENCODING_BASE64URL.to_owned(),
                signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        ),
    };
    Ok(serde_json::to_value(token)?)
}

fn authorizer(
    trusted_signing_key: &SigningKey,
) -> Result<CapabilityAuthorizer, CapabilityError> {
    let mut keys = TrustedKeyRegistry::default();
    keys.insert_ed25519(
        ISSUER_ID,
        KEY_ID,
        trusted_signing_key.verifying_key().to_bytes(),
    )?;
    Ok(CapabilityAuthorizer::new(keys))
}

#[test]
fn authorizes_exact_signer_bound_payload() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let signing_key = SigningKey::from_bytes(&[61_u8; 32]);
    let token = signer_bound_token(payload(&context), &signing_key, IssuerRole::Capability)?;
    let mut authorizer = authorizer(&signing_key)?;
    let receipt = authorizer.authorize_signer_bound(
        &token,
        &context.contract,
        &context.plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?;
    assert_eq!(receipt.token_id, "token.logo.signer-bound");
    assert_eq!(receipt.step_id, "step.logo");
    assert_eq!(receipt.use_number, 1);
    Ok(())
}

#[test]
fn payload_mutation_after_signing_fails_digest_binding() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let signing_key = SigningKey::from_bytes(&[62_u8; 32]);
    let mut token = signer_bound_token(payload(&context), &signing_key, IssuerRole::Capability)?;
    token["payload"]["grant"]["resource"] = json!("contract://outputs/*");
    let mut authorizer = authorizer(&signing_key)?;
    assert!(matches!(
        authorizer.authorize_signer_bound(
            &token,
            &context.contract,
            &context.plan,
            NOW,
            EXECUTOR_ID,
            Some(DEVICE_ID)
        ),
        Err(CapabilityError::SignerDigestMismatch)
    ));
    Ok(())
}

#[test]
fn cross_role_signer_response_fails_closed() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let signing_key = SigningKey::from_bytes(&[63_u8; 32]);
    let token = signer_bound_token(payload(&context), &signing_key, IssuerRole::Attestation)?;
    let mut authorizer = authorizer(&signing_key)?;
    assert!(matches!(
        authorizer.authorize_signer_bound(
            &token,
            &context.contract,
            &context.plan,
            NOW,
            EXECUTOR_ID,
            Some(DEVICE_ID)
        ),
        Err(CapabilityError::SignerRoleMismatch)
    ));
    Ok(())
}

#[test]
fn signer_public_key_must_equal_trusted_registry_key() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let signer_key = SigningKey::from_bytes(&[64_u8; 32]);
    let trusted_key = SigningKey::from_bytes(&[65_u8; 32]);
    let token = signer_bound_token(payload(&context), &signer_key, IssuerRole::Capability)?;
    let mut authorizer = authorizer(&trusted_key)?;
    assert!(matches!(
        authorizer.authorize_signer_bound(
            &token,
            &context.contract,
            &context.plan,
            NOW,
            EXECUTOR_ID,
            Some(DEVICE_ID)
        ),
        Err(CapabilityError::SignerPublicKeyMismatch)
    ));
    Ok(())
}
