use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding, SignedCapabilityToken,
    TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_evidence_runtime::{EvidenceBundleError, assess_bundle};
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, canonical_json_bytes, canonical_json_sha256,
};
use serde_json::{Value, json};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");
const ISSUER_ID: &str = "ergaxiom.policy-authority";
const KEY_ID: &str = "evidence-test-key";
const EXECUTOR_ID: &str = "executor.windows-01";
const DEVICE_ID: &str = "device.evidence-01";
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
        signing_key: SigningKey::from_bytes(&[11_u8; 32]),
    })
}

fn plan_value(compiled: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.social-post.0001",
        "created_at": "2026-07-21T09:30:00Z",
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
            plan_step("step.canvas", 0, "design.create_canvas", &[], "token.canvas"),
            plan_step("step.logo", 1, "design.place_asset", &["step.canvas"], "token.logo"),
            plan_step("step.text", 2, "design.compose_text", &["step.logo"], "token.text"),
            plan_step("step.export", 3, "design.export_raster", &["step.text"], "token.export")
        ]
    })
}

fn plan_step(
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

fn grant(capability: &str, resource: &str, access: PermissionAccess, constraints: Value) -> CapabilityGrant {
    CapabilityGrant {
        capability: capability.to_owned(),
        resource: resource.to_owned(),
        access,
        constraints,
    }
}

fn token_payload(
    context: &Context,
    step_id: &str,
    operator_id: &str,
    token_id: &str,
    nonce: &str,
    grant: CapabilityGrant,
) -> CapabilityTokenPayload {
    CapabilityTokenPayload {
        schema_version: "0.1.0".to_owned(),
        token_id: token_id.to_owned(),
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
        nonce: nonce.to_owned(),
        bindings: CapabilityBindings {
            contract_digest: context.contract.seal.contract_digest.clone(),
            capsule_digest: context.contract.seal.capsule_digest.clone(),
            plan_id: context.plan.plan_id.clone(),
            plan_digest: context.plan.plan_digest.clone(),
            step_id: step_id.to_owned(),
            operator_id: operator_id.to_owned(),
        },
        grant,
    }
}

fn sign_token(
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

fn authorized_trace(context: &Context) -> Result<Value, Box<dyn Error>> {
    let mut keys = TrustedKeyRegistry::default();
    keys.insert_ed25519(
        ISSUER_ID,
        KEY_ID,
        context.signing_key.verifying_key().to_bytes(),
    )?;
    let mut authorizer = CapabilityAuthorizer::new(keys);

    let definitions = vec![
        (
            "step.canvas",
            "design.create_canvas",
            "token.canvas",
            "evidence-nonce-00000001",
            grant(
                "design-editor",
                "isolated-workspace",
                PermissionAccess::Control,
                json!({"network": false}),
            ),
        ),
        (
            "step.logo",
            "design.place_asset",
            "token.logo",
            "evidence-nonce-00000002",
            grant(
                "filesystem",
                "contract://inputs/*",
                PermissionAccess::Read,
                json!({"immutable": true}),
            ),
        ),
        (
            "step.text",
            "design.compose_text",
            "token.text",
            "evidence-nonce-00000003",
            grant(
                "design-editor",
                "isolated-workspace",
                PermissionAccess::Control,
                json!({"network": false}),
            ),
        ),
        (
            "step.export",
            "design.export_raster",
            "token.export",
            "evidence-nonce-00000004",
            grant(
                "filesystem",
                "contract://outputs/*",
                PermissionAccess::Write,
                json!({"overwrite": false}),
            ),
        ),
    ];

    let mut authorization_receipts = Vec::new();
    let mut events = Vec::new();
    for (step_id, operator_id, token_id, nonce, step_grant) in definitions {
        let token = sign_token(
            token_payload(
                context,
                step_id,
                operator_id,
                token_id,
                nonce,
                step_grant,
            ),
            &context.signing_key,
        )?;
        let receipt = authorizer.authorize(
            &token,
            &context.contract,
            &context.plan,
            NOW,
            EXECUTOR_ID,
            Some(DEVICE_ID),
        )?;
        let receipt_value = serde_json::to_value(&receipt)?;
        let receipt_digest = canonical_json_sha256(&receipt_value)?;
        authorization_receipts.push(json!({
            "receipt_digest": receipt_digest,
            "receipt": receipt_value
        }));

        for status in ["STARTED", "SUCCEEDED"] {
            let sequence = events.len();
            events.push(json!({
                "event": {
                    "event_id": format!("event.{sequence}"),
                    "step_id": step_id,
                    "sequence": sequence,
                    "timestamp": format!("2026-07-21T09:30:{sequence:02}Z"),
                    "operator_id": operator_id,
                    "status": status,
                    "input_digests": [],
                    "output_digests": [],
                    "capability_token_id": token_id
                },
                "authorization_receipt_digest": receipt_digest
            }));
        }
    }

    Ok(json!({
        "schema_version": "0.1.0",
        "trace_id": "trace.social-post.0001",
        "plan_id": context.plan.plan_id,
        "plan_digest": context.plan.plan_digest,
        "claimed_conforms_to_authorized_plan": true,
        "authorization_receipts": authorization_receipts,
        "events": events
    }))
}

fn bundle(context: &Context) -> Result<Value, Box<dyn Error>> {
    let proofs = [
        proof(
            "evidence.width",
            "proof.canvas_width",
            "canvas_width",
            "delivery_raster",
            "raster.dimensions",
            "evidence.width.artifact",
            json!(1080),
        ),
        proof(
            "evidence.height",
            "proof.canvas_height",
            "canvas_height",
            "delivery_raster",
            "raster.dimensions",
            "evidence.height.artifact",
            json!(1350),
        ),
        proof(
            "evidence.profile",
            "proof.color_profile",
            "color_profile",
            "delivery_raster",
            "raster.icc_profile",
            "evidence.profile.artifact",
            json!("sRGB IEC61966-2.1"),
        ),
        proof(
            "evidence.logo-ratio",
            "proof.logo_aspect_ratio",
            "logo_aspect_ratio",
            "editable_master",
            "document.logo_geometry",
            "evidence.logo-ratio.artifact",
            json!(0),
        ),
        proof(
            "evidence.logo-space",
            "proof.logo_clear_space",
            "logo_clear_space",
            "editable_master",
            "document.logo_geometry",
            "evidence.logo-space.artifact",
            json!(48),
        ),
        proof(
            "evidence.text-bounds",
            "proof.text_within_safe_area",
            "text_within_safe_area",
            "editable_master",
            "document.text_bounds",
            "evidence.text-bounds.artifact",
            json!(0),
        ),
        proof(
            "evidence.contrast-luminance",
            "proof.minimum_text_contrast",
            "minimum_text_contrast",
            "delivery_raster",
            "raster.text_contrast.relative_luminance",
            "evidence.contrast-luminance.artifact",
            json!(7.1),
        ),
        proof(
            "evidence.contrast-sampling",
            "proof.minimum_text_contrast",
            "minimum_text_contrast",
            "delivery_raster",
            "raster.text_contrast.render_sampling",
            "evidence.contrast-sampling.artifact",
            json!(7.0),
        ),
        proof(
            "evidence.media-type",
            "proof.export_media_type",
            "export_media_type",
            "delivery_raster",
            "raster.media_type",
            "evidence.media-type.artifact",
            json!("image/png"),
        ),
    ];

    let mut artifacts = vec![
        artifact("editable_master", "output", "master-digest"),
        artifact("delivery_raster", "output", "raster-digest"),
    ];
    for proof in &proofs {
        let artifact_id = proof["evidence_artifact_ids"][0]
            .as_str()
            .ok_or("evidence artifact ID must be a string")?;
        artifacts.push(artifact(
            artifact_id,
            "evidence",
            &format!("digest-{artifact_id}"),
        ));
    }

    Ok(json!({
        "schema_version": "0.4.0",
        "bundle_id": "bundle.social-post.0001",
        "run_id": "run.social-post.0001",
        "created_at": "2026-07-21T09:35:00Z",
        "bindings": {
            "contract": {
                "id": context.contract.contract_id,
                "algorithm": "sha256",
                "digest": context.contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.graphic-designer",
                "algorithm": "sha256",
                "digest": context.contract.seal.capsule_digest
            },
            "operator_plan": {
                "id": context.plan.plan_id,
                "algorithm": "sha256",
                "digest": context.plan.plan_digest
            }
        },
        "environment": {
            "os": "windows",
            "kernel_version": "ergaxiom-proof-kernel/0.1.0",
            "applications": [],
            "clock_source": "test-clock",
            "sandbox_id": "sandbox-test"
        },
        "artifacts": artifacts,
        "trace": authorized_trace(context)?,
        "proof_results": proofs,
        "claimed_decision": {
            "status": "ACCEPTED",
            "assurance_level": "E3",
            "mandatory_passed": 8,
            "mandatory_failed": 0,
            "mandatory_unknown": 0,
            "reason": "All mandatory proof obligations passed.",
            "sealed_at": null,
            "signature": null
        }
    }))
}

fn proof(
    evidence_id: &str,
    obligation_id: &str,
    claim_id: &str,
    subject_artifact_id: &str,
    validator_id: &str,
    evidence_artifact_id: &str,
    observed: Value,
) -> Value {
    json!({
        "evidence_id": evidence_id,
        "obligation_id": obligation_id,
        "claim_id": claim_id,
        "subject_artifact_id": subject_artifact_id,
        "validator_id": validator_id,
        "validator_version": "0.1.0",
        "independence_class": "independent",
        "status": "PASSED",
        "mandatory": true,
        "observed": observed,
        "expected": null,
        "unit": null,
        "tolerance": null,
        "evidence_artifact_ids": [evidence_artifact_id],
        "evaluated_at": "2026-07-21T09:35:00Z"
    })
}

fn artifact(artifact_id: &str, role: &str, digest: &str) -> Value {
    json!({
        "artifact_id": artifact_id,
        "role": role,
        "uri": format!("bundle://artifacts/{artifact_id}"),
        "media_type": null,
        "algorithm": "sha256",
        "digest": digest,
        "size_bytes": 1
    })
}

#[test]
fn recomputes_authorized_trace_and_proof_acceptance() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let evidence_bundle = bundle(&context)?;
    let assessment = assess_bundle(
        context.contract,
        &context.plan,
        &evidence_bundle,
        AssuranceLevel::E3,
    )?;

    assert!(assessment.trace_assessment.conforms_to_authorized_plan);
    assert!(assessment.trace_assessment.authorization_violations.is_empty());
    assert_eq!(assessment.decision.status, DecisionStatus::Accepted);
    assert_eq!(assessment.mandatory_passed, 8);
    assert_eq!(assessment.mandatory_failed, 0);
    assert_eq!(assessment.mandatory_unknown, 0);
    assert_eq!(assessment.bundle_digest.len(), 64);
    Ok(())
}

#[test]
fn rejects_a_forged_claimed_decision() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut evidence_bundle = bundle(&context)?;
    evidence_bundle["claimed_decision"]["status"] = json!("REJECTED");

    assert!(matches!(
        assess_bundle(
            context.contract,
            &context.plan,
            &evidence_bundle,
            AssuranceLevel::E3
        ),
        Err(EvidenceBundleError::ClaimedDecisionMismatch(_))
    ));
    Ok(())
}

#[test]
fn missing_proof_cannot_keep_an_accepted_claim() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut evidence_bundle = bundle(&context)?;
    evidence_bundle["proof_results"]
        .as_array_mut()
        .ok_or("proof_results must be an array")?
        .pop();

    assert!(matches!(
        assess_bundle(
            context.contract,
            &context.plan,
            &evidence_bundle,
            AssuranceLevel::E3
        ),
        Err(EvidenceBundleError::ClaimedDecisionMismatch(_))
    ));
    Ok(())
}

#[test]
fn rejects_a_bundle_bound_to_another_contract() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut evidence_bundle = bundle(&context)?;
    evidence_bundle["bindings"]["contract"]["digest"] = json!("another-contract");

    assert!(matches!(
        assess_bundle(
            context.contract,
            &context.plan,
            &evidence_bundle,
            AssuranceLevel::E3
        ),
        Err(EvidenceBundleError::ContractDigestMismatch)
    ));
    Ok(())
}

#[test]
fn rejects_a_bundle_bound_to_another_plan() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut evidence_bundle = bundle(&context)?;
    evidence_bundle["bindings"]["operator_plan"]["digest"] = json!("another-plan");

    assert!(matches!(
        assess_bundle(
            context.contract,
            &context.plan,
            &evidence_bundle,
            AssuranceLevel::E3
        ),
        Err(EvidenceBundleError::PlanDigestMismatch)
    ));
    Ok(())
}

#[test]
fn detects_a_forged_authorized_trace_claim() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut evidence_bundle = bundle(&context)?;
    evidence_bundle["trace"]["events"]
        .as_array_mut()
        .ok_or("trace events must be an array")?
        .pop();

    assert!(matches!(
        assess_bundle(
            context.contract,
            &context.plan,
            &evidence_bundle,
            AssuranceLevel::E3
        ),
        Err(EvidenceBundleError::TraceClaimMismatch)
    ));
    Ok(())
}

#[test]
fn nonconforming_authorized_trace_blocks_bundle_when_claimed_honestly()
-> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut evidence_bundle = bundle(&context)?;
    evidence_bundle["trace"]["events"]
        .as_array_mut()
        .ok_or("trace events must be an array")?
        .pop();
    evidence_bundle["trace"]["claimed_conforms_to_authorized_plan"] = json!(false);

    assert!(matches!(
        assess_bundle(
            context.contract,
            &context.plan,
            &evidence_bundle,
            AssuranceLevel::E3
        ),
        Err(EvidenceBundleError::TraceNonConformance { .. })
    ));
    Ok(())
}

#[test]
fn forged_authorization_receipt_blocks_bundle() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut evidence_bundle = bundle(&context)?;
    evidence_bundle["trace"]["authorization_receipts"][0]["receipt_digest"] =
        json!("forged-receipt-digest");
    evidence_bundle["trace"]["claimed_conforms_to_authorized_plan"] = json!(false);

    assert!(matches!(
        assess_bundle(
            context.contract,
            &context.plan,
            &evidence_bundle,
            AssuranceLevel::E3
        ),
        Err(EvidenceBundleError::TraceNonConformance { .. })
    ));
    Ok(())
}

#[test]
fn rejects_evidence_reference_with_the_wrong_artifact_role() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut evidence_bundle = bundle(&context)?;
    evidence_bundle["artifacts"][2]["role"] = json!("output");

    assert!(matches!(
        assess_bundle(
            context.contract,
            &context.plan,
            &evidence_bundle,
            AssuranceLevel::E3
        ),
        Err(EvidenceBundleError::InvalidEvidenceArtifactRole(_))
    ));
    Ok(())
}

#[test]
fn bundle_cannot_self_assert_a_higher_assurance_level() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let evidence_bundle = bundle(&context)?;

    assert!(matches!(
        assess_bundle(
            context.contract,
            &context.plan,
            &evidence_bundle,
            AssuranceLevel::E2
        ),
        Err(EvidenceBundleError::ClaimedAssuranceMismatch { .. })
    ));
    Ok(())
}
