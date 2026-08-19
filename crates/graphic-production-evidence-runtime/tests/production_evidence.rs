use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_capability_runtime::{
    AuthorizationReceipt, CapabilityAuthorizer, CapabilityBindings, CapabilityGrant,
    CapabilitySubject, CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding,
    SignedCapabilityToken, TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_evidence_runtime::assess_bundle;
use ergaxiom_graphic_designer_twin_runtime::{
    ApprovedCopy, ApprovedLogo, BrandProfile, CanvasSpecification, GraphicDesignJob, PixelRect,
    Rgba8,
};
use ergaxiom_graphic_production_evidence_runtime::{
    ProductionGraphicEvidenceError, ProductionGraphicEvidenceRequest,
    build_production_graphic_evidence,
};
use ergaxiom_occupational_twin_runtime::{ApplicationIdentity, EnvironmentIdentity, TwinWorkspace};
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, canonical_json_bytes};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");
const POLICY_ISSUER: &str = "ergaxiom.policy-authority";
const POLICY_KEY_ID: &str = "graphic-production-evidence-key";
const EXECUTOR_ID: &str = "executor.graphic-production-evidence";
const DEVICE_ID: &str = "device.graphic-production-evidence";
const NOW: u64 = 10_000;

struct Context {
    contract_value: Value,
    compiled_contract: CompiledContract,
    compiled_plan: CompiledPlan,
    job: GraphicDesignJob,
    policy_key: SigningKey,
}

fn context() -> Result<Context, Box<dyn Error>> {
    let job = job();
    let mut contract_value: Value = serde_json::from_str(CONTRACT_SOURCE)?;
    set_constraint_expected(&mut contract_value, "canvas_width", json!(240))?;
    set_constraint_expected(&mut contract_value, "canvas_height", json!(300))?;
    set_constraint_expected(&mut contract_value, "logo_clear_space", json!(16))?;
    set_input_digest(
        &mut contract_value,
        &job.approved_logo.artifact_id,
        &sha256_hex(&job.approved_logo.content),
    )?;
    set_input_digest(
        &mut contract_value,
        &job.approved_copy.artifact_id,
        &sha256_hex(job.approved_copy.text.as_bytes()),
    )?;
    let brand_profile_bytes = serde_json::to_vec(&job.brand_profile)?;
    set_input_digest(
        &mut contract_value,
        &job.brand_profile.artifact_id,
        &sha256_hex(&brand_profile_bytes),
    )?;

    let capsule_value: Value = serde_json::from_str(CAPSULE_SOURCE)?;
    let compiled_contract = compile_contract(&contract_value, &capsule_value)?;
    let compiled_plan = compile_plan(
        &plan_value(&compiled_contract),
        &capsule_value,
        &compiled_contract,
    )?;
    Ok(Context {
        contract_value,
        compiled_contract,
        compiled_plan,
        job,
        policy_key: SigningKey::from_bytes(&[51_u8; 32]),
    })
}

fn job() -> GraphicDesignJob {
    GraphicDesignJob {
        schema_version: "0.1.0".to_owned(),
        job_id: "graphic-production-evidence.0001".to_owned(),
        evaluated_at: "2026-08-14T07:00:00Z".to_owned(),
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

fn plan_value(contract: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.graphic-production-evidence.0001",
        "created_at": "2026-08-14T07:00:00Z",
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
            step(
                "step.canvas",
                0,
                "design.create_canvas",
                &[],
                &["brand_profile"],
                &["editable_master"],
                "token.canvas",
            ),
            step(
                "step.logo",
                1,
                "design.place_asset",
                &["step.canvas"],
                &["editable_master", "approved_logo"],
                &["editable_master"],
                "token.logo",
            ),
            step(
                "step.text",
                2,
                "design.compose_text",
                &["step.logo"],
                &["editable_master", "approved_copy"],
                &["editable_master"],
                "token.text",
            ),
            step(
                "step.export",
                3,
                "design.export_raster",
                &["step.text"],
                &["editable_master"],
                &["delivery_raster"],
                "token.export",
            ),
        ]
    })
}

fn step(
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

fn workspace() -> Result<TwinWorkspace, Box<dyn Error>> {
    Ok(TwinWorkspace::new(
        "workspace.graphic-production-evidence",
        EnvironmentIdentity {
            os: "windows".to_owned(),
            architecture: "x86_64".to_owned(),
            runtime_id: "ergaxiom.graphic-production-evidence".to_owned(),
            runtime_version: "0.1.0".to_owned(),
            clock_source: "production-test-clock".to_owned(),
            sandbox_id: "sandbox.graphic-production-evidence".to_owned(),
            applications: vec![ApplicationIdentity {
                application_id: "ergaxiom.design-document-model".to_owned(),
                version: "0.1.0".to_owned(),
                digest: sha256_hex(b"ergaxiom.design-document-model@0.1.0"),
            }],
        },
    )?)
}

fn receipts(context: &Context) -> Result<Vec<AuthorizationReceipt>, Box<dyn Error>> {
    let mut keys = TrustedKeyRegistry::default();
    keys.insert_ed25519(
        POLICY_ISSUER,
        POLICY_KEY_ID,
        context.policy_key.verifying_key().to_bytes(),
    )?;
    let mut authorizer = CapabilityAuthorizer::new(keys);
    context
        .compiled_plan
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let permission = permission_for_step(context, &step.operator_id)?;
            let payload = CapabilityTokenPayload {
                schema_version: "0.1.0".to_owned(),
                token_id: step.capability_token_ids[0].clone(),
                issuer_id: POLICY_ISSUER.to_owned(),
                key_id: POLICY_KEY_ID.to_owned(),
                subject: CapabilitySubject {
                    executor_id: EXECUTOR_ID.to_owned(),
                    device_id: Some(DEVICE_ID.to_owned()),
                },
                issued_at_epoch_s: NOW - 100,
                not_before_epoch_s: NOW - 50,
                expires_at_epoch_s: NOW + 100,
                max_uses: 1,
                nonce: format!("graphic-production-evidence-nonce-{index:02}"),
                bindings: CapabilityBindings {
                    contract_digest: context.compiled_contract.seal.contract_digest.clone(),
                    capsule_digest: context.compiled_contract.seal.capsule_digest.clone(),
                    plan_id: context.compiled_plan.plan_id.clone(),
                    plan_digest: context.compiled_plan.plan_digest.clone(),
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
            let payload_value = serde_json::to_value(&payload)?;
            let signature = context
                .policy_key
                .sign(&canonical_json_bytes(&payload_value)?);
            let token_value = serde_json::to_value(SignedCapabilityToken {
                payload,
                signature: TokenSignature {
                    algorithm: SignatureAlgorithm::Ed25519,
                    encoding: SignatureEncoding::Base64url,
                    value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                },
            })?;
            Ok(authorizer.authorize(
                &token_value,
                &context.compiled_contract,
                &context.compiled_plan,
                NOW,
                EXECUTOR_ID,
                Some(DEVICE_ID),
            )?)
        })
        .collect()
}

fn permission_for_step<'a>(
    context: &'a Context,
    operator_id: &str,
) -> Result<&'a ergaxiom_contract_runtime::ContractPermission, Box<dyn Error>> {
    context
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
        .ok_or_else(|| "required contract permission missing".into())
}

#[test]
fn production_receipts_drive_accepted_twin_evidence() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let receipts = receipts(&context)?;
    let mut workspace = workspace()?;
    let evidence = build_production_graphic_evidence(ProductionGraphicEvidenceRequest {
        workspace: &mut workspace,
        compiled_contract: &context.compiled_contract,
        contract_value: &context.contract_value,
        compiled_plan: &context.compiled_plan,
        job: &context.job,
        authorization_receipts: &receipts,
        assurance_level: AssuranceLevel::E3,
        bundle_id: "bundle.graphic-production-evidence.0001",
        run_id: "run.graphic-production-evidence.0001",
        trace_id: "trace.graphic-production-evidence.0001",
    })?;

    assert_eq!(
        evidence.evidence_bundle.claimed_decision.status,
        DecisionStatus::Accepted
    );
    assert_eq!(
        evidence.evidence_bundle.trace.authorization_receipts.len(),
        4
    );
    assert_eq!(evidence.evidence_bundle.trace.events.len(), 8);
    assert_eq!(evidence.operation_receipts.len(), 4);
    assert!(
        evidence
            .operation_receipts
            .iter()
            .all(|receipt| receipt.violations.is_empty())
    );
    let bundle_value = serde_json::to_value(&evidence.evidence_bundle)?;
    let reassessed = assess_bundle(
        context.compiled_contract,
        &context.compiled_plan,
        &bundle_value,
        AssuranceLevel::E3,
    )?;
    assert_eq!(reassessed.decision.status, DecisionStatus::Accepted);
    assert_eq!(reassessed.mandatory_failed, 0);
    assert_eq!(reassessed.mandatory_unknown, 0);
    Ok(())
}

#[test]
fn tampered_receipt_binding_fails_before_twin_staging() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut receipts = receipts(&context)?;
    receipts[0].operator_id = "design.place_asset".to_owned();
    let mut workspace = workspace()?;
    let result = build_production_graphic_evidence(ProductionGraphicEvidenceRequest {
        workspace: &mut workspace,
        compiled_contract: &context.compiled_contract,
        contract_value: &context.contract_value,
        compiled_plan: &context.compiled_plan,
        job: &context.job,
        authorization_receipts: &receipts,
        assurance_level: AssuranceLevel::E3,
        bundle_id: "bundle.graphic-production-evidence.tamper",
        run_id: "run.graphic-production-evidence.tamper",
        trace_id: "trace.graphic-production-evidence.tamper",
    });

    assert!(matches!(
        result,
        Err(ProductionGraphicEvidenceError::InvalidStepReceipt(_))
    ));
    assert!(workspace.current_snapshot()?.artifacts.is_empty());
    Ok(())
}

fn set_constraint_expected(
    contract: &mut Value,
    constraint_id: &str,
    expected: Value,
) -> Result<(), Box<dyn Error>> {
    let constraints = contract
        .get_mut("requirements")
        .and_then(|value| value.get_mut("hard"))
        .and_then(Value::as_array_mut)
        .ok_or("hard requirements missing")?;
    let constraint = constraints
        .iter_mut()
        .find(|constraint| constraint.get("id").and_then(Value::as_str) == Some(constraint_id))
        .ok_or("constraint missing")?;
    constraint["expected"] = expected;
    Ok(())
}

fn set_input_digest(
    contract: &mut Value,
    artifact_id: &str,
    digest: &str,
) -> Result<(), Box<dyn Error>> {
    let inputs = contract
        .get_mut("inputs")
        .and_then(Value::as_array_mut)
        .ok_or("contract inputs missing")?;
    let input = inputs
        .iter_mut()
        .find(|input| input.get("id").and_then(Value::as_str) == Some(artifact_id))
        .ok_or("contract input missing")?;
    input["integrity"]["digest"] = json!(digest);
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
