use std::error::Error;

use ergaxiom_contract_runtime::{CompiledContract, compile_contract};
use ergaxiom_evidence_runtime::{EvidenceBundleError, assess_bundle};
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus};
use serde_json::{Value, json};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");

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
        "plan_id": "plan.social-post.0001",
        "created_at": "2026-07-20T21:10:00Z",
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

fn bundle(context: &Context) -> Value {
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
            .unwrap_or("invalid-evidence-artifact");
        artifacts.push(artifact(
            artifact_id,
            "evidence",
            &format!("digest-{artifact_id}"),
        ));
    }

    json!({
        "schema_version": "0.3.0",
        "bundle_id": "bundle.social-post.0001",
        "run_id": "run.social-post.0001",
        "created_at": "2026-07-20T21:15:00Z",
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
        "trace": {
            "events": trace_events(),
            "claimed_conforms_to_plan": true,
            "deviations": []
        },
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
    })
}

fn trace_events() -> Vec<Value> {
    let definitions = [
        ("step.canvas", "design.create_canvas", "token.canvas"),
        ("step.logo", "design.place_asset", "token.logo"),
        ("step.text", "design.compose_text", "token.text"),
        ("step.export", "design.export_raster", "token.export"),
    ];
    let mut events = Vec::new();
    for (step_id, operator_id, token_id) in definitions {
        events.push(trace_event(
            events.len(),
            step_id,
            operator_id,
            token_id,
            "STARTED",
        ));
        events.push(trace_event(
            events.len(),
            step_id,
            operator_id,
            token_id,
            "SUCCEEDED",
        ));
    }
    events
}

fn trace_event(
    sequence: usize,
    step_id: &str,
    operator_id: &str,
    token_id: &str,
    status: &str,
) -> Value {
    json!({
        "event_id": format!("event.{sequence}"),
        "step_id": step_id,
        "sequence": sequence,
        "timestamp": format!("2026-07-20T21:15:{sequence:02}Z"),
        "operator_id": operator_id,
        "status": status,
        "input_digests": [],
        "output_digests": [],
        "capability_token_id": token_id
    })
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
        "evaluated_at": "2026-07-20T21:15:00Z"
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
fn recomputes_plan_trace_and_proof_acceptance() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let evidence_bundle = bundle(&context);
    let assessment = assess_bundle(
        context.contract,
        &context.plan,
        &evidence_bundle,
        AssuranceLevel::E3,
    )?;

    assert!(assessment.trace_assessment.conforms_to_plan);
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
    let mut evidence_bundle = bundle(&context);
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
    let mut evidence_bundle = bundle(&context);
    let proof_results = evidence_bundle["proof_results"]
        .as_array_mut()
        .ok_or("proof_results must be an array")?;
    proof_results.pop();

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
    let mut evidence_bundle = bundle(&context);
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
    let mut evidence_bundle = bundle(&context);
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
fn detects_a_forged_trace_conformance_claim() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut evidence_bundle = bundle(&context);
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
fn nonconforming_trace_blocks_the_bundle_even_when_claimed_honestly() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut evidence_bundle = bundle(&context);
    evidence_bundle["trace"]["events"]
        .as_array_mut()
        .ok_or("trace events must be an array")?
        .pop();
    evidence_bundle["trace"]["claimed_conforms_to_plan"] = json!(false);

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
    let mut evidence_bundle = bundle(&context);
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
    let evidence_bundle = bundle(&context);

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
