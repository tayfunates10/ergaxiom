use std::error::Error;

use ergaxiom_contract_runtime::{CompiledContract, compile_contract};
use ergaxiom_operator_plan_runtime::{
    PlanCompileError, TraceEvent, TraceStatus, TraceViolation, compile_plan, verify_trace,
};
use serde_json::{Value, json};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");

fn documents() -> Result<(Value, Value, CompiledContract), Box<dyn Error>> {
    let contract: Value = serde_json::from_str(CONTRACT_SOURCE)?;
    let capsule: Value = serde_json::from_str(CAPSULE_SOURCE)?;
    let compiled = compile_contract(&contract, &capsule)?;
    Ok((contract, capsule, compiled))
}

fn plan(compiled: &CompiledContract) -> Value {
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
            step(
                "step.canvas",
                0,
                "design.create_canvas",
                &[],
                "token.canvas"
            ),
            step(
                "step.logo",
                1,
                "design.place_asset",
                &["step.canvas"],
                "token.logo"
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
    capability_token_id: &str,
) -> Value {
    json!({
        "step_id": step_id,
        "sequence": sequence,
        "operator_id": operator_id,
        "operator_version": "0.1.0",
        "depends_on": depends_on,
        "input_artifact_ids": [],
        "output_artifact_ids": [],
        "capability_token_ids": [capability_token_id],
        "mandatory": true,
        "rollback_step_id": null
    })
}

fn trace() -> Vec<TraceEvent> {
    let definitions = [
        ("step.canvas", "design.create_canvas", "token.canvas"),
        ("step.logo", "design.place_asset", "token.logo"),
        ("step.text", "design.compose_text", "token.text"),
        ("step.export", "design.export_raster", "token.export"),
    ];
    let mut events = Vec::new();
    for (step_id, operator_id, token_id) in definitions {
        events.push(event(
            events.len(),
            step_id,
            operator_id,
            token_id,
            TraceStatus::Started,
        ));
        events.push(event(
            events.len(),
            step_id,
            operator_id,
            token_id,
            TraceStatus::Succeeded,
        ));
    }
    events
}

fn event(
    sequence: usize,
    step_id: &str,
    operator_id: &str,
    token_id: &str,
    status: TraceStatus,
) -> TraceEvent {
    TraceEvent {
        event_id: format!("event.{sequence}"),
        step_id: step_id.to_owned(),
        sequence,
        timestamp: format!("2026-07-20T21:10:{sequence:02}Z"),
        operator_id: operator_id.to_owned(),
        status,
        input_digests: Vec::new(),
        output_digests: Vec::new(),
        capability_token_id: Some(token_id.to_owned()),
    }
}

#[test]
fn compiles_a_contract_bound_operator_plan() -> Result<(), Box<dyn Error>> {
    let (_, capsule, compiled_contract) = documents()?;
    let plan_value = plan(&compiled_contract);
    let compiled_plan = compile_plan(&plan_value, &capsule, &compiled_contract)?;

    assert_eq!(compiled_plan.plan_id, "plan.social-post.0001");
    assert_eq!(compiled_plan.steps.len(), 4);
    assert_eq!(compiled_plan.mandatory_step_count(), 4);
    assert_eq!(compiled_plan.plan_digest.len(), 64);
    Ok(())
}

#[test]
fn valid_started_and_succeeded_trace_conforms() -> Result<(), Box<dyn Error>> {
    let (_, capsule, compiled_contract) = documents()?;
    let compiled_plan = compile_plan(&plan(&compiled_contract), &capsule, &compiled_contract)?;
    let assessment = verify_trace(&compiled_plan, &trace(), true);

    assert!(assessment.conforms_to_plan);
    assert!(assessment.claim_matches);
    assert!(assessment.violations.is_empty());
    Ok(())
}

#[test]
fn dependency_must_succeed_before_the_next_step_starts() -> Result<(), Box<dyn Error>> {
    let (_, capsule, compiled_contract) = documents()?;
    let compiled_plan = compile_plan(&plan(&compiled_contract), &capsule, &compiled_contract)?;
    let mut events = trace();
    events.swap(1, 2);
    for (sequence, event) in events.iter_mut().enumerate() {
        event.sequence = sequence;
    }

    let assessment = verify_trace(&compiled_plan, &events, false);
    assert!(!assessment.conforms_to_plan);
    assert!(assessment.claim_matches);
    assert!(assessment.violations.iter().any(|violation| matches!(
        violation,
        TraceViolation::DependencyIncomplete { .. }
    )));
    Ok(())
}

#[test]
fn a_forged_conformance_claim_is_detected() -> Result<(), Box<dyn Error>> {
    let (_, capsule, compiled_contract) = documents()?;
    let compiled_plan = compile_plan(&plan(&compiled_contract), &capsule, &compiled_contract)?;
    let mut events = trace();
    events.pop();

    let assessment = verify_trace(&compiled_plan, &events, true);
    assert!(!assessment.conforms_to_plan);
    assert!(!assessment.claim_matches);
    Ok(())
}

#[test]
fn capability_token_must_be_authorized_for_the_step() -> Result<(), Box<dyn Error>> {
    let (_, capsule, compiled_contract) = documents()?;
    let compiled_plan = compile_plan(&plan(&compiled_contract), &capsule, &compiled_contract)?;
    let mut events = trace();
    events[0].capability_token_id = Some("token.not-authorized".to_owned());

    let assessment = verify_trace(&compiled_plan, &events, false);
    assert!(assessment.violations.iter().any(|violation| matches!(
        violation,
        TraceViolation::UnauthorizedCapabilityToken { .. }
    )));
    Ok(())
}

#[test]
fn operator_version_is_locked_to_the_capsule() -> Result<(), Box<dyn Error>> {
    let (_, capsule, compiled_contract) = documents()?;
    let mut plan_value = plan(&compiled_contract);
    plan_value["steps"][0]["operator_version"] = json!("99.0.0");

    assert!(matches!(
        compile_plan(&plan_value, &capsule, &compiled_contract),
        Err(PlanCompileError::OperatorVersionMismatch { .. })
    ));
    Ok(())
}
