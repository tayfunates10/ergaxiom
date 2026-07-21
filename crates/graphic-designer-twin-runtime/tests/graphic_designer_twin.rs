use std::error::Error;

use ergaxiom_contract_runtime::{CompiledContract, ContractSession, compile_contract};
use ergaxiom_graphic_designer_twin_runtime::{
    ApprovedCopy, ApprovedLogo, BrandProfile, CanvasSpecification, GraphicDesignJob,
    GraphicTwinError, PixelRect, Rgba8, ValidationError, decode_rgba_png,
    execute_graphic_design_twin, validate_graphic_artifacts, verify_validation_report_digest,
};
use ergaxiom_occupational_twin_runtime::{ApplicationIdentity, EnvironmentIdentity, TwinWorkspace};
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");

struct Context {
    contract_value: Value,
    compiled_contract: CompiledContract,
    compiled_plan: CompiledPlan,
    job: GraphicDesignJob,
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
    let plan_value = plan_value(&compiled_contract);
    let compiled_plan = compile_plan(&plan_value, &capsule_value, &compiled_contract)?;
    Ok(Context {
        contract_value,
        compiled_contract,
        compiled_plan,
        job,
    })
}

fn job() -> GraphicDesignJob {
    GraphicDesignJob {
        schema_version: "0.1.0".to_owned(),
        job_id: "graphic-twin-test.0001".to_owned(),
        evaluated_at: "2026-07-21T12:00:00Z".to_owned(),
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
            text: "ERGAXIOM\nVERIFIED".to_owned(),
        },
        brand_profile: BrandProfile {
            artifact_id: "brand_profile".to_owned(),
            media_type: "application/json".to_owned(),
            minimum_logo_clear_space_px: 16,
            minimum_text_contrast_milli: 4500,
        },
        editable_master_id: "editable_master".to_owned(),
        delivery_raster_id: "delivery_raster".to_owned(),
    }
}

fn plan_value(contract: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.graphic-twin-test.0001",
        "created_at": "2026-07-21T12:00:00Z",
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
            ),
            step(
                "step.logo",
                1,
                "design.place_asset",
                &["step.canvas"],
                &["editable_master", "approved_logo"],
                &["editable_master"],
            ),
            step(
                "step.text",
                2,
                "design.compose_text",
                &["step.logo"],
                &["editable_master", "approved_copy"],
                &["editable_master"],
            ),
            step(
                "step.export",
                3,
                "design.export_raster",
                &["step.text"],
                &["editable_master"],
                &["delivery_raster"],
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
) -> Value {
    json!({
        "step_id": step_id,
        "sequence": sequence,
        "operator_id": operator_id,
        "operator_version": "0.1.0",
        "depends_on": depends_on,
        "input_artifact_ids": inputs,
        "output_artifact_ids": outputs,
        "capability_token_ids": [],
        "mandatory": true,
        "rollback_step_id": null,
    })
}

fn workspace() -> Result<TwinWorkspace, Box<dyn Error>> {
    Ok(TwinWorkspace::new(
        "workspace.graphic-twin-test",
        EnvironmentIdentity {
            os: "windows".to_owned(),
            architecture: "x86_64".to_owned(),
            runtime_id: "ergaxiom.graphic-designer-twin".to_owned(),
            runtime_version: "0.1.0".to_owned(),
            clock_source: "test-clock".to_owned(),
            sandbox_id: "sandbox.graphic-twin-test".to_owned(),
            applications: vec![ApplicationIdentity {
                application_id: "ergaxiom.design-document-model".to_owned(),
                version: "0.1.0".to_owned(),
                digest: "design-document-model-digest".to_owned(),
            }],
        },
    )?)
}

#[test]
fn accepted_static_post_runs_through_contract_plan_twin_and_proof_kernel()
-> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut workspace = workspace()?;
    let run = execute_graphic_design_twin(
        &mut workspace,
        &context.compiled_contract,
        &context.contract_value,
        &context.compiled_plan,
        &context.job,
    )?;

    assert!(run.simulation.conforms_to_plan);
    assert!(run.validation.all_mandatory_passed);
    assert!(verify_validation_report_digest(&run.validation)?);
    assert_eq!(run.proof_evidence.len(), 9);
    let decoded = decode_rgba_png(&run.raster_png)?;
    assert_eq!((decoded.width, decoded.height), (240, 300));
    assert_eq!(decoded.profile_name, "sRGB IEC61966-2.1");
    assert_eq!(decoded.profile_description, "sRGB IEC61966-2.1");
    assert!(decoded.has_srgb_chunk);

    let mut session = ContractSession::new(context.compiled_contract.clone(), AssuranceLevel::E3)?;
    for evidence in run.proof_evidence {
        session.ingest_evidence(evidence)?;
    }
    assert_eq!(session.evaluate().status, DecisionStatus::Accepted);
    assert_eq!(
        workspace.artifact_content("approved_logo"),
        Some(context.job.approved_logo.content.as_slice())
    );
    assert_eq!(
        workspace.artifact_content("approved_copy"),
        Some(context.job.approved_copy.text.as_bytes())
    );
    Ok(())
}

#[test]
fn identical_sealed_inputs_produce_identical_raster_and_reports() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut first_workspace = workspace()?;
    let mut second_workspace = workspace()?;
    let first = execute_graphic_design_twin(
        &mut first_workspace,
        &context.compiled_contract,
        &context.contract_value,
        &context.compiled_plan,
        &context.job,
    )?;
    let second = execute_graphic_design_twin(
        &mut second_workspace,
        &context.compiled_contract,
        &context.contract_value,
        &context.compiled_plan,
        &context.job,
    )?;

    assert_eq!(first.raster_png, second.raster_png);
    assert_eq!(first.document, second.document);
    assert_eq!(first.validation, second.validation);
    assert_eq!(first.simulation, second.simulation);
    Ok(())
}

#[test]
fn raw_contract_mutation_after_compilation_is_rejected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut changed_contract = context.contract_value.clone();
    set_constraint_expected(&mut changed_contract, "canvas_width", json!(241))?;
    let mut workspace = workspace()?;
    let result = execute_graphic_design_twin(
        &mut workspace,
        &context.compiled_contract,
        &changed_contract,
        &context.compiled_plan,
        &context.job,
    );
    assert!(matches!(
        result,
        Err(GraphicTwinError::ContractDigestMismatch)
    ));
    Ok(())
}

#[test]
fn changed_approved_logo_bytes_are_rejected_before_staging() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut changed_job = context.job.clone();
    changed_job.approved_logo.content.push(0);
    let mut workspace = workspace()?;
    let result = execute_graphic_design_twin(
        &mut workspace,
        &context.compiled_contract,
        &context.contract_value,
        &context.compiled_plan,
        &changed_job,
    );
    assert!(matches!(
        result,
        Err(GraphicTwinError::InputIntegrityMismatch(ref id)) if id == "approved_logo"
    ));
    assert!(workspace.current_snapshot()?.artifacts.is_empty());
    Ok(())
}

#[test]
fn distorted_logo_is_rejected_by_contract_binding_before_execution() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut changed_job = context.job.clone();
    changed_job.logo_bounds.width = 81;
    let mut workspace = workspace()?;
    let result = execute_graphic_design_twin(
        &mut workspace,
        &context.compiled_contract,
        &context.contract_value,
        &context.compiled_plan,
        &changed_job,
    );
    assert!(matches!(
        result,
        Err(GraphicTwinError::ContractValueMismatch {
            field: "logo_aspect_ratio",
            ..
        })
    ));
    assert!(workspace.current_snapshot()?.artifacts.is_empty());
    Ok(())
}

#[test]
fn low_contrast_output_executes_but_proof_kernel_rejects_it() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut changed_job = context.job.clone();
    changed_job.text_color = Rgba8::opaque(180, 180, 180);
    let mut workspace = workspace()?;
    let run = execute_graphic_design_twin(
        &mut workspace,
        &context.compiled_contract,
        &context.contract_value,
        &context.compiled_plan,
        &changed_job,
    )?;
    assert!(run.simulation.conforms_to_plan);
    assert!(!run.validation.all_mandatory_passed);
    assert!(run.validation.observations.iter().any(|observation| {
        observation.claim_id == "minimum_text_contrast" && !observation.passed
    }));

    let mut session = ContractSession::new(context.compiled_contract, AssuranceLevel::E3)?;
    for evidence in run.proof_evidence {
        session.ingest_evidence(evidence)?;
    }
    assert_eq!(session.evaluate().status, DecisionStatus::Rejected);
    Ok(())
}

#[test]
fn text_outside_safe_area_executes_but_is_not_accepted() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut changed_job = context.job.clone();
    changed_job.text_origin_x = 4;
    let mut workspace = workspace()?;
    let run = execute_graphic_design_twin(
        &mut workspace,
        &context.compiled_contract,
        &context.contract_value,
        &context.compiled_plan,
        &changed_job,
    )?;
    assert!(!run.validation.all_mandatory_passed);
    assert!(run.validation.observations.iter().any(|observation| {
        observation.claim_id == "text_within_safe_area" && !observation.passed
    }));
    Ok(())
}

#[test]
fn png_chunk_tampering_is_detected_independently() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut workspace = workspace()?;
    let run = execute_graphic_design_twin(
        &mut workspace,
        &context.compiled_contract,
        &context.contract_value,
        &context.compiled_plan,
        &context.job,
    )?;
    let mut tampered = run.raster_png.clone();
    let idat_type = tampered
        .windows(4)
        .position(|window| window == b"IDAT")
        .ok_or("IDAT chunk not found")?;
    let data_index = idat_type.checked_add(8).ok_or("IDAT index overflow")?;
    let byte = tampered.get_mut(data_index).ok_or("IDAT data missing")?;
    *byte ^= 1;

    let editable_master = workspace
        .artifact_content(&context.job.editable_master_id)
        .ok_or("editable master missing")?;
    let result = validate_graphic_artifacts(&context.job, editable_master, &tampered);
    assert!(matches!(result, Err(ValidationError::Png(_))));
    Ok(())
}

#[test]
fn validation_report_mutation_invalidates_its_digest() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let mut workspace = workspace()?;
    let mut run = execute_graphic_design_twin(
        &mut workspace,
        &context.compiled_contract,
        &context.contract_value,
        &context.compiled_plan,
        &context.job,
    )?;
    run.validation.all_mandatory_passed = false;
    assert!(!verify_validation_report_digest(&run.validation)?);
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
