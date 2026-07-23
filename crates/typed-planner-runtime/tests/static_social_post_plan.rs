use std::error::Error;

use ergaxiom_contract_runtime::compile_contract;
use ergaxiom_graphic_designer_twin_runtime::{
    ApprovedCopy, ApprovedLogo, BrandProfile, CanvasSpecification, GraphicDesignJob, PixelRect,
    Rgba8, compile_graphic_design_simulation,
};
use ergaxiom_intent_contract_compiler_runtime::{
    InputArtifactIntent, IntentCompileOutcome, StaticSocialPostIntent,
    compile_static_social_post_intent,
};
use ergaxiom_operator_plan_runtime::compile_plan;
use ergaxiom_typed_planner_runtime::{
    StaticSocialPostPlanIdentity, TypedPlanOutcome, TypedPlannerError,
    synthesize_static_social_post_plan,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn complete_contract_produces_the_certified_four_step_plan() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let outcome = synthesize_static_social_post_plan(
        &identity(),
        &fixture.contract,
        &fixture.capsule,
    )?;

    let TypedPlanOutcome::Planned {
        plan,
        plan_digest,
        contract_digest,
        capsule_digest,
        mandatory_step_count,
        capability_requirement_digest,
        ..
    } = outcome
    else {
        panic!("complete planning identity must produce a plan");
    };

    assert_eq!(plan["schema_version"], "0.1.0");
    assert_eq!(plan["plan_id"], "plan.static-social.0001");
    assert_eq!(plan["steps"].as_array().map(Vec::len), Some(4));
    assert_eq!(plan["steps"][0]["operator_id"], "design.create_canvas");
    assert_eq!(plan["steps"][1]["operator_id"], "design.place_asset");
    assert_eq!(plan["steps"][2]["operator_id"], "design.compose_text");
    assert_eq!(plan["steps"][3]["operator_id"], "design.export_raster");
    assert_eq!(plan["steps"][3]["depends_on"], json!(["step.text"]));
    assert_eq!(
        plan["steps"][3]["capability_token_ids"],
        json!(["capability.plan.static-social.0001.export"])
    );
    assert_eq!(
        plan["metadata"]["capability_requirements"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );
    assert_eq!(mandatory_step_count, 4);
    assert_eq!(plan_digest.len(), 64);
    assert_eq!(contract_digest.len(), 64);
    assert_eq!(capsule_digest.len(), 64);
    assert_eq!(capability_requirement_digest.len(), 64);
    Ok(())
}

#[test]
fn missing_plan_identity_returns_resolution_requests_without_a_plan() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let outcome = synthesize_static_social_post_plan(
        &StaticSocialPostPlanIdentity::default(),
        &fixture.contract,
        &fixture.capsule,
    )?;

    let TypedPlanOutcome::NeedsResolution {
        resolution_requests,
        resolution_digest,
        ..
    } = outcome
    else {
        panic!("missing identity must not produce an Operator Plan");
    };

    assert_eq!(resolution_requests.len(), 2);
    assert_eq!(resolution_requests[0].field, "plan_id");
    assert_eq!(resolution_requests[1].field, "created_at");
    assert_eq!(resolution_digest.len(), 64);
    Ok(())
}

#[test]
fn identical_sealed_inputs_produce_identical_plan_material() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let identity = identity();
    let first = synthesize_static_social_post_plan(
        &identity,
        &fixture.contract,
        &fixture.capsule,
    )?;
    let second = synthesize_static_social_post_plan(
        &identity,
        &fixture.contract,
        &fixture.capsule,
    )?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn caller_supplied_plan_timestamp_changes_the_plan_digest() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let first = synthesize_static_social_post_plan(
        &identity(),
        &fixture.contract,
        &fixture.capsule,
    )?;
    let mut changed = identity();
    changed.created_at = Some("2026-07-23T12:30:01Z".to_owned());
    let second = synthesize_static_social_post_plan(
        &changed,
        &fixture.contract,
        &fixture.capsule,
    )?;

    let TypedPlanOutcome::Planned {
        plan_digest: first_digest,
        ..
    } = first
    else {
        panic!("first identity must plan");
    };
    let TypedPlanOutcome::Planned {
        plan_digest: second_digest,
        ..
    } = second
    else {
        panic!("second identity must plan");
    };
    assert_ne!(first_digest, second_digest);
    Ok(())
}

#[test]
fn undeclared_extra_input_cannot_enter_the_certified_plan() -> Result<(), Box<dyn Error>> {
    let mut fixture = fixture()?;
    fixture
        .contract
        .get_mut("inputs")
        .and_then(Value::as_array_mut)
        .ok_or("contract inputs missing")?
        .push(json!({
            "id": "hidden_asset",
            "kind": "reference_image",
            "uri": "contract://inputs/hidden.png",
            "integrity": {"algorithm": "sha256", "digest": "d".repeat(64)},
            "media_type": "image/png",
            "immutable": true
        }));

    let result = synthesize_static_social_post_plan(
        &identity(),
        &fixture.contract,
        &fixture.capsule,
    );
    assert!(matches!(
        result,
        Err(TypedPlannerError::ProfileMismatch {
            profile: "contract input",
            ..
        })
    ));
    Ok(())
}

#[test]
fn extra_permission_cannot_be_hidden_in_the_plan() -> Result<(), Box<dyn Error>> {
    let mut fixture = fixture()?;
    fixture
        .contract
        .get_mut("permissions")
        .and_then(Value::as_array_mut)
        .ok_or("contract permissions missing")?
        .push(json!({
            "capability": "network",
            "resource": "*",
            "access": "network",
            "constraints": {}
        }));

    let result = synthesize_static_social_post_plan(
        &identity(),
        &fixture.contract,
        &fixture.capsule,
    );
    assert!(matches!(
        result,
        Err(TypedPlannerError::ProfileMismatch {
            profile: "contract permission",
            ..
        })
    ));
    Ok(())
}

#[test]
fn missing_capsule_operator_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut fixture = fixture()?;
    let operators = fixture
        .capsule
        .get_mut("operators")
        .and_then(Value::as_array_mut)
        .ok_or("capsule operators missing")?;
    operators.retain(|operator| operator["id"] != "design.compose_text");

    let result = synthesize_static_social_post_plan(
        &identity(),
        &fixture.contract,
        &fixture.capsule,
    );
    assert!(matches!(
        result,
        Err(TypedPlannerError::MissingOperator(operator_id))
            if operator_id == "design.compose_text"
    ));
    Ok(())
}

#[test]
fn generated_plan_enters_graphic_twin_simulation_without_rewriting() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let outcome = synthesize_static_social_post_plan(
        &identity(),
        &fixture.contract,
        &fixture.capsule,
    )?;
    let TypedPlanOutcome::Planned { plan, .. } = outcome else {
        panic!("complete fixture must produce a plan");
    };

    let compiled_contract = compile_contract(&fixture.contract, &fixture.capsule)?;
    let compiled_plan = compile_plan(&plan, &fixture.capsule, &compiled_contract)?;
    let simulation = compile_graphic_design_simulation(
        &compiled_contract,
        &fixture.contract,
        &compiled_plan,
        &fixture.job,
    )?;

    assert_eq!(simulation.invocations.len(), 4);
    assert_eq!(simulation.plan_id, "plan.static-social.0001");
    assert_eq!(simulation.plan_digest, compiled_plan.plan_digest);
    Ok(())
}

struct Fixture {
    contract: Value,
    capsule: Value,
    job: GraphicDesignJob,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let capsule: Value = serde_json::from_str(include_str!(
        "../../../professions/graphic-designer/profession.json"
    ))?;
    let logo_content = b"<svg viewBox='0 0 200 100'>approved</svg>".to_vec();
    let approved_copy = "APPROVED".to_owned();
    let brand_profile = BrandProfile {
        artifact_id: "brand_profile".to_owned(),
        media_type: "application/json".to_owned(),
        minimum_logo_clear_space_px: 16,
        minimum_text_contrast_milli: 4_500,
    };
    let brand_profile_bytes = serde_json::to_vec(&brand_profile)?;

    let intent = StaticSocialPostIntent {
        contract_id: Some("contract.static-social.0001".to_owned()),
        created_at: Some("2026-07-23T12:00:00Z".to_owned()),
        original_text: Some("Create the certified static social post.".to_owned()),
        language: Some("en".to_owned()),
        requester_id: Some("user.fixture".to_owned()),
        approved_logo: artifact(
            "approved-logo.svg",
            "image/svg+xml",
            &sha256_hex(&logo_content),
        ),
        brand_profile: artifact(
            "brand-profile.json",
            "application/json",
            &sha256_hex(&brand_profile_bytes),
        ),
        approved_copy: artifact(
            "approved-copy.txt",
            "text/plain",
            &sha256_hex(approved_copy.as_bytes()),
        ),
        canvas_width_px: Some(240),
        canvas_height_px: Some(300),
        color_profile: Some("sRGB IEC61966-2.1".to_owned()),
        logo_clear_space_px: Some(16),
        minimum_text_contrast_milli: Some(4_500),
        visual_tone: Some("Clean and professional.".to_owned()),
        required_application_version: Some("1.4".to_owned()),
        require_pre_execution_approval: true,
    };
    let outcome = compile_static_social_post_intent(&intent, &capsule)?;
    let IntentCompileOutcome::Compiled { contract, .. } = outcome else {
        return Err("complete fixture intent did not compile".into());
    };

    let job = GraphicDesignJob {
        schema_version: "0.1.0".to_owned(),
        job_id: "job.static-social.0001".to_owned(),
        evaluated_at: "2026-07-23T12:31:00Z".to_owned(),
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
            content: logo_content,
            source_width: 200,
            source_height: 100,
            primary_color: Rgba8::opaque(20, 40, 80),
            secondary_color: Rgba8::opaque(40, 120, 220),
        },
        approved_copy: ApprovedCopy {
            artifact_id: "approved_copy".to_owned(),
            media_type: "text/plain".to_owned(),
            text: approved_copy,
        },
        brand_profile,
        editable_master_id: "editable_master".to_owned(),
        delivery_raster_id: "delivery_raster".to_owned(),
    };

    Ok(Fixture {
        contract,
        capsule,
        job,
    })
}

fn identity() -> StaticSocialPostPlanIdentity {
    StaticSocialPostPlanIdentity {
        plan_id: Some("plan.static-social.0001".to_owned()),
        created_at: Some("2026-07-23T12:30:00Z".to_owned()),
    }
}

fn artifact(name: &str, media_type: &str, sha256: &str) -> InputArtifactIntent {
    InputArtifactIntent {
        uri: Some(format!("contract://inputs/{name}")),
        media_type: Some(media_type.to_owned()),
        sha256: Some(sha256.to_owned()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
