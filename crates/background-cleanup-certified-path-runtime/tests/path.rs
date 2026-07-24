use std::error::Error;

use ergaxiom_background_cleanup_certified_path_runtime::{
    BackgroundCleanupCompileOutcome, BackgroundCleanupExecutionRequest, BackgroundCleanupIntent,
    BackgroundCleanupPlanIdentity, BackgroundCleanupPlanOutcome, BackgroundCleanupRuntimeError,
    BackgroundCleanupValidationReport, CleanupArtifactIntent, CleanupFailureCode,
    background_cleanup_failure_map, compile_background_cleanup_intent,
    encode_restricted_srgb_rgba_png, execute_background_cleanup,
    synthesize_background_cleanup_plan, validate_background_cleanup,
};
use ergaxiom_contract_runtime::compile_contract;
use ergaxiom_operator_plan_runtime::compile_plan;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn unresolved_cleanup_intent_returns_questions_without_a_contract() -> Result<(), Box<dyn Error>> {
    let outcome = compile_background_cleanup_intent(
        &BackgroundCleanupIntent::default(),
        &capsule()?,
    )?;
    let BackgroundCleanupCompileOutcome::NeedsResolution {
        resolution_requests,
        resolution_digest,
        ..
    } = outcome
    else {
        panic!("unresolved cleanup intent must not compile");
    };
    assert_eq!(resolution_requests.len(), 13);
    assert!(
        resolution_requests
            .iter()
            .any(|request| request.field == "approved_cleanup_mask.sha256")
    );
    assert_eq!(resolution_digest.len(), 64);
    Ok(())
}

#[test]
fn resolved_cleanup_intent_and_plan_are_deterministic() -> Result<(), Box<dyn Error>> {
    let (source, mask) = accepted_png_fixture()?;
    let capsule = capsule()?;
    let intent = complete_intent(&source, &mask);
    let first = compile_background_cleanup_intent(&intent, &capsule)?;
    let second = compile_background_cleanup_intent(&intent, &capsule)?;
    assert_eq!(first, second);

    let BackgroundCleanupCompileOutcome::Compiled {
        contract,
        proof_obligation_count,
        unresolved_mandatory_unknowns,
        ..
    } = first
    else {
        panic!("complete cleanup intent must compile");
    };
    assert_eq!(contract["profession"]["capsule_version"], "0.4.0");
    assert_eq!(contract["job_type"], "image_background_cleanup");
    assert_eq!(proof_obligation_count, 12);
    assert_eq!(unresolved_mandatory_unknowns, 0);

    let identity = BackgroundCleanupPlanIdentity {
        plan_id: Some("plan.background-cleanup.0001".to_owned()),
        created_at: Some("2026-07-24T08:01:00Z".to_owned()),
    };
    let planned = synthesize_background_cleanup_plan(&identity, &contract, &capsule)?;
    let BackgroundCleanupPlanOutcome::Planned {
        plan,
        mandatory_step_count,
        capability_requirements,
        ..
    } = planned
    else {
        panic!("resolved cleanup plan identity must plan");
    };
    assert_eq!(mandatory_step_count, 3);
    assert_eq!(capability_requirements.len(), 3);
    assert_eq!(plan["steps"][0]["operator_id"], "cleanup.apply_binary_mask");
    assert_eq!(plan["steps"][1]["operator_id"], "cleanup.inkscape_probe");
    assert_eq!(plan["steps"][2]["operator_id"], "cleanup.certify_delivery");

    let compiled_contract = compile_contract(&contract, &capsule)?;
    let compiled_plan = compile_plan(&plan, &capsule, &compiled_contract)?;
    assert_eq!(compiled_plan.mandatory_step_count(), 3);
    Ok(())
}

#[test]
fn binary_mask_execution_is_independently_accepted() -> Result<(), Box<dyn Error>> {
    let (source, mask) = accepted_png_fixture()?;
    let source_digest = sha256(&source);
    let mask_digest = sha256(&mask);
    let execution = execute_background_cleanup(BackgroundCleanupExecutionRequest {
        request_id: "cleanup.accepted.0001",
        source_png: &source,
        approved_mask_png: &mask,
        expected_source_digest: &source_digest,
        expected_mask_digest: &mask_digest,
        expected_width: 4,
        expected_height: 3,
    })?;
    assert!(execution.record.verified);
    assert_eq!(execution.record.foreground_pixels, 6);
    assert_eq!(execution.record.background_pixels, 6);

    let validation = validate_background_cleanup(
        &source,
        &mask,
        &execution.cleaned_png,
        &execution.record,
    )?;
    assert!(validation.accepted);
    assert_eq!(validation.background_alpha_violations, 0);
    assert_eq!(validation.foreground_rgba_violations, 0);
    assert!(background_cleanup_failure_map(&validation, true).is_empty());
    Ok(())
}

#[test]
fn non_binary_mask_is_rejected_before_output_exists() -> Result<(), Box<dyn Error>> {
    let (source, mut mask_pixels) = accepted_pixels();
    mask_pixels[3] = 128;
    let source_png = encode_restricted_srgb_rgba_png(4, 3, &source)?;
    let mask_png = encode_restricted_srgb_rgba_png(4, 3, &mask_pixels)?;
    let result = execute_background_cleanup(BackgroundCleanupExecutionRequest {
        request_id: "cleanup.nonbinary.0001",
        source_png: &source_png,
        approved_mask_png: &mask_png,
        expected_source_digest: &sha256(&source_png),
        expected_mask_digest: &sha256(&mask_png),
        expected_width: 4,
        expected_height: 3,
    });
    assert!(matches!(
        result,
        Err(BackgroundCleanupRuntimeError::NonBinaryMask { .. })
    ));
    Ok(())
}

#[test]
fn tampered_cleaned_output_fails_record_binding() -> Result<(), Box<dyn Error>> {
    let (source, mask) = accepted_png_fixture()?;
    let execution = execute_background_cleanup(BackgroundCleanupExecutionRequest {
        request_id: "cleanup.tamper.0001",
        source_png: &source,
        approved_mask_png: &mask,
        expected_source_digest: &sha256(&source),
        expected_mask_digest: &sha256(&mask),
        expected_width: 4,
        expected_height: 3,
    })?;
    let mut tampered = execution.cleaned_png.clone();
    let last = tampered.len().saturating_sub(1);
    tampered[last] ^= 1;
    let result = validate_background_cleanup(&source, &mask, &tampered, &execution.record);
    assert!(matches!(
        result,
        Err(BackgroundCleanupRuntimeError::ExecutionBindingMismatch)
            | Err(BackgroundCleanupRuntimeError::PngArtifact(_))
            | Err(BackgroundCleanupRuntimeError::IndependentPng(_))
    ));
    Ok(())
}

#[test]
fn failure_map_is_actionable_and_stable() {
    let report = BackgroundCleanupValidationReport {
        schema_version: "0.1.0".to_owned(),
        validator_version: "0.1.0".to_owned(),
        source_digest: "a".repeat(64),
        mask_digest: "b".repeat(64),
        output_digest: "c".repeat(64),
        width: 4,
        height: 3,
        output_media_type_png: false,
        output_srgb: false,
        mask_dimensions_match: false,
        mask_is_binary: false,
        mask_foreground_pixels: 0,
        mask_background_pixels: 0,
        background_alpha_violations: 2,
        foreground_rgba_violations: 3,
        source_immutable: false,
        accepted: false,
        report_digest: String::new(),
    };
    let failures = background_cleanup_failure_map(&report, false);
    assert_eq!(failures.len(), 9);
    assert_eq!(failures[0].code, CleanupFailureCode::OutputMediaType);
    assert!(failures.iter().all(|failure| !failure.action.is_empty()));
}

fn complete_intent(source: &[u8], mask: &[u8]) -> BackgroundCleanupIntent {
    BackgroundCleanupIntent {
        contract_id: Some("contract.background-cleanup.0001".to_owned()),
        created_at: Some("2026-07-24T08:00:00Z".to_owned()),
        original_text: Some("Remove the background using the approved mask.".to_owned()),
        language: Some("en".to_owned()),
        requester_id: Some("user.example".to_owned()),
        source_raster: artifact("source.png", source),
        approved_cleanup_mask: artifact("approved-mask.png", mask),
        source_width_px: Some(4),
        source_height_px: Some(3),
        required_application_version: Some("1.2.2".to_owned()),
        visual_preference: Some("Prefer visually natural edges.".to_owned()),
        require_pre_execution_approval: true,
    }
}

fn artifact(name: &str, bytes: &[u8]) -> CleanupArtifactIntent {
    CleanupArtifactIntent {
        uri: Some(format!("contract://inputs/{name}")),
        media_type: Some("image/png".to_owned()),
        sha256: Some(sha256(bytes)),
    }
}

fn accepted_png_fixture() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let (source, mask) = accepted_pixels();
    Ok((
        encode_restricted_srgb_rgba_png(4, 3, &source)?,
        encode_restricted_srgb_rgba_png(4, 3, &mask)?,
    ))
}

fn accepted_pixels() -> (Vec<u8>, Vec<u8>) {
    let mut source = Vec::new();
    let mut mask = Vec::new();
    for index in 0_u8..12 {
        source.extend_from_slice(&[
            index.saturating_mul(13),
            255_u8.saturating_sub(index.saturating_mul(7)),
            index.saturating_mul(5),
            255,
        ]);
        let foreground = index % 2 == 0;
        mask.extend_from_slice(&[255, 255, 255, if foreground { 255 } else { 0 }]);
    }
    (source, mask)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn capsule() -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(
        "../../../professions/graphic-designer/profession.json"
    ))?)
}
