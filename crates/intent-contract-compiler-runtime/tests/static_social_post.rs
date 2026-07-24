use std::error::Error;

use ergaxiom_intent_contract_compiler_runtime::{
    InputArtifactIntent, IntentCompileOutcome, IntentContractCompileError, StaticSocialPostIntent,
    compile_static_social_post_intent,
};
use serde_json::Value;

#[test]
fn complete_intent_compiles_into_the_real_capsule() -> Result<(), Box<dyn Error>> {
    let capsule = capsule()?;
    let outcome = compile_static_social_post_intent(&complete_intent(), &capsule)?;

    let IntentCompileOutcome::Compiled {
        contract,
        contract_digest,
        capsule_digest,
        proof_obligation_count,
        unresolved_mandatory_unknowns,
        ..
    } = outcome
    else {
        panic!("complete intent must compile");
    };

    assert_eq!(contract["schema_version"], "0.2.0");
    assert_eq!(contract["contract_id"], "contract.intent-compiler.0001");
    assert_eq!(contract["profession"]["capsule_version"], "0.5.0");
    assert_eq!(contract["job_type"], "social_media_static_post");
    assert_eq!(contract["requirements"]["unknowns"], Value::Array(vec![]));
    assert_eq!(
        contract["requirements"]["hard"][0]["expected"],
        Value::from(1080)
    );
    assert_eq!(
        contract["requirements"]["hard"][6]["expected"],
        serde_json::json!(4.5)
    );
    assert_eq!(contract["metadata"]["implicit_defaults"], false);
    assert_eq!(proof_obligation_count, 8);
    assert_eq!(unresolved_mandatory_unknowns, 0);
    assert_eq!(contract_digest.len(), 64);
    assert_eq!(capsule_digest.len(), 64);
    Ok(())
}

#[test]
fn missing_values_return_resolution_requests_without_a_contract() -> Result<(), Box<dyn Error>> {
    let outcome =
        compile_static_social_post_intent(&StaticSocialPostIntent::default(), &capsule()?)?;

    let IntentCompileOutcome::NeedsResolution {
        resolution_requests,
        resolution_digest,
        ..
    } = outcome
    else {
        panic!("missing intent must not compile");
    };

    assert_eq!(resolution_requests.len(), 18);
    assert_eq!(resolution_requests[0].field, "contract_id");
    assert_eq!(resolution_requests[1].field, "created_at");
    assert!(
        resolution_requests
            .iter()
            .any(|request| request.field == "approved_logo.sha256")
    );
    assert!(
        resolution_requests
            .iter()
            .any(|request| request.field == "minimum_text_contrast_milli")
    );
    assert_eq!(resolution_digest.len(), 64);
    Ok(())
}

#[test]
fn identical_resolved_intent_produces_identical_contract_and_digest() -> Result<(), Box<dyn Error>>
{
    let capsule = capsule()?;
    let intent = complete_intent();
    let first = compile_static_social_post_intent(&intent, &capsule)?;
    let second = compile_static_social_post_intent(&intent, &capsule)?;

    assert_eq!(first, second);
    Ok(())
}

#[test]
fn caller_supplied_timestamp_is_part_of_the_seal() -> Result<(), Box<dyn Error>> {
    let capsule = capsule()?;
    let first = compile_static_social_post_intent(&complete_intent(), &capsule)?;
    let mut changed = complete_intent();
    changed.created_at = Some("2026-07-23T12:00:01Z".to_owned());
    let second = compile_static_social_post_intent(&changed, &capsule)?;

    let IntentCompileOutcome::Compiled {
        contract_digest: first_digest,
        ..
    } = first
    else {
        panic!("first intent must compile");
    };
    let IntentCompileOutcome::Compiled {
        contract_digest: second_digest,
        ..
    } = second
    else {
        panic!("second intent must compile");
    };
    assert_ne!(first_digest, second_digest);
    Ok(())
}

#[test]
fn invalid_artifact_digest_fails_before_contract_generation() -> Result<(), Box<dyn Error>> {
    let mut intent = complete_intent();
    intent.approved_logo.sha256 = Some("ABC".to_owned());
    let result = compile_static_social_post_intent(&intent, &capsule()?);

    assert!(matches!(
        result,
        Err(IntentContractCompileError::InvalidIntentField {
            field: "approved_logo.sha256",
            ..
        })
    ));
    Ok(())
}

#[test]
fn unsupported_color_profile_cannot_enter_the_certified_path() -> Result<(), Box<dyn Error>> {
    let mut intent = complete_intent();
    intent.color_profile = Some("Display P3".to_owned());
    let result = compile_static_social_post_intent(&intent, &capsule()?);

    assert!(matches!(
        result,
        Err(IntentContractCompileError::UnsupportedCertifiedValue {
            field: "color_profile",
            ..
        })
    ));
    Ok(())
}

#[test]
fn unsafe_contrast_threshold_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut intent = complete_intent();
    intent.minimum_text_contrast_milli = Some(4_499);
    let result = compile_static_social_post_intent(&intent, &capsule()?);

    assert!(matches!(
        result,
        Err(IntentContractCompileError::InvalidIntentField {
            field: "minimum_text_contrast_milli",
            ..
        })
    ));
    Ok(())
}

fn complete_intent() -> StaticSocialPostIntent {
    StaticSocialPostIntent {
        contract_id: Some("contract.intent-compiler.0001".to_owned()),
        created_at: Some("2026-07-23T12:00:00Z".to_owned()),
        original_text: Some(
            "Create a 1080 by 1350 social post from the approved brand assets.".to_owned(),
        ),
        language: Some("en".to_owned()),
        requester_id: Some("user.example".to_owned()),
        approved_logo: artifact("approved-logo.png", "image/png", 'a'),
        brand_profile: artifact("brand-profile.json", "application/json", 'b'),
        approved_copy: artifact("approved-copy.txt", "text/plain", 'c'),
        canvas_width_px: Some(1080),
        canvas_height_px: Some(1350),
        color_profile: Some("sRGB IEC61966-2.1".to_owned()),
        logo_clear_space_px: Some(32),
        minimum_text_contrast_milli: Some(4_500),
        visual_tone: Some("Clean, restrained and professional.".to_owned()),
        required_application_version: Some("1.4".to_owned()),
        require_pre_execution_approval: true,
    }
}

fn artifact(name: &str, media_type: &str, digest_seed: char) -> InputArtifactIntent {
    InputArtifactIntent {
        uri: Some(format!("contract://inputs/{name}")),
        media_type: Some(media_type.to_owned()),
        sha256: Some(digest_seed.to_string().repeat(64)),
    }
}

fn capsule() -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(
        "../../../professions/graphic-designer/profession.json"
    ))?)
}
