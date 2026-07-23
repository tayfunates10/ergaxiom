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
    assert_eq!(contract["profession"]["capsule_version"], "0.3.0");
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
fn identical_resolved_intent_produces_identical_contract_and_digest() -> Result<(), Box<dyn Error>> {
    let capsule = capsule()?;
    let left = compile_static_social_post_intent(&complete_intent(), &capsule)?;
    let right = compile_static_social_post_intent(&complete_intent(), &capsule)?;
    assert_eq!(left, right);
    Ok(())
}

#[test]
fn caller_supplied_timestamp_is_part_of_the_seal() -> Result<(), Box<dyn Error>> {
    let capsule = capsule()?;
    let baseline = compile_static_social_post_intent(&complete_intent(), &capsule)?;
    let mut changed = complete_intent();
    changed.created_at = Some("2026-07-23T15:01:00Z".to_owned());
    let changed = compile_static_social_post_intent(&changed, &capsule)?;

    let IntentCompileOutcome::Compiled {
        contract_digest: baseline_digest,
        ..
    } = baseline
    else {
        panic!("baseline must compile");
    };
    let IntentCompileOutcome::Compiled {
        contract_digest: changed_digest,
        ..
    } = changed
    else {
        panic!("changed intent must compile");
    };
    assert_ne!(baseline_digest, changed_digest);
    Ok(())
}

#[test]
fn invalid_artifact_digest_fails_before_contract_generation() -> Result<(), Box<dyn Error>> {
    let mut intent = complete_intent();
    intent.approved_logo.sha256 = Some("not-a-digest".to_owned());
    assert!(matches!(
        compile_static_social_post_intent(&intent, &capsule()?),
        Err(IntentContractCompileError::InvalidArtifactDigest(_))
    ));
    Ok(())
}

#[test]
fn unsupported_color_profile_cannot_enter_the_certified_path() -> Result<(), Box<dyn Error>> {
    let mut intent = complete_intent();
    intent.color_profile = Some("Display P3".to_owned());
    assert!(matches!(
        compile_static_social_post_intent(&intent, &capsule()?),
        Err(IntentContractCompileError::UnsupportedColorProfile(_))
    ));
    Ok(())
}

#[test]
fn unsafe_contrast_threshold_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut intent = complete_intent();
    intent.minimum_text_contrast_milli = Some(4_499);
    assert!(matches!(
        compile_static_social_post_intent(&intent, &capsule()?),
        Err(IntentContractCompileError::UnsafeContrastThreshold(4_499))
    ));
    Ok(())
}

fn capsule() -> Result<Value, serde_json::Error> {
    serde_json::from_str(include_str!(
        "../../../professions/graphic-designer/profession.json"
    ))
}

fn complete_intent() -> StaticSocialPostIntent {
    StaticSocialPostIntent {
        contract_id: Some("contract.intent-compiler.0001".to_owned()),
        created_at: Some("2026-07-23T15:00:00Z".to_owned()),
        original_text: Some("Create a verified static social post.".to_owned()),
        language: Some("en".to_owned()),
        requester_id: Some("requester.test".to_owned()),
        approved_logo: artifact("approved-logo.svg", "image/svg+xml", 'a'),
        brand_profile: artifact("brand-profile.json", "application/json", 'b'),
        approved_copy: artifact("approved-copy.txt", "text/plain", 'c'),
        canvas_width_px: Some(1080),
        canvas_height_px: Some(1350),
        color_profile: Some("sRGB IEC61966-2.1".to_owned()),
        logo_clear_space_px: Some(48),
        minimum_text_contrast_milli: Some(4_500),
        visual_tone: Some("modern and strong".to_owned()),
        required_application_version: Some("1.2.2".to_owned()),
        require_pre_execution_approval: true,
    }
}

fn artifact(uri: &str, media_type: &str, digest_character: char) -> InputArtifactIntent {
    InputArtifactIntent {
        uri: Some(format!("contract://inputs/{uri}")),
        media_type: Some(media_type.to_owned()),
        sha256: Some(digest_character.to_string().repeat(64)),
    }
}
