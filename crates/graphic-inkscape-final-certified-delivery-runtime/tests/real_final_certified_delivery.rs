#![cfg(feature = "real-inkscape-tests")]

#[allow(dead_code)]
#[path = "../../graphic-inkscape-srgb-certified-delivery-runtime/tests/support/mod.rs"]
mod support;

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use ergaxiom_attestation_runtime::{AttestationKeyRegistry, verify_attestation_against_bundle};
use ergaxiom_contract_runtime::compile_contract;
use ergaxiom_graphic_designer_twin_runtime::{PixelRect as GraphicRect, Rgba8, encode_rgba_png};
use ergaxiom_graphic_final_artifact_verification_runtime::{
    FinalArtifactExpectations, FinalArtifactVerificationError, FinalArtifactVerificationRequest,
    verify_final_artifacts,
};
use ergaxiom_graphic_inkscape_final_certified_delivery_runtime::{
    InkscapeFinalArtifactCertificationRequest, certify_inkscape_final_artifacts,
};
use ergaxiom_graphic_inkscape_srgb_certified_delivery_runtime::{
    InkscapeSrgbCertificationRequest, certify_inkscape_srgb_graphic_delivery,
};
use ergaxiom_inkscape_adapter_runtime::{SetTextAndExportRequest, VerifiedInkscape, sha256_file};
use ergaxiom_inkscape_execution_evidence_runtime::{
    InkscapeExecutionKeyRegistry, sign_execution_record,
};
use ergaxiom_operator_plan_runtime::compile_plan;
use ergaxiom_png_logo_geometry_runtime::{
    LogoGeometryPolicy, PixelRect as LogoRect, validate_logo_geometry,
};
use ergaxiom_png_pixel_decoder_runtime::decode_png_bytes;
use ergaxiom_png_rendered_contrast_runtime::{
    PixelRect as ContrastRect, RenderedContrastPolicy, validate_rendered_contrast,
};
use ergaxiom_png_rendered_text_bounds_runtime::{
    PixelRect as TextRect, RenderedTextBoundsPolicy, validate_rendered_text_bounds,
};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus};
use ergaxiom_svg_approved_copy_runtime::{ApprovedCopyPolicy, validate_approved_copy};
use ergaxiom_typed_planner_runtime::{
    StaticSocialPostPlanIdentity, TypedPlanOutcome, synthesize_static_social_post_plan,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use support::{
    ATTESTATION_ISSUER, ATTESTATION_KEY_ID, EXECUTION_ISSUER, EXECUTION_KEY_ID, ExecutionFixture,
    NOW, TestDirectory, attestation_keys, authorizer, certify_base_delivery, context,
    normalization_fixture, normalization_material, signed_tokens, workspace,
};

const TEXT_ANALYSIS: TextRect = TextRect {
    x: 12,
    y: 100,
    width: 216,
    height: 80,
};
const TEXT_SAFE_AREA: TextRect = TextRect {
    x: 20,
    y: 110,
    width: 200,
    height: 61,
};
const LOGO_REGION: LogoRect = LogoRect {
    x: 24,
    y: 24,
    width: 80,
    height: 40,
};

#[test]
fn real_inkscape_artifacts_issue_final_acceptance_certificate() -> Result<(), Box<dyn Error>> {
    let (Ok(executable), Ok(executable_digest)) = (
        env::var("ERGAXIOM_INKSCAPE"),
        env::var("ERGAXIOM_INKSCAPE_SHA256"),
    ) else {
        return Ok(());
    };

    let approved_logo_png = approved_logo_png()?;
    let decoded_approved_logo = decode_png_bytes(&approved_logo_png)
        .map_err(|error| format!("approved-logo PNG decode failed: {error}"))?;
    let context = real_context(&approved_logo_png)?;
    let tokens = signed_tokens(&context)?;
    let directory = TestDirectory::create("real-final-artifact")?;
    let source = directory.join("source.svg");
    let editable = directory.join("editable.svg");
    let raw_raster = directory.join("raw.png");
    fs::write(&source, real_fixture_svg("BEFORE").as_bytes())?;

    let inkscape = VerifiedInkscape::open(&executable, &executable_digest)?;
    let execution_request = SetTextAndExportRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.real-final-artifact.0001".to_owned(),
        source_svg: source.clone(),
        expected_source_digest: sha256_file(&source)?,
        target_element_id: "headline".to_owned(),
        replacement_text: context.job.approved_copy.text.clone(),
        editable_output_svg: editable.clone(),
        raster_output_png: raw_raster.clone(),
        export_width: context.job.canvas.width,
        export_height: context.job.canvas.height,
    };
    let execution_record = inkscape.execute_set_text_and_export(&execution_request)?;
    let execution_key = SigningKey::from_bytes(&[73_u8; 32]);
    let execution_package = sign_execution_record(
        &execution_record,
        EXECUTION_ISSUER,
        EXECUTION_KEY_ID,
        &execution_key,
    )?;
    let mut execution_keys = InkscapeExecutionKeyRegistry::default();
    execution_keys.insert_ed25519(
        EXECUTION_ISSUER,
        EXECUTION_KEY_ID,
        execution_key.verifying_key().to_bytes(),
    )?;
    let execution = ExecutionFixture {
        _directory: directory,
        source,
        editable,
        raster: raw_raster,
        request: execution_request,
        package: execution_package,
        keys: execution_keys,
    };

    let raw_raster_bytes = fs::read(&execution.raster)?;
    decode_png_bytes(&raw_raster_bytes)
        .map_err(|error| format!("raw Inkscape PNG decode failed: {error}"))?;
    let normalization = normalization_fixture(&execution)
        .map_err(|error| format!("normalization fixture failed: {error}"))?;
    let mut workspace = workspace()?;
    let mut authorizer = authorizer(&context)?;
    let base_attestation_keys = attestation_keys(&context)?;
    let base_delivery = certify_base_delivery(
        &context,
        &mut workspace,
        &mut authorizer,
        &tokens,
        &execution,
    )
    .map_err(|error| format!("base delivery certification failed: {error}"))?;
    let srgb_delivery = certify_inkscape_srgb_graphic_delivery(InkscapeSrgbCertificationRequest {
        base_delivery,
        normalization_material: normalization_material(&execution, &normalization),
        normalization_keys: &normalization.keys,
        base_attestation_keys: &base_attestation_keys,
        contract_value: &context.contract_value,
        compiled_contract: &context.compiled_contract,
        compiled_plan: &context.compiled_plan,
        assurance_level: AssuranceLevel::E3,
        final_manifest_id: "manifest.real-final-artifact-srgb.0001",
        final_certificate_id: "certificate.real-final-artifact-srgb.0001",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW + 1,
        attestation_signing_key: &context.attestation_key,
    })
    .map_err(|error| format!("sRGB delivery certification failed: {error}"))?;

    let editable_bytes = fs::read(&execution.editable)?;
    let normalized_bytes = fs::read(&normalization.output)?;
    let approved_copy = validate_approved_copy(
        context.job.approved_copy.text.as_bytes(),
        &editable_bytes,
        &ApprovedCopyPolicy {
            target_element_id: "headline".to_owned(),
        },
    )?;
    let decoded_normalized = decode_png_bytes(&normalized_bytes)
        .map_err(|error| format!("normalized PNG decode failed: {error}"))?;
    let logo_geometry =
        validate_logo_geometry(&decoded_approved_logo, &decoded_normalized, &logo_policy())?;
    let text_bounds = validate_rendered_text_bounds(
        &decoded_normalized,
        &text_policy(TEXT_ANALYSIS, TEXT_SAFE_AREA),
    )?;
    let rendered_contrast =
        validate_rendered_contrast(&decoded_normalized, &contrast_policy(4_500))?;

    require_accepted("approved copy", approved_copy.accepted, &approved_copy)?;
    require_accepted("logo geometry", logo_geometry.accepted, &logo_geometry)?;
    require_accepted("text bounds", text_bounds.accepted, &text_bounds)?;
    require_accepted(
        "rendered contrast",
        rendered_contrast.accepted,
        &rendered_contrast,
    )?;

    let mut mixed_text_bounds = text_bounds.clone();
    mixed_text_bounds.report.rgba_pixel_digest = "0".repeat(64);
    let mixed_pixel_result = verify_final_artifacts(FinalArtifactVerificationRequest {
        expectations: FinalArtifactExpectations {
            approved_copy_artifact_digest: sha256_hex(context.job.approved_copy.text.as_bytes()),
            approved_logo_artifact_digest: sha256_hex(&approved_logo_png),
            editable_svg_digest: sha256_hex(&editable_bytes),
            normalized_png_digest: sha256_hex(&normalized_bytes),
            target_element_id: "headline".to_owned(),
        },
        approved_copy: &approved_copy,
        logo_geometry: &logo_geometry,
        text_bounds: &mixed_text_bounds,
        rendered_contrast: &rendered_contrast,
    });
    assert!(matches!(
        mixed_pixel_result,
        Err(FinalArtifactVerificationError::PixelDecodeBindingMismatch)
    ));

    assert_real_rejections(
        &editable_bytes,
        &decoded_approved_logo,
        &decoded_normalized,
        &text_bounds,
    )?;

    let delivery = certify_inkscape_final_artifacts(InkscapeFinalArtifactCertificationRequest {
        base_delivery: srgb_delivery,
        approved_logo_artifact_id: &context.job.approved_logo.artifact_id,
        approved_copy: &approved_copy,
        logo_geometry: &logo_geometry,
        text_bounds: &text_bounds,
        rendered_contrast: &rendered_contrast,
        base_attestation_keys: &base_attestation_keys,
        compiled_contract: &context.compiled_contract,
        compiled_plan: &context.compiled_plan,
        assurance_level: AssuranceLevel::E3,
        final_manifest_id: "manifest.real-final-artifacts.0001",
        final_certificate_id: "certificate.real-final-artifacts.0001",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW + 2,
        attestation_signing_key: &context.attestation_key,
    })?;

    assert_eq!(
        delivery.evidence_bundle.claimed_decision.status,
        DecisionStatus::Accepted
    );
    assert_eq!(
        delivery.verified_attestation.evidence_bundle_digest,
        delivery.evidence_bundle_digest
    );
    assert_eq!(
        logo_geometry.report.rendered_pixel_report_digest,
        text_bounds.report.pixel_report_digest
    );
    assert_eq!(
        text_bounds.report.pixel_report_digest,
        rendered_contrast.report.pixel_report_digest
    );
    assert_eq!(
        logo_geometry.report.rendered_rgba_pixel_digest,
        text_bounds.report.rgba_pixel_digest
    );
    assert_eq!(
        text_bounds.report.rgba_pixel_digest,
        rendered_contrast.report.rgba_pixel_digest
    );
    assert_eq!(execution_record.binary.executable_digest, executable_digest);

    let bundle_value = serde_json::to_value(&delivery.evidence_bundle)?;
    verify_attestation_against_bundle(
        &delivery.attestation,
        &base_attestation_keys,
        context.compiled_contract.clone(),
        &context.compiled_plan,
        &bundle_value,
        AssuranceLevel::E3,
    )?;
    assert!(
        verify_attestation_against_bundle(
            &delivery.attestation,
            &AttestationKeyRegistry::default(),
            context.compiled_contract.clone(),
            &context.compiled_plan,
            &bundle_value,
            AssuranceLevel::E3,
        )
        .is_err()
    );
    let mut mutated_bundle = bundle_value.clone();
    mutated_bundle["claimed_decision"]["reason"] = json!("mutated after certification");
    assert!(
        verify_attestation_against_bundle(
            &delivery.attestation,
            &base_attestation_keys,
            context.compiled_contract.clone(),
            &context.compiled_plan,
            &mutated_bundle,
            AssuranceLevel::E3,
        )
        .is_err()
    );

    let evidence_dir = evidence_directory(&execution)?;
    persist_evidence(
        &evidence_dir,
        &execution,
        &normalization.output,
        &approved_logo_png,
        &approved_copy,
        &logo_geometry,
        &text_bounds,
        &rendered_contrast,
        &delivery,
        &execution_record.binary.executable_digest,
    )?;

    eprintln!(
        "real final artifact evidence directory: {}",
        evidence_dir.display()
    );
    eprintln!(
        "real final evidence bundle digest: {}",
        delivery.evidence_bundle_digest
    );
    eprintln!(
        "real final artifact binding digest: {}",
        delivery.final_artifact_binding.binding_digest
    );
    eprintln!(
        "real final certification binding digest: {}",
        delivery.certification_binding.binding_digest
    );
    eprintln!(
        "real final acceptance certificate digest: {}",
        delivery.verified_attestation.certificate_digest
    );
    Ok(())
}

fn real_context(approved_logo_png: &[u8]) -> Result<support::Context, Box<dyn Error>> {
    let mut context = context()?;
    context.job.approved_logo.media_type = "image/png".to_owned();
    context.job.approved_logo.content = approved_logo_png.to_vec();
    context.job.approved_logo.source_width = 20;
    context.job.approved_logo.source_height = 10;
    context.job.approved_logo.primary_color = Rgba8::opaque(20, 40, 80);
    context.job.safe_area = GraphicRect {
        x: TEXT_SAFE_AREA.x,
        y: TEXT_SAFE_AREA.y,
        width: TEXT_SAFE_AREA.width,
        height: TEXT_SAFE_AREA.height,
    };
    context.job.text_origin_x = 36;
    context.job.text_origin_y = 150;

    let logo_digest = sha256_hex(approved_logo_png);
    let inputs = context
        .contract_value
        .get_mut("inputs")
        .and_then(Value::as_array_mut)
        .ok_or("contract inputs missing")?;
    let logo = inputs
        .iter_mut()
        .find(|input| input["id"] == "approved_logo")
        .ok_or("approved logo input missing")?;
    logo["uri"] = json!("contract://inputs/approved-logo.png");
    logo["media_type"] = json!("image/png");
    logo["integrity"]["digest"] = json!(logo_digest);

    let capsule: Value = serde_json::from_str(include_str!(
        "../../../professions/graphic-designer/profession.json"
    ))?;
    context.compiled_contract = compile_contract(&context.contract_value, &capsule)?;
    let planning = synthesize_static_social_post_plan(
        &StaticSocialPostPlanIdentity {
            plan_id: Some("plan.real-final-artifact.0001".to_owned()),
            created_at: Some("2026-07-23T12:40:00Z".to_owned()),
        },
        &context.contract_value,
        &capsule,
    )?;
    let TypedPlanOutcome::Planned { plan, .. } = planning else {
        return Err("resolved real final context did not produce an Operator Plan".into());
    };
    context.compiled_plan = compile_plan(&plan, &capsule, &context.compiled_contract)?;
    Ok(context)
}

fn approved_logo_png() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut pixels = Vec::with_capacity(20 * 10 * 4);
    for _ in 0..(20 * 10) {
        pixels.extend_from_slice(&[20, 40, 80, 255]);
    }
    let png = encode_rgba_png(20, 10, &pixels)?;
    strip_color_profile_chunks(&png)
}

fn strip_color_profile_chunks(png: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if png.get(..SIGNATURE.len()) != Some(SIGNATURE.as_slice()) {
        return Err("approved-logo PNG signature is invalid".into());
    }

    let mut output = png[..SIGNATURE.len()].to_vec();
    let mut offset = SIGNATURE.len();
    while offset < png.len() {
        if png.len().saturating_sub(offset) < 12 {
            return Err("approved-logo PNG chunk is truncated".into());
        }
        let length = u32::from_be_bytes(
            png[offset..offset + 4]
                .try_into()
                .map_err(|_| "approved-logo PNG length is truncated")?,
        ) as usize;
        let chunk_end = offset
            .checked_add(12)
            .and_then(|value| value.checked_add(length))
            .ok_or("approved-logo PNG chunk length overflow")?;
        if chunk_end > png.len() {
            return Err("approved-logo PNG chunk exceeds file length".into());
        }
        let chunk_type = &png[offset + 4..offset + 8];
        if chunk_type != b"sRGB" && chunk_type != b"iCCP" {
            output.extend_from_slice(&png[offset..chunk_end]);
        }
        offset = chunk_end;
    }
    Ok(output)
}

fn real_fixture_svg(text: &str) -> String {
    format!(
        r##"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="240" height="300" viewBox="0 0 240 300" id="root">
  <rect id="background" x="0" y="0" width="240" height="300" fill="#ffffff" />
  <rect id="approved-logo" x="24" y="24" width="80" height="40" fill="#142850" />
  <text id="headline" x="36" y="150" font-family="DejaVu Sans" font-size="28" font-weight="700" fill="#000000">{text}</text>
</svg>
"##
    )
}

fn logo_policy() -> LogoGeometryPolicy {
    LogoGeometryPolicy {
        logo_region: LOGO_REGION,
        clear_space_px: 16,
        background_ring_px: 4,
        approved_alpha_threshold: 1,
        approved_minimum_foreground_pixels: 200,
        approved_minimum_foreground_share_milli: 1_000,
        approved_maximum_foreground_share_milli: 1_000,
        foreground_minimum_distance_squared: 1_000,
        minimum_rendered_foreground_pixels: 3_000,
        minimum_mask_iou_milli: 980,
        maximum_aspect_ratio_error_ppm: 10_000,
        background_max_channel_deviation: 4,
        maximum_clear_space_intrusion_pixels: 0,
    }
}

fn text_policy(analysis_region: TextRect, safe_area: TextRect) -> RenderedTextBoundsPolicy {
    RenderedTextBoundsPolicy {
        analysis_region,
        safe_area,
        background_ring_px: 4,
        foreground_minimum_distance_squared: 1_000,
        minimum_foreground_pixels: 40,
        maximum_foreground_share_milli: 500,
        background_max_channel_deviation: 4,
        minimum_safe_area_margin_px: 2,
        clipping_guard_px: 2,
    }
}

fn contrast_policy(minimum_contrast_milli: u32) -> RenderedContrastPolicy {
    RenderedContrastPolicy {
        subject_region: ContrastRect {
            x: TEXT_ANALYSIS.x,
            y: TEXT_ANALYSIS.y,
            width: TEXT_ANALYSIS.width,
            height: TEXT_ANALYSIS.height,
        },
        background_ring_px: 4,
        minimum_contrast_milli,
        background_max_channel_deviation: 4,
        foreground_minimum_distance_squared: 1_000,
        minimum_candidate_pixels: 40,
        maximum_candidate_share_milli: 500,
        quantization_bits: 5,
        minimum_dominant_pixels: 20,
        minimum_dominant_share_milli: 100,
    }
}

fn assert_real_rejections(
    editable_bytes: &[u8],
    approved_logo: &ergaxiom_png_pixel_decoder_runtime::DecodedPng,
    normalized: &ergaxiom_png_pixel_decoder_runtime::DecodedPng,
    accepted_text_bounds: &ergaxiom_png_rendered_text_bounds_runtime::RenderedTextBoundsResult,
) -> Result<(), Box<dyn Error>> {
    let wrong_copy = validate_approved_copy(
        b"ALTERED",
        editable_bytes,
        &ApprovedCopyPolicy {
            target_element_id: "headline".to_owned(),
        },
    )?;
    assert!(!wrong_copy.accepted);

    let mut altered_logo_pixels = approved_logo.rgba8.clone();
    for (index, pixel) in altered_logo_pixels.chunks_exact_mut(4).enumerate() {
        if index % 2 == 0 {
            pixel[3] = 0;
        }
    }
    let altered_logo_png = encode_rgba_png(
        approved_logo.report.width,
        approved_logo.report.height,
        &altered_logo_pixels,
    )?;
    let altered_logo = decode_png_bytes(&altered_logo_png)?;
    let mut altered_logo_policy = logo_policy();
    altered_logo_policy.approved_minimum_foreground_pixels = 1;
    altered_logo_policy.approved_minimum_foreground_share_milli = 400;
    let rejected_logo = validate_logo_geometry(&altered_logo, normalized, &altered_logo_policy)?;
    assert!(!rejected_logo.accepted);

    let observed = accepted_text_bounds
        .report
        .observed_bounds
        .ok_or("accepted text bounds did not include observed bounds")?;
    let tight_analysis = TextRect {
        x: observed.x,
        y: observed.y,
        width: observed.width,
        height: observed.height,
    };
    let clipped =
        validate_rendered_text_bounds(normalized, &text_policy(tight_analysis, tight_analysis))?;
    assert!(!clipped.accepted);

    let low_contrast = validate_rendered_contrast(normalized, &contrast_policy(22_000))?;
    assert!(!low_contrast.accepted);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_evidence(
    directory: &Path,
    execution: &ExecutionFixture,
    normalized_png: &Path,
    approved_logo_png: &[u8],
    approved_copy: &impl Serialize,
    logo_geometry: &impl Serialize,
    text_bounds: &impl Serialize,
    rendered_contrast: &impl Serialize,
    delivery: &ergaxiom_graphic_inkscape_final_certified_delivery_runtime::CertifiedInkscapeFinalGraphicDelivery,
    inkscape_executable_digest: &str,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(directory)?;
    fs::write(directory.join("approved-logo.png"), approved_logo_png)?;
    fs::copy(&execution.source, directory.join("source.svg"))?;
    fs::copy(&execution.editable, directory.join("editable.svg"))?;
    fs::copy(&execution.raster, directory.join("raw.png"))?;
    fs::copy(normalized_png, directory.join("normalized.png"))?;
    write_json(directory.join("approved-copy-result.json"), approved_copy)?;
    write_json(directory.join("logo-geometry-result.json"), logo_geometry)?;
    write_json(directory.join("text-bounds-result.json"), text_bounds)?;
    write_json(
        directory.join("rendered-contrast-result.json"),
        rendered_contrast,
    )?;
    write_json(
        directory.join("final-artifact-binding.json"),
        &delivery.final_artifact_binding,
    )?;
    write_json(
        directory.join("final-certification-binding.json"),
        &delivery.certification_binding,
    )?;
    write_json(
        directory.join("evidence-bundle.json"),
        &delivery.evidence_bundle,
    )?;
    write_json(
        directory.join("acceptance-certificate.json"),
        &delivery.attestation,
    )?;
    write_json(
        directory.join("summary.json"),
        &json!({
            "inkscape_executable_digest": inkscape_executable_digest,
            "approved_copy_report_digest": delivery.final_artifact_binding.approved_copy_report_digest,
            "logo_geometry_report_digest": delivery.final_artifact_binding.logo_geometry_report_digest,
            "text_bounds_report_digest": delivery.final_artifact_binding.text_bounds_report_digest,
            "rendered_contrast_report_digest": delivery.final_artifact_binding.rendered_contrast_report_digest,
            "shared_pixel_report_digest": delivery.final_artifact_binding.shared_pixel_report_digest,
            "shared_rgba_pixel_digest": delivery.final_artifact_binding.shared_rgba_pixel_digest,
            "final_artifact_binding_digest": delivery.final_artifact_binding.binding_digest,
            "final_certification_binding_digest": delivery.certification_binding.binding_digest,
            "evidence_bundle_digest": delivery.evidence_bundle_digest,
            "certificate_digest": delivery.verified_attestation.certificate_digest
        }),
    )?;
    Ok(())
}

fn evidence_directory(execution: &ExecutionFixture) -> Result<PathBuf, Box<dyn Error>> {
    Ok(match env::var_os("ERGAXIOM_FINAL_EVIDENCE_DIR") {
        Some(path) => PathBuf::from(path),
        None => execution._directory.join("final-evidence"),
    })
}

fn write_json(path: PathBuf, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn require_accepted(
    name: &str,
    accepted: bool,
    value: &impl Serialize,
) -> Result<(), Box<dyn Error>> {
    if accepted {
        Ok(())
    } else {
        Err(format!(
            "{name} validator rejected real fixture: {}",
            serde_json::to_string_pretty(value)?
        )
        .into())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
