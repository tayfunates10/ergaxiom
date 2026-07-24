use std::error::Error;

use ergaxiom_background_cleanup_certified_path_runtime::encode_restricted_srgb_rgba_png;
use ergaxiom_brand_compliant_export_certified_path_runtime::{
    BrandArtifactIntent, BrandBackgroundRule, BrandExportCompileOutcome,
    BrandExportExecutionRecord, BrandExportIntent, BrandExportPlanIdentity, BrandExportPlanOutcome,
    BrandLogoRule, BrandRuleManifest, BrandTypographyRule, brand_export_failure_map,
    compile_brand_export_intent, normalize_brand_png_srgb, render_restricted_brand_svg,
    synthesize_brand_export_plan, validate_brand_export, validate_brand_source,
};
use ergaxiom_contract_runtime::compile_contract;
use ergaxiom_operator_plan_runtime::compile_plan;
use ergaxiom_proof_kernel::canonical_json_sha256;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn resolved_brand_intent_compiles_and_plans_deterministically() -> Result<(), Box<dyn Error>> {
    let logo = logo_png()?;
    let manifest = manifest(&logo);
    let source = render_restricted_brand_svg(&manifest, &logo)?;
    let capsule = capsule()?;
    let intent = resolved_intent(&source, &logo, &manifest)?;
    let first = compile_brand_export_intent(&intent, &capsule)?;
    let second = compile_brand_export_intent(&intent, &capsule)?;
    assert_eq!(first, second);
    let BrandExportCompileOutcome::Compiled {
        contract,
        proof_obligation_count,
        ..
    } = first
    else {
        panic!("resolved intent must compile");
    };
    assert_eq!(proof_obligation_count, 13);
    let compiled_contract = compile_contract(&contract, &capsule)?;
    let identity = BrandExportPlanIdentity {
        plan_id: Some("plan.brand-export.0001".to_owned()),
        created_at: Some("2026-07-24T11:01:00Z".to_owned()),
    };
    let plan_first = synthesize_brand_export_plan(&identity, &contract, &capsule)?;
    let plan_second = synthesize_brand_export_plan(&identity, &contract, &capsule)?;
    assert_eq!(plan_first, plan_second);
    let BrandExportPlanOutcome::Planned {
        plan,
        mandatory_step_count,
        capability_requirements,
        ..
    } = plan_first
    else {
        panic!("resolved identity must plan");
    };
    assert_eq!(mandatory_step_count, 3);
    assert_eq!(capability_requirements.len(), 3);
    let compiled_plan = compile_plan(&plan, &capsule, &compiled_contract)?;
    assert_eq!(compiled_plan.steps.len(), 3);
    Ok(())
}

#[test]
fn missing_brand_requirements_block_compilation() -> Result<(), Box<dyn Error>> {
    let capsule = capsule()?;
    let outcome = compile_brand_export_intent(&BrandExportIntent::default(), &capsule)?;
    let BrandExportCompileOutcome::NeedsResolution {
        resolution_requests,
        ..
    } = outcome
    else {
        panic!("unresolved intent must not compile");
    };
    assert!(resolution_requests.len() >= 10);
    Ok(())
}

#[test]
fn restricted_brand_source_and_delivery_are_independently_accepted() -> Result<(), Box<dyn Error>> {
    let logo = logo_png()?;
    let manifest = manifest(&logo);
    let source = render_restricted_brand_svg(&manifest, &logo)?;
    let source_report = validate_brand_source(&source, &logo, &manifest)?;
    assert!(source_report.accepted);
    let encoded = delivery_png(manifest.canvas_width_px, manifest.canvas_height_px)?;
    let raw_export = strip_srgb_chunk(&encoded)?;
    let normalization = normalize_brand_png_srgb(&raw_export)?;
    let delivery = normalization.png;
    let editable = source.clone();
    let record = execution_record(
        &source,
        &logo,
        &manifest,
        &editable,
        &raw_export,
        &delivery,
        normalization.record.clone(),
        &source_report,
    )?;
    let report = validate_brand_export(
        &source,
        &logo,
        &manifest,
        &editable,
        &raw_export,
        &delivery,
        &record,
    )?;
    assert!(report.accepted);
    assert!(brand_export_failure_map(&report).is_empty());
    Ok(())
}

#[test]
fn unapproved_palette_and_copy_fail_closed() -> Result<(), Box<dyn Error>> {
    let logo = logo_png()?;
    let manifest = manifest(&logo);
    let source = render_restricted_brand_svg(&manifest, &logo)?;
    let source_text = String::from_utf8(source)?;
    let bad_palette = source_text
        .replacen(&manifest.background.color, "#ff00ff", 1)
        .into_bytes();
    let palette_report = validate_brand_source(&bad_palette, &logo, &manifest)?;
    assert!(!palette_report.accepted);
    assert_eq!(palette_report.palette_violation_count, 1);

    let bad_copy = String::from_utf8(render_restricted_brand_svg(&manifest, &logo)?)?
        .replace(
            &manifest.typography.approved_copy,
            "Unapproved replacement copy",
        )
        .into_bytes();
    let copy_report = validate_brand_source(&bad_copy, &logo, &manifest)?;
    assert!(!copy_report.accepted);
    assert!(!copy_report.approved_copy_matches);
    Ok(())
}

#[test]
fn tampered_delivery_is_rejected_by_record_binding() -> Result<(), Box<dyn Error>> {
    let logo = logo_png()?;
    let manifest = manifest(&logo);
    let source = render_restricted_brand_svg(&manifest, &logo)?;
    let source_report = validate_brand_source(&source, &logo, &manifest)?;
    let encoded = delivery_png(manifest.canvas_width_px, manifest.canvas_height_px)?;
    let raw_export = strip_srgb_chunk(&encoded)?;
    let normalization = normalize_brand_png_srgb(&raw_export)?;
    let delivery = normalization.png;
    let editable = source.clone();
    let record = execution_record(
        &source,
        &logo,
        &manifest,
        &editable,
        &raw_export,
        &delivery,
        normalization.record.clone(),
        &source_report,
    )?;
    let mut tampered = delivery.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        validate_brand_export(
            &source,
            &logo,
            &manifest,
            &editable,
            &raw_export,
            &tampered,
            &record,
        )
        .is_err()
    );
    Ok(())
}

fn resolved_intent(
    source: &[u8],
    logo: &[u8],
    manifest: &BrandRuleManifest,
) -> Result<BrandExportIntent, Box<dyn Error>> {
    let manifest_digest = canonical_json_sha256(&serde_json::to_value(manifest)?)?;
    Ok(BrandExportIntent {
        contract_id: Some("contract.brand-export.0001".to_owned()),
        created_at: Some("2026-07-24T11:00:00Z".to_owned()),
        original_text: Some(
            "Export the approved design only when every declared brand rule is proven.".to_owned(),
        ),
        language: Some("en".to_owned()),
        requester_id: Some("fixture-user".to_owned()),
        source_svg: artifact("source.svg", "image/svg+xml", source),
        brand_manifest: BrandArtifactIntent {
            uri: Some("contract://inputs/brand-manifest.json".to_owned()),
            media_type: Some("application/json".to_owned()),
            sha256: Some(manifest_digest),
        },
        approved_logo: artifact("approved-logo.png", "image/png", logo),
        resolved_manifest: Some(manifest.clone()),
        required_application_version: Some("1.2.2".to_owned()),
        visual_preference: Some(
            "Prefer balanced composition, reviewed separately from technical brand acceptance."
                .to_owned(),
        ),
        require_pre_execution_approval: true,
    })
}

fn execution_record(
    source: &[u8],
    logo: &[u8],
    manifest: &BrandRuleManifest,
    editable: &[u8],
    raw_export: &[u8],
    delivery: &[u8],
    normalization_record: ergaxiom_brand_compliant_export_certified_path_runtime::BrandPngNormalizationRecord,
    source_report: &ergaxiom_brand_compliant_export_certified_path_runtime::BrandSourceValidationReport,
) -> Result<BrandExportExecutionRecord, Box<dyn Error>> {
    let mut record = BrandExportExecutionRecord {
        schema_version: "0.1.0".to_owned(),
        request_id: "brand.fixture.0001".to_owned(),
        operator_id: "brand.export_with_inkscape".to_owned(),
        operator_version: "0.1.0".to_owned(),
        source_svg_digest: sha256(source),
        manifest_digest: canonical_json_sha256(&serde_json::to_value(manifest)?)?,
        approved_logo_digest: sha256(logo),
        source_validation_report_digest: source_report.report_digest.clone(),
        editable_svg_digest: sha256(editable),
        raw_export_png_digest: sha256(raw_export),
        normalization_record,
        delivery_png_digest: sha256(delivery),
        width: manifest.canvas_width_px,
        height: manifest.canvas_height_px,
        application_id: "org.inkscape.Inkscape".to_owned(),
        application_version: "Inkscape 1.2.2".to_owned(),
        executable_digest: "a".repeat(64),
        adapter_record_digest: "b".repeat(64),
        source_immutable: true,
        verified: true,
        record_digest: String::new(),
    };
    let mut value = serde_json::to_value(&record)?;
    value["record_digest"] = json!("");
    record.record_digest = canonical_json_sha256(&value)?;
    Ok(record)
}

fn manifest(logo: &[u8]) -> BrandRuleManifest {
    BrandRuleManifest {
        schema_version: "0.1.0".to_owned(),
        manifest_id: "brand.fixture.0001".to_owned(),
        canvas_width_px: 100,
        canvas_height_px: 100,
        allowed_palette: vec!["#112233".to_owned(), "#ffffff".to_owned()],
        background: BrandBackgroundRule {
            element_id: "brand-background".to_owned(),
            color: "#112233".to_owned(),
        },
        logo: BrandLogoRule {
            element_id: "brand-logo".to_owned(),
            approved_sha256: sha256(logo),
            x_px: 10,
            y_px: 10,
            width_px: 20,
            height_px: 20,
            minimum_clear_space_px: 10,
        },
        typography: BrandTypographyRule {
            element_id: "brand-headline".to_owned(),
            approved_copy: "Approved Brand Export".to_owned(),
            x_px: 50,
            y_px: 70,
            font_family: "DejaVu Sans".to_owned(),
            font_size_px: 12,
            font_weight: 700,
            color: "#ffffff".to_owned(),
            text_anchor: "middle".to_owned(),
        },
    }
}

fn logo_png() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut pixels = Vec::new();
    for index in 0_u8..16 {
        pixels.extend_from_slice(&[
            index.saturating_mul(10),
            255_u8.saturating_sub(index.saturating_mul(7)),
            120,
            255,
        ]);
    }
    Ok(encode_restricted_srgb_rgba_png(4, 4, &pixels)?)
}

fn delivery_png(width: u32, height: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let pixel_count = usize::try_from(width)?
        .checked_mul(usize::try_from(height)?)
        .ok_or("pixel count overflow")?;
    let mut pixels = Vec::with_capacity(pixel_count * 4);
    for _ in 0..pixel_count {
        pixels.extend_from_slice(&[17, 34, 51, 255]);
    }
    Ok(encode_restricted_srgb_rgba_png(width, height, &pixels)?)
}

fn artifact(name: &str, media_type: &str, bytes: &[u8]) -> BrandArtifactIntent {
    BrandArtifactIntent {
        uri: Some(format!("contract://inputs/{name}")),
        media_type: Some(media_type.to_owned()),
        sha256: Some(sha256(bytes)),
    }
}

fn strip_srgb_chunk(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if bytes.len() < 8 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" {
        return Err("invalid PNG fixture".into());
    }
    let mut output = bytes[..8].to_vec();
    let mut offset = 8_usize;
    let mut removed = false;
    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err("truncated PNG fixture".into());
        }
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?) as usize;
        let end = offset + 12 + length;
        if end > bytes.len() {
            return Err("truncated PNG chunk fixture".into());
        }
        if &bytes[offset + 4..offset + 8] == b"sRGB" {
            removed = true;
        } else {
            output.extend_from_slice(&bytes[offset..end]);
        }
        offset = end;
    }
    if !removed {
        return Err("fixture did not contain sRGB".into());
    }
    Ok(output)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn capsule() -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(
        "../../../professions/graphic-designer/profession.json"
    ))?)
}
