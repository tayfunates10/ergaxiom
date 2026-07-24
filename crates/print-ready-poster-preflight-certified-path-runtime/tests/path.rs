use std::error::Error;

use ed25519_dalek::SigningKey;
use ergaxiom_contract_runtime::compile_contract;
use ergaxiom_operator_plan_runtime::compile_plan;
use ergaxiom_print_ready_poster_preflight_certified_path_runtime::{
    PdfBoxRecord, PdfNormalizationRecord, PrintArtifactIntent, PrintEvidenceKeyRegistry,
    PrintPreflightCompileOutcome, PrintPreflightExecutionRecord, PrintPreflightIntent,
    PrintPreflightPlanIdentity, PrintPreflightPlanOutcome, PrintSpecification,
    compile_print_preflight_intent, inspect_print_pdf, normalize_print_pdf,
    render_restricted_print_svg, sign_print_preflight_execution_record,
    synthesize_print_preflight_plan, validate_print_source, verify_pdf_normalization,
    verify_print_preflight_execution_record,
};
use lopdf::{Document, Object, Stream, dictionary};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn unresolved_intent_returns_questions_without_contract() -> Result<(), Box<dyn Error>> {
    let outcome = compile_print_preflight_intent(&PrintPreflightIntent::default(), &capsule()?)?;
    let PrintPreflightCompileOutcome::NeedsResolution {
        resolution_requests,
        resolution_digest,
        ..
    } = outcome
    else {
        panic!("unresolved preflight intent must not compile");
    };
    assert!(resolution_requests.len() >= 8);
    assert!(
        resolution_requests
            .iter()
            .any(|request| request.field == "resolved_specification")
    );
    assert_eq!(resolution_digest.len(), 64);
    Ok(())
}

#[test]
fn resolved_contract_and_plan_are_deterministic() -> Result<(), Box<dyn Error>> {
    let capsule = capsule()?;
    let spec = specification();
    let source = render_restricted_print_svg(&spec)?;
    let intent = complete_intent(&source, &spec)?;
    let first = compile_print_preflight_intent(&intent, &capsule)?;
    let second = compile_print_preflight_intent(&intent, &capsule)?;
    assert_eq!(first, second);
    let PrintPreflightCompileOutcome::Compiled {
        contract,
        proof_obligation_count,
        unresolved_mandatory_unknowns,
        ..
    } = first
    else {
        panic!("resolved preflight intent must compile");
    };
    assert_eq!(contract["profession"]["capsule_version"], "0.6.0");
    assert_eq!(proof_obligation_count, 18);
    assert_eq!(unresolved_mandatory_unknowns, 0);
    let compiled_contract = compile_contract(&contract, &capsule)?;
    let identity = PrintPreflightPlanIdentity {
        plan_id: Some("plan.print-preflight.0001".to_owned()),
        created_at: Some("2026-07-24T13:01:00Z".to_owned()),
    };
    let planned = synthesize_print_preflight_plan(&identity, &contract, &capsule)?;
    let PrintPreflightPlanOutcome::Planned {
        plan,
        mandatory_step_count,
        capability_requirements,
        ..
    } = planned
    else {
        panic!("resolved plan identity must plan");
    };
    assert_eq!(mandatory_step_count, 3);
    assert_eq!(capability_requirements.len(), 3);
    assert_eq!(plan["steps"][0]["operator_id"], "print.validate_source");
    assert_eq!(
        plan["steps"][1]["operator_id"],
        "print.export_pdf_with_inkscape"
    );
    assert_eq!(plan["steps"][2]["operator_id"], "print.certify_preflight");
    let compiled_plan = compile_plan(&plan, &capsule, &compiled_contract)?;
    assert_eq!(compiled_plan.mandatory_step_count(), 3);
    Ok(())
}

#[test]
fn restricted_source_is_accepted_and_attacks_fail_closed() -> Result<(), Box<dyn Error>> {
    let spec = specification();
    let accepted = render_restricted_print_svg(&spec)?;
    assert!(validate_print_source(&accepted, &spec)?.accepted);

    let live_text = String::from_utf8(accepted.clone())?.replace(
        "</svg>",
        "<text id=\"live\" x=\"20\" y=\"20\" fill=\"#ffffff\">NO</text></svg>",
    );
    let report = validate_print_source(live_text.as_bytes(), &spec)?;
    assert!(!report.accepted);
    assert_eq!(report.live_text_count, 1);

    let raster = String::from_utf8(accepted.clone())?.replace(
        "</svg>",
        "<image id=\"raster\" href=\"data:image/png;base64,AA==\" x=\"20\" y=\"20\" width=\"10\" height=\"10\"/></svg>",
    );
    let report = validate_print_source(raster.as_bytes(), &spec)?;
    assert!(!report.accepted);
    assert_eq!(report.raster_image_count, 1);

    let bad_color = String::from_utf8(accepted.clone())?.replace("#ffffff", "#00ff00");
    let report = validate_print_source(bad_color.as_bytes(), &spec)?;
    assert!(!report.accepted);
    assert!(report.palette_violation_count > 0);

    let unsafe_path = String::from_utf8(accepted)?.replace(
        "M 8 8",
        "M 1 1",
    );
    let report = validate_print_source(unsafe_path.as_bytes(), &spec)?;
    assert!(!report.accepted);
    assert!(!report.safe_area_satisfied);
    Ok(())
}

#[test]
fn pdf_boxes_and_structural_profile_are_recomputed() -> Result<(), Box<dyn Error>> {
    let spec = specification();
    let raw = minimal_vector_pdf()?;
    let (normalized, record) = normalize_print_pdf(&raw, &spec)?;
    verify_pdf_normalization(&raw, &normalized, &record, &spec)?;
    let inspection = inspect_print_pdf(&normalized, &spec)?;
    assert_eq!(inspection.page_count, 1);
    assert_eq!(inspection.pdf_version, "1.5");
    assert!(inspection.vector_only);
    assert!(inspection.fonts_outlined);
    assert!(inspection.allowed_color_spaces_only);
    assert!(inspection.transparency_absent);
    assert!(inspection.external_actions_absent);

    let mut tampered = record.clone();
    tampered.trim_box.right_milli_pt += 1000;
    assert!(verify_pdf_normalization(&raw, &normalized, &tampered, &spec).is_err());
    Ok(())
}

#[test]
fn signed_execution_record_rejects_tampering_and_unknown_keys() -> Result<(), Box<dyn Error>> {
    let raw = minimal_vector_pdf()?;
    let spec = specification();
    let (normalized, normalization_record) = normalize_print_pdf(&raw, &spec)?;
    let mut record = execution_record(&raw, &normalized, normalization_record);
    record.record_digest = record_digest(&record)?;
    let signing_key = SigningKey::from_bytes(&[61_u8; 32]);
    let package = sign_print_preflight_execution_record(
        &record,
        "ergaxiom.print-executor",
        "print-ed25519-01",
        &signing_key,
    )?;
    let mut keys = PrintEvidenceKeyRegistry::default();
    keys.insert_ed25519(
        "ergaxiom.print-executor",
        "print-ed25519-01",
        signing_key.verifying_key().to_bytes(),
    )?;
    verify_print_preflight_execution_record(&package, &keys)?;

    let mut tampered = package.clone();
    tampered.record.normalized_pdf_digest = "0".repeat(64);
    assert!(verify_print_preflight_execution_record(&tampered, &keys).is_err());
    assert!(
        verify_print_preflight_execution_record(
            &package,
            &PrintEvidenceKeyRegistry::default()
        )
        .is_err()
    );
    Ok(())
}

fn specification() -> PrintSpecification {
    PrintSpecification {
        schema_version: "0.1.0".to_owned(),
        manifest_id: "print-spec.a4-poster.0001".to_owned(),
        trim_width_milli_mm: 210_000,
        trim_height_milli_mm: 297_000,
        bleed_milli_mm: 3_000,
        safe_margin_milli_mm: 5_000,
        background_element_id: "bleed-background".to_owned(),
        allowed_palette: vec!["#101820".to_owned(), "#ffffff".to_owned()],
        allowed_pdf_color_spaces: vec!["DeviceRGB".to_owned(), "DeviceGray".to_owned()],
        required_pdf_version: "1.5".to_owned(),
    }
}

fn complete_intent(
    source: &[u8],
    spec: &PrintSpecification,
) -> Result<PrintPreflightIntent, Box<dyn Error>> {
    let spec_value = serde_json::to_value(spec)?;
    Ok(PrintPreflightIntent {
        contract_id: Some("contract.print-preflight.0001".to_owned()),
        created_at: Some("2026-07-24T13:00:00Z".to_owned()),
        original_text: Some("Preflight this outlined vector poster for the supplied printer specification.".to_owned()),
        language: Some("en".to_owned()),
        requester_id: Some("fixture.print-preflight".to_owned()),
        source_svg: PrintArtifactIntent {
            uri: Some("contract://inputs/poster.svg".to_owned()),
            media_type: Some("image/svg+xml".to_owned()),
            sha256: Some(sha256(source)),
        },
        print_specification: PrintArtifactIntent {
            uri: Some("contract://inputs/print-specification.json".to_owned()),
            media_type: Some("application/json".to_owned()),
            sha256: Some(ergaxiom_proof_kernel::canonical_json_sha256(&spec_value)?),
        },
        resolved_specification: Some(spec.clone()),
        required_application_version: Some("Inkscape 1.2".to_owned()),
        visual_preference: Some("Human reviewer may assess visual balance outside hard acceptance.".to_owned()),
        require_pre_execution_approval: true,
    })
}

fn minimal_vector_pdf() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut document = Document::with_version("1.5");
    let pages_id = document.new_object_id();
    let page_id = document.new_object_id();
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        b"0.1 0.2 0.3 rg 0 0 100 100 re f".to_vec(),
    ));
    let resources_id = document.add_object(dictionary! {});
    document.objects.insert(
        page_id,
        Object::Dictionary(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        }),
    );
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn execution_record(
    raw: &[u8],
    normalized: &[u8],
    normalization_record: PdfNormalizationRecord,
) -> PrintPreflightExecutionRecord {
    PrintPreflightExecutionRecord {
        schema_version: "0.1.0".to_owned(),
        request_id: "print.fixture.0001".to_owned(),
        operator_id: "print.export_pdf_with_inkscape".to_owned(),
        operator_version: "0.1.0".to_owned(),
        source_svg_digest: "1".repeat(64),
        specification_digest: "2".repeat(64),
        source_validation_report_digest: "3".repeat(64),
        editable_svg_digest: "4".repeat(64),
        raw_pdf_digest: sha256(raw),
        normalized_pdf_digest: sha256(normalized),
        normalization_record,
        application_id: "org.inkscape.Inkscape".to_owned(),
        application_version: "Inkscape 1.2".to_owned(),
        executable_digest: "5".repeat(64),
        adapter_record_digest: "6".repeat(64),
        source_immutable: true,
        verified: true,
        record_digest: String::new(),
    }
}

fn record_digest(record: &PrintPreflightExecutionRecord) -> Result<String, Box<dyn Error>> {
    let mut value = serde_json::to_value(record)?;
    value["record_digest"] = Value::String(String::new());
    Ok(ergaxiom_proof_kernel::canonical_json_sha256(&value)?)
}

fn capsule() -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(
        "../../../professions/graphic-designer/profession.json"
    ))?)
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[allow(dead_code)]
fn _box_type_check(_: PdfBoxRecord) {}
