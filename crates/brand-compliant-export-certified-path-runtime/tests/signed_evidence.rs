use std::error::Error;

use ed25519_dalek::SigningKey;
use ergaxiom_brand_compliant_export_certified_path_runtime::{
    BrandEvidenceKeyRegistry, BrandExportExecutionRecord, BrandPngNormalizationRecord,
    SignedBrandExportExecutionRecord, sign_brand_export_execution_record,
    verify_brand_export_execution_record,
};
use ergaxiom_proof_kernel::canonical_json_sha256;
use serde_json::json;

#[test]
fn signed_brand_execution_round_trips_and_tampering_fails() -> Result<(), Box<dyn Error>> {
    let record = execution_record()?;
    let key = SigningKey::from_bytes(&[41_u8; 32]);
    let package = sign_brand_export_execution_record(
        &record,
        "ergaxiom.brand-export-executor",
        "brand-export-ed25519-01",
        &key,
    )?;
    let mut registry = BrandEvidenceKeyRegistry::default();
    registry.insert_ed25519(
        "ergaxiom.brand-export-executor",
        "brand-export-ed25519-01",
        key.verifying_key().to_bytes(),
    )?;
    let verified = verify_brand_export_execution_record(&package, &registry)?;
    assert_eq!(verified.record_digest, record.record_digest);

    let mut tampered = package.clone();
    tampered.record.delivery_png_digest = "c".repeat(64);
    assert!(verify_brand_export_execution_record(&tampered, &registry).is_err());

    let unknown_registry = BrandEvidenceKeyRegistry::default();
    assert!(verify_brand_export_execution_record(&package, &unknown_registry).is_err());
    Ok(())
}

fn execution_record() -> Result<BrandExportExecutionRecord, Box<dyn Error>> {
    let mut record = BrandExportExecutionRecord {
        schema_version: "0.1.0".to_owned(),
        request_id: "brand.signed-fixture.0001".to_owned(),
        operator_id: "brand.export_with_inkscape".to_owned(),
        operator_version: "0.1.0".to_owned(),
        source_svg_digest: "1".repeat(64),
        manifest_digest: "2".repeat(64),
        approved_logo_digest: "3".repeat(64),
        source_validation_report_digest: "4".repeat(64),
        editable_svg_digest: "5".repeat(64),
        raw_export_png_digest: "6".repeat(64),
        normalization_record: normalization_record()?,
        delivery_png_digest: "9".repeat(64),
        width: 100,
        height: 100,
        application_id: "org.inkscape.Inkscape".to_owned(),
        application_version: "Inkscape 1.2.2".to_owned(),
        executable_digest: "7".repeat(64),
        adapter_record_digest: "8".repeat(64),
        source_immutable: true,
        verified: true,
        record_digest: String::new(),
    };
    let mut value = serde_json::to_value(&record)?;
    value["record_digest"] = json!("");
    record.record_digest = canonical_json_sha256(&value)?;
    Ok(record)
}

fn normalization_record() -> Result<BrandPngNormalizationRecord, Box<dyn Error>> {
    let mut record = BrandPngNormalizationRecord {
        schema_version: "0.1.0".to_owned(),
        input_png_digest: "6".repeat(64),
        output_png_digest: "9".repeat(64),
        input_report_digest: "a".repeat(64),
        output_report_digest: "b".repeat(64),
        input_idat_payload_digest: "c".repeat(64),
        output_idat_payload_digest: "c".repeat(64),
        inserted_srgb_crc32: "aece1ce9".to_owned(),
        rendering_intent: 0,
        width: 100,
        height: 100,
        bit_depth: 8,
        verified: true,
        record_digest: String::new(),
    };
    let mut value = serde_json::to_value(&record)?;
    value["record_digest"] = json!("");
    record.record_digest = canonical_json_sha256(&value)?;
    Ok(record)
}

#[allow(dead_code)]
fn _type_assertion(_value: SignedBrandExportExecutionRecord) {}
