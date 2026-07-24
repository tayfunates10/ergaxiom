use std::error::Error;

use ed25519_dalek::SigningKey;
use ergaxiom_background_cleanup_certified_path_runtime::{
    BackgroundCleanupExecutionRequest, CleanupEvidenceKeyRegistry,
    CleanupEvidenceSignatureError, InkscapeCleanupIntegrationReport,
    encode_restricted_srgb_rgba_png, execute_background_cleanup,
    sign_background_cleanup_execution_record, sign_inkscape_cleanup_integration_report,
    verify_background_cleanup_execution_record, verify_inkscape_cleanup_integration_report,
};
use ergaxiom_proof_kernel::canonical_json_sha256;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn tampered_signed_cleanup_execution_record_fails_closed() -> Result<(), Box<dyn Error>> {
    let (source, mask) = accepted_png_fixture()?;
    let execution = execute_background_cleanup(BackgroundCleanupExecutionRequest {
        request_id: "cleanup.signed-evidence.0001",
        source_png: &source,
        approved_mask_png: &mask,
        expected_source_digest: &sha256(&source),
        expected_mask_digest: &sha256(&mask),
        expected_width: 4,
        expected_height: 3,
    })?;
    let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
    let mut trusted_keys = CleanupEvidenceKeyRegistry::default();
    trusted_keys.insert_ed25519(
        "ergaxiom.cleanup-executor",
        "cleanup-execution-ed25519-attack-test",
        signing_key.verifying_key().to_bytes(),
    )?;
    let package = sign_background_cleanup_execution_record(
        &execution.record,
        "ergaxiom.cleanup-executor",
        "cleanup-execution-ed25519-attack-test",
        &signing_key,
    )?;
    let verified = verify_background_cleanup_execution_record(&package, &trusted_keys)?;
    assert_eq!(verified.record_digest, execution.record.record_digest);

    let mut tampered = package;
    tampered.record.output_digest = "f".repeat(64);
    assert!(matches!(
        verify_background_cleanup_execution_record(&tampered, &trusted_keys),
        Err(CleanupEvidenceSignatureError::ExecutionRecordDigestMismatch)
            | Err(CleanupEvidenceSignatureError::SignatureVerificationFailed)
    ));
    Ok(())
}

#[test]
fn tampered_signed_inkscape_integration_report_fails_closed() -> Result<(), Box<dyn Error>> {
    let signing_key = SigningKey::from_bytes(&[43_u8; 32]);
    let mut report = InkscapeCleanupIntegrationReport {
        schema_version: "0.1.0".to_owned(),
        application_id: "org.inkscape.Inkscape".to_owned(),
        application_version: "Inkscape 1.2.2".to_owned(),
        executable_digest: "a".repeat(64),
        cleaned_png_digest: "b".repeat(64),
        probe_png_digest: "c".repeat(64),
        probe_size_bytes: 128,
        probe_width: 4,
        probe_height: 3,
        adapter_record_digest: "d".repeat(64),
        verified: true,
        report_digest: String::new(),
    };
    report.report_digest = record_digest(&report)?;

    let mut trusted_keys = CleanupEvidenceKeyRegistry::default();
    trusted_keys.insert_ed25519(
        "ergaxiom.inkscape-executor",
        "inkscape-integration-ed25519-attack-test",
        signing_key.verifying_key().to_bytes(),
    )?;
    let package = sign_inkscape_cleanup_integration_report(
        &report,
        "ergaxiom.inkscape-executor",
        "inkscape-integration-ed25519-attack-test",
        &signing_key,
    )?;
    let verified = verify_inkscape_cleanup_integration_report(&package, &trusted_keys)?;
    assert_eq!(verified.report_digest, report.report_digest);

    let mut tampered = package;
    tampered.report.probe_width = 5;
    assert!(matches!(
        verify_inkscape_cleanup_integration_report(&tampered, &trusted_keys),
        Err(CleanupEvidenceSignatureError::IntegrationReportDigestMismatch)
            | Err(CleanupEvidenceSignatureError::SignatureVerificationFailed)
    ));
    Ok(())
}

#[test]
fn signed_cleanup_evidence_requires_a_registered_execution_key() -> Result<(), Box<dyn Error>> {
    let (source, mask) = accepted_png_fixture()?;
    let execution = execute_background_cleanup(BackgroundCleanupExecutionRequest {
        request_id: "cleanup.unknown-key.0001",
        source_png: &source,
        approved_mask_png: &mask,
        expected_source_digest: &sha256(&source),
        expected_mask_digest: &sha256(&mask),
        expected_width: 4,
        expected_height: 3,
    })?;
    let signing_key = SigningKey::from_bytes(&[47_u8; 32]);
    let package = sign_background_cleanup_execution_record(
        &execution.record,
        "ergaxiom.cleanup-executor",
        "unregistered-cleanup-key",
        &signing_key,
    )?;
    assert!(matches!(
        verify_background_cleanup_execution_record(
            &package,
            &CleanupEvidenceKeyRegistry::default()
        ),
        Err(CleanupEvidenceSignatureError::UnknownTrustedKey { .. })
    ));
    Ok(())
}

fn record_digest<T: serde::Serialize>(value: &T) -> Result<String, Box<dyn Error>> {
    let mut value = serde_json::to_value(value)?;
    let object = value.as_object_mut().ok_or("record must be an object")?;
    object.insert("report_digest".to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

fn accepted_png_fixture() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let mut source = Vec::new();
    let mut mask = Vec::new();
    for index in 0_u8..12 {
        source.extend_from_slice(&[
            index.saturating_mul(13),
            255_u8.saturating_sub(index.saturating_mul(7)),
            index.saturating_mul(5),
            255,
        ]);
        mask.extend_from_slice(&[
            255,
            255,
            255,
            if index % 2 == 0 { 255 } else { 0 },
        ]);
    }
    Ok((
        encode_restricted_srgb_rgba_png(4, 3, &source)?,
        encode_restricted_srgb_rgba_png(4, 3, &mask)?,
    ))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
