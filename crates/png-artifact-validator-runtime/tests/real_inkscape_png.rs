#![cfg(feature = "real-inkscape-tests")]

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_inkscape_adapter_runtime::{SetTextAndExportRequest, VerifiedInkscape, sha256_file};
use ergaxiom_png_artifact_validator_runtime::{
    PngColorProfileEvidence, PngColorType, PngPolicyViolation, PngProfileRequirement,
    PngValidationPolicy, inspect_png, validate_report,
};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!(
            "ergaxiom-real-png-validator-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn real_inkscape_png_is_structurally_verified_and_profile_status_is_explicit()
-> Result<(), Box<dyn Error>> {
    let (Ok(executable), Ok(executable_digest)) = (
        env::var("ERGAXIOM_INKSCAPE"),
        env::var("ERGAXIOM_INKSCAPE_SHA256"),
    ) else {
        return Ok(());
    };
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/inkscape/social-post.svg");
    let directory = TestDirectory::create()?;
    let editable = directory.path.join("editable.svg");
    let raster = directory.path.join("delivery.png");
    let inkscape = VerifiedInkscape::open(executable, &executable_digest)?;
    inkscape.execute_set_text_and_export(&SetTextAndExportRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.real-png-validator.0001".to_owned(),
        source_svg: fixture.clone(),
        expected_source_digest: sha256_file(&fixture)?,
        target_element_id: "headline".to_owned(),
        replacement_text: "APPROVED".to_owned(),
        editable_output_svg: editable,
        raster_output_png: raster.clone(),
        export_width: 512,
        export_height: 512,
    })?;

    let report = inspect_png(&raster)?;
    assert_eq!((report.width, report.height), (512, 512));
    assert!(report.idat_chunk_count > 0);
    assert!(report.idat_payload_bytes > 0);
    assert_eq!(report.artifact_digest, sha256_file(&raster)?);

    let structural = validate_report(
        report.clone(),
        &PngValidationPolicy {
            expected_width: 512,
            expected_height: 512,
            expected_bit_depth: Some(8),
            allowed_color_types: vec![PngColorType::Truecolor, PngColorType::TruecolorAlpha],
            profile_requirement: PngProfileRequirement::NotRequired,
        },
    )?;
    assert!(structural.accepted);

    let profiled = validate_report(
        report.clone(),
        &PngValidationPolicy {
            expected_width: 512,
            expected_height: 512,
            expected_bit_depth: Some(8),
            allowed_color_types: vec![PngColorType::Truecolor, PngColorType::TruecolorAlpha],
            profile_requirement: PngProfileRequirement::AnyEmbedded,
        },
    )?;
    match report.color_profile {
        PngColorProfileEvidence::None => {
            assert!(!profiled.accepted);
            assert_eq!(
                profiled.violations,
                vec![PngPolicyViolation::MissingColorProfile]
            );
        }
        PngColorProfileEvidence::Srgb { .. } | PngColorProfileEvidence::Icc { .. } => {
            assert!(profiled.accepted);
            assert!(profiled.violations.is_empty());
        }
    }
    eprintln!(
        "real Inkscape PNG profile evidence: {:?}",
        report.color_profile
    );
    Ok(())
}
