#![cfg(feature = "real-inkscape-tests")]

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_inkscape_adapter_runtime::{
    AlignmentAxis, AlignmentMode, ApprovedAssetMediaType, ExportMediaType, ProofBoundDesignRequest,
    ProofBoundExportRequest, ProofBoundOperation, TextAnchor, VerifiedInkscape, sha256_file,
};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!(
            "ergaxiom-proof-bound-operator-attacks-{}-{nonce}",
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

fn source_svg() -> &'static str {
    r##"<svg xmlns="http://www.w3.org/2000/svg" width="200" height="120" viewBox="0 0 200 120"><rect id="background" x="0" y="0" width="200" height="120" fill="#ffffff"/><rect id="a" x="20" y="20" width="20" height="20" fill="#111111"/><rect id="b" x="80" y="40" width="20" height="20" fill="#111111"/><rect id="c" x="150" y="70" width="20" height="20" fill="#111111"/></svg>"##
}

fn request(
    request_id: &str,
    source: &Path,
    source_digest: &str,
    output: PathBuf,
    operations: Vec<ProofBoundOperation>,
) -> ProofBoundDesignRequest {
    ProofBoundDesignRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: request_id.to_owned(),
        source_svg: source.to_path_buf(),
        expected_source_digest: source_digest.to_owned(),
        editable_output_svg: output,
        operations,
        exports: Vec::new(),
    }
}

#[test]
fn every_operator_surface_rejects_an_attack_case_without_mutating_source()
-> Result<(), Box<dyn Error>> {
    let executable = match env::var("ERGAXIOM_INKSCAPE") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let executable_digest = env::var("ERGAXIOM_INKSCAPE_SHA256")?;
    let directory = TestDirectory::create()?;
    let source = directory.path.join("source.svg");
    let asset = directory.path.join("approved.svg");
    fs::write(&source, source_svg())?;
    fs::write(
        &asset,
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#2155d9"/></svg>"##,
    )?;
    let source_digest = sha256_file(&source)?;
    let inkscape = VerifiedInkscape::open(executable, &executable_digest)?;

    let cases = vec![
        (
            "resize-zero",
            ProofBoundOperation::ResizeCanvas {
                width_px: 0,
                height_px: 120,
            },
        ),
        (
            "duplicate-layer-id",
            ProofBoundOperation::CreateLayer {
                layer_id: "background".to_owned(),
                label: "Collision".to_owned(),
            },
        ),
        (
            "asset-digest-substitution",
            ProofBoundOperation::PlaceAsset {
                element_id: "asset".to_owned(),
                layer_id: None,
                asset_path: asset,
                expected_asset_digest: "0".repeat(64),
                media_type: ApprovedAssetMediaType::Svg,
                x_milli: 10_000,
                y_milli: 10_000,
                width_milli: 20_000,
                height_milli: 20_000,
            },
        ),
        (
            "invalid-typography",
            ProofBoundOperation::CreateText {
                element_id: "headline".to_owned(),
                layer_id: None,
                text: "APPROVED".to_owned(),
                x_milli: 20_000,
                y_milli: 60_000,
                font_family: "DejaVu Sans".to_owned(),
                font_size_milli: 0,
                font_weight: 700,
                fill: "#102040".to_owned(),
                anchor: TextAnchor::Start,
            },
        ),
        (
            "missing-color-target",
            ProofBoundOperation::SetFill {
                target_id: "not-present".to_owned(),
                fill: "#112233".to_owned(),
            },
        ),
        (
            "zero-transform-scale",
            ProofBoundOperation::Transform {
                target_id: "a".to_owned(),
                translate_x_milli: 0,
                translate_y_milli: 0,
                rotate_degrees_milli: 0,
                scale_x_milli: 0,
                scale_y_milli: 1_000,
            },
        ),
        (
            "single-align-target",
            ProofBoundOperation::Align {
                target_ids: vec!["a".to_owned()],
                axis: AlignmentAxis::Horizontal,
                mode: AlignmentMode::Center,
            },
        ),
        (
            "two-distribute-targets",
            ProofBoundOperation::Distribute {
                target_ids: vec!["a".to_owned(), "b".to_owned()],
                axis: AlignmentAxis::Horizontal,
            },
        ),
    ];

    for (index, (name, operation)) in cases.into_iter().enumerate() {
        let output = directory.path.join(format!("attack-{index}.svg"));
        let result = inkscape.execute_proof_bound_design(&request(
            &format!("request.attack.{index}"),
            &source,
            &source_digest,
            output.clone(),
            vec![operation],
        ));
        assert!(
            result.is_err(),
            "attack case unexpectedly succeeded: {name}"
        );
        assert!(!output.exists(), "partial output survived: {name}");
        assert_eq!(
            sha256_file(&source)?,
            source_digest,
            "source changed: {name}"
        );
    }

    Ok(())
}

#[test]
fn save_and_export_boundaries_fail_closed() -> Result<(), Box<dyn Error>> {
    let executable = match env::var("ERGAXIOM_INKSCAPE") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let executable_digest = env::var("ERGAXIOM_INKSCAPE_SHA256")?;
    let directory = TestDirectory::create()?;
    let source = directory.path.join("source.svg");
    fs::write(&source, source_svg())?;
    let source_digest = sha256_file(&source)?;
    let inkscape = VerifiedInkscape::open(executable, &executable_digest)?;

    let path_collision = request(
        "request.attack.save-collision",
        &source,
        &source_digest,
        source.clone(),
        vec![ProofBoundOperation::SetFill {
            target_id: "background".to_owned(),
            fill: "#f4f7ff".to_owned(),
        }],
    );
    assert!(
        inkscape
            .execute_proof_bound_design(&path_collision)
            .is_err()
    );
    assert_eq!(sha256_file(&source)?, source_digest);

    let output = directory.path.join("editable.svg");
    let mut invalid_export = request(
        "request.attack.invalid-export",
        &source,
        &source_digest,
        output.clone(),
        vec![ProofBoundOperation::SetFill {
            target_id: "background".to_owned(),
            fill: "#f4f7ff".to_owned(),
        }],
    );
    invalid_export.exports.push(ProofBoundExportRequest {
        export_id: "missing-png-dimensions".to_owned(),
        media_type: ExportMediaType::Png,
        output_path: directory.path.join("invalid.png"),
        width_px: None,
        height_px: None,
    });
    assert!(
        inkscape
            .execute_proof_bound_design(&invalid_export)
            .is_err()
    );
    assert!(!output.exists());
    assert_eq!(sha256_file(&source)?, source_digest);
    Ok(())
}
