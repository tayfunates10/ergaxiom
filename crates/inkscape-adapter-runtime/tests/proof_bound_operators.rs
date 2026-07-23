#![cfg(feature = "real-inkscape-tests")]

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ergaxiom_inkscape_adapter_runtime::{
    AlignmentAxis, AlignmentMode, ApprovedAssetMediaType, ExportMediaType, ProofBoundDesignRequest,
    ProofBoundExportRequest, ProofBoundOperation, TextAnchor, VerifiedInkscape, observe_svg,
    read_png_info, sha256_file,
};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!(
            "ergaxiom-real-proof-bound-operators-{}-{nonce}",
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
fn real_inkscape_executes_the_expanded_proof_bound_operator_set() -> Result<(), Box<dyn Error>> {
    let executable = match env::var("ERGAXIOM_INKSCAPE") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let executable_digest = env::var("ERGAXIOM_INKSCAPE_SHA256")?;
    let directory = TestDirectory::create()?;
    let source = directory.path.join("source.svg");
    let vector_asset = directory.path.join("approved-vector.svg");
    let raster_asset = directory.path.join("approved-raster.png");
    let editable = directory.path.join("editable.svg");
    let png = directory.path.join("delivery.png");
    let svg = directory.path.join("delivery.svg");
    let pdf = directory.path.join("delivery.pdf");

    fs::write(
        &source,
        r##"<svg xmlns="http://www.w3.org/2000/svg" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" width="240" height="160" viewBox="0 0 240 160"><rect id="background" x="0" y="0" width="240" height="160" fill="#ffffff"/><rect id="box-a" x="20" y="30" width="24" height="24" fill="#111111"/><rect id="box-b" x="90" y="55" width="24" height="24" fill="#111111"/><rect id="box-c" x="180" y="85" width="24" height="24" fill="#111111"/></svg>"##,
    )?;
    fs::write(
        &vector_asset,
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 20"><rect width="40" height="20" rx="4" fill="#2155d9"/><circle cx="10" cy="10" r="5" fill="#ffffff"/></svg>"##,
    )?;
    let one_pixel_png = BASE64_STANDARD.decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9ZQmcAAAAASUVORK5CYII=",
    )?;
    fs::write(&raster_asset, one_pixel_png)?;

    let source_digest = sha256_file(&source)?;
    let vector_digest = sha256_file(&vector_asset)?;
    let raster_digest = sha256_file(&raster_asset)?;
    let inkscape = VerifiedInkscape::open(executable, &executable_digest)?;
    let record = inkscape.execute_proof_bound_design(&ProofBoundDesignRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.real-proof-bound-operators.0001".to_owned(),
        source_svg: source.clone(),
        expected_source_digest: source_digest.clone(),
        editable_output_svg: editable.clone(),
        operations: vec![
            ProofBoundOperation::ResizeCanvas {
                width_px: 320,
                height_px: 240,
            },
            ProofBoundOperation::CreateLayer {
                layer_id: "approved-assets".to_owned(),
                label: "Approved assets".to_owned(),
            },
            ProofBoundOperation::PlaceAsset {
                element_id: "vector-logo".to_owned(),
                layer_id: Some("approved-assets".to_owned()),
                asset_path: vector_asset,
                expected_asset_digest: vector_digest,
                media_type: ApprovedAssetMediaType::Svg,
                x_milli: 24_000,
                y_milli: 24_000,
                width_milli: 80_000,
                height_milli: 40_000,
            },
            ProofBoundOperation::PlaceAsset {
                element_id: "raster-mark".to_owned(),
                layer_id: Some("approved-assets".to_owned()),
                asset_path: raster_asset,
                expected_asset_digest: raster_digest,
                media_type: ApprovedAssetMediaType::Png,
                x_milli: 260_000,
                y_milli: 24_000,
                width_milli: 24_000,
                height_milli: 24_000,
            },
            ProofBoundOperation::CreateText {
                element_id: "headline".to_owned(),
                layer_id: Some("approved-assets".to_owned()),
                text: "ERGAXIOM VERIFIED".to_owned(),
                x_milli: 160_000,
                y_milli: 118_000,
                font_family: "DejaVu Sans".to_owned(),
                font_size_milli: 22_000,
                font_weight: 700,
                fill: "#102040".to_owned(),
                anchor: TextAnchor::Middle,
            },
            ProofBoundOperation::SetFill {
                target_id: "background".to_owned(),
                fill: "#f4f7ff".to_owned(),
            },
            ProofBoundOperation::Transform {
                target_id: "vector-logo".to_owned(),
                translate_x_milli: 2_000,
                translate_y_milli: 1_000,
                rotate_degrees_milli: 5_000,
                scale_x_milli: 1_000,
                scale_y_milli: 1_000,
            },
            ProofBoundOperation::Align {
                target_ids: vec!["box-a".to_owned(), "box-b".to_owned(), "box-c".to_owned()],
                axis: AlignmentAxis::Vertical,
                mode: AlignmentMode::Center,
            },
            ProofBoundOperation::Distribute {
                target_ids: vec!["box-a".to_owned(), "box-b".to_owned(), "box-c".to_owned()],
                axis: AlignmentAxis::Horizontal,
            },
        ],
        exports: vec![
            ProofBoundExportRequest {
                export_id: "delivery-png".to_owned(),
                media_type: ExportMediaType::Png,
                output_path: png.clone(),
                width_px: Some(640),
                height_px: Some(480),
            },
            ProofBoundExportRequest {
                export_id: "delivery-svg".to_owned(),
                media_type: ExportMediaType::Svg,
                output_path: svg.clone(),
                width_px: None,
                height_px: None,
            },
            ProofBoundExportRequest {
                export_id: "delivery-pdf".to_owned(),
                media_type: ExportMediaType::Pdf,
                output_path: pdf.clone(),
                width_px: None,
                height_px: None,
            },
        ],
    })?;

    assert!(record.verified);
    assert!(record.source_immutable);
    assert_eq!(record.operation_receipts.len(), 9);
    assert_eq!(record.export_receipts.len(), 3);
    assert_eq!(sha256_file(&source)?, source_digest);
    assert_eq!(sha256_file(&editable)?, record.editable_output_digest);
    assert_eq!(
        (read_png_info(&png)?.width, read_png_info(&png)?.height),
        (640, 480)
    );
    assert!(fs::read(&pdf)?.starts_with(b"%PDF-"));
    assert_eq!(sha256_file(&svg)?, record.export_receipts[1].output_digest);

    let snapshot = observe_svg(&editable)?;
    assert_eq!(snapshot.width.as_deref(), Some("320"));
    assert_eq!(snapshot.height.as_deref(), Some("240"));
    assert_eq!(
        snapshot
            .elements
            .get("headline")
            .map(|element| element.direct_text.as_str()),
        Some("ERGAXIOM VERIFIED")
    );
    assert_eq!(
        snapshot
            .elements
            .get("background")
            .and_then(|element| element.attributes.get("fill"))
            .map(String::as_str),
        Some("#f4f7ff")
    );
    assert!(record.record_digest.len() == 64);
    Ok(())
}
