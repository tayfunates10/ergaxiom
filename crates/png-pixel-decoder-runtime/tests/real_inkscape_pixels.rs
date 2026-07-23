#![cfg(feature = "real-inkscape-tests")]

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_inkscape_adapter_runtime::{
    SetTextAndExportRequest, VerifiedInkscape, sha256_file,
};
use ergaxiom_png_pixel_decoder_runtime::decode_png;
use ergaxiom_png_srgb_normalizer_runtime::{
    PngSrgbNormalizationRequest, SrgbRenderingIntent, normalize_png_srgb,
};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!(
            "ergaxiom-real-png-pixels-{}-{nonce}",
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
fn raw_and_srgb_normalized_inkscape_pngs_decode_to_identical_rgba()
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
    let raw_png = directory.path.join("raw.png");
    let normalized_png = directory.path.join("normalized.png");

    let inkscape = VerifiedInkscape::open(executable, &executable_digest)?;
    inkscape.execute_set_text_and_export(&SetTextAndExportRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.real-pixel-decoder.export.0001".to_owned(),
        source_svg: fixture.clone(),
        expected_source_digest: sha256_file(&fixture)?,
        target_element_id: "headline".to_owned(),
        replacement_text: "APPROVED".to_owned(),
        editable_output_svg: editable.clone(),
        raster_output_png: raw_png.clone(),
        export_width: 512,
        export_height: 512,
    })?;
    normalize_png_srgb(&PngSrgbNormalizationRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.real-pixel-decoder.normalize.0001".to_owned(),
        source_svg: editable.clone(),
        expected_source_svg_digest: sha256_file(&editable)?,
        input_png: raw_png.clone(),
        expected_input_png_digest: sha256_file(&raw_png)?,
        output_png: normalized_png.clone(),
        rendering_intent: SrgbRenderingIntent::RelativeColorimetric,
    })?;

    let raw = decode_png(&raw_png)?;
    let normalized = decode_png(&normalized_png)?;
    assert_eq!((raw.report.width, raw.report.height), (512, 512));
    assert_eq!(raw.report.color_type, normalized.report.color_type);
    assert_eq!(raw.report.filter_counts, normalized.report.filter_counts);
    assert_eq!(
        raw.report.non_opaque_pixel_count,
        normalized.report.non_opaque_pixel_count
    );
    assert_eq!(raw.report.idat_payload_digest, normalized.report.idat_payload_digest);
    assert_eq!(raw.report.rgba_pixel_digest, normalized.report.rgba_pixel_digest);
    assert_eq!(raw.rgba8, normalized.rgba8);
    assert_ne!(raw.report.artifact_digest, normalized.report.artifact_digest);
    eprintln!(
        "real Inkscape RGBA digest: {}; filters: {:?}; non-opaque: {}",
        raw.report.rgba_pixel_digest,
        raw.report.filter_counts,
        raw.report.non_opaque_pixel_count
    );
    Ok(())
}
