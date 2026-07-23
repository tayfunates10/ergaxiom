#![cfg(feature = "real-inkscape-tests")]

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_inkscape_adapter_runtime::{SetTextAndExportRequest, VerifiedInkscape, sha256_file};
use ergaxiom_png_pixel_decoder_runtime::decode_png;
use ergaxiom_png_rendered_contrast_runtime::{
    PixelRect, RenderedContrastPolicy, validate_rendered_contrast,
};
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
            "ergaxiom-real-rendered-contrast-{}-{nonce}",
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
fn real_inkscape_headline_has_independently_measured_rendered_contrast()
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
        request_id: "request.real-rendered-contrast.export.0001".to_owned(),
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
        request_id: "request.real-rendered-contrast.normalize.0001".to_owned(),
        source_svg: editable.clone(),
        expected_source_svg_digest: sha256_file(&editable)?,
        input_png: raw_png.clone(),
        expected_input_png_digest: sha256_file(&raw_png)?,
        output_png: normalized_png.clone(),
        rendering_intent: SrgbRenderingIntent::RelativeColorimetric,
    })?;

    let decoded = decode_png(&normalized_png)?;
    let result = validate_rendered_contrast(
        &decoded,
        &RenderedContrastPolicy {
            subject_region: PixelRect {
                x: 100,
                y: 205,
                width: 312,
                height: 80,
            },
            background_ring_px: 10,
            minimum_contrast_milli: 4500,
            background_max_channel_deviation: 4,
            foreground_minimum_distance_squared: 4096,
            minimum_candidate_pixels: 500,
            maximum_candidate_share_milli: 600,
            quantization_bits: 5,
            minimum_dominant_pixels: 300,
            minimum_dominant_share_milli: 300,
        },
    )?;

    eprintln!(
        "real rendered contrast report: {}; violations: {:?}",
        serde_json::to_string(&result.report)?,
        result.violations
    );
    assert!(result.accepted, "violations: {:?}", result.violations);
    assert_eq!(result.report.background_rgb, [249, 250, 251]);
    assert_eq!(result.report.foreground_rgb, [17, 24, 39]);
    assert!(result.report.minimum_dominant_contrast_milli >= 4500);
    assert_eq!(result.report.non_opaque_subject_pixel_count, 0);
    assert_eq!(result.report.non_opaque_background_pixel_count, 0);
    eprintln!(
        "real rendered contrast: {} milli; foreground {:?}; background {:?}; candidates {}; dominant {}; decision {}",
        result.report.minimum_dominant_contrast_milli,
        result.report.foreground_rgb,
        result.report.background_rgb,
        result.report.candidate_pixel_count,
        result.report.dominant_pixel_count,
        result.decision_digest
    );
    Ok(())
}
