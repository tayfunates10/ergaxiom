use std::error::Error;

use ergaxiom_png_artifact_validator_runtime::PngColorType;
use ergaxiom_png_pixel_decoder_runtime::{DecodedPng, PngPixelReport};
use ergaxiom_png_rendered_contrast_runtime::{
    PixelRect, RenderedContrastPolicy, RenderedContrastViolation, contrast_milli,
    relative_luminance_million, validate_rendered_contrast,
};

#[test]
fn high_contrast_core_pixels_are_accepted() -> Result<(), Box<dyn Error>> {
    let mut image = image(100, 60, [250, 250, 250, 255]);
    fill(&mut image, 100, rect(35, 23, 30, 14), [17, 24, 39, 255]);
    let result = validate_rendered_contrast(&decoded(100, 60, image), &policy())?;

    assert!(result.accepted);
    assert!(result.violations.is_empty());
    assert_eq!(result.report.background_rgb, [250, 250, 250]);
    assert_eq!(result.report.foreground_rgb, [17, 24, 39]);
    assert_eq!(result.report.candidate_pixel_count, 420);
    assert_eq!(result.report.dominant_pixel_count, 420);
    assert!(result.report.minimum_dominant_contrast_milli >= 15_000);
    assert_eq!(result.report.report_digest.len(), 64);
    assert_eq!(result.decision_digest.len(), 64);
    Ok(())
}

#[test]
fn anti_aliased_edges_do_not_replace_the_dominant_core_cluster() -> Result<(), Box<dyn Error>> {
    let mut image = image(100, 60, [250, 250, 250, 255]);
    fill(&mut image, 100, rect(34, 22, 32, 16), [120, 125, 132, 255]);
    fill(&mut image, 100, rect(36, 24, 28, 12), [17, 24, 39, 255]);
    let result = validate_rendered_contrast(&decoded(100, 60, image), &policy())?;

    assert!(result.accepted);
    assert_eq!(result.report.foreground_rgb, [17, 24, 39]);
    assert_eq!(result.report.dominant_pixel_count, 336);
    assert!(result.report.dominant_share_milli > 600);
    Ok(())
}

#[test]
fn low_contrast_rendered_text_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut image = image(100, 60, [250, 250, 250, 255]);
    fill(&mut image, 100, rect(35, 23, 30, 14), [170, 170, 170, 255]);
    let result = validate_rendered_contrast(&decoded(100, 60, image), &policy())?;

    assert!(!result.accepted);
    assert!(matches!(
        result.violations.as_slice(),
        [RenderedContrastViolation::ContrastTooLow {
            required_milli: 4500,
            actual_milli: _
        }]
    ));
    assert!(result.report.minimum_dominant_contrast_milli < 4500);
    Ok(())
}

#[test]
fn nonuniform_local_background_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut image = image(100, 60, [250, 250, 250, 255]);
    fill(&mut image, 100, rect(35, 23, 30, 14), [17, 24, 39, 255]);
    set_pixel(&mut image, 100, 14, 9, [20, 20, 20, 255]);
    let result = validate_rendered_contrast(&decoded(100, 60, image), &policy())?;

    assert!(!result.accepted);
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        RenderedContrastViolation::BackgroundNotUniform { .. }
    )));
    Ok(())
}

#[test]
fn missing_or_excessive_foreground_candidates_fail_closed() -> Result<(), Box<dyn Error>> {
    let empty = validate_rendered_contrast(
        &decoded(100, 60, image(100, 60, [250, 250, 250, 255])),
        &policy(),
    )?;
    assert!(!empty.accepted);
    assert!(empty.violations.iter().any(|violation| matches!(
        violation,
        RenderedContrastViolation::InsufficientCandidatePixels { actual: 0, .. }
    )));

    let mut full = image(100, 60, [250, 250, 250, 255]);
    fill(&mut full, 100, rect(20, 15, 60, 30), [17, 24, 39, 255]);
    let excessive = validate_rendered_contrast(&decoded(100, 60, full), &policy())?;
    assert!(!excessive.accepted);
    assert!(excessive.violations.iter().any(|violation| matches!(
        violation,
        RenderedContrastViolation::CandidateShareTooHigh { .. }
    )));
    Ok(())
}

#[test]
fn alpha_in_subject_or_background_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut image = image(100, 60, [250, 250, 250, 255]);
    fill(&mut image, 100, rect(35, 23, 30, 14), [17, 24, 39, 255]);
    set_pixel(&mut image, 100, 36, 24, [17, 24, 39, 200]);
    set_pixel(&mut image, 100, 14, 9, [250, 250, 250, 200]);
    let result = validate_rendered_contrast(&decoded(100, 60, image), &policy())?;

    assert!(!result.accepted);
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        RenderedContrastViolation::NonOpaqueSubjectPixels { count: 1 }
    )));
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        RenderedContrastViolation::NonOpaqueBackgroundPixels { count: 1 }
    )));
    Ok(())
}

#[test]
fn fixed_point_wcag_reference_ratios_are_stable() {
    assert_eq!(contrast_milli(0, 1_000_000), 21_000);
    let dark = relative_luminance_million([17, 24, 39]);
    let light = relative_luminance_million([249, 250, 251]);
    assert_eq!(dark, 9_189);
    assert_eq!(light, 954_760);
    assert_eq!(contrast_milli(dark, light), 16_975);
}

fn policy() -> RenderedContrastPolicy {
    RenderedContrastPolicy {
        subject_region: rect(20, 15, 60, 30),
        background_ring_px: 6,
        minimum_contrast_milli: 4500,
        background_max_channel_deviation: 4,
        foreground_minimum_distance_squared: 4096,
        minimum_candidate_pixels: 100,
        maximum_candidate_share_milli: 500,
        quantization_bits: 5,
        minimum_dominant_pixels: 100,
        minimum_dominant_share_milli: 500,
    }
}

fn rect(x: u32, y: u32, width: u32, height: u32) -> PixelRect {
    PixelRect {
        x,
        y,
        width,
        height,
    }
}

fn image(width: usize, height: usize, pixel: [u8; 4]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(width * height * 4);
    for _ in 0..width * height {
        bytes.extend_from_slice(&pixel);
    }
    bytes
}

fn fill(bytes: &mut [u8], width: usize, region: PixelRect, pixel: [u8; 4]) {
    for y in region.y..region.y + region.height {
        for x in region.x..region.x + region.width {
            set_pixel(bytes, width, x as usize, y as usize, pixel);
        }
    }
}

fn set_pixel(bytes: &mut [u8], width: usize, x: usize, y: usize, pixel: [u8; 4]) {
    let index = (y * width + x) * 4;
    bytes[index..index + 4].copy_from_slice(&pixel);
}

fn decoded(width: u32, height: u32, rgba8: Vec<u8>) -> DecodedPng {
    DecodedPng {
        report: PngPixelReport {
            schema_version: "0.1.0".to_owned(),
            artifact_digest: "a".repeat(64),
            validator_report_digest: "b".repeat(64),
            width,
            height,
            color_type: PngColorType::TruecolorAlpha,
            bit_depth: 8,
            interlace_method: 0,
            bytes_per_pixel: 4,
            row_bytes: u64::from(width) * 4,
            pixel_count: u64::from(width) * u64::from(height),
            non_opaque_pixel_count: 0,
            idat_payload_digest: "c".repeat(64),
            decompressed_scanline_digest: "d".repeat(64),
            rgba_pixel_digest: "e".repeat(64),
            filter_counts: [u64::from(height), 0, 0, 0, 0],
            report_digest: "f".repeat(64),
        },
        rgba8,
    }
}
