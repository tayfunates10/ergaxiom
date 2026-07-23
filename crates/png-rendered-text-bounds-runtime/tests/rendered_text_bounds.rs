use std::error::Error;

use ergaxiom_png_artifact_validator_runtime::PngColorType;
use ergaxiom_png_pixel_decoder_runtime::{DecodedPng, PngPixelReport};
use ergaxiom_png_rendered_text_bounds_runtime::{
    PixelRect, RenderedTextBoundsPolicy, RenderedTextBoundsViolation, validate_rendered_text_bounds,
};

#[test]
fn text_inside_safe_area_with_required_margins_is_accepted() -> Result<(), Box<dyn Error>> {
    let mut bytes = image(100, 60, [250, 250, 250, 255]);
    fill(&mut bytes, 100, rect(30, 25, 40, 10), [17, 24, 39, 255]);
    let result = validate_rendered_text_bounds(&decoded(100, 60, bytes), &policy())?;

    assert!(result.accepted);
    assert!(result.violations.is_empty());
    assert_eq!(result.report.foreground_pixel_count, 400);
    assert_eq!(result.report.foreground_share_milli, 125);
    assert_eq!(result.report.observed_bounds, Some(rect(30, 25, 40, 10)));
    assert_eq!(result.report.left_safe_margin_px, 10);
    assert_eq!(result.report.top_safe_margin_px, 10);
    assert_eq!(result.report.right_safe_margin_px, 10);
    assert_eq!(result.report.bottom_safe_margin_px, 10);
    assert_eq!(result.report.foreground_outside_safe_area_pixel_count, 0);
    assert_eq!(result.report.foreground_in_clipping_guard_pixel_count, 0);
    assert_eq!(result.report.report_digest.len(), 64);
    assert_eq!(result.decision_digest.len(), 64);
    Ok(())
}

#[test]
fn foreground_outside_safe_area_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut bytes = image(100, 60, [250, 250, 250, 255]);
    fill(&mut bytes, 100, rect(18, 25, 20, 10), [17, 24, 39, 255]);
    let result = validate_rendered_text_bounds(&decoded(100, 60, bytes), &policy())?;

    assert!(!result.accepted);
    assert_eq!(result.report.foreground_outside_safe_area_pixel_count, 20);
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        RenderedTextBoundsViolation::ForegroundOutsideSafeArea { count: 20 }
    )));
    Ok(())
}

#[test]
fn text_with_insufficient_safe_margin_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut bytes = image(100, 60, [250, 250, 250, 255]);
    fill(&mut bytes, 100, rect(22, 18, 56, 24), [17, 24, 39, 255]);
    let result = validate_rendered_text_bounds(&decoded(100, 60, bytes), &policy())?;

    assert!(!result.accepted);
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        RenderedTextBoundsViolation::SafeAreaMarginTooSmall {
            required_px: 5,
            left_px: 2,
            top_px: 3,
            right_px: 2,
            bottom_px: 3
        }
    )));
    Ok(())
}

#[test]
fn foreground_touching_analysis_boundary_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut bytes = image(100, 60, [250, 250, 250, 255]);
    fill(&mut bytes, 100, rect(10, 20, 10, 10), [17, 24, 39, 255]);
    let mut boundary_policy = policy();
    boundary_policy.safe_area = boundary_policy.analysis_region;
    boundary_policy.minimum_safe_area_margin_px = 0;
    boundary_policy.minimum_foreground_pixels = 20;
    let result = validate_rendered_text_bounds(&decoded(100, 60, bytes), &boundary_policy)?;

    assert!(!result.accepted);
    assert_eq!(result.report.foreground_in_clipping_guard_pixel_count, 30);
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        RenderedTextBoundsViolation::ForegroundTouchesAnalysisBoundary {
            guard_px: 3,
            count: 30
        }
    )));
    Ok(())
}

#[test]
fn missing_or_excessive_foreground_fails_closed() -> Result<(), Box<dyn Error>> {
    let missing = validate_rendered_text_bounds(
        &decoded(100, 60, image(100, 60, [250, 250, 250, 255])),
        &policy(),
    )?;
    assert!(!missing.accepted);
    assert!(missing.violations.iter().any(|violation| matches!(
        violation,
        RenderedTextBoundsViolation::InsufficientForegroundPixels { actual: 0, .. }
    )));

    let mut bytes = image(100, 60, [250, 250, 250, 255]);
    fill(&mut bytes, 100, rect(20, 15, 60, 30), [17, 24, 39, 255]);
    let excessive = validate_rendered_text_bounds(&decoded(100, 60, bytes), &policy())?;
    assert!(!excessive.accepted);
    assert!(excessive.violations.iter().any(|violation| matches!(
        violation,
        RenderedTextBoundsViolation::ForegroundShareTooHigh {
            maximum_milli: 500,
            ..
        }
    )));
    Ok(())
}

#[test]
fn alpha_and_nonuniform_background_fail_closed() -> Result<(), Box<dyn Error>> {
    let mut bytes = image(100, 60, [250, 250, 250, 255]);
    fill(&mut bytes, 100, rect(30, 25, 40, 10), [17, 24, 39, 255]);
    set_pixel(&mut bytes, 100, 30, 25, [17, 24, 39, 200]);
    set_pixel(&mut bytes, 100, 7, 7, [250, 250, 250, 200]);
    set_pixel(&mut bytes, 100, 8, 8, [20, 20, 20, 255]);
    let result = validate_rendered_text_bounds(&decoded(100, 60, bytes), &policy())?;

    assert!(!result.accepted);
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        RenderedTextBoundsViolation::NonOpaqueAnalysisPixels { count: 1 }
    )));
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        RenderedTextBoundsViolation::NonOpaqueBackgroundPixels { count: 1 }
    )));
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        RenderedTextBoundsViolation::BackgroundNotUniform { .. }
    )));
    Ok(())
}

#[test]
fn identical_inputs_produce_identical_evidence() -> Result<(), Box<dyn Error>> {
    let mut bytes = image(100, 60, [250, 250, 250, 255]);
    fill(&mut bytes, 100, rect(30, 25, 40, 10), [17, 24, 39, 255]);
    let decoded = decoded(100, 60, bytes);
    let first = validate_rendered_text_bounds(&decoded, &policy())?;
    let second = validate_rendered_text_bounds(&decoded, &policy())?;

    assert_eq!(first, second);
    Ok(())
}

fn policy() -> RenderedTextBoundsPolicy {
    RenderedTextBoundsPolicy {
        analysis_region: rect(10, 10, 80, 40),
        safe_area: rect(20, 15, 60, 30),
        background_ring_px: 4,
        foreground_minimum_distance_squared: 4096,
        minimum_foreground_pixels: 100,
        maximum_foreground_share_milli: 500,
        background_max_channel_deviation: 4,
        minimum_safe_area_margin_px: 5,
        clipping_guard_px: 3,
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
