use std::error::Error;

use ergaxiom_png_artifact_validator_runtime::PngColorType;
use ergaxiom_png_logo_geometry_runtime::{
    LogoGeometryError, LogoGeometryPolicy, LogoGeometryViolation, PixelRect, validate_logo_geometry,
};
use ergaxiom_png_pixel_decoder_runtime::{DecodedPng, PngPixelReport};

#[test]
fn exact_scaled_approved_logo_is_accepted() -> Result<(), Box<dyn Error>> {
    let approved = approved_logo();
    let rendered = rendered_with_exact_logo();
    let result = validate_logo_geometry(&approved, &rendered, &policy())?;

    assert!(result.accepted);
    assert!(result.violations.is_empty());
    assert_eq!(result.report.approved_foreground_pixel_count, 96);
    assert_eq!(result.report.approved_foreground_share_milli, 480);
    assert_eq!(result.report.expected_foreground_pixel_count, 384);
    assert_eq!(result.report.rendered_foreground_pixel_count, 384);
    assert_eq!(result.report.mask_iou_milli, 1000);
    assert_eq!(result.report.clear_space_intrusion_pixel_count, 0);
    assert_eq!(result.report.background_rgb, [250, 250, 250]);
    assert_eq!(result.report.report_digest.len(), 64);
    assert_eq!(result.decision_digest.len(), 64);
    Ok(())
}

#[test]
fn stretched_or_shrunken_logo_is_rejected() -> Result<(), Box<dyn Error>> {
    let approved = approved_logo();
    let mut image = image(120, 80, [250, 250, 250, 255]);
    fill(&mut image, 120, rect(44, 34, 24, 12), [17, 24, 39, 255]);
    let result = validate_logo_geometry(&approved, &decoded(120, 80, image, 'r'), &policy())?;

    assert!(!result.accepted);
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        LogoGeometryViolation::MaskSimilarityTooLow { .. }
    )));
    assert!(
        result.violations.iter().any(|violation| matches!(
            violation,
            LogoGeometryViolation::AspectRatioMismatch { .. }
        ))
    );
    Ok(())
}

#[test]
fn added_or_removed_logo_geometry_is_rejected() -> Result<(), Box<dyn Error>> {
    let approved = approved_logo();
    let mut rendered = rendered_with_exact_logo();
    fill(
        &mut rendered.rgba8,
        120,
        rect(40, 30, 4, 4),
        [17, 24, 39, 255],
    );
    let result = validate_logo_geometry(&approved, &rendered, &policy())?;

    assert!(!result.accepted);
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        LogoGeometryViolation::MaskSimilarityTooLow { .. }
    )));
    assert!(result.report.mask_iou_milli < 980);
    Ok(())
}

#[test]
fn clear_space_intrusion_is_rejected_independently() -> Result<(), Box<dyn Error>> {
    let approved = approved_logo();
    let mut rendered = rendered_with_exact_logo();
    set_pixel(&mut rendered.rgba8, 120, 38, 35, [17, 24, 39, 255]);
    let result = validate_logo_geometry(&approved, &rendered, &policy())?;

    assert!(!result.accepted);
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        LogoGeometryViolation::ClearSpaceIntrusion {
            maximum_pixels: 0,
            actual_pixels: 1
        }
    )));
    Ok(())
}

#[test]
fn alpha_in_logo_clear_space_or_background_fails_closed() -> Result<(), Box<dyn Error>> {
    let approved = approved_logo();
    let mut rendered = rendered_with_exact_logo();
    set_pixel(&mut rendered.rgba8, 120, 45, 35, [17, 24, 39, 200]);
    set_pixel(&mut rendered.rgba8, 120, 38, 35, [250, 250, 250, 200]);
    set_pixel(&mut rendered.rgba8, 120, 32, 22, [250, 250, 250, 200]);
    let result = validate_logo_geometry(&approved, &rendered, &policy())?;

    assert!(!result.accepted);
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        LogoGeometryViolation::NonOpaqueLogoPixels { count: 1 }
    )));
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        LogoGeometryViolation::NonOpaqueClearSpacePixels { count: 1 }
    )));
    assert!(result.violations.iter().any(|violation| matches!(
        violation,
        LogoGeometryViolation::NonOpaqueBackgroundPixels { count: 1 }
    )));
    Ok(())
}

#[test]
fn unsuitable_fully_opaque_approved_asset_is_rejected() {
    let approved = decoded(20, 10, image(20, 10, [17, 24, 39, 255]), 'a');
    let error = match validate_logo_geometry(&approved, &rendered_with_exact_logo(), &policy()) {
        Ok(_) => panic!("fully opaque source must not be treated as a transparent logo mask"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        LogoGeometryError::ApprovedMaskShareOutOfRange {
            actual_milli: 1000,
            ..
        }
    ));
}

#[test]
fn identical_inputs_produce_identical_evidence() -> Result<(), Box<dyn Error>> {
    let approved = approved_logo();
    let rendered = rendered_with_exact_logo();
    let first = validate_logo_geometry(&approved, &rendered, &policy())?;
    let second = validate_logo_geometry(&approved, &rendered, &policy())?;

    assert_eq!(first, second);
    Ok(())
}

fn approved_logo() -> DecodedPng {
    let mut bytes = image(20, 10, [0, 0, 0, 0]);
    fill(&mut bytes, 20, rect(2, 2, 16, 6), [17, 24, 39, 255]);
    decoded(20, 10, bytes, 'a')
}

fn rendered_with_exact_logo() -> DecodedPng {
    let mut bytes = image(120, 80, [250, 250, 250, 255]);
    fill(&mut bytes, 120, rect(44, 34, 32, 12), [17, 24, 39, 255]);
    decoded(120, 80, bytes, 'r')
}

fn policy() -> LogoGeometryPolicy {
    LogoGeometryPolicy {
        logo_region: rect(40, 30, 40, 20),
        clear_space_px: 5,
        background_ring_px: 4,
        approved_alpha_threshold: 128,
        approved_minimum_foreground_pixels: 50,
        approved_minimum_foreground_share_milli: 100,
        approved_maximum_foreground_share_milli: 900,
        foreground_minimum_distance_squared: 4096,
        minimum_rendered_foreground_pixels: 100,
        minimum_mask_iou_milli: 980,
        maximum_aspect_ratio_error_ppm: 10_000,
        background_max_channel_deviation: 4,
        maximum_clear_space_intrusion_pixels: 0,
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

fn decoded(width: u32, height: u32, rgba8: Vec<u8>, digest_seed: char) -> DecodedPng {
    DecodedPng {
        report: PngPixelReport {
            schema_version: "0.1.0".to_owned(),
            artifact_digest: digest_seed.to_string().repeat(64),
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
