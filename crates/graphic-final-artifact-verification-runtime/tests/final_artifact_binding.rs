use std::error::Error;

use ergaxiom_graphic_final_artifact_verification_runtime::{
    FinalArtifactExpectations, FinalArtifactVerificationError, FinalArtifactVerificationRequest,
    verify_final_artifacts,
};
use ergaxiom_png_logo_geometry_runtime::LogoGeometryResult;
use ergaxiom_png_rendered_contrast_runtime::RenderedContrastResult;
use ergaxiom_png_rendered_text_bounds_runtime::RenderedTextBoundsResult;
use ergaxiom_svg_approved_copy_runtime::ApprovedCopyResult;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

#[test]
fn all_independent_artifact_results_bind_deterministically() -> Result<(), Box<dyn Error>> {
    let (expectations, copy, logo, text, contrast) = accepted_fixture();
    let first = verify_final_artifacts(FinalArtifactVerificationRequest {
        expectations: expectations.clone(),
        approved_copy: &copy,
        logo_geometry: &logo,
        text_bounds: &text,
        rendered_contrast: &contrast,
    })?;
    let second = verify_final_artifacts(FinalArtifactVerificationRequest {
        expectations,
        approved_copy: &copy,
        logo_geometry: &logo,
        text_bounds: &text,
        rendered_contrast: &contrast,
    })?;

    assert_eq!(first, second);
    assert_eq!(first.binding_digest.len(), 64);
    assert_eq!(first.shared_pixel_report_digest, "5".repeat(64));
    assert_eq!(first.shared_rgba_pixel_digest, "6".repeat(64));
    assert_eq!(first.minimum_dominant_contrast_milli, 4500);
    assert_eq!(first.logo_mask_iou_milli, 995);
    Ok(())
}

#[test]
fn raster_digest_substitution_is_rejected() {
    let (expectations, copy, mut logo, text, contrast) = accepted_fixture();
    logo.report.rendered_artifact_digest = "9".repeat(64);
    let error = match verify_final_artifacts(FinalArtifactVerificationRequest {
        expectations,
        approved_copy: &copy,
        logo_geometry: &logo,
        text_bounds: &text,
        rendered_contrast: &contrast,
    }) {
        Ok(_) => panic!("substituted raster digest must fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        FinalArtifactVerificationError::RasterArtifactBindingMismatch
    ));
}

#[test]
fn independent_pixel_decode_mismatch_is_rejected() {
    let (expectations, copy, logo, mut text, contrast) = accepted_fixture();
    text.report.rgba_pixel_digest = "9".repeat(64);
    let error = match verify_final_artifacts(FinalArtifactVerificationRequest {
        expectations,
        approved_copy: &copy,
        logo_geometry: &logo,
        text_bounds: &text,
        rendered_contrast: &contrast,
    }) {
        Ok(_) => panic!("different decoded pixel material must fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        FinalArtifactVerificationError::PixelDecodeBindingMismatch
    ));
}

#[test]
fn contrast_region_must_equal_text_analysis_region() {
    let (expectations, copy, logo, text, mut contrast) = accepted_fixture();
    contrast.report.subject_region.x = 11;
    let error = match verify_final_artifacts(FinalArtifactVerificationRequest {
        expectations,
        approved_copy: &copy,
        logo_geometry: &logo,
        text_bounds: &text,
        rendered_contrast: &contrast,
    }) {
        Ok(_) => panic!("mismatched text regions must fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        FinalArtifactVerificationError::TextRegionBindingMismatch
    ));
}

#[test]
fn any_rejected_validator_blocks_the_binding() {
    let (expectations, copy, logo, text, mut contrast) = accepted_fixture();
    contrast.accepted = false;
    let error = match verify_final_artifacts(FinalArtifactVerificationRequest {
        expectations,
        approved_copy: &copy,
        logo_geometry: &logo,
        text_bounds: &text,
        rendered_contrast: &contrast,
    }) {
        Ok(_) => panic!("rejected validator must block final binding"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        FinalArtifactVerificationError::ValidatorRejected("rendered_contrast")
    ));
}

fn accepted_fixture() -> (
    FinalArtifactExpectations,
    ApprovedCopyResult,
    LogoGeometryResult,
    RenderedTextBoundsResult,
    RenderedContrastResult,
) {
    let expectations = FinalArtifactExpectations {
        approved_copy_artifact_digest: "1".repeat(64),
        approved_logo_artifact_digest: "2".repeat(64),
        editable_svg_digest: "3".repeat(64),
        normalized_png_digest: "4".repeat(64),
        target_element_id: "headline".to_owned(),
    };
    let copy = decode(json!({
        "schema_version": "0.1.0",
        "accepted": true,
        "report": {
            "schema_version": "0.1.0",
            "approved_copy_digest": "1".repeat(64),
            "approved_copy_byte_count": 10,
            "svg_artifact_digest": "3".repeat(64),
            "svg_byte_count": 100,
            "target_element_id": "headline",
            "target_element_name": "text",
            "extracted_copy_digest": "1".repeat(64),
            "extracted_copy_byte_count": 10,
            "exact_match": true,
            "report_digest": "a".repeat(64)
        },
        "violations": [],
        "decision_digest": "b".repeat(64)
    }));
    let logo = decode(json!({
        "schema_version": "0.1.0",
        "accepted": true,
        "report": {
            "schema_version": "0.1.0",
            "rendered_artifact_digest": "4".repeat(64),
            "rendered_pixel_report_digest": "5".repeat(64),
            "rendered_rgba_pixel_digest": "6".repeat(64),
            "approved_artifact_digest": "2".repeat(64),
            "approved_pixel_report_digest": "7".repeat(64),
            "approved_rgba_pixel_digest": "8".repeat(64),
            "approved_mask_digest": "9".repeat(64),
            "approved_mask_width": 20,
            "approved_mask_height": 10,
            "approved_foreground_pixel_count": 96,
            "approved_foreground_share_milli": 480,
            "logo_region": {"x": 10, "y": 10, "width": 40, "height": 20},
            "clear_space_px": 5,
            "background_ring_px": 4,
            "background_sample_count": 1024,
            "non_opaque_background_pixel_count": 0,
            "background_rgb": [250, 250, 250],
            "background_max_channel_deviation": 0,
            "non_opaque_logo_pixel_count": 0,
            "non_opaque_clear_space_pixel_count": 0,
            "rendered_foreground_pixel_count": 384,
            "expected_foreground_pixel_count": 384,
            "mask_intersection_pixel_count": 382,
            "mask_union_pixel_count": 384,
            "mask_iou_milli": 995,
            "expected_occupied_bounds": {"x": 14, "y": 14, "width": 32, "height": 12},
            "rendered_occupied_bounds": {"x": 14, "y": 14, "width": 32, "height": 12},
            "expected_aspect_ratio_ppm": 2666667,
            "rendered_aspect_ratio_ppm": 2666667,
            "aspect_ratio_error_ppm": 0,
            "clear_space_intrusion_pixel_count": 0,
            "report_digest": "c".repeat(64)
        },
        "violations": [],
        "decision_digest": "d".repeat(64)
    }));
    let text = decode(json!({
        "schema_version": "0.1.0",
        "accepted": true,
        "report": {
            "schema_version": "0.1.0",
            "artifact_digest": "4".repeat(64),
            "pixel_report_digest": "5".repeat(64),
            "rgba_pixel_digest": "6".repeat(64),
            "analysis_region": {"x": 10, "y": 10, "width": 80, "height": 40},
            "safe_area": {"x": 20, "y": 15, "width": 60, "height": 30},
            "background_ring_px": 4,
            "analysis_pixel_count": 3200,
            "background_sample_count": 1024,
            "non_opaque_analysis_pixel_count": 0,
            "non_opaque_background_pixel_count": 0,
            "background_rgb": [250, 250, 250],
            "background_max_channel_deviation": 0,
            "foreground_pixel_count": 400,
            "foreground_share_milli": 125,
            "observed_bounds": {"x": 30, "y": 25, "width": 40, "height": 10},
            "foreground_outside_safe_area_pixel_count": 0,
            "foreground_in_clipping_guard_pixel_count": 0,
            "left_safe_margin_px": 10,
            "top_safe_margin_px": 10,
            "right_safe_margin_px": 10,
            "bottom_safe_margin_px": 10,
            "report_digest": "e".repeat(64)
        },
        "violations": [],
        "decision_digest": "f".repeat(64)
    }));
    let contrast = decode(json!({
        "schema_version": "0.1.0",
        "accepted": true,
        "report": {
            "schema_version": "0.1.0",
            "artifact_digest": "4".repeat(64),
            "pixel_report_digest": "5".repeat(64),
            "rgba_pixel_digest": "6".repeat(64),
            "subject_region": {"x": 10, "y": 10, "width": 80, "height": 40},
            "background_ring_px": 4,
            "subject_pixel_count": 3200,
            "background_sample_count": 1024,
            "non_opaque_subject_pixel_count": 0,
            "non_opaque_background_pixel_count": 0,
            "background_rgb": [250, 250, 250],
            "background_max_channel_deviation": 0,
            "candidate_pixel_count": 400,
            "candidate_share_milli": 125,
            "dominant_bin": 123,
            "dominant_pixel_count": 380,
            "dominant_share_milli": 950,
            "foreground_rgb": [17, 24, 39],
            "background_luminance_million": 955000,
            "foreground_luminance_million": 9000,
            "representative_contrast_milli": 17000,
            "minimum_dominant_contrast_milli": 4500,
            "report_digest": "7".repeat(64)
        },
        "violations": [],
        "decision_digest": "8".repeat(64)
    }));
    (expectations, copy, logo, text, contrast)
}

fn decode<T: DeserializeOwned>(value: Value) -> T {
    match serde_json::from_value(value) {
        Ok(decoded) => decoded,
        Err(error) => panic!("fixture must decode: {error}"),
    }
}
