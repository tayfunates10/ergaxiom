#[path = "../../graphic-inkscape-srgb-certified-delivery-runtime/tests/support/mod.rs"]
mod support;

use std::error::Error;

use ergaxiom_attestation_runtime::{AttestationKeyRegistry, verify_attestation_against_bundle};
use ergaxiom_graphic_inkscape_final_certified_delivery_runtime::{
    InkscapeFinalArtifactCertificationError, InkscapeFinalArtifactCertificationRequest,
    certify_inkscape_final_artifacts,
};
use ergaxiom_graphic_inkscape_srgb_certified_delivery_runtime::{
    CertifiedInkscapeSrgbGraphicDelivery, InkscapeSrgbCertificationRequest,
    certify_inkscape_srgb_graphic_delivery,
};
use ergaxiom_png_logo_geometry_runtime::LogoGeometryResult;
use ergaxiom_png_rendered_contrast_runtime::RenderedContrastResult;
use ergaxiom_png_rendered_text_bounds_runtime::RenderedTextBoundsResult;
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus};
use ergaxiom_svg_approved_copy_runtime::ApprovedCopyResult;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use support::{
    ATTESTATION_ISSUER, ATTESTATION_KEY_ID, NOW, Context, attestation_keys, authorizer,
    certify_base_delivery, context, normalization_fixture, normalization_material, signed_tokens,
    synthetic_execution_fixture, workspace,
};

#[test]
fn independent_final_artifact_proofs_issue_a_new_attestation() -> Result<(), Box<dyn Error>> {
    let (context, base_delivery, base_keys) = certified_srgb_delivery()?;
    let (copy, logo, text, contrast) = accepted_results(&context, &base_delivery)?;

    let delivery = certify_inkscape_final_artifacts(InkscapeFinalArtifactCertificationRequest {
        base_delivery,
        approved_logo_artifact_id: &context.job.approved_logo.artifact_id,
        approved_copy: &copy,
        logo_geometry: &logo,
        text_bounds: &text,
        rendered_contrast: &contrast,
        base_attestation_keys: &base_keys,
        compiled_contract: &context.compiled_contract,
        compiled_plan: &context.compiled_plan,
        assurance_level: AssuranceLevel::E3,
        final_manifest_id: "manifest.graphic-inkscape-final-artifacts.0001",
        final_certificate_id: "certificate.graphic-inkscape-final-artifacts.0001",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW + 2,
        attestation_signing_key: &context.attestation_key,
    })?;

    assert_eq!(
        delivery.evidence_bundle.claimed_decision.status,
        DecisionStatus::Accepted
    );
    assert_eq!(
        delivery.verified_attestation.evidence_bundle_digest,
        delivery.evidence_bundle_digest
    );
    assert_eq!(delivery.final_artifact_binding.logo_mask_iou_milli, 995);
    assert_eq!(
        delivery.final_artifact_binding.minimum_dominant_contrast_milli,
        4500
    );
    assert_eq!(delivery.certification_binding.binding_digest.len(), 64);
    assert_ne!(
        delivery.evidence_bundle_digest,
        delivery.base_delivery.evidence_bundle_digest
    );
    for artifact_id in [
        "evidence.graphic.approved-copy-result",
        "evidence.graphic.logo-geometry-result",
        "evidence.graphic.text-bounds-result",
        "evidence.graphic.rendered-contrast-result",
        "evidence.graphic.final-artifact-binding",
        "evidence.graphic.final-certification-binding",
    ] {
        assert!(
            delivery
                .evidence_bundle
                .artifacts
                .iter()
                .any(|artifact| artifact.artifact_id == artifact_id)
        );
    }
    assert!(
        verify_attestation_against_bundle(
            &delivery.attestation,
            &base_keys,
            context.compiled_contract.clone(),
            &context.compiled_plan,
            &serde_json::to_value(&delivery.evidence_bundle)?,
            AssuranceLevel::E3,
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn mixed_pixel_decode_evidence_cannot_issue_a_certificate() -> Result<(), Box<dyn Error>> {
    let (context, base_delivery, base_keys) = certified_srgb_delivery()?;
    let (copy, logo, mut text, contrast) = accepted_results(&context, &base_delivery)?;
    text.report.rgba_pixel_digest = "9".repeat(64);

    let result = certify_inkscape_final_artifacts(InkscapeFinalArtifactCertificationRequest {
        base_delivery,
        approved_logo_artifact_id: &context.job.approved_logo.artifact_id,
        approved_copy: &copy,
        logo_geometry: &logo,
        text_bounds: &text,
        rendered_contrast: &contrast,
        base_attestation_keys: &base_keys,
        compiled_contract: &context.compiled_contract,
        compiled_plan: &context.compiled_plan,
        assurance_level: AssuranceLevel::E3,
        final_manifest_id: "manifest.graphic-inkscape-final-artifacts.invalid-pixels",
        final_certificate_id: "certificate.graphic-inkscape-final-artifacts.invalid-pixels",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW + 2,
        attestation_signing_key: &context.attestation_key,
    });

    assert!(matches!(
        result,
        Err(InkscapeFinalArtifactCertificationError::FinalArtifactVerification(
            ergaxiom_graphic_final_artifact_verification_runtime::FinalArtifactVerificationError::PixelDecodeBindingMismatch
        ))
    ));
    Ok(())
}

#[test]
fn untrusted_base_attestation_cannot_be_extended() -> Result<(), Box<dyn Error>> {
    let (context, base_delivery, _) = certified_srgb_delivery()?;
    let (copy, logo, text, contrast) = accepted_results(&context, &base_delivery)?;
    let empty_keys = AttestationKeyRegistry::default();

    let result = certify_inkscape_final_artifacts(InkscapeFinalArtifactCertificationRequest {
        base_delivery,
        approved_logo_artifact_id: &context.job.approved_logo.artifact_id,
        approved_copy: &copy,
        logo_geometry: &logo,
        text_bounds: &text,
        rendered_contrast: &contrast,
        base_attestation_keys: &empty_keys,
        compiled_contract: &context.compiled_contract,
        compiled_plan: &context.compiled_plan,
        assurance_level: AssuranceLevel::E3,
        final_manifest_id: "manifest.graphic-inkscape-final-artifacts.untrusted-base",
        final_certificate_id: "certificate.graphic-inkscape-final-artifacts.untrusted-base",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW + 2,
        attestation_signing_key: &context.attestation_key,
    });

    assert!(matches!(
        result,
        Err(InkscapeFinalArtifactCertificationError::AttestationVerify(_))
    ));
    Ok(())
}

fn certified_srgb_delivery() -> Result<
    (
        Context,
        CertifiedInkscapeSrgbGraphicDelivery,
        AttestationKeyRegistry,
    ),
    Box<dyn Error>,
> {
    let context = context()?;
    let tokens = signed_tokens(&context)?;
    let execution = synthetic_execution_fixture()?;
    let normalization = normalization_fixture(&execution)?;
    let mut workspace = workspace()?;
    let mut authorizer = authorizer(&context)?;
    let base_keys = attestation_keys(&context)?;
    let base_delivery = certify_base_delivery(
        &context,
        &mut workspace,
        &mut authorizer,
        &tokens,
        &execution,
    )?;
    let delivery = certify_inkscape_srgb_graphic_delivery(InkscapeSrgbCertificationRequest {
        base_delivery,
        normalization_material: normalization_material(&execution, &normalization),
        normalization_keys: &normalization.keys,
        base_attestation_keys: &base_keys,
        contract_value: &context.contract_value,
        compiled_contract: &context.compiled_contract,
        compiled_plan: &context.compiled_plan,
        assurance_level: AssuranceLevel::E3,
        final_manifest_id: "manifest.graphic-inkscape-final-artifacts-base.0001",
        final_certificate_id: "certificate.graphic-inkscape-final-artifacts-base.0001",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW + 1,
        attestation_signing_key: &context.attestation_key,
    })?;
    Ok((context, delivery, base_keys))
}

fn accepted_results(
    context: &Context,
    base: &CertifiedInkscapeSrgbGraphicDelivery,
) -> Result<
    (
        ApprovedCopyResult,
        LogoGeometryResult,
        RenderedTextBoundsResult,
        RenderedContrastResult,
    ),
    Box<dyn Error>,
> {
    let copy_digest = artifact_digest(
        base,
        &base
            .base_delivery
            .execution_binding
            .approved_copy_artifact_id,
    )?;
    let logo_digest = artifact_digest(base, &context.job.approved_logo.artifact_id)?;
    let editable_digest = base.normalization_binding.editable_svg_digest.clone();
    let raster_digest = base
        .normalization_binding
        .normalized_raster_png_digest
        .clone();
    let pixel_report_digest = "5".repeat(64);
    let rgba_digest = "6".repeat(64);

    let copy = decode(json!({
        "schema_version": "0.1.0",
        "accepted": true,
        "report": {
            "schema_version": "0.1.0",
            "approved_copy_digest": copy_digest,
            "approved_copy_byte_count": context.job.approved_copy.text.len(),
            "svg_artifact_digest": editable_digest,
            "svg_byte_count": 100,
            "target_element_id": base.base_delivery.execution_binding.target_element_id,
            "target_element_name": "text",
            "extracted_copy_digest": artifact_digest(base, &base.base_delivery.execution_binding.approved_copy_artifact_id)?,
            "extracted_copy_byte_count": context.job.approved_copy.text.len(),
            "exact_match": true,
            "report_digest": "a".repeat(64)
        },
        "violations": [],
        "decision_digest": "b".repeat(64)
    }))?;
    let logo = decode(json!({
        "schema_version": "0.1.0",
        "accepted": true,
        "report": {
            "schema_version": "0.1.0",
            "rendered_artifact_digest": raster_digest,
            "rendered_pixel_report_digest": pixel_report_digest,
            "rendered_rgba_pixel_digest": rgba_digest,
            "approved_artifact_digest": logo_digest,
            "approved_pixel_report_digest": "7".repeat(64),
            "approved_rgba_pixel_digest": "8".repeat(64),
            "approved_mask_digest": "9".repeat(64),
            "approved_mask_width": 20,
            "approved_mask_height": 10,
            "approved_foreground_pixel_count": 96,
            "approved_foreground_share_milli": 480,
            "logo_region": {"x": 24, "y": 24, "width": 80, "height": 40},
            "clear_space_px": 16,
            "background_ring_px": 4,
            "background_sample_count": 1024,
            "non_opaque_background_pixel_count": 0,
            "background_rgb": [255, 255, 255],
            "background_max_channel_deviation": 0,
            "non_opaque_logo_pixel_count": 0,
            "non_opaque_clear_space_pixel_count": 0,
            "rendered_foreground_pixel_count": 384,
            "expected_foreground_pixel_count": 384,
            "mask_intersection_pixel_count": 382,
            "mask_union_pixel_count": 384,
            "mask_iou_milli": 995,
            "expected_occupied_bounds": {"x": 28, "y": 28, "width": 64, "height": 24},
            "rendered_occupied_bounds": {"x": 28, "y": 28, "width": 64, "height": 24},
            "expected_aspect_ratio_ppm": 2666667,
            "rendered_aspect_ratio_ppm": 2666667,
            "aspect_ratio_error_ppm": 0,
            "clear_space_intrusion_pixel_count": 0,
            "report_digest": "c".repeat(64)
        },
        "violations": [],
        "decision_digest": "d".repeat(64)
    }))?;
    let text = decode(json!({
        "schema_version": "0.1.0",
        "accepted": true,
        "report": {
            "schema_version": "0.1.0",
            "artifact_digest": base.normalization_binding.normalized_raster_png_digest,
            "pixel_report_digest": "5".repeat(64),
            "rgba_pixel_digest": "6".repeat(64),
            "analysis_region": {"x": 12, "y": 80, "width": 216, "height": 100},
            "safe_area": {"x": 20, "y": 88, "width": 200, "height": 84},
            "background_ring_px": 4,
            "analysis_pixel_count": 21600,
            "background_sample_count": 2592,
            "non_opaque_analysis_pixel_count": 0,
            "non_opaque_background_pixel_count": 0,
            "background_rgb": [255, 255, 255],
            "background_max_channel_deviation": 0,
            "foreground_pixel_count": 400,
            "foreground_share_milli": 19,
            "observed_bounds": {"x": 30, "y": 100, "width": 120, "height": 30},
            "foreground_outside_safe_area_pixel_count": 0,
            "foreground_in_clipping_guard_pixel_count": 0,
            "left_safe_margin_px": 10,
            "top_safe_margin_px": 12,
            "right_safe_margin_px": 70,
            "bottom_safe_margin_px": 42,
            "report_digest": "e".repeat(64)
        },
        "violations": [],
        "decision_digest": "f".repeat(64)
    }))?;
    let contrast = decode(json!({
        "schema_version": "0.1.0",
        "accepted": true,
        "report": {
            "schema_version": "0.1.0",
            "artifact_digest": base.normalization_binding.normalized_raster_png_digest,
            "pixel_report_digest": "5".repeat(64),
            "rgba_pixel_digest": "6".repeat(64),
            "subject_region": {"x": 12, "y": 80, "width": 216, "height": 100},
            "background_ring_px": 4,
            "subject_pixel_count": 21600,
            "background_sample_count": 2592,
            "non_opaque_subject_pixel_count": 0,
            "non_opaque_background_pixel_count": 0,
            "background_rgb": [255, 255, 255],
            "background_max_channel_deviation": 0,
            "candidate_pixel_count": 400,
            "candidate_share_milli": 19,
            "dominant_bin": 123,
            "dominant_pixel_count": 380,
            "dominant_share_milli": 950,
            "foreground_rgb": [0, 0, 0],
            "background_luminance_million": 1000000,
            "foreground_luminance_million": 0,
            "representative_contrast_milli": 21000,
            "minimum_dominant_contrast_milli": 4500,
            "report_digest": "7".repeat(64)
        },
        "violations": [],
        "decision_digest": "8".repeat(64)
    }))?;
    Ok((copy, logo, text, contrast))
}

fn artifact_digest(
    base: &CertifiedInkscapeSrgbGraphicDelivery,
    artifact_id: &str,
) -> Result<String, Box<dyn Error>> {
    base.evidence_bundle
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_id == artifact_id)
        .map(|artifact| artifact.digest.clone())
        .ok_or_else(|| format!("artifact missing: {artifact_id}").into())
}

fn decode<T: DeserializeOwned>(value: Value) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_value(value)?)
}
