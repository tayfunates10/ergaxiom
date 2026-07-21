use std::collections::BTreeMap;

use ergaxiom_proof_kernel::{
    EvidenceRecord, HashingError, IndependenceClass, TruthValue, canonical_json_sha256,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{
    DesignLayer, GraphicDesignDocument, GraphicDesignJob, GraphicValidationReport, PixelRect,
    ValidatorObservation,
};
use crate::png::{PngError, decode_rgba_png};
use crate::render::{RenderError, contrast_ratio_milli, render_document};

const REPORT_SCHEMA: &str = "0.1.0";
const VALIDATOR_VERSION: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("failed to decode editable master: {0}")]
    DocumentDecode(#[source] serde_json::Error),
    #[error("failed to serialize validation evidence: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Png(#[from] PngError),
    #[error(transparent)]
    Render(#[from] RenderError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("graphic document is missing its logo layer")]
    MissingLogoLayer,
    #[error("graphic document is missing its text layer")]
    MissingTextLayer,
}

pub fn validate_graphic_artifacts(
    job: &GraphicDesignJob,
    editable_master: &[u8],
    raster_png: &[u8],
) -> Result<(GraphicDesignDocument, GraphicValidationReport), ValidationError> {
    let document: GraphicDesignDocument =
        serde_json::from_slice(editable_master).map_err(ValidationError::DocumentDecode)?;
    let document_value =
        serde_json::to_value(&document).map_err(ValidationError::Serialization)?;
    let document_digest = canonical_json_sha256(&document_value)?;
    let raster_digest = sha256_hex(raster_png);
    let decoded = decode_rgba_png(raster_png)?;
    let independently_rendered = render_document(&document)?;

    let logo = document
        .layers
        .iter()
        .find_map(|layer| match layer {
            DesignLayer::Logo(logo) => Some(logo),
            DesignLayer::Text(_) => None,
        })
        .ok_or(ValidationError::MissingLogoLayer)?;
    let text_layers: Vec<_> = document
        .layers
        .iter()
        .filter_map(|layer| match layer {
            DesignLayer::Text(text) => Some(text),
            DesignLayer::Logo(_) => None,
        })
        .collect();
    if text_layers.is_empty() {
        return Err(ValidationError::MissingTextLayer);
    }

    let mut observations = Vec::new();
    observations.push(observation(
        "raster.dimensions",
        "canvas_width",
        decoded.width == job.canvas.width,
        json!(decoded.width),
        json!(job.canvas.width),
    )?);
    observations.push(observation(
        "raster.dimensions",
        "canvas_height",
        decoded.height == job.canvas.height,
        json!(decoded.height),
        json!(job.canvas.height),
    )?);
    let profile_passed = decoded.has_srgb_chunk
        && decoded.profile_name == job.canvas.color_profile
        && decoded.profile_description == job.canvas.color_profile;
    observations.push(observation(
        "raster.icc_profile",
        "color_profile",
        profile_passed,
        json!({
            "chunk_name": decoded.profile_name,
            "description": decoded.profile_description,
            "srgb_chunk": decoded.has_srgb_chunk,
        }),
        json!(job.canvas.color_profile),
    )?);

    let ratio_preserved = u64::from(logo.source_width) * u64::from(logo.bounds.height)
        == u64::from(logo.source_height) * u64::from(logo.bounds.width);
    observations.push(observation(
        "document.logo_geometry",
        "logo_aspect_ratio",
        ratio_preserved,
        json!({
            "source": [logo.source_width, logo.source_height],
            "placed": [logo.bounds.width, logo.bounds.height],
            "ratio_delta": if ratio_preserved { 0 } else { 1 },
        }),
        json!(0),
    )?);

    let minimum_clear_space = minimum_logo_clear_space(
        logo.bounds,
        document.canvas.width,
        document.canvas.height,
        &text_layers.iter().map(|layer| layer.bounds).collect::<Vec<_>>(),
    );
    observations.push(observation(
        "document.logo_geometry",
        "logo_clear_space",
        minimum_clear_space >= job.brand_profile.minimum_logo_clear_space_px,
        json!(minimum_clear_space),
        json!(job.brand_profile.minimum_logo_clear_space_px),
    )?);

    let safe_area_violations = text_layers
        .iter()
        .filter(|layer| !contains(document.safe_area, layer.bounds))
        .count();
    observations.push(observation(
        "document.text_bounds",
        "text_within_safe_area",
        safe_area_violations == 0,
        json!(safe_area_violations),
        json!(0),
    )?);

    let copy_matches = text_layers
        .iter()
        .all(|layer| layer.approved_copy == job.approved_copy.text);
    observations.push(observation(
        "document.approved_copy",
        "approved_copy_integrity",
        copy_matches,
        json!(text_layers.iter().map(|layer| &layer.approved_copy).collect::<Vec<_>>()),
        json!(job.approved_copy.text),
    )?);

    let declared_contrast = text_layers
        .iter()
        .map(|layer| contrast_ratio_milli(layer.color, document.canvas.background))
        .min()
        .unwrap_or(0);
    observations.push(observation(
        "raster.text_contrast.relative_luminance",
        "minimum_text_contrast",
        declared_contrast >= job.brand_profile.minimum_text_contrast_milli,
        json!({"ratio_milli": declared_contrast}),
        json!({"ratio_milli": job.brand_profile.minimum_text_contrast_milli}),
    )?);

    let sampled_contrast = independently_rendered
        .contrast_samples
        .iter()
        .map(|sample| contrast_ratio_milli(sample.foreground, sample.background))
        .min()
        .unwrap_or(0);
    observations.push(observation(
        "raster.text_contrast.render_sampling",
        "minimum_text_contrast",
        sampled_contrast >= job.brand_profile.minimum_text_contrast_milli,
        json!({
            "ratio_milli": sampled_contrast,
            "sample_count": independently_rendered.contrast_samples.len(),
            "sample_coordinates": independently_rendered
                .contrast_samples
                .iter()
                .map(|sample| [sample.x, sample.y])
                .collect::<Vec<_>>(),
        }),
        json!({"ratio_milli": job.brand_profile.minimum_text_contrast_milli}),
    )?);

    let pixels_match = decoded.pixels == independently_rendered.pixels;
    observations.push(observation(
        "raster.render_reproduction",
        "render_reproducibility",
        pixels_match,
        json!({
            "decoded_digest": sha256_hex(&decoded.pixels),
            "rendered_digest": sha256_hex(&independently_rendered.pixels),
        }),
        json!("equal"),
    )?);
    observations.push(observation(
        "raster.media_type",
        "export_media_type",
        true,
        json!("image/png"),
        json!("image/png"),
    )?);

    let mandatory_claims = [
        "canvas_width",
        "canvas_height",
        "color_profile",
        "logo_aspect_ratio",
        "logo_clear_space",
        "text_within_safe_area",
        "minimum_text_contrast",
        "export_media_type",
    ];
    let all_mandatory_passed = mandatory_claims.iter().all(|claim| {
        observations
            .iter()
            .filter(|observation| observation.claim_id == *claim)
            .all(|observation| observation.passed)
    });

    let mut report = GraphicValidationReport {
        schema_version: REPORT_SCHEMA.to_owned(),
        job_id: job.job_id.clone(),
        document_digest,
        raster_digest,
        all_mandatory_passed,
        observations,
        report_digest: String::new(),
    };
    report.report_digest = report_digest(&report)?;
    Ok((document, report))
}

pub fn verify_validation_report_digest(
    report: &GraphicValidationReport,
) -> Result<bool, ValidationError> {
    Ok(report.report_digest == report_digest(report)?)
}

pub fn proof_evidence_from_report(
    job: &GraphicDesignJob,
    report: &GraphicValidationReport,
    contract_digest: &str,
) -> Vec<EvidenceRecord> {
    let obligations: BTreeMap<&str, &str> = BTreeMap::from([
        ("canvas_width", "proof.canvas_width"),
        ("canvas_height", "proof.canvas_height"),
        ("color_profile", "proof.color_profile"),
        ("logo_aspect_ratio", "proof.logo_aspect_ratio"),
        ("logo_clear_space", "proof.logo_clear_space"),
        ("text_within_safe_area", "proof.text_within_safe_area"),
        ("minimum_text_contrast", "proof.minimum_text_contrast"),
        ("export_media_type", "proof.export_media_type"),
    ]);
    report
        .observations
        .iter()
        .filter_map(|observation| {
            let obligation_id = obligations.get(observation.claim_id.as_str())?;
            let subject_digest = if observation.validator_id.starts_with("document.") {
                report.document_digest.clone()
            } else {
                report.raster_digest.clone()
            };
            Some(EvidenceRecord {
                evidence_id: format!(
                    "evidence.{}.{}.{}",
                    job.job_id, observation.validator_id, observation.claim_id
                ),
                obligation_id: (*obligation_id).to_owned(),
                constraint_id: observation.claim_id.clone(),
                contract_digest: contract_digest.to_owned(),
                subject_digest,
                validator_id: observation.validator_id.clone(),
                validator_version: observation.validator_version.clone(),
                result: if observation.passed {
                    TruthValue::True
                } else {
                    TruthValue::False
                },
                independence: IndependenceClass::Independent,
                observed_at: job.evaluated_at.clone(),
            })
        })
        .collect()
}

fn observation(
    validator_id: &str,
    claim_id: &str,
    passed: bool,
    observed: Value,
    expected: Value,
) -> Result<ValidatorObservation, ValidationError> {
    let evidence_value = json!({
        "validator_id": validator_id,
        "validator_version": VALIDATOR_VERSION,
        "claim_id": claim_id,
        "passed": passed,
        "observed": observed,
        "expected": expected,
    });
    Ok(ValidatorObservation {
        validator_id: validator_id.to_owned(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        claim_id: claim_id.to_owned(),
        passed,
        observed: evidence_value["observed"].clone(),
        expected: evidence_value["expected"].clone(),
        evidence_digest: canonical_json_sha256(&evidence_value)?,
    })
}

fn report_digest(report: &GraphicValidationReport) -> Result<String, ValidationError> {
    let value = json!({
        "schema_version": report.schema_version,
        "job_id": report.job_id,
        "document_digest": report.document_digest,
        "raster_digest": report.raster_digest,
        "all_mandatory_passed": report.all_mandatory_passed,
        "observations": report.observations,
    });
    Ok(canonical_json_sha256(&value)?)
}

fn contains(outer: PixelRect, inner: PixelRect) -> bool {
    inner.x >= outer.x
        && inner.y >= outer.y
        && inner
            .x
            .checked_add(inner.width)
            .zip(outer.x.checked_add(outer.width))
            .is_some_and(|(inner_right, outer_right)| inner_right <= outer_right)
        && inner
            .y
            .checked_add(inner.height)
            .zip(outer.y.checked_add(outer.height))
            .is_some_and(|(inner_bottom, outer_bottom)| inner_bottom <= outer_bottom)
}

fn minimum_logo_clear_space(
    logo: PixelRect,
    canvas_width: u32,
    canvas_height: u32,
    neighbors: &[PixelRect],
) -> u32 {
    let right = canvas_width.saturating_sub(logo.x.saturating_add(logo.width));
    let bottom = canvas_height.saturating_sub(logo.y.saturating_add(logo.height));
    let mut minimum = logo.x.min(logo.y).min(right).min(bottom);
    for neighbor in neighbors {
        minimum = minimum.min(rect_gap(logo, *neighbor));
    }
    minimum
}

fn rect_gap(left: PixelRect, right: PixelRect) -> u32 {
    let left_right = left.x.saturating_add(left.width);
    let right_right = right.x.saturating_add(right.width);
    let left_bottom = left.y.saturating_add(left.height);
    let right_bottom = right.y.saturating_add(right.height);
    let horizontal = if left_right <= right.x {
        right.x - left_right
    } else if right_right <= left.x {
        left.x - right_right
    } else {
        0
    };
    let vertical = if left_bottom <= right.y {
        right.y - left_bottom
    } else if right_bottom <= left.y {
        left.y - right_bottom
    } else {
        0
    };
    match (horizontal, vertical) {
        (0, 0) => 0,
        (0, value) | (value, 0) => value,
        (horizontal, vertical) => horizontal.min(vertical),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
