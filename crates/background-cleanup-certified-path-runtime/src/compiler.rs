use ergaxiom_contract_runtime::{ContractCompileError, compile_contract};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde_json::{Value, json};
use thiserror::Error;

use crate::model::{
    BackgroundCleanupCompileOutcome, BackgroundCleanupIntent, CleanupArtifactIntent,
    CleanupResolutionRequest,
};

pub const BACKGROUND_CLEANUP_JOB_TYPE: &str = "image_background_cleanup";
pub const GRAPHIC_DESIGNER_CAPSULE_ID: &str = "ergaxiom.profession.graphic-designer";
const CONTRACT_SCHEMA: &str = "0.2.0";
const SPECIALIZATION: &str = "image_editing";
const PNG_MEDIA_TYPE: &str = "image/png";
const MAXIMUM_EDGE: u32 = 32_768;

#[derive(Debug, Error)]
pub enum BackgroundCleanupCompileError {
    #[error("loaded capsule field is missing or invalid: {0}")]
    InvalidCapsuleField(&'static str),
    #[error("loaded capsule ID {actual} is unsupported; expected {expected}")]
    UnsupportedCapsule {
        actual: String,
        expected: &'static str,
    },
    #[error("loaded capsule does not declare the image_background_cleanup job type")]
    MissingJobType,
    #[error("intent field {field} is invalid: {reason}")]
    InvalidIntentField { field: String, reason: String },
    #[error("internal compiler invariant failed because resolved field is unavailable: {0}")]
    MissingResolvedField(String),
    #[error("failed to serialize background-cleanup compiler material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Contract(#[from] ContractCompileError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn compile_background_cleanup_intent(
    intent: &BackgroundCleanupIntent,
    capsule_value: &Value,
) -> Result<BackgroundCleanupCompileOutcome, BackgroundCleanupCompileError> {
    validate_capsule(capsule_value)?;
    validate_present_values(intent)?;

    let resolution_requests = missing_resolution_requests(intent);
    if !resolution_requests.is_empty() {
        let resolution_value = serde_json::to_value(&resolution_requests)?;
        return Ok(BackgroundCleanupCompileOutcome::NeedsResolution {
            job_type: BACKGROUND_CLEANUP_JOB_TYPE.to_owned(),
            resolution_digest: canonical_json_sha256(&resolution_value)?,
            resolution_requests,
        });
    }

    let contract = build_background_cleanup_contract(intent, capsule_value)?;
    let compiled = compile_contract(&contract, capsule_value)?;
    if compiled.unresolved_mandatory_unknowns != 0 {
        return Err(invalid(
            "requirements.unknowns",
            "a completed compiler result must not retain unresolved mandatory unknowns",
        ));
    }

    Ok(BackgroundCleanupCompileOutcome::Compiled {
        job_type: BACKGROUND_CLEANUP_JOB_TYPE.to_owned(),
        contract,
        contract_digest: compiled.seal.contract_digest.clone(),
        capsule_digest: compiled.seal.capsule_digest.clone(),
        proof_obligation_count: compiled.proof_obligation_count(),
        unresolved_mandatory_unknowns: compiled.unresolved_mandatory_unknowns,
    })
}

pub fn build_background_cleanup_contract(
    intent: &BackgroundCleanupIntent,
    capsule: &Value,
) -> Result<Value, BackgroundCleanupCompileError> {
    let capsule_version = capsule.get("version").and_then(Value::as_str).ok_or(
        BackgroundCleanupCompileError::InvalidCapsuleField("version"),
    )?;
    let contract_id = resolved(intent.contract_id.as_deref(), "contract_id")?;
    let created_at = resolved(intent.created_at.as_deref(), "created_at")?;
    let original_text = resolved(intent.original_text.as_deref(), "original_text")?;
    let language = resolved(intent.language.as_deref(), "language")?;
    let width = resolved_copy(intent.source_width_px, "source_width_px")?;
    let height = resolved_copy(intent.source_height_px, "source_height_px")?;
    let required_application_version = resolved(
        intent.required_application_version.as_deref(),
        "required_application_version",
    )?;

    let source = artifact_value("source_raster", "source_raster", &intent.source_raster)?;
    let mask = artifact_value(
        "approved_cleanup_mask",
        "approved_cleanup_mask",
        &intent.approved_cleanup_mask,
    )?;
    let preferences = intent
        .visual_preference
        .as_ref()
        .map_or_else(Vec::new, |description| {
            vec![json!({
                "id": "edge_quality_review",
                "description": description,
                "weight": 1,
                "evaluation_mode": "human_review"
            })]
        });

    Ok(json!({
        "schema_version": CONTRACT_SCHEMA,
        "contract_id": contract_id,
        "created_at": created_at,
        "request": {
            "original_text": original_text,
            "language": language,
            "requester_id": intent.requester_id
        },
        "profession": {
            "capsule_id": GRAPHIC_DESIGNER_CAPSULE_ID,
            "capsule_version": capsule_version,
            "specialization": SPECIALIZATION
        },
        "job_type": BACKGROUND_CLEANUP_JOB_TYPE,
        "environment": {
            "os": "windows",
            "applications": [{
                "application_id": "org.inkscape.Inkscape",
                "required_version": required_application_version
            }],
            "network_mode": "denied"
        },
        "inputs": [source, mask],
        "outputs": [
            {
                "id": "cleaned_raster",
                "kind": "cleaned_raster",
                "destination": "contract://outputs/background-cleaned.png",
                "media_type": PNG_MEDIA_TYPE,
                "required": true
            },
            {
                "id": "integration_probe",
                "kind": "integration_probe_raster",
                "destination": "contract://outputs/background-cleanup-probe.png",
                "media_type": PNG_MEDIA_TYPE,
                "required": true
            },
            {
                "id": "evidence_bundle",
                "kind": "evidence_bundle",
                "destination": "contract://outputs/background-cleanup-evidence.json",
                "media_type": "application/json",
                "required": true
            }
        ],
        "requirements": {
            "hard": [
                constraint("cleaned_width", format!("The cleaned PNG width is exactly {width} pixels."), "cleaned_raster.width", "eq", json!(width), Some("px"), "trusted_source_metadata"),
                constraint("cleaned_height", format!("The cleaned PNG height is exactly {height} pixels."), "cleaned_raster.height", "eq", json!(height), Some("px"), "trusted_source_metadata"),
                constraint("mask_dimensions_match", "The approved cleanup mask dimensions exactly match the source raster.".to_owned(), "approved_cleanup_mask.dimensions_match_source", "eq", json!(true), None, "approved_cleanup_mask"),
                constraint("mask_is_binary", "Every approved cleanup-mask alpha sample is exactly 0 or 255.".to_owned(), "approved_cleanup_mask.binary_alpha", "eq", json!(true), None, "approved_cleanup_mask"),
                constraint("mask_foreground_pixels", "The approved cleanup mask contains at least one foreground pixel.".to_owned(), "approved_cleanup_mask.foreground_pixels", "gte", json!(1), Some("count"), "approved_cleanup_mask"),
                constraint("mask_background_pixels", "The approved cleanup mask contains at least one background pixel.".to_owned(), "approved_cleanup_mask.background_pixels", "gte", json!(1), Some("count"), "approved_cleanup_mask"),
                constraint("background_alpha_violations", "Every pixel declared as background is fully transparent in the cleaned PNG.".to_owned(), "cleaned_raster.background_alpha_violations", "eq", json!(0), Some("count"), "approved_cleanup_mask"),
                constraint("foreground_rgba_violations", "Every pixel declared as foreground preserves the exact source RGBA sample.".to_owned(), "cleaned_raster.foreground_rgba_violations", "eq", json!(0), Some("count"), "source_raster"),
                constraint("output_media_type", "The cleaned artifact is a structurally valid PNG image.".to_owned(), "cleaned_raster.media_type", "eq", json!(PNG_MEDIA_TYPE), None, "certified_job_profile"),
                constraint("color_profile", "The cleaned PNG contains the restricted sRGB profile signal.".to_owned(), "cleaned_raster.color_profile", "eq", json!("sRGB IEC61966-2.1"), None, "certified_job_profile"),
                constraint("source_immutable", "The exact source-raster bytes remain unchanged throughout execution.".to_owned(), "source_raster.immutable", "eq", json!(true), None, "execution_record"),
                constraint("inkscape_probe_verified", "The cleaned PNG is imported and exported through the pinned Inkscape integration probe with matching dimensions.".to_owned(), "integration_probe.verified", "eq", json!(true), None, "trusted_application_identity")
            ],
            "preferences": preferences,
            "unknowns": []
        },
        "permissions": [
            {
                "capability": "filesystem",
                "resource": "contract://inputs/*",
                "access": "read",
                "constraints": {"immutable": true}
            },
            {
                "capability": "filesystem",
                "resource": "contract://outputs/*",
                "access": "write",
                "constraints": {"overwrite": false}
            },
            {
                "capability": "cleanup-runtime",
                "resource": "isolated-workspace",
                "access": "control",
                "constraints": {"network": false}
            },
            {
                "capability": "design-editor",
                "resource": "integration-probe",
                "access": "control",
                "constraints": {"network": false}
            }
        ],
        "proof_obligations": proof_obligations(),
        "approval_policy": {
            "require_pre_execution_approval": intent.require_pre_execution_approval,
            "require_irreversible_action_approval": true,
            "approval_ttl_seconds": 300
        },
        "acceptance": {
            "minimum_assurance_level": "E3",
            "unknowns_must_be_empty": true,
            "all_mandatory_proofs_must_pass": true,
            "validator_conflicts_allowed": false
        },
        "metadata": {
            "compiler": "ergaxiom-background-cleanup-certified-path-runtime",
            "compiler_version": "0.1.0",
            "intent_kind": BACKGROUND_CLEANUP_JOB_TYPE,
            "mask_policy": "digest_bound_binary_alpha",
            "subjective_edge_quality_is_hard_acceptance": false,
            "deterministic": true,
            "implicit_defaults": false
        }
    }))
}

fn validate_capsule(capsule: &Value) -> Result<(), BackgroundCleanupCompileError> {
    let capsule_id = capsule.get("capsule_id").and_then(Value::as_str).ok_or(
        BackgroundCleanupCompileError::InvalidCapsuleField("capsule_id"),
    )?;
    if capsule_id != GRAPHIC_DESIGNER_CAPSULE_ID {
        return Err(BackgroundCleanupCompileError::UnsupportedCapsule {
            actual: capsule_id.to_owned(),
            expected: GRAPHIC_DESIGNER_CAPSULE_ID,
        });
    }
    capsule
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(BackgroundCleanupCompileError::InvalidCapsuleField(
            "version",
        ))?;
    let has_job = capsule
        .get("job_types")
        .and_then(Value::as_array)
        .is_some_and(|jobs| {
            jobs.iter().any(|job| {
                job.get("id").and_then(Value::as_str) == Some(BACKGROUND_CLEANUP_JOB_TYPE)
            })
        });
    if !has_job {
        return Err(BackgroundCleanupCompileError::MissingJobType);
    }
    Ok(())
}

fn validate_present_values(
    intent: &BackgroundCleanupIntent,
) -> Result<(), BackgroundCleanupCompileError> {
    validate_optional_text("contract_id", intent.contract_id.as_deref(), 1)?;
    validate_timestamp(intent.created_at.as_deref())?;
    validate_optional_text("original_text", intent.original_text.as_deref(), 1)?;
    validate_optional_text("language", intent.language.as_deref(), 2)?;
    validate_optional_text("requester_id", intent.requester_id.as_deref(), 1)?;
    validate_optional_text("visual_preference", intent.visual_preference.as_deref(), 1)?;
    validate_optional_text(
        "required_application_version",
        intent.required_application_version.as_deref(),
        1,
    )?;
    validate_artifact("source_raster", &intent.source_raster)?;
    validate_artifact("approved_cleanup_mask", &intent.approved_cleanup_mask)?;
    if let Some(width) = intent.source_width_px {
        validate_edge("source_width_px", width)?;
    }
    if let Some(height) = intent.source_height_px {
        validate_edge("source_height_px", height)?;
    }
    Ok(())
}

fn validate_timestamp(value: Option<&str>) -> Result<(), BackgroundCleanupCompileError> {
    if let Some(value) = value {
        if value.len() < 20 || !value.contains('T') || !value.ends_with('Z') {
            return Err(invalid(
                "created_at",
                "must be a caller-supplied UTC RFC 3339 timestamp ending in Z",
            ));
        }
    }
    Ok(())
}

fn validate_optional_text(
    field: &str,
    value: Option<&str>,
    minimum_length: usize,
) -> Result<(), BackgroundCleanupCompileError> {
    if let Some(value) = value {
        if value.trim().len() < minimum_length {
            return Err(invalid(field, "must not be empty or whitespace-only"));
        }
        if value.contains('\0') {
            return Err(invalid(field, "must not contain NUL"));
        }
    }
    Ok(())
}

fn validate_artifact(
    prefix: &str,
    artifact: &CleanupArtifactIntent,
) -> Result<(), BackgroundCleanupCompileError> {
    if let Some(uri) = artifact.uri.as_deref() {
        if !uri.starts_with("contract://inputs/") || uri.len() <= "contract://inputs/".len() {
            return Err(invalid(
                &format!("{prefix}.uri"),
                "must use a non-empty contract://inputs/ URI",
            ));
        }
    }
    if let Some(media_type) = artifact.media_type.as_deref() {
        if media_type != PNG_MEDIA_TYPE {
            return Err(invalid(
                &format!("{prefix}.media_type"),
                "the certified v1 cleanup path accepts only image/png",
            ));
        }
    }
    if let Some(digest) = artifact.sha256.as_deref() {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid(
                &format!("{prefix}.sha256"),
                "must be exactly 64 lowercase hexadecimal characters",
            ));
        }
    }
    Ok(())
}

fn validate_edge(field: &str, value: u32) -> Result<(), BackgroundCleanupCompileError> {
    if value == 0 || value > MAXIMUM_EDGE {
        return Err(invalid(field, "must be between 1 and 32768 pixels"));
    }
    Ok(())
}

fn missing_resolution_requests(intent: &BackgroundCleanupIntent) -> Vec<CleanupResolutionRequest> {
    let mut requests = Vec::new();
    push_missing(
        &mut requests,
        intent.contract_id.is_none(),
        "contract_id",
        "What stable identifier should be assigned to this cleanup Work Contract?",
        "The identifier is part of the canonical contract seal and cannot be generated implicitly.",
        &["user_answer", "trusted_orchestrator"],
    );
    push_missing(
        &mut requests,
        intent.created_at.is_none(),
        "created_at",
        "What trusted UTC timestamp should be sealed into the cleanup contract?",
        "The compiler does not read the runtime clock because hidden time defaults break replay.",
        &["trusted_clock"],
    );
    push_missing(
        &mut requests,
        intent.original_text.is_none(),
        "original_text",
        "What exact user request should be preserved?",
        "The original request must remain auditable and must not be rewritten as fact.",
        &["user_answer"],
    );
    push_missing(
        &mut requests,
        intent.language.is_none(),
        "language",
        "What language code describes the original request?",
        "Language is required for deterministic interpretation and audit.",
        &["user_answer", "trusted_locale"],
    );
    append_artifact_requests(&mut requests, "source_raster", &intent.source_raster);
    append_artifact_requests(
        &mut requests,
        "approved_cleanup_mask",
        &intent.approved_cleanup_mask,
    );
    push_missing(
        &mut requests,
        intent.source_width_px.is_none(),
        "source_width_px",
        "What width was independently decoded from the source PNG?",
        "The cleanup path preserves source dimensions and does not infer them later.",
        &["trusted_decoder"],
    );
    push_missing(
        &mut requests,
        intent.source_height_px.is_none(),
        "source_height_px",
        "What height was independently decoded from the source PNG?",
        "The cleanup path preserves source dimensions and does not infer them later.",
        &["trusted_decoder"],
    );
    push_missing(
        &mut requests,
        intent.required_application_version.is_none(),
        "required_application_version",
        "Which pinned Inkscape version must execute the integration probe?",
        "Application identity and version are mandatory certification evidence.",
        &["trusted_application_inventory"],
    );
    requests
}

fn append_artifact_requests(
    requests: &mut Vec<CleanupResolutionRequest>,
    prefix: &str,
    artifact: &CleanupArtifactIntent,
) {
    let display = prefix.replace('_', " ");
    push_missing(
        requests,
        artifact.uri.is_none(),
        &format!("{prefix}.uri"),
        &format!("What immutable contract URI contains the {display}?"),
        "Every accepted input must be resource-scoped.",
        &["trusted_upload", "user_answer"],
    );
    push_missing(
        requests,
        artifact.media_type.is_none(),
        &format!("{prefix}.media_type"),
        &format!("What media type was independently identified for the {display}?"),
        "File extensions are not accepted as media-type proof.",
        &["trusted_decoder"],
    );
    push_missing(
        requests,
        artifact.sha256.is_none(),
        &format!("{prefix}.sha256"),
        &format!("What SHA-256 digest identifies the exact {display} bytes?"),
        "Input bytes must be sealed before planning or execution.",
        &["trusted_hasher"],
    );
}

fn push_missing(
    requests: &mut Vec<CleanupResolutionRequest>,
    missing: bool,
    field: &str,
    question: &str,
    reason: &str,
    accepted_sources: &[&str],
) {
    if missing {
        requests.push(CleanupResolutionRequest {
            field: field.to_owned(),
            question: question.to_owned(),
            reason: reason.to_owned(),
            accepted_sources: accepted_sources
                .iter()
                .map(|source| (*source).to_owned())
                .collect(),
        });
    }
}

fn artifact_value(
    id: &str,
    kind: &str,
    artifact: &CleanupArtifactIntent,
) -> Result<Value, BackgroundCleanupCompileError> {
    Ok(json!({
        "id": id,
        "kind": kind,
        "uri": resolved(artifact.uri.as_deref(), &format!("{id}.uri"))?,
        "integrity": {
            "algorithm": "sha256",
            "digest": resolved(artifact.sha256.as_deref(), &format!("{id}.sha256"))?
        },
        "media_type": resolved(artifact.media_type.as_deref(), &format!("{id}.media_type"))?,
        "immutable": true
    }))
}

fn constraint(
    id: &str,
    claim: String,
    subject: &str,
    operator: &str,
    expected: Value,
    unit: Option<&str>,
    source: &str,
) -> Value {
    json!({
        "id": id,
        "claim": claim,
        "subject": subject,
        "operator": operator,
        "expected": expected,
        "unit": unit,
        "tolerance": 0,
        "mandatory": true,
        "source": source
    })
}

fn proof_obligations() -> Vec<Value> {
    vec![
        obligation(
            "proof.cleaned_width",
            "cleaned_width",
            "cleanup.png.structure",
            &["decoded_image_metadata", "measurement_record"],
        ),
        obligation(
            "proof.cleaned_height",
            "cleaned_height",
            "cleanup.png.structure",
            &["decoded_image_metadata", "measurement_record"],
        ),
        obligation(
            "proof.mask_dimensions_match",
            "mask_dimensions_match",
            "cleanup.mask.dimensions",
            &["decoded_image_metadata", "dimension_comparison"],
        ),
        obligation(
            "proof.mask_is_binary",
            "mask_is_binary",
            "cleanup.mask.binary",
            &["decoded_mask_pixels", "mask_histogram"],
        ),
        obligation(
            "proof.mask_foreground_pixels",
            "mask_foreground_pixels",
            "cleanup.mask.binary",
            &["decoded_mask_pixels", "mask_histogram"],
        ),
        obligation(
            "proof.mask_background_pixels",
            "mask_background_pixels",
            "cleanup.mask.binary",
            &["decoded_mask_pixels", "mask_histogram"],
        ),
        obligation(
            "proof.background_alpha_violations",
            "background_alpha_violations",
            "cleanup.alpha.background",
            &["decoded_output_pixels", "mask_bound_comparison"],
        ),
        obligation(
            "proof.foreground_rgba_violations",
            "foreground_rgba_violations",
            "cleanup.foreground.preservation",
            &[
                "decoded_source_pixels",
                "decoded_output_pixels",
                "mask_bound_comparison",
            ],
        ),
        obligation(
            "proof.output_media_type",
            "output_media_type",
            "cleanup.png.structure",
            &["magic_bytes", "decoded_image_metadata"],
        ),
        obligation(
            "proof.color_profile",
            "color_profile",
            "cleanup.png.structure",
            &["png_chunk_evidence", "decoded_image_metadata"],
        ),
        obligation(
            "proof.source_immutable",
            "source_immutable",
            "cleanup.source.immutability",
            &["pre_execution_digest", "post_execution_digest"],
        ),
        obligation(
            "proof.inkscape_probe_verified",
            "inkscape_probe_verified",
            "cleanup.inkscape.integration",
            &[
                "application_identity",
                "adapter_receipt",
                "decoded_image_metadata",
            ],
        ),
    ]
}

fn obligation(id: &str, constraint_id: &str, validator_id: &str, evidence_types: &[&str]) -> Value {
    json!({
        "id": id,
        "constraint_id": constraint_id,
        "validator_ids": [validator_id],
        "mandatory": true,
        "independence_class": "independent",
        "evidence_types": evidence_types
    })
}

fn resolved<'a>(
    value: Option<&'a str>,
    field: &str,
) -> Result<&'a str, BackgroundCleanupCompileError> {
    value.ok_or_else(|| BackgroundCleanupCompileError::MissingResolvedField(field.to_owned()))
}

fn resolved_copy<T: Copy>(
    value: Option<T>,
    field: &str,
) -> Result<T, BackgroundCleanupCompileError> {
    value.ok_or_else(|| BackgroundCleanupCompileError::MissingResolvedField(field.to_owned()))
}

fn invalid(field: &str, reason: &str) -> BackgroundCleanupCompileError {
    BackgroundCleanupCompileError::InvalidIntentField {
        field: field.to_owned(),
        reason: reason.to_owned(),
    }
}
