#![forbid(unsafe_code)]

use ergaxiom_contract_runtime::{ContractCompileError, compile_contract};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value, json};
use thiserror::Error;

const SCHEMA_VERSION: &str = "0.2.0";
const CAPSULE_ID: &str = "ergaxiom.profession.graphic-designer";
const JOB_TYPE: &str = "social_media_static_post";
const SPECIALIZATION: &str = "social_media_design";
const CERTIFIED_COLOR_PROFILE: &str = "sRGB IEC61966-2.1";
const MINIMUM_CERTIFIED_CONTRAST_MILLI: u32 = 4_500;
const MAXIMUM_CONTRAST_MILLI: u32 = 21_000;
const MAXIMUM_CANVAS_EDGE_PX: u32 = 32_768;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InputArtifactIntent {
    pub uri: Option<String>,
    pub media_type: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StaticSocialPostIntent {
    pub contract_id: Option<String>,
    pub created_at: Option<String>,
    pub original_text: Option<String>,
    pub language: Option<String>,
    pub requester_id: Option<String>,
    pub approved_logo: InputArtifactIntent,
    pub brand_profile: InputArtifactIntent,
    pub approved_copy: InputArtifactIntent,
    pub canvas_width_px: Option<u32>,
    pub canvas_height_px: Option<u32>,
    pub color_profile: Option<String>,
    pub logo_clear_space_px: Option<u32>,
    pub minimum_text_contrast_milli: Option<u32>,
    pub visual_tone: Option<String>,
    pub required_application_version: Option<String>,
    pub require_pre_execution_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionRequest {
    pub field: String,
    pub question: String,
    pub reason: String,
    pub accepted_sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentCompileOutcome {
    NeedsResolution {
        intent_kind: String,
        resolution_requests: Vec<ResolutionRequest>,
        resolution_digest: String,
    },
    Compiled {
        intent_kind: String,
        contract: Value,
        contract_digest: String,
        capsule_digest: String,
        proof_obligation_count: usize,
        unresolved_mandatory_unknowns: usize,
    },
}

#[derive(Debug, Error)]
pub enum IntentContractCompileError {
    #[error("loaded capsule field is missing or invalid: {0}")]
    InvalidCapsuleField(&'static str),
    #[error("loaded capsule ID {actual} is unsupported; expected {expected}")]
    UnsupportedCapsule { actual: String, expected: &'static str },
    #[error("intent field {field} is invalid: {reason}")]
    InvalidIntentField { field: &'static str, reason: String },
    #[error("intent field {field} uses unsupported certified value {actual:?}: {reason}")]
    UnsupportedCertifiedValue {
        field: &'static str,
        actual: String,
        reason: &'static str,
    },
    #[error("internal compiler invariant failed because resolved field is unavailable: {0}")]
    MissingResolvedField(&'static str),
    #[error("failed to encode a deterministic decimal value: {0}")]
    InvalidDecimal(String),
    #[error("failed to serialize intent compiler material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Contract(#[from] ContractCompileError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn compile_static_social_post_intent(
    intent: &StaticSocialPostIntent,
    capsule_value: &Value,
) -> Result<IntentCompileOutcome, IntentContractCompileError> {
    validate_capsule(capsule_value)?;
    validate_present_values(intent)?;

    let resolution_requests = missing_resolution_requests(intent);
    if !resolution_requests.is_empty() {
        let resolution_value = serde_json::to_value(&resolution_requests)?;
        return Ok(IntentCompileOutcome::NeedsResolution {
            intent_kind: JOB_TYPE.to_owned(),
            resolution_digest: canonical_json_sha256(&resolution_value)?,
            resolution_requests,
        });
    }

    let contract = build_contract(intent, capsule_value)?;
    let compiled = compile_contract(&contract, capsule_value)?;
    if compiled.unresolved_mandatory_unknowns != 0 {
        return Err(IntentContractCompileError::InvalidIntentField {
            field: "requirements.unknowns",
            reason: "a completed compiler result must not retain unresolved mandatory unknowns"
                .to_owned(),
        });
    }

    Ok(IntentCompileOutcome::Compiled {
        intent_kind: JOB_TYPE.to_owned(),
        contract,
        contract_digest: compiled.seal.contract_digest,
        capsule_digest: compiled.seal.capsule_digest,
        proof_obligation_count: compiled.proof_obligation_count(),
        unresolved_mandatory_unknowns: compiled.unresolved_mandatory_unknowns,
    })
}

fn validate_capsule(capsule: &Value) -> Result<(), IntentContractCompileError> {
    let capsule_id = capsule
        .get("capsule_id")
        .and_then(Value::as_str)
        .ok_or(IntentContractCompileError::InvalidCapsuleField("capsule_id"))?;
    if capsule_id != CAPSULE_ID {
        return Err(IntentContractCompileError::UnsupportedCapsule {
            actual: capsule_id.to_owned(),
            expected: CAPSULE_ID,
        });
    }
    capsule
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(IntentContractCompileError::InvalidCapsuleField("version"))?;
    Ok(())
}

fn validate_present_values(
    intent: &StaticSocialPostIntent,
) -> Result<(), IntentContractCompileError> {
    validate_optional_text("contract_id", intent.contract_id.as_deref(), 1)?;
    if let Some(created_at) = intent.created_at.as_deref() {
        if created_at.len() < 20 || !created_at.contains('T') || !created_at.ends_with('Z') {
            return Err(invalid(
                "created_at",
                "must be a caller-supplied UTC RFC 3339 timestamp ending in Z",
            ));
        }
    }
    validate_optional_text("original_text", intent.original_text.as_deref(), 1)?;
    validate_optional_text("language", intent.language.as_deref(), 2)?;
    validate_optional_text("requester_id", intent.requester_id.as_deref(), 1)?;
    validate_optional_text("visual_tone", intent.visual_tone.as_deref(), 1)?;
    validate_optional_text(
        "required_application_version",
        intent.required_application_version.as_deref(),
        1,
    )?;

    validate_artifact("approved_logo", &intent.approved_logo)?;
    validate_artifact("brand_profile", &intent.brand_profile)?;
    validate_artifact("approved_copy", &intent.approved_copy)?;

    if let Some(width) = intent.canvas_width_px {
        validate_canvas_edge("canvas_width_px", width)?;
    }
    if let Some(height) = intent.canvas_height_px {
        validate_canvas_edge("canvas_height_px", height)?;
    }
    if let Some(profile) = intent.color_profile.as_deref() {
        if profile != CERTIFIED_COLOR_PROFILE {
            return Err(IntentContractCompileError::UnsupportedCertifiedValue {
                field: "color_profile",
                actual: profile.to_owned(),
                reason: "v1 certification supports only the restricted sRGB proof path",
            });
        }
    }
    if let Some(clear_space) = intent.logo_clear_space_px {
        if clear_space == 0 {
            return Err(invalid(
                "logo_clear_space_px",
                "must be greater than zero",
            ));
        }
    }
    if let Some(contrast) = intent.minimum_text_contrast_milli {
        if !(MINIMUM_CERTIFIED_CONTRAST_MILLI..=MAXIMUM_CONTRAST_MILLI).contains(&contrast) {
            return Err(invalid(
                "minimum_text_contrast_milli",
                "must be between 4500 and 21000 for the certified WCAG text path",
            ));
        }
    }
    if let (Some(width), Some(height), Some(clear_space)) = (
        intent.canvas_width_px,
        intent.canvas_height_px,
        intent.logo_clear_space_px,
    ) {
        if clear_space.saturating_mul(2) >= width.min(height) {
            return Err(invalid(
                "logo_clear_space_px",
                "twice the clear-space requirement must be smaller than the shortest canvas edge",
            ));
        }
    }
    Ok(())
}

fn validate_optional_text(
    field: &'static str,
    value: Option<&str>,
    minimum_length: usize,
) -> Result<(), IntentContractCompileError> {
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
    prefix: &'static str,
    artifact: &InputArtifactIntent,
) -> Result<(), IntentContractCompileError> {
    if let Some(uri) = artifact.uri.as_deref() {
        if !uri.starts_with("contract://inputs/") || uri.len() <= "contract://inputs/".len() {
            return Err(invalid(
                artifact_field(prefix, "uri"),
                "must use a non-empty contract://inputs/ URI",
            ));
        }
    }
    if let Some(media_type) = artifact.media_type.as_deref() {
        if media_type.trim().is_empty() || !media_type.contains('/') {
            return Err(invalid(
                artifact_field(prefix, "media_type"),
                "must be a non-empty MIME media type",
            ));
        }
    }
    if let Some(digest) = artifact.sha256.as_deref() {
        if !is_lowercase_sha256(digest) {
            return Err(invalid(
                artifact_field(prefix, "sha256"),
                "must be exactly 64 lowercase hexadecimal characters",
            ));
        }
    }
    Ok(())
}

fn artifact_field(prefix: &'static str, suffix: &'static str) -> &'static str {
    match (prefix, suffix) {
        ("approved_logo", "uri") => "approved_logo.uri",
        ("approved_logo", "media_type") => "approved_logo.media_type",
        ("approved_logo", "sha256") => "approved_logo.sha256",
        ("brand_profile", "uri") => "brand_profile.uri",
        ("brand_profile", "media_type") => "brand_profile.media_type",
        ("brand_profile", "sha256") => "brand_profile.sha256",
        ("approved_copy", "uri") => "approved_copy.uri",
        ("approved_copy", "media_type") => "approved_copy.media_type",
        ("approved_copy", "sha256") => "approved_copy.sha256",
        _ => "artifact",
    }
}

fn validate_canvas_edge(
    field: &'static str,
    value: u32,
) -> Result<(), IntentContractCompileError> {
    if value == 0 || value > MAXIMUM_CANVAS_EDGE_PX {
        return Err(invalid(
            field,
            "must be between 1 and 32768 pixels",
        ));
    }
    Ok(())
}

fn invalid(field: &'static str, reason: &str) -> IntentContractCompileError {
    IntentContractCompileError::InvalidIntentField {
        field,
        reason: reason.to_owned(),
    }
}

fn missing_resolution_requests(intent: &StaticSocialPostIntent) -> Vec<ResolutionRequest> {
    let mut requests = Vec::new();
    push_missing(
        &mut requests,
        intent.contract_id.is_none(),
        "contract_id",
        "What stable identifier should be assigned to this work contract?",
        "The identifier is part of the canonical contract seal and cannot be generated implicitly.",
        &["user_answer", "trusted_orchestrator"],
    );
    push_missing(
        &mut requests,
        intent.created_at.is_none(),
        "created_at",
        "What trusted UTC creation timestamp should be sealed into the contract?",
        "Using the runtime clock implicitly would make compilation nondeterministic.",
        &["trusted_clock"],
    );
    push_missing(
        &mut requests,
        intent.original_text.is_none(),
        "original_text",
        "What exact user request should be preserved in the contract?",
        "The compiler must retain the original intent without rewriting it as fact.",
        &["user_answer"],
    );
    push_missing(
        &mut requests,
        intent.language.is_none(),
        "language",
        "What language code describes the original request?",
        "Language is required for later interpretation and audit.",
        &["user_answer", "trusted_locale"],
    );
    append_artifact_requests(&mut requests, "approved_logo", &intent.approved_logo);
    append_artifact_requests(&mut requests, "brand_profile", &intent.brand_profile);
    append_artifact_requests(&mut requests, "approved_copy", &intent.approved_copy);
    push_missing(
        &mut requests,
        intent.canvas_width_px.is_none(),
        "canvas_width_px",
        "What exact output width is required in pixels?",
        "Canvas dimensions are mandatory and independently validated.",
        &["user_answer", "trusted_platform_profile"],
    );
    push_missing(
        &mut requests,
        intent.canvas_height_px.is_none(),
        "canvas_height_px",
        "What exact output height is required in pixels?",
        "Canvas dimensions are mandatory and independently validated.",
        &["user_answer", "trusted_platform_profile"],
    );
    push_missing(
        &mut requests,
        intent.color_profile.is_none(),
        "color_profile",
        "Which certified color profile must the delivery use?",
        "The delivery color space cannot be inferred from appearance.",
        &["trusted_brand_profile", "user_answer"],
    );
    push_missing(
        &mut requests,
        intent.logo_clear_space_px.is_none(),
        "logo_clear_space_px",
        "What minimum clear space is required around the approved logo?",
        "Logo clear space is a mandatory brand invariant.",
        &["trusted_brand_profile", "user_answer"],
    );
    push_missing(
        &mut requests,
        intent.minimum_text_contrast_milli.is_none(),
        "minimum_text_contrast_milli",
        "What minimum text contrast ratio should be enforced, in thousandths?",
        "The contrast threshold is a mandatory acceptance condition and cannot be guessed.",
        &["trusted_profession_standard", "user_answer"],
    );
    requests
}

fn append_artifact_requests(
    requests: &mut Vec<ResolutionRequest>,
    prefix: &'static str,
    artifact: &InputArtifactIntent,
) {
    let display = prefix.replace('_', " ");
    push_missing(
        requests,
        artifact.uri.is_none(),
        artifact_field(prefix, "uri"),
        &format!("What immutable contract input URI contains the {display}?"),
        "Every accepted input must be named and resource-scoped.",
        &["trusted_upload", "user_answer"],
    );
    push_missing(
        requests,
        artifact.media_type.is_none(),
        artifact_field(prefix, "media_type"),
        &format!("What media type was independently identified for the {display}?"),
        "File extensions are not accepted as artifact type proof.",
        &["trusted_decoder", "trusted_upload"],
    );
    push_missing(
        requests,
        artifact.sha256.is_none(),
        artifact_field(prefix, "sha256"),
        &format!("What SHA-256 digest identifies the exact {display} bytes?"),
        "Immutable input bytes must be sealed before planning or execution.",
        &["trusted_hasher"],
    );
}

fn push_missing(
    requests: &mut Vec<ResolutionRequest>,
    missing: bool,
    field: &'static str,
    question: &str,
    reason: &str,
    sources: &[&str],
) {
    if missing {
        requests.push(ResolutionRequest {
            field: field.to_owned(),
            question: question.to_owned(),
            reason: reason.to_owned(),
            accepted_sources: sources.iter().map(|source| (*source).to_owned()).collect(),
        });
    }
}

fn build_contract(
    intent: &StaticSocialPostIntent,
    capsule: &Value,
) -> Result<Value, IntentContractCompileError> {
    let capsule_version = capsule
        .get("version")
        .and_then(Value::as_str)
        .ok_or(IntentContractCompileError::InvalidCapsuleField("version"))?;
    let contract_id = resolved(intent.contract_id.as_deref(), "contract_id")?;
    let created_at = resolved(intent.created_at.as_deref(), "created_at")?;
    let original_text = resolved(intent.original_text.as_deref(), "original_text")?;
    let language = resolved(intent.language.as_deref(), "language")?;
    let width = resolved_copy(intent.canvas_width_px, "canvas_width_px")?;
    let height = resolved_copy(intent.canvas_height_px, "canvas_height_px")?;
    let color_profile = resolved(intent.color_profile.as_deref(), "color_profile")?;
    let clear_space = resolved_copy(intent.logo_clear_space_px, "logo_clear_space_px")?;
    let contrast_milli = resolved_copy(
        intent.minimum_text_contrast_milli,
        "minimum_text_contrast_milli",
    )?;
    let contrast_value = decimal_milli(contrast_milli)?;

    let approved_logo = artifact_value("approved_logo", "approved_logo", &intent.approved_logo)?;
    let brand_profile = artifact_value("brand_profile", "brand_profile", &intent.brand_profile)?;
    let approved_copy = artifact_value("approved_copy", "approved_copy", &intent.approved_copy)?;

    let preferences = intent.visual_tone.as_ref().map_or_else(Vec::new, |tone| {
        vec![json!({
            "id": "visual_tone",
            "description": tone,
            "weight": 1,
            "evaluation_mode": "human_review"
        })]
    });

    Ok(json!({
        "schema_version": SCHEMA_VERSION,
        "contract_id": contract_id,
        "created_at": created_at,
        "request": {
            "original_text": original_text,
            "language": language,
            "requester_id": intent.requester_id
        },
        "profession": {
            "capsule_id": CAPSULE_ID,
            "capsule_version": capsule_version,
            "specialization": SPECIALIZATION
        },
        "job_type": JOB_TYPE,
        "environment": {
            "os": "windows",
            "applications": [{
                "application_id": "design-editor",
                "required_version": intent.required_application_version
            }],
            "network_mode": "denied"
        },
        "inputs": [approved_logo, brand_profile, approved_copy],
        "outputs": [
            {
                "id": "editable_master",
                "kind": "editable_master",
                "destination": "contract://outputs/master.design",
                "media_type": "application/x-ergaxiom-design-document",
                "required": true
            },
            {
                "id": "delivery_raster",
                "kind": "delivery_raster",
                "destination": "contract://outputs/social-post.png",
                "media_type": "image/png",
                "required": true
            },
            {
                "id": "evidence_bundle",
                "kind": "evidence_bundle",
                "destination": "contract://outputs/evidence.json",
                "media_type": "application/json",
                "required": true
            }
        ],
        "requirements": {
            "hard": [
                constraint("canvas_width", format!("The exported raster width is exactly {width} pixels."), "delivery_raster.width", "eq", json!(width), Some("px"), "work_intent"),
                constraint("canvas_height", format!("The exported raster height is exactly {height} pixels."), "delivery_raster.height", "eq", json!(height), Some("px"), "work_intent"),
                constraint("color_profile", format!("The delivery raster contains the approved {color_profile} profile."), "delivery_raster.icc_profile", "eq", json!(color_profile), None, "brand_profile"),
                constraint("logo_aspect_ratio", "The placed logo preserves the source aspect ratio.".to_owned(), "editable_master.logo.aspect_ratio_delta", "lte", json!(0), Some("ratio_delta"), "approved_logo"),
                constraint("logo_clear_space", format!("The logo clear space is at least {clear_space} pixels."), "editable_master.logo.minimum_clear_space", "gte", json!(clear_space), Some("px"), "brand_profile"),
                constraint("text_within_safe_area", "All rendered text bounds are contained by the declared safe area.".to_owned(), "editable_master.text.safe_area_violations", "eq", json!(0), Some("count"), "work_intent"),
                constraint("minimum_text_contrast", format!("Every declared text region has a contrast ratio of at least {} to 1.", decimal_milli_string(contrast_milli)), "delivery_raster.text.minimum_contrast_ratio", "gte", contrast_value, Some("ratio"), "profession_standard.wcag-contrast"),
                constraint("export_media_type", "The delivery artifact is a valid PNG image.".to_owned(), "delivery_raster.media_type", "eq", json!("image/png"), None, "certified_job_profile")
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
                "capability": "design-editor",
                "resource": "isolated-workspace",
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
            "compiler": "ergaxiom-intent-contract-compiler-runtime",
            "compiler_version": "0.1.0",
            "intent_kind": JOB_TYPE,
            "deterministic": true,
            "implicit_defaults": false
        }
    }))
}

fn artifact_value(
    id: &str,
    kind: &str,
    artifact: &InputArtifactIntent,
) -> Result<Value, IntentContractCompileError> {
    Ok(json!({
        "id": id,
        "kind": kind,
        "uri": resolved(artifact.uri.as_deref(), artifact_field(id, "uri"))?,
        "integrity": {
            "algorithm": "sha256",
            "digest": resolved(artifact.sha256.as_deref(), artifact_field(id, "sha256"))?
        },
        "media_type": resolved(artifact.media_type.as_deref(), artifact_field(id, "media_type"))?,
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
        obligation("proof.canvas_width", "canvas_width", &["raster.dimensions"], "independent", &["decoded_image_metadata", "measurement_record"]),
        obligation("proof.canvas_height", "canvas_height", &["raster.dimensions"], "independent", &["decoded_image_metadata", "measurement_record"]),
        obligation("proof.color_profile", "color_profile", &["raster.icc_profile"], "independent", &["embedded_profile_digest", "decoded_image_metadata"]),
        obligation("proof.logo_aspect_ratio", "logo_aspect_ratio", &["document.logo_geometry"], "independent", &["document_geometry_snapshot", "measurement_record"]),
        obligation("proof.logo_clear_space", "logo_clear_space", &["document.logo_geometry"], "independent", &["document_geometry_snapshot", "measurement_record"]),
        obligation("proof.text_within_safe_area", "text_within_safe_area", &["document.text_bounds"], "independent", &["text_bounds_snapshot", "safe_area_geometry", "measurement_record"]),
        obligation("proof.minimum_text_contrast", "minimum_text_contrast", &["raster.text_contrast.relative_luminance", "raster.text_contrast.render_sampling"], "diverse", &["contrast_measurements", "sample_coordinates", "render_digest"]),
        obligation("proof.export_media_type", "export_media_type", &["raster.media_type"], "independent", &["magic_bytes", "decoded_image_metadata"]),
    ]
}

fn obligation(
    id: &str,
    constraint_id: &str,
    validator_ids: &[&str],
    independence_class: &str,
    evidence_types: &[&str],
) -> Value {
    json!({
        "id": id,
        "constraint_id": constraint_id,
        "validator_ids": validator_ids,
        "mandatory": true,
        "independence_class": independence_class,
        "evidence_types": evidence_types
    })
}

fn resolved<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, IntentContractCompileError> {
    value.ok_or(IntentContractCompileError::MissingResolvedField(field))
}

fn resolved_copy<T: Copy>(
    value: Option<T>,
    field: &'static str,
) -> Result<T, IntentContractCompileError> {
    value.ok_or(IntentContractCompileError::MissingResolvedField(field))
}

fn decimal_milli(value: u32) -> Result<Value, IntentContractCompileError> {
    let encoded = decimal_milli_string(value);
    let number = encoded
        .parse::<Number>()
        .map_err(|_| IntentContractCompileError::InvalidDecimal(encoded.clone()))?;
    Ok(Value::Number(number))
}

fn decimal_milli_string(value: u32) -> String {
    let whole = value / 1000;
    let fraction = value % 1000;
    if fraction == 0 {
        whole.to_string()
    } else if fraction % 100 == 0 {
        format!("{whole}.{}", fraction / 100)
    } else if fraction % 10 == 0 {
        format!("{whole}.{:02}", fraction / 10)
    } else {
        format!("{whole}.{fraction:03}")
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::decimal_milli_string;

    #[test]
    fn decimal_milli_encoding_is_canonical() {
        assert_eq!(decimal_milli_string(4_500), "4.5");
        assert_eq!(decimal_milli_string(5_250), "5.25");
        assert_eq!(decimal_milli_string(7_125), "7.125");
        assert_eq!(decimal_milli_string(21_000), "21");
    }
}
