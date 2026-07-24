use ergaxiom_contract_runtime::{ContractCompileError, compile_contract};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde_json::{Value, json};
use thiserror::Error;

use crate::model::{
    BrandArtifactIntent, BrandExportCompileOutcome, BrandExportIntent, BrandResolutionRequest,
    BrandRuleManifest,
};
use crate::svg::{BrandSvgError, validate_manifest};
use crate::util::{BrandDigestError, canonical_value_digest, is_sha256};

pub const BRAND_EXPORT_JOB_TYPE: &str = "brand_compliant_image_export";
pub const GRAPHIC_DESIGNER_CAPSULE_ID: &str = "ergaxiom.profession.graphic-designer";
const CONTRACT_SCHEMA: &str = "0.2.0";
const SPECIALIZATION: &str = "brand_compliance";
const PNG_MEDIA_TYPE: &str = "image/png";
const SVG_MEDIA_TYPE: &str = "image/svg+xml";

#[derive(Debug, Error)]
pub enum BrandExportCompileError {
    #[error("loaded capsule field is missing or invalid: {0}")]
    InvalidCapsuleField(&'static str),
    #[error("loaded capsule ID is unsupported")]
    UnsupportedCapsule,
    #[error("loaded capsule does not declare brand_compliant_image_export")]
    MissingJobType,
    #[error("intent field {field} is invalid: {reason}")]
    InvalidIntentField { field: String, reason: String },
    #[error("resolved intent field is unavailable: {0}")]
    MissingResolvedField(&'static str),
    #[error("failed to serialize brand export compiler material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Contract(#[from] ContractCompileError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    Digest(#[from] BrandDigestError),
    #[error(transparent)]
    Svg(#[from] BrandSvgError),
}

pub fn compile_brand_export_intent(
    intent: &BrandExportIntent,
    capsule_value: &Value,
) -> Result<BrandExportCompileOutcome, BrandExportCompileError> {
    validate_capsule(capsule_value)?;
    validate_present_values(intent)?;
    let resolution_requests = missing_resolution_requests(intent);
    if !resolution_requests.is_empty() {
        let value = serde_json::to_value(&resolution_requests)?;
        return Ok(BrandExportCompileOutcome::NeedsResolution {
            job_type: BRAND_EXPORT_JOB_TYPE.to_owned(),
            resolution_digest: canonical_json_sha256(&value)?,
            resolution_requests,
        });
    }
    let contract = build_brand_export_contract(intent, capsule_value)?;
    let compiled = compile_contract(&contract, capsule_value)?;
    if compiled.unresolved_mandatory_unknowns != 0 {
        return Err(invalid(
            "requirements.unknowns",
            "completed compiler output cannot retain mandatory unknowns",
        ));
    }
    Ok(BrandExportCompileOutcome::Compiled {
        job_type: BRAND_EXPORT_JOB_TYPE.to_owned(),
        contract,
        contract_digest: compiled.seal.contract_digest.clone(),
        capsule_digest: compiled.seal.capsule_digest.clone(),
        proof_obligation_count: compiled.proof_obligation_count(),
        unresolved_mandatory_unknowns: compiled.unresolved_mandatory_unknowns,
    })
}

pub fn build_brand_export_contract(
    intent: &BrandExportIntent,
    capsule: &Value,
) -> Result<Value, BrandExportCompileError> {
    let capsule_version = capsule
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(BrandExportCompileError::InvalidCapsuleField("version"))?;
    let contract_id = resolved(intent.contract_id.as_deref(), "contract_id")?;
    let created_at = resolved(intent.created_at.as_deref(), "created_at")?;
    let original_text = resolved(intent.original_text.as_deref(), "original_text")?;
    let language = resolved(intent.language.as_deref(), "language")?;
    let application_version = resolved(
        intent.required_application_version.as_deref(),
        "required_application_version",
    )?;
    let manifest =
        intent
            .resolved_manifest
            .as_ref()
            .ok_or(BrandExportCompileError::MissingResolvedField(
                "resolved_manifest",
            ))?;
    validate_manifest(manifest)?;
    let manifest_digest = canonical_value_digest(manifest)?;
    if intent.brand_manifest.sha256.as_deref() != Some(manifest_digest.as_str()) {
        return Err(invalid(
            "brand_manifest.sha256",
            "must equal the canonical digest of resolved_manifest",
        ));
    }
    let source = artifact_value("source_svg", "source_svg", &intent.source_svg)?;
    let manifest_artifact =
        artifact_value("brand_manifest", "brand_manifest", &intent.brand_manifest)?;
    let logo = artifact_value("approved_logo", "approved_logo", &intent.approved_logo)?;
    let preferences = intent
        .visual_preference
        .as_ref()
        .map_or_else(Vec::new, |description| {
            vec![json!({
                "id": "subjective_brand_review",
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
        "job_type": BRAND_EXPORT_JOB_TYPE,
        "environment": {
            "os": null,
            "applications": [{
                "application_id": "org.inkscape.Inkscape",
                "required_version": application_version
            }],
            "network_mode": "denied"
        },
        "inputs": [source, manifest_artifact, logo],
        "outputs": [
            {
                "id": "editable_master",
                "kind": "editable_master",
                "destination": "contract://outputs/brand-compliant.svg",
                "media_type": SVG_MEDIA_TYPE,
                "required": true
            },
            {
                "id": "delivery_raster",
                "kind": "delivery_raster",
                "destination": "contract://outputs/brand-compliant.png",
                "media_type": PNG_MEDIA_TYPE,
                "required": true
            },
            {
                "id": "evidence_bundle",
                "kind": "evidence_bundle",
                "destination": "contract://outputs/brand-compliant-evidence.json",
                "media_type": "application/json",
                "required": true
            }
        ],
        "requirements": {
            "hard": [
                constraint("canvas_width", format!("The SVG and PNG width is exactly {} pixels.", manifest.canvas_width_px), "delivery_raster.width", "eq", json!(manifest.canvas_width_px), Some("px"), "brand_manifest"),
                constraint("canvas_height", format!("The SVG and PNG height is exactly {} pixels.", manifest.canvas_height_px), "delivery_raster.height", "eq", json!(manifest.canvas_height_px), Some("px"), "brand_manifest"),
                constraint("restricted_svg_profile", "The source uses only the certified root, background, embedded-logo and direct-text SVG profile.".to_owned(), "source_svg.restricted_profile", "eq", json!(true), None, "certified_job_profile"),
                constraint("palette_violations", "Every declared fill color is present in the approved brand palette.".to_owned(), "source_svg.palette_violations", "eq", json!(0), Some("count"), "brand_manifest"),
                constraint("logo_digest_match", "The embedded logo bytes exactly match the approved logo SHA-256.".to_owned(), "source_svg.logo_digest_match", "eq", json!(true), None, "approved_logo"),
                constraint("logo_geometry_match", "The logo placement and dimensions exactly match the approved brand rule.".to_owned(), "source_svg.logo_geometry_match", "eq", json!(true), None, "brand_manifest"),
                constraint("logo_clear_space", "The logo satisfies the minimum clear-space rule on all canvas edges.".to_owned(), "source_svg.logo_clear_space", "eq", json!(true), None, "brand_manifest"),
                constraint("typography_match", "Font family, size, weight, position, color and anchor exactly match the approved typography rule.".to_owned(), "source_svg.typography_match", "eq", json!(true), None, "brand_manifest"),
                constraint("approved_copy_match", "The direct text exactly matches approved copy.".to_owned(), "source_svg.approved_copy_match", "eq", json!(true), None, "brand_manifest"),
                constraint("output_media_type", "The delivery artifact is a structurally valid PNG.".to_owned(), "delivery_raster.media_type", "eq", json!(PNG_MEDIA_TYPE), None, "certified_job_profile"),
                constraint("color_profile", "The delivery PNG contains an sRGB profile signal.".to_owned(), "delivery_raster.color_profile", "eq", json!("sRGB IEC61966-2.1"), None, "certified_job_profile"),
                constraint("source_immutable", "The exact source SVG bytes remain unchanged during execution.".to_owned(), "source_svg.immutable", "eq", json!(true), None, "execution_record"),
                constraint("inkscape_export_verified", "The brand-compliant SVG is exported through the pinned Inkscape adapter with matching dimensions and digest-bound evidence.".to_owned(), "delivery_raster.inkscape_export_verified", "eq", json!(true), None, "trusted_application_identity")
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
                "capability": "brand-validator",
                "resource": "isolated-workspace",
                "access": "control",
                "constraints": {"network": false}
            },
            {
                "capability": "design-editor",
                "resource": "brand-export",
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
            "compiler": "ergaxiom-brand-compliant-export-certified-path-runtime",
            "compiler_version": "0.1.0",
            "intent_kind": BRAND_EXPORT_JOB_TYPE,
            "brand_manifest_digest": manifest_digest,
            "restricted_svg_profile": "root_background_embedded_logo_direct_text_v1",
            "subjective_brand_quality_is_hard_acceptance": false,
            "deterministic": true,
            "implicit_defaults": false
        }
    }))
}

fn validate_capsule(capsule: &Value) -> Result<(), BrandExportCompileError> {
    let capsule_id = capsule
        .get("capsule_id")
        .and_then(Value::as_str)
        .ok_or(BrandExportCompileError::InvalidCapsuleField("capsule_id"))?;
    if capsule_id != GRAPHIC_DESIGNER_CAPSULE_ID {
        return Err(BrandExportCompileError::UnsupportedCapsule);
    }
    capsule
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(BrandExportCompileError::InvalidCapsuleField("version"))?;
    let has_job = capsule
        .get("job_types")
        .and_then(Value::as_array)
        .is_some_and(|jobs| {
            jobs.iter()
                .any(|job| job.get("id").and_then(Value::as_str) == Some(BRAND_EXPORT_JOB_TYPE))
        });
    if !has_job {
        return Err(BrandExportCompileError::MissingJobType);
    }
    Ok(())
}

fn validate_present_values(intent: &BrandExportIntent) -> Result<(), BrandExportCompileError> {
    validate_optional_text("contract_id", intent.contract_id.as_deref())?;
    validate_optional_text("created_at", intent.created_at.as_deref())?;
    validate_optional_text("original_text", intent.original_text.as_deref())?;
    validate_optional_text("language", intent.language.as_deref())?;
    validate_optional_text("requester_id", intent.requester_id.as_deref())?;
    validate_optional_text(
        "required_application_version",
        intent.required_application_version.as_deref(),
    )?;
    validate_optional_text("visual_preference", intent.visual_preference.as_deref())?;
    validate_artifact("source_svg", &intent.source_svg, SVG_MEDIA_TYPE)?;
    validate_artifact("brand_manifest", &intent.brand_manifest, "application/json")?;
    validate_artifact("approved_logo", &intent.approved_logo, PNG_MEDIA_TYPE)?;
    if let Some(created_at) = intent.created_at.as_deref() {
        if created_at.len() < 20 || !created_at.contains('T') || !created_at.ends_with('Z') {
            return Err(invalid(
                "created_at",
                "must be a caller-supplied UTC RFC 3339 timestamp ending in Z",
            ));
        }
    }
    if let Some(manifest) = &intent.resolved_manifest {
        validate_manifest(manifest)?;
    }
    Ok(())
}

fn validate_optional_text(field: &str, value: Option<&str>) -> Result<(), BrandExportCompileError> {
    if let Some(value) = value {
        if value.trim().is_empty() || value.contains('\0') {
            return Err(invalid(field, "must be non-empty and NUL-free"));
        }
    }
    Ok(())
}

fn validate_artifact(
    field: &str,
    artifact: &BrandArtifactIntent,
    media_type: &str,
) -> Result<(), BrandExportCompileError> {
    if let Some(uri) = artifact.uri.as_deref() {
        if !uri.starts_with("contract://inputs/") {
            return Err(invalid(field, "URI must use contract://inputs/"));
        }
    }
    if let Some(actual) = artifact.media_type.as_deref() {
        if actual != media_type {
            return Err(invalid(
                field,
                "media type does not match certified profile",
            ));
        }
    }
    if let Some(digest) = artifact.sha256.as_deref() {
        if !is_sha256(digest) {
            return Err(invalid(field, "digest must be lowercase SHA-256"));
        }
    }
    Ok(())
}

fn missing_resolution_requests(intent: &BrandExportIntent) -> Vec<BrandResolutionRequest> {
    let mut requests = Vec::new();
    for (field, question, reason, present) in [
        (
            "contract_id",
            "What stable Work Contract identifier should be used?",
            "The contract identifier is part of the canonical seal.",
            intent.contract_id.is_some(),
        ),
        (
            "created_at",
            "What trusted UTC timestamp should be sealed into the contract?",
            "The compiler does not read a hidden runtime clock.",
            intent.created_at.is_some(),
        ),
        (
            "original_text",
            "What user instruction should be preserved verbatim?",
            "The original instruction remains auditable evidence.",
            intent.original_text.is_some(),
        ),
        (
            "language",
            "What language identifies the original instruction?",
            "Language is required for deterministic request provenance.",
            intent.language.is_some(),
        ),
        (
            "requester_id",
            "Which requester identity should be bound?",
            "A stable requester identity is required for approval provenance.",
            intent.requester_id.is_some(),
        ),
        (
            "required_application_version",
            "Which pinned Inkscape version is required?",
            "Application identity must be resolved before execution.",
            intent.required_application_version.is_some(),
        ),
        (
            "resolved_manifest",
            "Which fully resolved brand-rule manifest should govern acceptance?",
            "Palette, logo, typography and canvas rules cannot be guessed.",
            intent.resolved_manifest.is_some(),
        ),
    ] {
        if !present {
            requests.push(resolution(field, question, reason));
        }
    }
    for (field, artifact) in [
        ("source_svg", &intent.source_svg),
        ("brand_manifest", &intent.brand_manifest),
        ("approved_logo", &intent.approved_logo),
    ] {
        if artifact.uri.is_none() || artifact.media_type.is_none() || artifact.sha256.is_none() {
            requests.push(resolution(
                field,
                "What immutable URI, media type and SHA-256 identify this input?",
                "Every input must be digest-bound before planning or execution.",
            ));
        }
    }
    requests
}

fn resolution(field: &str, question: &str, reason: &str) -> BrandResolutionRequest {
    BrandResolutionRequest {
        field: field.to_owned(),
        question: question.to_owned(),
        reason: reason.to_owned(),
        accepted_sources: vec![
            "user_answer".to_owned(),
            "trusted_asset_registry".to_owned(),
            "trusted_orchestrator".to_owned(),
        ],
    }
}

fn artifact_value(
    id: &str,
    kind: &str,
    artifact: &BrandArtifactIntent,
) -> Result<Value, BrandExportCompileError> {
    Ok(json!({
        "id": id,
        "kind": kind,
        "uri": resolved(artifact.uri.as_deref(), "artifact.uri")?,
        "integrity": {
            "algorithm": "sha256",
            "digest": resolved(artifact.sha256.as_deref(), "artifact.sha256")?
        },
        "media_type": resolved(artifact.media_type.as_deref(), "artifact.media_type")?,
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
    [
        (
            "canvas_width",
            "brand.canvas.dimensions",
            "decoded_image_metadata",
        ),
        (
            "canvas_height",
            "brand.canvas.dimensions",
            "decoded_image_metadata",
        ),
        (
            "restricted_svg_profile",
            "brand.svg.structure",
            "parsed_svg_snapshot",
        ),
        (
            "palette_violations",
            "brand.palette.allowlist",
            "parsed_svg_snapshot",
        ),
        (
            "logo_digest_match",
            "brand.logo.identity",
            "embedded_asset_digest",
        ),
        (
            "logo_geometry_match",
            "brand.logo.geometry",
            "parsed_svg_geometry",
        ),
        (
            "logo_clear_space",
            "brand.logo.clear_space",
            "parsed_svg_geometry",
        ),
        (
            "typography_match",
            "brand.typography",
            "parsed_svg_typography",
        ),
        (
            "approved_copy_match",
            "brand.copy.identity",
            "parsed_direct_text",
        ),
        (
            "output_media_type",
            "brand.png.structure",
            "decoded_image_metadata",
        ),
        ("color_profile", "brand.png.structure", "png_chunk_evidence"),
        (
            "source_immutable",
            "brand.source.immutability",
            "pre_post_digest",
        ),
        (
            "inkscape_export_verified",
            "brand.inkscape.integration",
            "signed_application_record",
        ),
    ]
    .into_iter()
    .map(|(constraint_id, validator_id, evidence_type)| {
        json!({
            "id": format!("proof.{constraint_id}"),
            "constraint_id": constraint_id,
            "validator_ids": [validator_id],
            "mandatory": true,
            "independence_class": "independent",
            "evidence_types": [evidence_type]
        })
    })
    .collect()
}

fn resolved<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, BrandExportCompileError> {
    value.ok_or(BrandExportCompileError::MissingResolvedField(field))
}

fn invalid(field: &str, reason: &str) -> BrandExportCompileError {
    BrandExportCompileError::InvalidIntentField {
        field: field.to_owned(),
        reason: reason.to_owned(),
    }
}
