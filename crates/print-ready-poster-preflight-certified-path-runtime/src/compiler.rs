use ergaxiom_contract_runtime::{ContractCompileError, compile_contract};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde_json::{Value, json};
use thiserror::Error;

use crate::model::{
    PrintArtifactIntent, PrintPreflightCompileOutcome, PrintPreflightIntent, PrintResolutionRequest,
};
use crate::svg::{PrintSvgError, validate_print_specification};
use crate::util::{PrintDigestError, canonical_value_digest, is_sha256};

pub const PRINT_PREFLIGHT_JOB_TYPE: &str = "print_ready_poster_preflight";
pub const GRAPHIC_DESIGNER_CAPSULE_ID: &str = "ergaxiom.profession.graphic-designer";
const CONTRACT_SCHEMA: &str = "0.2.0";
const SVG_MEDIA_TYPE: &str = "image/svg+xml";
const PDF_MEDIA_TYPE: &str = "application/pdf";

#[derive(Debug, Error)]
pub enum PrintPreflightCompileError {
    #[error("loaded capsule field is missing or invalid: {0}")]
    InvalidCapsuleField(&'static str),
    #[error("loaded capsule is not the Graphic Designer capsule")]
    UnsupportedCapsule,
    #[error("loaded capsule does not declare print_ready_poster_preflight")]
    MissingJobType,
    #[error("intent field {field} is invalid: {reason}")]
    InvalidIntentField { field: String, reason: String },
    #[error("resolved intent field is unavailable: {0}")]
    MissingResolvedField(&'static str),
    #[error("failed to serialize print preflight compiler material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Contract(#[from] ContractCompileError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    Digest(#[from] PrintDigestError),
    #[error(transparent)]
    Svg(#[from] PrintSvgError),
}

pub fn compile_print_preflight_intent(
    intent: &PrintPreflightIntent,
    capsule_value: &Value,
) -> Result<PrintPreflightCompileOutcome, PrintPreflightCompileError> {
    validate_capsule(capsule_value)?;
    validate_present_values(intent)?;
    let resolution_requests = missing_resolution_requests(intent);
    if !resolution_requests.is_empty() {
        let value = serde_json::to_value(&resolution_requests)?;
        return Ok(PrintPreflightCompileOutcome::NeedsResolution {
            job_type: PRINT_PREFLIGHT_JOB_TYPE.to_owned(),
            resolution_digest: canonical_json_sha256(&value)?,
            resolution_requests,
        });
    }
    let contract = build_print_preflight_contract(intent, capsule_value)?;
    let compiled = compile_contract(&contract, capsule_value)?;
    if compiled.unresolved_mandatory_unknowns != 0 {
        return Err(invalid(
            "requirements.unknowns",
            "completed compiler output cannot retain mandatory unknowns",
        ));
    }
    Ok(PrintPreflightCompileOutcome::Compiled {
        job_type: PRINT_PREFLIGHT_JOB_TYPE.to_owned(),
        contract,
        contract_digest: compiled.seal.contract_digest.clone(),
        capsule_digest: compiled.seal.capsule_digest.clone(),
        proof_obligation_count: compiled.proof_obligation_count(),
        unresolved_mandatory_unknowns: compiled.unresolved_mandatory_unknowns,
    })
}

pub fn build_print_preflight_contract(
    intent: &PrintPreflightIntent,
    capsule: &Value,
) -> Result<Value, PrintPreflightCompileError> {
    let capsule_version = capsule
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(PrintPreflightCompileError::InvalidCapsuleField("version"))?;
    let contract_id = resolved(intent.contract_id.as_deref(), "contract_id")?;
    let created_at = resolved(intent.created_at.as_deref(), "created_at")?;
    let original_text = resolved(intent.original_text.as_deref(), "original_text")?;
    let language = resolved(intent.language.as_deref(), "language")?;
    let requester_id = resolved(intent.requester_id.as_deref(), "requester_id")?;
    let application_version = resolved(
        intent.required_application_version.as_deref(),
        "required_application_version",
    )?;
    let specification = intent.resolved_specification.as_ref().ok_or(
        PrintPreflightCompileError::MissingResolvedField("resolved_specification"),
    )?;
    validate_print_specification(specification)?;
    let specification_digest = canonical_value_digest(specification)?;
    if intent.print_specification.sha256.as_deref() != Some(specification_digest.as_str()) {
        return Err(invalid(
            "print_specification.sha256",
            "must equal the canonical digest of resolved_specification",
        ));
    }
    let source = artifact_value("source_svg", "source_svg", &intent.source_svg)?;
    let specification_artifact = artifact_value(
        "print_specification",
        "print_specification",
        &intent.print_specification,
    )?;
    let preferences = intent
        .visual_preference
        .as_ref()
        .map_or_else(Vec::new, |description| {
            vec![json!({
                "id": "subjective_print_review",
                "description": description,
                "weight": 1,
                "evaluation_mode": "human_review"
            })]
        });
    let total_width = specification.trim_width_milli_mm + 2 * specification.bleed_milli_mm;
    let total_height = specification.trim_height_milli_mm + 2 * specification.bleed_milli_mm;

    Ok(json!({
        "schema_version": CONTRACT_SCHEMA,
        "contract_id": contract_id,
        "created_at": created_at,
        "request": {
            "original_text": original_text,
            "language": language,
            "requester_id": requester_id
        },
        "profession": {
            "capsule_id": GRAPHIC_DESIGNER_CAPSULE_ID,
            "capsule_version": capsule_version,
            "specialization": "print_production"
        },
        "job_type": PRINT_PREFLIGHT_JOB_TYPE,
        "environment": {
            "os": null,
            "applications": [{
                "application_id": "org.inkscape.Inkscape",
                "required_version": application_version
            }],
            "network_mode": "denied"
        },
        "inputs": [source, specification_artifact],
        "outputs": [
            {
                "id": "editable_master",
                "kind": "editable_master",
                "destination": "contract://outputs/print-ready-poster.svg",
                "media_type": SVG_MEDIA_TYPE,
                "required": true
            },
            {
                "id": "delivery_pdf",
                "kind": "delivery_pdf",
                "destination": "contract://outputs/print-ready-poster.pdf",
                "media_type": PDF_MEDIA_TYPE,
                "required": true
            },
            {
                "id": "evidence_bundle",
                "kind": "evidence_bundle",
                "destination": "contract://outputs/print-ready-poster-evidence.json",
                "media_type": "application/json",
                "required": true
            }
        ],
        "requirements": {
            "hard": [
                constraint("restricted_svg_profile", "The source uses only the certified vector poster SVG profile.", "source_svg.restricted_profile", "eq", json!(true), null_unit(), "certified_job_profile"),
                constraint("canvas_dimensions_match", format!("The bleed canvas is exactly {total_width} by {total_height} milli-mm."), "source_svg.canvas_dimensions_match", "eq", json!(true), null_unit(), "print_specification"),
                constraint("bleed_coverage", "The approved background covers the entire bleed canvas.", "source_svg.bleed_coverage", "eq", json!(true), null_unit(), "print_specification"),
                constraint("safe_area_satisfied", "Every non-background vector bound remains inside the declared safe area.", "source_svg.safe_area_satisfied", "eq", json!(true), null_unit(), "print_specification"),
                constraint("palette_violations", "Every fill belongs to the exact print palette allowlist.", "source_svg.palette_violations", "eq", json!(0), Some("count"), "print_specification"),
                constraint("vector_only", "The delivery contains no raster image XObjects.", "delivery_pdf.vector_only", "eq", json!(true), null_unit(), "certified_job_profile"),
                constraint("fonts_outlined", "The source and delivery contain no live text or PDF font resources.", "delivery_pdf.fonts_outlined", "eq", json!(true), null_unit(), "certified_job_profile"),
                constraint("page_count", "The delivery PDF contains exactly one page.", "delivery_pdf.page_count", "eq", json!(1), Some("page"), "print_specification"),
                constraint("media_box_match", "The PDF MediaBox exactly matches the bleed canvas.", "delivery_pdf.media_box_match", "eq", json!(true), null_unit(), "print_specification"),
                constraint("trim_box_match", "The PDF TrimBox exactly matches the declared trim size and bleed inset.", "delivery_pdf.trim_box_match", "eq", json!(true), null_unit(), "print_specification"),
                constraint("bleed_box_match", "The PDF BleedBox exactly equals the MediaBox.", "delivery_pdf.bleed_box_match", "eq", json!(true), null_unit(), "print_specification"),
                constraint("crop_box_match", "The PDF CropBox exactly equals the MediaBox.", "delivery_pdf.crop_box_match", "eq", json!(true), null_unit(), "print_specification"),
                constraint("pdf_version", format!("The normalized delivery uses PDF {}.", specification.required_pdf_version), "delivery_pdf.pdf_version", "eq", json!(specification.required_pdf_version), null_unit(), "print_specification"),
                constraint("allowed_color_spaces", "Only printer-approved DeviceRGB or DeviceGray operators are present.", "delivery_pdf.allowed_color_spaces", "eq", json!(true), null_unit(), "print_specification"),
                constraint("transparency_absent", "Transparency, soft masks and ExtGState resources are absent.", "delivery_pdf.transparency_absent", "eq", json!(true), null_unit(), "certified_job_profile"),
                constraint("external_actions_absent", "Annotations, JavaScript, launch actions and embedded files are absent.", "delivery_pdf.external_actions_absent", "eq", json!(true), null_unit(), "certified_job_profile"),
                constraint("source_immutable", "The exact source SVG bytes remain unchanged during execution.", "source_svg.immutable", "eq", json!(true), null_unit(), "execution_record"),
                constraint("inkscape_export_verified", "The PDF was exported through the pinned proof-bound Inkscape adapter.", "delivery_pdf.inkscape_export_verified", "eq", json!(true), null_unit(), "trusted_application_identity")
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
                "capability": "print-validator",
                "resource": "isolated-workspace",
                "access": "control",
                "constraints": {"network": false}
            },
            {
                "capability": "design-editor",
                "resource": "print-export",
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
            "compiler": "ergaxiom-print-ready-poster-preflight-certified-path-runtime",
            "compiler_version": "0.1.0",
            "intent_kind": PRINT_PREFLIGHT_JOB_TYPE,
            "print_specification_digest": specification_digest,
            "restricted_svg_profile": "flat_vector_outlined_path_poster_v1",
            "subjective_print_quality_is_hard_acceptance": false,
            "deterministic": true,
            "implicit_defaults": false
        }
    }))
}

fn proof_obligations() -> Vec<Value> {
    [
        (
            "restricted_svg_profile",
            "print.svg.structure",
            "parsed_svg_snapshot",
        ),
        (
            "canvas_dimensions_match",
            "print.canvas.dimensions",
            "parsed_svg_geometry",
        ),
        (
            "bleed_coverage",
            "print.bleed.coverage",
            "parsed_svg_geometry",
        ),
        (
            "safe_area_satisfied",
            "print.safe_area.geometry",
            "parsed_svg_geometry",
        ),
        (
            "palette_violations",
            "print.palette.allowlist",
            "parsed_svg_snapshot",
        ),
        (
            "vector_only",
            "print.pdf.vector_only",
            "parsed_pdf_resources",
        ),
        (
            "fonts_outlined",
            "print.pdf.fonts_outlined",
            "parsed_pdf_resources",
        ),
        ("page_count", "print.pdf.page", "parsed_pdf_page_tree"),
        (
            "media_box_match",
            "print.pdf.boxes",
            "parsed_pdf_page_boxes",
        ),
        ("trim_box_match", "print.pdf.boxes", "parsed_pdf_page_boxes"),
        (
            "bleed_box_match",
            "print.pdf.boxes",
            "parsed_pdf_page_boxes",
        ),
        ("crop_box_match", "print.pdf.boxes", "parsed_pdf_page_boxes"),
        ("pdf_version", "print.pdf.version", "parsed_pdf_header"),
        (
            "allowed_color_spaces",
            "print.pdf.color_spaces",
            "decoded_pdf_content",
        ),
        (
            "transparency_absent",
            "print.pdf.transparency",
            "parsed_pdf_resources",
        ),
        (
            "external_actions_absent",
            "print.pdf.security",
            "parsed_pdf_catalog",
        ),
        (
            "source_immutable",
            "print.source.immutability",
            "pre_execution_digest",
        ),
        (
            "inkscape_export_verified",
            "print.inkscape.integration",
            "signed_execution_record",
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

fn validate_capsule(capsule: &Value) -> Result<(), PrintPreflightCompileError> {
    let capsule_id = capsule.get("capsule_id").and_then(Value::as_str).ok_or(
        PrintPreflightCompileError::InvalidCapsuleField("capsule_id"),
    )?;
    if capsule_id != GRAPHIC_DESIGNER_CAPSULE_ID {
        return Err(PrintPreflightCompileError::UnsupportedCapsule);
    }
    capsule
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(PrintPreflightCompileError::InvalidCapsuleField("version"))?;
    let has_job = capsule
        .get("job_types")
        .and_then(Value::as_array)
        .is_some_and(|jobs| {
            jobs.iter()
                .any(|job| job.get("id").and_then(Value::as_str) == Some(PRINT_PREFLIGHT_JOB_TYPE))
        });
    if !has_job {
        return Err(PrintPreflightCompileError::MissingJobType);
    }
    Ok(())
}

fn validate_present_values(
    intent: &PrintPreflightIntent,
) -> Result<(), PrintPreflightCompileError> {
    for (field, value) in [
        ("contract_id", intent.contract_id.as_deref()),
        ("created_at", intent.created_at.as_deref()),
        ("original_text", intent.original_text.as_deref()),
        ("language", intent.language.as_deref()),
        ("requester_id", intent.requester_id.as_deref()),
        (
            "required_application_version",
            intent.required_application_version.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            if value.trim().is_empty() || value.contains('\0') {
                return Err(invalid(field, "must be non-empty and NUL-free"));
            }
        }
    }
    if let Some(created_at) = intent.created_at.as_deref() {
        if created_at.len() < 20 || !created_at.contains('T') || !created_at.ends_with('Z') {
            return Err(invalid(
                "created_at",
                "must be a caller-supplied UTC RFC 3339 timestamp ending in Z",
            ));
        }
    }
    validate_artifact("source_svg", &intent.source_svg, SVG_MEDIA_TYPE)?;
    validate_artifact(
        "print_specification",
        &intent.print_specification,
        "application/json",
    )?;
    if let Some(specification) = &intent.resolved_specification {
        validate_print_specification(specification)?;
    }
    Ok(())
}

fn validate_artifact(
    field: &str,
    artifact: &PrintArtifactIntent,
    media_type: &str,
) -> Result<(), PrintPreflightCompileError> {
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

fn missing_resolution_requests(intent: &PrintPreflightIntent) -> Vec<PrintResolutionRequest> {
    let mut requests = Vec::new();
    for (field, question, reason, present) in [
        (
            "contract_id",
            "What stable Work Contract identifier should be used?",
            "The identifier is part of the canonical seal.",
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
            "Language is required for deterministic provenance.",
            intent.language.is_some(),
        ),
        (
            "requester_id",
            "Which requester identity should be bound?",
            "Approval provenance requires a stable requester.",
            intent.requester_id.is_some(),
        ),
        (
            "required_application_version",
            "Which pinned Inkscape version is required?",
            "Application identity must be resolved before execution.",
            intent.required_application_version.is_some(),
        ),
        (
            "resolved_specification",
            "Which fully resolved print specification governs acceptance?",
            "Trim, bleed, safe area, palette and PDF profile cannot be guessed.",
            intent.resolved_specification.is_some(),
        ),
    ] {
        if !present {
            requests.push(resolution(field, question, reason));
        }
    }
    for (field, artifact) in [
        ("source_svg", &intent.source_svg),
        ("print_specification", &intent.print_specification),
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

fn resolution(field: &str, question: &str, reason: &str) -> PrintResolutionRequest {
    PrintResolutionRequest {
        field: field.to_owned(),
        question: question.to_owned(),
        reason: reason.to_owned(),
        accepted_sources: vec![
            "user_answer".to_owned(),
            "trusted_print_specification_registry".to_owned(),
            "trusted_orchestrator".to_owned(),
        ],
    }
}

fn artifact_value(
    id: &str,
    kind: &str,
    artifact: &PrintArtifactIntent,
) -> Result<Value, PrintPreflightCompileError> {
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
    claim: impl Into<String>,
    subject: &str,
    operator: &str,
    expected: Value,
    unit: Option<&str>,
    source: &str,
) -> Value {
    json!({
        "id": id,
        "claim": claim.into(),
        "subject": subject,
        "operator": operator,
        "expected": expected,
        "unit": unit,
        "tolerance": 0,
        "mandatory": true,
        "source": source
    })
}

fn null_unit() -> Option<&'static str> {
    None
}

fn resolved<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, PrintPreflightCompileError> {
    value.ok_or(PrintPreflightCompileError::MissingResolvedField(field))
}

fn invalid(field: &str, reason: &str) -> PrintPreflightCompileError {
    PrintPreflightCompileError::InvalidIntentField {
        field: field.to_owned(),
        reason: reason.to_owned(),
    }
}
