use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_occupational_twin_runtime::{
    StateCondition, TwinArtifactRole, TwinRuntimeError, TwinWorkspace, TypedOperation,
    WorkspaceCommand,
};
use ergaxiom_operator_plan_runtime::{CompiledPlan, PlanStep};
use ergaxiom_operator_simulation_runtime::{
    OperatorSimulationPlan, SimulationRuntimeError, StepInvocation, simulate_operator_plan,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{
    DesignLayer, GraphicDesignDocument, GraphicDesignJob, GraphicDesignTwinRun, LogoLayer,
    TextLayer,
};
use crate::png::{PngError, encode_rgba_png};
use crate::render::{RenderError, measure_text_bounds, render_document};
use crate::validate::{
    ValidationError, proof_evidence_from_report, validate_graphic_artifacts,
};

const JOB_SCHEMA: &str = "0.1.0";
const DOCUMENT_SCHEMA: &str = "0.1.0";
const SIMULATION_SCHEMA: &str = "0.1.0";
const EDITABLE_MASTER_MEDIA_TYPE: &str = "application/x-ergaxiom-design-document";
const PNG_MEDIA_TYPE: &str = "image/png";

#[derive(Debug, Error)]
pub enum GraphicTwinError {
    #[error("unsupported graphic-design job schema {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        actual: String,
        expected: &'static str,
    },
    #[error("required graphic-design field is empty: {0}")]
    EmptyField(&'static str),
    #[error("canvas, safe area or placement geometry is invalid")]
    InvalidGeometry,
    #[error("only opaque RGBA colors are supported in the deterministic renderer")]
    NonOpaqueColor,
    #[error("the functional twin currently supports only sRGB IEC61966-2.1")]
    UnsupportedColorProfile,
    #[error("compiled plan must contain each required Graphic Designer operator exactly once")]
    InvalidOperatorSet,
    #[error("plan step {step_id} has invalid artifact bindings for operator {operator_id}")]
    InvalidStepBinding {
        step_id: String,
        operator_id: String,
    },
    #[error("failed to serialize graphic document: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error("simulation did not conform to the sealed operator plan")]
    SimulationNonConformance,
    #[error("workspace is missing artifact {0}")]
    MissingArtifact(String),
    #[error(transparent)]
    Twin(#[from] TwinRuntimeError),
    #[error(transparent)]
    Simulation(#[from] SimulationRuntimeError),
    #[error(transparent)]
    Render(#[from] RenderError),
    #[error(transparent)]
    Png(#[from] PngError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

pub fn stage_graphic_design_inputs(
    workspace: &mut TwinWorkspace,
    job: &GraphicDesignJob,
) -> Result<(), GraphicTwinError> {
    validate_job(job)?;
    stage_input(
        workspace,
        &job.approved_logo.artifact_id,
        &job.approved_logo.media_type,
        job.approved_logo.content.clone(),
    )?;
    stage_input(
        workspace,
        &job.approved_copy.artifact_id,
        &job.approved_copy.media_type,
        job.approved_copy.text.as_bytes().to_vec(),
    )?;
    let brand_profile = serde_json::to_vec(&job.brand_profile)
        .map_err(GraphicTwinError::Serialization)?;
    stage_input(
        workspace,
        &job.brand_profile.artifact_id,
        &job.brand_profile.media_type,
        brand_profile,
    )?;
    Ok(())
}

pub fn compile_graphic_design_simulation(
    compiled_plan: &CompiledPlan,
    job: &GraphicDesignJob,
) -> Result<OperatorSimulationPlan, GraphicTwinError> {
    validate_job(job)?;
    let operator_steps = required_operator_steps(compiled_plan)?;

    let canvas_document = GraphicDesignDocument {
        schema_version: DOCUMENT_SCHEMA.to_owned(),
        document_id: format!("document.{}", job.job_id),
        canvas: job.canvas.clone(),
        safe_area: job.safe_area,
        layers: Vec::new(),
    };
    let logo_document = GraphicDesignDocument {
        layers: vec![DesignLayer::Logo(LogoLayer {
            layer_id: "layer.logo".to_owned(),
            source_artifact_id: job.approved_logo.artifact_id.clone(),
            source_width: job.approved_logo.source_width,
            source_height: job.approved_logo.source_height,
            bounds: job.logo_bounds,
            primary_color: job.approved_logo.primary_color,
            secondary_color: job.approved_logo.secondary_color,
        })],
        ..canvas_document.clone()
    };
    let text_bounds = measure_text_bounds(
        &job.approved_copy.text,
        job.text_origin_x,
        job.text_origin_y,
        job.text_scale,
    )?;
    let final_document = GraphicDesignDocument {
        layers: vec![
            logo_document.layers[0].clone(),
            DesignLayer::Text(TextLayer {
                layer_id: "layer.copy".to_owned(),
                source_artifact_id: job.approved_copy.artifact_id.clone(),
                approved_copy: job.approved_copy.text.clone(),
                bounds: text_bounds,
                origin_x: job.text_origin_x,
                origin_y: job.text_origin_y,
                glyph_scale: job.text_scale,
                color: job.text_color,
            }),
        ],
        ..canvas_document.clone()
    };
    let rendered = render_document(&final_document)?;
    let raster_png = encode_rgba_png(rendered.width, rendered.height, &rendered.pixels)?;

    let canvas_bytes = canonical_struct_bytes(&canvas_document)?;
    let logo_bytes = canonical_struct_bytes(&logo_document)?;
    let text_bytes = canonical_struct_bytes(&final_document)?;

    let contents = BTreeMap::from([
        ("design.create_canvas", canvas_bytes),
        ("design.place_asset", logo_bytes),
        ("design.compose_text", text_bytes),
        ("design.export_raster", raster_png),
    ]);
    let mut invocations = Vec::with_capacity(compiled_plan.steps.len());
    for step in &compiled_plan.steps {
        let content = contents
            .get(step.operator_id.as_str())
            .ok_or(GraphicTwinError::InvalidOperatorSet)?;
        let (target_id, role, media_type) = match step.operator_id.as_str() {
            "design.create_canvas" | "design.place_asset" | "design.compose_text" => (
                job.editable_master_id.as_str(),
                TwinArtifactRole::Intermediate,
                EDITABLE_MASTER_MEDIA_TYPE,
            ),
            "design.export_raster" => (
                job.delivery_raster_id.as_str(),
                TwinArtifactRole::Output,
                PNG_MEDIA_TYPE,
            ),
            _ => return Err(GraphicTwinError::InvalidOperatorSet),
        };
        validate_step_binding(step, job, target_id)?;
        let digest = sha256_hex(content);
        let mut preconditions = step
            .input_artifact_ids
            .iter()
            .map(|artifact_id| StateCondition::ArtifactExists {
                artifact_id: artifact_id.clone(),
            })
            .collect::<Vec<_>>();
        for artifact_id in &step.input_artifact_ids {
            if is_immutable_input(job, artifact_id) {
                preconditions.push(StateCondition::ArtifactImmutable {
                    artifact_id: artifact_id.clone(),
                });
            }
        }
        if step.operator_id == "design.create_canvas" {
            preconditions.push(StateCondition::ArtifactAbsent {
                artifact_id: target_id.to_owned(),
            });
        }
        invocations.push(StepInvocation {
            step_id: step.step_id.clone(),
            operator_id: step.operator_id.clone(),
            operator_version: step.operator_version.clone(),
            operation: TypedOperation {
                operation_id: format!("operation.{}.{}", job.job_id, step.step_id),
                operator_id: step.operator_id.clone(),
                declared_input_ids: step.input_artifact_ids.clone(),
                declared_output_ids: step.output_artifact_ids.clone(),
                preconditions,
                commands: vec![WorkspaceCommand::WriteArtifact {
                    artifact_id: target_id.to_owned(),
                    role,
                    media_type: media_type.to_owned(),
                    content_base64url: URL_SAFE_NO_PAD.encode(content),
                }],
                postconditions: vec![StateCondition::ArtifactDigestEquals {
                    artifact_id: target_id.to_owned(),
                    digest,
                }],
            },
            fault: None,
        });
    }

    if operator_steps.len() != invocations.len() {
        return Err(GraphicTwinError::InvalidOperatorSet);
    }
    Ok(OperatorSimulationPlan {
        schema_version: SIMULATION_SCHEMA.to_owned(),
        simulation_id: format!("simulation.{}", job.job_id),
        plan_id: compiled_plan.plan_id.clone(),
        plan_digest: compiled_plan.plan_digest.clone(),
        invocations,
    })
}

pub fn execute_graphic_design_twin(
    workspace: &mut TwinWorkspace,
    compiled_plan: &CompiledPlan,
    job: &GraphicDesignJob,
    contract_digest: &str,
) -> Result<GraphicDesignTwinRun, GraphicTwinError> {
    stage_graphic_design_inputs(workspace, job)?;
    let simulation_plan = compile_graphic_design_simulation(compiled_plan, job)?;
    let simulation = simulate_operator_plan(workspace, compiled_plan, &simulation_plan)?;
    if !simulation.conforms_to_plan {
        return Err(GraphicTwinError::SimulationNonConformance);
    }
    let editable_master = workspace
        .artifact_content(&job.editable_master_id)
        .ok_or_else(|| GraphicTwinError::MissingArtifact(job.editable_master_id.clone()))?;
    let raster_png = workspace
        .artifact_content(&job.delivery_raster_id)
        .ok_or_else(|| GraphicTwinError::MissingArtifact(job.delivery_raster_id.clone()))?;
    let (document, validation) = validate_graphic_artifacts(job, editable_master, raster_png)?;
    let proof_evidence = proof_evidence_from_report(job, &validation, contract_digest);
    Ok(GraphicDesignTwinRun {
        simulation,
        document,
        raster_png: raster_png.to_vec(),
        validation,
        proof_evidence,
    })
}

fn validate_job(job: &GraphicDesignJob) -> Result<(), GraphicTwinError> {
    if job.schema_version != JOB_SCHEMA {
        return Err(GraphicTwinError::UnsupportedSchemaVersion {
            actual: job.schema_version.clone(),
            expected: JOB_SCHEMA,
        });
    }
    for (field, value) in [
        ("job_id", job.job_id.as_str()),
        ("evaluated_at", job.evaluated_at.as_str()),
        ("color_profile", job.canvas.color_profile.as_str()),
        ("approved_logo.artifact_id", job.approved_logo.artifact_id.as_str()),
        ("approved_copy.artifact_id", job.approved_copy.artifact_id.as_str()),
        ("brand_profile.artifact_id", job.brand_profile.artifact_id.as_str()),
        ("editable_master_id", job.editable_master_id.as_str()),
        ("delivery_raster_id", job.delivery_raster_id.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(GraphicTwinError::EmptyField(field));
        }
    }
    if job.canvas.width == 0
        || job.canvas.height == 0
        || job.approved_logo.source_width == 0
        || job.approved_logo.source_height == 0
        || job.logo_bounds.width == 0
        || job.logo_bounds.height == 0
        || job.text_scale == 0
        || !rect_inside(job.safe_area, job.canvas.width, job.canvas.height)
        || !rect_inside(job.logo_bounds, job.canvas.width, job.canvas.height)
    {
        return Err(GraphicTwinError::InvalidGeometry);
    }
    let text_bounds = measure_text_bounds(
        &job.approved_copy.text,
        job.text_origin_x,
        job.text_origin_y,
        job.text_scale,
    )?;
    if !rect_inside(text_bounds, job.canvas.width, job.canvas.height) {
        return Err(GraphicTwinError::InvalidGeometry);
    }
    if [
        job.canvas.background.alpha,
        job.text_color.alpha,
        job.approved_logo.primary_color.alpha,
        job.approved_logo.secondary_color.alpha,
    ]
    .iter()
    .any(|alpha| *alpha != 255)
    {
        return Err(GraphicTwinError::NonOpaqueColor);
    }
    if job.canvas.color_profile != "sRGB IEC61966-2.1" {
        return Err(GraphicTwinError::UnsupportedColorProfile);
    }
    Ok(())
}

fn required_operator_steps<'a>(
    compiled_plan: &'a CompiledPlan,
) -> Result<BTreeMap<&'static str, &'a PlanStep>, GraphicTwinError> {
    let required = [
        "design.create_canvas",
        "design.place_asset",
        "design.compose_text",
        "design.export_raster",
    ];
    let mut steps = BTreeMap::new();
    for step in &compiled_plan.steps {
        if !required.contains(&step.operator_id.as_str())
            || steps.insert(step.operator_id.as_str(), step).is_some()
        {
            return Err(GraphicTwinError::InvalidOperatorSet);
        }
    }
    if steps.len() != required.len() || required.iter().any(|operator| !steps.contains_key(operator)) {
        return Err(GraphicTwinError::InvalidOperatorSet);
    }
    Ok(steps.into_iter().map(|(key, value)| {
        let stable_key = required
            .iter()
            .copied()
            .find(|required_key| *required_key == key)
            .unwrap_or("invalid");
        (stable_key, value)
    }).collect())
}

fn validate_step_binding(
    step: &PlanStep,
    job: &GraphicDesignJob,
    target_id: &str,
) -> Result<(), GraphicTwinError> {
    let output_set: BTreeSet<_> = step.output_artifact_ids.iter().map(String::as_str).collect();
    if step.output_artifact_ids.len() != 1 || output_set != BTreeSet::from([target_id]) {
        return Err(GraphicTwinError::InvalidStepBinding {
            step_id: step.step_id.clone(),
            operator_id: step.operator_id.clone(),
        });
    }
    let input_set: BTreeSet<_> = step.input_artifact_ids.iter().map(String::as_str).collect();
    let valid = match step.operator_id.as_str() {
        "design.create_canvas" => true,
        "design.place_asset" => {
            input_set.contains(job.editable_master_id.as_str())
                && input_set.contains(job.approved_logo.artifact_id.as_str())
        }
        "design.compose_text" => {
            input_set.contains(job.editable_master_id.as_str())
                && input_set.contains(job.approved_copy.artifact_id.as_str())
        }
        "design.export_raster" => input_set.contains(job.editable_master_id.as_str()),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(GraphicTwinError::InvalidStepBinding {
            step_id: step.step_id.clone(),
            operator_id: step.operator_id.clone(),
        })
    }
}

fn is_immutable_input(job: &GraphicDesignJob, artifact_id: &str) -> bool {
    artifact_id == job.approved_logo.artifact_id
        || artifact_id == job.approved_copy.artifact_id
        || artifact_id == job.brand_profile.artifact_id
}

fn stage_input(
    workspace: &mut TwinWorkspace,
    artifact_id: &str,
    media_type: &str,
    content: Vec<u8>,
) -> Result<(), GraphicTwinError> {
    let digest = sha256_hex(&content);
    workspace.stage_immutable_input(artifact_id, media_type, content, &digest)?;
    Ok(())
}

fn canonical_struct_bytes(value: &impl Serialize) -> Result<Vec<u8>, GraphicTwinError> {
    serde_json::to_vec(value).map_err(GraphicTwinError::Serialization)
}

fn rect_inside(rect: crate::model::PixelRect, width: u32, height: u32) -> bool {
    rect.x
        .checked_add(rect.width)
        .is_some_and(|right| right <= width)
        && rect
            .y
            .checked_add(rect.height)
            .is_some_and(|bottom| bottom <= height)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
