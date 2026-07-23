use ergaxiom_contract_runtime::compile_contract;
use ergaxiom_desktop_shell_runtime::{
    ApprovalSummary, DesktopShellMaterial, DesktopShellSnapshot, DigestItem, PlanStepSummary,
    StageStatus, TrustComponentStatus, ValidatorSummary, build_desktop_shell_snapshot,
};
use ergaxiom_graphic_designer_twin_runtime::{
    ApprovedCopy, ApprovedLogo, BrandProfile, CanvasSpecification, GraphicDesignJob, PixelRect,
    Rgba8, execute_graphic_design_twin,
};
use ergaxiom_intent_contract_compiler_runtime::{
    InputArtifactIntent, IntentCompileOutcome, StaticSocialPostIntent,
    compile_static_social_post_intent,
};
use ergaxiom_occupational_twin_runtime::{
    ApplicationIdentity, EnvironmentIdentity, TwinWorkspace,
};
use ergaxiom_operator_plan_runtime::compile_plan;
use ergaxiom_operator_simulation_runtime::SimulatedStepStatus;
use ergaxiom_typed_planner_runtime::{
    StaticSocialPostPlanIdentity, TypedPlanOutcome, synthesize_static_social_post_plan,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const GENERATED_AT: &str = "2026-07-23T14:00:00Z";
const JOB_ID: &str = "job.desktop-shell.0001";

pub fn build_pipeline_snapshot() -> Result<DesktopShellSnapshot, String> {
    let capsule: Value = serde_json::from_str(include_str!(
        "../../../../professions/graphic-designer/profession.json"
    ))
    .map_err(|error| format!("profession capsule decode failed: {error}"))?;
    let job = graphic_job();
    let brand_profile_bytes = serde_json::to_vec(&job.brand_profile)
        .map_err(|error| format!("brand profile encoding failed: {error}"))?;

    let intent = StaticSocialPostIntent {
        contract_id: Some("contract.desktop-shell.0001".to_owned()),
        created_at: Some(GENERATED_AT.to_owned()),
        original_text: Some(
            "Create a verified static social post using the approved brand inputs.".to_owned(),
        ),
        language: Some("tr".to_owned()),
        requester_id: Some("ergaxiom.desktop".to_owned()),
        approved_logo: artifact_intent(
            "contract://inputs/approved-logo.svg",
            &job.approved_logo.media_type,
            &job.approved_logo.content,
        ),
        brand_profile: artifact_intent(
            "contract://inputs/brand-profile.json",
            &job.brand_profile.media_type,
            &brand_profile_bytes,
        ),
        approved_copy: artifact_intent(
            "contract://inputs/approved-copy.txt",
            &job.approved_copy.media_type,
            job.approved_copy.text.as_bytes(),
        ),
        canvas_width_px: Some(job.canvas.width),
        canvas_height_px: Some(job.canvas.height),
        color_profile: Some(job.canvas.color_profile.clone()),
        logo_clear_space_px: Some(job.brand_profile.minimum_logo_clear_space_px),
        minimum_text_contrast_milli: Some(job.brand_profile.minimum_text_contrast_milli),
        visual_tone: Some("technical premium".to_owned()),
        required_application_version: Some("1.2.2".to_owned()),
        require_pre_execution_approval: true,
    };

    let IntentCompileOutcome::Compiled {
        contract,
        contract_digest,
        capsule_digest,
        proof_obligation_count,
        unresolved_mandatory_unknowns,
        ..
    } = compile_static_social_post_intent(&intent, &capsule)
        .map_err(|error| format!("intent compilation failed: {error}"))?
    else {
        return Err("fully resolved desktop fixture unexpectedly needs resolution".to_owned());
    };

    let TypedPlanOutcome::Planned {
        plan,
        plan_digest,
        capability_requirement_digest,
        mandatory_step_count,
        ..
    } = synthesize_static_social_post_plan(
        &StaticSocialPostPlanIdentity {
            plan_id: Some("plan.desktop-shell.0001".to_owned()),
            created_at: Some(GENERATED_AT.to_owned()),
        },
        &contract,
        &capsule,
    )
    .map_err(|error| format!("typed planning failed: {error}"))?
    else {
        return Err("resolved desktop contract unexpectedly needs plan resolution".to_owned());
    };

    let compiled_contract = compile_contract(&contract, &capsule)
        .map_err(|error| format!("contract recompile failed: {error}"))?;
    let compiled_plan = compile_plan(&plan, &capsule, &compiled_contract)
        .map_err(|error| format!("plan recompile failed: {error}"))?;
    let mut workspace = twin_workspace()?;
    let run = execute_graphic_design_twin(
        &mut workspace,
        &compiled_contract,
        &contract,
        &compiled_plan,
        &job,
    )
    .map_err(|error| format!("Occupational Twin execution failed: {error}"))?;

    let staged_inputs = vec![
        digest_item(
            &job.approved_logo.artifact_id,
            &job.approved_logo.media_type,
            &job.approved_logo.content,
        ),
        digest_item(
            &job.approved_copy.artifact_id,
            &job.approved_copy.media_type,
            job.approved_copy.text.as_bytes(),
        ),
        digest_item(
            &job.brand_profile.artifact_id,
            &job.brand_profile.media_type,
            &brand_profile_bytes,
        ),
    ];
    let steps = run
        .simulation
        .steps
        .iter()
        .map(|step| PlanStepSummary {
            step_id: step.step_id.clone(),
            operator_id: compiled_plan
                .steps
                .iter()
                .find(|planned| planned.step_id == step.step_id)
                .map(|planned| planned.operator_id.clone())
                .unwrap_or_else(|| "unknown.operator".to_owned()),
            status: simulation_status(step.status),
            before_digest: Some(step.before_snapshot_digest.clone()),
            after_digest: Some(step.after_snapshot_digest.clone()),
        })
        .collect();
    let validators = run
        .validation
        .observations
        .iter()
        .map(|observation| ValidatorSummary {
            validator_id: observation.validator_id.clone(),
            claim_id: observation.claim_id.clone(),
            report_digest: observation.evidence_digest.clone(),
            status: if observation.passed {
                StageStatus::Passed
            } else {
                StageStatus::Failed
            },
            actionable_message: (!observation.passed).then(|| {
                format!(
                    "Observed value did not satisfy the sealed expectation: {}",
                    observation.expected
                )
            }),
        })
        .collect();

    build_desktop_shell_snapshot(DesktopShellMaterial {
        generated_at: GENERATED_AT.to_owned(),
        job_id: Some(JOB_ID.to_owned()),
        unresolved: Vec::new(),
        staged_inputs,
        contract: Some(DigestItem {
            id: compiled_contract.contract_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: contract_digest,
            status: StageStatus::Passed,
        }),
        approval: Some(ApprovalSummary {
            approval_id: "approval.desktop-shell.0001".to_owned(),
            contract_digest: compiled_contract.seal.contract_digest.clone(),
            plan_digest: plan_digest.clone(),
            permission_digest: capability_requirement_digest,
            expires_at_epoch_s: 1_800_000_000,
            status: StageStatus::Pending,
        }),
        plan: Some(DigestItem {
            id: compiled_plan.plan_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: plan_digest,
            status: StageStatus::Passed,
        }),
        steps,
        validators,
        evidence_bundle: None,
        replay_manifest: Some(DigestItem {
            id: run.simulation.simulation_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: run.simulation.simulation_digest.clone(),
            status: StageStatus::Passed,
        }),
        certificate: None,
        profession_capsules: vec![TrustComponentStatus {
            component_id: "ergaxiom.profession.graphic-designer".to_owned(),
            version: capsule
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
            digest: capsule_digest,
            trusted: true,
        }],
        adapters: vec![TrustComponentStatus {
            component_id: "ergaxiom.design-document-model".to_owned(),
            version: "0.1.0".to_owned(),
            digest: sha256_hex(b"ergaxiom.design-document-model@0.1.0"),
            trusted: true,
        }],
        trusted_keys: vec![TrustComponentStatus {
            component_id: "final-attestation-key".to_owned(),
            version: "not-loaded".to_owned(),
            digest: sha256_hex(b"final-attestation-key:not-loaded"),
            trusted: false,
        }],
        metadata: json!({
            "pipeline": "intent_compiler -> typed_planner -> occupational_twin",
            "twin_validation_passed": run.validation.all_mandatory_passed,
            "simulation_conforms_to_plan": run.simulation.conforms_to_plan,
            "proof_obligation_count": proof_obligation_count,
            "proof_evidence_count": run.proof_evidence.len(),
            "mandatory_step_count": mandatory_step_count,
            "unresolved_mandatory_unknowns": unresolved_mandatory_unknowns,
            "validation_report_digest": run.validation.report_digest,
            "raster_digest": run.validation.raster_digest,
            "acceptance_blocker": "A final signed Evidence Bundle and Acceptance Certificate are not loaded in this read-only shell snapshot."
        }),
    })
    .map_err(|error| format!("desktop snapshot construction failed: {error}"))
}

fn graphic_job() -> GraphicDesignJob {
    GraphicDesignJob {
        schema_version: "0.1.0".to_owned(),
        job_id: JOB_ID.to_owned(),
        evaluated_at: GENERATED_AT.to_owned(),
        canvas: CanvasSpecification {
            width: 240,
            height: 300,
            color_profile: "sRGB IEC61966-2.1".to_owned(),
            background: Rgba8::opaque(255, 255, 255),
        },
        safe_area: PixelRect {
            x: 12,
            y: 12,
            width: 216,
            height: 276,
        },
        logo_bounds: PixelRect {
            x: 24,
            y: 24,
            width: 80,
            height: 40,
        },
        text_origin_x: 24,
        text_origin_y: 100,
        text_scale: 3,
        text_color: Rgba8::opaque(0, 0, 0),
        approved_logo: ApprovedLogo {
            artifact_id: "approved_logo".to_owned(),
            media_type: "image/svg+xml".to_owned(),
            content: b"<svg viewBox='0 0 200 100'>approved</svg>".to_vec(),
            source_width: 200,
            source_height: 100,
            primary_color: Rgba8::opaque(20, 40, 80),
            secondary_color: Rgba8::opaque(40, 120, 220),
        },
        approved_copy: ApprovedCopy {
            artifact_id: "approved_copy".to_owned(),
            media_type: "text/plain".to_owned(),
            text: "ERGAXIOM\nVERIFIED".to_owned(),
        },
        brand_profile: BrandProfile {
            artifact_id: "brand_profile".to_owned(),
            media_type: "application/json".to_owned(),
            minimum_logo_clear_space_px: 16,
            minimum_text_contrast_milli: 4_500,
        },
        editable_master_id: "editable_master".to_owned(),
        delivery_raster_id: "delivery_raster".to_owned(),
    }
}

fn artifact_intent(uri: &str, media_type: &str, content: &[u8]) -> InputArtifactIntent {
    InputArtifactIntent {
        uri: Some(uri.to_owned()),
        media_type: Some(media_type.to_owned()),
        sha256: Some(sha256_hex(content)),
    }
}

fn digest_item(id: &str, media_type: &str, content: &[u8]) -> DigestItem {
    DigestItem {
        id: id.to_owned(),
        media_type: Some(media_type.to_owned()),
        digest: sha256_hex(content),
        status: StageStatus::Passed,
    }
}

fn twin_workspace() -> Result<TwinWorkspace, String> {
    TwinWorkspace::new(
        "workspace.desktop-shell",
        EnvironmentIdentity {
            os: "windows".to_owned(),
            architecture: "x86_64".to_owned(),
            runtime_id: "ergaxiom.desktop-shell".to_owned(),
            runtime_version: "0.1.0".to_owned(),
            clock_source: "sealed-fixture-clock".to_owned(),
            sandbox_id: "sandbox.desktop-shell".to_owned(),
            applications: vec![ApplicationIdentity {
                application_id: "ergaxiom.design-document-model".to_owned(),
                version: "0.1.0".to_owned(),
                digest: sha256_hex(b"ergaxiom.design-document-model@0.1.0"),
            }],
        },
    )
    .map_err(|error| format!("Twin workspace creation failed: {error}"))
}

fn simulation_status(status: SimulatedStepStatus) -> StageStatus {
    match status {
        SimulatedStepStatus::Succeeded => StageStatus::Passed,
        SimulatedStepStatus::Rejected | SimulatedStepStatus::RolledBack => StageStatus::Failed,
        SimulatedStepStatus::Blocked => StageStatus::Blocked,
        SimulatedStepStatus::Missing => StageStatus::Unknown,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use ergaxiom_desktop_shell_runtime::{
        AuthorityStatus, StageStatus, verify_desktop_shell_snapshot,
    };

    use super::build_pipeline_snapshot;

    #[test]
    fn deterministic_pipeline_produces_verified_non_accepted_snapshot() {
        let snapshot = build_pipeline_snapshot().expect("pipeline fixture must build");
        assert!(verify_desktop_shell_snapshot(&snapshot).expect("snapshot must verify"));
        assert_eq!(snapshot.authority_status, AuthorityStatus::Ready);
        assert!(snapshot.certificate.is_none());
        assert!(snapshot.evidence_bundle.is_none());
        assert!(snapshot.steps.iter().all(|step| step.status == StageStatus::Passed));
        assert!(
            snapshot
                .validators
                .iter()
                .all(|validator| validator.status == StageStatus::Passed)
        );
        assert_eq!(
            snapshot
                .metadata
                .get("twin_validation_passed")
                .and_then(Value::as_bool),
            Some(true)
        );
    }
}
