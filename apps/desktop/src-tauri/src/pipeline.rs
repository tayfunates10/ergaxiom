use ergaxiom_contract_runtime::{CompiledContract, compile_contract};
use ergaxiom_desktop_shell_runtime::{
    ApprovalSummary, DesktopApprovalRecord, DesktopControlStatus, DesktopShellMaterial,
    DesktopShellSnapshot, DigestItem, PlanStepSummary, StageStatus, TrustComponentStatus,
    build_desktop_shell_snapshot,
};
use ergaxiom_graphic_designer_twin_runtime::{
    ApprovedCopy, ApprovedLogo, BrandProfile, CanvasSpecification, GraphicDesignJob, PixelRect,
    Rgba8,
};
use ergaxiom_intent_contract_compiler_runtime::{
    InputArtifactIntent, IntentCompileOutcome, StaticSocialPostIntent,
    compile_static_social_post_intent,
};
use ergaxiom_occupational_twin_runtime::{ApplicationIdentity, EnvironmentIdentity, TwinWorkspace};
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_typed_planner_runtime::{
    StaticSocialPostPlanIdentity, TypedPlanOutcome, synthesize_static_social_post_plan,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) const GENERATED_AT: &str = "2026-07-23T14:00:00Z";
pub(crate) const JOB_ID: &str = "job.desktop-shell.0001";

#[derive(Clone, Copy)]
pub enum PipelineSnapshotMode<'a> {
    AwaitingApproval,
    Approved(&'a DesktopApprovalRecord),
    Executed(&'a DesktopApprovalRecord),
    Cancelled(Option<&'a DesktopApprovalRecord>),
    RolledBack(&'a DesktopApprovalRecord),
}

impl<'a> PipelineSnapshotMode<'a> {
    fn control_status(self) -> DesktopControlStatus {
        match self {
            Self::AwaitingApproval => DesktopControlStatus::AwaitingApproval,
            Self::Approved(_) => DesktopControlStatus::Approved,
            Self::Executed(_) => DesktopControlStatus::Executed,
            Self::Cancelled(_) => DesktopControlStatus::Cancelled,
            Self::RolledBack(_) => DesktopControlStatus::RolledBack,
        }
    }

    fn approval(self) -> Option<&'a DesktopApprovalRecord> {
        match self {
            Self::AwaitingApproval => None,
            Self::Approved(record) | Self::Executed(record) | Self::RolledBack(record) => {
                Some(record)
            }
            Self::Cancelled(record) => record,
        }
    }

    fn approval_status(self) -> StageStatus {
        match self {
            Self::AwaitingApproval => StageStatus::Pending,
            Self::Approved(_) | Self::Executed(_) | Self::RolledBack(_) => StageStatus::Passed,
            Self::Cancelled(_) => StageStatus::Blocked,
        }
    }

    fn step_status(self) -> StageStatus {
        match self {
            Self::Cancelled(_) | Self::RolledBack(_) => StageStatus::Blocked,
            _ => StageStatus::Pending,
        }
    }
}

pub(crate) struct PreparedDesktopJob {
    pub capsule: Value,
    pub contract: Value,
    pub compiled_contract: CompiledContract,
    pub compiled_plan: CompiledPlan,
    pub job: GraphicDesignJob,
    pub staged_inputs: Vec<DigestItem>,
    pub contract_digest: String,
    pub capsule_digest: String,
    pub capability_requirement_digest: String,
    pub proof_obligation_count: usize,
    pub unresolved_mandatory_unknowns: usize,
    pub mandatory_step_count: usize,
}

pub(crate) fn prepare_desktop_job() -> Result<PreparedDesktopJob, String> {
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
        return Err("fully resolved desktop job unexpectedly needs resolution".to_owned());
    };

    let TypedPlanOutcome::Planned {
        plan,
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

    Ok(PreparedDesktopJob {
        capsule,
        contract,
        compiled_contract,
        compiled_plan,
        job,
        staged_inputs,
        contract_digest,
        capsule_digest,
        capability_requirement_digest,
        proof_obligation_count,
        unresolved_mandatory_unknowns,
        mandatory_step_count,
    })
}

pub fn build_pipeline_snapshot(
    mode: PipelineSnapshotMode<'_>,
) -> Result<DesktopShellSnapshot, String> {
    if matches!(mode, PipelineSnapshotMode::Executed(_)) {
        return Err(
            "production execution cannot be synthesized by the prepare-only desktop pipeline"
                .to_owned(),
        );
    }
    let prepared = prepare_desktop_job()?;
    let steps = prepared
        .compiled_plan
        .steps
        .iter()
        .map(|step| PlanStepSummary {
            step_id: step.step_id.clone(),
            operator_id: step.operator_id.clone(),
            status: mode.step_status(),
            before_digest: None,
            after_digest: None,
        })
        .collect();

    build_desktop_shell_snapshot(DesktopShellMaterial {
        generated_at: GENERATED_AT.to_owned(),
        job_id: Some(JOB_ID.to_owned()),
        unresolved: Vec::new(),
        staged_inputs: prepared.staged_inputs,
        contract: Some(DigestItem {
            id: prepared.compiled_contract.contract_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: prepared.contract_digest,
            status: StageStatus::Passed,
        }),
        approval: Some(ApprovalSummary {
            approval_id: mode
                .approval()
                .map(|record| record.approval_id.clone())
                .unwrap_or_else(|| "approval.desktop-shell.pending".to_owned()),
            contract_digest: prepared.compiled_contract.seal.contract_digest.clone(),
            plan_digest: prepared.compiled_plan.plan_digest.clone(),
            permission_digest: prepared.capability_requirement_digest,
            expires_at_epoch_s: mode
                .approval()
                .map(|record| record.expires_at_epoch_s)
                .unwrap_or(0),
            status: mode.approval_status(),
        }),
        plan: Some(DigestItem {
            id: prepared.compiled_plan.plan_id.clone(),
            media_type: Some("application/json".to_owned()),
            digest: prepared.compiled_plan.plan_digest.clone(),
            status: StageStatus::Passed,
        }),
        steps,
        validators: Vec::new(),
        evidence_bundle: None,
        replay_manifest: None,
        certificate: None,
        profession_capsules: vec![TrustComponentStatus {
            component_id: "ergaxiom.profession.graphic-designer".to_owned(),
            version: prepared
                .capsule
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
            digest: prepared.capsule_digest,
            trusted: true,
        }],
        adapters: vec![TrustComponentStatus {
            component_id: "ergaxiom.design-document-model".to_owned(),
            version: "0.1.0".to_owned(),
            digest: sha256_hex(b"ergaxiom.design-document-model@0.1.0"),
            trusted: true,
        }],
        trusted_keys: Vec::new(),
        metadata: json!({
            "pipeline": "intent_compiler -> typed_planner -> production_authorization_boundary",
            "control_status": mode.control_status(),
            "approval_digest": mode.approval().map(|record| record.approval_digest.clone()),
            "execution_material_exposed": false,
            "twin_executed": false,
            "proof_obligation_count": prepared.proof_obligation_count,
            "mandatory_step_count": prepared.mandatory_step_count,
            "unresolved_mandatory_unknowns": prepared.unresolved_mandatory_unknowns,
            "acceptance_blocker": "Production Capability issuance, durable consumption, Twin execution, Evidence Bundle and Acceptance Certificate are required."
        }),
    })
    .map_err(|error| format!("desktop snapshot construction failed: {error}"))
}

pub(crate) fn graphic_job() -> GraphicDesignJob {
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

pub(crate) fn twin_workspace() -> Result<TwinWorkspace, String> {
    TwinWorkspace::new(
        "workspace.desktop-shell",
        EnvironmentIdentity {
            os: "windows".to_owned(),
            architecture: "x86_64".to_owned(),
            runtime_id: "ergaxiom.desktop-shell".to_owned(),
            runtime_version: "0.1.0".to_owned(),
            clock_source: "trusted-production-boundary-clock".to_owned(),
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

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use ergaxiom_desktop_shell_runtime::{
        AuthorityStatus, DesktopApprovalRequest, StageStatus, issue_desktop_approval,
        verify_desktop_shell_snapshot,
    };

    use super::{PipelineSnapshotMode, build_pipeline_snapshot};

    #[test]
    fn pre_execution_pipeline_never_runs_or_exposes_twin_material() {
        let awaiting = build_pipeline_snapshot(PipelineSnapshotMode::AwaitingApproval)
            .expect("prepare-only pipeline must build");
        assert!(verify_desktop_shell_snapshot(&awaiting).expect("snapshot must verify"));
        assert_eq!(awaiting.authority_status, AuthorityStatus::Ready);
        assert!(awaiting.validators.is_empty());
        assert!(awaiting.replay_manifest.is_none());
        assert!(awaiting.evidence_bundle.is_none());
        assert!(awaiting.certificate.is_none());
        assert_eq!(
            awaiting.metadata.get("twin_executed").and_then(Value::as_bool),
            Some(false)
        );
        assert!(
            awaiting
                .steps
                .iter()
                .all(|step| step.status == StageStatus::Pending)
        );

        let pending = awaiting.approval.as_ref().expect("pending approval");
        let approval = issue_desktop_approval(
            &awaiting,
            &DesktopApprovalRequest {
                expected_snapshot_digest: awaiting.snapshot_digest.clone(),
                contract_digest: pending.contract_digest.clone(),
                plan_digest: pending.plan_digest.clone(),
                permission_digest: pending.permission_digest.clone(),
            },
            "ergaxiom.local.operator",
            1_000,
            900,
        )
        .expect("approval must issue");
        let approved = build_pipeline_snapshot(PipelineSnapshotMode::Approved(&approval))
            .expect("approved snapshot must build without Twin execution");
        assert_eq!(
            approved.metadata.get("twin_executed").and_then(Value::as_bool),
            Some(false)
        );
        assert!(build_pipeline_snapshot(PipelineSnapshotMode::Executed(&approval)).is_err());
    }
}
