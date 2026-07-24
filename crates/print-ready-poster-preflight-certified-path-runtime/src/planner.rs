use std::collections::{BTreeMap, BTreeSet};

use ergaxiom_contract_runtime::{ContractCompileError, compile_contract};
use ergaxiom_operator_plan_runtime::{PlanCompileError, compile_plan};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::Deserialize;
use serde_json::{Value, json};
use thiserror::Error;

use crate::compiler::{
    GRAPHIC_DESIGNER_CAPSULE_ID, PRINT_PREFLIGHT_JOB_TYPE,
};
use crate::model::{
    PrintCapabilityRequirement, PrintPreflightPlanIdentity, PrintPreflightPlanOutcome,
    PrintResolutionRequest,
};

const PLAN_SCHEMA: &str = "0.1.0";
const REQUIRED_OPERATORS: [&str; 3] = [
    "print.validate_source",
    "print.export_pdf_with_inkscape",
    "print.certify_preflight",
];

#[derive(Debug, Error)]
pub enum PrintPreflightPlannerError {
    #[error("plan identity field {field} is invalid: {reason}")]
    InvalidIdentityField { field: &'static str, reason: String },
    #[error("failed to decode Work Contract planning fields: {0}")]
    ContractDecode(#[source] serde_json::Error),
    #[error("failed to decode Profession Capsule planning fields: {0}")]
    CapsuleDecode(#[source] serde_json::Error),
    #[error("unsupported print-preflight contract profile: {0}")]
    UnsupportedProfile(&'static str),
    #[error("duplicate {kind} identifier: {id}")]
    DuplicateIdentifier { kind: &'static str, id: String },
    #[error("profile mismatch for {profile}; expected {expected}, actual {actual}")]
    ProfileMismatch {
        profile: &'static str,
        expected: String,
        actual: String,
    },
    #[error("required operator is missing: {0}")]
    MissingOperator(String),
    #[error("operator version is empty: {0}")]
    EmptyOperatorVersion(String),
    #[error("resolved plan identity is unavailable: {0}")]
    MissingResolvedField(&'static str),
    #[error("failed to serialize planner material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Contract(#[from] ContractCompileError),
    #[error(transparent)]
    Plan(#[from] PlanCompileError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

#[derive(Debug, Deserialize)]
struct ContractView {
    job_type: String,
    inputs: Vec<InputView>,
    outputs: Vec<OutputView>,
    permissions: Vec<PermissionView>,
}

#[derive(Debug, Deserialize)]
struct InputView {
    id: String,
    kind: String,
    immutable: bool,
}

#[derive(Debug, Deserialize)]
struct OutputView {
    id: String,
    kind: String,
    destination: String,
    media_type: Option<String>,
    required: bool,
}

#[derive(Debug, Deserialize)]
struct PermissionView {
    capability: String,
    resource: String,
    access: String,
    #[serde(default)]
    constraints: Value,
}

#[derive(Debug, Deserialize)]
struct CapsuleView {
    capsule_id: String,
    version: String,
    operators: Vec<OperatorView>,
    job_types: Vec<JobView>,
}

#[derive(Debug, Deserialize)]
struct OperatorView {
    id: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct JobView {
    id: String,
    operator_ids: Vec<String>,
}

pub fn synthesize_print_preflight_plan(
    identity: &PrintPreflightPlanIdentity,
    contract_value: &Value,
    capsule_value: &Value,
) -> Result<PrintPreflightPlanOutcome, PrintPreflightPlannerError> {
    validate_identity(identity)?;
    let resolution_requests = missing_resolution_requests(identity);
    if !resolution_requests.is_empty() {
        let value = serde_json::to_value(&resolution_requests)?;
        return Ok(PrintPreflightPlanOutcome::NeedsResolution {
            job_type: PRINT_PREFLIGHT_JOB_TYPE.to_owned(),
            resolution_digest: canonical_json_sha256(&value)?,
            resolution_requests,
        });
    }
    let compiled_contract = compile_contract(contract_value, capsule_value)?;
    if compiled_contract.job_type != PRINT_PREFLIGHT_JOB_TYPE
        || compiled_contract.unresolved_mandatory_unknowns != 0
    {
        return Err(PrintPreflightPlannerError::UnsupportedProfile(
            "contract must be a fully resolved print_ready_poster_preflight",
        ));
    }
    let contract: ContractView = serde_json::from_value(contract_value.clone())
        .map_err(PrintPreflightPlannerError::ContractDecode)?;
    let capsule: CapsuleView = serde_json::from_value(capsule_value.clone())
        .map_err(PrintPreflightPlannerError::CapsuleDecode)?;
    validate_contract(&contract)?;
    validate_capsule(&capsule)?;
    let versions = operator_versions(&capsule)?;
    let plan_id = resolved(identity.plan_id.as_deref(), "plan_id")?;
    let created_at = resolved(identity.created_at.as_deref(), "created_at")?;
    let capability_requirements = capabilities(plan_id);
    let capability_value = serde_json::to_value(&capability_requirements)?;
    let capability_requirement_digest = canonical_json_sha256(&capability_value)?;
    let plan = json!({
        "schema_version": PLAN_SCHEMA,
        "plan_id": plan_id,
        "created_at": created_at,
        "bindings": {
            "contract": {
                "id": compiled_contract.contract_id,
                "algorithm": "sha256",
                "digest": compiled_contract.seal.contract_digest,
                "uri": null
            },
            "profession_capsule": {
                "id": capsule.capsule_id,
                "algorithm": "sha256",
                "digest": compiled_contract.seal.capsule_digest,
                "uri": null
            }
        },
        "steps": [
            step(plan_id, "validate", "step.validate", 0, REQUIRED_OPERATORS[0], versions[REQUIRED_OPERATORS[0]], &[], &["source_svg", "print_specification"], &[]),
            step(plan_id, "export", "step.export", 1, REQUIRED_OPERATORS[1], versions[REQUIRED_OPERATORS[1]], &["step.validate"], &["source_svg", "print_specification"], &["editable_master", "delivery_pdf"]),
            step(plan_id, "certify", "step.certify", 2, REQUIRED_OPERATORS[2], versions[REQUIRED_OPERATORS[2]], &["step.export"], &["editable_master", "delivery_pdf"], &["evidence_bundle"])
        ],
        "metadata": {
            "planner": "ergaxiom-print-ready-poster-preflight-certified-path-runtime",
            "planner_version": "0.1.0",
            "job_type": PRINT_PREFLIGHT_JOB_TYPE,
            "deterministic": true,
            "implicit_defaults": false,
            "capability_requirements": capability_value
        }
    });
    let compiled_plan = compile_plan(&plan, capsule_value, &compiled_contract)?;
    Ok(PrintPreflightPlanOutcome::Planned {
        job_type: PRINT_PREFLIGHT_JOB_TYPE.to_owned(),
        plan,
        plan_digest: compiled_plan.plan_digest,
        contract_digest: compiled_plan.contract_digest,
        capsule_digest: compiled_plan.capsule_digest,
        mandatory_step_count: compiled_plan.mandatory_step_count(),
        capability_requirements,
        capability_requirement_digest,
    })
}

fn validate_identity(identity: &PrintPreflightPlanIdentity) -> Result<(), PrintPreflightPlannerError> {
    if let Some(plan_id) = identity.plan_id.as_deref() {
        if plan_id.is_empty()
            || !plan_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(PrintPreflightPlannerError::InvalidIdentityField {
                field: "plan_id",
                reason: "must contain only ASCII letters, digits, dot, underscore or hyphen"
                    .to_owned(),
            });
        }
    }
    if let Some(created_at) = identity.created_at.as_deref() {
        if created_at.len() < 20 || !created_at.contains('T') || !created_at.ends_with('Z') {
            return Err(PrintPreflightPlannerError::InvalidIdentityField {
                field: "created_at",
                reason: "must be a caller-supplied UTC RFC 3339 timestamp ending in Z".to_owned(),
            });
        }
    }
    Ok(())
}

fn missing_resolution_requests(identity: &PrintPreflightPlanIdentity) -> Vec<PrintResolutionRequest> {
    let mut requests = Vec::new();
    if identity.plan_id.is_none() {
        requests.push(PrintResolutionRequest {
            field: "plan_id".to_owned(),
            question: "What stable identifier should be assigned to this preflight plan?".to_owned(),
            reason: "The identifier is part of the plan digest and capability namespace."
                .to_owned(),
            accepted_sources: vec!["trusted_orchestrator".to_owned(), "user_answer".to_owned()],
        });
    }
    if identity.created_at.is_none() {
        requests.push(PrintResolutionRequest {
            field: "created_at".to_owned(),
            question: "What trusted UTC timestamp should be sealed into the plan?".to_owned(),
            reason: "The planner does not read a hidden runtime clock.".to_owned(),
            accepted_sources: vec!["trusted_clock".to_owned()],
        });
    }
    requests
}

fn validate_contract(contract: &ContractView) -> Result<(), PrintPreflightPlannerError> {
    if contract.job_type != PRINT_PREFLIGHT_JOB_TYPE {
        return Err(PrintPreflightPlannerError::UnsupportedProfile(
            "job type mismatch",
        ));
    }
    let expected_inputs = BTreeMap::from([
        ("print_specification", "print_specification"),
        ("source_svg", "source_svg"),
    ]);
    let mut actual_inputs = BTreeMap::new();
    for input in &contract.inputs {
        if !input.immutable {
            return Err(PrintPreflightPlannerError::UnsupportedProfile(
                "all inputs must be immutable",
            ));
        }
        if actual_inputs
            .insert(input.id.as_str(), input.kind.as_str())
            .is_some()
        {
            return Err(PrintPreflightPlannerError::DuplicateIdentifier {
                kind: "input",
                id: input.id.clone(),
            });
        }
    }
    if actual_inputs != expected_inputs {
        return Err(PrintPreflightPlannerError::ProfileMismatch {
            profile: "inputs",
            expected: render_map(&expected_inputs),
            actual: render_map(&actual_inputs),
        });
    }
    let expected_outputs = BTreeSet::from([
        "delivery_pdf|delivery_pdf|contract://outputs/print-ready-poster.pdf|application/pdf",
        "editable_master|editable_master|contract://outputs/print-ready-poster.svg|image/svg+xml",
        "evidence_bundle|evidence_bundle|contract://outputs/print-ready-poster-evidence.json|application/json",
    ]);
    let mut actual_outputs = BTreeSet::new();
    for output in &contract.outputs {
        if !output.required {
            return Err(PrintPreflightPlannerError::UnsupportedProfile(
                "all outputs must be required",
            ));
        }
        let signature = format!(
            "{}|{}|{}|{}",
            output.id,
            output.kind,
            output.destination,
            output.media_type.as_deref().unwrap_or("none")
        );
        if !actual_outputs.insert(signature.clone()) {
            return Err(PrintPreflightPlannerError::DuplicateIdentifier {
                kind: "output",
                id: signature,
            });
        }
    }
    if actual_outputs != expected_outputs {
        return Err(PrintPreflightPlannerError::ProfileMismatch {
            profile: "outputs",
            expected: expected_outputs.into_iter().collect::<Vec<_>>().join(","),
            actual: actual_outputs.into_iter().collect::<Vec<_>>().join(","),
        });
    }
    validate_permissions(&contract.permissions)
}

fn validate_permissions(permissions: &[PermissionView]) -> Result<(), PrintPreflightPlannerError> {
    let expected = BTreeSet::from([
        "design-editor|print-export|control|network=false".to_owned(),
        "filesystem|contract://inputs/*|read|immutable=true".to_owned(),
        "filesystem|contract://outputs/*|write|overwrite=false".to_owned(),
        "print-validator|isolated-workspace|control|network=false".to_owned(),
    ]);
    let mut actual = BTreeSet::new();
    for permission in permissions {
        let constraint = match (
            permission.capability.as_str(),
            permission.resource.as_str(),
            permission.access.as_str(),
        ) {
            ("filesystem", "contract://inputs/*", "read") => format!(
                "immutable={}",
                permission
                    .constraints
                    .get("immutable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            ),
            ("filesystem", "contract://outputs/*", "write") => format!(
                "overwrite={}",
                permission
                    .constraints
                    .get("overwrite")
                    .and_then(Value::as_bool)
                    .unwrap_or(true)
            ),
            ("print-validator", "isolated-workspace", "control")
            | ("design-editor", "print-export", "control") => format!(
                "network={}",
                permission
                    .constraints
                    .get("network")
                    .and_then(Value::as_bool)
                    .unwrap_or(true)
            ),
            _ => "unsupported=true".to_owned(),
        };
        actual.insert(format!(
            "{}|{}|{}|{}",
            permission.capability, permission.resource, permission.access, constraint
        ));
    }
    if actual != expected {
        return Err(PrintPreflightPlannerError::ProfileMismatch {
            profile: "permissions",
            expected: expected.into_iter().collect::<Vec<_>>().join(","),
            actual: actual.into_iter().collect::<Vec<_>>().join(","),
        });
    }
    Ok(())
}

fn validate_capsule(capsule: &CapsuleView) -> Result<(), PrintPreflightPlannerError> {
    if capsule.capsule_id != GRAPHIC_DESIGNER_CAPSULE_ID || capsule.version.trim().is_empty() {
        return Err(PrintPreflightPlannerError::UnsupportedProfile(
            "capsule identity mismatch",
        ));
    }
    let job = capsule
        .job_types
        .iter()
        .find(|job| job.id == PRINT_PREFLIGHT_JOB_TYPE)
        .ok_or(PrintPreflightPlannerError::UnsupportedProfile(
            "capsule job is missing",
        ))?;
    let actual = job.operator_ids.join(",");
    let expected = REQUIRED_OPERATORS.join(",");
    if actual != expected {
        return Err(PrintPreflightPlannerError::ProfileMismatch {
            profile: "operator allowlist",
            expected,
            actual,
        });
    }
    Ok(())
}

fn operator_versions(
    capsule: &CapsuleView,
) -> Result<BTreeMap<&str, &str>, PrintPreflightPlannerError> {
    let all: BTreeMap<&str, &str> = capsule
        .operators
        .iter()
        .map(|operator| (operator.id.as_str(), operator.version.as_str()))
        .collect();
    let mut selected = BTreeMap::new();
    for operator_id in REQUIRED_OPERATORS {
        let version = all
            .get(operator_id)
            .copied()
            .ok_or_else(|| PrintPreflightPlannerError::MissingOperator(operator_id.to_owned()))?;
        if version.trim().is_empty() {
            return Err(PrintPreflightPlannerError::EmptyOperatorVersion(
                operator_id.to_owned(),
            ));
        }
        selected.insert(operator_id, version);
    }
    Ok(selected)
}

fn capabilities(plan_id: &str) -> Vec<PrintCapabilityRequirement> {
    vec![
        capability(
            plan_id,
            "validate",
            "step.validate",
            "print-validator",
            "isolated-workspace",
        ),
        capability(
            plan_id,
            "export",
            "step.export",
            "design-editor",
            "print-export",
        ),
        capability(
            plan_id,
            "certify",
            "step.certify",
            "print-validator",
            "isolated-workspace",
        ),
    ]
}

fn capability(
    plan_id: &str,
    suffix: &str,
    step_id: &str,
    capability: &str,
    resource: &str,
) -> PrintCapabilityRequirement {
    PrintCapabilityRequirement {
        token_id: format!("capability.{plan_id}.{suffix}"),
        step_id: step_id.to_owned(),
        capability: capability.to_owned(),
        resource: resource.to_owned(),
        access: "control".to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
fn step(
    plan_id: &str,
    token_suffix: &str,
    step_id: &str,
    sequence: usize,
    operator_id: &str,
    operator_version: &str,
    depends_on: &[&str],
    input_artifact_ids: &[&str],
    output_artifact_ids: &[&str],
) -> Value {
    json!({
        "step_id": step_id,
        "sequence": sequence,
        "operator_id": operator_id,
        "operator_version": operator_version,
        "depends_on": depends_on,
        "input_artifact_ids": input_artifact_ids,
        "output_artifact_ids": output_artifact_ids,
        "capability_token_ids": [format!("capability.{plan_id}.{token_suffix}")],
        "mandatory": true,
        "rollback_step_id": null
    })
}

fn resolved<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, PrintPreflightPlannerError> {
    value.ok_or(PrintPreflightPlannerError::MissingResolvedField(field))
}

fn render_map(map: &BTreeMap<&str, &str>) -> String {
    map.iter()
        .map(|(id, kind)| format!("{id}:{kind}"))
        .collect::<Vec<_>>()
        .join(",")
}
