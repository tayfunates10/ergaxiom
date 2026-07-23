#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use ergaxiom_contract_runtime::{CompiledContract, ContractCompileError, compile_contract};
use ergaxiom_operator_plan_runtime::{PlanCompileError, compile_plan};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

const CONTRACT_SCHEMA: &str = "0.2.0";
const PLAN_SCHEMA: &str = "0.1.0";
const CAPSULE_ID: &str = "ergaxiom.profession.graphic-designer";
const JOB_TYPE: &str = "social_media_static_post";
const PLANNER_ID: &str = "ergaxiom-typed-planner-runtime";
const PLANNER_VERSION: &str = "0.1.0";
const REQUIRED_OPERATORS: [&str; 4] = [
    "design.create_canvas",
    "design.place_asset",
    "design.compose_text",
    "design.export_raster",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StaticSocialPostPlanIdentity {
    pub plan_id: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanResolutionRequest {
    pub field: String,
    pub question: String,
    pub reason: String,
    pub accepted_sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedCapabilityRequirement {
    pub token_id: String,
    pub step_id: String,
    pub capability: String,
    pub resource: String,
    pub access: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TypedPlanOutcome {
    NeedsResolution {
        job_type: String,
        resolution_requests: Vec<PlanResolutionRequest>,
        resolution_digest: String,
    },
    Planned {
        job_type: String,
        plan: Value,
        plan_digest: String,
        contract_digest: String,
        capsule_digest: String,
        mandatory_step_count: usize,
        capability_requirement_digest: String,
    },
}

#[derive(Debug, Error)]
pub enum TypedPlannerError {
    #[error("plan identity field {field} is invalid: {reason}")]
    InvalidIdentityField { field: &'static str, reason: String },
    #[error("failed to decode planning fields from Work Contract: {0}")]
    ContractPlanningDecode(#[source] serde_json::Error),
    #[error("failed to decode planning fields from Profession Capsule: {0}")]
    CapsulePlanningDecode(#[source] serde_json::Error),
    #[error("compiled contract profile is unsupported: {0}")]
    UnsupportedContractProfile(&'static str),
    #[error("contract planning identity does not match the compiled contract")]
    ContractIdentityMismatch,
    #[error("capsule planning identity is invalid")]
    CapsuleIdentityMismatch,
    #[error("duplicate {kind} identifier in planning material: {id}")]
    DuplicateIdentifier { kind: &'static str, id: String },
    #[error("{profile} profile mismatch; expected {expected}, actual {actual}")]
    ProfileMismatch {
        profile: &'static str,
        expected: String,
        actual: String,
    },
    #[error("input artifact {0} must be immutable")]
    MutableInput(String),
    #[error("output artifact {0} must be required")]
    OptionalOutput(String),
    #[error("required operator is missing from the pinned capsule: {0}")]
    MissingOperator(String),
    #[error("operator version is empty in the pinned capsule: {0}")]
    EmptyOperatorVersion(String),
    #[error("internal planner invariant failed because resolved field is unavailable: {0}")]
    MissingResolvedField(&'static str),
    #[error("failed to serialize typed planner material: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Contract(#[from] ContractCompileError),
    #[error(transparent)]
    Plan(#[from] PlanCompileError),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

#[derive(Debug, Deserialize)]
struct ContractPlanningView {
    schema_version: String,
    contract_id: String,
    job_type: String,
    inputs: Vec<ContractInputView>,
    outputs: Vec<ContractOutputView>,
    permissions: Vec<ContractPermissionView>,
}

#[derive(Debug, Deserialize)]
struct ContractInputView {
    id: String,
    kind: String,
    immutable: bool,
}

#[derive(Debug, Deserialize)]
struct ContractOutputView {
    id: String,
    kind: String,
    destination: String,
    media_type: Option<String>,
    required: bool,
}

#[derive(Debug, Deserialize)]
struct ContractPermissionView {
    capability: String,
    resource: String,
    access: String,
    #[serde(default)]
    constraints: Value,
}

#[derive(Debug, Deserialize)]
struct CapsulePlanningView {
    capsule_id: String,
    version: String,
    operators: Vec<CapsuleOperatorView>,
    job_types: Vec<CapsuleJobTypeView>,
}

#[derive(Debug, Deserialize)]
struct CapsuleOperatorView {
    id: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct CapsuleJobTypeView {
    id: String,
    operator_ids: Vec<String>,
}

pub fn synthesize_static_social_post_plan(
    identity: &StaticSocialPostPlanIdentity,
    contract_value: &Value,
    capsule_value: &Value,
) -> Result<TypedPlanOutcome, TypedPlannerError> {
    validate_identity_values(identity)?;
    let resolution_requests = missing_resolution_requests(identity);
    if !resolution_requests.is_empty() {
        let resolution_value = serde_json::to_value(&resolution_requests)?;
        return Ok(TypedPlanOutcome::NeedsResolution {
            job_type: JOB_TYPE.to_owned(),
            resolution_digest: canonical_json_sha256(&resolution_value)?,
            resolution_requests,
        });
    }

    let compiled_contract = compile_contract(contract_value, capsule_value)?;
    if compiled_contract.job_type != JOB_TYPE {
        return Err(TypedPlannerError::UnsupportedContractProfile(
            "only social_media_static_post is supported by planner v1",
        ));
    }
    if compiled_contract.unresolved_mandatory_unknowns != 0 {
        return Err(TypedPlannerError::UnsupportedContractProfile(
            "unresolved mandatory unknowns block planning",
        ));
    }

    let contract: ContractPlanningView = serde_json::from_value(contract_value.clone())
        .map_err(TypedPlannerError::ContractPlanningDecode)?;
    let capsule: CapsulePlanningView = serde_json::from_value(capsule_value.clone())
        .map_err(TypedPlannerError::CapsulePlanningDecode)?;
    validate_contract_profile(&contract, &compiled_contract)?;
    validate_capsule_profile(&capsule)?;
    validate_input_profile(&contract.inputs)?;
    validate_output_profile(&contract.outputs)?;
    validate_permission_profile(&contract.permissions)?;

    let operator_versions = resolve_operator_versions(&capsule)?;
    let plan_id = resolved(identity.plan_id.as_deref(), "plan_id")?;
    let created_at = resolved(identity.created_at.as_deref(), "created_at")?;
    let capability_requirements = capability_requirements(plan_id);
    let capability_requirement_value = serde_json::to_value(&capability_requirements)?;
    let capability_requirement_digest = canonical_json_sha256(&capability_requirement_value)?;

    let plan = build_plan(
        plan_id,
        created_at,
        &compiled_contract,
        &capsule,
        &operator_versions,
        capability_requirement_value,
    );
    let compiled_plan = compile_plan(&plan, capsule_value, &compiled_contract)?;
    let mandatory_step_count = compiled_plan.mandatory_step_count();

    Ok(TypedPlanOutcome::Planned {
        job_type: JOB_TYPE.to_owned(),
        plan,
        plan_digest: compiled_plan.plan_digest,
        contract_digest: compiled_plan.contract_digest,
        capsule_digest: compiled_plan.capsule_digest,
        mandatory_step_count,
        capability_requirement_digest,
    })
}

fn validate_identity_values(
    identity: &StaticSocialPostPlanIdentity,
) -> Result<(), TypedPlannerError> {
    if let Some(plan_id) = identity.plan_id.as_deref() {
        if plan_id.is_empty()
            || !plan_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(invalid_identity(
                "plan_id",
                "must contain only ASCII letters, digits, dot, underscore or hyphen",
            ));
        }
    }
    if let Some(created_at) = identity.created_at.as_deref() {
        if created_at.len() < 20 || !created_at.contains('T') || !created_at.ends_with('Z') {
            return Err(invalid_identity(
                "created_at",
                "must be a caller-supplied UTC RFC 3339 timestamp ending in Z",
            ));
        }
    }
    Ok(())
}

fn missing_resolution_requests(
    identity: &StaticSocialPostPlanIdentity,
) -> Vec<PlanResolutionRequest> {
    let mut requests = Vec::new();
    if identity.plan_id.is_none() {
        requests.push(PlanResolutionRequest {
            field: "plan_id".to_owned(),
            question: "What stable identifier should be assigned to this Operator Plan?".to_owned(),
            reason: "The plan identifier is part of the canonical plan digest and capability-token namespace."
                .to_owned(),
            accepted_sources: vec!["trusted_orchestrator".to_owned(), "user_answer".to_owned()],
        });
    }
    if identity.created_at.is_none() {
        requests.push(PlanResolutionRequest {
            field: "created_at".to_owned(),
            question: "What trusted UTC creation timestamp should be sealed into the Operator Plan?"
                .to_owned(),
            reason: "The planner does not read the runtime clock because hidden time defaults break deterministic replay."
                .to_owned(),
            accepted_sources: vec!["trusted_clock".to_owned()],
        });
    }
    requests
}

fn validate_contract_profile(
    contract: &ContractPlanningView,
    compiled: &CompiledContract,
) -> Result<(), TypedPlannerError> {
    if contract.schema_version != CONTRACT_SCHEMA {
        return Err(TypedPlannerError::UnsupportedContractProfile(
            "Work Contract schema must be 0.2.0",
        ));
    }
    if contract.contract_id != compiled.contract_id || contract.job_type != compiled.job_type {
        return Err(TypedPlannerError::ContractIdentityMismatch);
    }
    Ok(())
}

fn validate_capsule_profile(capsule: &CapsulePlanningView) -> Result<(), TypedPlannerError> {
    if capsule.capsule_id != CAPSULE_ID || capsule.version.trim().is_empty() {
        return Err(TypedPlannerError::CapsuleIdentityMismatch);
    }
    let job_type = capsule
        .job_types
        .iter()
        .find(|candidate| candidate.id == JOB_TYPE)
        .ok_or(TypedPlannerError::UnsupportedContractProfile(
            "pinned capsule does not declare social_media_static_post",
        ))?;
    let actual = job_type.operator_ids.join(",");
    let expected = REQUIRED_OPERATORS.join(",");
    if actual != expected {
        return Err(TypedPlannerError::ProfileMismatch {
            profile: "job operator allowlist",
            expected,
            actual,
        });
    }
    Ok(())
}

fn validate_input_profile(inputs: &[ContractInputView]) -> Result<(), TypedPlannerError> {
    let expected = BTreeMap::from([
        ("approved_copy", "approved_copy"),
        ("approved_logo", "approved_logo"),
        ("brand_profile", "brand_profile"),
    ]);
    let mut actual = BTreeMap::new();
    for input in inputs {
        if actual
            .insert(input.id.as_str(), input.kind.as_str())
            .is_some()
        {
            return Err(TypedPlannerError::DuplicateIdentifier {
                kind: "contract input",
                id: input.id.clone(),
            });
        }
        if !input.immutable {
            return Err(TypedPlannerError::MutableInput(input.id.clone()));
        }
    }
    if actual != expected {
        return Err(TypedPlannerError::ProfileMismatch {
            profile: "contract input",
            expected: render_map(&expected),
            actual: render_map(&actual),
        });
    }
    Ok(())
}

fn validate_output_profile(outputs: &[ContractOutputView]) -> Result<(), TypedPlannerError> {
    let expected = BTreeMap::from([
        (
            "delivery_raster",
            (
                "delivery_raster",
                "contract://outputs/social-post.png",
                Some("image/png"),
            ),
        ),
        (
            "editable_master",
            (
                "editable_master",
                "contract://outputs/master.design",
                Some("application/x-ergaxiom-design-document"),
            ),
        ),
        (
            "evidence_bundle",
            (
                "evidence_bundle",
                "contract://outputs/evidence.json",
                Some("application/json"),
            ),
        ),
    ]);
    let mut actual = BTreeMap::new();
    for output in outputs {
        if !output.required {
            return Err(TypedPlannerError::OptionalOutput(output.id.clone()));
        }
        let profile = (
            output.kind.as_str(),
            output.destination.as_str(),
            output.media_type.as_deref(),
        );
        if actual.insert(output.id.as_str(), profile).is_some() {
            return Err(TypedPlannerError::DuplicateIdentifier {
                kind: "contract output",
                id: output.id.clone(),
            });
        }
    }
    if actual != expected {
        return Err(TypedPlannerError::ProfileMismatch {
            profile: "contract output",
            expected: render_output_map(&expected),
            actual: render_output_map(&actual),
        });
    }
    Ok(())
}

fn validate_permission_profile(
    permissions: &[ContractPermissionView],
) -> Result<(), TypedPlannerError> {
    let expected = BTreeSet::from([
        "design-editor|isolated-workspace|control|network=false".to_owned(),
        "filesystem|contract://inputs/*|read|immutable=true".to_owned(),
        "filesystem|contract://outputs/*|write|overwrite=false".to_owned(),
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
            ("design-editor", "isolated-workspace", "control") => format!(
                "network={}",
                permission
                    .constraints
                    .get("network")
                    .and_then(Value::as_bool)
                    .unwrap_or(true)
            ),
            _ => "unsupported=true".to_owned(),
        };
        let signature = format!(
            "{}|{}|{}|{}",
            permission.capability, permission.resource, permission.access, constraint
        );
        if !actual.insert(signature.clone()) {
            return Err(TypedPlannerError::DuplicateIdentifier {
                kind: "contract permission",
                id: signature,
            });
        }
    }
    if actual != expected {
        return Err(TypedPlannerError::ProfileMismatch {
            profile: "contract permission",
            expected: expected.into_iter().collect::<Vec<_>>().join(","),
            actual: actual.into_iter().collect::<Vec<_>>().join(","),
        });
    }
    Ok(())
}

fn resolve_operator_versions(
    capsule: &CapsulePlanningView,
) -> Result<BTreeMap<&str, &str>, TypedPlannerError> {
    let mut operators = BTreeMap::new();
    for operator in &capsule.operators {
        if operators
            .insert(operator.id.as_str(), operator.version.as_str())
            .is_some()
        {
            return Err(TypedPlannerError::DuplicateIdentifier {
                kind: "capsule operator",
                id: operator.id.clone(),
            });
        }
    }
    let mut selected = BTreeMap::new();
    for operator_id in REQUIRED_OPERATORS {
        let version = operators
            .get(operator_id)
            .copied()
            .ok_or_else(|| TypedPlannerError::MissingOperator(operator_id.to_owned()))?;
        if version.trim().is_empty() {
            return Err(TypedPlannerError::EmptyOperatorVersion(
                operator_id.to_owned(),
            ));
        }
        selected.insert(operator_id, version);
    }
    Ok(selected)
}

fn capability_requirements(plan_id: &str) -> Vec<PlannedCapabilityRequirement> {
    vec![
        capability(
            plan_id,
            "canvas",
            "step.canvas",
            "design-editor",
            "isolated-workspace",
            "control",
        ),
        capability(
            plan_id,
            "logo",
            "step.logo",
            "filesystem",
            "contract://inputs/*",
            "read",
        ),
        capability(
            plan_id,
            "text",
            "step.text",
            "design-editor",
            "isolated-workspace",
            "control",
        ),
        capability(
            plan_id,
            "export",
            "step.export",
            "filesystem",
            "contract://outputs/*",
            "write",
        ),
    ]
}

fn capability(
    plan_id: &str,
    suffix: &str,
    step_id: &str,
    capability: &str,
    resource: &str,
    access: &str,
) -> PlannedCapabilityRequirement {
    PlannedCapabilityRequirement {
        token_id: format!("capability.{plan_id}.{suffix}"),
        step_id: step_id.to_owned(),
        capability: capability.to_owned(),
        resource: resource.to_owned(),
        access: access.to_owned(),
    }
}

fn build_plan(
    plan_id: &str,
    created_at: &str,
    compiled: &CompiledContract,
    capsule: &CapsulePlanningView,
    versions: &BTreeMap<&str, &str>,
    capability_requirements: Value,
) -> Value {
    json!({
        "schema_version": PLAN_SCHEMA,
        "plan_id": plan_id,
        "created_at": created_at,
        "bindings": {
            "contract": {
                "id": compiled.contract_id,
                "algorithm": "sha256",
                "digest": compiled.seal.contract_digest,
                "uri": null
            },
            "profession_capsule": {
                "id": capsule.capsule_id,
                "algorithm": "sha256",
                "digest": compiled.seal.capsule_digest,
                "uri": null
            }
        },
        "steps": [
            step(
                plan_id,
                "canvas",
                "step.canvas",
                0,
                REQUIRED_OPERATORS[0],
                versions[REQUIRED_OPERATORS[0]],
                &[],
                &["brand_profile"],
                &["editable_master"]
            ),
            step(
                plan_id,
                "logo",
                "step.logo",
                1,
                REQUIRED_OPERATORS[1],
                versions[REQUIRED_OPERATORS[1]],
                &["step.canvas"],
                &["editable_master", "approved_logo"],
                &["editable_master"]
            ),
            step(
                plan_id,
                "text",
                "step.text",
                2,
                REQUIRED_OPERATORS[2],
                versions[REQUIRED_OPERATORS[2]],
                &["step.logo"],
                &["editable_master", "approved_copy"],
                &["editable_master"]
            ),
            step(
                plan_id,
                "export",
                "step.export",
                3,
                REQUIRED_OPERATORS[3],
                versions[REQUIRED_OPERATORS[3]],
                &["step.text"],
                &["editable_master"],
                &["delivery_raster"]
            )
        ],
        "metadata": {
            "planner": PLANNER_ID,
            "planner_version": PLANNER_VERSION,
            "job_type": JOB_TYPE,
            "deterministic": true,
            "implicit_defaults": false,
            "capability_requirements": capability_requirements
        }
    })
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

fn resolved<'a>(value: Option<&'a str>, field: &'static str) -> Result<&'a str, TypedPlannerError> {
    value.ok_or(TypedPlannerError::MissingResolvedField(field))
}

fn invalid_identity(field: &'static str, reason: &str) -> TypedPlannerError {
    TypedPlannerError::InvalidIdentityField {
        field,
        reason: reason.to_owned(),
    }
}

fn render_map(map: &BTreeMap<&str, &str>) -> String {
    map.iter()
        .map(|(id, kind)| format!("{id}:{kind}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn render_output_map(map: &BTreeMap<&str, (&str, &str, Option<&str>)>) -> String {
    map.iter()
        .map(|(id, (kind, destination, media_type))| {
            format!("{id}:{kind}:{destination}:{}", media_type.unwrap_or("none"))
        })
        .collect::<Vec<_>>()
        .join(",")
}
