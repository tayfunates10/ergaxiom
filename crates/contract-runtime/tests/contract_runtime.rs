use std::error::Error;

use ergaxiom_contract_runtime::{
    ContractCompileError, ContractRuntimeError, ContractSession, compile_contract,
};
use ergaxiom_proof_kernel::{
    AssuranceLevel, EvidenceRecord, IndependenceClass, ObligationState, TruthValue,
};
use serde_json::{Value, json};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");

fn documents() -> Result<(Value, Value), serde_json::Error> {
    Ok((
        serde_json::from_str(CONTRACT_SOURCE)?,
        serde_json::from_str(CAPSULE_SOURCE)?,
    ))
}

fn evidence(
    contract_digest: &str,
    obligation_id: &str,
    constraint_id: &str,
    validator_id: &str,
    validator_version: &str,
) -> EvidenceRecord {
    EvidenceRecord {
        evidence_id: format!("evidence.{validator_id}"),
        obligation_id: obligation_id.to_owned(),
        constraint_id: constraint_id.to_owned(),
        contract_digest: contract_digest.to_owned(),
        subject_digest: "subject-sha256".to_owned(),
        validator_id: validator_id.to_owned(),
        validator_version: validator_version.to_owned(),
        result: TruthValue::True,
        independence: IndependenceClass::Independent,
        observed_at: "2026-07-20T20:45:00Z".to_owned(),
    }
}

#[test]
fn compiles_the_repository_example_into_a_sealed_plan() -> Result<(), Box<dyn Error>> {
    let (contract, capsule) = documents()?;
    let compiled = compile_contract(&contract, &capsule)?;

    assert_eq!(compiled.contract_id, "example.social-post.0001");
    assert_eq!(compiled.job_type, "social_media_static_post");
    assert_eq!(compiled.minimum_assurance_level, AssuranceLevel::E3);
    assert_eq!(compiled.unresolved_mandatory_unknowns, 0);
    assert_eq!(compiled.proof_obligation_count(), 8);
    assert_eq!(compiled.seal.contract_digest.len(), 64);
    assert_eq!(compiled.seal.capsule_digest.len(), 64);
    Ok(())
}

#[test]
fn diverse_obligation_needs_both_authorized_validators() -> Result<(), Box<dyn Error>> {
    let (contract, capsule) = documents()?;
    let compiled = compile_contract(&contract, &capsule)?;
    let digest = compiled.seal.contract_digest.clone();
    let mut session = ContractSession::new(compiled, AssuranceLevel::E3)?;

    let first_state = session.ingest_evidence(evidence(
        &digest,
        "proof.minimum_text_contrast",
        "minimum_text_contrast",
        "raster.text_contrast.relative_luminance",
        "0.1.0",
    ))?;
    assert_eq!(first_state, ObligationState::Indeterminate);

    let second_state = session.ingest_evidence(evidence(
        &digest,
        "proof.minimum_text_contrast",
        "minimum_text_contrast",
        "raster.text_contrast.render_sampling",
        "0.1.0",
    ))?;
    assert_eq!(second_state, ObligationState::Satisfied);
    Ok(())
}

#[test]
fn unauthorized_validator_is_rejected_before_the_proof_kernel() -> Result<(), Box<dyn Error>> {
    let (contract, capsule) = documents()?;
    let compiled = compile_contract(&contract, &capsule)?;
    let digest = compiled.seal.contract_digest.clone();
    let mut session = ContractSession::new(compiled, AssuranceLevel::E3)?;

    let result = session.ingest_evidence(evidence(
        &digest,
        "proof.canvas_width",
        "canvas_width",
        "validator.not-in-capsule",
        "0.1.0",
    ));
    assert!(matches!(
        result,
        Err(ContractRuntimeError::UnauthorizedValidator { .. })
    ));
    Ok(())
}

#[test]
fn validator_version_must_match_the_sealed_capsule() -> Result<(), Box<dyn Error>> {
    let (contract, capsule) = documents()?;
    let compiled = compile_contract(&contract, &capsule)?;
    let digest = compiled.seal.contract_digest.clone();
    let mut session = ContractSession::new(compiled, AssuranceLevel::E3)?;

    let result = session.ingest_evidence(evidence(
        &digest,
        "proof.canvas_width",
        "canvas_width",
        "raster.dimensions",
        "99.0.0",
    ));
    assert!(matches!(
        result,
        Err(ContractRuntimeError::ValidatorVersionMismatch { .. })
    ));
    Ok(())
}

#[test]
fn one_validator_cannot_compile_as_diverse_proof() -> Result<(), Box<dyn Error>> {
    let (mut contract, capsule) = documents()?;
    contract["proof_obligations"][6]["validator_ids"] =
        json!(["raster.text_contrast.relative_luminance"]);

    let result = compile_contract(&contract, &capsule);
    assert!(matches!(
        result,
        Err(ContractCompileError::InsufficientValidatorIndependence { .. })
    ));
    Ok(())
}

#[test]
fn capsule_version_mismatch_fails_closed() -> Result<(), Box<dyn Error>> {
    let (mut contract, capsule) = documents()?;
    contract["profession"]["capsule_version"] = json!("0.1.0");

    let result = compile_contract(&contract, &capsule);
    assert!(matches!(
        result,
        Err(ContractCompileError::CapsuleVersionMismatch { .. })
    ));
    Ok(())
}

#[test]
fn contract_digest_changes_after_a_material_edit() -> Result<(), Box<dyn Error>> {
    let (contract, capsule) = documents()?;
    let original = compile_contract(&contract, &capsule)?;

    let mut modified_contract = contract;
    modified_contract["requirements"]["hard"][0]["expected"] = json!(1081);
    let modified = compile_contract(&modified_contract, &capsule)?;

    assert_ne!(original.seal.contract_digest, modified.seal.contract_digest);
    Ok(())
}
