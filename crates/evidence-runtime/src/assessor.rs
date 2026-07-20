use std::collections::{BTreeMap, BTreeSet};

use ergaxiom_contract_runtime::{CompiledContract, ContractRuntimeError, ContractSession};
use ergaxiom_proof_kernel::{
    AcceptanceDecision, AssuranceLevel, DecisionStatus, EvidenceRecord, HashingError,
    ObligationState, TruthValue, canonical_json_sha256,
};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    ArtifactEvidence, ArtifactRole, DigestAlgorithm, EvidenceBundle, ProofResultStatus,
};

const SUPPORTED_EVIDENCE_SCHEMA: &str = "0.2.0";

#[derive(Debug, Error)]
pub enum EvidenceBundleError {
    #[error("failed to decode Evidence Bundle: {0}")]
    BundleDecode(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    ContractRuntime(#[from] ContractRuntimeError),
    #[error("unsupported Evidence Bundle schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        actual: String,
        expected: &'static str,
    },
    #[error("bundle contract ID {actual} does not match compiled contract {expected}")]
    ContractBindingIdMismatch { actual: String, expected: String },
    #[error("bundle contract digest does not match the compiled contract")]
    ContractDigestMismatch,
    #[error("bundle profession-capsule digest does not match the compiled capsule")]
    CapsuleDigestMismatch,
    #[error("binding {0} must use sha256")]
    UnsupportedBindingAlgorithm(&'static str),
    #[error("execution trace does not conform to the sealed operator plan")]
    TraceNonConformance,
    #[error("duplicate artifact identifier: {0}")]
    DuplicateArtifact(String),
    #[error("proof result references unknown subject artifact {0}")]
    UnknownSubjectArtifact(String),
    #[error("proof result references unknown evidence artifact {0}")]
    UnknownEvidenceArtifact(String),
    #[error("artifact {0} is not declared with evidence role")]
    InvalidEvidenceArtifactRole(String),
    #[error("proof result references unknown obligation {0}")]
    UnknownProofObligation(String),
    #[error("proof result claim {actual} does not match obligation claim {expected}")]
    ClaimMismatch { actual: String, expected: String },
    #[error("proof result mandatory flag for {obligation_id} is {actual}, expected {expected}")]
    MandatoryFlagMismatch {
        obligation_id: String,
        actual: bool,
        expected: bool,
    },
    #[error("claimed assurance {claimed:?} does not match verified assurance {verified:?}")]
    ClaimedAssuranceMismatch {
        claimed: AssuranceLevel,
        verified: AssuranceLevel,
    },
    #[error("claimed decision does not match recomputed decision: {0}")]
    ClaimedDecisionMismatch(String),
}

#[derive(Debug, Clone)]
pub struct BundleAssessment {
    pub bundle_id: String,
    pub run_id: String,
    pub bundle_digest: String,
    pub verified_assurance_level: AssuranceLevel,
    pub mandatory_passed: usize,
    pub mandatory_failed: usize,
    pub mandatory_unknown: usize,
    pub decision: AcceptanceDecision,
}

pub fn assess_bundle(
    compiled: CompiledContract,
    bundle_value: &Value,
    verified_assurance_level: AssuranceLevel,
) -> Result<BundleAssessment, EvidenceBundleError> {
    let bundle: EvidenceBundle = serde_json::from_value(bundle_value.clone())
        .map_err(EvidenceBundleError::BundleDecode)?;

    if bundle.schema_version != SUPPORTED_EVIDENCE_SCHEMA {
        return Err(EvidenceBundleError::UnsupportedSchemaVersion {
            actual: bundle.schema_version,
            expected: SUPPORTED_EVIDENCE_SCHEMA,
        });
    }
    validate_bindings(&compiled, &bundle)?;
    if !bundle.trace.conforms_to_plan {
        return Err(EvidenceBundleError::TraceNonConformance);
    }
    if bundle.claimed_decision.assurance_level != verified_assurance_level {
        return Err(EvidenceBundleError::ClaimedAssuranceMismatch {
            claimed: bundle.claimed_decision.assurance_level,
            verified: verified_assurance_level,
        });
    }

    let artifacts = index_artifacts(&bundle.artifacts)?;
    let requirements: BTreeMap<_, _> = compiled
        .proof_requirements
        .iter()
        .cloned()
        .map(|requirement| (requirement.obligation_id.clone(), requirement))
        .collect();
    let contract_digest = compiled.seal.contract_digest.clone();
    let mut evidence_ids = BTreeSet::new();
    let mut session = ContractSession::new(compiled, verified_assurance_level)?;

    for result in &bundle.proof_results {
        if !evidence_ids.insert(result.evidence_id.as_str()) {
            return Err(EvidenceBundleError::ClaimedDecisionMismatch(format!(
                "duplicate evidence ID {}",
                result.evidence_id
            )));
        }
        let requirement = requirements.get(&result.obligation_id).ok_or_else(|| {
            EvidenceBundleError::UnknownProofObligation(result.obligation_id.clone())
        })?;
        if result.claim_id != requirement.constraint_id {
            return Err(EvidenceBundleError::ClaimMismatch {
                actual: result.claim_id.clone(),
                expected: requirement.constraint_id.clone(),
            });
        }
        if result.mandatory != requirement.mandatory {
            return Err(EvidenceBundleError::MandatoryFlagMismatch {
                obligation_id: result.obligation_id.clone(),
                actual: result.mandatory,
                expected: requirement.mandatory,
            });
        }

        let subject = artifacts
            .get(result.subject_artifact_id.as_str())
            .ok_or_else(|| {
                EvidenceBundleError::UnknownSubjectArtifact(result.subject_artifact_id.clone())
            })?;
        for evidence_artifact_id in &result.evidence_artifact_ids {
            let artifact = artifacts
                .get(evidence_artifact_id.as_str())
                .ok_or_else(|| {
                    EvidenceBundleError::UnknownEvidenceArtifact(evidence_artifact_id.clone())
                })?;
            if artifact.role != ArtifactRole::Evidence {
                return Err(EvidenceBundleError::InvalidEvidenceArtifactRole(
                    evidence_artifact_id.clone(),
                ));
            }
        }

        session.ingest_evidence(EvidenceRecord {
            evidence_id: result.evidence_id.clone(),
            obligation_id: result.obligation_id.clone(),
            constraint_id: result.claim_id.clone(),
            contract_digest: contract_digest.clone(),
            subject_digest: subject.digest.clone(),
            validator_id: result.validator_id.clone(),
            validator_version: result.validator_version.clone(),
            result: truth_value(result.status),
            independence: result.independence_class,
            observed_at: result.evaluated_at.clone(),
        })?;
    }

    let decision = session.evaluate();
    let (mandatory_passed, mandatory_failed, mandatory_unknown) = count_mandatory(&decision);
    validate_claimed_decision(
        &bundle,
        &decision,
        mandatory_passed,
        mandatory_failed,
        mandatory_unknown,
    )?;

    Ok(BundleAssessment {
        bundle_id: bundle.bundle_id,
        run_id: bundle.run_id,
        bundle_digest: canonical_json_sha256(bundle_value)?,
        verified_assurance_level,
        mandatory_passed,
        mandatory_failed,
        mandatory_unknown,
        decision,
    })
}

fn validate_bindings(
    compiled: &CompiledContract,
    bundle: &EvidenceBundle,
) -> Result<(), EvidenceBundleError> {
    if bundle.bindings.contract.algorithm != DigestAlgorithm::Sha256 {
        return Err(EvidenceBundleError::UnsupportedBindingAlgorithm("contract"));
    }
    if bundle.bindings.profession_capsule.algorithm != DigestAlgorithm::Sha256 {
        return Err(EvidenceBundleError::UnsupportedBindingAlgorithm(
            "profession_capsule",
        ));
    }
    if bundle.bindings.contract.id != compiled.contract_id {
        return Err(EvidenceBundleError::ContractBindingIdMismatch {
            actual: bundle.bindings.contract.id.clone(),
            expected: compiled.contract_id.clone(),
        });
    }
    if bundle.bindings.contract.digest != compiled.seal.contract_digest {
        return Err(EvidenceBundleError::ContractDigestMismatch);
    }
    if bundle.bindings.profession_capsule.digest != compiled.seal.capsule_digest {
        return Err(EvidenceBundleError::CapsuleDigestMismatch);
    }
    Ok(())
}

fn index_artifacts(
    artifacts: &[ArtifactEvidence],
) -> Result<BTreeMap<&str, &ArtifactEvidence>, EvidenceBundleError> {
    let mut index = BTreeMap::new();
    for artifact in artifacts {
        if index
            .insert(artifact.artifact_id.as_str(), artifact)
            .is_some()
        {
            return Err(EvidenceBundleError::DuplicateArtifact(
                artifact.artifact_id.clone(),
            ));
        }
    }
    Ok(index)
}

fn truth_value(status: ProofResultStatus) -> TruthValue {
    match status {
        ProofResultStatus::Passed => TruthValue::True,
        ProofResultStatus::Failed => TruthValue::False,
        ProofResultStatus::Unknown => TruthValue::Unknown,
    }
}

fn count_mandatory(decision: &AcceptanceDecision) -> (usize, usize, usize) {
    let mut passed = 0_usize;
    let mut failed = 0_usize;
    let mut unknown = 0_usize;

    for report in decision
        .obligation_reports
        .iter()
        .filter(|report| report.mandatory)
    {
        match report.state {
            ObligationState::Satisfied => passed += 1,
            ObligationState::Failed | ObligationState::Invalidated => failed += 1,
            ObligationState::Pending | ObligationState::Indeterminate => unknown += 1,
        }
    }
    (passed, failed, unknown)
}

fn validate_claimed_decision(
    bundle: &EvidenceBundle,
    decision: &AcceptanceDecision,
    mandatory_passed: usize,
    mandatory_failed: usize,
    mandatory_unknown: usize,
) -> Result<(), EvidenceBundleError> {
    let claimed = &bundle.claimed_decision;
    if claimed.status != decision.status {
        return Err(EvidenceBundleError::ClaimedDecisionMismatch(format!(
            "status {:?} != {:?}",
            claimed.status, decision.status
        )));
    }
    if claimed.mandatory_passed != mandatory_passed
        || claimed.mandatory_failed != mandatory_failed
        || claimed.mandatory_unknown != mandatory_unknown
    {
        return Err(EvidenceBundleError::ClaimedDecisionMismatch(format!(
            "counts ({}, {}, {}) != ({mandatory_passed}, {mandatory_failed}, {mandatory_unknown})",
            claimed.mandatory_passed, claimed.mandatory_failed, claimed.mandatory_unknown
        )));
    }
    if decision.status == DecisionStatus::Accepted && mandatory_unknown > 0 {
        return Err(EvidenceBundleError::ClaimedDecisionMismatch(
            "accepted decision contains mandatory unknowns".to_owned(),
        ));
    }
    Ok(())
}
