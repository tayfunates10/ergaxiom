use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_evidence_runtime::{
    EvidenceBundle, EvidenceBundleError, assess_bundle,
};
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, HashingError, canonical_json_bytes, canonical_json_sha256,
};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    AcceptanceCertificatePayload, AttestationPackage, AttestationSignature,
    AttestationSignatureAlgorithm, AttestationSignatureEncoding, ReplayArtifact, ReplayManifest,
    SignedAcceptanceCertificate,
};

const REPLAY_MANIFEST_SCHEMA: &str = "0.1.0";
const ACCEPTANCE_CERTIFICATE_SCHEMA: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum AttestationIssueError {
    #[error(transparent)]
    Evidence(#[from] EvidenceBundleError),
    #[error("failed to decode independently accepted Evidence Bundle: {0}")]
    BundleDecode(#[source] serde_json::Error),
    #[error("failed to serialize attestation payload: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("attestation field is empty: {0}")]
    EmptyField(&'static str),
    #[error("acceptance certificate cannot be issued for decision {0:?}")]
    DecisionNotAccepted(DecisionStatus),
    #[error("accepted assessment contains failed or unknown mandatory obligations")]
    InvalidAcceptedCounts,
}

#[allow(clippy::too_many_arguments)]
pub fn issue_attestation(
    compiled_contract: CompiledContract,
    compiled_plan: &CompiledPlan,
    bundle_value: &Value,
    verified_assurance_level: AssuranceLevel,
    manifest_id: &str,
    certificate_id: &str,
    issuer_id: &str,
    key_id: &str,
    issued_at_epoch_s: u64,
    signing_key: &SigningKey,
) -> Result<AttestationPackage, AttestationIssueError> {
    require_non_empty("manifest_id", manifest_id)?;
    require_non_empty("certificate_id", certificate_id)?;
    require_non_empty("issuer_id", issuer_id)?;
    require_non_empty("key_id", key_id)?;

    let assessment = assess_bundle(
        compiled_contract,
        compiled_plan,
        bundle_value,
        verified_assurance_level,
    )?;
    if assessment.decision.status != DecisionStatus::Accepted {
        return Err(AttestationIssueError::DecisionNotAccepted(
            assessment.decision.status,
        ));
    }
    if assessment.mandatory_failed > 0 || assessment.mandatory_unknown > 0 {
        return Err(AttestationIssueError::InvalidAcceptedCounts);
    }

    let bundle: EvidenceBundle = serde_json::from_value(bundle_value.clone())
        .map_err(AttestationIssueError::BundleDecode)?;
    let replay_manifest = build_replay_manifest(
        manifest_id,
        compiled_plan,
        &bundle,
        &assessment.bundle_digest,
        assessment.decision.status,
        verified_assurance_level,
        assessment.mandatory_passed,
        assessment.mandatory_failed,
        assessment.mandatory_unknown,
    )?;
    let manifest_value = serde_json::to_value(&replay_manifest)
        .map_err(AttestationIssueError::Serialization)?;
    let replay_manifest_digest = canonical_json_sha256(&manifest_value)?;
    let authorized_trace_digest = replay_manifest.authorized_trace_digest.clone();

    let payload = AcceptanceCertificatePayload {
        schema_version: ACCEPTANCE_CERTIFICATE_SCHEMA.to_owned(),
        certificate_id: certificate_id.to_owned(),
        issuer_id: issuer_id.to_owned(),
        key_id: key_id.to_owned(),
        issued_at_epoch_s,
        contract_digest: compiled_plan.contract_digest.clone(),
        capsule_digest: compiled_plan.capsule_digest.clone(),
        plan_id: compiled_plan.plan_id.clone(),
        plan_digest: compiled_plan.plan_digest.clone(),
        evidence_bundle_id: assessment.bundle_id,
        run_id: assessment.run_id,
        evidence_bundle_digest: assessment.bundle_digest,
        authorized_trace_digest,
        replay_manifest_digest,
        assurance_level: verified_assurance_level,
        mandatory_passed: assessment.mandatory_passed,
        mandatory_failed: assessment.mandatory_failed,
        mandatory_unknown: assessment.mandatory_unknown,
        decision: assessment.decision.status,
    };
    let payload_value =
        serde_json::to_value(&payload).map_err(AttestationIssueError::Serialization)?;
    let signature = signing_key.sign(&canonical_json_bytes(&payload_value)?);

    Ok(AttestationPackage {
        replay_manifest,
        certificate: SignedAcceptanceCertificate {
            payload,
            signature: AttestationSignature {
                algorithm: AttestationSignatureAlgorithm::Ed25519,
                encoding: AttestationSignatureEncoding::Base64url,
                value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        },
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_replay_manifest(
    manifest_id: &str,
    compiled_plan: &CompiledPlan,
    bundle: &EvidenceBundle,
    evidence_bundle_digest: &str,
    expected_decision: DecisionStatus,
    assurance_level: AssuranceLevel,
    mandatory_passed: usize,
    mandatory_failed: usize,
    mandatory_unknown: usize,
) -> Result<ReplayManifest, AttestationIssueError> {
    let trace_value =
        serde_json::to_value(&bundle.trace).map_err(AttestationIssueError::Serialization)?;
    let environment_value =
        serde_json::to_value(&bundle.environment).map_err(AttestationIssueError::Serialization)?;

    let mut artifacts: Vec<_> = bundle
        .artifacts
        .iter()
        .map(|artifact| ReplayArtifact {
            artifact_id: artifact.artifact_id.clone(),
            role: artifact.role,
            algorithm: artifact.algorithm,
            digest: artifact.digest.clone(),
            size_bytes: artifact.size_bytes,
        })
        .collect();
    artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));

    let mut authorization_receipt_digests: Vec<_> = bundle
        .trace
        .authorization_receipts
        .iter()
        .map(|record| record.receipt_digest.clone())
        .collect();
    authorization_receipt_digests.sort();

    let mut proof_evidence_ids: Vec<_> = bundle
        .proof_results
        .iter()
        .map(|result| result.evidence_id.clone())
        .collect();
    proof_evidence_ids.sort();

    Ok(ReplayManifest {
        schema_version: REPLAY_MANIFEST_SCHEMA.to_owned(),
        manifest_id: manifest_id.to_owned(),
        contract_digest: compiled_plan.contract_digest.clone(),
        capsule_digest: compiled_plan.capsule_digest.clone(),
        plan_id: compiled_plan.plan_id.clone(),
        plan_digest: compiled_plan.plan_digest.clone(),
        evidence_bundle_id: bundle.bundle_id.clone(),
        run_id: bundle.run_id.clone(),
        evidence_bundle_digest: evidence_bundle_digest.to_owned(),
        authorized_trace_digest: canonical_json_sha256(&trace_value)?,
        environment_digest: canonical_json_sha256(&environment_value)?,
        artifacts,
        authorization_receipt_digests,
        proof_evidence_ids,
        expected_decision,
        assurance_level,
        mandatory_passed,
        mandatory_failed,
        mandatory_unknown,
    })
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), AttestationIssueError> {
    if value.trim().is_empty() {
        Err(AttestationIssueError::EmptyField(field))
    } else {
        Ok(())
    }
}
