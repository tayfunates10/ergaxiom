use ergaxiom_evidence_runtime::{ArtifactRole, DigestAlgorithm};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayManifest {
    pub schema_version: String,
    pub manifest_id: String,
    pub contract_digest: String,
    pub capsule_digest: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub evidence_bundle_id: String,
    pub run_id: String,
    pub evidence_bundle_digest: String,
    pub authorized_trace_digest: String,
    pub environment_digest: String,
    pub artifacts: Vec<ReplayArtifact>,
    pub authorization_receipt_digests: Vec<String>,
    pub proof_evidence_ids: Vec<String>,
    pub expected_decision: DecisionStatus,
    pub assurance_level: AssuranceLevel,
    pub mandatory_passed: usize,
    pub mandatory_failed: usize,
    pub mandatory_unknown: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayArtifact {
    pub artifact_id: String,
    pub role: ArtifactRole,
    pub algorithm: DigestAlgorithm,
    pub digest: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceCertificatePayload {
    pub schema_version: String,
    pub certificate_id: String,
    pub issuer_id: String,
    pub key_id: String,
    pub issued_at_epoch_s: u64,
    pub contract_digest: String,
    pub capsule_digest: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub evidence_bundle_id: String,
    pub run_id: String,
    pub evidence_bundle_digest: String,
    pub authorized_trace_digest: String,
    pub replay_manifest_digest: String,
    pub assurance_level: AssuranceLevel,
    pub mandatory_passed: usize,
    pub mandatory_failed: usize,
    pub mandatory_unknown: usize,
    pub decision: DecisionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAcceptanceCertificate {
    pub payload: AcceptanceCertificatePayload,
    pub signature: AttestationSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationSignature {
    pub algorithm: AttestationSignatureAlgorithm,
    pub encoding: AttestationSignatureEncoding,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationSignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationSignatureEncoding {
    Base64url,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationPackage {
    pub replay_manifest: ReplayManifest,
    pub certificate: SignedAcceptanceCertificate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub certificate_id: String,
    pub certificate_digest: String,
    pub replay_manifest_digest: String,
    pub evidence_bundle_digest: String,
    pub decision: DecisionStatus,
    pub assurance_level: AssuranceLevel,
}
