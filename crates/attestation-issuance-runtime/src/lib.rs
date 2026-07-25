#![forbid(unsafe_code)]

use ergaxiom_attestation_runtime::{
    AcceptanceCertificatePayload, AttestationIssueError, SignerBoundAcceptanceCertificate,
    SignerBoundAttestationPackage, build_replay_manifest,
};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_evidence_runtime::{EvidenceBundle, EvidenceBundleError, assess_bundle};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{
    AssuranceLevel, DecisionStatus, HashingError, canonical_json_sha256,
};
use ergaxiom_windows_signer_client_runtime::{SignerClientError, SignerProcessClient};
use ergaxiom_windows_signer_protocol_runtime::{
    SignerProtocolError, SignerRequest, SignerResponse, SignerSuccess, decode_hex_32,
    validate_identifier, validate_sha256,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const ACCEPTANCE_CERTIFICATE_SCHEMA: &str = "0.1.0";
pub const ATTESTATION_ISSUER_ID: &str = "ergaxiom.attestation-authority";
pub const ATTESTATION_KEY_ID: &str = "attestation-key-v1";
const REQUEST_ID_PREFIX: &str = "attestation.issue.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationCertificateDraft {
    pub manifest_id: String,
    pub certificate_id: String,
    pub issued_at_epoch_s: u64,
}

pub trait AttestationSignerTransport {
    fn invoke(&self, request: &SignerRequest) -> Result<SignerResponse, AttestationIssuanceError>;
}

impl AttestationSignerTransport for SignerProcessClient {
    fn invoke(&self, request: &SignerRequest) -> Result<SignerResponse, AttestationIssuanceError> {
        SignerProcessClient::invoke(self, request).map_err(AttestationIssuanceError::SignerClient)
    }
}

#[derive(Debug, Clone)]
pub struct AttestationIssuanceAuthority<T> {
    transport: T,
    expected_public_key: [u8; 32],
}

impl<T> AttestationIssuanceAuthority<T>
where
    T: AttestationSignerTransport,
{
    #[must_use]
    pub const fn new(transport: T, expected_public_key: [u8; 32]) -> Self {
        Self {
            transport,
            expected_public_key,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        compiled_contract: CompiledContract,
        compiled_plan: &CompiledPlan,
        bundle_value: &Value,
        verified_assurance_level: AssuranceLevel,
        draft: AttestationCertificateDraft,
    ) -> Result<SignerBoundAttestationPackage, AttestationIssuanceError> {
        validate_draft(&draft)?;
        let assessment = assess_bundle(
            compiled_contract,
            compiled_plan,
            bundle_value,
            verified_assurance_level,
        )?;
        if assessment.decision.status != DecisionStatus::Accepted {
            return Err(AttestationIssuanceError::DecisionNotAccepted(
                assessment.decision.status,
            ));
        }
        if assessment.mandatory_failed > 0 || assessment.mandatory_unknown > 0 {
            return Err(AttestationIssuanceError::InvalidAcceptedCounts);
        }

        let bundle: EvidenceBundle = serde_json::from_value(bundle_value.clone())
            .map_err(AttestationIssuanceError::BundleDecode)?;
        let replay_manifest = build_replay_manifest(
            &draft.manifest_id,
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
            .map_err(AttestationIssuanceError::Serialization)?;
        let replay_manifest_digest = canonical_json_sha256(&manifest_value)?;
        let payload = AcceptanceCertificatePayload {
            schema_version: ACCEPTANCE_CERTIFICATE_SCHEMA.to_owned(),
            certificate_id: draft.certificate_id,
            issuer_id: ATTESTATION_ISSUER_ID.to_owned(),
            key_id: ATTESTATION_KEY_ID.to_owned(),
            issued_at_epoch_s: draft.issued_at_epoch_s,
            contract_digest: compiled_plan.contract_digest.clone(),
            capsule_digest: compiled_plan.capsule_digest.clone(),
            plan_id: compiled_plan.plan_id.clone(),
            plan_digest: compiled_plan.plan_digest.clone(),
            evidence_bundle_id: assessment.bundle_id,
            run_id: assessment.run_id,
            evidence_bundle_digest: assessment.bundle_digest,
            authorized_trace_digest: replay_manifest.authorized_trace_digest.clone(),
            replay_manifest_digest,
            assurance_level: verified_assurance_level,
            mandatory_passed: assessment.mandatory_passed,
            mandatory_failed: assessment.mandatory_failed,
            mandatory_unknown: assessment.mandatory_unknown,
            decision: assessment.decision.status,
        };
        let payload_value =
            serde_json::to_value(&payload).map_err(AttestationIssuanceError::Serialization)?;
        let payload_digest = canonical_json_sha256(&payload_value)?;
        let request_id = request_id_for_payload(&payload_digest)?;
        let request = SignerRequest::sign_digest(
            request_id.clone(),
            IssuerRole::Attestation,
            ATTESTATION_ISSUER_ID,
            ATTESTATION_KEY_ID,
            payload_digest.clone(),
        );
        let signer_response = self.transport.invoke(&request)?;
        let envelope = signer_response.verify_digest_signature()?;
        if envelope.request_id != request_id {
            return Err(AttestationIssuanceError::SignerRequestIdMismatch);
        }
        if envelope.role != IssuerRole::Attestation {
            return Err(AttestationIssuanceError::SignerRoleMismatch);
        }
        if envelope.issuer_id != ATTESTATION_ISSUER_ID {
            return Err(AttestationIssuanceError::SignerIssuerMismatch);
        }
        if envelope.key_id != ATTESTATION_KEY_ID {
            return Err(AttestationIssuanceError::SignerKeyMismatch);
        }
        if envelope.digest != payload_digest {
            return Err(AttestationIssuanceError::SignerDigestMismatch);
        }
        if response_public_key(&signer_response)? != self.expected_public_key {
            return Err(AttestationIssuanceError::SignerPublicKeyMismatch);
        }

        Ok(SignerBoundAttestationPackage {
            replay_manifest,
            certificate: SignerBoundAcceptanceCertificate {
                payload,
                signer_response,
            },
        })
    }
}

pub fn request_id_for_payload(payload_digest: &str) -> Result<String, AttestationIssuanceError> {
    validate_sha256(payload_digest)?;
    Ok(format!("{REQUEST_ID_PREFIX}{}", &payload_digest[..48]))
}

fn validate_draft(draft: &AttestationCertificateDraft) -> Result<(), AttestationIssuanceError> {
    validate_identifier("manifest_id", &draft.manifest_id)?;
    validate_identifier("certificate_id", &draft.certificate_id)?;
    if draft.issued_at_epoch_s == 0 {
        return Err(AttestationIssuanceError::InvalidIssuedAt);
    }
    Ok(())
}

fn response_public_key(response: &SignerResponse) -> Result<[u8; 32], AttestationIssuanceError> {
    match response {
        SignerResponse::Success {
            result: SignerSuccess::DigestSigned { public_key_hex, .. },
            ..
        } => Ok(decode_hex_32(public_key_hex)?),
        SignerResponse::Error { .. }
        | SignerResponse::Success {
            result: SignerSuccess::KeyInitialized { .. } | SignerSuccess::PublicKey { .. },
            ..
        } => Err(AttestationIssuanceError::SignerProtocol(
            SignerProtocolError::ResponseDoesNotContainSignature,
        )),
    }
}

#[derive(Debug, Error)]
pub enum AttestationIssuanceError {
    #[error("signer process rejected attestation issuance: {0}")]
    SignerClient(#[source] SignerClientError),
    #[error(transparent)]
    Evidence(#[from] EvidenceBundleError),
    #[error("failed to decode independently accepted Evidence Bundle: {0}")]
    BundleDecode(#[source] serde_json::Error),
    #[error("failed to serialize attestation material: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    ManifestBuild(#[from] AttestationIssueError),
    #[error(transparent)]
    SignerProtocol(#[from] SignerProtocolError),
    #[error("acceptance certificate cannot be issued for decision {0:?}")]
    DecisionNotAccepted(DecisionStatus),
    #[error("accepted assessment contains failed or unknown mandatory obligations")]
    InvalidAcceptedCounts,
    #[error("attestation draft issued_at_epoch_s must be greater than zero")]
    InvalidIssuedAt,
    #[error("signer response request ID does not match the internally derived request ID")]
    SignerRequestIdMismatch,
    #[error("signer response was not issued under the Attestation role")]
    SignerRoleMismatch,
    #[error("signer response issuer does not match the fixed attestation issuer")]
    SignerIssuerMismatch,
    #[error("signer response key ID does not match the fixed attestation key")]
    SignerKeyMismatch,
    #[error("signer response digest does not match the canonical certificate payload digest")]
    SignerDigestMismatch,
    #[error("signer response public key does not match the provisioned attestation key")]
    SignerPublicKeyMismatch,
}
