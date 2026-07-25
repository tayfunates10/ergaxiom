#![forbid(unsafe_code)]

mod issuer;
mod model;
mod verifier;

pub use issuer::{AttestationIssueError, build_replay_manifest, issue_attestation};
pub use model::{
    AcceptanceCertificatePayload, AttestationPackage, AttestationSignature,
    AttestationSignatureAlgorithm, AttestationSignatureEncoding, ReplayArtifact, ReplayManifest,
    SignedAcceptanceCertificate, SignerBoundAcceptanceCertificate, SignerBoundAttestationPackage,
    VerifiedAttestation,
};
pub use verifier::{
    AttestationKeyRegistry, AttestationVerifyError, verify_attestation,
    verify_attestation_against_bundle, verify_signer_bound_attestation,
    verify_signer_bound_attestation_against_bundle,
};
