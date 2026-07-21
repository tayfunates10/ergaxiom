#![forbid(unsafe_code)]

mod issuer;
mod model;
mod verifier;

pub use issuer::{AttestationIssueError, issue_attestation};
pub use model::{
    AcceptanceCertificatePayload, AttestationPackage, AttestationSignature,
    AttestationSignatureAlgorithm, AttestationSignatureEncoding, ReplayArtifact, ReplayManifest,
    SignedAcceptanceCertificate, VerifiedAttestation,
};
pub use verifier::{
    AttestationKeyRegistry, AttestationVerifyError, verify_attestation,
    verify_attestation_against_bundle,
};
