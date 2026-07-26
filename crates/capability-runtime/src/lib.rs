#![forbid(unsafe_code)]

mod authorizer;
mod model;

pub use authorizer::{CapabilityAuthorizer, CapabilityError, TrustedKeyRegistry};
pub use model::{
    AuthorizationReceipt, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    CapabilityTokenPayload, ProductionSignerBoundCapabilityToken, SignatureAlgorithm,
    SignatureEncoding, SignedCapabilityToken, SignerBoundCapabilityToken, TokenSignature,
};
