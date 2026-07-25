#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signature;
use ergaxiom_attestation_runtime::{
    AttestationKeyRegistry, AttestationPackage, AttestationVerifyError, VerifiedAttestation,
    verify_attestation, verify_attestation_against_bundle,
};
use ergaxiom_capability_runtime::{
    AuthorizationReceipt, CapabilityAuthorizer, CapabilityError, SignatureAlgorithm,
    SignatureEncoding, SignedCapabilityToken, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_key_governance_runtime::{
    GovernedKeyRegistry, IssuerRole, KeyGovernanceError, KeyMutationReceipt,
};
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::{AssuranceLevel, HashingError, canonical_json_bytes};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GovernedVerificationError {
    #[error(transparent)]
    KeyGovernance(#[from] KeyGovernanceError),
    #[error(transparent)]
    Capability(#[from] CapabilityError),
    #[error(transparent)]
    Attestation(#[from] AttestationVerifyError),
    #[error("failed to decode governed capability token: {0}")]
    CapabilityTokenDecode(#[source] serde_json::Error),
    #[error("governed capability signature metadata is unsupported")]
    UnsupportedCapabilitySignatureMetadata,
    #[error("governed capability signature is not valid base64url")]
    InvalidCapabilitySignatureEncoding,
    #[error("governed capability signature has an invalid Ed25519 length")]
    InvalidCapabilitySignatureLength,
    #[error("governed capability signature verification failed")]
    CapabilitySignatureVerificationFailed,
    #[error("governed capability authorizer is missing for {issuer_id}/{key_id}")]
    MissingCapabilityAuthorizer { issuer_id: String, key_id: String },
    #[error("governed attestation verifier is missing for {issuer_id}/{key_id}")]
    MissingAttestationKey { issuer_id: String, key_id: String },
    #[error("capability and attestation roles require their dedicated insertion methods")]
    DedicatedRoleInsertionRequired,
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

#[derive(Debug, Default)]
pub struct GovernedVerificationRuntime {
    registry: GovernedKeyRegistry,
    capability_authorizers: BTreeMap<(String, String), CapabilityAuthorizer>,
    attestation_public_keys: BTreeMap<(String, String), [u8; 32]>,
}

impl GovernedVerificationRuntime {
    #[must_use]
    pub const fn registry_revision(&self) -> u64 {
        self.registry.revision()
    }

    pub fn registry_digest(&self) -> Result<String, GovernedVerificationError> {
        Ok(self.registry.registry_digest()?)
    }

    pub fn insert_capability_key(
        &mut self,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
        not_before_epoch_s: u64,
        not_after_epoch_s: u64,
    ) -> Result<KeyMutationReceipt, GovernedVerificationError> {
        let issuer_id = issuer_id.into();
        let key_id = key_id.into();
        let receipt = self.registry.insert_ed25519(
            IssuerRole::Capability,
            issuer_id.clone(),
            key_id.clone(),
            public_key,
            not_before_epoch_s,
            not_after_epoch_s,
        )?;
        self.capability_authorizers.insert(
            (issuer_id.clone(), key_id.clone()),
            capability_authorizer(&issuer_id, &key_id, public_key)?,
        );
        Ok(receipt)
    }

    pub fn insert_attestation_key(
        &mut self,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
        not_before_epoch_s: u64,
        not_after_epoch_s: u64,
    ) -> Result<KeyMutationReceipt, GovernedVerificationError> {
        let issuer_id = issuer_id.into();
        let key_id = key_id.into();
        let receipt = self.registry.insert_ed25519(
            IssuerRole::Attestation,
            issuer_id.clone(),
            key_id.clone(),
            public_key,
            not_before_epoch_s,
            not_after_epoch_s,
        )?;
        self.attestation_public_keys
            .insert((issuer_id, key_id), public_key);
        Ok(receipt)
    }

    pub fn insert_auxiliary_key(
        &mut self,
        role: IssuerRole,
        issuer_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
        not_before_epoch_s: u64,
        not_after_epoch_s: u64,
    ) -> Result<KeyMutationReceipt, GovernedVerificationError> {
        if matches!(role, IssuerRole::Capability | IssuerRole::Attestation) {
            return Err(GovernedVerificationError::DedicatedRoleInsertionRequired);
        }
        Ok(self.registry.insert_ed25519(
            role,
            issuer_id,
            key_id,
            public_key,
            not_before_epoch_s,
            not_after_epoch_s,
        )?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rotate_capability_key_guarded(
        &mut self,
        expected_revision: u64,
        expected_registry_digest: &str,
        issuer_id: &str,
        current_key_id: &str,
        new_key_id: &str,
        new_public_key: [u8; 32],
        activation_at_epoch_s: u64,
        current_retirement_at_epoch_s: u64,
        new_not_after_epoch_s: u64,
    ) -> Result<KeyMutationReceipt, GovernedVerificationError> {
        let receipt = self.registry.rotate_ed25519_guarded(
            expected_revision,
            expected_registry_digest,
            IssuerRole::Capability,
            issuer_id,
            current_key_id,
            new_key_id,
            new_public_key,
            activation_at_epoch_s,
            current_retirement_at_epoch_s,
            new_not_after_epoch_s,
        )?;
        self.capability_authorizers.insert(
            (issuer_id.to_owned(), new_key_id.to_owned()),
            capability_authorizer(issuer_id, new_key_id, new_public_key)?,
        );
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rotate_attestation_key_guarded(
        &mut self,
        expected_revision: u64,
        expected_registry_digest: &str,
        issuer_id: &str,
        current_key_id: &str,
        new_key_id: &str,
        new_public_key: [u8; 32],
        activation_at_epoch_s: u64,
        current_retirement_at_epoch_s: u64,
        new_not_after_epoch_s: u64,
    ) -> Result<KeyMutationReceipt, GovernedVerificationError> {
        let receipt = self.registry.rotate_ed25519_guarded(
            expected_revision,
            expected_registry_digest,
            IssuerRole::Attestation,
            issuer_id,
            current_key_id,
            new_key_id,
            new_public_key,
            activation_at_epoch_s,
            current_retirement_at_epoch_s,
            new_not_after_epoch_s,
        )?;
        self.attestation_public_keys.insert(
            (issuer_id.to_owned(), new_key_id.to_owned()),
            new_public_key,
        );
        Ok(receipt)
    }

    pub fn revoke_key_guarded(
        &mut self,
        expected_revision: u64,
        expected_registry_digest: &str,
        role: IssuerRole,
        issuer_id: &str,
        key_id: &str,
        revoked_at_epoch_s: u64,
        revocation_reason_digest: &str,
    ) -> Result<KeyMutationReceipt, GovernedVerificationError> {
        Ok(self.registry.revoke_ed25519_guarded(
            expected_revision,
            expected_registry_digest,
            role,
            issuer_id,
            key_id,
            revoked_at_epoch_s,
            revocation_reason_digest,
        )?)
    }

    pub fn verify_capability_token_signature(
        &self,
        token_value: &Value,
    ) -> Result<SignedCapabilityToken, GovernedVerificationError> {
        let token: SignedCapabilityToken = serde_json::from_value(token_value.clone())
            .map_err(GovernedVerificationError::CapabilityTokenDecode)?;
        if token.signature.algorithm != SignatureAlgorithm::Ed25519
            || token.signature.encoding != SignatureEncoding::Base64url
        {
            return Err(GovernedVerificationError::UnsupportedCapabilitySignatureMetadata);
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&token.signature.value)
            .map_err(|_| GovernedVerificationError::InvalidCapabilitySignatureEncoding)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| GovernedVerificationError::InvalidCapabilitySignatureLength)?;
        let payload_value = serde_json::to_value(&token.payload)
            .map_err(GovernedVerificationError::CapabilityTokenDecode)?;
        let key = self.registry.resolve_ed25519(
            IssuerRole::Capability,
            &token.payload.issuer_id,
            &token.payload.key_id,
            token.payload.issued_at_epoch_s,
        )?;
        key.verify_strict(&canonical_json_bytes(&payload_value)?, &signature)
            .map_err(|_| GovernedVerificationError::CapabilitySignatureVerificationFailed)?;
        Ok(token)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_capability(
        &mut self,
        token_value: &Value,
        compiled_contract: &CompiledContract,
        compiled_plan: &CompiledPlan,
        trusted_now_epoch_s: u64,
        expected_executor_id: &str,
        expected_device_id: Option<&str>,
    ) -> Result<AuthorizationReceipt, GovernedVerificationError> {
        let token = self.verify_capability_token_signature(token_value)?;
        let identity = (
            token.payload.issuer_id.clone(),
            token.payload.key_id.clone(),
        );
        let authorizer = self
            .capability_authorizers
            .get_mut(&identity)
            .ok_or_else(|| GovernedVerificationError::MissingCapabilityAuthorizer {
                issuer_id: identity.0.clone(),
                key_id: identity.1.clone(),
            })?;
        Ok(authorizer.authorize(
            token_value,
            compiled_contract,
            compiled_plan,
            trusted_now_epoch_s,
            expected_executor_id,
            expected_device_id,
        )?)
    }

    pub fn verify_attestation_package(
        &self,
        package: &AttestationPackage,
    ) -> Result<VerifiedAttestation, GovernedVerificationError> {
        let registry = self.legacy_attestation_registry(package)?;
        Ok(verify_attestation(package, &registry)?)
    }

    pub fn verify_attestation_package_against_bundle(
        &self,
        package: &AttestationPackage,
        compiled_contract: CompiledContract,
        compiled_plan: &CompiledPlan,
        bundle_value: &Value,
        verified_assurance_level: AssuranceLevel,
    ) -> Result<VerifiedAttestation, GovernedVerificationError> {
        let registry = self.legacy_attestation_registry(package)?;
        Ok(verify_attestation_against_bundle(
            package,
            &registry,
            compiled_contract,
            compiled_plan,
            bundle_value,
            verified_assurance_level,
        )?)
    }

    fn legacy_attestation_registry(
        &self,
        package: &AttestationPackage,
    ) -> Result<AttestationKeyRegistry, GovernedVerificationError> {
        let payload = &package.certificate.payload;
        self.registry.resolve_ed25519(
            IssuerRole::Attestation,
            &payload.issuer_id,
            &payload.key_id,
            payload.issued_at_epoch_s,
        )?;
        let identity = (payload.issuer_id.clone(), payload.key_id.clone());
        let public_key = self.attestation_public_keys.get(&identity).ok_or_else(|| {
            GovernedVerificationError::MissingAttestationKey {
                issuer_id: identity.0.clone(),
                key_id: identity.1.clone(),
            }
        })?;
        let mut registry = AttestationKeyRegistry::default();
        registry.insert_ed25519(&identity.0, &identity.1, *public_key)?;
        Ok(registry)
    }
}

fn capability_authorizer(
    issuer_id: &str,
    key_id: &str,
    public_key: [u8; 32],
) -> Result<CapabilityAuthorizer, CapabilityError> {
    let mut registry = TrustedKeyRegistry::default();
    registry.insert_ed25519(issuer_id, key_id, public_key)?;
    Ok(CapabilityAuthorizer::new(registry))
}
