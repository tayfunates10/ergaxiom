use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use ergaxiom_windows_production_key_governance_runtime::{
    PRODUCTION_KEY_TRUST_BINDING_SCHEMA, ProductionKeyGovernanceError, ProductionKeyRecord,
    ProductionKeyRegistry, ProductionKeyTrustBinding,
};
use ergaxiom_windows_production_signer_protocol_runtime::{
    ProductionSignerProtocolError, ProductionSignerResponse,
};
use ergaxiom_windows_production_signer_runtime::{
    AuthenticatedCallerIdentity, ProductionKeyIdentity, ProductionKeyPolicy, ProductionSignerError,
    SignerServiceIdentity, validate_identifier, validate_sha256,
};
use ergaxiom_windows_production_signer_service_runtime::{
    GovernedProductionSignerTrustSnapshot, ProductionSignerServiceError,
    ProductionSignerTrustSnapshot,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    DeployedAuthorizedProductionSignerPackage, DeployedProductionSignerError,
    ProductionSignerDeploymentPolicy, ProductionTrustStateBinding, ProductionTrustStateError,
    TrustBoundSignerServiceIdentity, VerifiedProductionTrustState,
};

pub const PRODUCTION_SIGNER_IDENTITY_CHALLENGE_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_SIGNER_IDENTITY_PROOF_PAYLOAD_SCHEMA: &str = "0.1.0";
pub const DEPLOYED_PRODUCTION_SIGNER_IDENTITY_PROOF_SCHEMA: &str = "0.1.0";
pub const PRODUCTION_SIGNER_IDENTITY_PROOF_PURPOSE: &str =
    "ergaxiom.production-signer.service-identity-proof.v1";
pub const MAX_PRODUCTION_SIGNER_IDENTITY_CHALLENGE_LIFETIME_S: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSignerIdentityChallenge {
    pub schema_version: String,
    pub purpose: String,
    pub request_id: String,
    pub client_nonce: String,
    pub deployment_id: String,
    pub service_id: String,
    pub signer_service_executable_digest: String,
    pub deployment_policy_revision: u64,
    pub deployment_policy_digest: String,
    pub trust_state_revision: u64,
    pub trust_state_binding_digest: String,
    pub registry_revision: u64,
    pub registry_digest: String,
    pub attestation_generation: u64,
    pub attestation_public_key_digest: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub challenge_digest: String,
}

impl ProductionSignerIdentityChallenge {
    pub fn build(
        request_id: impl Into<String>,
        client_nonce: impl Into<String>,
        accepted: &VerifiedProductionTrustState,
        deployment_policy: &ProductionSignerDeploymentPolicy,
        issued_at_epoch_s: u64,
        expires_at_epoch_s: u64,
    ) -> Result<Self, ProductionSignerIdentityProofError> {
        deployment_policy.validate_seal()?;
        accepted.binding().validate_seal()?;
        let attestation_key = active_attestation_binding(accepted, issued_at_epoch_s)?;
        let binding = accepted.binding();
        let mut challenge = Self {
            schema_version: PRODUCTION_SIGNER_IDENTITY_CHALLENGE_SCHEMA.to_owned(),
            purpose: PRODUCTION_SIGNER_IDENTITY_PROOF_PURPOSE.to_owned(),
            request_id: request_id.into(),
            client_nonce: client_nonce.into(),
            deployment_id: binding.deployment_id.clone(),
            service_id: deployment_policy.service_id.clone(),
            signer_service_executable_digest: binding.signer_service_executable_digest.clone(),
            deployment_policy_revision: deployment_policy.revision,
            deployment_policy_digest: deployment_policy.policy_digest.clone(),
            trust_state_revision: binding.revision,
            trust_state_binding_digest: binding.binding_digest.clone(),
            registry_revision: binding.registry_revision,
            registry_digest: binding.registry_digest.clone(),
            attestation_generation: attestation_key.generation,
            attestation_public_key_digest: attestation_key.public_key_digest,
            issued_at_epoch_s,
            expires_at_epoch_s,
            challenge_digest: String::new(),
        };
        challenge.challenge_digest = challenge.expected_digest()?;
        challenge.validate_against(accepted, deployment_policy, issued_at_epoch_s)?;
        Ok(challenge)
    }

    pub fn validate_against(
        &self,
        accepted: &VerifiedProductionTrustState,
        deployment_policy: &ProductionSignerDeploymentPolicy,
        trusted_now_epoch_s: u64,
    ) -> Result<ProductionKeyTrustBinding, ProductionSignerIdentityProofError> {
        if self.schema_version != PRODUCTION_SIGNER_IDENTITY_CHALLENGE_SCHEMA {
            return Err(ProductionSignerIdentityProofError::UnsupportedChallengeSchema);
        }
        if self.purpose != PRODUCTION_SIGNER_IDENTITY_PROOF_PURPOSE {
            return Err(ProductionSignerIdentityProofError::PurposeSubstitution);
        }
        validate_identifier("identity_proof_request_id", &self.request_id)?;
        validate_sha256(&self.client_nonce)?;
        validate_identifier("deployment_id", &self.deployment_id)?;
        validate_identifier("service_id", &self.service_id)?;
        validate_sha256(&self.signer_service_executable_digest)?;
        validate_sha256(&self.deployment_policy_digest)?;
        validate_sha256(&self.trust_state_binding_digest)?;
        validate_sha256(&self.registry_digest)?;
        validate_sha256(&self.attestation_public_key_digest)?;
        validate_sha256(&self.challenge_digest)?;
        if self.deployment_policy_revision == 0
            || self.trust_state_revision == 0
            || self.registry_revision == 0
            || self.attestation_generation == 0
            || self.issued_at_epoch_s == 0
            || self.expires_at_epoch_s <= self.issued_at_epoch_s
            || self
                .expires_at_epoch_s
                .saturating_sub(self.issued_at_epoch_s)
                > MAX_PRODUCTION_SIGNER_IDENTITY_CHALLENGE_LIFETIME_S
        {
            return Err(ProductionSignerIdentityProofError::InvalidChallengeWindow);
        }
        if trusted_now_epoch_s < self.issued_at_epoch_s
            || trusted_now_epoch_s >= self.expires_at_epoch_s
        {
            return Err(ProductionSignerIdentityProofError::ChallengeOutsideValidityWindow);
        }
        deployment_policy.validate_seal()?;
        accepted.binding().validate_seal()?;
        let body = accepted.body();
        let binding = accepted.binding();
        if self.issued_at_epoch_s < body.not_before_epoch_s
            || self.expires_at_epoch_s > body.not_after_epoch_s
            || self.deployment_id != deployment_policy.deployment_id
            || self.deployment_id != binding.deployment_id
            || self.service_id != deployment_policy.service_id
            || self.signer_service_executable_digest != binding.signer_service_executable_digest
            || self.deployment_policy_revision != deployment_policy.revision
            || self.deployment_policy_digest != deployment_policy.policy_digest
            || self.trust_state_revision != binding.revision
            || self.trust_state_binding_digest != binding.binding_digest
            || self.registry_revision != binding.registry_revision
            || self.registry_digest != binding.registry_digest
        {
            return Err(ProductionSignerIdentityProofError::ChallengeBindingMismatch);
        }
        let attestation_key = active_attestation_binding(accepted, trusted_now_epoch_s)?;
        if self.attestation_generation != attestation_key.generation
            || self.attestation_public_key_digest != attestation_key.public_key_digest
        {
            return Err(ProductionSignerIdentityProofError::AttestationKeyMismatch);
        }
        if self.challenge_digest != self.expected_digest()? {
            return Err(ProductionSignerIdentityProofError::ChallengeDigestMismatch);
        }
        Ok(attestation_key)
    }

    fn expected_digest(&self) -> Result<String, ProductionSignerIdentityProofError> {
        digest_with_blank_field(self, "challenge_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSignerIdentityProofPayload {
    pub schema_version: String,
    pub purpose: String,
    pub request_id: String,
    pub client_nonce: String,
    pub challenge_digest: String,
    pub caller_identity_digest: String,
    pub base_service_identity: SignerServiceIdentity,
    pub signer_service_identity: TrustBoundSignerServiceIdentity,
    pub trust_state: ProductionTrustStateBinding,
    pub deployment_policy_revision: u64,
    pub deployment_policy_digest: String,
    pub attestation_key: ProductionKeyTrustBinding,
    pub proved_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub payload_digest: String,
}

impl ProductionSignerIdentityProofPayload {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build(
        challenge: &ProductionSignerIdentityChallenge,
        caller: &AuthenticatedCallerIdentity,
        base_service_identity: &SignerServiceIdentity,
        signer_service_identity: &TrustBoundSignerServiceIdentity,
        accepted: &VerifiedProductionTrustState,
        deployment_policy: &ProductionSignerDeploymentPolicy,
        proved_at_epoch_s: u64,
    ) -> Result<Self, ProductionSignerIdentityProofError> {
        let attestation_key =
            challenge.validate_against(accepted, deployment_policy, proved_at_epoch_s)?;
        caller.validate()?;
        base_service_identity.validate()?;
        signer_service_identity.validate_seal()?;
        let expected_bound_identity = TrustBoundSignerServiceIdentity::build(
            base_service_identity,
            accepted.binding(),
            deployment_policy,
        )?;
        if signer_service_identity != &expected_bound_identity
            || base_service_identity.service_id != challenge.service_id
            || base_service_identity.executable_sha256 != challenge.signer_service_executable_digest
        {
            return Err(ProductionSignerIdentityProofError::ServiceIdentityMismatch);
        }
        let mut payload = Self {
            schema_version: PRODUCTION_SIGNER_IDENTITY_PROOF_PAYLOAD_SCHEMA.to_owned(),
            purpose: PRODUCTION_SIGNER_IDENTITY_PROOF_PURPOSE.to_owned(),
            request_id: challenge.request_id.clone(),
            client_nonce: challenge.client_nonce.clone(),
            challenge_digest: challenge.challenge_digest.clone(),
            caller_identity_digest: caller.digest()?,
            base_service_identity: base_service_identity.clone(),
            signer_service_identity: signer_service_identity.clone(),
            trust_state: accepted.binding().clone(),
            deployment_policy_revision: deployment_policy.revision,
            deployment_policy_digest: deployment_policy.policy_digest.clone(),
            attestation_key,
            proved_at_epoch_s,
            expires_at_epoch_s: challenge.expires_at_epoch_s,
            payload_digest: String::new(),
        };
        payload.payload_digest = payload.expected_digest()?;
        payload.validate_shape()?;
        Ok(payload)
    }

    pub fn validate_shape(&self) -> Result<(), ProductionSignerIdentityProofError> {
        if self.schema_version != PRODUCTION_SIGNER_IDENTITY_PROOF_PAYLOAD_SCHEMA {
            return Err(ProductionSignerIdentityProofError::UnsupportedProofPayloadSchema);
        }
        if self.purpose != PRODUCTION_SIGNER_IDENTITY_PROOF_PURPOSE {
            return Err(ProductionSignerIdentityProofError::PurposeSubstitution);
        }
        validate_identifier("identity_proof_request_id", &self.request_id)?;
        validate_sha256(&self.client_nonce)?;
        validate_sha256(&self.challenge_digest)?;
        validate_sha256(&self.caller_identity_digest)?;
        self.base_service_identity.validate()?;
        self.signer_service_identity.validate_seal()?;
        self.trust_state.validate_seal()?;
        validate_sha256(&self.deployment_policy_digest)?;
        self.attestation_key.validate_shape()?;
        validate_sha256(&self.payload_digest)?;
        if self.deployment_policy_revision == 0
            || self.proved_at_epoch_s == 0
            || self.expires_at_epoch_s <= self.proved_at_epoch_s
            || self.attestation_key.identity != ProductionKeyIdentity::attestation()
            || self.attestation_key.registry_revision != self.trust_state.registry_revision
            || self.attestation_key.registry_digest != self.trust_state.registry_digest
            || self.base_service_identity.digest()?
                != self.signer_service_identity.base_service_identity_digest
            || self.trust_state.binding_digest
                != self.signer_service_identity.trust_state_binding_digest
            || self.deployment_policy_digest
                != self.signer_service_identity.deployment_policy_digest
            || self.deployment_policy_revision != self.trust_state.service_policy_revision
            || self.deployment_policy_digest != self.trust_state.service_policy_digest
        {
            return Err(ProductionSignerIdentityProofError::ProofPayloadBindingMismatch);
        }
        if self.payload_digest != self.expected_digest()? {
            return Err(ProductionSignerIdentityProofError::ProofPayloadDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, ProductionSignerIdentityProofError> {
        digest_with_blank_field(self, "payload_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployedProductionSignerIdentityProof {
    pub schema_version: String,
    pub payload: ProductionSignerIdentityProofPayload,
    pub signed_package: DeployedAuthorizedProductionSignerPackage,
    pub proof_digest: String,
}

impl DeployedProductionSignerIdentityProof {
    pub(crate) fn build(
        payload: ProductionSignerIdentityProofPayload,
        signed_package: DeployedAuthorizedProductionSignerPackage,
    ) -> Result<Self, ProductionSignerIdentityProofError> {
        let mut proof = Self {
            schema_version: DEPLOYED_PRODUCTION_SIGNER_IDENTITY_PROOF_SCHEMA.to_owned(),
            payload,
            signed_package,
            proof_digest: String::new(),
        };
        proof.proof_digest = proof.expected_digest()?;
        proof.validate_seal()?;
        Ok(proof)
    }

    pub fn validate_seal(&self) -> Result<(), ProductionSignerIdentityProofError> {
        if self.schema_version != DEPLOYED_PRODUCTION_SIGNER_IDENTITY_PROOF_SCHEMA {
            return Err(ProductionSignerIdentityProofError::UnsupportedProofSchema);
        }
        self.payload.validate_shape()?;
        self.signed_package.validate_seal()?;
        let ProductionSignerResponse::Success { request_id, result } =
            &self.signed_package.signer_package.signer_response
        else {
            return Err(ProductionSignerIdentityProofError::SignedProofMissing);
        };
        if request_id != &self.payload.request_id
            || result.envelope.request.identity != ProductionKeyIdentity::attestation()
            || result.envelope.request.digest != self.payload.payload_digest
            || self.signed_package.trust_state != self.payload.trust_state
            || self.signed_package.signer_service_identity != self.payload.signer_service_identity
            || self.signed_package.key_generation != self.payload.attestation_key.generation
            || self
                .signed_package
                .signer_package
                .caller_authorization
                .caller_identity_digest
                != self.payload.caller_identity_digest
            || self
                .signed_package
                .signer_package
                .caller_authorization
                .signer_service_identity_digest
                != self.payload.base_service_identity.digest()?
            || self
                .signed_package
                .signer_package
                .caller_authorization
                .authorized_at_epoch_s
                != self.payload.proved_at_epoch_s
        {
            return Err(ProductionSignerIdentityProofError::SignedProofBindingMismatch);
        }
        validate_sha256(&self.proof_digest)?;
        if self.proof_digest != self.expected_digest()? {
            return Err(ProductionSignerIdentityProofError::ProofDigestMismatch);
        }
        Ok(())
    }

    pub fn verify(
        &self,
        challenge: &ProductionSignerIdentityChallenge,
        accepted: &VerifiedProductionTrustState,
        deployment_policy: &ProductionSignerDeploymentPolicy,
        trusted_now_epoch_s: u64,
    ) -> Result<SignerServiceIdentity, ProductionSignerIdentityProofError> {
        let attestation_key =
            challenge.validate_against(accepted, deployment_policy, trusted_now_epoch_s)?;
        self.validate_seal()?;
        if self.payload.request_id != challenge.request_id
            || self.payload.client_nonce != challenge.client_nonce
            || self.payload.challenge_digest != challenge.challenge_digest
            || self.payload.trust_state != *accepted.binding()
            || self.payload.deployment_policy_revision != deployment_policy.revision
            || self.payload.deployment_policy_digest != deployment_policy.policy_digest
            || self.payload.attestation_key != attestation_key
            || self.payload.proved_at_epoch_s < challenge.issued_at_epoch_s
            || self.payload.proved_at_epoch_s >= challenge.expires_at_epoch_s
            || trusted_now_epoch_s >= self.payload.expires_at_epoch_s
        {
            return Err(ProductionSignerIdentityProofError::ProofChallengeMismatch);
        }
        let expected_bound_identity = TrustBoundSignerServiceIdentity::build(
            &self.payload.base_service_identity,
            accepted.binding(),
            deployment_policy,
        )?;
        if self.payload.signer_service_identity != expected_bound_identity {
            return Err(ProductionSignerIdentityProofError::ServiceIdentityMismatch);
        }
        let signer_trust = ProductionSignerTrustSnapshot {
            identity: ProductionKeyIdentity::attestation(),
            public_key_digest: attestation_key.public_key_digest.clone(),
            allowlist_revision: accepted.binding().caller_allowlist_revision,
            allowlist_digest: accepted.binding().caller_allowlist_digest.clone(),
            caller_identity_digest: self.payload.caller_identity_digest.clone(),
            signer_service_identity_digest: self.payload.base_service_identity.digest()?,
        };
        let governed_trust = GovernedProductionSignerTrustSnapshot {
            signer: signer_trust,
            key: attestation_key,
        };
        let envelope = self.signed_package.verify_deployed(
            accepted,
            deployment_policy,
            &self.payload.base_service_identity,
            &governed_trust,
            self.payload.proved_at_epoch_s,
        )?;
        let policy = ProductionKeyPolicy::attestation();
        envelope.validate_for(&policy)?;
        if envelope.request.digest != self.payload.payload_digest {
            return Err(ProductionSignerIdentityProofError::SignedProofBindingMismatch);
        }
        Ok(self.payload.base_service_identity.clone())
    }

    fn expected_digest(&self) -> Result<String, ProductionSignerIdentityProofError> {
        digest_with_blank_field(self, "proof_digest")
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedProductionSignerTrustLease {
    proof_digest: String,
    caller_identity_digest: String,
    service_identity: SignerServiceIdentity,
    trust_state: ProductionTrustStateBinding,
    deployment_policy_revision: u64,
    deployment_policy_digest: String,
    proved_at_epoch_s: u64,
    expires_at_epoch_s: u64,
    capability_trust: GovernedProductionSignerTrustSnapshot,
    attestation_trust: GovernedProductionSignerTrustSnapshot,
    registry: ProductionKeyRegistry,
}

impl VerifiedProductionSignerTrustLease {
    pub fn validate_at(
        &self,
        accepted: &VerifiedProductionTrustState,
        deployment_policy: &ProductionSignerDeploymentPolicy,
        trusted_now_epoch_s: u64,
    ) -> Result<(), ProductionSignerIdentityProofError> {
        validate_sha256(&self.proof_digest)?;
        validate_sha256(&self.caller_identity_digest)?;
        self.service_identity.validate()?;
        self.trust_state.validate_seal()?;
        deployment_policy.validate_seal()?;
        accepted.binding().validate_seal()?;
        if trusted_now_epoch_s < self.proved_at_epoch_s
            || trusted_now_epoch_s >= self.expires_at_epoch_s
        {
            return Err(ProductionSignerIdentityProofError::TrustLeaseOutsideValidityWindow);
        }
        if self.trust_state != *accepted.binding()
            || self.deployment_policy_revision != deployment_policy.revision
            || self.deployment_policy_digest != deployment_policy.policy_digest
            || self.service_identity.service_id != deployment_policy.service_id
            || self.service_identity.executable_sha256
                != accepted.binding().signer_service_executable_digest
            || self.capability_trust.signer.caller_identity_digest != self.caller_identity_digest
            || self.attestation_trust.signer.caller_identity_digest != self.caller_identity_digest
            || self.capability_trust.signer.signer_service_identity_digest
                != self.service_identity.digest()?
            || self.attestation_trust.signer.signer_service_identity_digest
                != self.service_identity.digest()?
        {
            return Err(ProductionSignerIdentityProofError::TrustLeaseBindingMismatch);
        }
        self.capability_trust.validate_for(
            &ProductionKeyPolicy::capability(),
            &self.registry,
            trusted_now_epoch_s,
        )?;
        self.attestation_trust.validate_for(
            &ProductionKeyPolicy::attestation(),
            &self.registry,
            trusted_now_epoch_s,
        )?;
        Ok(())
    }

    #[must_use]
    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }

    #[must_use]
    pub fn caller_identity_digest(&self) -> &str {
        &self.caller_identity_digest
    }

    #[must_use]
    pub const fn service_identity(&self) -> &SignerServiceIdentity {
        &self.service_identity
    }

    #[must_use]
    pub const fn trust_state(&self) -> &ProductionTrustStateBinding {
        &self.trust_state
    }

    #[must_use]
    pub const fn proved_at_epoch_s(&self) -> u64 {
        self.proved_at_epoch_s
    }

    #[must_use]
    pub const fn expires_at_epoch_s(&self) -> u64 {
        self.expires_at_epoch_s
    }

    #[must_use]
    pub const fn capability_trust(&self) -> &GovernedProductionSignerTrustSnapshot {
        &self.capability_trust
    }

    #[must_use]
    pub const fn attestation_trust(&self) -> &GovernedProductionSignerTrustSnapshot {
        &self.attestation_trust
    }

    #[must_use]
    pub const fn registry(&self) -> &ProductionKeyRegistry {
        &self.registry
    }
}

impl DeployedProductionSignerIdentityProof {
    pub fn verify_trust_lease(
        &self,
        challenge: &ProductionSignerIdentityChallenge,
        accepted: &VerifiedProductionTrustState,
        deployment_policy: &ProductionSignerDeploymentPolicy,
        trusted_now_epoch_s: u64,
    ) -> Result<VerifiedProductionSignerTrustLease, ProductionSignerIdentityProofError> {
        let service_identity =
            self.verify(challenge, accepted, deployment_policy, trusted_now_epoch_s)?;
        let capability_trust = governed_trust_for_identity(
            &ProductionKeyIdentity::capability(),
            &self.payload.caller_identity_digest,
            &service_identity,
            accepted,
            deployment_policy,
            trusted_now_epoch_s,
        )?;
        let attestation_trust = governed_trust_for_identity(
            &ProductionKeyIdentity::attestation(),
            &self.payload.caller_identity_digest,
            &service_identity,
            accepted,
            deployment_policy,
            trusted_now_epoch_s,
        )?;
        if attestation_trust.key != self.payload.attestation_key {
            return Err(ProductionSignerIdentityProofError::TrustLeaseBindingMismatch);
        }
        let lease = VerifiedProductionSignerTrustLease {
            proof_digest: self.proof_digest.clone(),
            caller_identity_digest: self.payload.caller_identity_digest.clone(),
            service_identity,
            trust_state: accepted.binding().clone(),
            deployment_policy_revision: deployment_policy.revision,
            deployment_policy_digest: deployment_policy.policy_digest.clone(),
            proved_at_epoch_s: self.payload.proved_at_epoch_s,
            expires_at_epoch_s: self.payload.expires_at_epoch_s,
            capability_trust,
            attestation_trust,
            registry: accepted.registry().clone(),
        };
        lease.validate_at(accepted, deployment_policy, trusted_now_epoch_s)?;
        Ok(lease)
    }
}

fn governed_trust_for_identity(
    identity: &ProductionKeyIdentity,
    caller_identity_digest: &str,
    service_identity: &SignerServiceIdentity,
    accepted: &VerifiedProductionTrustState,
    deployment_policy: &ProductionSignerDeploymentPolicy,
    trusted_now_epoch_s: u64,
) -> Result<GovernedProductionSignerTrustSnapshot, ProductionSignerIdentityProofError> {
    if !deployment_policy.permits(identity) {
        return Err(ProductionSignerIdentityProofError::TrustLeaseIdentityNotEnabled);
    }
    validate_sha256(caller_identity_digest)?;
    service_identity.validate()?;
    let record = accepted
        .registry()
        .active_record(identity, trusted_now_epoch_s)?;
    let key = key_binding(record, accepted.binding())?;
    let trust = GovernedProductionSignerTrustSnapshot {
        signer: ProductionSignerTrustSnapshot {
            identity: identity.clone(),
            public_key_digest: key.public_key_digest.clone(),
            allowlist_revision: accepted.binding().caller_allowlist_revision,
            allowlist_digest: accepted.binding().caller_allowlist_digest.clone(),
            caller_identity_digest: caller_identity_digest.to_owned(),
            signer_service_identity_digest: service_identity.digest()?,
        },
        key,
    };
    trust.validate_for(
        &ProductionKeyPolicy::for_identity(identity.clone()),
        accepted.registry(),
        trusted_now_epoch_s,
    )?;
    Ok(trust)
}

fn active_attestation_binding(
    accepted: &VerifiedProductionTrustState,
    at_epoch_s: u64,
) -> Result<ProductionKeyTrustBinding, ProductionSignerIdentityProofError> {
    let record = accepted
        .registry()
        .active_record(&ProductionKeyIdentity::attestation(), at_epoch_s)?;
    key_binding(record, accepted.binding())
}

fn key_binding(
    record: &ProductionKeyRecord,
    trust_state: &ProductionTrustStateBinding,
) -> Result<ProductionKeyTrustBinding, ProductionSignerIdentityProofError> {
    record.validate_seal()?;
    trust_state.validate_seal()?;
    let binding = ProductionKeyTrustBinding {
        schema_version: PRODUCTION_KEY_TRUST_BINDING_SCHEMA.to_owned(),
        identity: record.identity.clone(),
        generation: record.generation,
        public_key_digest: record.public_key_digest.clone(),
        key_record_digest: record.record_digest.clone(),
        registry_revision: trust_state.registry_revision,
        registry_digest: trust_state.registry_digest.clone(),
    };
    binding.validate_shape()?;
    Ok(binding)
}

fn digest_with_blank_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, ProductionSignerIdentityProofError> {
    let mut value = serde_json::to_value(value)?;
    let object = value
        .as_object_mut()
        .ok_or(ProductionSignerIdentityProofError::InvalidCanonicalObject)?;
    object.insert(field.to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

#[derive(Debug, Error)]
pub enum ProductionSignerIdentityProofError {
    #[error("production signer identity challenge schema is unsupported")]
    UnsupportedChallengeSchema,
    #[error("production signer identity proof payload schema is unsupported")]
    UnsupportedProofPayloadSchema,
    #[error("production signer identity proof schema is unsupported")]
    UnsupportedProofSchema,
    #[error("production signer identity proof purpose was substituted")]
    PurposeSubstitution,
    #[error("production signer identity challenge validity window is invalid")]
    InvalidChallengeWindow,
    #[error("production signer identity challenge is outside its validity window")]
    ChallengeOutsideValidityWindow,
    #[error("production signer identity challenge does not match accepted deployment state")]
    ChallengeBindingMismatch,
    #[error("production signer identity challenge digest does not match")]
    ChallengeDigestMismatch,
    #[error("production signer identity challenge attestation key does not match")]
    AttestationKeyMismatch,
    #[error("production signer live service identity does not match accepted deployment state")]
    ServiceIdentityMismatch,
    #[error("production signer identity proof payload bindings do not match")]
    ProofPayloadBindingMismatch,
    #[error("production signer identity proof payload digest does not match")]
    ProofPayloadDigestMismatch,
    #[error("production signer identity proof does not contain a signed package")]
    SignedProofMissing,
    #[error("production signer identity proof signed package bindings do not match")]
    SignedProofBindingMismatch,
    #[error("production signer identity proof does not match the client challenge")]
    ProofChallengeMismatch,
    #[error("production signer identity proof digest does not match")]
    ProofDigestMismatch,
    #[error("production signer trust lease is outside its proof validity window")]
    TrustLeaseOutsideValidityWindow,
    #[error("production signer trust lease bindings do not match the verified deployment")]
    TrustLeaseBindingMismatch,
    #[error("production signer trust lease requires a disabled production identity")]
    TrustLeaseIdentityNotEnabled,
    #[error("production signer identity proof canonical object is invalid")]
    InvalidCanonicalObject,
    #[error("production signer identity proof JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error(transparent)]
    Production(#[from] ProductionSignerError),
    #[error(transparent)]
    Protocol(#[from] ProductionSignerProtocolError),
    #[error(transparent)]
    KeyGovernance(#[from] ProductionKeyGovernanceError),
    #[error(transparent)]
    TrustState(#[from] ProductionTrustStateError),
    #[error(transparent)]
    Service(#[from] ProductionSignerServiceError),
    #[error(transparent)]
    Deployed(#[from] DeployedProductionSignerError),
}
