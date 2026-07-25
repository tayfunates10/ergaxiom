use ergaxiom_attestation_runtime::{
    AttestationKeyRegistry, SignerBoundAttestationPackage, VerifiedAttestation,
    verify_signer_bound_attestation, verify_signer_bound_attestation_against_bundle,
};
use ergaxiom_capability_runtime::{AuthorizationReceipt, SignerBoundCapabilityToken};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_operator_plan_runtime::CompiledPlan;
use ergaxiom_proof_kernel::AssuranceLevel;
use serde_json::Value;

use crate::{GovernedVerificationError, GovernedVerificationRuntime};

impl GovernedVerificationRuntime {
    pub fn verify_signer_bound_capability_token_signature(
        &self,
        token_value: &Value,
    ) -> Result<SignerBoundCapabilityToken, GovernedVerificationError> {
        let token: SignerBoundCapabilityToken = serde_json::from_value(token_value.clone())
            .map_err(GovernedVerificationError::CapabilityTokenDecode)?;
        self.registry.resolve_ed25519(
            IssuerRole::Capability,
            &token.payload.issuer_id,
            &token.payload.key_id,
            token.payload.issued_at_epoch_s,
        )?;
        let identity = (
            token.payload.issuer_id.clone(),
            token.payload.key_id.clone(),
        );
        let authorizer = self.capability_authorizers.get(&identity).ok_or_else(|| {
            GovernedVerificationError::MissingCapabilityAuthorizer {
                issuer_id: identity.0.clone(),
                key_id: identity.1.clone(),
            }
        })?;
        authorizer.verify_signer_bound_signature(&token)?;
        Ok(token)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_signer_bound_capability(
        &mut self,
        token_value: &Value,
        compiled_contract: &CompiledContract,
        compiled_plan: &CompiledPlan,
        trusted_now_epoch_s: u64,
        expected_executor_id: &str,
        expected_device_id: Option<&str>,
    ) -> Result<AuthorizationReceipt, GovernedVerificationError> {
        let token = self.verify_signer_bound_capability_token_signature(token_value)?;
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
        Ok(authorizer.authorize_signer_bound(
            token_value,
            compiled_contract,
            compiled_plan,
            trusted_now_epoch_s,
            expected_executor_id,
            expected_device_id,
        )?)
    }

    pub fn verify_signer_bound_attestation_package(
        &self,
        package: &SignerBoundAttestationPackage,
    ) -> Result<VerifiedAttestation, GovernedVerificationError> {
        let registry = self.signer_bound_attestation_registry(package)?;
        Ok(verify_signer_bound_attestation(package, &registry)?)
    }

    pub fn verify_signer_bound_attestation_package_against_bundle(
        &self,
        package: &SignerBoundAttestationPackage,
        compiled_contract: CompiledContract,
        compiled_plan: &CompiledPlan,
        bundle_value: &Value,
        verified_assurance_level: AssuranceLevel,
    ) -> Result<VerifiedAttestation, GovernedVerificationError> {
        let registry = self.signer_bound_attestation_registry(package)?;
        Ok(verify_signer_bound_attestation_against_bundle(
            package,
            &registry,
            compiled_contract,
            compiled_plan,
            bundle_value,
            verified_assurance_level,
        )?)
    }

    fn signer_bound_attestation_registry(
        &self,
        package: &SignerBoundAttestationPackage,
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
