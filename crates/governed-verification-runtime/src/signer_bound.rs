use ergaxiom_capability_runtime::{AuthorizationReceipt, SignerBoundCapabilityToken};
use ergaxiom_contract_runtime::CompiledContract;
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_operator_plan_runtime::CompiledPlan;
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
        let authorizer = self.capability_authorizers.get_mut(&identity).ok_or_else(|| {
            GovernedVerificationError::MissingCapabilityAuthorizer {
                issuer_id: identity.0.clone(),
                key_id: identity.1.clone(),
            }
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
}
