use ergaxiom_backend_issuance_runtime::LoadedBackendProductionDeployment;
use ergaxiom_desktop_shell_runtime::{AuthorityStatus, verify_desktop_shell_snapshot};
use ergaxiom_evidence_runtime::assess_bundle;
use ergaxiom_production_execution_authority_runtime::PersistentProductionExecutionAuthority;
use ergaxiom_production_execution_runtime::{
    ProductionExecutionChainState, ProductionExecutionStage,
};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, canonical_json_sha256};
use ergaxiom_windows_production_governed_issuance_runtime::verify_governed_production_attestation_against_bundle;
use ergaxiom_windows_production_trust_state_runtime::VerifiedProductionSignerTrustLease;

use crate::pipeline::PreparedDesktopJob;
use crate::production_execution::ProductionExecutionBoundaryError;

pub(crate) fn verify_recovered_production_chain(
    authority: &PersistentProductionExecutionAuthority,
    state: &ProductionExecutionChainState,
    lease: &VerifiedProductionSignerTrustLease,
    deployment: &LoadedBackendProductionDeployment,
    trusted_now_epoch_s: u64,
    prepared: &PreparedDesktopJob,
) -> Result<(), ProductionExecutionBoundaryError> {
    if !matches!(
        state.stage,
        ProductionExecutionStage::Certified | ProductionExecutionStage::RolledBack
    ) || state.state_digest != authority.chain_state().state_digest
    {
        return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
    }
    lease
        .validate_at(
            &deployment.signer.accepted,
            &deployment.signer.deployment_policy,
            trusted_now_epoch_s,
        )
        .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;

    let bundle = state
        .evidence_bundle
        .as_ref()
        .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    let executed_snapshot = state
        .executed_snapshot
        .as_ref()
        .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    authority
        .verify_execution_evidence_binding(bundle, executed_snapshot)
        .map_err(ProductionExecutionBoundaryError::from)?;
    let assessment = assess_bundle(
        prepared.compiled_contract.clone(),
        &prepared.compiled_plan,
        bundle,
        AssuranceLevel::E3,
    )
    .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    if assessment.decision.status != DecisionStatus::Accepted
        || assessment.mandatory_failed != 0
        || assessment.mandatory_unknown != 0
        || state.evidence_bundle_digest.as_deref() != Some(assessment.bundle_digest.as_str())
    {
        return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
    }

    let package = state
        .acceptance_package
        .as_ref()
        .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    let verified = verify_governed_production_attestation_against_bundle(
        package,
        lease.attestation_trust(),
        lease.registry(),
        prepared.compiled_contract.clone(),
        &prepared.compiled_plan,
        bundle,
        AssuranceLevel::E3,
    )
    .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    if verified.decision != DecisionStatus::Accepted
        || state.verified_attestation.as_ref() != Some(&verified)
        || state.replay_manifest.as_ref() != Some(&package.replay_manifest)
    {
        return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
    }

    let final_snapshot = state
        .final_snapshot
        .as_ref()
        .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    if !verify_desktop_shell_snapshot(final_snapshot)
        .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?
        || final_snapshot.authority_status != AuthorityStatus::VerifiedAccepted
    {
        return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
    }
    let certificate = final_snapshot
        .certificate
        .as_ref()
        .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
    if !certificate.signature_verified
        || !certificate.bundle_verified
        || !certificate.decision_accepted
        || certificate.mandatory_failures != 0
        || certificate.mandatory_unknowns != 0
        || certificate.certificate_id != verified.certificate_id
        || certificate.certificate_digest != verified.certificate_digest
        || certificate.evidence_bundle_digest != verified.evidence_bundle_digest
    {
        return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
    }

    if state.capabilities.len() != prepared.compiled_plan.steps.len() {
        return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
    }
    for capability in &state.capabilities {
        capability
            .token
            .signer_package
            .verify_governed(
                lease.capability_trust(),
                lease.registry(),
                capability.token.payload.issued_at_epoch_s,
            )
            .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
        let token_value = serde_json::to_value(&capability.token)
            .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
        let token_digest = canonical_json_sha256(&token_value)
            .map_err(|_| ProductionExecutionBoundaryError::TrustLeaseRejected)?;
        let receipt = capability
            .consumption_receipt
            .as_ref()
            .ok_or(ProductionExecutionBoundaryError::TrustLeaseRejected)?;
        if token_digest != capability.token_digest
            || receipt.token_digest != token_digest
            || receipt.token_id != capability.token.payload.token_id
            || receipt.executor_id != authority.executor_id()
            || receipt.device_id.as_deref() != authority.device_id()
            || receipt.contract_digest != prepared.compiled_contract.seal.contract_digest
            || receipt.capsule_digest != prepared.compiled_contract.seal.capsule_digest
            || receipt.plan_id != prepared.compiled_plan.plan_id
            || receipt.plan_digest != prepared.compiled_plan.plan_digest
            || receipt.use_number != 1
            || receipt.max_uses != 1
        {
            return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
        }
    }
    Ok(())
}
