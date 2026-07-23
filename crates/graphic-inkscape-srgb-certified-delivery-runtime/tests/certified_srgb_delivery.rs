mod support;

use std::error::Error;

use ergaxiom_graphic_inkscape_srgb_certified_delivery_runtime::{
    InkscapeSrgbCertificationError, InkscapeSrgbCertificationRequest,
    certify_inkscape_srgb_graphic_delivery,
};
use ergaxiom_png_srgb_normalizer_runtime::NormalizationEvidenceError;
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus};
use serde_json::json;

use support::{
    ATTESTATION_ISSUER, ATTESTATION_KEY_ID, NOW, attestation_keys, authorizer,
    certify_base_delivery, context, normalization_fixture, normalization_material, signed_tokens,
    synthetic_execution_fixture, workspace,
};

#[test]
fn signed_normalization_is_bound_into_a_new_final_attestation() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let tokens = signed_tokens(&context)?;
    let execution = synthetic_execution_fixture()?;
    let normalization = normalization_fixture(&execution)?;
    let mut workspace = workspace()?;
    let mut authorizer = authorizer(&context)?;
    let base_attestation_keys = attestation_keys(&context)?;
    let base_delivery = certify_base_delivery(
        &context,
        &mut workspace,
        &mut authorizer,
        &tokens,
        &execution,
    )?;

    let delivery = certify_inkscape_srgb_graphic_delivery(InkscapeSrgbCertificationRequest {
        base_delivery,
        normalization_material: normalization_material(&execution, &normalization),
        normalization_keys: &normalization.keys,
        base_attestation_keys: &base_attestation_keys,
        base_attestation_keys: &base_attestation_keys,
        contract_value: &context.contract_value,
        compiled_contract: &context.compiled_contract,
        compiled_plan: &context.compiled_plan,
        assurance_level: AssuranceLevel::E3,
        final_manifest_id: "manifest.graphic-inkscape-srgb-final.0001",
        final_certificate_id: "certificate.graphic-inkscape-srgb-final.0001",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW + 1,
        attestation_signing_key: &context.attestation_key,
    })?;

    assert_eq!(
        delivery.evidence_bundle.claimed_decision.status,
        DecisionStatus::Accepted
    );
    assert_eq!(
        delivery.verified_attestation.evidence_bundle_digest,
        delivery.evidence_bundle_digest
    );
    assert_eq!(
        delivery.verified_normalization.input_idat_payload_digest,
        delivery.verified_normalization.output_idat_payload_digest
    );
    assert_eq!(
        delivery.normalization_binding.contract_color_profile,
        "sRGB IEC61966-2.1"
    );
    assert_eq!(delivery.normalization_binding_digest.len(), 64);
    assert_ne!(
        delivery.evidence_bundle_digest,
        delivery.base_delivery.evidence_bundle_digest
    );
    for artifact_id in [
        "evidence.inkscape.srgb-normalization-package",
        "evidence.inkscape.srgb-normalization-verification",
        "evidence.inkscape.srgb-delivery-binding",
        "evidence.inkscape.normalized-raster-png",
    ] {
        assert!(
            delivery
                .evidence_bundle
                .artifacts
                .iter()
                .any(|artifact| artifact.artifact_id == artifact_id)
        );
    }
    let keys = base_attestation_keys;
    assert!(
        ergaxiom_attestation_runtime::verify_attestation_against_bundle(
            &delivery.attestation,
            &keys,
            context.compiled_contract.clone(),
            &context.compiled_plan,
            &serde_json::to_value(&delivery.evidence_bundle)?,
            AssuranceLevel::E3,
        )
        .is_ok()
    );
    assert_eq!(
        authorizer.usage_count("ergaxiom.policy-authority", "token.canvas"),
        1
    );
    assert_eq!(
        authorizer.usage_count("ergaxiom.policy-authority", "token.export"),
        1
    );
    Ok(())
}

#[test]
fn mutated_normalization_record_cannot_certify() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let tokens = signed_tokens(&context)?;
    let execution = synthetic_execution_fixture()?;
    let mut normalization = normalization_fixture(&execution)?;
    normalization.package.record.output_png_digest = "0".repeat(64);
    let mut workspace = workspace()?;
    let mut authorizer = authorizer(&context)?;
    let base_attestation_keys = attestation_keys(&context)?;
    let base_delivery = certify_base_delivery(
        &context,
        &mut workspace,
        &mut authorizer,
        &tokens,
        &execution,
    )?;

    let result = certify_inkscape_srgb_graphic_delivery(InkscapeSrgbCertificationRequest {
        base_delivery,
        normalization_material: normalization_material(&execution, &normalization),
        normalization_keys: &normalization.keys,
        base_attestation_keys: &base_attestation_keys,
        base_attestation_keys: &base_attestation_keys,
        contract_value: &context.contract_value,
        compiled_contract: &context.compiled_contract,
        compiled_plan: &context.compiled_plan,
        assurance_level: AssuranceLevel::E3,
        final_manifest_id: "manifest.graphic-inkscape-srgb.invalid-signature",
        final_certificate_id: "certificate.graphic-inkscape-srgb.invalid-signature",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW + 1,
        attestation_signing_key: &context.attestation_key,
    });

    assert!(matches!(
        result,
        Err(InkscapeSrgbCertificationError::NormalizationEvidence(
            NormalizationEvidenceError::SignatureVerificationFailed
        ))
    ));
    Ok(())
}

#[test]
fn non_srgb_contract_cannot_re_attest_the_normalized_delivery() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let tokens = signed_tokens(&context)?;
    let execution = synthetic_execution_fixture()?;
    let normalization = normalization_fixture(&execution)?;
    let mut workspace = workspace()?;
    let mut authorizer = authorizer(&context)?;
    let base_attestation_keys = attestation_keys(&context)?;
    let base_delivery = certify_base_delivery(
        &context,
        &mut workspace,
        &mut authorizer,
        &tokens,
        &execution,
    )?;
    let mut altered_contract = context.contract_value.clone();
    let requirements = altered_contract["requirements"]["hard"]
        .as_array_mut()
        .ok_or("hard requirements missing")?;
    let profile = requirements
        .iter_mut()
        .find(|requirement| requirement["id"] == json!("color_profile"))
        .ok_or("profile requirement missing")?;
    profile["expected"] = json!("Adobe RGB (1998)");

    let result = certify_inkscape_srgb_graphic_delivery(InkscapeSrgbCertificationRequest {
        base_delivery,
        normalization_material: normalization_material(&execution, &normalization),
        normalization_keys: &normalization.keys,
        base_attestation_keys: &base_attestation_keys,
        base_attestation_keys: &base_attestation_keys,
        contract_value: &altered_contract,
        compiled_contract: &context.compiled_contract,
        compiled_plan: &context.compiled_plan,
        assurance_level: AssuranceLevel::E3,
        final_manifest_id: "manifest.graphic-inkscape-srgb.invalid-profile",
        final_certificate_id: "certificate.graphic-inkscape-srgb.invalid-profile",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW + 1,
        attestation_signing_key: &context.attestation_key,
    });

    assert!(matches!(
        result,
        Err(InkscapeSrgbCertificationError::ContractColorProfileMismatch)
    ));
    Ok(())
}
