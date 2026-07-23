mod support;

use std::error::Error;
use std::{env, fs};

use ed25519_dalek::SigningKey;
use ergaxiom_attestation_runtime::{AttestationKeyRegistry, AttestationVerifyError};
use ergaxiom_inkscape_adapter_runtime::{SetTextAndExportRequest, VerifiedInkscape, sha256_file};
use ergaxiom_inkscape_execution_evidence_runtime::{
    InkscapeExecutionKeyRegistry, sign_execution_record,
};

use ergaxiom_graphic_inkscape_srgb_certified_delivery_runtime::{
    InkscapeSrgbCertificationError, InkscapeSrgbCertificationRequest,
    certify_inkscape_srgb_graphic_delivery,
};
use ergaxiom_png_srgb_normalizer_runtime::NormalizationEvidenceError;
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus};
use serde_json::json;

use support::{
    ATTESTATION_ISSUER, ATTESTATION_KEY_ID, EXECUTION_ISSUER, EXECUTION_KEY_ID, ExecutionFixture,
    NOW, TestDirectory, attestation_keys, authorizer, certify_base_delivery, context,
    normalization_fixture, normalization_material, signed_tokens, svg, synthetic_execution_fixture,
    workspace,
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

#[cfg(feature = "real-inkscape-tests")]
#[test]
fn real_inkscape_srgb_execution_produces_final_attestation() -> Result<(), Box<dyn Error>> {
    let (Ok(executable), Ok(executable_digest)) = (
        env::var("ERGAXIOM_INKSCAPE"),
        env::var("ERGAXIOM_INKSCAPE_SHA256"),
    ) else {
        return Ok(());
    };

    let context = context()?;
    let tokens = signed_tokens(&context)?;
    let directory = TestDirectory::create("real-final")?;
    let source = directory.join("source.svg");
    let editable = directory.join("editable.svg");
    let raster = directory.join("raw.png");
    fs::write(&source, svg("BEFORE"))?;

    let inkscape = VerifiedInkscape::open(&executable, &executable_digest)?;
    let execution_request = SetTextAndExportRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.real-inkscape-srgb-final.0001".to_owned(),
        source_svg: source.clone(),
        expected_source_digest: sha256_file(&source)?,
        target_element_id: "headline".to_owned(),
        replacement_text: context.job.approved_copy.text.clone(),
        editable_output_svg: editable.clone(),
        raster_output_png: raster.clone(),
        export_width: context.job.canvas.width,
        export_height: context.job.canvas.height,
    };
    let execution_record = inkscape.execute_set_text_and_export(&execution_request)?;
    let execution_key = SigningKey::from_bytes(&[73_u8; 32]);
    let execution_package = sign_execution_record(
        &execution_record,
        EXECUTION_ISSUER,
        EXECUTION_KEY_ID,
        &execution_key,
    )?;
    let mut execution_keys = InkscapeExecutionKeyRegistry::default();
    execution_keys.insert_ed25519(
        EXECUTION_ISSUER,
        EXECUTION_KEY_ID,
        execution_key.verifying_key().to_bytes(),
    )?;
    let execution = ExecutionFixture {
        _directory: directory,
        source,
        editable,
        raster,
        request: execution_request,
        package: execution_package,
        keys: execution_keys,
    };
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
        contract_value: &context.contract_value,
        compiled_contract: &context.compiled_contract,
        compiled_plan: &context.compiled_plan,
        assurance_level: AssuranceLevel::E3,
        final_manifest_id: "manifest.real-inkscape-srgb-final.0001",
        final_certificate_id: "certificate.real-inkscape-srgb-final.0001",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW + 2,
        attestation_signing_key: &context.attestation_key,
    })?;

    assert_eq!(execution_record.binary.executable_digest, executable_digest);
    assert_eq!(
        delivery.normalization_binding.editable_svg_digest,
        execution_record.editable_output_digest
    );
    assert_eq!(
        delivery.normalization_binding.raw_raster_png_digest,
        execution_record.raster_output_digest
    );
    assert_eq!(
        delivery.normalization_binding.input_idat_payload_digest,
        delivery.normalization_binding.output_idat_payload_digest
    );
    assert_eq!(
        delivery.normalization_binding.contract_color_profile,
        "sRGB IEC61966-2.1"
    );
    assert_eq!(
        delivery.verified_attestation.evidence_bundle_digest,
        delivery.evidence_bundle_digest
    );
    assert_eq!(
        delivery.evidence_bundle.claimed_decision.status,
        DecisionStatus::Accepted
    );
    assert_eq!(
        authorizer.usage_count("ergaxiom.policy-authority", "token.canvas"),
        1
    );
    assert_eq!(
        authorizer.usage_count("ergaxiom.policy-authority", "token.export"),
        1
    );
    eprintln!(
        "real Inkscape sRGB final attestation digest: {}",
        delivery.evidence_bundle_digest
    );
    Ok(())
}

#[test]
fn untrusted_base_attestation_key_cannot_re_attest() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let tokens = signed_tokens(&context)?;
    let execution = synthetic_execution_fixture()?;
    let normalization = normalization_fixture(&execution)?;
    let mut workspace = workspace()?;
    let mut authorizer = authorizer(&context)?;
    let base_delivery = certify_base_delivery(
        &context,
        &mut workspace,
        &mut authorizer,
        &tokens,
        &execution,
    )?;
    let untrusted_keys = AttestationKeyRegistry::default();

    let result = certify_inkscape_srgb_graphic_delivery(InkscapeSrgbCertificationRequest {
        base_delivery,
        normalization_material: normalization_material(&execution, &normalization),
        normalization_keys: &normalization.keys,
        base_attestation_keys: &untrusted_keys,
        contract_value: &context.contract_value,
        compiled_contract: &context.compiled_contract,
        compiled_plan: &context.compiled_plan,
        assurance_level: AssuranceLevel::E3,
        final_manifest_id: "manifest.graphic-inkscape-srgb.untrusted-base",
        final_certificate_id: "certificate.graphic-inkscape-srgb.untrusted-base",
        attestation_issuer_id: ATTESTATION_ISSUER,
        attestation_key_id: ATTESTATION_KEY_ID,
        certificate_issued_at_epoch_s: NOW + 1,
        attestation_signing_key: &context.attestation_key,
    });

    assert!(matches!(
        result,
        Err(InkscapeSrgbCertificationError::AttestationVerify(
            AttestationVerifyError::UnknownTrustedKey { .. }
        ))
    ));
    Ok(())
}
