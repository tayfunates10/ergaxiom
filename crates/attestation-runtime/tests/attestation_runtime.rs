use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_attestation_runtime::{
    AttestationIssueError, AttestationKeyRegistry, AttestationVerifyError, issue_attestation,
    verify_attestation, verify_attestation_against_bundle,
};
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding, SignedCapabilityToken,
    TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::{AssuranceLevel, DecisionStatus, canonical_json_bytes, canonical_json_sha256};
use serde_json::{Value, json};

const POLICY_ISSUER: &str = "ergaxiom.policy-authority";
const POLICY_KEY_ID: &str = "policy-key-01";
const CERTIFICATE_ISSUER: &str = "ergaxiom.certificate-authority";
const CERTIFICATE_KEY_ID: &str = "certificate-key-01";
const EXECUTOR_ID: &str = "executor.test-01";
const DEVICE_ID: &str = "device.test-01";
const NOW: u64 = 2_000;

struct Context {
    contract: CompiledContract,
    plan: CompiledPlan,
    bundle: Value,
    certificate_key: SigningKey,
}

fn context() -> Result<Context, Box<dyn Error>> {
    let contract_value = contract_value();
    let capsule_value = capsule_value();
    let contract = compile_contract(&contract_value, &capsule_value)?;
    let plan = compile_plan(&plan_value(&contract), &capsule_value, &contract)?;
    let policy_key = SigningKey::from_bytes(&[17_u8; 32]);
    let bundle = bundle_value(&contract, &plan, &policy_key)?;
    Ok(Context {
        contract,
        plan,
        bundle,
        certificate_key: SigningKey::from_bytes(&[23_u8; 32]),
    })
}

fn contract_value() -> Value {
    json!({
        "schema_version": "0.2.0",
        "contract_id": "contract.attestation-test.0001",
        "profession": {
            "capsule_id": "ergaxiom.profession.attestation-test",
            "capsule_version": "0.1.0"
        },
        "job_type": "attestation_test_job",
        "requirements": {
            "hard": [{"id": "output_ok", "mandatory": true}],
            "unknowns": []
        },
        "permissions": [{
            "capability": "filesystem",
            "resource": "contract://inputs/*",
            "access": "read",
            "constraints": {"immutable": true}
        }],
        "proof_obligations": [{
            "id": "proof.output_ok",
            "constraint_id": "output_ok",
            "validator_ids": ["validator.output"],
            "mandatory": true,
            "independence_class": "independent",
            "evidence_types": ["measurement"]
        }],
        "acceptance": {
            "minimum_assurance_level": "E1",
            "unknowns_must_be_empty": true,
            "all_mandatory_proofs_must_pass": true,
            "validator_conflicts_allowed": false
        }
    })
}

fn capsule_value() -> Value {
    json!({
        "schema_version": "0.1.0",
        "capsule_id": "ergaxiom.profession.attestation-test",
        "version": "0.1.0",
        "job_types": [{
            "id": "attestation_test_job",
            "required_constraints": ["output_ok"],
            "minimum_assurance_level": "E1",
            "operator_ids": ["operator.test"]
        }],
        "operators": [{"id": "operator.test", "version": "1.0.0"}],
        "validators": [{
            "id": "validator.output",
            "version": "1.0.0",
            "claims": ["output_ok"],
            "independence_class": "independent",
            "evidence_types": ["measurement"]
        }],
        "policies": {
            "minimum_assurance_by_job_type": {"attestation_test_job": "E1"}
        }
    })
}

fn plan_value(contract: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.attestation-test.0001",
        "created_at": "2026-07-21T10:10:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.attestation-test",
                "algorithm": "sha256",
                "digest": contract.seal.capsule_digest
            }
        },
        "steps": [{
            "step_id": "step.test",
            "sequence": 0,
            "operator_id": "operator.test",
            "operator_version": "1.0.0",
            "depends_on": [],
            "input_artifact_ids": ["input"],
            "output_artifact_ids": ["output"],
            "capability_token_ids": ["token.test"],
            "mandatory": true,
            "rollback_step_id": null
        }]
    })
}

fn bundle_value(
    contract: &CompiledContract,
    plan: &CompiledPlan,
    policy_key: &SigningKey,
) -> Result<Value, Box<dyn Error>> {
    let token = signed_capability_token(contract, plan, policy_key)?;
    let mut trusted_keys = TrustedKeyRegistry::default();
    trusted_keys.insert_ed25519(
        POLICY_ISSUER,
        POLICY_KEY_ID,
        policy_key.verifying_key().to_bytes(),
    )?;
    let mut authorizer = CapabilityAuthorizer::new(trusted_keys);
    let receipt = authorizer.authorize(
        &token,
        contract,
        plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?;
    let receipt_value = serde_json::to_value(&receipt)?;
    let receipt_digest = canonical_json_sha256(&receipt_value)?;

    Ok(json!({
        "schema_version": "0.4.0",
        "bundle_id": "bundle.attestation-test.0001",
        "run_id": "run.attestation-test.0001",
        "created_at": "2026-07-21T10:15:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.attestation-test",
                "algorithm": "sha256",
                "digest": contract.seal.capsule_digest
            },
            "operator_plan": {
                "id": plan.plan_id,
                "algorithm": "sha256",
                "digest": plan.plan_digest
            }
        },
        "environment": {
            "os": "test-os",
            "kernel_version": "ergaxiom-proof-kernel/0.1.0",
            "applications": [{
                "id": "test-application",
                "version": "1.0.0",
                "digest": "application-digest"
            }],
            "clock_source": "trusted-test-clock",
            "sandbox_id": "sandbox-attestation-test"
        },
        "artifacts": [
            {
                "artifact_id": "output",
                "role": "output",
                "uri": "bundle://artifacts/output",
                "media_type": "application/octet-stream",
                "algorithm": "sha256",
                "digest": "output-digest",
                "size_bytes": 42
            },
            {
                "artifact_id": "evidence.output",
                "role": "evidence",
                "uri": "bundle://artifacts/evidence.output",
                "media_type": "application/json",
                "algorithm": "sha256",
                "digest": "evidence-digest",
                "size_bytes": 21
            }
        ],
        "trace": {
            "schema_version": "0.1.0",
            "trace_id": "trace.attestation-test.0001",
            "plan_id": plan.plan_id,
            "plan_digest": plan.plan_digest,
            "claimed_conforms_to_authorized_plan": true,
            "authorization_receipts": [{
                "receipt_digest": receipt_digest,
                "receipt": receipt_value
            }],
            "events": [
                {
                    "event": trace_event(0, "STARTED"),
                    "authorization_receipt_digest": receipt_digest
                },
                {
                    "event": trace_event(1, "SUCCEEDED"),
                    "authorization_receipt_digest": receipt_digest
                }
            ]
        },
        "proof_results": [{
            "evidence_id": "evidence.output-ok",
            "obligation_id": "proof.output_ok",
            "claim_id": "output_ok",
            "subject_artifact_id": "output",
            "validator_id": "validator.output",
            "validator_version": "1.0.0",
            "independence_class": "independent",
            "status": "PASSED",
            "mandatory": true,
            "observed": true,
            "expected": true,
            "unit": null,
            "tolerance": null,
            "evidence_artifact_ids": ["evidence.output"],
            "evaluated_at": "2026-07-21T10:15:00Z"
        }],
        "claimed_decision": {
            "status": "ACCEPTED",
            "assurance_level": "E1",
            "mandatory_passed": 1,
            "mandatory_failed": 0,
            "mandatory_unknown": 0,
            "reason": "Mandatory output proof passed.",
            "sealed_at": null,
            "signature": null
        }
    }))
}

fn signed_capability_token(
    contract: &CompiledContract,
    plan: &CompiledPlan,
    policy_key: &SigningKey,
) -> Result<Value, Box<dyn Error>> {
    let payload = CapabilityTokenPayload {
        schema_version: "0.1.0".to_owned(),
        token_id: "token.test".to_owned(),
        issuer_id: POLICY_ISSUER.to_owned(),
        key_id: POLICY_KEY_ID.to_owned(),
        subject: CapabilitySubject {
            executor_id: EXECUTOR_ID.to_owned(),
            device_id: Some(DEVICE_ID.to_owned()),
        },
        issued_at_epoch_s: 1_900,
        not_before_epoch_s: 1_950,
        expires_at_epoch_s: 2_100,
        max_uses: 1,
        nonce: "attestation-nonce-000001".to_owned(),
        bindings: CapabilityBindings {
            contract_digest: contract.seal.contract_digest.clone(),
            capsule_digest: contract.seal.capsule_digest.clone(),
            plan_id: plan.plan_id.clone(),
            plan_digest: plan.plan_digest.clone(),
            step_id: "step.test".to_owned(),
            operator_id: "operator.test".to_owned(),
        },
        grant: CapabilityGrant {
            capability: "filesystem".to_owned(),
            resource: "contract://inputs/*".to_owned(),
            access: PermissionAccess::Read,
            constraints: json!({"immutable": true}),
        },
    };
    let payload_value = serde_json::to_value(&payload)?;
    let signature = policy_key.sign(&canonical_json_bytes(&payload_value)?);
    Ok(serde_json::to_value(SignedCapabilityToken {
        payload,
        signature: TokenSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            encoding: SignatureEncoding::Base64url,
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })?)
}

fn trace_event(sequence: usize, status: &str) -> Value {
    json!({
        "event_id": format!("event.{sequence}"),
        "step_id": "step.test",
        "sequence": sequence,
        "timestamp": format!("2026-07-21T10:12:{sequence:02}Z"),
        "operator_id": "operator.test",
        "status": status,
        "input_digests": ["input-digest"],
        "output_digests": ["output-digest"],
        "capability_token_id": "token.test"
    })
}

fn certificate_registry(context: &Context) -> Result<AttestationKeyRegistry, Box<dyn Error>> {
    let mut registry = AttestationKeyRegistry::default();
    registry.insert_ed25519(
        CERTIFICATE_ISSUER,
        CERTIFICATE_KEY_ID,
        context.certificate_key.verifying_key().to_bytes(),
    )?;
    Ok(registry)
}

fn issue(context: Context) -> Result<ergaxiom_attestation_runtime::AttestationPackage, Box<dyn Error>> {
    Ok(issue_attestation(
        context.contract,
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        "manifest.attestation-test.0001",
        "certificate.attestation-test.0001",
        CERTIFICATE_ISSUER,
        CERTIFICATE_KEY_ID,
        2_050,
        &context.certificate_key,
    )?)
}

#[test]
fn issues_and_verifies_an_accepted_bundle() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let registry = certificate_registry(&context)?;
    let package = issue_attestation(
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        "manifest.attestation-test.0001",
        "certificate.attestation-test.0001",
        CERTIFICATE_ISSUER,
        CERTIFICATE_KEY_ID,
        2_050,
        &context.certificate_key,
    )?;

    let verified = verify_attestation_against_bundle(
        &package,
        &registry,
        context.contract,
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
    )?;
    assert_eq!(verified.decision, DecisionStatus::Accepted);
    assert_eq!(verified.assurance_level, AssuranceLevel::E1);
    assert_eq!(verified.certificate_digest.len(), 64);
    assert_eq!(verified.replay_manifest_digest.len(), 64);
    assert_eq!(package.replay_manifest.mandatory_passed, 1);
    Ok(())
}

#[test]
fn refuses_to_issue_for_a_rejected_bundle() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.bundle["proof_results"][0]["status"] = json!("FAILED");
    context.bundle["claimed_decision"]["status"] = json!("REJECTED");
    context.bundle["claimed_decision"]["mandatory_passed"] = json!(0);
    context.bundle["claimed_decision"]["mandatory_failed"] = json!(1);

    let result = issue_attestation(
        context.contract,
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        "manifest.rejected",
        "certificate.rejected",
        CERTIFICATE_ISSUER,
        CERTIFICATE_KEY_ID,
        2_050,
        &context.certificate_key,
    );
    assert!(matches!(
        result,
        Err(AttestationIssueError::DecisionNotAccepted(
            DecisionStatus::Rejected
        ))
    ));
    Ok(())
}

#[test]
fn bundle_mutation_after_issuance_invalidates_source_verification() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let registry = certificate_registry(&context)?;
    let package = issue_attestation(
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        "manifest.attestation-test.0001",
        "certificate.attestation-test.0001",
        CERTIFICATE_ISSUER,
        CERTIFICATE_KEY_ID,
        2_050,
        &context.certificate_key,
    )?;
    let mut mutated_bundle = context.bundle.clone();
    mutated_bundle["artifacts"][0]["digest"] = json!("mutated-output-digest");

    assert!(matches!(
        verify_attestation_against_bundle(
            &package,
            &registry,
            context.contract,
            &context.plan,
            &mutated_bundle,
            AssuranceLevel::E1
        ),
        Err(AttestationVerifyError::RecomputedManifestMismatch)
    ));
    Ok(())
}

#[test]
fn replay_manifest_mutation_breaks_certificate_binding() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let registry = certificate_registry(&context)?;
    let mut package = issue(context)?;
    package.replay_manifest.environment_digest = "mutated-environment".to_owned();

    assert!(matches!(
        verify_attestation(&package, &registry),
        Err(AttestationVerifyError::ManifestDigestMismatch)
    ));
    Ok(())
}

#[test]
fn unknown_certificate_key_is_rejected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let package = issue(context)?;
    let empty_registry = AttestationKeyRegistry::default();

    assert!(matches!(
        verify_attestation(&package, &empty_registry),
        Err(AttestationVerifyError::UnknownTrustedKey { .. })
    ));
    Ok(())
}

#[test]
fn signature_tampering_is_rejected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let registry = certificate_registry(&context)?;
    let mut package = issue(context)?;
    package.certificate.signature.value = "invalid-signature".to_owned();

    assert!(matches!(
        verify_attestation(&package, &registry),
        Err(AttestationVerifyError::InvalidSignatureLength)
            | Err(AttestationVerifyError::SignatureVerificationFailed)
    ));
    Ok(())
}

#[test]
fn certificate_payload_mutation_is_rejected() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let registry = certificate_registry(&context)?;
    let mut package = issue(context)?;
    package.certificate.payload.evidence_bundle_digest = "mutated-bundle".to_owned();

    assert!(matches!(
        verify_attestation(&package, &registry),
        Err(AttestationVerifyError::SignatureVerificationFailed)
    ));
    Ok(())
}

#[test]
fn deterministic_manifest_is_stable_for_the_same_accepted_run() -> Result<(), Box<dyn Error>> {
    let first_context = context()?;
    let second_context = context()?;
    let first = issue_attestation(
        first_context.contract,
        &first_context.plan,
        &first_context.bundle,
        AssuranceLevel::E1,
        "manifest.stable",
        "certificate.first",
        CERTIFICATE_ISSUER,
        CERTIFICATE_KEY_ID,
        2_050,
        &first_context.certificate_key,
    )?;
    let second = issue_attestation(
        second_context.contract,
        &second_context.plan,
        &second_context.bundle,
        AssuranceLevel::E1,
        "manifest.stable",
        "certificate.second",
        CERTIFICATE_ISSUER,
        CERTIFICATE_KEY_ID,
        2_060,
        &second_context.certificate_key,
    )?;

    assert_eq!(first.replay_manifest, second.replay_manifest);
    Ok(())
}
