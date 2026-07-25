use std::cell::Cell;
use std::error::Error;
use std::rc::Rc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_attestation_issuance_runtime::{
    ATTESTATION_ISSUER_ID, ATTESTATION_KEY_ID, AttestationCertificateDraft,
    AttestationIssuanceAuthority, AttestationIssuanceError, AttestationSignerTransport,
};
use ergaxiom_attestation_runtime::{
    AttestationKeyRegistry, AttestationVerifyError, verify_signer_bound_attestation_against_bundle,
};
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding, SignedCapabilityToken,
    TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::{AssuranceLevel, canonical_json_bytes, canonical_json_sha256};
use ergaxiom_windows_signer_protocol_runtime::{
    SIGNATURE_ALGORITHM_ED25519, SIGNATURE_ENCODING_BASE64URL, SignerRequest, SignerResponse,
    SignerSuccess, encode_hex,
};
use serde_json::{Value, json};

const POLICY_ISSUER: &str = "ergaxiom.policy-authority";
const POLICY_KEY_ID: &str = "policy-key-01";
const EXECUTOR_ID: &str = "executor.attestation-issuance.0001";
const DEVICE_ID: &str = "device.attestation-issuance.0001";
const NOW: u64 = 2_000;

#[derive(Debug, Clone, Copy)]
enum Mutation {
    None,
    Role,
    Digest,
    Issuer,
    Key,
}

#[derive(Clone)]
struct TestTransport {
    signing_key: SigningKey,
    mutation: Mutation,
    calls: Rc<Cell<u32>>,
}

impl AttestationSignerTransport for TestTransport {
    fn invoke(&self, request: &SignerRequest) -> Result<SignerResponse, AttestationIssuanceError> {
        self.calls.set(self.calls.get().saturating_add(1));
        let mut signed_request = request.clone();
        match self.mutation {
            Mutation::None => {}
            Mutation::Role => signed_request.role = IssuerRole::Capability,
            Mutation::Digest => signed_request.digest = Some("f".repeat(64)),
            Mutation::Issuer => signed_request.issuer_id = "attestation.substituted".to_owned(),
            Mutation::Key => signed_request.key_id = "attestation-substituted-v1".to_owned(),
        }
        let envelope = signed_request.signing_envelope()?;
        let signature = self.signing_key.sign(&envelope.canonical_bytes()?);
        Ok(SignerResponse::success(
            signed_request.request_id.clone(),
            SignerSuccess::DigestSigned {
                public_key_hex: encode_hex(&self.signing_key.verifying_key().to_bytes()),
                envelope_digest: envelope.digest()?,
                envelope,
                signature_algorithm: SIGNATURE_ALGORITHM_ED25519.to_owned(),
                signature_encoding: SIGNATURE_ENCODING_BASE64URL.to_owned(),
                signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        ))
    }
}

struct Context {
    contract: CompiledContract,
    plan: CompiledPlan,
    bundle: Value,
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
    })
}

fn contract_value() -> Value {
    json!({
        "schema_version": "0.2.0",
        "contract_id": "contract.attestation-issuance.0001",
        "profession": {
            "capsule_id": "ergaxiom.profession.attestation-issuance-test",
            "capsule_version": "0.1.0"
        },
        "job_type": "attestation_issuance_test_job",
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
        "capsule_id": "ergaxiom.profession.attestation-issuance-test",
        "version": "0.1.0",
        "job_types": [{
            "id": "attestation_issuance_test_job",
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
            "minimum_assurance_by_job_type": {"attestation_issuance_test_job": "E1"}
        }
    })
}

fn plan_value(contract: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.attestation-issuance.0001",
        "created_at": "2026-07-25T16:00:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.attestation-issuance-test",
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
    let receipt =
        authorizer.authorize(&token, contract, plan, NOW, EXECUTOR_ID, Some(DEVICE_ID))?;
    let receipt_value = serde_json::to_value(&receipt)?;
    let receipt_digest = canonical_json_sha256(&receipt_value)?;

    Ok(json!({
        "schema_version": "0.4.0",
        "bundle_id": "bundle.attestation-issuance.0001",
        "run_id": "run.attestation-issuance.0001",
        "created_at": "2026-07-25T16:05:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.attestation-issuance-test",
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
            "sandbox_id": "sandbox-attestation-issuance"
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
            "trace_id": "trace.attestation-issuance.0001",
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
            "evaluated_at": "2026-07-25T16:05:00Z"
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
        nonce: "attestation-issuance-nonce-0001".to_owned(),
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
        "timestamp": format!("2026-07-25T16:02:{sequence:02}Z"),
        "operator_id": "operator.test",
        "status": status,
        "input_digests": ["input-digest"],
        "output_digests": ["output-digest"],
        "capability_token_id": "token.test"
    })
}

fn draft() -> AttestationCertificateDraft {
    AttestationCertificateDraft {
        manifest_id: "manifest.attestation-issuance.0001".to_owned(),
        certificate_id: "certificate.attestation-issuance.0001".to_owned(),
        issued_at_epoch_s: 2_050,
    }
}

fn authority(
    signing_key: SigningKey,
    mutation: Mutation,
    calls: Rc<Cell<u32>>,
) -> AttestationIssuanceAuthority<TestTransport> {
    AttestationIssuanceAuthority::new(
        TestTransport {
            signing_key: signing_key.clone(),
            mutation,
            calls,
        },
        signing_key.verifying_key().to_bytes(),
    )
}

#[test]
fn authority_reassesses_bundle_and_fixes_all_signer_fields() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let signing_key = SigningKey::from_bytes(&[61_u8; 32]);
    let calls = Rc::new(Cell::new(0));
    let package = authority(signing_key.clone(), Mutation::None, calls.clone()).issue(
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        draft(),
    )?;
    assert_eq!(calls.get(), 1);
    assert_eq!(package.certificate.payload.issuer_id, ATTESTATION_ISSUER_ID);
    assert_eq!(package.certificate.payload.key_id, ATTESTATION_KEY_ID);
    assert_eq!(package.certificate.payload.decision, ergaxiom_proof_kernel::DecisionStatus::Accepted);
    let envelope = package.certificate.signer_response.verify_digest_signature()?;
    assert_eq!(envelope.role, IssuerRole::Attestation);
    assert_eq!(envelope.issuer_id, ATTESTATION_ISSUER_ID);
    assert_eq!(envelope.key_id, ATTESTATION_KEY_ID);
    assert!(envelope.request_id.starts_with("attestation.issue."));

    let serialized_draft = serde_json::to_value(draft())?;
    for forbidden in ["issuer_id", "key_id", "role", "digest", "request_id"] {
        assert!(serialized_draft.get(forbidden).is_none());
    }

    let mut registry = AttestationKeyRegistry::default();
    registry.insert_ed25519(
        ATTESTATION_ISSUER_ID,
        ATTESTATION_KEY_ID,
        signing_key.verifying_key().to_bytes(),
    )?;
    verify_signer_bound_attestation_against_bundle(
        &package,
        &registry,
        context.contract,
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
    )?;
    Ok(())
}

#[test]
fn role_issuer_key_and_digest_substitution_fail_closed() -> Result<(), Box<dyn Error>> {
    for mutation in [
        Mutation::Role,
        Mutation::Issuer,
        Mutation::Key,
        Mutation::Digest,
    ] {
        let context = context()?;
        let signing_key = SigningKey::from_bytes(&[62_u8; 32]);
        let result = authority(signing_key, mutation, Rc::new(Cell::new(0))).issue(
            context.contract,
            &context.plan,
            &context.bundle,
            AssuranceLevel::E1,
            draft(),
        );
        assert!(matches!(
            result,
            Err(AttestationIssuanceError::SignerRoleMismatch)
                | Err(AttestationIssuanceError::SignerIssuerMismatch)
                | Err(AttestationIssuanceError::SignerKeyMismatch)
                | Err(AttestationIssuanceError::SignerDigestMismatch)
        ));
    }
    Ok(())
}

#[test]
fn substituted_public_key_fails_closed() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let signing_key = SigningKey::from_bytes(&[63_u8; 32]);
    let different_key = SigningKey::from_bytes(&[64_u8; 32]);
    let authority = AttestationIssuanceAuthority::new(
        TestTransport {
            signing_key,
            mutation: Mutation::None,
            calls: Rc::new(Cell::new(0)),
        },
        different_key.verifying_key().to_bytes(),
    );
    assert!(matches!(
        authority.issue(
            context.contract,
            &context.plan,
            &context.bundle,
            AssuranceLevel::E1,
            draft(),
        ),
        Err(AttestationIssuanceError::SignerPublicKeyMismatch)
    ));
    Ok(())
}

#[test]
fn failed_proof_blocks_before_signer_invocation() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.bundle["proof_results"][0]["status"] = json!("FAILED");
    context.bundle["proof_results"][0]["observed"] = json!(false);
    context.bundle["claimed_decision"]["status"] = json!("REJECTED");
    context.bundle["claimed_decision"]["mandatory_passed"] = json!(0);
    context.bundle["claimed_decision"]["mandatory_failed"] = json!(1);
    let calls = Rc::new(Cell::new(0));
    let result = authority(
        SigningKey::from_bytes(&[65_u8; 32]),
        Mutation::None,
        calls.clone(),
    )
    .issue(
        context.contract,
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        draft(),
    );
    assert!(result.is_err());
    assert_eq!(calls.get(), 0);
    Ok(())
}

#[test]
fn payload_and_manifest_mutation_fail_independent_verification() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let signing_key = SigningKey::from_bytes(&[66_u8; 32]);
    let package = authority(
        signing_key.clone(),
        Mutation::None,
        Rc::new(Cell::new(0)),
    )
    .issue(
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        draft(),
    )?;
    let mut registry = AttestationKeyRegistry::default();
    registry.insert_ed25519(
        ATTESTATION_ISSUER_ID,
        ATTESTATION_KEY_ID,
        signing_key.verifying_key().to_bytes(),
    )?;

    let mut payload_tampered = package.clone();
    payload_tampered.certificate.payload.plan_digest = "f".repeat(64);
    assert!(matches!(
        verify_signer_bound_attestation_against_bundle(
            &payload_tampered,
            &registry,
            context.contract.clone(),
            &context.plan,
            &context.bundle,
            AssuranceLevel::E1,
        ),
        Err(AttestationVerifyError::ManifestPayloadMismatch("plan_digest"))
            | Err(AttestationVerifyError::SignerDigestMismatch)
    ));

    let mut manifest_tampered = package;
    manifest_tampered.replay_manifest.environment_digest = "e".repeat(64);
    assert!(matches!(
        verify_signer_bound_attestation_against_bundle(
            &manifest_tampered,
            &registry,
            context.contract,
            &context.plan,
            &context.bundle,
            AssuranceLevel::E1,
        ),
        Err(AttestationVerifyError::ManifestDigestMismatch)
            | Err(AttestationVerifyError::RecomputedManifestMismatch)
    ));
    Ok(())
}
