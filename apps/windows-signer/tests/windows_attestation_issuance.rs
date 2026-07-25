#![cfg(windows)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_attestation_issuance_runtime::{
    ATTESTATION_ISSUER_ID, ATTESTATION_KEY_ID, AttestationCertificateDraft,
    AttestationIssuanceAuthority, AttestationIssuanceError,
};
use ergaxiom_attestation_runtime::{
    AttestationKeyRegistry, verify_signer_bound_attestation_against_bundle,
};
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding, SignedCapabilityToken,
    TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_governed_verification_runtime::{
    GovernedVerificationError, GovernedVerificationRuntime,
};
use ergaxiom_key_governance_runtime::{IssuerRole, KeyGovernanceError};
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::{AssuranceLevel, canonical_json_bytes, canonical_json_sha256};
use ergaxiom_windows_signer_client_runtime::{SignerClientError, SignerProcessClient};
use ergaxiom_windows_signer_protocol_runtime::{
    SignerRequest, SignerResponse, SignerSuccess, decode_hex_32,
};
use serde_json::{Value, json};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
const POLICY_ISSUER: &str = "ergaxiom.policy-authority";
const POLICY_KEY_ID: &str = "policy-key-01";
const EXECUTOR_ID: &str = "executor.windows.attestation.0001";
const DEVICE_ID: &str = "device.windows.attestation.0001";
const NOW: u64 = 2_000;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create(name: &str) -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ergaxiom-attestation-issuance-{name}-{}-{counter}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
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
        "contract_id": "contract.windows-attestation.0001",
        "profession": {
            "capsule_id": "ergaxiom.profession.windows-attestation-test",
            "capsule_version": "0.1.0"
        },
        "job_type": "windows_attestation_test_job",
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
        "capsule_id": "ergaxiom.profession.windows-attestation-test",
        "version": "0.1.0",
        "job_types": [{
            "id": "windows_attestation_test_job",
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
            "minimum_assurance_by_job_type": {"windows_attestation_test_job": "E1"}
        }
    })
}

fn plan_value(contract: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.windows-attestation.0001",
        "created_at": "2026-07-25T16:00:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.windows-attestation-test",
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
        "bundle_id": "bundle.windows-attestation.0001",
        "run_id": "run.windows-attestation.0001",
        "created_at": "2026-07-25T16:05:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.windows-attestation-test",
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
            "os": "windows-test",
            "kernel_version": "ergaxiom-proof-kernel/0.1.0",
            "applications": [{
                "id": "test-application",
                "version": "1.0.0",
                "digest": "application-digest"
            }],
            "clock_source": "trusted-test-clock",
            "sandbox_id": "sandbox-windows-attestation"
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
            "trace_id": "trace.windows-attestation.0001",
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
        nonce: "windows-attestation-nonce-0001".to_owned(),
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

fn initialized_public_key(response: SignerResponse) -> Result<[u8; 32], Box<dyn Error>> {
    match response {
        SignerResponse::Success {
            result: SignerSuccess::KeyInitialized { public_key_hex, .. },
            ..
        } => Ok(decode_hex_32(&public_key_hex)?),
        _ => Err("signer did not initialize the attestation key".into()),
    }
}

fn draft() -> AttestationCertificateDraft {
    AttestationCertificateDraft {
        manifest_id: "manifest.windows-attestation.0001".to_owned(),
        certificate_id: "certificate.windows-attestation.0001".to_owned(),
        issued_at_epoch_s: 2_050,
    }
}

#[test]
fn real_dpapi_signer_issues_and_governs_acceptance_certificate() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("real-process")?;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_ergaxiom-windows-signer"));
    let client = SignerProcessClient::isolated_test(executable, directory.path())?;
    let initialized = client.invoke(&SignerRequest::initialize_key(
        "attestation.initialize.windows.0001",
        IssuerRole::Attestation,
        ATTESTATION_ISSUER_ID,
        ATTESTATION_KEY_ID,
    ))?;
    let public_key = initialized_public_key(initialized)?;

    let context = context()?;
    let certificate_draft = draft();
    let authority = AttestationIssuanceAuthority::new(client.clone(), public_key);
    let package = authority.issue(
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        certificate_draft.clone(),
    )?;
    assert!(!package.certificate.signer_response.contains_private_material_field());

    let mut trusted = AttestationKeyRegistry::default();
    trusted.insert_ed25519(ATTESTATION_ISSUER_ID, ATTESTATION_KEY_ID, public_key)?;
    verify_signer_bound_attestation_against_bundle(
        &package,
        &trusted,
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
    )?;

    let mut governed = GovernedVerificationRuntime::default();
    governed.insert_attestation_key(
        ATTESTATION_ISSUER_ID,
        ATTESTATION_KEY_ID,
        public_key,
        0,
        3_000,
    )?;
    governed.verify_signer_bound_attestation_package_against_bundle(
        &package,
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
    )?;

    let revision = governed.registry_revision();
    let registry_digest = governed.registry_digest()?;
    governed.revoke_key_guarded(
        revision,
        &registry_digest,
        IssuerRole::Attestation,
        ATTESTATION_ISSUER_ID,
        ATTESTATION_KEY_ID,
        2_051,
        &"a".repeat(64),
    )?;
    assert!(matches!(
        governed.verify_signer_bound_attestation_package(&package),
        Err(GovernedVerificationError::KeyGovernance(
            KeyGovernanceError::KeyRevoked
        ))
    ));

    assert!(matches!(
        authority.issue(
            context.contract,
            &context.plan,
            &context.bundle,
            AssuranceLevel::E1,
            certificate_draft,
        ),
        Err(AttestationIssuanceError::SignerClient(
            SignerClientError::SignerRejected(code)
        )) if code == "REQUEST_REPLAYED"
    ));
    Ok(())
}
