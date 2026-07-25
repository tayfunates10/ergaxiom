#![cfg(windows)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_capability_issuance_runtime::{
    CAPABILITY_ISSUER_ID, CAPABILITY_KEY_ID, CapabilityIssuanceAuthority,
    CapabilityIssuanceError, CapabilityTokenDraft,
};
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_governed_verification_runtime::{
    GovernedVerificationError, GovernedVerificationRuntime,
};
use ergaxiom_key_governance_runtime::{IssuerRole, KeyGovernanceError};
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_windows_signer_client_runtime::{SignerClientError, SignerProcessClient};
use ergaxiom_windows_signer_protocol_runtime::{
    SignerRequest, SignerResponse, SignerSuccess, decode_hex_32,
};
use serde_json::{Value, json};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");
const EXECUTOR_ID: &str = "executor.windows.capability.0001";
const DEVICE_ID: &str = "device.windows.capability.0001";
const NOW: u64 = 1_000;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create(name: &str) -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ergaxiom-capability-issuance-{name}-{}-{counter}-{nonce}",
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
}

fn context() -> Result<Context, Box<dyn Error>> {
    let contract_value: Value = serde_json::from_str(CONTRACT_SOURCE)?;
    let capsule_value: Value = serde_json::from_str(CAPSULE_SOURCE)?;
    let contract = compile_contract(&contract_value, &capsule_value)?;
    let plan = compile_plan(&plan_value(&contract), &capsule_value, &contract)?;
    Ok(Context { contract, plan })
}

fn plan_value(compiled: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.windows.capability.0001",
        "created_at": "2026-07-25T14:00:00Z",
        "bindings": {
            "contract": {
                "id": compiled.contract_id,
                "algorithm": "sha256",
                "digest": compiled.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.graphic-designer",
                "algorithm": "sha256",
                "digest": compiled.seal.capsule_digest
            }
        },
        "steps": [
            step("step.canvas", 0, "design.create_canvas", &[], "token.canvas"),
            step(
                "step.logo",
                1,
                "design.place_asset",
                &["step.canvas"],
                "token.windows.capability.0001"
            ),
            step(
                "step.text",
                2,
                "design.compose_text",
                &["step.logo"],
                "token.text"
            ),
            step(
                "step.export",
                3,
                "design.export_raster",
                &["step.text"],
                "token.export"
            )
        ]
    })
}

fn step(
    step_id: &str,
    sequence: usize,
    operator_id: &str,
    depends_on: &[&str],
    token_id: &str,
) -> Value {
    json!({
        "step_id": step_id,
        "sequence": sequence,
        "operator_id": operator_id,
        "operator_version": "0.1.0",
        "depends_on": depends_on,
        "input_artifact_ids": [],
        "output_artifact_ids": [],
        "capability_token_ids": [token_id],
        "mandatory": true,
        "rollback_step_id": null
    })
}

fn draft(context: &Context) -> CapabilityTokenDraft {
    CapabilityTokenDraft {
        token_id: "token.windows.capability.0001".to_owned(),
        subject: CapabilitySubject {
            executor_id: EXECUTOR_ID.to_owned(),
            device_id: Some(DEVICE_ID.to_owned()),
        },
        issued_at_epoch_s: 900,
        not_before_epoch_s: 950,
        expires_at_epoch_s: 1_100,
        max_uses: 1,
        nonce: "nonce-windows-capability-0001".to_owned(),
        bindings: CapabilityBindings {
            contract_digest: context.contract.seal.contract_digest.clone(),
            capsule_digest: context.contract.seal.capsule_digest.clone(),
            plan_id: context.plan.plan_id.clone(),
            plan_digest: context.plan.plan_digest.clone(),
            step_id: "step.logo".to_owned(),
            operator_id: "design.place_asset".to_owned(),
        },
        grant: CapabilityGrant {
            capability: "filesystem".to_owned(),
            resource: "contract://inputs/*".to_owned(),
            access: PermissionAccess::Read,
            constraints: json!({"immutable": true}),
        },
    }
}

fn initialized_public_key(response: SignerResponse) -> Result<[u8; 32], Box<dyn Error>> {
    match response {
        SignerResponse::Success {
            result: SignerSuccess::KeyInitialized { public_key_hex, .. },
            ..
        } => Ok(decode_hex_32(&public_key_hex)?),
        _ => Err("signer did not initialize the capability key".into()),
    }
}

#[test]
fn real_dpapi_signer_issues_and_governs_purpose_locked_capability()
-> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("real-process")?;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_ergaxiom-windows-signer"));
    let client = SignerProcessClient::isolated_test(executable, directory.path())?;
    let initialized = client.invoke(&SignerRequest::initialize_key(
        "capability.initialize.windows.0001",
        IssuerRole::Capability,
        CAPABILITY_ISSUER_ID,
        CAPABILITY_KEY_ID,
    ))?;
    let public_key = initialized_public_key(initialized)?;

    let context = context()?;
    let token_draft = draft(&context);
    let authority = CapabilityIssuanceAuthority::new(client.clone(), public_key);
    let token = authority.issue(token_draft.clone())?;
    let token_value = serde_json::to_value(&token)?;

    let mut trusted_keys = TrustedKeyRegistry::default();
    trusted_keys.insert_ed25519(CAPABILITY_ISSUER_ID, CAPABILITY_KEY_ID, public_key)?;
    let mut legacy_authorizer = CapabilityAuthorizer::new(trusted_keys);
    let receipt = legacy_authorizer.authorize_signer_bound(
        &token_value,
        &context.contract,
        &context.plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?;
    assert_eq!(receipt.token_id, token_draft.token_id);
    assert_eq!(receipt.step_id, "step.logo");

    let mut governed = GovernedVerificationRuntime::default();
    governed.insert_capability_key(
        CAPABILITY_ISSUER_ID,
        CAPABILITY_KEY_ID,
        public_key,
        0,
        2_000,
    )?;
    governed.authorize_signer_bound_capability(
        &token_value,
        &context.contract,
        &context.plan,
        NOW,
        EXECUTOR_ID,
        Some(DEVICE_ID),
    )?;

    let revision = governed.registry_revision();
    let registry_digest = governed.registry_digest()?;
    governed.revoke_key_guarded(
        revision,
        &registry_digest,
        IssuerRole::Capability,
        CAPABILITY_ISSUER_ID,
        CAPABILITY_KEY_ID,
        1_001,
        &"e".repeat(64),
    )?;
    assert!(matches!(
        governed.verify_signer_bound_capability_token_signature(&token_value),
        Err(GovernedVerificationError::KeyGovernance(
            KeyGovernanceError::KeyRevoked
        ))
    ));

    assert!(matches!(
        authority.issue(token_draft),
        Err(CapabilityIssuanceError::SignerClient(
            SignerClientError::SignerRejected(code)
        )) if code == "REQUEST_REPLAYED"
    ));
    Ok(())
}
