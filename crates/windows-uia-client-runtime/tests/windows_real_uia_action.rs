#![cfg(windows)]

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_capability_runtime::{
    CapabilityAuthorizer, CapabilityBindings, CapabilityGrant, CapabilitySubject,
    CapabilityTokenPayload, SignatureAlgorithm, SignatureEncoding, SignedCapabilityToken,
    TokenSignature, TrustedKeyRegistry,
};
use ergaxiom_contract_runtime::{CompiledContract, PermissionAccess, compile_contract};
use ergaxiom_execution_runtime::AuthorizationReceiptRecord;
use ergaxiom_operator_plan_runtime::{CompiledPlan, compile_plan};
use ergaxiom_proof_kernel::{canonical_json_bytes, canonical_json_sha256};
use ergaxiom_windows_bridge_runtime::{
    WindowsApplicationIdentity, WindowsBridgeAction, WindowsBridgeExecutionContext,
    WindowsBridgeKeyRegistry, WindowsBridgeRequest, WindowsBridgeStatus, WindowsControlMethod,
    WindowsStateAssertion, WindowsTargetSelector, execute_windows_bridge,
    verify_windows_bridge_package,
};
use ergaxiom_windows_uia_client_runtime::{ChildJsonLineTransport, WindowsUiaClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CONTRACT_SOURCE: &str =
    include_str!("../../../examples/work-contracts/social-media-static-post.json");
const CAPSULE_SOURCE: &str = include_str!("../../../professions/graphic-designer/profession.json");
const POLICY_ISSUER: &str = "ergaxiom.policy-authority";
const POLICY_KEY_ID: &str = "windows-real-uia-policy-key";
const BRIDGE_ISSUER: &str = "ergaxiom.windows-bridge-authority";
const BRIDGE_KEY_ID: &str = "windows-real-uia-bridge-key";
const EXECUTOR_ID: &str = "executor.windows-real-uia-test";
const DEVICE_ID: &str = "device.windows-real-uia-test";
const NOW: u64 = 5_000;
const READY_TIMEOUT: Duration = Duration::from_secs(20);

struct Context {
    contract: CompiledContract,
    plan: CompiledPlan,
    authorization: AuthorizationReceiptRecord,
    bridge_key: SigningKey,
}

struct TargetProcess {
    child: Child,
    ready_file: PathBuf,
}

impl Drop for TargetProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.ready_file);
    }
}

#[test]
fn real_uia_set_value_is_signed_and_independently_verified() -> Result<(), Box<dyn Error>> {
    let context = context()?;
    let host_path = env::var("ERGAXIOM_WINDOWS_UIA_HOST")?;
    let host_digest = env::var("ERGAXIOM_WINDOWS_UIA_HOST_SHA256")?;
    let target_path = PathBuf::from(env::var("ERGAXIOM_WINDOWS_UIA_TARGET")?);
    let target_application_id = env::var("ERGAXIOM_WINDOWS_UIA_TARGET_APPLICATION_ID")?;
    let target_version = env::var("ERGAXIOM_WINDOWS_UIA_TARGET_VERSION")?;
    let target_digest = sha256_file(&target_path)?;
    let target = spawn_target(&target_path)?;

    let mut request = request(
        &context,
        WindowsApplicationIdentity {
            application_id: target_application_id,
            version: target_version,
            executable_digest: target_digest,
            instance_id: format!("pid:{}", target.child.id()),
        },
    );
    let transport = ChildJsonLineTransport::spawn(host_path, &host_digest)?;
    let mut client = WindowsUiaClient::new(transport);
    let primed = client.prime(&request)?;
    assert_eq!(
        primed.properties.get("value").map(String::as_str),
        Some("BEFORE")
    );
    request.expected_pre_state_digest = primed.state_digest.clone();

    let package = execute_windows_bridge(
        &mut client,
        WindowsBridgeExecutionContext {
            compiled_contract: &context.contract,
            compiled_plan: &context.plan,
            signing_key: &context.bridge_key,
            issuer_id: BRIDGE_ISSUER,
            key_id: BRIDGE_KEY_ID,
            record_id: "record.windows-real-uia-test.0001",
            recorded_at_epoch_ms: 6_000,
        },
        request,
        context.authorization.clone(),
    )?;

    assert_eq!(
        package.record.payload.status,
        WindowsBridgeStatus::Succeeded
    );
    assert!(package.record.payload.violations.is_empty());
    assert_eq!(
        package
            .pre_state
            .properties
            .get("value")
            .map(String::as_str),
        Some("BEFORE")
    );
    assert_eq!(
        package
            .post_state
            .properties
            .get("value")
            .map(String::as_str),
        Some("APPROVED")
    );

    let mut bridge_keys = WindowsBridgeKeyRegistry::default();
    bridge_keys.insert_ed25519(
        BRIDGE_ISSUER,
        BRIDGE_KEY_ID,
        context.bridge_key.verifying_key().to_bytes(),
    )?;
    let verified =
        verify_windows_bridge_package(&package, &bridge_keys, &context.contract, &context.plan)?;
    assert_eq!(verified.status, WindowsBridgeStatus::Succeeded);
    assert_eq!(verified.pre_state_digest, primed.state_digest);
    Ok(())
}

fn context() -> Result<Context, Box<dyn Error>> {
    let contract_value: Value = serde_json::from_str(CONTRACT_SOURCE)?;
    let capsule_value: Value = serde_json::from_str(CAPSULE_SOURCE)?;
    let contract = compile_contract(&contract_value, &capsule_value)?;
    let plan = compile_plan(&plan_value(&contract), &capsule_value, &contract)?;
    let policy_key = SigningKey::from_bytes(&[83_u8; 32]);
    let token = signed_token(&contract, &plan, &policy_key)?;
    let mut policy_keys = TrustedKeyRegistry::default();
    policy_keys.insert_ed25519(
        POLICY_ISSUER,
        POLICY_KEY_ID,
        policy_key.verifying_key().to_bytes(),
    )?;
    let mut authorizer = CapabilityAuthorizer::new(policy_keys);
    let receipt =
        authorizer.authorize(&token, &contract, &plan, NOW, EXECUTOR_ID, Some(DEVICE_ID))?;
    let receipt_value = serde_json::to_value(&receipt)?;
    Ok(Context {
        contract,
        plan,
        authorization: AuthorizationReceiptRecord {
            receipt_digest: canonical_json_sha256(&receipt_value)?,
            receipt,
        },
        bridge_key: SigningKey::from_bytes(&[97_u8; 32]),
    })
}

fn plan_value(contract: &CompiledContract) -> Value {
    json!({
        "schema_version": "0.1.0",
        "plan_id": "plan.windows-real-uia-test.0001",
        "created_at": "2026-07-22T00:00:00Z",
        "bindings": {
            "contract": {
                "id": contract.contract_id,
                "algorithm": "sha256",
                "digest": contract.seal.contract_digest
            },
            "profession_capsule": {
                "id": "ergaxiom.profession.graphic-designer",
                "algorithm": "sha256",
                "digest": contract.seal.capsule_digest
            }
        },
        "steps": [{
            "step_id": "step.text",
            "sequence": 0,
            "operator_id": "design.compose_text",
            "operator_version": "0.1.0",
            "depends_on": [],
            "input_artifact_ids": [],
            "output_artifact_ids": [],
            "capability_token_ids": ["token.text.real-uia"],
            "mandatory": true,
            "rollback_step_id": null
        }]
    })
}

fn signed_token(
    contract: &CompiledContract,
    plan: &CompiledPlan,
    signing_key: &SigningKey,
) -> Result<Value, Box<dyn Error>> {
    let payload = CapabilityTokenPayload {
        schema_version: "0.1.0".to_owned(),
        token_id: "token.text.real-uia".to_owned(),
        issuer_id: POLICY_ISSUER.to_owned(),
        key_id: POLICY_KEY_ID.to_owned(),
        subject: CapabilitySubject {
            executor_id: EXECUTOR_ID.to_owned(),
            device_id: Some(DEVICE_ID.to_owned()),
        },
        issued_at_epoch_s: NOW - 100,
        not_before_epoch_s: NOW - 50,
        expires_at_epoch_s: NOW + 100,
        max_uses: 1,
        nonce: "windows-real-uia-nonce-0001".to_owned(),
        bindings: CapabilityBindings {
            contract_digest: contract.seal.contract_digest.clone(),
            capsule_digest: contract.seal.capsule_digest.clone(),
            plan_id: plan.plan_id.clone(),
            plan_digest: plan.plan_digest.clone(),
            step_id: "step.text".to_owned(),
            operator_id: "design.compose_text".to_owned(),
        },
        grant: design_editor_grant(),
    };
    let payload_value = serde_json::to_value(&payload)?;
    let signature = signing_key.sign(&canonical_json_bytes(&payload_value)?);
    Ok(serde_json::to_value(SignedCapabilityToken {
        payload,
        signature: TokenSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            encoding: SignatureEncoding::Base64url,
            value: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    })?)
}

fn request(context: &Context, application: WindowsApplicationIdentity) -> WindowsBridgeRequest {
    WindowsBridgeRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.windows-real-uia-test.0001".to_owned(),
        bridge_id: "bridge.windows-uia-host".to_owned(),
        plan_id: context.plan.plan_id.clone(),
        plan_digest: context.plan.plan_digest.clone(),
        step_id: "step.text".to_owned(),
        operator_id: "design.compose_text".to_owned(),
        executor_id: EXECUTOR_ID.to_owned(),
        device_id: Some(DEVICE_ID.to_owned()),
        control_method: WindowsControlMethod::UiAutomation,
        application,
        selector: WindowsTargetSelector::UiAutomation {
            automation_id: "copy-field".to_owned(),
            control_type: "Edit".to_owned(),
        },
        action: WindowsBridgeAction::SetValue {
            value: "APPROVED".to_owned(),
        },
        required_grant: design_editor_grant(),
        expected_pre_state_digest: "unprimed".to_owned(),
        postconditions: vec![WindowsStateAssertion::PropertyEquals {
            key: "value".to_owned(),
            value: "APPROVED".to_owned(),
        }],
        authorization_receipt_digest: context.authorization.receipt_digest.clone(),
    }
}

fn design_editor_grant() -> CapabilityGrant {
    CapabilityGrant {
        capability: "design-editor".to_owned(),
        resource: "isolated-workspace".to_owned(),
        access: PermissionAccess::Control,
        constraints: json!({"network": false}),
    }
}

fn spawn_target(target_path: &Path) -> Result<TargetProcess, Box<dyn Error>> {
    let ready_file = unique_ready_file()?;
    let _ = fs::remove_file(&ready_file);
    let mut child = Command::new(target_path)
        .arg("--ready-file")
        .arg(&ready_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    wait_until_ready(&mut child, &ready_file)?;
    Ok(TargetProcess { child, ready_file })
}

fn wait_until_ready(child: &mut Child, ready_file: &Path) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    loop {
        if ready_file.is_file() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!("WPF UIA test target exited before readiness: {status}").into());
        }
        if started.elapsed() >= READY_TIMEOUT {
            return Err("WPF UIA test target readiness timed out".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn unique_ready_file() -> Result<PathBuf, Box<dyn Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(env::temp_dir().join(format!(
        "ergaxiom-windows-uia-ready-{}-{nonce}.txt",
        std::process::id()
    )))
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}
