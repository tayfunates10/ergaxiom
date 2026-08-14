#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use ergaxiom_contract_runtime::{WorkContract, compile_contract};
use ergaxiom_operator_plan_runtime::compile_plan;
use ergaxiom_production_execution_runtime::{
    ProductionExecutionChainStore, ProductionExecutionStage, verify_recovered_certified_chain,
};
use ergaxiom_proof_kernel::{AssuranceLevel, canonical_json_sha256};
use ergaxiom_windows_production_trust_state_runtime::{
    DeployedProductionSignerIdentityProof, ProductionSignerDeploymentPolicy,
    ProductionSignerIdentityChallenge, ProductionTrustStateEnvelope, TrustGovernancePolicy,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const VERIFIER_SCHEMA: &str = "0.1.0";
const VERIFIER_ID: &str = "ergaxiom.production-release-chain-verifier";

fn main() {
    if let Err(error) = run() {
        eprintln!("production release chain verification failed: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    let repo_root = absolute_dir(required(&args, "repo-root")?, "repo-root")?;
    let chain_root = absolute_existing_chain_root(required(&args, "chain-root")?)?;
    let output = absolute_output(required(&args, "output")?)?;
    let source_commit = required(&args, "source-commit")?;
    require_lower_hex(source_commit, 40, "source-commit")?;
    verify_checkout(&repo_root, source_commit)?;

    let service_sha256 = required(&args, "expected-signed-service-sha256")?;
    require_lower_hex(service_sha256, 64, "expected-signed-service-sha256")?;
    let job_id = required(&args, "job-id")?;
    let trusted_now_epoch_s = required(&args, "trusted-now-epoch-s")?.parse::<u64>()?;
    if trusted_now_epoch_s == 0 {
        return Err("trusted-now-epoch-s must be positive".into());
    }
    let expected_executor_id = required(&args, "expected-executor-id")?;
    let expected_device_id = args.get("expected-device-id").map(String::as_str);
    let assurance = assurance_level(required(&args, "assurance-level")?)?;

    let governance: TrustGovernancePolicy = read_json_arg(&args, "governance-policy")?;
    governance.validate_seal()?;
    let envelope: ProductionTrustStateEnvelope = read_json_arg(&args, "trust-state-envelope")?;
    let accepted = envelope.verify(&governance, trusted_now_epoch_s)?;
    if accepted.binding().signer_service_executable_digest != service_sha256 {
        return Err(
            "accepted trust state signer-service digest does not match signed release artifact"
                .into(),
        );
    }

    let deployment: ProductionSignerDeploymentPolicy = read_json_arg(&args, "deployment-policy")?;
    deployment.validate_seal()?;
    let challenge: ProductionSignerIdentityChallenge = read_json_arg(&args, "identity-challenge")?;
    let proof: DeployedProductionSignerIdentityProof = read_json_arg(&args, "identity-proof")?;
    let lease = proof.verify_trust_lease(
        &challenge,
        &accepted,
        &deployment,
        trusted_now_epoch_s,
    )?;
    if lease.service_identity().executable_sha256 != service_sha256 {
        return Err("live signer identity digest does not match signed release artifact".into());
    }

    // The legacy flag names are retained for the release-runner CLI contract, but these are raw
    // canonical Work Contract and Operator Plan JSON documents. The verifier independently resolves
    // the profession capsule from the exact checked-out catalog and recompiles both objects.
    let work_contract_value = read_json_value_arg(&args, "compiled-contract")?;
    let operator_plan_value = read_json_value_arg(&args, "compiled-plan")?;
    let work_contract: WorkContract = serde_json::from_value(work_contract_value.clone())?;
    let profession_capsule = resolve_profession_capsule(&repo_root, &work_contract)?;
    let compiled_contract = compile_contract(&work_contract_value, &profession_capsule)?;
    let compiled_plan = compile_plan(
        &operator_plan_value,
        &profession_capsule,
        &compiled_contract,
    )?;

    let store = ProductionExecutionChainStore::load_or_create(&chain_root, job_id)?;
    let state = store.current();
    if state.stage != ProductionExecutionStage::Certified {
        return Err(format!(
            "release requires certified production chain, observed {:?}",
            state.stage
        )
        .into());
    }

    let verified = verify_recovered_certified_chain(
        state,
        &lease,
        &accepted,
        &deployment,
        trusted_now_epoch_s,
        compiled_contract,
        &compiled_plan,
        assurance,
        expected_executor_id,
        expected_device_id,
    )?;

    let input_digests = json!({
        "compiled_contract": canonical_json_sha256(&json!({
            "profession_capsule": &profession_capsule,
            "work_contract": &work_contract_value,
        }))?,
        "compiled_plan": canonical_json_sha256(&json!({
            "operator_plan": &operator_plan_value,
            "profession_capsule": &profession_capsule,
        }))?,
        "deployment_policy": digest(&deployment)?,
        "governance_policy": digest(&governance)?,
        "identity_challenge": digest(&challenge)?,
        "identity_proof": digest(&proof)?,
        "trust_state_envelope": digest(&envelope)?,
    });
    let mut result = json!({
        "schema_version": VERIFIER_SCHEMA,
        "verifier_id": VERIFIER_ID,
        "gate": "PRODUCTION_CHAIN_VERIFIED",
        "verified": true,
        "source_commit": source_commit,
        "job_id": state.job_id,
        "chain_stage": "certified",
        "chain_revision": state.revision,
        "chain_state_digest": state.state_digest,
        "signer_service_sha256": service_sha256,
        "trust_state_binding_digest": accepted.binding().binding_digest,
        "signer_identity_proof_digest": lease.proof_digest(),
        "certificate_id": verified.certificate_id,
        "certificate_digest": verified.certificate_digest,
        "replay_manifest_digest": verified.replay_manifest_digest,
        "evidence_bundle_digest": verified.evidence_bundle_digest,
        "decision": verified.decision,
        "assurance_level": verified.assurance_level,
        "input_digests": input_digests,
        "verification_digest": "",
    });
    let verification_digest = canonical_json_sha256(&result)?;
    result["verification_digest"] = Value::String(verification_digest);
    write_create_new(&output, &result)?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn resolve_profession_capsule(
    repo_root: &Path,
    contract: &WorkContract,
) -> Result<Value, Box<dyn std::error::Error>> {
    let catalog_path = repo_root.join("professions").join("catalog.json");
    let catalog = read_bounded_json_file(&catalog_path, "profession catalog")?;
    if catalog.get("schema_version") != Some(&Value::String("0.1.0".to_owned()))
        || catalog.get("catalog_id")
            != Some(&Value::String("ergaxiom.profession-catalog".to_owned()))
    {
        return Err("profession catalog identity rejected".into());
    }
    let entries = catalog
        .get("entries")
        .and_then(Value::as_array)
        .ok_or("profession catalog entries missing")?;
    let matching: Vec<&Value> = entries
        .iter()
        .filter(|entry| {
            entry.get("capsule_id").and_then(Value::as_str)
                == Some(contract.profession.capsule_id.as_str())
                && entry.get("capsule_version").and_then(Value::as_str)
                    == Some(contract.profession.capsule_version.as_str())
        })
        .collect();
    if matching.len() != 1 {
        return Err("profession capsule catalog cardinality rejected".into());
    }
    let entry = matching[0];
    let relative = entry
        .get("capsule_path")
        .and_then(Value::as_str)
        .ok_or("profession capsule path missing")?;
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("profession capsule path rejected".into());
    }
    let capsule_path = repo_root.join("professions").join(relative_path);
    let capsule = read_bounded_json_file(&capsule_path, "profession capsule")?;
    let expected_digest = entry
        .get("capsule_digest")
        .and_then(Value::as_str)
        .ok_or("profession capsule digest missing")?;
    require_lower_hex(expected_digest, 64, "profession capsule digest")?;
    if canonical_json_sha256(&capsule)? != expected_digest {
        return Err("profession capsule catalog digest mismatch".into());
    }
    Ok(capsule)
}

fn parse_args() -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.len() % 2 != 0 {
        return Err("every verifier flag requires one value".into());
    }
    let mut result = BTreeMap::new();
    for pair in raw.chunks_exact(2) {
        let flag = pair[0]
            .strip_prefix("--")
            .ok_or("unexpected positional argument")?;
        if !matches!(
            flag,
            "repo-root"
                | "chain-root"
                | "job-id"
                | "governance-policy"
                | "trust-state-envelope"
                | "deployment-policy"
                | "identity-challenge"
                | "identity-proof"
                | "compiled-contract"
                | "compiled-plan"
                | "assurance-level"
                | "expected-executor-id"
                | "expected-device-id"
                | "trusted-now-epoch-s"
                | "source-commit"
                | "expected-signed-service-sha256"
                | "output"
        ) {
            return Err(format!("unknown verifier flag: --{flag}").into());
        }
        if result.insert(flag.to_owned(), pair[1].clone()).is_some() {
            return Err(format!("duplicate verifier flag: --{flag}").into());
        }
    }
    Ok(result)
}

fn required<'a>(
    args: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    args.get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing --{name}").into())
}

fn read_json_arg<T: DeserializeOwned>(
    args: &BTreeMap<String, String>,
    name: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(read_json_value_arg(args, name)?)?)
}

fn read_json_value_arg(
    args: &BTreeMap<String, String>,
    name: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let path = absolute_file(required(args, name)?, name)?;
    read_bounded_json_file(&path, name)
}

fn read_bounded_json_file(
    path: &Path,
    label: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_INPUT_BYTES
    {
        return Err(format!("{label} is not a bounded regular file").into());
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("{label} size is invalid").into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn absolute_file(value: &str, label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(value);
    if !path.is_absolute() || !path.is_file() {
        return Err(format!("{label} must be an existing absolute file").into());
    }
    Ok(path)
}

fn absolute_dir(value: &str, label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(value);
    let metadata = fs::symlink_metadata(&path)?;
    if !path.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} must be an existing non-symlink absolute directory").into());
    }
    Ok(path)
}

fn absolute_existing_chain_root(value: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = absolute_dir(value, "chain-root")?;
    let mut records = 0usize;
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err("chain-root contains non-UTF8 entry".into());
        };
        if name.starts_with("production-execution-state-") && name.ends_with(".json") {
            records = records.saturating_add(1);
        }
    }
    if records == 0 {
        return Err("chain-root contains no persisted production execution records".into());
    }
    Ok(root)
}

fn absolute_output(value: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(value);
    if !path.is_absolute() || path.exists() {
        return Err("output must be a new absolute path".into());
    }
    let parent = path.parent().ok_or("output parent missing")?;
    if !parent.is_dir() {
        return Err("output parent must already exist".into());
    }
    Ok(path)
}

fn verify_checkout(repo_root: &Path, expected: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !output.status.success() {
        return Err("git rev-parse HEAD failed".into());
    }
    let actual = String::from_utf8(output.stdout)?.trim().to_owned();
    if actual != expected {
        return Err(format!("source checkout mismatch: expected={expected} actual={actual}").into());
    }
    Ok(())
}

fn require_lower_hex(
    value: &str,
    len: usize,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value.len() != len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be {len} lowercase hex characters").into());
    }
    Ok(())
}

fn assurance_level(value: &str) -> Result<AssuranceLevel, Box<dyn std::error::Error>> {
    Ok(match value {
        "E0" => AssuranceLevel::E0,
        "E1" => AssuranceLevel::E1,
        "E2" => AssuranceLevel::E2,
        "E3" => AssuranceLevel::E3,
        "E4" => AssuranceLevel::E4,
        "E5" => AssuranceLevel::E5,
        _ => return Err("assurance-level must be E0..E5".into()),
    })
}

fn digest<T: serde::Serialize>(value: &T) -> Result<String, Box<dyn std::error::Error>> {
    Ok(canonical_json_sha256(&serde_json::to_value(value)?)?)
}

fn write_create_new(path: &Path, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(serde_json::to_string_pretty(value)?.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
