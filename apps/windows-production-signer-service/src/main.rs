use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_windows_production_deployment_evidence_runtime::{
    DeploymentEvidencePolicy, SignedProductionSignerInstallationEvidence,
    SignedProductionSignerRecoveryEvidence,
};
use ergaxiom_windows_production_signer_host_runtime::{
    LoadedProductionSignerHostConfig, ProductionSignerInstallationValidationReceipt,
    ProductionSignerRecoveryExerciseReceipt, ProductionSignerServiceManifest, install_service,
    run_service_dispatcher, uninstall_service, validate_installed_service,
};
use serde::de::DeserializeOwned;

const MAX_EVIDENCE_BYTES: u64 = 16 * 1024 * 1024;

fn main() {
    let exit_code = match execute() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("production signer service command failed: {error}");
            2
        }
    };
    std::process::exit(exit_code);
}

fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [command, manifest_flag, manifest]
            if command == "--service" && manifest_flag == "--manifest" =>
        {
            run_service_dispatcher(require_absolute(manifest)?)?;
        }
        [command, manifest_flag, manifest]
            if command == "--install" && manifest_flag == "--manifest" =>
        {
            install_service(&require_absolute(manifest)?, trusted_now_epoch_s()?)?;
        }
        [command, manifest_flag, manifest]
            if command == "--validate" && manifest_flag == "--manifest" =>
        {
            let manifest = require_absolute(manifest)?;
            LoadedProductionSignerHostConfig::load(&manifest, trusted_now_epoch_s()?)?;
            validate_installed_service(&manifest, trusted_now_epoch_s()?)?;
        }
        [command, manifest_flag, manifest]
            if command == "--uninstall" && manifest_flag == "--manifest" =>
        {
            uninstall_service(&require_absolute(manifest)?)?;
        }
        [
            command,
            manifest_flag,
            manifest,
            ceremony_flag,
            ceremony_id,
            output_flag,
            output,
        ] if command == "--capture-installation"
            && manifest_flag == "--manifest"
            && ceremony_flag == "--ceremony-id"
            && output_flag == "--output" =>
        {
            let receipt = ProductionSignerInstallationValidationReceipt::capture_live(
                &require_absolute(manifest)?,
                ceremony_id,
                trusted_now_epoch_s()?,
            )?;
            receipt.write_create_new(&require_absolute(output)?)?;
        }
        [
            command,
            manifest_flag,
            manifest,
            exercise_flag,
            exercise_id,
            output_flag,
            output,
        ] if command == "--exercise-recovery"
            && manifest_flag == "--manifest"
            && exercise_flag == "--exercise-id"
            && output_flag == "--output" =>
        {
            let receipt = ProductionSignerRecoveryExerciseReceipt::execute_live(
                &require_absolute(manifest)?,
                exercise_id,
                trusted_now_epoch_s()?,
            )?;
            receipt.write_create_new(&require_absolute(output)?)?;
        }
        [command, receipt_flag, receipt]
            if command == "--verify-installation-receipt" && receipt_flag == "--receipt" =>
        {
            let receipt: ProductionSignerInstallationValidationReceipt =
                read_json(&require_absolute(receipt)?)?;
            receipt.validate_seal()?;
        }
        [command, receipt_flag, receipt]
            if command == "--verify-recovery-receipt" && receipt_flag == "--receipt" =>
        {
            let receipt: ProductionSignerRecoveryExerciseReceipt =
                read_json(&require_absolute(receipt)?)?;
            receipt.validate_seal()?;
        }
        [
            command,
            evidence_flag,
            evidence,
            policy_flag,
            policy,
            manifest_flag,
            manifest,
        ] if command == "--verify-signed-installation-evidence"
            && evidence_flag == "--evidence"
            && policy_flag == "--evidence-policy"
            && manifest_flag == "--manifest" =>
        {
            let evidence: SignedProductionSignerInstallationEvidence =
                read_json(&require_absolute(evidence)?)?;
            let policy: DeploymentEvidencePolicy = read_json(&require_absolute(policy)?)?;
            let loaded = LoadedProductionSignerHostConfig::load(
                &require_absolute(manifest)?,
                trusted_now_epoch_s()?,
            )?;
            evidence.verify(
                &policy,
                &loaded.governance_policy,
                &loaded.accepted,
                trusted_now_epoch_s()?,
            )?;
        }
        [
            command,
            evidence_flag,
            evidence,
            policy_flag,
            policy,
            manifest_flag,
            manifest,
        ] if command == "--verify-signed-recovery-evidence"
            && evidence_flag == "--evidence"
            && policy_flag == "--evidence-policy"
            && manifest_flag == "--manifest" =>
        {
            let evidence: SignedProductionSignerRecoveryEvidence =
                read_json(&require_absolute(evidence)?)?;
            let policy: DeploymentEvidencePolicy = read_json(&require_absolute(policy)?)?;
            let loaded = LoadedProductionSignerHostConfig::load(
                &require_absolute(manifest)?,
                trusted_now_epoch_s()?,
            )?;
            evidence.verify(
                &policy,
                &loaded.governance_policy,
                &loaded.accepted,
                trusted_now_epoch_s()?,
            )?;
        }
        [
            command,
            executable_flag,
            executable,
            trust_store_flag,
            trust_store,
            governance_flag,
            governance,
            allowlist_flag,
            allowlist,
            deployment_flag,
            deployment,
            pipe_sid_flag,
            pipe_sid,
            output_flag,
            output,
        ] if command == "--create-manifest"
            && executable_flag == "--executable"
            && trust_store_flag == "--trust-store"
            && governance_flag == "--governance-policy"
            && allowlist_flag == "--allowlist"
            && deployment_flag == "--deployment-policy"
            && pipe_sid_flag == "--pipe-sid"
            && output_flag == "--output" =>
        {
            let manifest = ProductionSignerServiceManifest::from_files(
                require_absolute(executable)?,
                require_absolute(trust_store)?,
                require_absolute(governance)?,
                require_absolute(allowlist)?,
                require_absolute(deployment)?,
                pipe_sid,
                trusted_now_epoch_s()?,
            )?;
            manifest.write_create_new(&require_absolute(output)?)?;
        }
        _ => return Err("COMMAND_LINE_REJECTED".into()),
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_EVIDENCE_BYTES
    {
        return Err("EVIDENCE_FILE_INVALID".into());
    }
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_EVIDENCE_BYTES {
        return Err("EVIDENCE_FILE_INVALID".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn require_absolute(value: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if value.is_empty() || value.contains('\0') || value.contains('"') {
        return Err("PATH_INVALID".into());
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err("PATH_NOT_ABSOLUTE".into());
    }
    Ok(path.to_path_buf())
}

fn trusted_now_epoch_s() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
