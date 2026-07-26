#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::fs::{OpenOptions, remove_file, rename};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_windows_cng_key_provider_runtime::CngPlatformKeyProvider;
use ergaxiom_windows_production_signer_provisioning_runtime::{
    ProvisioningAuthority, ProvisioningError, require_elevated_administrator,
};
use ergaxiom_windows_production_signer_runtime::ProductionKeyPolicy;
use thiserror::Error;

fn main() {
    if let Err(error) = run(env::args_os().skip(1)) {
        eprintln!("production signer provisioning failed: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), ProvisionerError> {
    let command = Command::parse(arguments)?;
    require_elevated_administrator()?;
    let policy = match command.role {
        IssuerRole::Capability => ProductionKeyPolicy::capability(),
        IssuerRole::Attestation => ProductionKeyPolicy::attestation(),
        IssuerRole::Execution | IssuerRole::Normalization | IssuerRole::Release => {
            return Err(ProvisionerError::UnsupportedRole)
        }
    };
    let provisioned_at_epoch_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProvisionerError::SystemClockBeforeEpoch)?
        .as_secs();
    if provisioned_at_epoch_s == 0 {
        return Err(ProvisionerError::SystemClockBeforeEpoch);
    }
    let authority = ProvisioningAuthority::new(CngPlatformKeyProvider::production());
    let evidence = authority.provision(
        &policy,
        command.expected_public_key_digest.as_deref(),
        provisioned_at_epoch_s,
    )?;
    evidence.verify_contract(&policy)?;
    write_new_json(&command.output, &evidence)?;
    println!("role={:?}", command.role);
    println!("created={}", evidence.statement.created);
    println!("public_key_digest={}", evidence.receipt.public_key_digest);
    println!("receipt_digest={}", evidence.receipt.receipt_digest);
    println!("evidence_digest={}", evidence.evidence_digest);
    Ok(())
}

#[derive(Debug)]
struct Command {
    role: IssuerRole,
    output: PathBuf,
    expected_public_key_digest: Option<String>,
}

impl Command {
    fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, ProvisionerError> {
        let mut arguments = arguments.into_iter();
        let mut role = None;
        let mut output = None;
        let mut expected_public_key_digest = None;
        while let Some(argument) = arguments.next() {
            let argument = argument
                .into_string()
                .map_err(|_| ProvisionerError::ArgumentNotUtf8)?;
            match argument.as_str() {
                "--role" => {
                    let value = next_utf8(&mut arguments, "--role")?;
                    role = Some(match value.as_str() {
                        "capability" => IssuerRole::Capability,
                        "attestation" => IssuerRole::Attestation,
                        _ => return Err(ProvisionerError::UnsupportedRole),
                    });
                }
                "--output" => {
                    output = Some(PathBuf::from(next_utf8(&mut arguments, "--output")?));
                }
                "--expected-public-key-digest" => {
                    expected_public_key_digest = Some(next_utf8(
                        &mut arguments,
                        "--expected-public-key-digest",
                    )?);
                }
                "--help" | "-h" => return Err(ProvisionerError::Usage),
                _ => return Err(ProvisionerError::UnknownArgument(argument)),
            }
        }
        let role = role.ok_or(ProvisionerError::MissingArgument("--role"))?;
        let output = output.ok_or(ProvisionerError::MissingArgument("--output"))?;
        validate_output_path(&output)?;
        Ok(Self {
            role,
            output,
            expected_public_key_digest,
        })
    }
}

fn next_utf8(
    arguments: &mut impl Iterator<Item = OsString>,
    name: &'static str,
) -> Result<String, ProvisionerError> {
    arguments
        .next()
        .ok_or(ProvisionerError::MissingArgument(name))?
        .into_string()
        .map_err(|_| ProvisionerError::ArgumentNotUtf8)
}

fn validate_output_path(path: &Path) -> Result<(), ProvisionerError> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(ProvisionerError::InvalidOutputPath);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let metadata = parent
        .metadata()
        .map_err(ProvisionerError::OutputDirectoryReadFailed)?;
    if !metadata.is_dir() {
        return Err(ProvisionerError::InvalidOutputPath);
    }
    if path.exists() {
        return Err(ProvisionerError::OutputAlreadyExists);
    }
    Ok(())
}

fn write_new_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), ProvisionerError> {
    validate_output_path(path)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(ProvisionerError::EvidenceSizeInvalid);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ProvisionerError::InvalidOutputPath)?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.provisioning.tmp",
        std::process::id()
    ));
    let write_result = (|| -> Result<(), ProvisionerError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(ProvisionerError::TemporaryFileCreateFailed)?;
        file.write_all(&bytes)
            .map_err(ProvisionerError::EvidenceWriteFailed)?;
        file.write_all(b"\n")
            .map_err(ProvisionerError::EvidenceWriteFailed)?;
        file.sync_all()
            .map_err(ProvisionerError::EvidenceSyncFailed)?;
        drop(file);
        if path.exists() {
            return Err(ProvisionerError::OutputAlreadyExists);
        }
        rename(&temporary, path).map_err(ProvisionerError::EvidenceRenameFailed)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = remove_file(&temporary);
    }
    write_result
}

#[derive(Debug, Error)]
enum ProvisionerError {
    #[error("usage: ergaxiom-windows-production-signer-provisioner --role capability|attestation --output <new-json-path> [--expected-public-key-digest <sha256>]")]
    Usage,
    #[error("command-line argument is not valid UTF-8")]
    ArgumentNotUtf8,
    #[error("required argument is missing: {0}")]
    MissingArgument(&'static str),
    #[error("unknown command-line argument: {0}")]
    UnknownArgument(String),
    #[error("only capability and attestation provisioning roles are supported")]
    UnsupportedRole,
    #[error("provisioning output path is invalid")]
    InvalidOutputPath,
    #[error("provisioning output already exists")]
    OutputAlreadyExists,
    #[error("provisioning output directory could not be read: {0}")]
    OutputDirectoryReadFailed(#[source] std::io::Error),
    #[error("temporary provisioning evidence file could not be created: {0}")]
    TemporaryFileCreateFailed(#[source] std::io::Error),
    #[error("provisioning evidence could not be written: {0}")]
    EvidenceWriteFailed(#[source] std::io::Error),
    #[error("provisioning evidence could not be synchronized: {0}")]
    EvidenceSyncFailed(#[source] std::io::Error),
    #[error("provisioning evidence could not be atomically installed: {0}")]
    EvidenceRenameFailed(#[source] std::io::Error),
    #[error("provisioning evidence size is invalid")]
    EvidenceSizeInvalid,
    #[error("system clock is before the Unix epoch")]
    SystemClockBeforeEpoch,
    #[error("provisioning evidence JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Provisioning(#[from] ProvisioningError),
}
