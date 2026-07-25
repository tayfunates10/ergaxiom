#![cfg(windows)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_windows_signer::{
    DpapiProtector, SecretProtector, SeedSource, SignerService, SignerServiceError,
};
use ergaxiom_windows_signer_client_runtime::{SignerClientError, SignerProcessClient};
use ergaxiom_windows_signer_protocol_runtime::{SignerRequest, SignerResponse};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
const FIXED_SEED: [u8; 32] = [29_u8; 32];
const DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[derive(Debug)]
struct FixedSeedSource;

impl SeedSource for FixedSeedSource {
    fn fill_seed(&mut self, seed: &mut [u8; 32]) -> Result<(), SignerServiceError> {
        *seed = FIXED_SEED;
        Ok(())
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ergaxiom-real-dpapi-{name}-{}-{counter}-{nonce}",
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

#[test]
fn dpapi_current_user_roundtrip_requires_exact_entropy() -> Result<(), Box<dyn std::error::Error>> {
    let protector = DpapiProtector;
    let plaintext = b"ergaxiom-dpapi-test-private-material";
    let protected = protector.protect(plaintext, b"entropy-a")?;
    assert_ne!(protected, plaintext);
    assert_eq!(protector.unprotect(&protected, b"entropy-a")?, plaintext);
    assert!(protector.unprotect(&protected, b"entropy-b").is_err());
    Ok(())
}

#[test]
fn real_dpapi_store_never_persists_raw_seed_and_signs_exact_envelope(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TestDirectory::create("service")?;
    let mut service = SignerService::new(
        directory.path().to_path_buf(),
        DpapiProtector,
        FixedSeedSource,
    )?;
    let initialize = SignerRequest::initialize_key(
        "request.release.initialize.dpapi.0001",
        IssuerRole::Release,
        "ergaxiom.release-authority",
        "release-key-dpapi-01",
    );
    service.handle(&initialize)?;

    let keys_directory = directory.path().join("keys");
    let mut entries = fs::read_dir(keys_directory)?;
    let record = entries.next().ok_or("missing DPAPI key record")??.path();
    assert!(entries.next().is_none());
    let stored = fs::read(record)?;
    assert!(!stored.windows(FIXED_SEED.len()).any(|window| window == FIXED_SEED));

    let signed = service.handle(&SignerRequest::sign_digest(
        "request.release.sign.dpapi.0001",
        IssuerRole::Release,
        "ergaxiom.release-authority",
        "release-key-dpapi-01",
        DIGEST,
    ))?;
    let envelope = signed.verify_digest_signature()?;
    assert_eq!(envelope.digest, DIGEST);
    assert_eq!(envelope.role, IssuerRole::Release);
    assert!(!signed.contains_private_material_field());
    Ok(())
}

#[test]
fn isolated_process_returns_only_public_material_and_rejects_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TestDirectory::create("process")?;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_ergaxiom-windows-signer"));
    let client = SignerProcessClient::isolated_test(executable, directory.path())?;
    let initialize = SignerRequest::initialize_key(
        "request.attestation.initialize.process.0001",
        IssuerRole::Attestation,
        "ergaxiom.attestation-authority",
        "attestation-key-process-01",
    );
    let initialized = client.invoke(&initialize)?;
    assert!(!initialized.contains_private_material_field());

    let sign = SignerRequest::sign_digest(
        "request.attestation.sign.process.0001",
        IssuerRole::Attestation,
        "ergaxiom.attestation-authority",
        "attestation-key-process-01",
        DIGEST,
    );
    let signed = client.invoke(&sign)?;
    signed.verify_digest_signature()?;
    assert!(!signed.contains_private_material_field());
    assert!(matches!(
        client.invoke(&sign),
        Err(SignerClientError::SignerRejected(code)) if code == "REQUEST_REPLAYED"
    ));
    Ok(())
}

#[test]
fn production_process_rejects_test_store_override_without_explicit_test_mode(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = TestDirectory::create("cli-boundary")?;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_ergaxiom-windows-signer"));
    let request = SignerRequest::public_key(
        "request.release.public.cli.0001",
        IssuerRole::Release,
        "ergaxiom.release-authority",
        "release-key-cli-01",
    );
    let mut child = Command::new(executable)
        .arg("--store")
        .arg(directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("missing signer stdin")?;
    serde_json::to_writer(&mut stdin, &request)?;
    stdin.write_all(b"\n")?;
    drop(stdin);
    let output = child.wait_with_output()?;
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let response: SignerResponse = serde_json::from_slice(&output.stdout)?;
    assert!(matches!(
        response,
        SignerResponse::Error { code, .. } if code == "COMMAND_LINE_REJECTED"
    ));
    Ok(())
}
