use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_windows_signer::{SecretProtector, SeedSource, SignerService, SignerServiceError};
use ergaxiom_windows_signer_protocol_runtime::{SignerRequest, SignerResponse};
use sha2::{Digest, Sha256};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
const FIXED_SEED: [u8; 32] = [7_u8; 32];
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Debug, Clone, Copy)]
struct AuthenticatedTestProtector;

impl SecretProtector for AuthenticatedTestProtector {
    fn protect(&self, plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, SignerServiceError> {
        let mut output = Sha256::new()
            .chain_update(entropy)
            .chain_update(plaintext)
            .finalize()
            .to_vec();
        output.extend(
            plaintext
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ entropy[index % entropy.len()] ^ 0xa5),
        );
        Ok(output)
    }

    fn unprotect(&self, ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, SignerServiceError> {
        if ciphertext.len() < 32 || entropy.is_empty() {
            return Err(SignerServiceError::StoredKeyCorrupt);
        }
        let plaintext: Vec<u8> = ciphertext[32..]
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ entropy[index % entropy.len()] ^ 0xa5)
            .collect();
        let expected = Sha256::new()
            .chain_update(entropy)
            .chain_update(&plaintext)
            .finalize();
        if expected.as_slice() != &ciphertext[..32] {
            return Err(SignerServiceError::StoredKeyCorrupt);
        }
        Ok(plaintext)
    }
}

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
            "ergaxiom-windows-signer-{name}-{}-{counter}-{nonce}",
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

fn requests() -> (SignerRequest, SignerRequest, SignerRequest) {
    (
        SignerRequest::initialize_key(
            "request.attestation.initialize.0001",
            IssuerRole::Attestation,
            "ergaxiom.attestation-authority",
            "attestation-key-01",
        ),
        SignerRequest::public_key(
            "request.attestation.public.0001",
            IssuerRole::Attestation,
            "ergaxiom.attestation-authority",
            "attestation-key-01",
        ),
        SignerRequest::sign_digest(
            "request.attestation.sign.0001",
            IssuerRole::Attestation,
            "ergaxiom.attestation-authority",
            "attestation-key-01",
            DIGEST,
        ),
    )
}

#[test]
fn private_seed_stays_protected_and_digest_signature_verifies()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TestDirectory::create("protected-roundtrip")?;
    let mut service = SignerService::new(
        directory.path().to_path_buf(),
        AuthenticatedTestProtector,
        FixedSeedSource,
    )?;
    let (initialize, public_key, sign) = requests();

    let initialized = service.handle(&initialize)?;
    assert!(!initialized.contains_private_material_field());

    let keys_directory = directory.path().join("keys");
    let mut entries = fs::read_dir(keys_directory)?;
    let record_path = entries.next().ok_or("missing stored key record")??.path();
    assert!(entries.next().is_none());
    let stored_bytes = fs::read(record_path)?;
    assert!(
        !stored_bytes
            .windows(FIXED_SEED.len())
            .any(|window| window == FIXED_SEED)
    );
    let raw_seed_base64 = STANDARD.encode(FIXED_SEED);
    let stored_text = String::from_utf8(stored_bytes)?;
    assert!(!stored_text.contains(&raw_seed_base64));

    let public = service.handle(&public_key)?;
    assert!(!public.contains_private_material_field());
    let signed = service.handle(&sign)?;
    let envelope = signed.verify_digest_signature()?;
    assert_eq!(envelope.digest, DIGEST);
    assert_eq!(envelope.role, IssuerRole::Attestation);
    assert!(!signed.contains_private_material_field());
    Ok(())
}

#[test]
fn duplicate_request_ids_and_duplicate_initialization_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TestDirectory::create("replay")?;
    let mut service = SignerService::new(
        directory.path().to_path_buf(),
        AuthenticatedTestProtector,
        FixedSeedSource,
    )?;
    let (initialize, _, sign) = requests();
    service.handle(&initialize)?;
    assert!(matches!(
        service.handle(&initialize),
        Err(SignerServiceError::ReplayDetected)
    ));

    let duplicate_initialize = SignerRequest::initialize_key(
        "request.attestation.initialize.0002",
        IssuerRole::Attestation,
        "ergaxiom.attestation-authority",
        "attestation-key-01",
    );
    assert!(matches!(
        service.handle(&duplicate_initialize),
        Err(SignerServiceError::KeyAlreadyExists)
    ));

    service.handle(&sign)?;
    assert!(matches!(
        service.handle(&sign),
        Err(SignerServiceError::ReplayDetected)
    ));
    Ok(())
}

#[test]
fn role_or_key_changes_cannot_open_existing_private_material()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TestDirectory::create("role-binding")?;
    let mut service = SignerService::new(
        directory.path().to_path_buf(),
        AuthenticatedTestProtector,
        FixedSeedSource,
    )?;
    let (initialize, _, _) = requests();
    service.handle(&initialize)?;

    let wrong_role = SignerRequest::sign_digest(
        "request.capability.sign.0001",
        IssuerRole::Capability,
        "ergaxiom.attestation-authority",
        "attestation-key-01",
        DIGEST,
    );
    assert!(matches!(
        service.handle(&wrong_role),
        Err(SignerServiceError::UnknownKey)
    ));

    let wrong_key = SignerRequest::sign_digest(
        "request.attestation.sign.0002",
        IssuerRole::Attestation,
        "ergaxiom.attestation-authority",
        "attestation-key-02",
        DIGEST,
    );
    assert!(matches!(
        service.handle(&wrong_key),
        Err(SignerServiceError::UnknownKey)
    ));
    Ok(())
}

#[test]
fn responses_never_serialize_secret_shaped_fields() -> Result<(), Box<dyn std::error::Error>> {
    let response = SignerResponse::rejected(
        Some("request.attestation.sign.0003".to_owned()),
        "DPAPI_UNPROTECT_FAILED",
    );
    let json = serde_json::to_string(&response)?;
    for forbidden in ["private_key", "private_seed", "protected_seed", "secret"] {
        assert!(!json.contains(forbidden));
    }
    Ok(())
}
