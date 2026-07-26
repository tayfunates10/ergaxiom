use std::error::Error;
use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ergaxiom_windows_production_key_governance_runtime::ProductionKeyRegistry;
use ergaxiom_windows_production_signer_runtime::{
    ECDSA_P256_SHA256, HardwareAssurance, HardwareKeyDescriptor,
    MICROSOFT_PLATFORM_CRYPTO_PROVIDER, NON_EXPORTABLE_POLICY, P1363_FIXED_64,
    ProductionKeyIdentity, ProductionKeyPolicy, SEC1_UNCOMPRESSED_P256,
};
use ergaxiom_windows_production_trust_state_runtime::{
    OfflineBootstrapExpectation, ProductionTrustRecoveryBody, ProductionTrustRecoveryEnvelope,
    ProductionTrustStateActivator, ProductionTrustStateBody, ProductionTrustStateEnvelope,
    ProductionTrustStateError, ProductionTrustStateStore, ProductionTrustStoreError,
    TrustGovernanceKeyRecord, TrustGovernancePolicy, TrustGovernanceSignature,
    trust_recovery_signature_message, trust_state_signature_message,
};
use p256::ecdsa::SigningKey as P256SigningKey;
use sha2::{Digest, Sha256};

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ACTIVATION: u64 = 1_900_000_000;

struct GovernanceFixture {
    policy: TrustGovernancePolicy,
    keys: Vec<(String, SigningKey)>,
}

impl GovernanceFixture {
    fn threshold_two() -> Result<Self, Box<dyn Error>> {
        let keys = vec![
            (
                "governance-root-a".to_owned(),
                SigningKey::from_bytes(&[31_u8; 32]),
            ),
            (
                "governance-root-b".to_owned(),
                SigningKey::from_bytes(&[47_u8; 32]),
            ),
            (
                "governance-root-c".to_owned(),
                SigningKey::from_bytes(&[59_u8; 32]),
            ),
        ];
        let records = keys
            .iter()
            .map(|(key_id, signing_key)| {
                TrustGovernanceKeyRecord::new_active(
                    key_id.clone(),
                    signing_key.verifying_key().to_bytes(),
                    ACTIVATION - 100,
                    ACTIVATION + 10_000,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let policy = TrustGovernancePolicy::new("production-trust-governance", 1, 2, records)?;
        Ok(Self { policy, keys })
    }

    fn state_envelope(
        &self,
        body: ProductionTrustStateBody,
    ) -> Result<ProductionTrustStateEnvelope, Box<dyn Error>> {
        let message = trust_state_signature_message(&body.body_digest)?;
        let signatures = self
            .keys
            .iter()
            .take(2)
            .map(|(key_id, signing_key)| {
                TrustGovernanceSignature::from_signature_bytes(
                    key_id.clone(),
                    body.body_digest.clone(),
                    signing_key.sign(&message).to_bytes(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProductionTrustStateEnvelope::new(
            body,
            &self.policy,
            signatures,
        )?)
    }

    fn recovery_envelope(
        &self,
        body: ProductionTrustRecoveryBody,
    ) -> Result<ProductionTrustRecoveryEnvelope, Box<dyn Error>> {
        let message = trust_recovery_signature_message(&body.body_digest)?;
        let signatures = self
            .keys
            .iter()
            .take(2)
            .map(|(key_id, signing_key)| {
                TrustGovernanceSignature::from_signature_bytes(
                    key_id.clone(),
                    body.body_digest.clone(),
                    signing_key.sign(&message).to_bytes(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProductionTrustRecoveryEnvelope::new(
            body,
            &self.policy,
            signatures,
        )?)
    }
}

#[test]
fn explicit_bootstrap_and_monotonic_activation_reject_unsigned_stale_forked_and_downgraded_states()
-> Result<(), Box<dyn Error>> {
    let governance = GovernanceFixture::threshold_two()?;
    let registry = initial_registry()?;
    let state_one =
        governance.state_envelope(state_body(1, None, registry.snapshot(), 1, 1, 1)?)?;
    let expectation = OfflineBootstrapExpectation::new(
        "ergaxiom-production-a",
        state_one.envelope_digest.clone(),
        governance.policy.policy_digest.clone(),
    )?;
    let mut activator = ProductionTrustStateActivator::default();
    let activated_one =
        activator.bootstrap(&state_one, &governance.policy, &expectation, ACTIVATION)?;
    assert_eq!(activated_one.checkpoint.revision, 1);

    let mut unsigned = state_one.clone();
    unsigned.signatures.clear();
    assert!(matches!(
        unsigned.verify(&governance.policy, ACTIVATION),
        Err(ProductionTrustStateError::GovernanceSignaturesMissing)
    ));

    let state_two = governance.state_envelope(state_body(
        2,
        Some(state_one.body.body_digest.clone()),
        registry.snapshot(),
        2,
        2,
        1,
    )?)?;
    let activated_two = activator.activate(&state_two, &governance.policy, ACTIVATION + 1)?;
    assert_eq!(activated_two.checkpoint.revision, 2);

    assert!(matches!(
        activator.activate(&state_two, &governance.policy, ACTIVATION + 1),
        Err(ProductionTrustStateError::NonMonotonicRevision)
    ));

    let skipped = governance.state_envelope(state_body(
        4,
        Some(state_two.body.body_digest.clone()),
        registry.snapshot(),
        4,
        4,
        1,
    )?)?;
    assert!(matches!(
        activator.activate(&skipped, &governance.policy, ACTIVATION + 2),
        Err(ProductionTrustStateError::NonMonotonicRevision)
    ));

    let forked = governance.state_envelope(state_body(
        3,
        Some(DIGEST_C.to_owned()),
        registry.snapshot(),
        3,
        3,
        1,
    )?)?;
    assert!(matches!(
        activator.activate(&forked, &governance.policy, ACTIVATION + 2),
        Err(ProductionTrustStateError::PreviousStateDigestMismatch)
    ));

    let downgraded = governance.state_envelope(state_body(
        3,
        Some(state_two.body.body_digest.clone()),
        registry.snapshot(),
        1,
        1,
        1,
    )?)?;
    assert!(matches!(
        activator.activate(&downgraded, &governance.policy, ACTIVATION + 2),
        Err(ProductionTrustStateError::TrustStateDowngrade)
    ));
    Ok(())
}

#[test]
fn recovery_is_separate_replay_protected_and_cannot_reactivate_revoked_keys()
-> Result<(), Box<dyn Error>> {
    let governance = GovernanceFixture::threshold_two()?;
    let mut registry = initial_registry()?;
    let state_one =
        governance.state_envelope(state_body(1, None, registry.snapshot(), 1, 1, 1)?)?;
    let expectation = OfflineBootstrapExpectation::new(
        "ergaxiom-production-a",
        state_one.envelope_digest.clone(),
        governance.policy.policy_digest.clone(),
    )?;
    let mut activator = ProductionTrustStateActivator::default();
    activator.bootstrap(&state_one, &governance.policy, &expectation, ACTIVATION)?;

    let before_revocation = registry.snapshot();
    let expected_revision = registry.revision();
    let expected_digest = registry.registry_digest()?;
    registry.revoke_guarded(
        expected_revision,
        &expected_digest,
        &ProductionKeyIdentity::capability(),
        1,
        ACTIVATION + 10,
        DIGEST_C,
    )?;
    let revoked_state = governance.state_envelope(state_body(
        2,
        Some(state_one.body.body_digest.clone()),
        registry.snapshot(),
        2,
        2,
        1,
    )?)?;
    activator.activate(&revoked_state, &governance.policy, ACTIVATION + 10)?;

    let replacement = governance.state_envelope(state_body(
        3,
        Some(revoked_state.body.body_digest.clone()),
        before_revocation,
        3,
        3,
        2,
    )?)?;
    let recovery_body = ProductionTrustRecoveryBody::new(
        "ergaxiom-production-a",
        "offline-recovery-v1",
        revoked_state.body.body_digest.clone(),
        replacement.body.body_digest.clone(),
        DIGEST_B,
        1,
        2,
        3,
        ACTIVATION + 100,
    )?;
    let recovery = governance.recovery_envelope(recovery_body)?;
    assert!(matches!(
        activator.recover(&replacement, &recovery, &governance.policy, ACTIVATION + 20),
        Err(ProductionTrustStateError::RevokedKeyReactivation)
    ));

    let safe_replacement = governance.state_envelope(state_body(
        3,
        Some(revoked_state.body.body_digest.clone()),
        registry.snapshot(),
        3,
        3,
        2,
    )?)?;
    let safe_recovery = governance.recovery_envelope(ProductionTrustRecoveryBody::new(
        "ergaxiom-production-a",
        "offline-recovery-v1",
        revoked_state.body.body_digest.clone(),
        safe_replacement.body.body_digest.clone(),
        DIGEST_B,
        1,
        2,
        3,
        ACTIVATION + 100,
    )?)?;
    let recovered = activator.recover(
        &safe_replacement,
        &safe_recovery,
        &governance.policy,
        ACTIVATION + 20,
    )?;
    assert_eq!(recovered.checkpoint.last_recovery_sequence, 1);
    assert!(matches!(
        activator.recover(
            &safe_replacement,
            &safe_recovery,
            &governance.policy,
            ACTIVATION + 20
        ),
        Err(ProductionTrustStateError::RecoveryReplay)
            | Err(ProductionTrustStateError::RecoveryStateDigestMismatch)
    ));
    Ok(())
}

#[test]
fn immutable_state_plus_atomic_pointer_preserves_previous_acceptance_on_pre_activation_crash()
-> Result<(), Box<dyn Error>> {
    let governance = GovernanceFixture::threshold_two()?;
    let registry = initial_registry()?;
    let state_one =
        governance.state_envelope(state_body(1, None, registry.snapshot(), 1, 1, 1)?)?;
    let expectation = OfflineBootstrapExpectation::new(
        "ergaxiom-production-a",
        state_one.envelope_digest.clone(),
        governance.policy.policy_digest.clone(),
    )?;
    let mut activator = ProductionTrustStateActivator::default();
    let activated_one =
        activator.bootstrap(&state_one, &governance.policy, &expectation, ACTIVATION)?;

    let root = unique_temp_directory("trust-store-atomic")?;
    let store = ProductionTrustStateStore::new(root.clone())?;
    store.initialize_protected()?;
    store.persist_activated(&activated_one)?;
    let loaded_one = store.load_accepted(&governance.policy, ACTIVATION)?;
    assert_eq!(loaded_one.checkpoint.revision, 1);

    let state_two = governance.state_envelope(state_body(
        2,
        Some(state_one.body.body_digest.clone()),
        registry.snapshot(),
        2,
        2,
        1,
    )?)?;
    let activated_two = activator.activate(&state_two, &governance.policy, ACTIVATION + 1)?;

    let stale_temporary_pointer = root.join("accepted.json.tmp");
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stale_temporary_pointer)?;
    assert!(matches!(
        store.persist_activated(&activated_two),
        Err(ProductionTrustStoreError::Io(_))
    ));
    let still_loaded_one = store.load_accepted(&governance.policy, ACTIVATION + 1)?;
    assert_eq!(still_loaded_one.checkpoint.revision, 1);

    fs::remove_file(stale_temporary_pointer)?;
    store.persist_activated(&activated_two)?;
    let loaded_two = store.load_accepted(&governance.policy, ACTIVATION + 1)?;
    assert_eq!(loaded_two.checkpoint.revision, 2);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn relative_or_environment_selected_production_paths_have_no_runtime_surface() {
    assert!(matches!(
        ProductionTrustStateStore::new(PathBuf::from("relative/trust")),
        Err(ProductionTrustStoreError::InvalidStoreConfiguration)
    ));
}

fn initial_registry() -> Result<ProductionKeyRegistry, Box<dyn Error>> {
    let mut registry = ProductionKeyRegistry::default();
    let initial_digest = registry.registry_digest()?;
    registry.insert_initial_guarded(
        0,
        &initial_digest,
        descriptor(ProductionKeyIdentity::capability(), [7_u8; 32])?,
        ACTIVATION - 10,
        ACTIVATION + 1_000,
        ACTIVATION - 5,
    )?;
    let revision = registry.revision();
    let digest = registry.registry_digest()?;
    registry.insert_initial_guarded(
        revision,
        &digest,
        descriptor(ProductionKeyIdentity::attestation(), [11_u8; 32])?,
        ACTIVATION - 10,
        ACTIVATION + 1_000,
        ACTIVATION - 4,
    )?;
    Ok(registry)
}

fn descriptor(
    identity: ProductionKeyIdentity,
    secret: [u8; 32],
) -> Result<HardwareKeyDescriptor, Box<dyn Error>> {
    let signing_key = P256SigningKey::from_bytes((&secret).into())?;
    let public = signing_key.verifying_key().to_encoded_point(false);
    let public_bytes = public.as_bytes();
    let policy = ProductionKeyPolicy::for_identity(identity.clone());
    Ok(HardwareKeyDescriptor {
        identity,
        provider: MICROSOFT_PLATFORM_CRYPTO_PROVIDER.to_owned(),
        algorithm: ECDSA_P256_SHA256.to_owned(),
        public_key_encoding: SEC1_UNCOMPRESSED_P256.to_owned(),
        public_key_base64url: URL_SAFE_NO_PAD.encode(public_bytes),
        public_key_digest: encode_hex(&Sha256::digest(public_bytes)),
        signature_encoding: P1363_FIXED_64.to_owned(),
        export_policy: NON_EXPORTABLE_POLICY.to_owned(),
        provider_implementation_flags: 1,
        assurance: HardwareAssurance::ProvenHardwareBacked,
        policy_digest: policy.digest()?,
    })
}

fn state_body(
    revision: u64,
    previous: Option<String>,
    registry: ergaxiom_windows_production_key_governance_runtime::ProductionKeyRegistrySnapshot,
    allowlist_revision: u64,
    service_policy_revision: u64,
    minimum_accepted_revision: u64,
) -> Result<ProductionTrustStateBody, Box<dyn Error>> {
    Ok(ProductionTrustStateBody::new(
        "ergaxiom-production-a",
        revision,
        previous,
        registry,
        allowlist_revision,
        DIGEST_A,
        DIGEST_B,
        service_policy_revision,
        DIGEST_C,
        ACTIVATION + revision - 1,
        ACTIVATION - 10,
        ACTIVATION + 1_000,
        minimum_accepted_revision,
        "offline-recovery-v1",
    )?)
}

fn unique_temp_directory(label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!("ergaxiom-{label}-{}-{nonce}", std::process::id())))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
