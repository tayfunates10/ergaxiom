use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_windows_cng_key_provider_runtime::CngProvisioningResult;
use ergaxiom_windows_production_signer_provisioning_runtime::{
    KeyPossessionSignature, ProvisioningAuthority, ProvisioningBackend, ProvisioningError,
    require_elevated_administrator,
};
use ergaxiom_windows_production_signer_runtime::{
    ECDSA_P256_SHA256, HardwareAssurance, HardwareKeyDescriptor, P1363_FIXED_64,
    ProductionKeyPolicy, SEC1_UNCOMPRESSED_P256,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};

const OTHER_DIGEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[derive(Debug)]
struct FakeProvisioningBackend {
    signing_key: SigningKey,
    created: bool,
}

impl ProvisioningBackend for FakeProvisioningBackend {
    fn provision(
        &self,
        policy: &ProductionKeyPolicy,
        expected_public_key_digest: Option<&str>,
    ) -> Result<CngProvisioningResult, ProvisioningError> {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        let public_key = point.as_bytes();
        let public_key_digest = encode_hex(&Sha256::digest(public_key));
        if expected_public_key_digest.is_some_and(|expected| expected != public_key_digest) {
            return Err(ProvisioningError::PublicKeyDigestMismatch);
        }
        Ok(CngProvisioningResult {
            key_name:
                ergaxiom_windows_cng_key_provider_runtime::CngPlatformKeyProvider::key_name_for(
                    policy,
                )?,
            created: self.created,
            descriptor: HardwareKeyDescriptor {
                identity: policy.identity.clone(),
                provider: policy.provider.clone(),
                algorithm: ECDSA_P256_SHA256.to_owned(),
                public_key_encoding: SEC1_UNCOMPRESSED_P256.to_owned(),
                public_key_base64url: URL_SAFE_NO_PAD.encode(public_key),
                public_key_digest,
                signature_encoding: P1363_FIXED_64.to_owned(),
                export_policy: policy.export_policy.clone(),
                provider_implementation_flags: 1,
                assurance: HardwareAssurance::Unproven,
                policy_digest: policy.digest()?,
            },
        })
    }

    fn sign_key_possession(
        &self,
        policy: &ProductionKeyPolicy,
        provisioning: &CngProvisioningResult,
        digest: &str,
    ) -> Result<KeyPossessionSignature, ProvisioningError> {
        let digest_bytes = decode_sha256(digest)?;
        let signature: Signature = self
            .signing_key
            .sign_prehash(&digest_bytes)
            .map_err(|_| ProvisioningError::KeyPossessionVerificationFailed)?;
        Ok(KeyPossessionSignature {
            digest_algorithm: "sha256".to_owned(),
            digest: digest.to_owned(),
            signature_encoding: P1363_FIXED_64.to_owned(),
            signature_base64url: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            public_key_digest: provisioning.descriptor.public_key_digest.clone(),
            key_policy_digest: policy.digest()?,
        })
    }
}

fn authority(
    created: bool,
) -> Result<ProvisioningAuthority<FakeProvisioningBackend>, Box<dyn std::error::Error>> {
    Ok(ProvisioningAuthority::new(FakeProvisioningBackend {
        signing_key: SigningKey::from_bytes((&[13_u8; 32]).into())?,
        created,
    }))
}

#[test]
fn sealed_key_possession_evidence_verifies_without_promoting_hardware()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = ProductionKeyPolicy::capability();
    let evidence = authority(true)?.provision(&policy, None, 1_800_000_000)?;
    let verified = evidence.verify_contract(&policy)?;
    assert!(verified.created);
    assert_eq!(verified.assurance, HardwareAssurance::Unproven);
    assert_eq!(
        verified.public_key_digest,
        evidence.receipt.public_key_digest
    );
    assert!(matches!(
        evidence.verify_production_eligible(&policy),
        Err(ProvisioningError::Production(
            ergaxiom_windows_production_signer_runtime::ProductionSignerError::HardwareAssuranceUnproven
        ))
    ));
    assert!(!serde_json::to_string(&evidence)?.contains("private_key"));
    assert!(!serde_json::to_string(&evidence)?.contains("seed"));
    Ok(())
}

#[test]
fn existing_key_receipt_preserves_created_false() -> Result<(), Box<dyn std::error::Error>> {
    let policy = ProductionKeyPolicy::attestation();
    let evidence = authority(false)?.provision(&policy, None, 1_800_000_100)?;
    let verified = evidence.verify_contract(&policy)?;
    assert!(!verified.created);
    Ok(())
}

#[test]
fn receipt_statement_signature_and_evidence_substitution_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = ProductionKeyPolicy::capability();
    let evidence = authority(true)?.provision(&policy, None, 1_800_000_000)?;

    for mutation in 0..5 {
        let mut altered = evidence.clone();
        match mutation {
            0 => altered.receipt.provisioned_at_epoch_s += 1,
            1 => altered.statement.key_name_digest = OTHER_DIGEST.to_owned(),
            2 => altered.key_possession.digest = OTHER_DIGEST.to_owned(),
            3 => altered.key_possession.signature_base64url = URL_SAFE_NO_PAD.encode([0_u8; 64]),
            4 => altered.evidence_digest = OTHER_DIGEST.to_owned(),
            _ => return Err("unexpected mutation".into()),
        }
        assert!(altered.verify_contract(&policy).is_err());
    }
    Ok(())
}

#[test]
fn expected_public_key_digest_is_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let policy = ProductionKeyPolicy::capability();
    assert!(matches!(
        authority(true)?.provision(&policy, Some(OTHER_DIGEST), 1_800_000_000),
        Err(ProvisioningError::PublicKeyDigestMismatch)
    ));
    Ok(())
}

#[cfg(not(windows))]
#[test]
fn administrator_gate_fails_closed_off_windows() {
    assert!(matches!(
        require_elevated_administrator(),
        Err(ProvisioningError::UnsupportedPlatform)
    ));
}

fn decode_sha256(value: &str) -> Result<[u8; 32], ProvisioningError> {
    if value.len() != 64 {
        return Err(ProvisioningError::InvalidDigestEncoding);
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = nibble(chunk[0])? << 4 | nibble(chunk[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, ProvisioningError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ProvisioningError::InvalidDigestEncoding),
    }
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
