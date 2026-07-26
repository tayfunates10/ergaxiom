include!("issuance.rs");

use std::cell::RefCell;

use ergaxiom_attestation_issuance_runtime::{
    ProductionAttestationIssuanceAuthority, ProductionAttestationSignerTransport,
};
use ergaxiom_attestation_runtime::verify_production_signer_bound_attestation_against_bundle;
use ergaxiom_windows_production_signer_protocol_runtime::ProductionSignerRequest;
use ergaxiom_windows_production_signer_runtime::{
    AUTHENTICATED_CALLER_SCHEMA, AuthenticatedCallerIdentity, ECDSA_P256_SHA256, HardwareAssurance,
    HardwareKeyDescriptor, HardwareSignature, P1363_FIXED_64, ProductionKeyPolicy,
    SEC1_UNCOMPRESSED_P256, SIGNER_SERVICE_IDENTITY_SCHEMA, SignerRequestBinding,
    SignerServiceIdentity,
};
use ergaxiom_windows_production_signer_service_runtime::{
    AuthorizedProductionSignerPackage, HardwareSignerBackend, HardwareSignerBackendError,
    ProductionSignerService, ProductionSignerTrustSnapshot,
};
use ergaxiom_windows_signer_service_identity_runtime::{
    AllowedSignerCaller, SignerCallerAllowlist,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, signature::hazmat::PrehashSigner,
};
use sha2::{Digest, Sha256};

const PRODUCTION_CALLER_IMAGE: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PRODUCTION_SERVICE_IMAGE: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[derive(Debug)]
struct ProductionBackend {
    signing_key: P256SigningKey,
}

impl HardwareSignerBackend for ProductionBackend {
    fn descriptor(
        &self,
        policy: &ProductionKeyPolicy,
    ) -> Result<HardwareKeyDescriptor, HardwareSignerBackendError> {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        let public_key = point.as_bytes();
        Ok(HardwareKeyDescriptor {
            identity: policy.identity.clone(),
            provider: policy.provider.clone(),
            algorithm: ECDSA_P256_SHA256.to_owned(),
            public_key_encoding: SEC1_UNCOMPRESSED_P256.to_owned(),
            public_key_base64url: URL_SAFE_NO_PAD.encode(public_key),
            public_key_digest: production_encode_hex(&Sha256::digest(public_key)),
            signature_encoding: P1363_FIXED_64.to_owned(),
            export_policy: policy.export_policy.clone(),
            provider_implementation_flags: 1,
            assurance: HardwareAssurance::ProvenHardwareBacked,
            policy_digest: policy
                .digest()
                .map_err(|_| HardwareSignerBackendError::new("POLICY_DIGEST_FAILED"))?,
        })
    }

    fn sign_sha256_digest(
        &self,
        policy: &ProductionKeyPolicy,
        descriptor: &HardwareKeyDescriptor,
        binding: &SignerRequestBinding,
        digest: &str,
    ) -> Result<HardwareSignature, HardwareSignerBackendError> {
        let digest_bytes = production_decode_sha256(digest)
            .map_err(|_| HardwareSignerBackendError::new("DIGEST_DECODE_FAILED"))?;
        let signature: P256Signature = self
            .signing_key
            .sign_prehash(&digest_bytes)
            .map_err(|_| HardwareSignerBackendError::new("SIGNING_FAILED"))?;
        Ok(HardwareSignature {
            identity: policy.identity.clone(),
            algorithm: ECDSA_P256_SHA256.to_owned(),
            signature_encoding: P1363_FIXED_64.to_owned(),
            digest_algorithm: "sha256".to_owned(),
            digest: digest.to_owned(),
            signature_base64url: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            public_key_digest: descriptor.public_key_digest.clone(),
            key_policy_digest: descriptor.policy_digest.clone(),
            request_binding_digest: binding
                .digest()
                .map_err(|_| HardwareSignerBackendError::new("BINDING_DIGEST_FAILED"))?,
        })
    }
}

struct ProductionTransport {
    service: RefCell<ProductionSignerService<ProductionBackend>>,
    caller: AuthenticatedCallerIdentity,
    calls: Rc<Cell<u32>>,
}

impl ProductionAttestationSignerTransport for ProductionTransport {
    fn invoke(
        &self,
        request: &ProductionSignerRequest,
    ) -> Result<AuthorizedProductionSignerPackage, AttestationIssuanceError> {
        self.calls.set(self.calls.get().saturating_add(1));
        self.service
            .borrow_mut()
            .handle_authenticated(request, &self.caller, 2_050)
            .map_err(AttestationIssuanceError::ProductionSigner)
    }
}

fn production_caller() -> AuthenticatedCallerIdentity {
    AuthenticatedCallerIdentity {
        schema_version: AUTHENTICATED_CALLER_SCHEMA.to_owned(),
        process_id: 7400,
        process_creation_time_100ns: 123_456_789,
        principal_sid: "S-1-5-21-1000".to_owned(),
        session_id: 2,
        executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
        executable_sha256: PRODUCTION_CALLER_IMAGE.to_owned(),
    }
}

fn production_service_identity() -> SignerServiceIdentity {
    SignerServiceIdentity {
        schema_version: SIGNER_SERVICE_IDENTITY_SCHEMA.to_owned(),
        service_id: "ergaxiom.production-signer".to_owned(),
        instance_nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        process_id: 7500,
        process_creation_time_100ns: 223_456_789,
        executable_sha256: PRODUCTION_SERVICE_IMAGE.to_owned(),
        started_at_epoch_s: 2_000,
    }
}

fn production_allowlist() -> Result<SignerCallerAllowlist, Box<dyn Error>> {
    Ok(SignerCallerAllowlist::build(
        1,
        vec![AllowedSignerCaller {
            caller_id: "ergaxiom.backend".to_owned(),
            principal_sid: "S-1-5-21-1000".to_owned(),
            session_id: Some(2),
            executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
            executable_sha256: PRODUCTION_CALLER_IMAGE.to_owned(),
        }],
    )?)
}

fn production_authority(
    calls: Rc<Cell<u32>>,
) -> Result<
    (
        ProductionAttestationIssuanceAuthority<ProductionTransport>,
        ProductionSignerTrustSnapshot,
    ),
    Box<dyn Error>,
> {
    let signing_key = P256SigningKey::from_bytes((&[12_u8; 32]).into())?;
    let point = signing_key.verifying_key().to_encoded_point(false);
    let caller = production_caller();
    let service_identity = production_service_identity();
    let allowlist = production_allowlist()?;
    let trust = ProductionSignerTrustSnapshot {
        identity: ProductionKeyPolicy::attestation().identity,
        public_key_digest: production_encode_hex(&Sha256::digest(point.as_bytes())),
        allowlist_revision: allowlist.revision,
        allowlist_digest: allowlist.allowlist_digest.clone(),
        caller_identity_digest: caller.digest()?,
        signer_service_identity_digest: service_identity.digest()?,
    };
    let service = ProductionSignerService::new(
        ProductionBackend { signing_key },
        service_identity,
        allowlist,
    )?;
    let authority = ProductionAttestationIssuanceAuthority::new(
        ProductionTransport {
            service: RefCell::new(service),
            caller,
            calls,
        },
        trust.clone(),
    )?;
    Ok((authority, trust))
}

#[test]
fn production_authority_reassesses_and_issues_verified_p256_certificate()
-> Result<(), Box<dyn Error>> {
    let context = context()?;
    let calls = Rc::new(Cell::new(0));
    let (authority, trust) = production_authority(calls.clone())?;
    let package = authority.issue(
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        draft(),
    )?;
    assert_eq!(calls.get(), 1);
    assert_eq!(package.certificate.payload.issuer_id, ATTESTATION_ISSUER_ID);
    assert_eq!(package.certificate.payload.key_id, ATTESTATION_KEY_ID);
    let envelope = package.certificate.signer_package.verify_trusted(&trust)?;
    assert_eq!(envelope.request.identity.role, IssuerRole::Attestation);
    assert_eq!(envelope.request.identity.issuer_id, ATTESTATION_ISSUER_ID);
    assert_eq!(envelope.request.identity.key_id, ATTESTATION_KEY_ID);
    assert!(
        envelope
            .request
            .request_id
            .starts_with("attestation.issue.")
    );
    verify_production_signer_bound_attestation_against_bundle(
        &package,
        &trust,
        context.contract,
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
    )?;
    Ok(())
}

#[test]
fn production_failed_proof_blocks_before_signer_invocation() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.bundle["proof_results"][0]["status"] = json!("FAILED");
    context.bundle["proof_results"][0]["observed"] = json!(false);
    context.bundle["claimed_decision"]["status"] = json!("REJECTED");
    context.bundle["claimed_decision"]["mandatory_passed"] = json!(0);
    context.bundle["claimed_decision"]["mandatory_failed"] = json!(1);
    let calls = Rc::new(Cell::new(0));
    let (authority, _) = production_authority(calls.clone())?;
    assert!(
        authority
            .issue(
                context.contract,
                &context.plan,
                &context.bundle,
                AssuranceLevel::E1,
                draft(),
            )
            .is_err()
    );
    assert_eq!(calls.get(), 0);
    Ok(())
}

fn production_decode_sha256(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    if value.len() != 64 {
        return Err("invalid digest length".into());
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = production_nibble(chunk[0])? << 4 | production_nibble(chunk[1])?;
    }
    Ok(output)
}

fn production_nibble(value: u8) -> Result<u8, Box<dyn Error>> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("invalid digest encoding".into()),
    }
}

fn production_encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
