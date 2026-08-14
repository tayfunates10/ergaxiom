use std::cell::RefCell;
use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ergaxiom_capability_issuance_runtime::{
    CAPABILITY_ISSUER_ID, CAPABILITY_KEY_ID, CapabilityIssuanceError, CapabilityTokenDraft,
    ProductionCapabilityIssuanceAuthority, ProductionCapabilitySignerTransport,
};
use ergaxiom_capability_runtime::{CapabilityBindings, CapabilityGrant, CapabilitySubject};
use ergaxiom_contract_runtime::PermissionAccess;
use ergaxiom_key_governance_runtime::IssuerRole;
use ergaxiom_windows_production_signer_protocol_runtime::{
    ProductionSignerRequest, ProductionSignerResponse,
};
use ergaxiom_windows_production_signer_runtime::{
    AUTHENTICATED_CALLER_SCHEMA, AuthenticatedCallerIdentity, ECDSA_P256_SHA256, HardwareAssurance,
    HardwareKeyDescriptor, HardwareSignature, P1363_FIXED_64, ProductionKeyPolicy,
    SEC1_UNCOMPRESSED_P256, SIGNER_SERVICE_IDENTITY_SCHEMA, SignerRequestBinding,
    SignerServiceIdentity,
};
use ergaxiom_windows_production_signer_service_runtime::{
    AuthorizedProductionSignerPackage, HardwareSignerBackend, HardwareSignerBackendError,
    ProductionSignerService, ProductionSignerServiceError, ProductionSignerTrustSnapshot,
};
use ergaxiom_windows_signer_service_identity_runtime::{
    AllowedSignerCaller, SignerCallerAllowlist, SignerIdentityError,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use serde_json::json;
use sha2::{Digest, Sha256};

const CALLER_IMAGE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SERVICE_IMAGE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[derive(Debug, Clone, Copy)]
enum Mutation {
    None,
    AuthorizationTime,
}

#[derive(Debug)]
struct FakeHardwareBackend {
    signing_key: SigningKey,
}

impl HardwareSignerBackend for FakeHardwareBackend {
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
            public_key_digest: encode_hex(&Sha256::digest(public_key)),
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
        let digest_bytes = decode_sha256(digest)
            .map_err(|_| HardwareSignerBackendError::new("DIGEST_DECODE_FAILED"))?;
        let signature: Signature = self
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

struct TestProductionTransport {
    service: RefCell<ProductionSignerService<FakeHardwareBackend>>,
    caller: AuthenticatedCallerIdentity,
    mutation: Mutation,
}

impl ProductionCapabilitySignerTransport for TestProductionTransport {
    fn invoke(
        &self,
        request: &ProductionSignerRequest,
    ) -> Result<AuthorizedProductionSignerPackage, CapabilityIssuanceError> {
        let mut package = self
            .service
            .borrow_mut()
            .handle_authenticated(request, &self.caller, 1_800_000_100)
            .map_err(CapabilityIssuanceError::ProductionSigner)?;
        if matches!(self.mutation, Mutation::AuthorizationTime) {
            package.caller_authorization.authorized_at_epoch_s += 1;
        }
        Ok(package)
    }
}

fn caller() -> AuthenticatedCallerIdentity {
    AuthenticatedCallerIdentity {
        schema_version: AUTHENTICATED_CALLER_SCHEMA.to_owned(),
        process_id: 7200,
        process_creation_time_100ns: 123_456_789,
        principal_sid: "S-1-5-21-1000".to_owned(),
        session_id: 2,
        executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
        executable_sha256: CALLER_IMAGE.to_owned(),
    }
}

fn service_identity() -> SignerServiceIdentity {
    SignerServiceIdentity {
        schema_version: SIGNER_SERVICE_IDENTITY_SCHEMA.to_owned(),
        service_id: "ergaxiom.production-signer".to_owned(),
        instance_nonce: "0123456789abcdef0123456789abcdef".to_owned(),
        process_id: 7300,
        process_creation_time_100ns: 223_456_789,
        executable_sha256: SERVICE_IMAGE.to_owned(),
        started_at_epoch_s: 1_800_000_000,
    }
}

fn allowlist() -> Result<SignerCallerAllowlist, Box<dyn Error>> {
    Ok(SignerCallerAllowlist::build(
        1,
        vec![AllowedSignerCaller {
            caller_id: "ergaxiom.backend".to_owned(),
            principal_sid: "S-1-5-21-1000".to_owned(),
            session_id: Some(2),
            executable_path: r"C:\Program Files\Ergaxiom\ergaxiom-backend.exe".to_owned(),
            executable_sha256: CALLER_IMAGE.to_owned(),
        }],
    )?)
}

fn authority(
    mutation: Mutation,
) -> Result<
    (
        ProductionCapabilityIssuanceAuthority<TestProductionTransport>,
        ProductionSignerTrustSnapshot,
    ),
    Box<dyn Error>,
> {
    let signing_key = SigningKey::from_bytes((&[11_u8; 32]).into())?;
    let point = signing_key.verifying_key().to_encoded_point(false);
    let public_key_digest = encode_hex(&Sha256::digest(point.as_bytes()));
    let caller = caller();
    let service_identity = service_identity();
    let allowlist = allowlist()?;
    let trust = ProductionSignerTrustSnapshot {
        identity: ProductionKeyPolicy::capability().identity,
        public_key_digest,
        allowlist_revision: allowlist.revision,
        allowlist_digest: allowlist.allowlist_digest.clone(),
        caller_identity_digest: caller.digest()?,
        signer_service_identity_digest: service_identity.digest()?,
    };
    let service = ProductionSignerService::new(
        FakeHardwareBackend { signing_key },
        service_identity,
        allowlist,
    )?;
    let authority = ProductionCapabilityIssuanceAuthority::new(
        TestProductionTransport {
            service: RefCell::new(service),
            caller,
            mutation,
        },
        trust.clone(),
    )?;
    Ok((authority, trust))
}

fn draft() -> CapabilityTokenDraft {
    CapabilityTokenDraft {
        token_id: "token.capability.production.0001".to_owned(),
        subject: CapabilitySubject {
            executor_id: "executor.windows.0001".to_owned(),
            device_id: Some("device.windows.0001".to_owned()),
        },
        issued_at_epoch_s: 100,
        not_before_epoch_s: 100,
        expires_at_epoch_s: 900,
        max_uses: 1,
        nonce: "nonce-capability-production-0001".to_owned(),
        bindings: CapabilityBindings {
            contract_digest: "a".repeat(64),
            capsule_digest: "b".repeat(64),
            plan_id: "plan.capability.0001".to_owned(),
            plan_digest: "c".repeat(64),
            step_id: "step.capability.0001".to_owned(),
            operator_id: "operator.capability.0001".to_owned(),
        },
        grant: CapabilityGrant {
            capability: "application.control".to_owned(),
            resource: "fixture://capability".to_owned(),
            access: PermissionAccess::Control,
            constraints: json!({"bounded": true}),
        },
    }
}

#[test]
fn production_authority_fixes_identity_digest_and_public_trust() -> Result<(), Box<dyn Error>> {
    let (authority, trust) = authority(Mutation::None)?;
    let token = authority.issue(draft())?;
    assert_eq!(token.payload.issuer_id, CAPABILITY_ISSUER_ID);
    assert_eq!(token.payload.key_id, CAPABILITY_KEY_ID);
    let envelope = token.signer_package.verify_trusted(&trust)?;
    assert_eq!(envelope.request.identity.role, IssuerRole::Capability);
    assert_eq!(envelope.request.identity.issuer_id, CAPABILITY_ISSUER_ID);
    assert_eq!(envelope.request.identity.key_id, CAPABILITY_KEY_ID);
    assert!(envelope.request.request_id.starts_with("capability.issue."));
    assert_eq!(
        envelope.request.request_id.len(),
        "capability.issue.".len() + 48
    );
    assert!(
        !token
            .signer_package
            .signer_response
            .contains_private_material_field()
    );
    let ProductionSignerResponse::Success { result, .. } = token.signer_package.signer_response
    else {
        return Err("expected production signer response".into());
    };
    assert_eq!(result.descriptor.public_key_digest, trust.public_key_digest);
    Ok(())
}

#[test]
fn altered_authorization_receipt_seal_fails_closed() -> Result<(), Box<dyn Error>> {
    let (authority, _) = authority(Mutation::AuthorizationTime)?;
    assert!(matches!(
        authority.issue(draft()),
        Err(CapabilityIssuanceError::ProductionSigner(
            ProductionSignerServiceError::Identity(
                SignerIdentityError::AuthorizationReceiptDigestMismatch
            )
        ))
    ));
    Ok(())
}

fn decode_sha256(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    if value.len() != 64 {
        return Err("invalid digest length".into());
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(chunk[0])? << 4) | nibble(chunk[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, Box<dyn Error>> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("invalid digest encoding".into()),
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
