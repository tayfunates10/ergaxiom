include!("../../attestation-issuance-runtime/tests/production.rs");

#[test]
fn governed_attestation_reassesses_bundle_and_binds_registry_generation()
-> Result<(), Box<dyn Error>> {
    let context = context()?;
    let calls = Rc::new(Cell::new(0));
    let signing_key = P256SigningKey::from_bytes((&[12_u8; 32]).into())?;
    let backend = ProductionBackend { signing_key };
    let policy = ProductionKeyPolicy::attestation();
    let descriptor = backend.descriptor(&policy)?;
    let caller = production_caller();
    let service_identity = production_service_identity();
    let allowlist = production_allowlist()?;
    let signer_trust = ProductionSignerTrustSnapshot {
        identity: descriptor.identity.clone(),
        public_key_digest: descriptor.public_key_digest.clone(),
        allowlist_revision: allowlist.revision,
        allowlist_digest: allowlist.allowlist_digest.clone(),
        caller_identity_digest: caller.digest()?,
        signer_service_identity_digest: service_identity.digest()?,
    };
    let mut registry =
        ergaxiom_windows_production_key_governance_runtime::ProductionKeyRegistry::default();
    let empty_digest = registry.registry_digest()?;
    registry.insert_initial_guarded(0, &empty_digest, descriptor, 1, 10_000, 1)?;
    let certificate_draft = draft();
    let trust =
        ergaxiom_windows_production_signer_service_runtime::GovernedProductionSignerTrustSnapshot {
            signer: signer_trust,
            key: registry.trust_binding(
                &policy.identity,
                1,
                certificate_draft.issued_at_epoch_s,
            )?,
        };
    let service = ProductionSignerService::new(backend, service_identity, allowlist)?;
    let authority = ergaxiom_windows_production_governed_issuance_runtime::GovernedProductionAttestationIssuanceAuthority::new(
        ProductionTransport {
            service: RefCell::new(service),
            caller,
            calls: calls.clone(),
        },
        trust.clone(),
        registry.clone(),
    )?;
    let package = authority.issue(
        context.contract.clone(),
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        certificate_draft,
    )?;
    assert_eq!(calls.get(), 1);
    ergaxiom_windows_production_governed_issuance_runtime::verify_governed_production_attestation_against_bundle(
        &package,
        &trust,
        &registry,
        context.contract,
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
    )?;
    Ok(())
}

#[test]
fn governed_attestation_stale_registry_and_revocation_fail_closed()
-> Result<(), Box<dyn Error>> {
    let context = context()?;
    let calls = Rc::new(Cell::new(0));
    let signing_key = P256SigningKey::from_bytes((&[12_u8; 32]).into())?;
    let backend = ProductionBackend { signing_key };
    let policy = ProductionKeyPolicy::attestation();
    let descriptor = backend.descriptor(&policy)?;
    let caller = production_caller();
    let service_identity = production_service_identity();
    let allowlist = production_allowlist()?;
    let signer_trust = ProductionSignerTrustSnapshot {
        identity: descriptor.identity.clone(),
        public_key_digest: descriptor.public_key_digest.clone(),
        allowlist_revision: allowlist.revision,
        allowlist_digest: allowlist.allowlist_digest.clone(),
        caller_identity_digest: caller.digest()?,
        signer_service_identity_digest: service_identity.digest()?,
    };
    let mut registry =
        ergaxiom_windows_production_key_governance_runtime::ProductionKeyRegistry::default();
    let empty_digest = registry.registry_digest()?;
    registry.insert_initial_guarded(0, &empty_digest, descriptor, 1, 10_000, 1)?;
    let certificate_draft = draft();
    let trust =
        ergaxiom_windows_production_signer_service_runtime::GovernedProductionSignerTrustSnapshot {
            signer: signer_trust,
            key: registry.trust_binding(
                &policy.identity,
                1,
                certificate_draft.issued_at_epoch_s,
            )?,
        };
    let service = ProductionSignerService::new(backend, service_identity, allowlist)?;
    let authority = ergaxiom_windows_production_governed_issuance_runtime::GovernedProductionAttestationIssuanceAuthority::new(
        ProductionTransport {
            service: RefCell::new(service),
            caller,
            calls,
        },
        trust.clone(),
        registry.clone(),
    )?;
    let package = authority.issue(
        context.contract,
        &context.plan,
        &context.bundle,
        AssuranceLevel::E1,
        certificate_draft,
    )?;
    registry.revoke_guarded(
        registry.revision(),
        &registry.registry_digest()?,
        &policy.identity,
        1,
        package.certificate.payload.issued_at_epoch_s + 1,
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    )?;
    assert!(
        ergaxiom_windows_production_governed_issuance_runtime::verify_governed_production_attestation(
            &package,
            &trust,
            &registry,
        )
        .is_err()
    );
    Ok(())
}
