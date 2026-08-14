from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    target = Path(path)
    text = target.read_text()
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"{label} anchor missing in {path}")
    target.write_text(text.replace(old, new, 1))


replace_once(
    "crates/production-execution-runtime/src/lib.rs",
    "    #[error(transparent)]\n    Lease(#[from] ProductionSignerIdentityProofError),\n",
    "    #[error(transparent)]\n    Lease(#[from] ProductionSignerIdentityProofError),\n    #[error(transparent)]\n    DesktopShell(#[from] DesktopShellError),\n",
    "production verification error conversion",
)

replace_once(
    "crates/key-governance-runtime/src/lib.rs",
    '''                public_key_hex: record
                    .verifying_key
                    .to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
''',
    '''                public_key_hex: record.verifying_key.to_bytes().iter().fold(
                    String::with_capacity(64),
                    |mut output, byte| {
                        use std::fmt::Write as _;
                        write!(&mut output, "{byte:02x}")
                            .expect("writing hexadecimal bytes to String cannot fail");
                        output
                    },
                ),
''',
    "key governance hex formatting",
)

precedence_patterns = [
    (
        "decode_nibble(chunk[0])? << 4 | decode_nibble(chunk[1])?",
        "(decode_nibble(chunk[0])? << 4) | decode_nibble(chunk[1])?",
    ),
    (
        "nibble(chunk[0])? << 4 | nibble(chunk[1])?",
        "(nibble(chunk[0])? << 4) | nibble(chunk[1])?",
    ),
    (
        "u16::from(bytes[0]) << 8 | u16::from(bytes[1])",
        "(u16::from(bytes[0]) << 8) | u16::from(bytes[1])",
    ),
]
precedence_hits = 0
for target in Path("crates").rglob("*.rs"):
    text = target.read_text()
    updated = text
    for old, new in precedence_patterns:
        hits = updated.count(old)
        if hits:
            updated = updated.replace(old, new)
            precedence_hits += hits
    if updated != text:
        target.write_text(updated)
if precedence_hits == 0:
    already_fixed = any(
        any(new in target.read_text() for _, new in precedence_patterns)
        for target in Path("crates").rglob("*.rs")
    )
    if not already_fixed:
        raise SystemExit("expected production precedence expressions were not found")

acceptance = Path("crates/production-execution-authority-runtime/tests/persistent_chain.rs")
text = acceptance.read_text()
anchor = 'include!("../../backend-issuance-runtime/tests/persistent_production_capability.rs");\n\n'
imports = '''use ergaxiom_capability_runtime::AuthorizationReceipt;
use ergaxiom_desktop_shell_runtime::CertificateVerification;
use ergaxiom_proof_kernel::DecisionStatus;
use ergaxiom_windows_production_governed_issuance_runtime::verify_governed_production_attestation_against_bundle;
use sha2::{Digest as _, Sha256};

'''
if imports not in text:
    if anchor not in text:
        raise SystemExit("production acceptance import anchor missing")
    acceptance.write_text(text.replace(anchor, anchor + imports, 1))

replace_once(
    "apps/desktop/src-tauri/src/production_startup.rs",
    '''    status.recovery_required = recovery_required;
    status.last_identity_proof_epoch_s = last_identity_proof_epoch_s;
    status
}
''',
    '''    status.recovery_required = recovery_required;
    status.last_identity_proof_epoch_s = last_identity_proof_epoch_s;
    status.production_issuance_enabled = phase == ProductionSignerStartupPhase::LiveVerified
        && live_service_identity_verified
        && !recovery_required;
    status
}
''',
    "production startup issuance readiness",
)

pipeline = Path("apps/desktop/src-tauri/src/production_pipeline.rs")
text = pipeline.read_text()
text = text.replace("    ProductionSignerBoundCapabilityToken,\n", "")
text = text.replace("use ergaxiom_occupational_twin_runtime::OperationReceipt;\n", "")
pipeline.write_text(text)

replace_once(
    "apps/desktop/src-tauri/src/production_pipeline.rs",
    '''    let prepared = prepare_desktop_job()?;
    validate_approved_bindings(&prepared, approved_snapshot, approval, approve_receipt)?;

    let stage = production
        .with_fresh_lease(|authority, _lease, _deployment, _client, _now| {
            Ok(authority.chain_state().stage)
        })
        .map_err(boundary_error)?;
    if stage == ProductionExecutionStage::Executed {
        return resume_attestation(production, &prepared, approval);
    }
''',
    '''    let prepared = prepare_desktop_job()?;
    let stage = production
        .with_fresh_lease(|authority, _lease, _deployment, _client, _now| {
            Ok(authority.chain_state().stage)
        })
        .map_err(boundary_error)?;
    if stage == ProductionExecutionStage::Executed {
        return resume_attestation(production, &prepared, approval);
    }
    validate_approved_bindings(&prepared, approved_snapshot, approval, approve_receipt)?;
''',
    "executed restart resume ordering",
)

replace_once(
    "apps/desktop/src-tauri/src/production_pipeline.rs",
    "    let authorization_receipts = collect_authorization_receipts(production, &prepared)?;\n",
    "    let authorization_receipts = collect_authorization_receipts(production, &prepared, approval)?;\n",
    "authorization receipt collection call",
)

replace_once(
    "apps/desktop/src-tauri/src/production_pipeline.rs",
    '''fn collect_authorization_receipts(
    production: &ProductionExecutionState,
    prepared: &PreparedDesktopJob,
) -> Result<Vec<AuthorizationReceipt>, String> {
''',
    '''fn collect_authorization_receipts(
    production: &ProductionExecutionState,
    prepared: &PreparedDesktopJob,
    approval: &DesktopApprovalRecord,
) -> Result<Vec<AuthorizationReceipt>, String> {
''',
    "authorization receipt collection signature",
)

replace_once(
    "apps/desktop/src-tauri/src/production_pipeline.rs",
    '''                        &prepared.compiled_plan,
                        step,
                    )?;
                    return Ok(());
''',
    '''                        &prepared.compiled_plan,
                        step,
                        now,
                    )?;
                    return Ok(());
''',
    "persisted issued token current-time verification",
)

replace_once(
    "apps/desktop/src-tauri/src/production_pipeline.rs",
    '''                    if verified != receipt {
                        return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
                    }
                    return Ok(receipt);
''',
    '''                    if verified != receipt {
                        return Err(ProductionExecutionBoundaryError::TrustLeaseRejected);
                    }
                    verify_persisted_token(
                        &persisted,
                        lease,
                        authority.executor_id(),
                        authority.device_id(),
                        approval,
                        &prepared.compiled_contract,
                        &prepared.compiled_plan,
                        step,
                        now,
                    )?;
                    return Ok(receipt);
''',
    "persisted consumed token current-time verification",
)

replace_once(
    "apps/desktop/src-tauri/src/production_pipeline.rs",
    '''    plan: &CompiledPlan,
    step: &PlanStep,
) -> Result<(), ProductionExecutionBoundaryError> {
''',
    '''    plan: &CompiledPlan,
    step: &PlanStep,
    trusted_now_epoch_s: u64,
) -> Result<(), ProductionExecutionBoundaryError> {
''',
    "persisted token verification signature",
)

replace_once(
    "apps/desktop/src-tauri/src/production_pipeline.rs",
    '''        || token.payload.max_uses != 1
        || token.payload.expires_at_epoch_s != approval.expires_at_epoch_s
''',
    '''        || token.payload.max_uses != 1
        || token.payload.issued_at_epoch_s > trusted_now_epoch_s
        || trusted_now_epoch_s < token.payload.not_before_epoch_s
        || trusted_now_epoch_s >= token.payload.expires_at_epoch_s
        || trusted_now_epoch_s >= approval.expires_at_epoch_s
        || token.payload.expires_at_epoch_s != approval.expires_at_epoch_s
''',
    "persisted token temporal validity",
)

replace_once(
    "apps/desktop/src-tauri/src/production_pipeline.rs",
    '            "uri": format!("bundle://artifacts/execution_receipt.{}", receipt.operation_id),\n',
    '            "uri": format!("ergaxiom-inline-hex:{}", hex_encode(&bytes)),\n',
    "inline operation receipt evidence",
)

replace_once(
    "apps/desktop/src-tauri/src/production_pipeline.rs",
    '''fn random_nonce() -> Result<String, ProductionExecutionBoundaryError> {
''',
    '''fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn random_nonce() -> Result<String, ProductionExecutionBoundaryError> {
''',
    "inline operation receipt hex encoder",
)
