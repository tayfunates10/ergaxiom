from pathlib import Path

runtime = Path("crates/production-execution-runtime/src/lib.rs")
text = runtime.read_text()
old = "    #[error(transparent)]\n    Lease(#[from] ProductionSignerIdentityProofError),\n"
new = old + "    #[error(transparent)]\n    DesktopShell(#[from] DesktopShellError),\n"
if new not in text:
    if old not in text:
        raise SystemExit("production verification error anchor missing")
    runtime.write_text(text.replace(old, new, 1))

governance = Path("crates/key-governance-runtime/src/lib.rs")
text = governance.read_text()
old = '''                public_key_hex: record
                    .verifying_key
                    .to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
'''
new = '''                public_key_hex: record.verifying_key.to_bytes().iter().fold(
                    String::with_capacity(64),
                    |mut output, byte| {
                        use std::fmt::Write as _;
                        write!(&mut output, "{byte:02x}")
                            .expect("writing hexadecimal bytes to String cannot fail");
                        output
                    },
                ),
'''
if new not in text:
    if old not in text:
        raise SystemExit("key governance hex formatting anchor missing")
    governance.write_text(text.replace(old, new, 1))

protocol = Path("crates/windows-signer-protocol-runtime/src/lib.rs")
text = protocol.read_text()
old = "        output[index] = decode_nibble(chunk[0])? << 4 | decode_nibble(chunk[1])?;\n"
new = "        output[index] = (decode_nibble(chunk[0])? << 4) | decode_nibble(chunk[1])?;\n"
if new not in text:
    if old not in text:
        raise SystemExit("signer protocol precedence anchor missing")
    protocol.write_text(text.replace(old, new, 1))

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
