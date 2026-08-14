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
