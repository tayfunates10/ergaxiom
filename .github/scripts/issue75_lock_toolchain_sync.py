from pathlib import Path

key_file = Path("crates/key-governance-runtime/src/lib.rs")
text = key_file.read_text()
old = '''                public_key_hex: record.verifying_key.to_bytes().iter().fold(
                    String::with_capacity(64),
                    |mut output, byte| {
                        use std::fmt::Write as _;
                        write!(&mut output, "{byte:02x}")
                            .expect("writing hexadecimal bytes to String cannot fail");
                        output
                    },
                ),
'''
new = '''                public_key_hex: encode_hex(&record.verifying_key.to_bytes()),
'''
if new not in text:
    if old not in text:
        raise SystemExit("key-governance encoding anchor missing")
    text = text.replace(old, new, 1)
helper_anchor = '''fn validate_identifier(field: &'static str, value: &str) -> Result<(), KeyGovernanceError> {
'''
helper = '''fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

'''
if helper not in text:
    if helper_anchor not in text:
        raise SystemExit("key-governance helper anchor missing")
    text = text.replace(helper_anchor, helper + helper_anchor, 1)
key_file.write_text(text)

workflow = Path(".github/workflows/production-execution-chain.yml")
text = workflow.read_text()
replacements = {
    "cargo fmt --all -- --check": "cargo +1.85.0 fmt --all -- --check",
    "cargo fmt --all": "cargo +1.85.0 fmt --all",
    "cargo clippy --locked": "cargo +1.85.0 clippy --locked",
    "cargo test --locked": "cargo +1.85.0 test --locked",
    "cargo check --locked": "cargo +1.85.0 check --locked",
}
for old, new in replacements.items():
    text = text.replace(old, new)
workflow.write_text(text)
