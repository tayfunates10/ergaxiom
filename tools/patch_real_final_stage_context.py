from pathlib import Path

TARGET = Path(
    "crates/graphic-inkscape-final-certified-delivery-runtime/"
    "tests/real_final_certified_delivery.rs"
)
text = TARGET.read_text(encoding="utf-8")
if "normalization fixture failed" in text:
    raise SystemExit(0)

replacements = [
    (
        "let normalization = normalization_fixture(&execution)?;",
        "let normalization = normalization_fixture(&execution)\n        .map_err(|error| format!(\"normalization fixture failed: {error}\"))?;",
    ),
    (
        """    let base_delivery = certify_base_delivery(
        &context,
        &mut workspace,
        &mut authorizer,
        &tokens,
        &execution,
    )?;""",
        """    let base_delivery = certify_base_delivery(
        &context,
        &mut workspace,
        &mut authorizer,
        &tokens,
        &execution,
    )
    .map_err(|error| format!("base delivery certification failed: {error}"))?;""",
    ),
    (
        """    let srgb_delivery = certify_inkscape_srgb_graphic_delivery(InkscapeSrgbCertificationRequest {
        base_delivery,""",
        """    let srgb_delivery = certify_inkscape_srgb_graphic_delivery(InkscapeSrgbCertificationRequest {
        base_delivery,""",
    ),
    (
        """        attestation_signing_key: &context.attestation_key,
    })?;

    let editable_bytes""",
        """        attestation_signing_key: &context.attestation_key,
    })
    .map_err(|error| format!("sRGB delivery certification failed: {error}"))?;

    let editable_bytes""",
    ),
]

for old, new in replacements:
    if old not in text:
        raise SystemExit(f"stage context pattern not found: {old[:80]}")
    text = text.replace(old, new, 1)

TARGET.write_text(text, encoding="utf-8")
