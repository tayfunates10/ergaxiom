from pathlib import Path

TARGET = Path(
    "crates/graphic-inkscape-final-certified-delivery-runtime/"
    "tests/real_final_certified_delivery.rs"
)
text = TARGET.read_text(encoding="utf-8")
if "approved-logo PNG decode failed" in text:
    raise SystemExit(0)

replacements = [
    (
        """    let approved_logo_png = approved_logo_png()?;
    let context = real_context(&approved_logo_png)?;""",
        """    let approved_logo_png = approved_logo_png()?;
    let decoded_approved_logo = decode_png_bytes(&approved_logo_png)
        .map_err(|error| format!("approved-logo PNG decode failed: {error}"))?;
    let context = real_context(&approved_logo_png)?;""",
    ),
    (
        """    let normalization = normalization_fixture(&execution)?;""",
        """    let raw_raster_bytes = fs::read(&execution.raster)?;
    decode_png_bytes(&raw_raster_bytes)
        .map_err(|error| format!("raw Inkscape PNG decode failed: {error}"))?;
    let normalization = normalization_fixture(&execution)?;""",
    ),
    (
        """    let decoded_normalized = decode_png_bytes(&normalized_bytes)?;
    let decoded_approved_logo = decode_png_bytes(&approved_logo_png)?;""",
        """    let decoded_normalized = decode_png_bytes(&normalized_bytes)
        .map_err(|error| format!("normalized PNG decode failed: {error}"))?;""",
    ),
]

for old, new in replacements:
    if old not in text:
        raise SystemExit(f"PNG diagnostic pattern not found: {old[:80]}")
    text = text.replace(old, new, 1)

TARGET.write_text(text, encoding="utf-8")
