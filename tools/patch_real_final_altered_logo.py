from pathlib import Path

TARGET = Path(
    "crates/graphic-inkscape-final-certified-delivery-runtime/"
    "tests/real_final_certified_delivery.rs"
)
text = TARGET.read_text(encoding="utf-8")
old = """    let altered_logo_png = encode_rgba_png(
        approved_logo.report.width,
        approved_logo.report.height,
        &altered_logo_pixels,
    )?;
    let altered_logo = decode_png_bytes(&altered_logo_png)?;"""
new = """    let altered_logo_png = strip_color_profile_chunks(&encode_rgba_png(
        approved_logo.report.width,
        approved_logo.report.height,
        &altered_logo_pixels,
    )?)?;
    let altered_logo = decode_png_bytes(&altered_logo_png)?;"""
if old not in text:
    raise SystemExit("altered-logo PNG pattern not found")
TARGET.write_text(text.replace(old, new, 1), encoding="utf-8")
