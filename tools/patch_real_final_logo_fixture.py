from pathlib import Path

TARGET = Path(
    "crates/graphic-inkscape-final-certified-delivery-runtime/"
    "tests/real_final_certified_delivery.rs"
)

text = TARGET.read_text(encoding="utf-8")
if "fn strip_color_profile_chunks" in text:
    raise SystemExit(0)

old = """    Ok(encode_rgba_png(20, 10, &pixels)?)
}

fn real_fixture_svg(text: &str) -> String {"""
new = """    let png = encode_rgba_png(20, 10, &pixels)?;
    strip_color_profile_chunks(&png)
}

fn strip_color_profile_chunks(png: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    const SIGNATURE: &[u8; 8] = b"\\x89PNG\\r\\n\\x1a\\n";
    if png.get(..SIGNATURE.len()) != Some(SIGNATURE.as_slice()) {
        return Err("approved-logo PNG signature is invalid".into());
    }

    let mut output = png[..SIGNATURE.len()].to_vec();
    let mut offset = SIGNATURE.len();
    while offset < png.len() {
        if png.len().saturating_sub(offset) < 12 {
            return Err("approved-logo PNG chunk is truncated".into());
        }
        let length = u32::from_be_bytes(
            png[offset..offset + 4]
                .try_into()
                .map_err(|_| "approved-logo PNG length is truncated")?,
        ) as usize;
        let chunk_end = offset
            .checked_add(12)
            .and_then(|value| value.checked_add(length))
            .ok_or("approved-logo PNG chunk length overflow")?;
        if chunk_end > png.len() {
            return Err("approved-logo PNG chunk exceeds file length".into());
        }
        let chunk_type = &png[offset + 4..offset + 8];
        if chunk_type != b"sRGB" && chunk_type != b"iCCP" {
            output.extend_from_slice(&png[offset..chunk_end]);
        }
        offset = chunk_end;
    }
    Ok(output)
}

fn real_fixture_svg(text: &str) -> String {"""

if old not in text:
    raise SystemExit("approved-logo generator pattern not found")

TARGET.write_text(text.replace(old, new, 1), encoding="utf-8")
