use std::fs;
use std::io;
use std::path::Path;

const ICON_SIZE: u8 = 32;
const ICON_PIXELS: usize = usize::from(ICON_SIZE) * usize::from(ICON_SIZE);
const XOR_BYTES: usize = ICON_PIXELS * 4;
const AND_ROW_BYTES: usize = usize::from(ICON_SIZE).div_ceil(32) * 4;
const AND_BYTES: usize = AND_ROW_BYTES * usize::from(ICON_SIZE);
const BITMAP_HEADER_BYTES: usize = 40;
const IMAGE_BYTES: usize = BITMAP_HEADER_BYTES + XOR_BYTES + AND_BYTES;
const IMAGE_OFFSET: u32 = 6 + 16;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    write_deterministic_windows_icon(Path::new("icons/icon.ico"))?;
    tauri_build::build();
    Ok(())
}

fn write_deterministic_windows_icon(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut icon = Vec::with_capacity(usize::try_from(IMAGE_OFFSET).unwrap_or(22) + IMAGE_BYTES);
    icon.extend_from_slice(&0_u16.to_le_bytes());
    icon.extend_from_slice(&1_u16.to_le_bytes());
    icon.extend_from_slice(&1_u16.to_le_bytes());

    icon.push(ICON_SIZE);
    icon.push(ICON_SIZE);
    icon.push(0);
    icon.push(0);
    icon.extend_from_slice(&1_u16.to_le_bytes());
    icon.extend_from_slice(&32_u16.to_le_bytes());
    icon.extend_from_slice(&(IMAGE_BYTES as u32).to_le_bytes());
    icon.extend_from_slice(&IMAGE_OFFSET.to_le_bytes());

    icon.extend_from_slice(&(BITMAP_HEADER_BYTES as u32).to_le_bytes());
    icon.extend_from_slice(&i32::from(ICON_SIZE).to_le_bytes());
    icon.extend_from_slice(&(i32::from(ICON_SIZE) * 2).to_le_bytes());
    icon.extend_from_slice(&1_u16.to_le_bytes());
    icon.extend_from_slice(&32_u16.to_le_bytes());
    icon.extend_from_slice(&0_u32.to_le_bytes());
    icon.extend_from_slice(&((XOR_BYTES + AND_BYTES) as u32).to_le_bytes());
    icon.extend_from_slice(&0_i32.to_le_bytes());
    icon.extend_from_slice(&0_i32.to_le_bytes());
    icon.extend_from_slice(&0_u32.to_le_bytes());
    icon.extend_from_slice(&0_u32.to_le_bytes());

    for stored_y in 0..usize::from(ICON_SIZE) {
        let y = usize::from(ICON_SIZE) - 1 - stored_y;
        for x in 0..usize::from(ICON_SIZE) {
            let mark = (8..=12).contains(&x) && (6..=25).contains(&y)
                || (8..=24).contains(&x) && (6..=10).contains(&y)
                || (8..=21).contains(&x) && (14..=18).contains(&y)
                || (8..=24).contains(&x) && (22..=26).contains(&y);
            let pixel = if mark {
                [0xff, 0xf4, 0xed, 0xff]
            } else {
                [0x1f, 0x11, 0x07, 0xff]
            };
            icon.extend_from_slice(&pixel);
        }
    }
    icon.resize(icon.len() + AND_BYTES, 0);

    fs::write(path, icon)
}
