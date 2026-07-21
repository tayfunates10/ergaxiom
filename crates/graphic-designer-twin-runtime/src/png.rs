use thiserror::Error;

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const PROFILE_NAME: &str = "sRGB IEC61966-2.1";

#[derive(Debug, Error)]
pub enum PngError {
    #[error("PNG dimensions must be positive")]
    InvalidDimensions,
    #[error("RGBA buffer length does not match dimensions")]
    InvalidPixelLength,
    #[error("PNG signature is invalid")]
    InvalidSignature,
    #[error("PNG chunk is truncated")]
    TruncatedChunk,
    #[error("PNG chunk CRC mismatch for {0}")]
    CrcMismatch(String),
    #[error("required PNG chunk is missing: {0}")]
    MissingChunk(&'static str),
    #[error("unsupported PNG format")]
    UnsupportedFormat,
    #[error("zlib stream is invalid")]
    InvalidZlib,
    #[error("PNG scanline data is invalid")]
    InvalidScanlines,
    #[error("embedded ICC profile is invalid")]
    InvalidIccProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPng {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
    pub profile_name: String,
    pub profile_description: String,
    pub has_srgb_chunk: bool,
}

pub fn encode_rgba_png(width: u32, height: u32, pixels: &[u8]) -> Result<Vec<u8>, PngError> {
    if width == 0 || height == 0 {
        return Err(PngError::InvalidDimensions);
    }
    let expected = usize::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(usize::try_from(height).ok()?))
        .and_then(|value| value.checked_mul(4))
        .ok_or(PngError::InvalidPixelLength)?;
    if pixels.len() != expected {
        return Err(PngError::InvalidPixelLength);
    }

    let mut png = Vec::new();
    png.extend_from_slice(PNG_SIGNATURE);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    push_chunk(&mut png, b"IHDR", &ihdr);
    push_chunk(&mut png, b"sRGB", &[0]);

    let profile = minimal_srgb_profile();
    let mut iccp = Vec::new();
    iccp.extend_from_slice(PROFILE_NAME.as_bytes());
    iccp.push(0);
    iccp.push(0);
    iccp.extend_from_slice(&zlib_store(&profile));
    push_chunk(&mut png, b"iCCP", &iccp);

    let row_bytes = usize::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(PngError::InvalidPixelLength)?;
    let mut scanlines = Vec::with_capacity(expected + usize::try_from(height).unwrap_or(0));
    for row in pixels.chunks_exact(row_bytes) {
        scanlines.push(0);
        scanlines.extend_from_slice(row);
    }
    push_chunk(&mut png, b"IDAT", &zlib_store(&scanlines));
    push_chunk(&mut png, b"IEND", &[]);
    Ok(png)
}

pub fn decode_rgba_png(bytes: &[u8]) -> Result<DecodedPng, PngError> {
    if bytes.get(..8) != Some(PNG_SIGNATURE.as_slice()) {
        return Err(PngError::InvalidSignature);
    }
    let mut cursor = 8_usize;
    let mut width = None;
    let mut height = None;
    let mut idat = Vec::new();
    let mut profile_name = None;
    let mut profile_description = None;
    let mut has_srgb_chunk = false;
    let mut saw_iend = false;

    while cursor < bytes.len() {
        if cursor.checked_add(12).is_none_or(|end| end > bytes.len()) {
            return Err(PngError::TruncatedChunk);
        }
        let length = u32::from_be_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| PngError::TruncatedChunk)?,
        ) as usize;
        let chunk_type = &bytes[cursor + 4..cursor + 8];
        let data_start = cursor + 8;
        let data_end = data_start
            .checked_add(length)
            .ok_or(PngError::TruncatedChunk)?;
        let crc_end = data_end.checked_add(4).ok_or(PngError::TruncatedChunk)?;
        if crc_end > bytes.len() {
            return Err(PngError::TruncatedChunk);
        }
        let data = &bytes[data_start..data_end];
        let declared_crc = u32::from_be_bytes(
            bytes[data_end..crc_end]
                .try_into()
                .map_err(|_| PngError::TruncatedChunk)?,
        );
        let mut crc_input = Vec::with_capacity(4 + data.len());
        crc_input.extend_from_slice(chunk_type);
        crc_input.extend_from_slice(data);
        if crc32(&crc_input) != declared_crc {
            return Err(PngError::CrcMismatch(
                String::from_utf8_lossy(chunk_type).into_owned(),
            ));
        }

        match chunk_type {
            b"IHDR" => {
                if data.len() != 13 || data[8..] != [8, 6, 0, 0, 0] {
                    return Err(PngError::UnsupportedFormat);
                }
                width = Some(u32::from_be_bytes(
                    data[0..4]
                        .try_into()
                        .map_err(|_| PngError::UnsupportedFormat)?,
                ));
                height = Some(u32::from_be_bytes(
                    data[4..8]
                        .try_into()
                        .map_err(|_| PngError::UnsupportedFormat)?,
                ));
            }
            b"sRGB" => {
                if data.len() != 1 {
                    return Err(PngError::UnsupportedFormat);
                }
                has_srgb_chunk = true;
            }
            b"iCCP" => {
                let zero = data
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or(PngError::InvalidIccProfile)?;
                if zero == 0 || data.get(zero + 1) != Some(&0) {
                    return Err(PngError::InvalidIccProfile);
                }
                let name =
                    std::str::from_utf8(&data[..zero]).map_err(|_| PngError::InvalidIccProfile)?;
                let compressed = data.get(zero + 2..).ok_or(PngError::InvalidIccProfile)?;
                let profile = zlib_unstore(compressed)?;
                profile_name = Some(name.to_owned());
                profile_description = Some(parse_icc_description(&profile)?);
            }
            b"IDAT" => idat.extend_from_slice(data),
            b"IEND" => {
                saw_iend = true;
                break;
            }
            _ => {}
        }
        cursor = crc_end;
    }

    if !saw_iend {
        return Err(PngError::MissingChunk("IEND"));
    }
    let width = width.ok_or(PngError::MissingChunk("IHDR"))?;
    let height = height.ok_or(PngError::MissingChunk("IHDR"))?;
    if width == 0 || height == 0 {
        return Err(PngError::InvalidDimensions);
    }
    let profile_name = profile_name.ok_or(PngError::MissingChunk("iCCP"))?;
    let profile_description = profile_description.ok_or(PngError::MissingChunk("iCCP"))?;
    if idat.is_empty() {
        return Err(PngError::MissingChunk("IDAT"));
    }
    let scanlines = zlib_unstore(&idat)?;
    let row_bytes = usize::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(PngError::InvalidScanlines)?;
    let expected_scanlines = row_bytes
        .checked_add(1)
        .and_then(|value| value.checked_mul(usize::try_from(height).ok()?))
        .ok_or(PngError::InvalidScanlines)?;
    if scanlines.len() != expected_scanlines {
        return Err(PngError::InvalidScanlines);
    }
    let mut pixels = Vec::with_capacity(row_bytes * usize::try_from(height).unwrap_or(0));
    for row in scanlines.chunks_exact(row_bytes + 1) {
        if row[0] != 0 {
            return Err(PngError::UnsupportedFormat);
        }
        pixels.extend_from_slice(&row[1..]);
    }

    Ok(DecodedPng {
        width,
        height,
        pixels,
        profile_name,
        profile_description,
        has_srgb_chunk,
    })
}

fn push_chunk(target: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    target.extend_from_slice(&(data.len() as u32).to_be_bytes());
    target.extend_from_slice(chunk_type);
    target.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(chunk_type);
    crc_input.extend_from_slice(data);
    target.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1_u32;
    let mut b = 0_u32;
    for byte in bytes {
        a = (a + u32::from(*byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

fn zlib_store(bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![0x78, 0x01];
    if bytes.is_empty() {
        output.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    } else {
        let chunks = bytes.chunks(65_535);
        let chunk_count = chunks.len();
        for (index, chunk) in bytes.chunks(65_535).enumerate() {
            output.push(if index + 1 == chunk_count { 1 } else { 0 });
            let length = chunk.len() as u16;
            output.extend_from_slice(&length.to_le_bytes());
            output.extend_from_slice(&(!length).to_le_bytes());
            output.extend_from_slice(chunk);
        }
    }
    output.extend_from_slice(&adler32(bytes).to_be_bytes());
    output
}

fn zlib_unstore(bytes: &[u8]) -> Result<Vec<u8>, PngError> {
    if bytes.len() < 11 || (u16::from(bytes[0]) << 8 | u16::from(bytes[1])) % 31 != 0 {
        return Err(PngError::InvalidZlib);
    }
    let mut cursor = 2_usize;
    let mut output = Vec::new();
    loop {
        let header = *bytes.get(cursor).ok_or(PngError::InvalidZlib)?;
        cursor += 1;
        if header & 0b110 != 0 {
            return Err(PngError::InvalidZlib);
        }
        let final_block = header & 1 == 1;
        let length_bytes = bytes.get(cursor..cursor + 2).ok_or(PngError::InvalidZlib)?;
        let inverse_bytes = bytes
            .get(cursor + 2..cursor + 4)
            .ok_or(PngError::InvalidZlib)?;
        let length =
            u16::from_le_bytes(length_bytes.try_into().map_err(|_| PngError::InvalidZlib)?);
        let inverse = u16::from_le_bytes(
            inverse_bytes
                .try_into()
                .map_err(|_| PngError::InvalidZlib)?,
        );
        if inverse != !length {
            return Err(PngError::InvalidZlib);
        }
        cursor += 4;
        let end = cursor
            .checked_add(usize::from(length))
            .ok_or(PngError::InvalidZlib)?;
        output.extend_from_slice(bytes.get(cursor..end).ok_or(PngError::InvalidZlib)?);
        cursor = end;
        if final_block {
            break;
        }
    }
    let declared_adler = u32::from_be_bytes(
        bytes
            .get(cursor..cursor + 4)
            .ok_or(PngError::InvalidZlib)?
            .try_into()
            .map_err(|_| PngError::InvalidZlib)?,
    );
    if cursor + 4 != bytes.len() || adler32(&output) != declared_adler {
        return Err(PngError::InvalidZlib);
    }
    Ok(output)
}

fn minimal_srgb_profile() -> Vec<u8> {
    let description = format!("{PROFILE_NAME}\0");
    let mut desc = Vec::new();
    desc.extend_from_slice(b"desc");
    desc.extend_from_slice(&[0; 4]);
    desc.extend_from_slice(&(description.len() as u32).to_be_bytes());
    desc.extend_from_slice(description.as_bytes());
    while desc.len() % 4 != 0 {
        desc.push(0);
    }

    let profile_size = 144 + desc.len();
    let mut profile = vec![0_u8; 144];
    profile[0..4].copy_from_slice(&(profile_size as u32).to_be_bytes());
    profile[8..12].copy_from_slice(&0x0210_0000_u32.to_be_bytes());
    profile[12..16].copy_from_slice(b"mntr");
    profile[16..20].copy_from_slice(b"RGB ");
    profile[20..24].copy_from_slice(b"XYZ ");
    profile[24..26].copy_from_slice(&2026_u16.to_be_bytes());
    profile[26..28].copy_from_slice(&7_u16.to_be_bytes());
    profile[28..30].copy_from_slice(&21_u16.to_be_bytes());
    profile[30..32].copy_from_slice(&12_u16.to_be_bytes());
    profile[32..34].copy_from_slice(&0_u16.to_be_bytes());
    profile[34..36].copy_from_slice(&0_u16.to_be_bytes());
    profile[36..40].copy_from_slice(b"acsp");
    profile[40..44].copy_from_slice(b"MSFT");
    profile[48..52].copy_from_slice(b"ERGX");
    profile[52..56].copy_from_slice(b"sRGB");
    profile[68..72].copy_from_slice(&0x0000_f6d6_u32.to_be_bytes());
    profile[72..76].copy_from_slice(&0x0001_0000_u32.to_be_bytes());
    profile[76..80].copy_from_slice(&0x0000_d32d_u32.to_be_bytes());
    profile[80..84].copy_from_slice(b"ERGX");
    profile[128..132].copy_from_slice(&1_u32.to_be_bytes());
    profile[132..136].copy_from_slice(b"desc");
    profile[136..140].copy_from_slice(&144_u32.to_be_bytes());
    profile[140..144].copy_from_slice(&(desc.len() as u32).to_be_bytes());
    profile.extend_from_slice(&desc);
    profile
}

fn parse_icc_description(profile: &[u8]) -> Result<String, PngError> {
    if profile.len() < 144
        || profile.get(36..40) != Some(b"acsp".as_slice())
        || profile.get(16..20) != Some(b"RGB ".as_slice())
        || profile.get(20..24) != Some(b"XYZ ".as_slice())
    {
        return Err(PngError::InvalidIccProfile);
    }
    let declared_size = u32::from_be_bytes(
        profile[0..4]
            .try_into()
            .map_err(|_| PngError::InvalidIccProfile)?,
    ) as usize;
    if declared_size != profile.len() {
        return Err(PngError::InvalidIccProfile);
    }
    let tag_count = u32::from_be_bytes(
        profile[128..132]
            .try_into()
            .map_err(|_| PngError::InvalidIccProfile)?,
    ) as usize;
    for index in 0..tag_count {
        let entry = 132 + index * 12;
        if entry + 12 > profile.len() {
            return Err(PngError::InvalidIccProfile);
        }
        if &profile[entry..entry + 4] != b"desc" {
            continue;
        }
        let offset = u32::from_be_bytes(
            profile[entry + 4..entry + 8]
                .try_into()
                .map_err(|_| PngError::InvalidIccProfile)?,
        ) as usize;
        let size = u32::from_be_bytes(
            profile[entry + 8..entry + 12]
                .try_into()
                .map_err(|_| PngError::InvalidIccProfile)?,
        ) as usize;
        let data = profile
            .get(offset..offset + size)
            .ok_or(PngError::InvalidIccProfile)?;
        if data.len() < 12 || &data[0..4] != b"desc" {
            return Err(PngError::InvalidIccProfile);
        }
        let count = u32::from_be_bytes(
            data[8..12]
                .try_into()
                .map_err(|_| PngError::InvalidIccProfile)?,
        ) as usize;
        let text = data
            .get(12..12 + count)
            .ok_or(PngError::InvalidIccProfile)?;
        let text = text.strip_suffix(&[0]).unwrap_or(text);
        return std::str::from_utf8(text)
            .map(str::to_owned)
            .map_err(|_| PngError::InvalidIccProfile);
    }
    Err(PngError::InvalidIccProfile)
}
