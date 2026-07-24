use std::io::{Cursor, Read};

use flate2::bufread::ZlibDecoder;
use thiserror::Error;

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const MAX_PIXELS: u64 = 100_000_000;
const MAX_IDAT_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestrictedRgbaPng {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
    pub has_srgb: bool,
}

#[derive(Debug, Error)]
pub enum RestrictedPngError {
    #[error("PNG signature is invalid")]
    InvalidSignature,
    #[error("PNG chunk is truncated")]
    TruncatedChunk,
    #[error("PNG chunk CRC mismatch for {0}")]
    CrcMismatch(String),
    #[error("PNG must contain exactly one valid IHDR chunk")]
    InvalidHeader,
    #[error("restricted cleanup PNGs must be 8-bit, non-interlaced RGBA")]
    UnsupportedFormat,
    #[error("restricted cleanup PNG has invalid dimensions")]
    InvalidDimensions,
    #[error("PNG pixel count exceeds the certified limit")]
    PixelLimitExceeded,
    #[error("PNG image-data payload is missing or exceeds the certified limit")]
    InvalidImageData,
    #[error("zlib decompression failed: {0}")]
    Zlib(String),
    #[error("decompressed PNG scanline length does not match the declared dimensions")]
    ScanlineLengthMismatch,
    #[error("restricted cleanup PNGs must use filter type 0 for every scanline")]
    UnsupportedFilter,
    #[error("RGBA buffer length does not match the declared dimensions")]
    InvalidPixelLength,
    #[error("PNG buffer arithmetic overflow")]
    SizeOverflow,
}

pub(crate) fn decode_restricted_rgba_png(
    bytes: &[u8],
) -> Result<RestrictedRgbaPng, RestrictedPngError> {
    if bytes.get(..PNG_SIGNATURE.len()) != Some(PNG_SIGNATURE.as_slice()) {
        return Err(RestrictedPngError::InvalidSignature);
    }
    let mut offset = PNG_SIGNATURE.len();
    let mut width = None;
    let mut height = None;
    let mut idat = Vec::new();
    let mut has_srgb = false;
    let mut saw_iend = false;

    while offset < bytes.len() {
        if bytes.len().saturating_sub(offset) < 12 {
            return Err(RestrictedPngError::TruncatedChunk);
        }
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| RestrictedPngError::TruncatedChunk)?,
        );
        let length = usize::try_from(length).map_err(|_| RestrictedPngError::SizeOverflow)?;
        let data_start = offset
            .checked_add(8)
            .ok_or(RestrictedPngError::SizeOverflow)?;
        let data_end = data_start
            .checked_add(length)
            .ok_or(RestrictedPngError::SizeOverflow)?;
        let chunk_end = data_end
            .checked_add(4)
            .ok_or(RestrictedPngError::SizeOverflow)?;
        if chunk_end > bytes.len() {
            return Err(RestrictedPngError::TruncatedChunk);
        }
        let chunk_type = &bytes[offset + 4..offset + 8];
        let data = &bytes[data_start..data_end];
        let declared_crc = u32::from_be_bytes(
            bytes[data_end..chunk_end]
                .try_into()
                .map_err(|_| RestrictedPngError::TruncatedChunk)?,
        );
        if crc32_pair(chunk_type, data) != declared_crc {
            return Err(RestrictedPngError::CrcMismatch(
                String::from_utf8_lossy(chunk_type).into_owned(),
            ));
        }

        match chunk_type {
            b"IHDR" => {
                if width.is_some() || data.len() != 13 || data[8..] != [8, 6, 0, 0, 0] {
                    return Err(RestrictedPngError::InvalidHeader);
                }
                width = Some(u32::from_be_bytes(
                    data[0..4]
                        .try_into()
                        .map_err(|_| RestrictedPngError::InvalidHeader)?,
                ));
                height = Some(u32::from_be_bytes(
                    data[4..8]
                        .try_into()
                        .map_err(|_| RestrictedPngError::InvalidHeader)?,
                ));
            }
            b"sRGB" => {
                if data.len() != 1 || has_srgb {
                    return Err(RestrictedPngError::UnsupportedFormat);
                }
                has_srgb = true;
            }
            b"IDAT" => {
                let next_len = idat
                    .len()
                    .checked_add(data.len())
                    .ok_or(RestrictedPngError::SizeOverflow)?;
                if next_len > MAX_IDAT_BYTES {
                    return Err(RestrictedPngError::InvalidImageData);
                }
                idat.extend_from_slice(data);
            }
            b"IEND" => {
                if !data.is_empty() {
                    return Err(RestrictedPngError::TruncatedChunk);
                }
                saw_iend = true;
                break;
            }
            _ => {}
        }
        offset = chunk_end;
    }

    if !saw_iend || idat.is_empty() {
        return Err(RestrictedPngError::InvalidImageData);
    }
    let width = width.ok_or(RestrictedPngError::InvalidHeader)?;
    let height = height.ok_or(RestrictedPngError::InvalidHeader)?;
    if width == 0 || height == 0 {
        return Err(RestrictedPngError::InvalidDimensions);
    }
    let pixel_count = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(RestrictedPngError::SizeOverflow)?;
    if pixel_count > MAX_PIXELS {
        return Err(RestrictedPngError::PixelLimitExceeded);
    }
    let row_bytes = usize::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(RestrictedPngError::SizeOverflow)?;
    let scanline_len = row_bytes
        .checked_add(1)
        .and_then(|value| value.checked_mul(usize::try_from(height).ok()?))
        .ok_or(RestrictedPngError::SizeOverflow)?;

    let mut decoder = ZlibDecoder::new(Cursor::new(&idat));
    let mut scanlines = Vec::with_capacity(scanline_len);
    decoder
        .read_to_end(&mut scanlines)
        .map_err(|error| RestrictedPngError::Zlib(error.to_string()))?;
    if scanlines.len() != scanline_len {
        return Err(RestrictedPngError::ScanlineLengthMismatch);
    }
    let mut pixels = Vec::with_capacity(
        row_bytes
            .checked_mul(usize::try_from(height).map_err(|_| RestrictedPngError::SizeOverflow)?)
            .ok_or(RestrictedPngError::SizeOverflow)?,
    );
    for row in scanlines.chunks_exact(row_bytes + 1) {
        if row[0] != 0 {
            return Err(RestrictedPngError::UnsupportedFilter);
        }
        pixels.extend_from_slice(&row[1..]);
    }

    Ok(RestrictedRgbaPng {
        width,
        height,
        pixels,
        has_srgb,
    })
}

pub fn encode_restricted_srgb_rgba_png(
    width: u32,
    height: u32,
    pixels: &[u8],
) -> Result<Vec<u8>, RestrictedPngError> {
    if width == 0 || height == 0 {
        return Err(RestrictedPngError::InvalidDimensions);
    }
    let expected = usize::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(usize::try_from(height).ok()?))
        .and_then(|value| value.checked_mul(4))
        .ok_or(RestrictedPngError::SizeOverflow)?;
    if pixels.len() != expected {
        return Err(RestrictedPngError::InvalidPixelLength);
    }

    let mut output = Vec::new();
    output.extend_from_slice(PNG_SIGNATURE);
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    push_chunk(&mut output, b"IHDR", &ihdr)?;
    push_chunk(&mut output, b"sRGB", &[0])?;

    let row_bytes = usize::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(RestrictedPngError::SizeOverflow)?;
    let mut scanlines = Vec::with_capacity(
        pixels
            .len()
            .checked_add(usize::try_from(height).map_err(|_| RestrictedPngError::SizeOverflow)?)
            .ok_or(RestrictedPngError::SizeOverflow)?,
    );
    for row in pixels.chunks_exact(row_bytes) {
        scanlines.push(0);
        scanlines.extend_from_slice(row);
    }
    let compressed = zlib_store(&scanlines)?;
    push_chunk(&mut output, b"IDAT", &compressed)?;
    push_chunk(&mut output, b"IEND", &[])?;
    Ok(output)
}

fn push_chunk(
    output: &mut Vec<u8>,
    chunk_type: &[u8; 4],
    data: &[u8],
) -> Result<(), RestrictedPngError> {
    let length = u32::try_from(data.len()).map_err(|_| RestrictedPngError::SizeOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(chunk_type);
    output.extend_from_slice(data);
    output.extend_from_slice(&crc32_pair(chunk_type, data).to_be_bytes());
    Ok(())
}

fn zlib_store(bytes: &[u8]) -> Result<Vec<u8>, RestrictedPngError> {
    let mut output = vec![0x78, 0x01];
    if bytes.is_empty() {
        output.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    } else {
        let chunk_count = bytes.chunks(65_535).len();
        for (index, chunk) in bytes.chunks(65_535).enumerate() {
            output.push(if index + 1 == chunk_count { 1 } else { 0 });
            let length =
                u16::try_from(chunk.len()).map_err(|_| RestrictedPngError::SizeOverflow)?;
            output.extend_from_slice(&length.to_le_bytes());
            output.extend_from_slice(&(!length).to_le_bytes());
            output.extend_from_slice(chunk);
        }
    }
    output.extend_from_slice(&adler32(bytes).to_be_bytes());
    Ok(output)
}

fn crc32_pair(chunk_type: &[u8], data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in chunk_type.iter().chain(data.iter()) {
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
