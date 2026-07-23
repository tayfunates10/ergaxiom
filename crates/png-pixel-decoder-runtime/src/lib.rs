#![forbid(unsafe_code)]

use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use ergaxiom_png_artifact_validator_runtime::{PngArtifactError, PngColorType, inspect_png_bytes};
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use flate2::bufread::ZlibDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const REPORT_SCHEMA: &str = "0.1.0";
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const MAX_PIXELS: u64 = 100_000_000;
const MAX_DECODED_SCANLINE_BYTES: usize = 512 * 1024 * 1024;
const MAX_IDAT_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PngPixelReport {
    pub schema_version: String,
    pub artifact_digest: String,
    pub validator_report_digest: String,
    pub width: u32,
    pub height: u32,
    pub color_type: PngColorType,
    pub bit_depth: u8,
    pub interlace_method: u8,
    pub bytes_per_pixel: u8,
    pub row_bytes: u64,
    pub pixel_count: u64,
    pub non_opaque_pixel_count: u64,
    pub idat_payload_digest: String,
    pub decompressed_scanline_digest: String,
    pub rgba_pixel_digest: String,
    pub filter_counts: [u64; 5],
    pub report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPng {
    pub report: PngPixelReport,
    pub rgba8: Vec<u8>,
}

impl DecodedPng {
    #[must_use]
    pub fn pixel(&self, x: u32, y: u32) -> Option<[u8; 4]> {
        if x >= self.report.width || y >= self.report.height {
            return None;
        }
        let width = usize::try_from(self.report.width).ok()?;
        let x = usize::try_from(x).ok()?;
        let y = usize::try_from(y).ok()?;
        let index = y.checked_mul(width)?.checked_add(x)?.checked_mul(4)?;
        let end = index.checked_add(4)?;
        let bytes = self.rgba8.get(index..end)?;
        Some([bytes[0], bytes[1], bytes[2], bytes[3]])
    }
}

#[derive(Debug, Error)]
pub enum PngPixelDecodeError {
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Png(#[from] PngArtifactError),
    #[error("pixel decoder supports only 8-bit PNGs; actual bit depth is {0}")]
    UnsupportedBitDepth(u8),
    #[error(
        "pixel decoder supports only truecolor and truecolor-alpha PNGs; actual color type is {0:?}"
    )]
    UnsupportedColorType(PngColorType),
    #[error("pixel decoder does not support interlaced PNGs")]
    UnsupportedInterlace,
    #[error("PNG pixel count exceeds the {MAX_PIXELS}-pixel decoder limit")]
    PixelLimitExceeded,
    #[error("PNG row or buffer size overflow")]
    SizeOverflow,
    #[error("PNG contains no IDAT payload")]
    MissingImageData,
    #[error("combined IDAT payload exceeds the {MAX_IDAT_PAYLOAD_BYTES}-byte decoder limit")]
    ImageDataLimitExceeded,
    #[error("zlib decompression failed: {0}")]
    Zlib(String),
    #[error("decompressed scanline stream exceeds the declared image size")]
    DecompressedDataLimitExceeded,
    #[error("decompressed scanline length mismatch: expected {expected}, actual {actual}")]
    DecompressedLengthMismatch { expected: usize, actual: usize },
    #[error("compressed IDAT payload contains bytes after the zlib stream")]
    TrailingCompressedData,
    #[error("PNG scanline uses unsupported filter type {0}")]
    InvalidFilter(u8),
    #[error("failed to serialize PNG pixel report: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn decode_png(path: impl AsRef<Path>) -> Result<DecodedPng, PngPixelDecodeError> {
    let bytes = fs::read(path)?;
    decode_png_bytes(&bytes)
}

pub fn decode_png_bytes(bytes: &[u8]) -> Result<DecodedPng, PngPixelDecodeError> {
    let structural = inspect_png_bytes(bytes)?;
    if structural.bit_depth != 8 {
        return Err(PngPixelDecodeError::UnsupportedBitDepth(
            structural.bit_depth,
        ));
    }
    if structural.interlace_method != 0 {
        return Err(PngPixelDecodeError::UnsupportedInterlace);
    }
    let bytes_per_pixel = match structural.color_type {
        PngColorType::Truecolor => 3_usize,
        PngColorType::TruecolorAlpha => 4_usize,
        actual => return Err(PngPixelDecodeError::UnsupportedColorType(actual)),
    };

    let pixel_count = u64::from(structural.width)
        .checked_mul(u64::from(structural.height))
        .ok_or(PngPixelDecodeError::SizeOverflow)?;
    if pixel_count > MAX_PIXELS {
        return Err(PngPixelDecodeError::PixelLimitExceeded);
    }
    let width = usize::try_from(structural.width).map_err(|_| PngPixelDecodeError::SizeOverflow)?;
    let height =
        usize::try_from(structural.height).map_err(|_| PngPixelDecodeError::SizeOverflow)?;
    let row_bytes = width
        .checked_mul(bytes_per_pixel)
        .ok_or(PngPixelDecodeError::SizeOverflow)?;
    let scanline_bytes = row_bytes
        .checked_add(1)
        .and_then(|row| row.checked_mul(height))
        .ok_or(PngPixelDecodeError::SizeOverflow)?;
    if scanline_bytes > MAX_DECODED_SCANLINE_BYTES {
        return Err(PngPixelDecodeError::DecompressedDataLimitExceeded);
    }

    let idat = collect_idat_payload(bytes)?;
    let scanlines = decompress_exact(&idat, scanline_bytes)?;
    let (unfiltered, filter_counts) =
        unfilter_scanlines(&scanlines, width, height, bytes_per_pixel, row_bytes)?;
    let rgba8 = convert_to_rgba(&unfiltered, structural.color_type, pixel_count)?;
    let non_opaque_pixel_count = rgba8
        .chunks_exact(4)
        .filter(|pixel| pixel[3] != 255)
        .count() as u64;

    let mut report = PngPixelReport {
        schema_version: REPORT_SCHEMA.to_owned(),
        artifact_digest: structural.artifact_digest,
        validator_report_digest: structural.report_digest,
        width: structural.width,
        height: structural.height,
        color_type: structural.color_type,
        bit_depth: structural.bit_depth,
        interlace_method: structural.interlace_method,
        bytes_per_pixel: u8::try_from(bytes_per_pixel)
            .map_err(|_| PngPixelDecodeError::SizeOverflow)?,
        row_bytes: u64::try_from(row_bytes).map_err(|_| PngPixelDecodeError::SizeOverflow)?,
        pixel_count,
        non_opaque_pixel_count,
        idat_payload_digest: sha256_hex(&idat),
        decompressed_scanline_digest: sha256_hex(&scanlines),
        rgba_pixel_digest: sha256_hex(&rgba8),
        filter_counts,
        report_digest: String::new(),
    };
    report.report_digest = report_digest(&report)?;
    Ok(DecodedPng { report, rgba8 })
}

fn collect_idat_payload(bytes: &[u8]) -> Result<Vec<u8>, PngPixelDecodeError> {
    if bytes.len() < PNG_SIGNATURE.len() || &bytes[..PNG_SIGNATURE.len()] != PNG_SIGNATURE {
        return Err(PngPixelDecodeError::Png(PngArtifactError::InvalidSignature));
    }
    let mut offset = PNG_SIGNATURE.len();
    let mut idat = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err(PngPixelDecodeError::Png(PngArtifactError::TruncatedChunk));
        }
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| PngArtifactError::TruncatedChunk)?,
        );
        let length = usize::try_from(length).map_err(|_| PngPixelDecodeError::SizeOverflow)?;
        let data_start = offset
            .checked_add(8)
            .ok_or(PngPixelDecodeError::SizeOverflow)?;
        let data_end = data_start
            .checked_add(length)
            .ok_or(PngPixelDecodeError::SizeOverflow)?;
        let chunk_end = data_end
            .checked_add(4)
            .ok_or(PngPixelDecodeError::SizeOverflow)?;
        if chunk_end > bytes.len() {
            return Err(PngPixelDecodeError::Png(PngArtifactError::TruncatedChunk));
        }
        if &bytes[offset + 4..offset + 8] == b"IDAT" {
            let next_len = idat
                .len()
                .checked_add(length)
                .ok_or(PngPixelDecodeError::SizeOverflow)?;
            if next_len > MAX_IDAT_PAYLOAD_BYTES {
                return Err(PngPixelDecodeError::ImageDataLimitExceeded);
            }
            idat.extend_from_slice(&bytes[data_start..data_end]);
        }
        offset = chunk_end;
    }
    if idat.is_empty() {
        return Err(PngPixelDecodeError::MissingImageData);
    }
    Ok(idat)
}

fn decompress_exact(idat: &[u8], expected_len: usize) -> Result<Vec<u8>, PngPixelDecodeError> {
    let cursor = Cursor::new(idat);
    let mut decoder = ZlibDecoder::new(cursor);
    let limit = u64::try_from(expected_len)
        .map_err(|_| PngPixelDecodeError::SizeOverflow)?
        .checked_add(1)
        .ok_or(PngPixelDecodeError::SizeOverflow)?;
    let mut output = Vec::with_capacity(expected_len);
    decoder
        .by_ref()
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|error| PngPixelDecodeError::Zlib(error.to_string()))?;
    if output.len() > expected_len {
        return Err(PngPixelDecodeError::DecompressedDataLimitExceeded);
    }
    if output.len() != expected_len {
        return Err(PngPixelDecodeError::DecompressedLengthMismatch {
            expected: expected_len,
            actual: output.len(),
        });
    }
    let consumed =
        usize::try_from(decoder.total_in()).map_err(|_| PngPixelDecodeError::SizeOverflow)?;
    if consumed != idat.len() {
        return Err(PngPixelDecodeError::TrailingCompressedData);
    }
    Ok(output)
}

fn unfilter_scanlines(
    scanlines: &[u8],
    width: usize,
    height: usize,
    bytes_per_pixel: usize,
    row_bytes: usize,
) -> Result<(Vec<u8>, [u64; 5]), PngPixelDecodeError> {
    let expected_row_bytes = width
        .checked_mul(bytes_per_pixel)
        .ok_or(PngPixelDecodeError::SizeOverflow)?;
    if expected_row_bytes != row_bytes {
        return Err(PngPixelDecodeError::SizeOverflow);
    }
    let mut output = Vec::with_capacity(
        row_bytes
            .checked_mul(height)
            .ok_or(PngPixelDecodeError::SizeOverflow)?,
    );
    let mut previous = vec![0_u8; row_bytes];
    let mut current = vec![0_u8; row_bytes];
    let mut filter_counts = [0_u64; 5];

    for row in 0..height {
        let source_start = row
            .checked_mul(row_bytes + 1)
            .ok_or(PngPixelDecodeError::SizeOverflow)?;
        let filter = scanlines[source_start];
        if filter > 4 {
            return Err(PngPixelDecodeError::InvalidFilter(filter));
        }
        filter_counts[usize::from(filter)] = filter_counts[usize::from(filter)].saturating_add(1);
        let filtered = &scanlines[source_start + 1..source_start + 1 + row_bytes];
        for index in 0..row_bytes {
            let left = if index >= bytes_per_pixel {
                current[index - bytes_per_pixel]
            } else {
                0
            };
            let up = previous[index];
            let upper_left = if index >= bytes_per_pixel {
                previous[index - bytes_per_pixel]
            } else {
                0
            };
            let predictor = match filter {
                0 => 0,
                1 => left,
                2 => up,
                3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
                4 => paeth(left, up, upper_left),
                _ => return Err(PngPixelDecodeError::InvalidFilter(filter)),
            };
            current[index] = filtered[index].wrapping_add(predictor);
        }
        output.extend_from_slice(&current);
        std::mem::swap(&mut previous, &mut current);
        current.fill(0);
    }
    Ok((output, filter_counts))
}

fn convert_to_rgba(
    unfiltered: &[u8],
    color_type: PngColorType,
    pixel_count: u64,
) -> Result<Vec<u8>, PngPixelDecodeError> {
    let output_len = usize::try_from(pixel_count)
        .map_err(|_| PngPixelDecodeError::SizeOverflow)?
        .checked_mul(4)
        .ok_or(PngPixelDecodeError::SizeOverflow)?;
    let mut rgba = Vec::with_capacity(output_len);
    match color_type {
        PngColorType::Truecolor => {
            for pixel in unfiltered.chunks_exact(3) {
                rgba.extend_from_slice(&[pixel[0], pixel[1], pixel[2], 255]);
            }
        }
        PngColorType::TruecolorAlpha => rgba.extend_from_slice(unfiltered),
        actual => return Err(PngPixelDecodeError::UnsupportedColorType(actual)),
    }
    if rgba.len() != output_len {
        return Err(PngPixelDecodeError::SizeOverflow);
    }
    Ok(rgba)
}

fn paeth(left: u8, up: u8, upper_left: u8) -> u8 {
    let left = i32::from(left);
    let up = i32::from(up);
    let upper_left = i32::from(upper_left);
    let estimate = left + up - upper_left;
    let left_distance = (estimate - left).abs();
    let up_distance = (estimate - up).abs();
    let upper_left_distance = (estimate - upper_left).abs();
    if left_distance <= up_distance && left_distance <= upper_left_distance {
        left as u8
    } else if up_distance <= upper_left_distance {
        up as u8
    } else {
        upper_left as u8
    }
}

fn report_digest(report: &PngPixelReport) -> Result<String, PngPixelDecodeError> {
    let mut value = serde_json::to_value(report)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other("pixel report is not an object"))
    })?;
    object.insert(
        "report_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::paeth;

    #[test]
    fn paeth_predictor_uses_the_nearest_candidate() {
        assert_eq!(paeth(10, 20, 15), 15);
        assert_eq!(paeth(100, 10, 0), 100);
        assert_eq!(paeth(10, 100, 0), 100);
    }
}
