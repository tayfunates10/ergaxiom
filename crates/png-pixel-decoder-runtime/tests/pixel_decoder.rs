use std::error::Error;
use std::io::Write;

use ergaxiom_png_artifact_validator_runtime::PngColorType;
use ergaxiom_png_pixel_decoder_runtime::{PngPixelDecodeError, decode_png_bytes};
use flate2::Compression;
use flate2::write::ZlibEncoder;

#[test]
fn all_png_filters_reconstruct_exact_rgba_pixels() -> Result<(), Box<dyn Error>> {
    let width = 3_u32;
    let rows = vec![
        vec![10, 20, 30, 255, 40, 50, 60, 128, 70, 80, 90, 255],
        vec![11, 21, 31, 255, 41, 51, 61, 127, 71, 81, 91, 255],
        vec![12, 22, 32, 255, 42, 52, 62, 126, 72, 82, 92, 255],
        vec![13, 23, 33, 255, 43, 53, 63, 125, 73, 83, 93, 255],
        vec![14, 24, 34, 255, 44, 54, 64, 124, 74, 84, 94, 255],
    ];
    let filters = [0_u8, 1, 2, 3, 4];
    let scanlines = filtered_scanlines(&rows, &filters, 4);
    let png = png_bytes(width, rows.len() as u32, 8, 6, 0, &zlib(&scanlines)?);

    let decoded = decode_png_bytes(&png)?;
    let expected: Vec<u8> = rows.into_iter().flatten().collect();
    assert_eq!(decoded.rgba8, expected);
    assert_eq!(decoded.report.filter_counts, [1, 1, 1, 1, 1]);
    assert_eq!(decoded.report.color_type, PngColorType::TruecolorAlpha);
    assert_eq!(decoded.report.non_opaque_pixel_count, 5);
    assert_eq!(decoded.pixel(1, 0), Some([40, 50, 60, 128]));
    assert_eq!(decoded.pixel(3, 0), None);
    assert_eq!(decoded.report.rgba_pixel_digest.len(), 64);
    assert_eq!(decoded.report.report_digest.len(), 64);
    Ok(())
}

#[test]
fn truecolor_pixels_receive_opaque_alpha() -> Result<(), Box<dyn Error>> {
    let rows = vec![vec![1, 2, 3, 4, 5, 6], vec![7, 8, 9, 10, 11, 12]];
    let scanlines = filtered_scanlines(&rows, &[0, 2], 3);
    let png = png_bytes(2, 2, 8, 2, 0, &zlib(&scanlines)?);

    let decoded = decode_png_bytes(&png)?;
    assert_eq!(
        decoded.rgba8,
        vec![
            1, 2, 3, 255, 4, 5, 6, 255, 7, 8, 9, 255, 10, 11, 12, 255,
        ]
    );
    assert_eq!(decoded.report.non_opaque_pixel_count, 0);
    assert_eq!(decoded.report.filter_counts, [1, 0, 1, 0, 0]);
    Ok(())
}

#[test]
fn identical_png_bytes_produce_identical_reports() -> Result<(), Box<dyn Error>> {
    let rows = vec![vec![10, 20, 30, 255]];
    let scanlines = filtered_scanlines(&rows, &[0], 4);
    let png = png_bytes(1, 1, 8, 6, 0, &zlib(&scanlines)?);
    let left = decode_png_bytes(&png)?;
    let right = decode_png_bytes(&png)?;
    assert_eq!(left, right);
    Ok(())
}

#[test]
fn unsupported_bit_depth_color_type_and_interlace_fail_closed() -> Result<(), Box<dyn Error>> {
    let compressed = zlib(&[0, 0, 0, 0, 0, 0, 0])?;
    assert!(matches!(
        decode_png_bytes(&png_bytes(1, 1, 16, 2, 0, &compressed)),
        Err(PngPixelDecodeError::UnsupportedBitDepth(16))
    ));

    let grayscale = zlib(&[0, 42])?;
    assert!(matches!(
        decode_png_bytes(&png_bytes(1, 1, 8, 0, 0, &grayscale)),
        Err(PngPixelDecodeError::UnsupportedColorType(
            PngColorType::Grayscale
        ))
    ));

    let rgba = zlib(&[0, 1, 2, 3, 4])?;
    assert!(matches!(
        decode_png_bytes(&png_bytes(1, 1, 8, 6, 1, &rgba)),
        Err(PngPixelDecodeError::UnsupportedInterlace)
    ));
    Ok(())
}

#[test]
fn invalid_filter_and_corrupt_zlib_fail_closed() -> Result<(), Box<dyn Error>> {
    let invalid_filter = zlib(&[5, 1, 2, 3, 4])?;
    assert!(matches!(
        decode_png_bytes(&png_bytes(1, 1, 8, 6, 0, &invalid_filter)),
        Err(PngPixelDecodeError::InvalidFilter(5))
    ));

    let corrupt = vec![0x78, 0x9c, 0xff, 0xff, 0xff];
    assert!(matches!(
        decode_png_bytes(&png_bytes(1, 1, 8, 6, 0, &corrupt)),
        Err(PngPixelDecodeError::Zlib(_))
            | Err(PngPixelDecodeError::DecompressedLengthMismatch { .. })
    ));
    Ok(())
}

#[test]
fn short_and_oversized_decompressed_streams_fail_closed() -> Result<(), Box<dyn Error>> {
    let short = zlib(&[0, 1, 2, 3])?;
    assert!(matches!(
        decode_png_bytes(&png_bytes(1, 1, 8, 6, 0, &short)),
        Err(PngPixelDecodeError::DecompressedLengthMismatch {
            expected: 5,
            actual: 4,
        })
    ));

    let oversized = zlib(&[0, 1, 2, 3, 4, 5])?;
    assert!(matches!(
        decode_png_bytes(&png_bytes(1, 1, 8, 6, 0, &oversized)),
        Err(PngPixelDecodeError::DecompressedDataLimitExceeded)
    ));
    Ok(())
}

#[test]
fn bytes_after_zlib_stream_are_rejected() -> Result<(), Box<dyn Error>> {
    let mut payload = zlib(&[0, 1, 2, 3, 4])?;
    payload.extend_from_slice(b"trailing-compressed-bytes");
    assert!(matches!(
        decode_png_bytes(&png_bytes(1, 1, 8, 6, 0, &payload)),
        Err(PngPixelDecodeError::TrailingCompressedData)
    ));
    Ok(())
}

fn filtered_scanlines(rows: &[Vec<u8>], filters: &[u8], bytes_per_pixel: usize) -> Vec<u8> {
    assert_eq!(rows.len(), filters.len());
    let row_bytes = rows.first().map_or(0, Vec::len);
    let mut output = Vec::with_capacity(rows.len() * (row_bytes + 1));
    let zero = vec![0_u8; row_bytes];
    for (index, row) in rows.iter().enumerate() {
        let previous = if index == 0 { &zero } else { &rows[index - 1] };
        let filter = filters[index];
        output.push(filter);
        for position in 0..row_bytes {
            let left = if position >= bytes_per_pixel {
                row[position - bytes_per_pixel]
            } else {
                0
            };
            let up = previous[position];
            let upper_left = if position >= bytes_per_pixel {
                previous[position - bytes_per_pixel]
            } else {
                0
            };
            let predictor = match filter {
                0 => 0,
                1 => left,
                2 => up,
                3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
                4 => paeth(left, up, upper_left),
                _ => 0,
            };
            output.push(row[position].wrapping_sub(predictor));
        }
    }
    output
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

fn zlib(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

fn png_bytes(
    width: u32,
    height: u32,
    bit_depth: u8,
    color_type: u8,
    interlace: u8,
    idat: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::from(*b"\x89PNG\r\n\x1a\n");
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[bit_depth, color_type, 0, 0, interlace]);
    append_chunk(&mut bytes, b"IHDR", &ihdr);
    append_chunk(&mut bytes, b"IDAT", idat);
    append_chunk(&mut bytes, b"IEND", &[]);
    bytes
}

fn append_chunk(output: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(chunk_type);
    output.extend_from_slice(data);
    output.extend_from_slice(&crc32_pair(chunk_type, data).to_be_bytes());
}

fn crc32_pair(left: &[u8], right: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in left.iter().chain(right) {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
