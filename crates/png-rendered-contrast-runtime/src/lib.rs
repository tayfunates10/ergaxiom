#![forbid(unsafe_code)]

use ergaxiom_png_pixel_decoder_runtime::DecodedPng;
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA_VERSION: &str = "0.1.0";
const MAX_SUBJECT_PIXELS: u64 = 20_000_000;
const LINEAR_SRGB_MILLION: [u32; 256] = [
    0, 304, 607, 911, 1214, 1518, 1821, 2125, 2428, 2732, 3035, 3347, 3677, 4025, 4391, 4777, 5182,
    5605, 6049, 6512, 6995, 7499, 8023, 8568, 9134, 9721, 10330, 10960, 11612, 12286, 12983, 13702,
    14444, 15209, 15996, 16807, 17642, 18500, 19382, 20289, 21219, 22174, 23153, 24158, 25187,
    26241, 27321, 28426, 29557, 30713, 31896, 33105, 34340, 35601, 36889, 38204, 39546, 40915,
    42311, 43735, 45186, 46665, 48172, 49707, 51269, 52861, 54480, 56128, 57805, 59511, 61246,
    63010, 64803, 66626, 68478, 70360, 72272, 74214, 76185, 78187, 80220, 82283, 84376, 86500,
    88656, 90842, 93059, 95307, 97587, 99899, 102242, 104616, 107023, 109462, 111932, 114435,
    116971, 119538, 122139, 124772, 127438, 130136, 132868, 135633, 138432, 141263, 144128, 147027,
    149960, 152926, 155926, 158961, 162029, 165132, 168269, 171441, 174647, 177888, 181164, 184475,
    187821, 191202, 194618, 198069, 201556, 205079, 208637, 212231, 215861, 219526, 223228, 226966,
    230740, 234551, 238398, 242281, 246201, 250158, 254152, 258183, 262251, 266356, 270498, 274677,
    278894, 283149, 287441, 291771, 296138, 300544, 304987, 309469, 313989, 318547, 323143, 327778,
    332452, 337164, 341914, 346704, 351533, 356400, 361307, 366253, 371238, 376262, 381326, 386429,
    391572, 396755, 401978, 407240, 412543, 417885, 423268, 428690, 434154, 439657, 445201, 450786,
    456411, 462077, 467784, 473531, 479320, 485150, 491021, 496933, 502886, 508881, 514918, 520996,
    527115, 533276, 539479, 545724, 552011, 558340, 564712, 571125, 577580, 584078, 590619, 597202,
    603827, 610496, 617207, 623960, 630757, 637597, 644480, 651406, 658375, 665387, 672443, 679542,
    686685, 693872, 701102, 708376, 715694, 723055, 730461, 737910, 745404, 752942, 760525, 768151,
    775822, 783538, 791298, 799103, 806952, 814847, 822786, 830770, 838799, 846873, 854993, 863157,
    871367, 879622, 887923, 896269, 904661, 913099, 921582, 930111, 938686, 947307, 955973, 964686,
    973445, 982251, 991102, 1000000,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PixelRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedContrastPolicy {
    pub subject_region: PixelRect,
    pub background_ring_px: u32,
    pub minimum_contrast_milli: u32,
    pub background_max_channel_deviation: u8,
    pub foreground_minimum_distance_squared: u32,
    pub minimum_candidate_pixels: u32,
    pub maximum_candidate_share_milli: u16,
    pub quantization_bits: u8,
    pub minimum_dominant_pixels: u32,
    pub minimum_dominant_share_milli: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedContrastReport {
    pub schema_version: String,
    pub artifact_digest: String,
    pub pixel_report_digest: String,
    pub rgba_pixel_digest: String,
    pub subject_region: PixelRect,
    pub background_ring_px: u32,
    pub subject_pixel_count: u64,
    pub background_sample_count: u64,
    pub non_opaque_subject_pixel_count: u64,
    pub non_opaque_background_pixel_count: u64,
    pub background_rgb: [u8; 3],
    pub background_max_channel_deviation: u8,
    pub candidate_pixel_count: u64,
    pub candidate_share_milli: u16,
    pub dominant_bin: u32,
    pub dominant_pixel_count: u64,
    pub dominant_share_milli: u16,
    pub foreground_rgb: [u8; 3],
    pub background_luminance_million: u32,
    pub foreground_luminance_million: u32,
    pub representative_contrast_milli: u32,
    pub minimum_dominant_contrast_milli: u32,
    pub report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RenderedContrastViolation {
    NonOpaqueSubjectPixels {
        count: u64,
    },
    NonOpaqueBackgroundPixels {
        count: u64,
    },
    BackgroundNotUniform {
        allowed: u8,
        actual: u8,
    },
    InsufficientCandidatePixels {
        required: u32,
        actual: u64,
    },
    CandidateShareTooHigh {
        maximum_milli: u16,
        actual_milli: u16,
    },
    InsufficientDominantPixels {
        required: u32,
        actual: u64,
    },
    DominantShareTooLow {
        required_milli: u16,
        actual_milli: u16,
    },
    ContrastTooLow {
        required_milli: u32,
        actual_milli: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedContrastResult {
    pub schema_version: String,
    pub accepted: bool,
    pub report: RenderedContrastReport,
    pub violations: Vec<RenderedContrastViolation>,
    pub decision_digest: String,
}

#[derive(Debug, Error)]
pub enum RenderedContrastError {
    #[error("subject region dimensions must be non-zero")]
    EmptySubjectRegion,
    #[error("subject region exceeds decoded image bounds")]
    SubjectRegionOutOfBounds,
    #[error("background ring must be non-zero and remain inside the decoded image")]
    InvalidBackgroundRing,
    #[error("subject region exceeds the {MAX_SUBJECT_PIXELS}-pixel validator limit")]
    SubjectPixelLimitExceeded,
    #[error("minimum contrast must be non-zero")]
    InvalidContrastThreshold,
    #[error("candidate and dominant pixel minimums must be non-zero")]
    InvalidPixelMinimum,
    #[error("share thresholds must be in the range 1 through 1000")]
    InvalidShareThreshold,
    #[error("quantization bits must be between 3 and 5")]
    InvalidQuantizationBits,
    #[error("decoded RGBA byte length does not match its pixel report")]
    DecodedPixelLengthMismatch,
    #[error("integer overflow while evaluating contrast regions")]
    SizeOverflow,
    #[error("failed to serialize rendered contrast evidence: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn validate_rendered_contrast(
    decoded: &DecodedPng,
    policy: &RenderedContrastPolicy,
) -> Result<RenderedContrastResult, RenderedContrastError> {
    let geometry = validate_policy(decoded, policy)?;
    let background = measure_background(decoded, geometry)?;
    let foreground = measure_foreground(decoded, policy, geometry, background.rgb)?;

    let background_luminance = relative_luminance_million(background.rgb);
    let foreground_luminance = relative_luminance_million(foreground.rgb);
    let representative_contrast = contrast_milli(background_luminance, foreground_luminance);

    let mut violations = Vec::new();
    if foreground.non_opaque_subject > 0 {
        violations.push(RenderedContrastViolation::NonOpaqueSubjectPixels {
            count: foreground.non_opaque_subject,
        });
    }
    if background.non_opaque > 0 {
        violations.push(RenderedContrastViolation::NonOpaqueBackgroundPixels {
            count: background.non_opaque,
        });
    }
    if background.max_deviation > policy.background_max_channel_deviation {
        violations.push(RenderedContrastViolation::BackgroundNotUniform {
            allowed: policy.background_max_channel_deviation,
            actual: background.max_deviation,
        });
    }
    if foreground.candidate_count < u64::from(policy.minimum_candidate_pixels) {
        violations.push(RenderedContrastViolation::InsufficientCandidatePixels {
            required: policy.minimum_candidate_pixels,
            actual: foreground.candidate_count,
        });
    }
    if foreground.candidate_share_milli > policy.maximum_candidate_share_milli {
        violations.push(RenderedContrastViolation::CandidateShareTooHigh {
            maximum_milli: policy.maximum_candidate_share_milli,
            actual_milli: foreground.candidate_share_milli,
        });
    }
    if foreground.dominant_count < u64::from(policy.minimum_dominant_pixels) {
        violations.push(RenderedContrastViolation::InsufficientDominantPixels {
            required: policy.minimum_dominant_pixels,
            actual: foreground.dominant_count,
        });
    }
    if foreground.dominant_share_milli < policy.minimum_dominant_share_milli {
        violations.push(RenderedContrastViolation::DominantShareTooLow {
            required_milli: policy.minimum_dominant_share_milli,
            actual_milli: foreground.dominant_share_milli,
        });
    }
    if foreground.minimum_contrast_milli < policy.minimum_contrast_milli {
        violations.push(RenderedContrastViolation::ContrastTooLow {
            required_milli: policy.minimum_contrast_milli,
            actual_milli: foreground.minimum_contrast_milli,
        });
    }

    let mut report = RenderedContrastReport {
        schema_version: SCHEMA_VERSION.to_owned(),
        artifact_digest: decoded.report.artifact_digest.clone(),
        pixel_report_digest: decoded.report.report_digest.clone(),
        rgba_pixel_digest: decoded.report.rgba_pixel_digest.clone(),
        subject_region: policy.subject_region,
        background_ring_px: policy.background_ring_px,
        subject_pixel_count: geometry.subject_pixels,
        background_sample_count: geometry.ring_pixels,
        non_opaque_subject_pixel_count: foreground.non_opaque_subject,
        non_opaque_background_pixel_count: background.non_opaque,
        background_rgb: background.rgb,
        background_max_channel_deviation: background.max_deviation,
        candidate_pixel_count: foreground.candidate_count,
        candidate_share_milli: foreground.candidate_share_milli,
        dominant_bin: foreground.dominant_bin,
        dominant_pixel_count: foreground.dominant_count,
        dominant_share_milli: foreground.dominant_share_milli,
        foreground_rgb: foreground.rgb,
        background_luminance_million: background_luminance,
        foreground_luminance_million: foreground_luminance,
        representative_contrast_milli: representative_contrast,
        minimum_dominant_contrast_milli: foreground.minimum_contrast_milli,
        report_digest: String::new(),
    };
    report.report_digest = report_digest(&report)?;

    let mut result = RenderedContrastResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        accepted: violations.is_empty(),
        report,
        violations,
        decision_digest: String::new(),
    };
    result.decision_digest = decision_digest(&result)?;
    Ok(result)
}

#[derive(Debug, Clone, Copy)]
struct Geometry {
    subject: Bounds,
    expanded: Bounds,
    subject_pixels: u64,
    ring_pixels: u64,
    image_width: usize,
}

#[derive(Debug, Clone, Copy)]
struct Bounds {
    left: usize,
    top: usize,
    right: usize,
    bottom: usize,
}

#[derive(Debug)]
struct BackgroundMeasurement {
    rgb: [u8; 3],
    max_deviation: u8,
    non_opaque: u64,
}

#[derive(Debug)]
struct ForegroundMeasurement {
    rgb: [u8; 3],
    candidate_count: u64,
    candidate_share_milli: u16,
    dominant_bin: u32,
    dominant_count: u64,
    dominant_share_milli: u16,
    minimum_contrast_milli: u32,
    non_opaque_subject: u64,
}

fn validate_policy(
    decoded: &DecodedPng,
    policy: &RenderedContrastPolicy,
) -> Result<Geometry, RenderedContrastError> {
    let region = policy.subject_region;
    if region.width == 0 || region.height == 0 {
        return Err(RenderedContrastError::EmptySubjectRegion);
    }
    if policy.background_ring_px == 0 {
        return Err(RenderedContrastError::InvalidBackgroundRing);
    }
    if policy.minimum_contrast_milli == 0 {
        return Err(RenderedContrastError::InvalidContrastThreshold);
    }
    if policy.minimum_candidate_pixels == 0 || policy.minimum_dominant_pixels == 0 {
        return Err(RenderedContrastError::InvalidPixelMinimum);
    }
    if !(1..=1000).contains(&policy.maximum_candidate_share_milli)
        || !(1..=1000).contains(&policy.minimum_dominant_share_milli)
    {
        return Err(RenderedContrastError::InvalidShareThreshold);
    }
    if !(3..=5).contains(&policy.quantization_bits) {
        return Err(RenderedContrastError::InvalidQuantizationBits);
    }

    let image_width =
        usize::try_from(decoded.report.width).map_err(|_| RenderedContrastError::SizeOverflow)?;
    let image_height =
        usize::try_from(decoded.report.height).map_err(|_| RenderedContrastError::SizeOverflow)?;
    let expected_rgba = image_width
        .checked_mul(image_height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(RenderedContrastError::SizeOverflow)?;
    if decoded.rgba8.len() != expected_rgba {
        return Err(RenderedContrastError::DecodedPixelLengthMismatch);
    }

    let left = usize::try_from(region.x).map_err(|_| RenderedContrastError::SizeOverflow)?;
    let top = usize::try_from(region.y).map_err(|_| RenderedContrastError::SizeOverflow)?;
    let width = usize::try_from(region.width).map_err(|_| RenderedContrastError::SizeOverflow)?;
    let height = usize::try_from(region.height).map_err(|_| RenderedContrastError::SizeOverflow)?;
    let right = left
        .checked_add(width)
        .ok_or(RenderedContrastError::SizeOverflow)?;
    let bottom = top
        .checked_add(height)
        .ok_or(RenderedContrastError::SizeOverflow)?;
    if right > image_width || bottom > image_height {
        return Err(RenderedContrastError::SubjectRegionOutOfBounds);
    }
    let ring = usize::try_from(policy.background_ring_px)
        .map_err(|_| RenderedContrastError::SizeOverflow)?;
    let expanded_left = left
        .checked_sub(ring)
        .ok_or(RenderedContrastError::InvalidBackgroundRing)?;
    let expanded_top = top
        .checked_sub(ring)
        .ok_or(RenderedContrastError::InvalidBackgroundRing)?;
    let expanded_right = right
        .checked_add(ring)
        .ok_or(RenderedContrastError::SizeOverflow)?;
    let expanded_bottom = bottom
        .checked_add(ring)
        .ok_or(RenderedContrastError::SizeOverflow)?;
    if expanded_right > image_width || expanded_bottom > image_height {
        return Err(RenderedContrastError::InvalidBackgroundRing);
    }

    let subject_pixels = u64::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(u64::try_from(height).ok()?))
        .ok_or(RenderedContrastError::SizeOverflow)?;
    if subject_pixels > MAX_SUBJECT_PIXELS {
        return Err(RenderedContrastError::SubjectPixelLimitExceeded);
    }
    let expanded_width = expanded_right - expanded_left;
    let expanded_height = expanded_bottom - expanded_top;
    let expanded_pixels = u64::try_from(expanded_width)
        .ok()
        .and_then(|value| value.checked_mul(u64::try_from(expanded_height).ok()?))
        .ok_or(RenderedContrastError::SizeOverflow)?;
    let ring_pixels = expanded_pixels
        .checked_sub(subject_pixels)
        .ok_or(RenderedContrastError::SizeOverflow)?;
    if ring_pixels == 0 {
        return Err(RenderedContrastError::InvalidBackgroundRing);
    }

    Ok(Geometry {
        subject: Bounds {
            left,
            top,
            right,
            bottom,
        },
        expanded: Bounds {
            left: expanded_left,
            top: expanded_top,
            right: expanded_right,
            bottom: expanded_bottom,
        },
        subject_pixels,
        ring_pixels,
        image_width,
    })
}

fn measure_background(
    decoded: &DecodedPng,
    geometry: Geometry,
) -> Result<BackgroundMeasurement, RenderedContrastError> {
    let mut histograms = [[0_u64; 256]; 3];
    let mut non_opaque = 0_u64;
    for y in geometry.expanded.top..geometry.expanded.bottom {
        for x in geometry.expanded.left..geometry.expanded.right {
            if contains(geometry.subject, x, y) {
                continue;
            }
            let pixel = pixel_at(decoded, geometry.image_width, x, y)?;
            if pixel[3] != 255 {
                non_opaque = non_opaque.saturating_add(1);
            }
            histograms[0][usize::from(pixel[0])] += 1;
            histograms[1][usize::from(pixel[1])] += 1;
            histograms[2][usize::from(pixel[2])] += 1;
        }
    }
    let rgb = [
        histogram_median(&histograms[0], geometry.ring_pixels),
        histogram_median(&histograms[1], geometry.ring_pixels),
        histogram_median(&histograms[2], geometry.ring_pixels),
    ];
    let mut max_deviation = 0_u8;
    for y in geometry.expanded.top..geometry.expanded.bottom {
        for x in geometry.expanded.left..geometry.expanded.right {
            if contains(geometry.subject, x, y) {
                continue;
            }
            let pixel = pixel_at(decoded, geometry.image_width, x, y)?;
            for channel in 0..3 {
                max_deviation = max_deviation.max(pixel[channel].abs_diff(rgb[channel]));
            }
        }
    }
    Ok(BackgroundMeasurement {
        rgb,
        max_deviation,
        non_opaque,
    })
}

fn measure_foreground(
    decoded: &DecodedPng,
    policy: &RenderedContrastPolicy,
    geometry: Geometry,
    background: [u8; 3],
) -> Result<ForegroundMeasurement, RenderedContrastError> {
    let bits = usize::from(policy.quantization_bits);
    let bin_count = 1_usize
        .checked_shl(u32::from(policy.quantization_bits) * 3)
        .ok_or(RenderedContrastError::SizeOverflow)?;
    let shift = 8_usize - bits;
    let mut bins = vec![0_u64; bin_count];
    let mut candidate_count = 0_u64;
    let mut non_opaque_subject = 0_u64;

    for y in geometry.subject.top..geometry.subject.bottom {
        for x in geometry.subject.left..geometry.subject.right {
            let pixel = pixel_at(decoded, geometry.image_width, x, y)?;
            if pixel[3] != 255 {
                non_opaque_subject = non_opaque_subject.saturating_add(1);
            }
            if color_distance_squared(pixel, background)
                >= policy.foreground_minimum_distance_squared
            {
                candidate_count = candidate_count.saturating_add(1);
                bins[quantized_bin(pixel, bits, shift)] += 1;
            }
        }
    }

    let (dominant_bin, dominant_count) = bins
        .iter()
        .enumerate()
        .max_by(|left, right| left.1.cmp(right.1).then_with(|| right.0.cmp(&left.0)))
        .map(|(index, count)| (index, *count))
        .unwrap_or((0, 0));

    let candidate_share_milli = share_milli(candidate_count, geometry.subject_pixels);
    let dominant_share_milli = share_milli(dominant_count, candidate_count);
    let mut histograms = [[0_u64; 256]; 3];
    let mut minimum_contrast = u32::MAX;
    for y in geometry.subject.top..geometry.subject.bottom {
        for x in geometry.subject.left..geometry.subject.right {
            let pixel = pixel_at(decoded, geometry.image_width, x, y)?;
            if color_distance_squared(pixel, background)
                < policy.foreground_minimum_distance_squared
                || quantized_bin(pixel, bits, shift) != dominant_bin
            {
                continue;
            }
            histograms[0][usize::from(pixel[0])] += 1;
            histograms[1][usize::from(pixel[1])] += 1;
            histograms[2][usize::from(pixel[2])] += 1;
            let pixel_luminance = relative_luminance_million([pixel[0], pixel[1], pixel[2]]);
            let background_luminance = relative_luminance_million(background);
            minimum_contrast =
                minimum_contrast.min(contrast_milli(pixel_luminance, background_luminance));
        }
    }
    let rgb = if dominant_count == 0 {
        [0, 0, 0]
    } else {
        [
            histogram_median(&histograms[0], dominant_count),
            histogram_median(&histograms[1], dominant_count),
            histogram_median(&histograms[2], dominant_count),
        ]
    };
    if minimum_contrast == u32::MAX {
        minimum_contrast = 0;
    }

    Ok(ForegroundMeasurement {
        rgb,
        candidate_count,
        candidate_share_milli,
        dominant_bin: u32::try_from(dominant_bin)
            .map_err(|_| RenderedContrastError::SizeOverflow)?,
        dominant_count,
        dominant_share_milli,
        minimum_contrast_milli: minimum_contrast,
        non_opaque_subject,
    })
}

fn pixel_at(
    decoded: &DecodedPng,
    width: usize,
    x: usize,
    y: usize,
) -> Result<[u8; 4], RenderedContrastError> {
    let index = y
        .checked_mul(width)
        .and_then(|value| value.checked_add(x))
        .and_then(|value| value.checked_mul(4))
        .ok_or(RenderedContrastError::SizeOverflow)?;
    let bytes = decoded
        .rgba8
        .get(index..index + 4)
        .ok_or(RenderedContrastError::DecodedPixelLengthMismatch)?;
    Ok([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn contains(bounds: Bounds, x: usize, y: usize) -> bool {
    x >= bounds.left && x < bounds.right && y >= bounds.top && y < bounds.bottom
}

fn histogram_median(histogram: &[u64; 256], count: u64) -> u8 {
    let target = count.saturating_sub(1) / 2;
    let mut cumulative = 0_u64;
    for (value, frequency) in histogram.iter().enumerate() {
        cumulative = cumulative.saturating_add(*frequency);
        if cumulative > target {
            return value as u8;
        }
    }
    0
}

fn color_distance_squared(pixel: [u8; 4], background: [u8; 3]) -> u32 {
    let red = i32::from(pixel[0]) - i32::from(background[0]);
    let green = i32::from(pixel[1]) - i32::from(background[1]);
    let blue = i32::from(pixel[2]) - i32::from(background[2]);
    (red * red + green * green + blue * blue) as u32
}

fn quantized_bin(pixel: [u8; 4], bits: usize, shift: usize) -> usize {
    let mask = (1_usize << bits) - 1;
    ((usize::from(pixel[0]) >> shift) & mask) << (bits * 2)
        | ((usize::from(pixel[1]) >> shift) & mask) << bits
        | ((usize::from(pixel[2]) >> shift) & mask)
}

fn share_milli(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let rounded = numerator
        .saturating_mul(1000)
        .saturating_add(denominator / 2)
        / denominator;
    u16::try_from(rounded.min(1000)).unwrap_or(1000)
}

pub fn relative_luminance_million(rgb: [u8; 3]) -> u32 {
    let red = u64::from(LINEAR_SRGB_MILLION[usize::from(rgb[0])]);
    let green = u64::from(LINEAR_SRGB_MILLION[usize::from(rgb[1])]);
    let blue = u64::from(LINEAR_SRGB_MILLION[usize::from(rgb[2])]);
    ((2126 * red + 7152 * green + 722 * blue + 5000) / 10_000) as u32
}

pub fn contrast_milli(left_luminance_million: u32, right_luminance_million: u32) -> u32 {
    let high = u64::from(left_luminance_million.max(right_luminance_million));
    let low = u64::from(left_luminance_million.min(right_luminance_million));
    let numerator = (high + 50_000) * 1000;
    let denominator = low + 50_000;
    ((numerator + denominator / 2) / denominator) as u32
}

fn report_digest(report: &RenderedContrastReport) -> Result<String, RenderedContrastError> {
    let mut value = serde_json::to_value(report)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other("contrast report is not an object"))
    })?;
    object.insert(
        "report_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

fn decision_digest(result: &RenderedContrastResult) -> Result<String, RenderedContrastError> {
    let mut value = serde_json::to_value(result)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other("contrast result is not an object"))
    })?;
    object.insert(
        "decision_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

#[cfg(test)]
mod tests {
    use super::{contrast_milli, relative_luminance_million};

    #[test]
    fn black_and_white_have_twenty_one_to_one_contrast() {
        assert_eq!(relative_luminance_million([0, 0, 0]), 0);
        assert_eq!(relative_luminance_million([255, 255, 255]), 1_000_000);
        assert_eq!(contrast_milli(0, 1_000_000), 21_000);
    }
}
