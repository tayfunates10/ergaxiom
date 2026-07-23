#![forbid(unsafe_code)]

use ergaxiom_png_pixel_decoder_runtime::DecodedPng;
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SCHEMA_VERSION: &str = "0.1.0";
const MAX_IMAGE_PIXELS: u64 = 20_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PixelRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoGeometryPolicy {
    pub logo_region: PixelRect,
    pub clear_space_px: u32,
    pub background_ring_px: u32,
    pub approved_alpha_threshold: u8,
    pub approved_minimum_foreground_pixels: u32,
    pub approved_minimum_foreground_share_milli: u16,
    pub approved_maximum_foreground_share_milli: u16,
    pub foreground_minimum_distance_squared: u32,
    pub minimum_rendered_foreground_pixels: u32,
    pub minimum_mask_iou_milli: u16,
    pub maximum_aspect_ratio_error_ppm: u32,
    pub background_max_channel_deviation: u8,
    pub maximum_clear_space_intrusion_pixels: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoGeometryReport {
    pub schema_version: String,
    pub rendered_artifact_digest: String,
    pub rendered_pixel_report_digest: String,
    pub rendered_rgba_pixel_digest: String,
    pub approved_artifact_digest: String,
    pub approved_pixel_report_digest: String,
    pub approved_rgba_pixel_digest: String,
    pub approved_mask_digest: String,
    pub approved_mask_width: u32,
    pub approved_mask_height: u32,
    pub approved_foreground_pixel_count: u64,
    pub approved_foreground_share_milli: u16,
    pub logo_region: PixelRect,
    pub clear_space_px: u32,
    pub background_ring_px: u32,
    pub background_sample_count: u64,
    pub non_opaque_background_pixel_count: u64,
    pub background_rgb: [u8; 3],
    pub background_max_channel_deviation: u8,
    pub non_opaque_logo_pixel_count: u64,
    pub non_opaque_clear_space_pixel_count: u64,
    pub rendered_foreground_pixel_count: u64,
    pub expected_foreground_pixel_count: u64,
    pub mask_intersection_pixel_count: u64,
    pub mask_union_pixel_count: u64,
    pub mask_iou_milli: u16,
    pub expected_occupied_bounds: Option<PixelRect>,
    pub rendered_occupied_bounds: Option<PixelRect>,
    pub expected_aspect_ratio_ppm: u32,
    pub rendered_aspect_ratio_ppm: u32,
    pub aspect_ratio_error_ppm: u32,
    pub clear_space_intrusion_pixel_count: u64,
    pub report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LogoGeometryViolation {
    NonOpaqueLogoPixels {
        count: u64,
    },
    NonOpaqueClearSpacePixels {
        count: u64,
    },
    NonOpaqueBackgroundPixels {
        count: u64,
    },
    BackgroundNotUniform {
        allowed: u8,
        actual: u8,
    },
    InsufficientRenderedForegroundPixels {
        required: u32,
        actual: u64,
    },
    MaskSimilarityTooLow {
        required_milli: u16,
        actual_milli: u16,
    },
    AspectRatioMismatch {
        maximum_error_ppm: u32,
        actual_error_ppm: u32,
    },
    ClearSpaceIntrusion {
        maximum_pixels: u32,
        actual_pixels: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoGeometryResult {
    pub schema_version: String,
    pub accepted: bool,
    pub report: LogoGeometryReport,
    pub violations: Vec<LogoGeometryViolation>,
    pub decision_digest: String,
}

#[derive(Debug, Error)]
pub enum LogoGeometryError {
    #[error("logo region dimensions must be non-zero")]
    EmptyLogoRegion,
    #[error("logo region exceeds decoded image bounds")]
    LogoRegionOutOfBounds,
    #[error("clear-space and background rings must be non-zero and remain inside the image")]
    InvalidSurroundingRings,
    #[error("decoded image exceeds the {MAX_IMAGE_PIXELS}-pixel validator limit")]
    ImagePixelLimitExceeded,
    #[error("decoded RGBA byte length does not match its pixel report")]
    DecodedPixelLengthMismatch,
    #[error("approved alpha threshold must be non-zero")]
    InvalidApprovedAlphaThreshold,
    #[error("approved and rendered foreground minimums must be non-zero")]
    InvalidForegroundMinimum,
    #[error("share and similarity thresholds must be in the range 1 through 1000")]
    InvalidShareThreshold,
    #[error("approved minimum foreground share exceeds its maximum")]
    InvalidApprovedShareRange,
    #[error("maximum aspect-ratio error must not exceed 1,000,000 ppm")]
    InvalidAspectRatioThreshold,
    #[error("foreground color-distance threshold must be non-zero")]
    InvalidForegroundDistanceThreshold,
    #[error(
        "approved logo alpha mask contains too few foreground pixels: required {required}, actual {actual}"
    )]
    ApprovedMaskTooSparse { required: u32, actual: u64 },
    #[error(
        "approved logo alpha-mask share is outside policy: minimum {minimum_milli}, maximum {maximum_milli}, actual {actual_milli}"
    )]
    ApprovedMaskShareOutOfRange {
        minimum_milli: u16,
        maximum_milli: u16,
        actual_milli: u16,
    },
    #[error("integer overflow while evaluating logo geometry")]
    SizeOverflow,
    #[error("failed to serialize logo geometry evidence: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn validate_logo_geometry(
    approved_logo: &DecodedPng,
    rendered: &DecodedPng,
    policy: &LogoGeometryPolicy,
) -> Result<LogoGeometryResult, LogoGeometryError> {
    let geometry = validate_policy(approved_logo, rendered, policy)?;
    let approved = derive_approved_mask(approved_logo, policy)?;
    let background = measure_background(rendered, geometry)?;
    let measurement = measure_rendered_logo(
        approved_logo,
        rendered,
        policy,
        geometry,
        &approved.mask,
        background.rgb,
    )?;

    let mut violations = Vec::new();
    if measurement.non_opaque_logo > 0 {
        violations.push(LogoGeometryViolation::NonOpaqueLogoPixels {
            count: measurement.non_opaque_logo,
        });
    }
    if measurement.non_opaque_clear_space > 0 {
        violations.push(LogoGeometryViolation::NonOpaqueClearSpacePixels {
            count: measurement.non_opaque_clear_space,
        });
    }
    if background.non_opaque > 0 {
        violations.push(LogoGeometryViolation::NonOpaqueBackgroundPixels {
            count: background.non_opaque,
        });
    }
    if background.max_deviation > policy.background_max_channel_deviation {
        violations.push(LogoGeometryViolation::BackgroundNotUniform {
            allowed: policy.background_max_channel_deviation,
            actual: background.max_deviation,
        });
    }
    if measurement.rendered_foreground_count < u64::from(policy.minimum_rendered_foreground_pixels)
    {
        violations.push(
            LogoGeometryViolation::InsufficientRenderedForegroundPixels {
                required: policy.minimum_rendered_foreground_pixels,
                actual: measurement.rendered_foreground_count,
            },
        );
    }
    if measurement.iou_milli < policy.minimum_mask_iou_milli {
        violations.push(LogoGeometryViolation::MaskSimilarityTooLow {
            required_milli: policy.minimum_mask_iou_milli,
            actual_milli: measurement.iou_milli,
        });
    }
    if measurement.aspect_ratio_error_ppm > policy.maximum_aspect_ratio_error_ppm {
        violations.push(LogoGeometryViolation::AspectRatioMismatch {
            maximum_error_ppm: policy.maximum_aspect_ratio_error_ppm,
            actual_error_ppm: measurement.aspect_ratio_error_ppm,
        });
    }
    if measurement.clear_space_intrusions > u64::from(policy.maximum_clear_space_intrusion_pixels) {
        violations.push(LogoGeometryViolation::ClearSpaceIntrusion {
            maximum_pixels: policy.maximum_clear_space_intrusion_pixels,
            actual_pixels: measurement.clear_space_intrusions,
        });
    }

    let mut report = LogoGeometryReport {
        schema_version: SCHEMA_VERSION.to_owned(),
        rendered_artifact_digest: rendered.report.artifact_digest.clone(),
        rendered_pixel_report_digest: rendered.report.report_digest.clone(),
        rendered_rgba_pixel_digest: rendered.report.rgba_pixel_digest.clone(),
        approved_artifact_digest: approved_logo.report.artifact_digest.clone(),
        approved_pixel_report_digest: approved_logo.report.report_digest.clone(),
        approved_rgba_pixel_digest: approved_logo.report.rgba_pixel_digest.clone(),
        approved_mask_digest: approved.mask_digest,
        approved_mask_width: approved_logo.report.width,
        approved_mask_height: approved_logo.report.height,
        approved_foreground_pixel_count: approved.foreground_count,
        approved_foreground_share_milli: approved.foreground_share_milli,
        logo_region: policy.logo_region,
        clear_space_px: policy.clear_space_px,
        background_ring_px: policy.background_ring_px,
        background_sample_count: geometry.background_sample_pixels,
        non_opaque_background_pixel_count: background.non_opaque,
        background_rgb: background.rgb,
        background_max_channel_deviation: background.max_deviation,
        non_opaque_logo_pixel_count: measurement.non_opaque_logo,
        non_opaque_clear_space_pixel_count: measurement.non_opaque_clear_space,
        rendered_foreground_pixel_count: measurement.rendered_foreground_count,
        expected_foreground_pixel_count: measurement.expected_foreground_count,
        mask_intersection_pixel_count: measurement.intersection_count,
        mask_union_pixel_count: measurement.union_count,
        mask_iou_milli: measurement.iou_milli,
        expected_occupied_bounds: measurement.expected_bounds,
        rendered_occupied_bounds: measurement.rendered_bounds,
        expected_aspect_ratio_ppm: measurement.expected_aspect_ratio_ppm,
        rendered_aspect_ratio_ppm: measurement.rendered_aspect_ratio_ppm,
        aspect_ratio_error_ppm: measurement.aspect_ratio_error_ppm,
        clear_space_intrusion_pixel_count: measurement.clear_space_intrusions,
        report_digest: String::new(),
    };
    report.report_digest = report_digest(&report)?;

    let mut result = LogoGeometryResult {
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
struct Bounds {
    left: usize,
    top: usize,
    right: usize,
    bottom: usize,
}

#[derive(Debug, Clone, Copy)]
struct Geometry {
    logo: Bounds,
    clear: Bounds,
    background: Bounds,
    background_sample_pixels: u64,
    rendered_width: usize,
}

#[derive(Debug)]
struct ApprovedMask {
    mask: Vec<u8>,
    foreground_count: u64,
    foreground_share_milli: u16,
    mask_digest: String,
}

#[derive(Debug)]
struct BackgroundMeasurement {
    rgb: [u8; 3],
    max_deviation: u8,
    non_opaque: u64,
}

#[derive(Debug)]
struct RenderedMeasurement {
    non_opaque_logo: u64,
    non_opaque_clear_space: u64,
    rendered_foreground_count: u64,
    expected_foreground_count: u64,
    intersection_count: u64,
    union_count: u64,
    iou_milli: u16,
    expected_bounds: Option<PixelRect>,
    rendered_bounds: Option<PixelRect>,
    expected_aspect_ratio_ppm: u32,
    rendered_aspect_ratio_ppm: u32,
    aspect_ratio_error_ppm: u32,
    clear_space_intrusions: u64,
}

#[derive(Debug)]
struct BoundsTracker {
    any: bool,
    left: usize,
    top: usize,
    right: usize,
    bottom: usize,
}

impl BoundsTracker {
    fn new() -> Self {
        Self {
            any: false,
            left: usize::MAX,
            top: usize::MAX,
            right: 0,
            bottom: 0,
        }
    }

    fn include(&mut self, x: usize, y: usize) -> Result<(), LogoGeometryError> {
        self.any = true;
        self.left = self.left.min(x);
        self.top = self.top.min(y);
        self.right = self
            .right
            .max(x.checked_add(1).ok_or(LogoGeometryError::SizeOverflow)?);
        self.bottom = self
            .bottom
            .max(y.checked_add(1).ok_or(LogoGeometryError::SizeOverflow)?);
        Ok(())
    }

    fn absolute_rect(
        &self,
        offset_x: usize,
        offset_y: usize,
    ) -> Result<Option<PixelRect>, LogoGeometryError> {
        if !self.any {
            return Ok(None);
        }
        let x = offset_x
            .checked_add(self.left)
            .ok_or(LogoGeometryError::SizeOverflow)?;
        let y = offset_y
            .checked_add(self.top)
            .ok_or(LogoGeometryError::SizeOverflow)?;
        Ok(Some(PixelRect {
            x: u32::try_from(x).map_err(|_| LogoGeometryError::SizeOverflow)?,
            y: u32::try_from(y).map_err(|_| LogoGeometryError::SizeOverflow)?,
            width: u32::try_from(self.right - self.left)
                .map_err(|_| LogoGeometryError::SizeOverflow)?,
            height: u32::try_from(self.bottom - self.top)
                .map_err(|_| LogoGeometryError::SizeOverflow)?,
        }))
    }
}

fn validate_policy(
    approved: &DecodedPng,
    rendered: &DecodedPng,
    policy: &LogoGeometryPolicy,
) -> Result<Geometry, LogoGeometryError> {
    validate_decoded(approved)?;
    validate_decoded(rendered)?;

    if policy.logo_region.width == 0 || policy.logo_region.height == 0 {
        return Err(LogoGeometryError::EmptyLogoRegion);
    }
    if policy.clear_space_px == 0 || policy.background_ring_px == 0 {
        return Err(LogoGeometryError::InvalidSurroundingRings);
    }
    if policy.approved_alpha_threshold == 0 {
        return Err(LogoGeometryError::InvalidApprovedAlphaThreshold);
    }
    if policy.approved_minimum_foreground_pixels == 0
        || policy.minimum_rendered_foreground_pixels == 0
    {
        return Err(LogoGeometryError::InvalidForegroundMinimum);
    }
    if !(1..=1000).contains(&policy.approved_minimum_foreground_share_milli)
        || !(1..=1000).contains(&policy.approved_maximum_foreground_share_milli)
        || !(1..=1000).contains(&policy.minimum_mask_iou_milli)
    {
        return Err(LogoGeometryError::InvalidShareThreshold);
    }
    if policy.approved_minimum_foreground_share_milli
        > policy.approved_maximum_foreground_share_milli
    {
        return Err(LogoGeometryError::InvalidApprovedShareRange);
    }
    if policy.maximum_aspect_ratio_error_ppm > 1_000_000 {
        return Err(LogoGeometryError::InvalidAspectRatioThreshold);
    }
    if policy.foreground_minimum_distance_squared == 0 {
        return Err(LogoGeometryError::InvalidForegroundDistanceThreshold);
    }

    let image_width =
        usize::try_from(rendered.report.width).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let image_height =
        usize::try_from(rendered.report.height).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let left =
        usize::try_from(policy.logo_region.x).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let top = usize::try_from(policy.logo_region.y).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let width =
        usize::try_from(policy.logo_region.width).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let height =
        usize::try_from(policy.logo_region.height).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let right = left
        .checked_add(width)
        .ok_or(LogoGeometryError::SizeOverflow)?;
    let bottom = top
        .checked_add(height)
        .ok_or(LogoGeometryError::SizeOverflow)?;
    if right > image_width || bottom > image_height {
        return Err(LogoGeometryError::LogoRegionOutOfBounds);
    }

    let clear_px =
        usize::try_from(policy.clear_space_px).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let background_px =
        usize::try_from(policy.background_ring_px).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let logo = Bounds {
        left,
        top,
        right,
        bottom,
    };
    let clear = expand_bounds(logo, clear_px, image_width, image_height)?;
    let background = expand_bounds(clear, background_px, image_width, image_height)?;

    let logo_pixels = pixel_count(width, height)?;
    if logo_pixels > MAX_IMAGE_PIXELS {
        return Err(LogoGeometryError::ImagePixelLimitExceeded);
    }
    let clear_pixels = pixel_count(clear.right - clear.left, clear.bottom - clear.top)?;
    let background_pixels = pixel_count(
        background.right - background.left,
        background.bottom - background.top,
    )?;
    let background_sample_pixels = background_pixels
        .checked_sub(clear_pixels)
        .ok_or(LogoGeometryError::SizeOverflow)?;
    if background_sample_pixels == 0 {
        return Err(LogoGeometryError::InvalidSurroundingRings);
    }

    Ok(Geometry {
        logo,
        clear,
        background,
        background_sample_pixels,
        rendered_width: image_width,
    })
}

fn validate_decoded(decoded: &DecodedPng) -> Result<(), LogoGeometryError> {
    let width =
        usize::try_from(decoded.report.width).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let height =
        usize::try_from(decoded.report.height).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let pixels = pixel_count(width, height)?;
    if pixels > MAX_IMAGE_PIXELS {
        return Err(LogoGeometryError::ImagePixelLimitExceeded);
    }
    let expected = usize::try_from(pixels)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(LogoGeometryError::SizeOverflow)?;
    if decoded.rgba8.len() != expected {
        return Err(LogoGeometryError::DecodedPixelLengthMismatch);
    }
    Ok(())
}

fn expand_bounds(
    bounds: Bounds,
    amount: usize,
    image_width: usize,
    image_height: usize,
) -> Result<Bounds, LogoGeometryError> {
    let left = bounds
        .left
        .checked_sub(amount)
        .ok_or(LogoGeometryError::InvalidSurroundingRings)?;
    let top = bounds
        .top
        .checked_sub(amount)
        .ok_or(LogoGeometryError::InvalidSurroundingRings)?;
    let right = bounds
        .right
        .checked_add(amount)
        .ok_or(LogoGeometryError::SizeOverflow)?;
    let bottom = bounds
        .bottom
        .checked_add(amount)
        .ok_or(LogoGeometryError::SizeOverflow)?;
    if right > image_width || bottom > image_height {
        return Err(LogoGeometryError::InvalidSurroundingRings);
    }
    Ok(Bounds {
        left,
        top,
        right,
        bottom,
    })
}

fn derive_approved_mask(
    approved: &DecodedPng,
    policy: &LogoGeometryPolicy,
) -> Result<ApprovedMask, LogoGeometryError> {
    let mut mask = Vec::with_capacity(approved.rgba8.len() / 4);
    let mut foreground_count = 0_u64;
    for pixel in approved.rgba8.chunks_exact(4) {
        let foreground = pixel[3] >= policy.approved_alpha_threshold;
        mask.push(u8::from(foreground));
        if foreground {
            foreground_count = foreground_count.saturating_add(1);
        }
    }
    if foreground_count < u64::from(policy.approved_minimum_foreground_pixels) {
        return Err(LogoGeometryError::ApprovedMaskTooSparse {
            required: policy.approved_minimum_foreground_pixels,
            actual: foreground_count,
        });
    }
    let approved_pixel_count =
        u64::try_from(mask.len()).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let foreground_share_milli = share_milli(foreground_count, approved_pixel_count);
    if foreground_share_milli < policy.approved_minimum_foreground_share_milli
        || foreground_share_milli > policy.approved_maximum_foreground_share_milli
    {
        return Err(LogoGeometryError::ApprovedMaskShareOutOfRange {
            minimum_milli: policy.approved_minimum_foreground_share_milli,
            maximum_milli: policy.approved_maximum_foreground_share_milli,
            actual_milli: foreground_share_milli,
        });
    }

    Ok(ApprovedMask {
        mask_digest: sha256_hex(&mask),
        mask,
        foreground_count,
        foreground_share_milli,
    })
}

fn measure_background(
    rendered: &DecodedPng,
    geometry: Geometry,
) -> Result<BackgroundMeasurement, LogoGeometryError> {
    let mut histograms = [[0_u64; 256]; 3];
    let mut non_opaque = 0_u64;
    for y in geometry.background.top..geometry.background.bottom {
        for x in geometry.background.left..geometry.background.right {
            if contains(geometry.clear, x, y) {
                continue;
            }
            let pixel = pixel_at(rendered, geometry.rendered_width, x, y)?;
            if pixel[3] != 255 {
                non_opaque = non_opaque.saturating_add(1);
            }
            histograms[0][usize::from(pixel[0])] += 1;
            histograms[1][usize::from(pixel[1])] += 1;
            histograms[2][usize::from(pixel[2])] += 1;
        }
    }
    let rgb = [
        histogram_median(&histograms[0], geometry.background_sample_pixels),
        histogram_median(&histograms[1], geometry.background_sample_pixels),
        histogram_median(&histograms[2], geometry.background_sample_pixels),
    ];
    let mut max_deviation = 0_u8;
    for y in geometry.background.top..geometry.background.bottom {
        for x in geometry.background.left..geometry.background.right {
            if contains(geometry.clear, x, y) {
                continue;
            }
            let pixel = pixel_at(rendered, geometry.rendered_width, x, y)?;
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

fn measure_rendered_logo(
    approved: &DecodedPng,
    rendered: &DecodedPng,
    policy: &LogoGeometryPolicy,
    geometry: Geometry,
    approved_mask: &[u8],
    background: [u8; 3],
) -> Result<RenderedMeasurement, LogoGeometryError> {
    let source_width =
        usize::try_from(approved.report.width).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let source_height =
        usize::try_from(approved.report.height).map_err(|_| LogoGeometryError::SizeOverflow)?;
    let target_width = geometry.logo.right - geometry.logo.left;
    let target_height = geometry.logo.bottom - geometry.logo.top;

    let mut expected_tracker = BoundsTracker::new();
    let mut rendered_tracker = BoundsTracker::new();
    let mut non_opaque_logo = 0_u64;
    let mut rendered_foreground_count = 0_u64;
    let mut expected_foreground_count = 0_u64;
    let mut intersection_count = 0_u64;
    let mut union_count = 0_u64;

    for relative_y in 0..target_height {
        for relative_x in 0..target_width {
            let absolute_x = geometry
                .logo
                .left
                .checked_add(relative_x)
                .ok_or(LogoGeometryError::SizeOverflow)?;
            let absolute_y = geometry
                .logo
                .top
                .checked_add(relative_y)
                .ok_or(LogoGeometryError::SizeOverflow)?;
            let pixel = pixel_at(rendered, geometry.rendered_width, absolute_x, absolute_y)?;
            if pixel[3] != 255 {
                non_opaque_logo = non_opaque_logo.saturating_add(1);
            }
            let observed = color_distance_squared(pixel, background)
                >= policy.foreground_minimum_distance_squared;
            let expected = scaled_mask_at(
                approved_mask,
                source_width,
                source_height,
                target_width,
                target_height,
                relative_x,
                relative_y,
            )?;
            if observed {
                rendered_foreground_count = rendered_foreground_count.saturating_add(1);
                rendered_tracker.include(relative_x, relative_y)?;
            }
            if expected {
                expected_foreground_count = expected_foreground_count.saturating_add(1);
                expected_tracker.include(relative_x, relative_y)?;
            }
            if observed && expected {
                intersection_count = intersection_count.saturating_add(1);
            }
            if observed || expected {
                union_count = union_count.saturating_add(1);
            }
        }
    }

    let mut non_opaque_clear_space = 0_u64;
    let mut clear_space_intrusions = 0_u64;
    for y in geometry.clear.top..geometry.clear.bottom {
        for x in geometry.clear.left..geometry.clear.right {
            if contains(geometry.logo, x, y) {
                continue;
            }
            let pixel = pixel_at(rendered, geometry.rendered_width, x, y)?;
            if pixel[3] != 255 {
                non_opaque_clear_space = non_opaque_clear_space.saturating_add(1);
            }
            if color_distance_squared(pixel, background)
                >= policy.foreground_minimum_distance_squared
            {
                clear_space_intrusions = clear_space_intrusions.saturating_add(1);
            }
        }
    }

    let expected_bounds = expected_tracker.absolute_rect(geometry.logo.left, geometry.logo.top)?;
    let rendered_bounds = rendered_tracker.absolute_rect(geometry.logo.left, geometry.logo.top)?;
    let expected_aspect_ratio_ppm = aspect_ratio_ppm(expected_bounds)?;
    let rendered_aspect_ratio_ppm = aspect_ratio_ppm(rendered_bounds)?;
    let aspect_ratio_error_ppm =
        relative_error_ppm(expected_aspect_ratio_ppm, rendered_aspect_ratio_ppm);

    Ok(RenderedMeasurement {
        non_opaque_logo,
        non_opaque_clear_space,
        rendered_foreground_count,
        expected_foreground_count,
        intersection_count,
        union_count,
        iou_milli: share_milli(intersection_count, union_count),
        expected_bounds,
        rendered_bounds,
        expected_aspect_ratio_ppm,
        rendered_aspect_ratio_ppm,
        aspect_ratio_error_ppm,
        clear_space_intrusions,
    })
}

fn scaled_mask_at(
    mask: &[u8],
    source_width: usize,
    source_height: usize,
    target_width: usize,
    target_height: usize,
    target_x: usize,
    target_y: usize,
) -> Result<bool, LogoGeometryError> {
    let source_x = target_x
        .checked_mul(source_width)
        .ok_or(LogoGeometryError::SizeOverflow)?
        / target_width;
    let source_y = target_y
        .checked_mul(source_height)
        .ok_or(LogoGeometryError::SizeOverflow)?
        / target_height;
    let index = source_y
        .checked_mul(source_width)
        .and_then(|value| value.checked_add(source_x))
        .ok_or(LogoGeometryError::SizeOverflow)?;
    Ok(mask.get(index).copied().unwrap_or(0) == 1)
}

fn aspect_ratio_ppm(bounds: Option<PixelRect>) -> Result<u32, LogoGeometryError> {
    let Some(bounds) = bounds else {
        return Ok(0);
    };
    if bounds.height == 0 {
        return Ok(0);
    }
    let numerator = u64::from(bounds.width)
        .checked_mul(1_000_000)
        .ok_or(LogoGeometryError::SizeOverflow)?;
    let rounded = numerator
        .checked_add(u64::from(bounds.height) / 2)
        .ok_or(LogoGeometryError::SizeOverflow)?
        / u64::from(bounds.height);
    u32::try_from(rounded).map_err(|_| LogoGeometryError::SizeOverflow)
}

fn relative_error_ppm(expected: u32, observed: u32) -> u32 {
    if expected == 0 {
        return 1_000_000;
    }
    let numerator = u64::from(expected.abs_diff(observed)).saturating_mul(1_000_000);
    let rounded = numerator.saturating_add(u64::from(expected) / 2) / u64::from(expected);
    u32::try_from(rounded.min(1_000_000)).unwrap_or(1_000_000)
}

fn pixel_at(
    decoded: &DecodedPng,
    width: usize,
    x: usize,
    y: usize,
) -> Result<[u8; 4], LogoGeometryError> {
    let index = y
        .checked_mul(width)
        .and_then(|value| value.checked_add(x))
        .and_then(|value| value.checked_mul(4))
        .ok_or(LogoGeometryError::SizeOverflow)?;
    let bytes = decoded
        .rgba8
        .get(index..index + 4)
        .ok_or(LogoGeometryError::DecodedPixelLengthMismatch)?;
    Ok([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn color_distance_squared(pixel: [u8; 4], background: [u8; 3]) -> u32 {
    let red = i32::from(pixel[0]) - i32::from(background[0]);
    let green = i32::from(pixel[1]) - i32::from(background[1]);
    let blue = i32::from(pixel[2]) - i32::from(background[2]);
    (red * red + green * green + blue * blue) as u32
}

fn contains(bounds: Bounds, x: usize, y: usize) -> bool {
    x >= bounds.left && x < bounds.right && y >= bounds.top && y < bounds.bottom
}

fn pixel_count(width: usize, height: usize) -> Result<u64, LogoGeometryError> {
    u64::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(u64::try_from(height).ok()?))
        .ok_or(LogoGeometryError::SizeOverflow)
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

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn report_digest(report: &LogoGeometryReport) -> Result<String, LogoGeometryError> {
    let mut value = serde_json::to_value(report)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other(
            "logo geometry report is not an object",
        ))
    })?;
    object.insert(
        "report_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

fn decision_digest(result: &LogoGeometryResult) -> Result<String, LogoGeometryError> {
    let mut value = serde_json::to_value(result)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other(
            "logo geometry result is not an object",
        ))
    })?;
    object.insert(
        "decision_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

#[cfg(test)]
mod tests {
    use super::share_milli;

    #[test]
    fn share_rounding_is_stable() {
        assert_eq!(share_milli(1, 2), 500);
        assert_eq!(share_milli(0, 0), 0);
    }
}
