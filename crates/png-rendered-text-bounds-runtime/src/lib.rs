#![forbid(unsafe_code)]

use ergaxiom_png_pixel_decoder_runtime::DecodedPng;
use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA_VERSION: &str = "0.1.0";
const MAX_ANALYSIS_PIXELS: u64 = 20_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PixelRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedTextBoundsPolicy {
    pub analysis_region: PixelRect,
    pub safe_area: PixelRect,
    pub background_ring_px: u32,
    pub foreground_minimum_distance_squared: u32,
    pub minimum_foreground_pixels: u32,
    pub maximum_foreground_share_milli: u16,
    pub background_max_channel_deviation: u8,
    pub minimum_safe_area_margin_px: u32,
    pub clipping_guard_px: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedTextBoundsReport {
    pub schema_version: String,
    pub artifact_digest: String,
    pub pixel_report_digest: String,
    pub rgba_pixel_digest: String,
    pub analysis_region: PixelRect,
    pub safe_area: PixelRect,
    pub background_ring_px: u32,
    pub analysis_pixel_count: u64,
    pub background_sample_count: u64,
    pub non_opaque_analysis_pixel_count: u64,
    pub non_opaque_background_pixel_count: u64,
    pub background_rgb: [u8; 3],
    pub background_max_channel_deviation: u8,
    pub foreground_pixel_count: u64,
    pub foreground_share_milli: u16,
    pub observed_bounds: Option<PixelRect>,
    pub foreground_outside_safe_area_pixel_count: u64,
    pub foreground_in_clipping_guard_pixel_count: u64,
    pub left_safe_margin_px: u32,
    pub top_safe_margin_px: u32,
    pub right_safe_margin_px: u32,
    pub bottom_safe_margin_px: u32,
    pub report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RenderedTextBoundsViolation {
    NonOpaqueAnalysisPixels {
        count: u64,
    },
    NonOpaqueBackgroundPixels {
        count: u64,
    },
    BackgroundNotUniform {
        allowed: u8,
        actual: u8,
    },
    InsufficientForegroundPixels {
        required: u32,
        actual: u64,
    },
    ForegroundShareTooHigh {
        maximum_milli: u16,
        actual_milli: u16,
    },
    ForegroundOutsideSafeArea {
        count: u64,
    },
    SafeAreaMarginTooSmall {
        required_px: u32,
        left_px: u32,
        top_px: u32,
        right_px: u32,
        bottom_px: u32,
    },
    ForegroundTouchesAnalysisBoundary {
        guard_px: u32,
        count: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedTextBoundsResult {
    pub schema_version: String,
    pub accepted: bool,
    pub report: RenderedTextBoundsReport,
    pub violations: Vec<RenderedTextBoundsViolation>,
    pub decision_digest: String,
}

#[derive(Debug, Error)]
pub enum RenderedTextBoundsError {
    #[error("analysis and safe-area rectangles must have non-zero dimensions")]
    EmptyRegion,
    #[error("analysis region exceeds decoded image bounds")]
    AnalysisRegionOutOfBounds,
    #[error("safe area must remain completely inside the analysis region")]
    SafeAreaOutsideAnalysis,
    #[error("background ring must be non-zero and remain inside the decoded image")]
    InvalidBackgroundRing,
    #[error("clipping guard must be non-zero and smaller than half the analysis dimensions")]
    InvalidClippingGuard,
    #[error("foreground distance and minimum pixel thresholds must be non-zero")]
    InvalidForegroundThreshold,
    #[error("maximum foreground share must be in the range 1 through 1000")]
    InvalidShareThreshold,
    #[error("analysis region exceeds the {MAX_ANALYSIS_PIXELS}-pixel validator limit")]
    AnalysisPixelLimitExceeded,
    #[error("decoded RGBA byte length does not match its pixel report")]
    DecodedPixelLengthMismatch,
    #[error("integer overflow while evaluating rendered text bounds")]
    SizeOverflow,
    #[error("failed to serialize rendered text-bounds evidence: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn validate_rendered_text_bounds(
    decoded: &DecodedPng,
    policy: &RenderedTextBoundsPolicy,
) -> Result<RenderedTextBoundsResult, RenderedTextBoundsError> {
    let geometry = validate_policy(decoded, policy)?;
    let background = measure_background(decoded, geometry)?;
    let measurement = measure_foreground(decoded, policy, geometry, background.rgb)?;

    let mut violations = Vec::new();
    if measurement.non_opaque_analysis > 0 {
        violations.push(RenderedTextBoundsViolation::NonOpaqueAnalysisPixels {
            count: measurement.non_opaque_analysis,
        });
    }
    if background.non_opaque > 0 {
        violations.push(RenderedTextBoundsViolation::NonOpaqueBackgroundPixels {
            count: background.non_opaque,
        });
    }
    if background.max_deviation > policy.background_max_channel_deviation {
        violations.push(RenderedTextBoundsViolation::BackgroundNotUniform {
            allowed: policy.background_max_channel_deviation,
            actual: background.max_deviation,
        });
    }
    if measurement.foreground_count < u64::from(policy.minimum_foreground_pixels) {
        violations.push(RenderedTextBoundsViolation::InsufficientForegroundPixels {
            required: policy.minimum_foreground_pixels,
            actual: measurement.foreground_count,
        });
    }
    if measurement.foreground_share_milli > policy.maximum_foreground_share_milli {
        violations.push(RenderedTextBoundsViolation::ForegroundShareTooHigh {
            maximum_milli: policy.maximum_foreground_share_milli,
            actual_milli: measurement.foreground_share_milli,
        });
    }
    if measurement.outside_safe_area > 0 {
        violations.push(RenderedTextBoundsViolation::ForegroundOutsideSafeArea {
            count: measurement.outside_safe_area,
        });
    }
    if measurement.observed_bounds.is_some()
        && (measurement.left_margin < policy.minimum_safe_area_margin_px
            || measurement.top_margin < policy.minimum_safe_area_margin_px
            || measurement.right_margin < policy.minimum_safe_area_margin_px
            || measurement.bottom_margin < policy.minimum_safe_area_margin_px)
    {
        violations.push(RenderedTextBoundsViolation::SafeAreaMarginTooSmall {
            required_px: policy.minimum_safe_area_margin_px,
            left_px: measurement.left_margin,
            top_px: measurement.top_margin,
            right_px: measurement.right_margin,
            bottom_px: measurement.bottom_margin,
        });
    }
    if measurement.clipping_guard_count > 0 {
        violations.push(
            RenderedTextBoundsViolation::ForegroundTouchesAnalysisBoundary {
                guard_px: policy.clipping_guard_px,
                count: measurement.clipping_guard_count,
            },
        );
    }

    let mut report = RenderedTextBoundsReport {
        schema_version: SCHEMA_VERSION.to_owned(),
        artifact_digest: decoded.report.artifact_digest.clone(),
        pixel_report_digest: decoded.report.report_digest.clone(),
        rgba_pixel_digest: decoded.report.rgba_pixel_digest.clone(),
        analysis_region: policy.analysis_region,
        safe_area: policy.safe_area,
        background_ring_px: policy.background_ring_px,
        analysis_pixel_count: geometry.analysis_pixels,
        background_sample_count: geometry.background_pixels,
        non_opaque_analysis_pixel_count: measurement.non_opaque_analysis,
        non_opaque_background_pixel_count: background.non_opaque,
        background_rgb: background.rgb,
        background_max_channel_deviation: background.max_deviation,
        foreground_pixel_count: measurement.foreground_count,
        foreground_share_milli: measurement.foreground_share_milli,
        observed_bounds: measurement.observed_bounds,
        foreground_outside_safe_area_pixel_count: measurement.outside_safe_area,
        foreground_in_clipping_guard_pixel_count: measurement.clipping_guard_count,
        left_safe_margin_px: measurement.left_margin,
        top_safe_margin_px: measurement.top_margin,
        right_safe_margin_px: measurement.right_margin,
        bottom_safe_margin_px: measurement.bottom_margin,
        report_digest: String::new(),
    };
    report.report_digest = report_digest(&report)?;

    let mut result = RenderedTextBoundsResult {
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
    analysis: Bounds,
    safe: Bounds,
    expanded: Bounds,
    analysis_pixels: u64,
    background_pixels: u64,
    image_width: usize,
    clipping_guard: usize,
}

#[derive(Debug)]
struct BackgroundMeasurement {
    rgb: [u8; 3],
    max_deviation: u8,
    non_opaque: u64,
}

#[derive(Debug)]
struct ForegroundMeasurement {
    non_opaque_analysis: u64,
    foreground_count: u64,
    foreground_share_milli: u16,
    observed_bounds: Option<PixelRect>,
    outside_safe_area: u64,
    clipping_guard_count: u64,
    left_margin: u32,
    top_margin: u32,
    right_margin: u32,
    bottom_margin: u32,
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

    fn include(&mut self, x: usize, y: usize) -> Result<(), RenderedTextBoundsError> {
        self.any = true;
        self.left = self.left.min(x);
        self.top = self.top.min(y);
        self.right = self
            .right
            .max(x.checked_add(1).ok_or(RenderedTextBoundsError::SizeOverflow)?);
        self.bottom = self
            .bottom
            .max(y.checked_add(1).ok_or(RenderedTextBoundsError::SizeOverflow)?);
        Ok(())
    }

    fn rect(&self) -> Result<Option<PixelRect>, RenderedTextBoundsError> {
        if !self.any {
            return Ok(None);
        }
        Ok(Some(PixelRect {
            x: u32::try_from(self.left).map_err(|_| RenderedTextBoundsError::SizeOverflow)?,
            y: u32::try_from(self.top).map_err(|_| RenderedTextBoundsError::SizeOverflow)?,
            width: u32::try_from(self.right - self.left)
                .map_err(|_| RenderedTextBoundsError::SizeOverflow)?,
            height: u32::try_from(self.bottom - self.top)
                .map_err(|_| RenderedTextBoundsError::SizeOverflow)?,
        }))
    }
}

fn validate_policy(
    decoded: &DecodedPng,
    policy: &RenderedTextBoundsPolicy,
) -> Result<Geometry, RenderedTextBoundsError> {
    let image_width =
        usize::try_from(decoded.report.width).map_err(|_| RenderedTextBoundsError::SizeOverflow)?;
    let image_height =
        usize::try_from(decoded.report.height).map_err(|_| RenderedTextBoundsError::SizeOverflow)?;
    let image_pixels = pixel_count(image_width, image_height)?;
    let expected_rgba = usize::try_from(image_pixels)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(RenderedTextBoundsError::SizeOverflow)?;
    if decoded.rgba8.len() != expected_rgba {
        return Err(RenderedTextBoundsError::DecodedPixelLengthMismatch);
    }

    if is_empty(policy.analysis_region) || is_empty(policy.safe_area) {
        return Err(RenderedTextBoundsError::EmptyRegion);
    }
    if policy.background_ring_px == 0 {
        return Err(RenderedTextBoundsError::InvalidBackgroundRing);
    }
    if policy.foreground_minimum_distance_squared == 0 || policy.minimum_foreground_pixels == 0 {
        return Err(RenderedTextBoundsError::InvalidForegroundThreshold);
    }
    if !(1..=1000).contains(&policy.maximum_foreground_share_milli) {
        return Err(RenderedTextBoundsError::InvalidShareThreshold);
    }

    let analysis = rect_to_bounds(policy.analysis_region)?;
    let safe = rect_to_bounds(policy.safe_area)?;
    if analysis.right > image_width || analysis.bottom > image_height {
        return Err(RenderedTextBoundsError::AnalysisRegionOutOfBounds);
    }
    if !contains_bounds(analysis, safe) {
        return Err(RenderedTextBoundsError::SafeAreaOutsideAnalysis);
    }

    let analysis_width = analysis.right - analysis.left;
    let analysis_height = analysis.bottom - analysis.top;
    let analysis_pixels = pixel_count(analysis_width, analysis_height)?;
    if analysis_pixels > MAX_ANALYSIS_PIXELS {
        return Err(RenderedTextBoundsError::AnalysisPixelLimitExceeded);
    }

    let clipping_guard = usize::try_from(policy.clipping_guard_px)
        .map_err(|_| RenderedTextBoundsError::SizeOverflow)?;
    if clipping_guard == 0
        || clipping_guard
            .checked_mul(2)
            .ok_or(RenderedTextBoundsError::SizeOverflow)?
            >= analysis_width
        || clipping_guard
            .checked_mul(2)
            .ok_or(RenderedTextBoundsError::SizeOverflow)?
            >= analysis_height
    {
        return Err(RenderedTextBoundsError::InvalidClippingGuard);
    }

    let ring = usize::try_from(policy.background_ring_px)
        .map_err(|_| RenderedTextBoundsError::SizeOverflow)?;
    let expanded = expand_bounds(analysis, ring, image_width, image_height)?;
    let expanded_pixels = pixel_count(
        expanded.right - expanded.left,
        expanded.bottom - expanded.top,
    )?;
    let background_pixels = expanded_pixels
        .checked_sub(analysis_pixels)
        .ok_or(RenderedTextBoundsError::SizeOverflow)?;

    Ok(Geometry {
        analysis,
        safe,
        expanded,
        analysis_pixels,
        background_pixels,
        image_width,
        clipping_guard,
    })
}

fn measure_background(
    decoded: &DecodedPng,
    geometry: Geometry,
) -> Result<BackgroundMeasurement, RenderedTextBoundsError> {
    let mut histograms = [[0_u64; 256]; 3];
    let mut non_opaque = 0_u64;
    for y in geometry.expanded.top..geometry.expanded.bottom {
        for x in geometry.expanded.left..geometry.expanded.right {
            if contains(geometry.analysis, x, y) {
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
        histogram_median(&histograms[0], geometry.background_pixels),
        histogram_median(&histograms[1], geometry.background_pixels),
        histogram_median(&histograms[2], geometry.background_pixels),
    ];
    let mut max_deviation = 0_u8;
    for y in geometry.expanded.top..geometry.expanded.bottom {
        for x in geometry.expanded.left..geometry.expanded.right {
            if contains(geometry.analysis, x, y) {
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
    policy: &RenderedTextBoundsPolicy,
    geometry: Geometry,
    background: [u8; 3],
) -> Result<ForegroundMeasurement, RenderedTextBoundsError> {
    let mut tracker = BoundsTracker::new();
    let mut non_opaque_analysis = 0_u64;
    let mut foreground_count = 0_u64;
    let mut outside_safe_area = 0_u64;
    let mut clipping_guard_count = 0_u64;

    for y in geometry.analysis.top..geometry.analysis.bottom {
        for x in geometry.analysis.left..geometry.analysis.right {
            let pixel = pixel_at(decoded, geometry.image_width, x, y)?;
            if pixel[3] != 255 {
                non_opaque_analysis = non_opaque_analysis.saturating_add(1);
            }
            if color_distance_squared(pixel, background)
                < policy.foreground_minimum_distance_squared
            {
                continue;
            }
            foreground_count = foreground_count.saturating_add(1);
            tracker.include(x, y)?;
            if !contains(geometry.safe, x, y) {
                outside_safe_area = outside_safe_area.saturating_add(1);
            }
            let relative_x = x - geometry.analysis.left;
            let relative_y = y - geometry.analysis.top;
            let width = geometry.analysis.right - geometry.analysis.left;
            let height = geometry.analysis.bottom - geometry.analysis.top;
            if relative_x < geometry.clipping_guard
                || relative_y < geometry.clipping_guard
                || relative_x >= width - geometry.clipping_guard
                || relative_y >= height - geometry.clipping_guard
            {
                clipping_guard_count = clipping_guard_count.saturating_add(1);
            }
        }
    }

    let observed_bounds = tracker.rect()?;
    let (left_margin, top_margin, right_margin, bottom_margin) =
        safe_margins(observed_bounds, geometry.safe)?;

    Ok(ForegroundMeasurement {
        non_opaque_analysis,
        foreground_count,
        foreground_share_milli: share_milli(foreground_count, geometry.analysis_pixels),
        observed_bounds,
        outside_safe_area,
        clipping_guard_count,
        left_margin,
        top_margin,
        right_margin,
        bottom_margin,
    })
}

fn safe_margins(
    observed: Option<PixelRect>,
    safe: Bounds,
) -> Result<(u32, u32, u32, u32), RenderedTextBoundsError> {
    let Some(observed) = observed else {
        return Ok((0, 0, 0, 0));
    };
    let observed = rect_to_bounds(observed)?;
    let left = observed.left.saturating_sub(safe.left);
    let top = observed.top.saturating_sub(safe.top);
    let right = safe.right.saturating_sub(observed.right);
    let bottom = safe.bottom.saturating_sub(observed.bottom);
    Ok((
        u32::try_from(left).map_err(|_| RenderedTextBoundsError::SizeOverflow)?,
        u32::try_from(top).map_err(|_| RenderedTextBoundsError::SizeOverflow)?,
        u32::try_from(right).map_err(|_| RenderedTextBoundsError::SizeOverflow)?,
        u32::try_from(bottom).map_err(|_| RenderedTextBoundsError::SizeOverflow)?,
    ))
}

fn rect_to_bounds(rect: PixelRect) -> Result<Bounds, RenderedTextBoundsError> {
    let left = usize::try_from(rect.x).map_err(|_| RenderedTextBoundsError::SizeOverflow)?;
    let top = usize::try_from(rect.y).map_err(|_| RenderedTextBoundsError::SizeOverflow)?;
    let width = usize::try_from(rect.width).map_err(|_| RenderedTextBoundsError::SizeOverflow)?;
    let height = usize::try_from(rect.height).map_err(|_| RenderedTextBoundsError::SizeOverflow)?;
    Ok(Bounds {
        left,
        top,
        right: left
            .checked_add(width)
            .ok_or(RenderedTextBoundsError::SizeOverflow)?,
        bottom: top
            .checked_add(height)
            .ok_or(RenderedTextBoundsError::SizeOverflow)?,
    })
}

fn expand_bounds(
    bounds: Bounds,
    amount: usize,
    image_width: usize,
    image_height: usize,
) -> Result<Bounds, RenderedTextBoundsError> {
    let left = bounds
        .left
        .checked_sub(amount)
        .ok_or(RenderedTextBoundsError::InvalidBackgroundRing)?;
    let top = bounds
        .top
        .checked_sub(amount)
        .ok_or(RenderedTextBoundsError::InvalidBackgroundRing)?;
    let right = bounds
        .right
        .checked_add(amount)
        .ok_or(RenderedTextBoundsError::SizeOverflow)?;
    let bottom = bounds
        .bottom
        .checked_add(amount)
        .ok_or(RenderedTextBoundsError::SizeOverflow)?;
    if right > image_width || bottom > image_height {
        return Err(RenderedTextBoundsError::InvalidBackgroundRing);
    }
    Ok(Bounds {
        left,
        top,
        right,
        bottom,
    })
}

fn is_empty(rect: PixelRect) -> bool {
    rect.width == 0 || rect.height == 0
}

fn contains(bounds: Bounds, x: usize, y: usize) -> bool {
    x >= bounds.left && x < bounds.right && y >= bounds.top && y < bounds.bottom
}

fn contains_bounds(outer: Bounds, inner: Bounds) -> bool {
    inner.left >= outer.left
        && inner.top >= outer.top
        && inner.right <= outer.right
        && inner.bottom <= outer.bottom
}

fn pixel_at(
    decoded: &DecodedPng,
    width: usize,
    x: usize,
    y: usize,
) -> Result<[u8; 4], RenderedTextBoundsError> {
    let index = y
        .checked_mul(width)
        .and_then(|value| value.checked_add(x))
        .and_then(|value| value.checked_mul(4))
        .ok_or(RenderedTextBoundsError::SizeOverflow)?;
    let bytes = decoded
        .rgba8
        .get(index..index + 4)
        .ok_or(RenderedTextBoundsError::DecodedPixelLengthMismatch)?;
    Ok([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn color_distance_squared(pixel: [u8; 4], background: [u8; 3]) -> u32 {
    let red = i32::from(pixel[0]) - i32::from(background[0]);
    let green = i32::from(pixel[1]) - i32::from(background[1]);
    let blue = i32::from(pixel[2]) - i32::from(background[2]);
    (red * red + green * green + blue * blue) as u32
}

fn pixel_count(width: usize, height: usize) -> Result<u64, RenderedTextBoundsError> {
    u64::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(u64::try_from(height).ok()?))
        .ok_or(RenderedTextBoundsError::SizeOverflow)
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

fn report_digest(
    report: &RenderedTextBoundsReport,
) -> Result<String, RenderedTextBoundsError> {
    let mut value = serde_json::to_value(report)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other("text bounds report is not an object"))
    })?;
    object.insert(
        "report_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

fn decision_digest(
    result: &RenderedTextBoundsResult,
) -> Result<String, RenderedTextBoundsError> {
    let mut value = serde_json::to_value(result)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other("text bounds result is not an object"))
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
        assert_eq!(share_milli(1, 8), 125);
        assert_eq!(share_milli(0, 0), 0);
    }
}
