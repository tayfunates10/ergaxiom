use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};
use thiserror::Error;

use crate::model::{PrintSourceValidationReport, PrintSpecification};
use crate::util::{PrintDigestError, canonical_record_digest, canonical_value_digest, sha256_hex};

const REPORT_SCHEMA: &str = "0.1.0";
const VALIDATOR_VERSION: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum PrintSvgError {
    #[error("invalid UTF-8 in SVG: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("malformed SVG XML: {0}")]
    Xml(String),
    #[error("print specification is invalid: {0}")]
    InvalidSpecification(String),
    #[error(transparent)]
    Digest(#[from] PrintDigestError),
}

#[derive(Debug, Clone, Copy)]
struct Bounds {
    min_x: i64,
    min_y: i64,
    max_x: i64,
    max_y: i64,
}

#[derive(Debug, Default)]
struct SvgMeasurements {
    root_seen: bool,
    root_width: Option<i64>,
    root_height: Option<i64>,
    view_box: Option<[i64; 4]>,
    restricted: bool,
    background_ok: bool,
    safe_area_ok: bool,
    palette_violations: u64,
    raster_images: u64,
    live_text: u64,
    unsupported_paths: u64,
    ids: BTreeSet<String>,
}

pub fn validate_print_specification(spec: &PrintSpecification) -> Result<(), PrintSvgError> {
    if spec.schema_version != "0.1.0" {
        return Err(PrintSvgError::InvalidSpecification(
            "schema_version must be 0.1.0".to_owned(),
        ));
    }
    if spec.manifest_id.trim().is_empty()
        || spec.background_element_id.trim().is_empty()
        || spec.trim_width_milli_mm == 0
        || spec.trim_height_milli_mm == 0
        || spec.bleed_milli_mm == 0
        || spec.safe_margin_milli_mm == 0
    {
        return Err(PrintSvgError::InvalidSpecification(
            "identity, trim, bleed and safe margin must be resolved and positive".to_owned(),
        ));
    }
    if spec.allowed_palette.is_empty() || spec.allowed_pdf_color_spaces.is_empty() {
        return Err(PrintSvgError::InvalidSpecification(
            "palette and PDF color-space allowlists must be non-empty".to_owned(),
        ));
    }
    let mut colors = BTreeSet::new();
    for color in &spec.allowed_palette {
        let normalized = normalize_color(color).ok_or_else(|| {
            PrintSvgError::InvalidSpecification(format!(
                "palette entry is not lowercase #rrggbb: {color}"
            ))
        })?;
        if normalized != *color || !colors.insert(normalized) {
            return Err(PrintSvgError::InvalidSpecification(
                "palette entries must be unique lowercase #rrggbb values".to_owned(),
            ));
        }
    }
    for color_space in &spec.allowed_pdf_color_spaces {
        if !matches!(color_space.as_str(), "DeviceRGB" | "DeviceGray") {
            return Err(PrintSvgError::InvalidSpecification(
                "certified PDF color spaces are limited to DeviceRGB and DeviceGray".to_owned(),
            ));
        }
    }
    if spec.required_pdf_version != "1.5" {
        return Err(PrintSvgError::InvalidSpecification(
            "certified profile currently requires PDF 1.5".to_owned(),
        ));
    }
    let total_width = u64::from(spec.trim_width_milli_mm)
        .checked_add(u64::from(spec.bleed_milli_mm) * 2)
        .ok_or_else(|| PrintSvgError::InvalidSpecification("width overflow".to_owned()))?;
    let total_height = u64::from(spec.trim_height_milli_mm)
        .checked_add(u64::from(spec.bleed_milli_mm) * 2)
        .ok_or_else(|| PrintSvgError::InvalidSpecification("height overflow".to_owned()))?;
    if total_width > 2_000_000 || total_height > 2_000_000 {
        return Err(PrintSvgError::InvalidSpecification(
            "poster edge exceeds the 2000 mm certified limit".to_owned(),
        ));
    }
    let inset = u64::from(spec.bleed_milli_mm) + u64::from(spec.safe_margin_milli_mm);
    if inset * 2 >= total_width || inset * 2 >= total_height {
        return Err(PrintSvgError::InvalidSpecification(
            "bleed plus safe margin consumes the page".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_print_source(
    source_svg: &[u8],
    spec: &PrintSpecification,
) -> Result<PrintSourceValidationReport, PrintSvgError> {
    validate_print_specification(spec)?;
    let mut measurements = inspect_svg(source_svg, spec)?;
    let total_width = i64::from(spec.trim_width_milli_mm) + 2 * i64::from(spec.bleed_milli_mm);
    let total_height = i64::from(spec.trim_height_milli_mm) + 2 * i64::from(spec.bleed_milli_mm);
    let canvas_dimensions_match = measurements.root_seen
        && measurements.root_width == Some(total_width)
        && measurements.root_height == Some(total_height)
        && measurements.view_box == Some([0, 0, total_width, total_height]);
    measurements.restricted &= measurements.root_seen;
    let accepted = measurements.restricted
        && canvas_dimensions_match
        && measurements.background_ok
        && measurements.safe_area_ok
        && measurements.palette_violations == 0
        && measurements.raster_images == 0
        && measurements.live_text == 0
        && measurements.unsupported_paths == 0;
    let mut report = PrintSourceValidationReport {
        schema_version: REPORT_SCHEMA.to_owned(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        source_svg_digest: sha256_hex(source_svg),
        specification_digest: canonical_value_digest(spec)?,
        restricted_svg_profile: measurements.restricted,
        canvas_dimensions_match,
        bleed_coverage: measurements.background_ok,
        safe_area_satisfied: measurements.safe_area_ok,
        palette_violation_count: measurements.palette_violations,
        raster_image_count: measurements.raster_images,
        live_text_count: measurements.live_text,
        unsupported_path_count: measurements.unsupported_paths,
        accepted,
        report_digest: String::new(),
    };
    report.report_digest = canonical_record_digest(&report, "report_digest")?;
    Ok(report)
}

pub fn render_restricted_print_svg(spec: &PrintSpecification) -> Result<Vec<u8>, PrintSvgError> {
    validate_print_specification(spec)?;
    let total_width = i64::from(spec.trim_width_milli_mm) + 2 * i64::from(spec.bleed_milli_mm);
    let total_height = i64::from(spec.trim_height_milli_mm) + 2 * i64::from(spec.bleed_milli_mm);
    let inset = i64::from(spec.bleed_milli_mm) + i64::from(spec.safe_margin_milli_mm);
    let content_width = total_width - 2 * inset;
    let content_height = total_height - 2 * inset;
    let background = spec
        .allowed_palette
        .first()
        .ok_or_else(|| PrintSvgError::InvalidSpecification("palette is empty".to_owned()))?;
    let foreground = spec.allowed_palette.get(1).unwrap_or(background);
    let x2 = inset + content_width;
    let y2 = inset + content_height;
    let svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" width=\"{}mm\" height=\"{}mm\" viewBox=\"0 0 {} {}\"><rect id=\"{}\" x=\"0\" y=\"0\" width=\"{}\" height=\"{}\" fill=\"{}\"/><g id=\"outlined-content\"><path id=\"outlined-title\" d=\"M {} {} L {} {} L {} {} L {} {} Z\" fill=\"{}\"/></g></svg>",
        format_milli(total_width),
        format_milli(total_height),
        format_milli(total_width),
        format_milli(total_height),
        spec.background_element_id,
        format_milli(total_width),
        format_milli(total_height),
        background,
        format_milli(inset),
        format_milli(inset),
        format_milli(x2),
        format_milli(inset),
        format_milli(x2),
        format_milli(y2),
        format_milli(inset),
        format_milli(y2),
        foreground,
    );
    Ok(svg.into_bytes())
}

fn inspect_svg(
    source_svg: &[u8],
    spec: &PrintSpecification,
) -> Result<SvgMeasurements, PrintSvgError> {
    std::str::from_utf8(source_svg)?;
    let mut reader = Reader::from_reader(Cursor::new(source_svg));
    reader.config_mut().trim_text(true);
    let mut measurements = SvgMeasurements {
        restricted: true,
        safe_area_ok: true,
        ..SvgMeasurements::default()
    };
    let allowed_palette: BTreeSet<&str> = spec.allowed_palette.iter().map(String::as_str).collect();
    let total_width = i64::from(spec.trim_width_milli_mm) + 2 * i64::from(spec.bleed_milli_mm);
    let total_height = i64::from(spec.trim_height_milli_mm) + 2 * i64::from(spec.bleed_milli_mm);
    let safe_left = i64::from(spec.bleed_milli_mm) + i64::from(spec.safe_margin_milli_mm);
    let safe_top = safe_left;
    let safe_right = total_width - safe_left;
    let safe_bottom = total_height - safe_top;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) | Ok(Event::Empty(element)) => {
                let name = local_name(element.name().as_ref());
                let attributes = decode_attributes(&reader, &element)?;
                match name.as_str() {
                    "svg" => {
                        if measurements.root_seen {
                            measurements.restricted = false;
                        }
                        measurements.root_seen = true;
                        measurements.root_width = attributes
                            .get("width")
                            .and_then(|value| parse_mm_dimension(value));
                        measurements.root_height = attributes
                            .get("height")
                            .and_then(|value| parse_mm_dimension(value));
                        measurements.view_box = attributes
                            .get("viewBox")
                            .and_then(|value| parse_view_box(value));
                        measurements.restricted &= allowed_attributes(
                            &attributes,
                            &["xmlns", "version", "width", "height", "viewBox"],
                        );
                    }
                    "g" => {
                        measurements.restricted &= allowed_attributes(&attributes, &["id"]);
                        register_id(&mut measurements, &attributes);
                    }
                    "rect" => {
                        measurements.restricted &= allowed_attributes(
                            &attributes,
                            &["id", "x", "y", "width", "height", "fill"],
                        );
                        register_id(&mut measurements, &attributes);
                        validate_fill(&mut measurements, &attributes, &allowed_palette);
                        let bounds = rect_bounds(&attributes);
                        if attributes.get("id").map(String::as_str)
                            == Some(spec.background_element_id.as_str())
                        {
                            measurements.background_ok = bounds.is_some_and(|bounds| {
                                bounds.min_x == 0
                                    && bounds.min_y == 0
                                    && bounds.max_x == total_width
                                    && bounds.max_y == total_height
                            });
                        } else if let Some(bounds) = bounds {
                            measurements.safe_area_ok &= inside_safe_area(
                                bounds,
                                safe_left,
                                safe_top,
                                safe_right,
                                safe_bottom,
                            );
                        } else {
                            measurements.restricted = false;
                        }
                    }
                    "path" => {
                        measurements.restricted &=
                            allowed_attributes(&attributes, &["id", "d", "fill"]);
                        register_id(&mut measurements, &attributes);
                        validate_fill(&mut measurements, &attributes, &allowed_palette);
                        match attributes
                            .get("d")
                            .and_then(|value| simple_path_bounds(value))
                        {
                            Some(bounds) => {
                                measurements.safe_area_ok &= inside_safe_area(
                                    bounds,
                                    safe_left,
                                    safe_top,
                                    safe_right,
                                    safe_bottom,
                                );
                            }
                            None => measurements.unsupported_paths += 1,
                        }
                    }
                    "image" => {
                        measurements.raster_images += 1;
                        measurements.restricted = false;
                    }
                    "text" | "tspan" => {
                        measurements.live_text += 1;
                        measurements.restricted = false;
                    }
                    _ => measurements.restricted = false,
                }
                if attributes.keys().any(|key| {
                    key.starts_with("on")
                        || matches!(
                            key.as_str(),
                            "href"
                                | "xlink:href"
                                | "style"
                                | "transform"
                                | "opacity"
                                | "filter"
                                | "mask"
                                | "clip-path"
                                | "stroke"
                        )
                }) {
                    measurements.restricted = false;
                }
            }
            Ok(Event::DocType(_)) | Ok(Event::GeneralRef(_)) => {
                measurements.restricted = false;
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(PrintSvgError::Xml(error.to_string())),
        }
    }
    Ok(measurements)
}

fn decode_attributes(
    reader: &Reader<Cursor<&[u8]>>,
    element: &quick_xml::events::BytesStart<'_>,
) -> Result<BTreeMap<String, String>, PrintSvgError> {
    let mut values = BTreeMap::new();
    for attribute in element.attributes().with_checks(false) {
        let attribute = attribute.map_err(|error| PrintSvgError::Xml(error.to_string()))?;
        let key = local_name(attribute.key.as_ref());
        let value = attribute
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
            .map_err(|error| PrintSvgError::Xml(error.to_string()))?
            .into_owned();
        if values.insert(key, value).is_some() {
            return Err(PrintSvgError::Xml("duplicate attribute".to_owned()));
        }
    }
    Ok(values)
}

fn local_name(raw: &[u8]) -> String {
    let raw = std::str::from_utf8(raw).unwrap_or_default();
    raw.rsplit(':').next().unwrap_or(raw).to_owned()
}

fn allowed_attributes(attributes: &BTreeMap<String, String>, allowed: &[&str]) -> bool {
    attributes
        .keys()
        .all(|key| allowed.iter().any(|candidate| key == candidate))
}

fn register_id(measurements: &mut SvgMeasurements, attributes: &BTreeMap<String, String>) {
    let Some(id) = attributes.get("id") else {
        measurements.restricted = false;
        return;
    };
    if id.is_empty() || !measurements.ids.insert(id.clone()) {
        measurements.restricted = false;
    }
}

fn validate_fill(
    measurements: &mut SvgMeasurements,
    attributes: &BTreeMap<String, String>,
    allowed_palette: &BTreeSet<&str>,
) {
    let Some(fill) = attributes
        .get("fill")
        .and_then(|value| normalize_color(value))
    else {
        measurements.palette_violations += 1;
        return;
    };
    if !allowed_palette.contains(fill.as_str()) {
        measurements.palette_violations += 1;
    }
}

fn normalize_color(value: &str) -> Option<String> {
    let value = value.trim();
    if value.len() == 7
        && value.starts_with('#')
        && value[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

fn parse_mm_dimension(value: &str) -> Option<i64> {
    value.strip_suffix("mm").and_then(parse_decimal_milli)
}

fn parse_view_box(value: &str) -> Option<[i64; 4]> {
    let values = value
        .split(|character: char| character.is_ascii_whitespace() || character == ',')
        .filter(|part| !part.is_empty())
        .map(parse_decimal_milli)
        .collect::<Option<Vec<_>>>()?;
    values.try_into().ok()
}

fn rect_bounds(attributes: &BTreeMap<String, String>) -> Option<Bounds> {
    let x = attributes
        .get("x")
        .and_then(|value| parse_decimal_milli(value))?;
    let y = attributes
        .get("y")
        .and_then(|value| parse_decimal_milli(value))?;
    let width = attributes
        .get("width")
        .and_then(|value| parse_decimal_milli(value))?;
    let height = attributes
        .get("height")
        .and_then(|value| parse_decimal_milli(value))?;
    if width <= 0 || height <= 0 {
        return None;
    }
    Some(Bounds {
        min_x: x,
        min_y: y,
        max_x: x.checked_add(width)?,
        max_y: y.checked_add(height)?,
    })
}

fn simple_path_bounds(value: &str) -> Option<Bounds> {
    let tokens = tokenize_path(value)?;
    let mut index = 0;
    let mut command = None;
    let mut current_x = 0;
    let mut current_y = 0;
    let mut points = Vec::new();
    while index < tokens.len() {
        if let PathToken::Command(value) = tokens[index] {
            command = Some(value);
            index += 1;
            if value == 'Z' {
                continue;
            }
        }
        match command? {
            'M' | 'L' => {
                let x = token_number(tokens.get(index)?)?;
                let y = token_number(tokens.get(index + 1)?)?;
                current_x = x;
                current_y = y;
                points.push((x, y));
                index += 2;
            }
            'H' => {
                current_x = token_number(tokens.get(index)?)?;
                points.push((current_x, current_y));
                index += 1;
            }
            'V' => {
                current_y = token_number(tokens.get(index)?)?;
                points.push((current_x, current_y));
                index += 1;
            }
            'Z' => return None,
            _ => return None,
        }
    }
    let mut iterator = points.into_iter();
    let (first_x, first_y) = iterator.next()?;
    let mut bounds = Bounds {
        min_x: first_x,
        min_y: first_y,
        max_x: first_x,
        max_y: first_y,
    };
    for (x, y) in iterator {
        bounds.min_x = bounds.min_x.min(x);
        bounds.min_y = bounds.min_y.min(y);
        bounds.max_x = bounds.max_x.max(x);
        bounds.max_y = bounds.max_y.max(y);
    }
    Some(bounds)
}

#[derive(Debug, Clone, Copy)]
enum PathToken {
    Command(char),
    Number(i64),
}

fn tokenize_path(value: &str) -> Option<Vec<PathToken>> {
    let mut tokens = Vec::new();
    let mut number = String::new();
    let flush = |number: &mut String, tokens: &mut Vec<PathToken>| -> Option<()> {
        if !number.is_empty() {
            tokens.push(PathToken::Number(parse_decimal_milli(number)?));
            number.clear();
        }
        Some(())
    };
    for character in value.chars() {
        if character.is_ascii_alphabetic() {
            flush(&mut number, &mut tokens)?;
            if !matches!(character, 'M' | 'L' | 'H' | 'V' | 'Z') {
                return None;
            }
            tokens.push(PathToken::Command(character));
        } else if character.is_ascii_whitespace() || character == ',' {
            flush(&mut number, &mut tokens)?;
        } else if character == '-' || character == '+' {
            flush(&mut number, &mut tokens)?;
            number.push(character);
        } else if character.is_ascii_digit() || character == '.' {
            number.push(character);
        } else {
            return None;
        }
    }
    flush(&mut number, &mut tokens)?;
    Some(tokens)
}

fn token_number(token: &PathToken) -> Option<i64> {
    match token {
        PathToken::Number(value) => Some(*value),
        PathToken::Command(_) => None,
    }
}

fn parse_decimal_milli(value: &str) -> Option<i64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (negative, unsigned) = match value.as_bytes().first()? {
        b'-' => (true, &value[1..]),
        b'+' => (false, &value[1..]),
        _ => (false, value),
    };
    let mut parts = unsigned.split('.');
    let whole = parts.next()?;
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let mut fractional = fraction.unwrap_or("").to_owned();
    if fractional.len() > 3 || !fractional.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    while fractional.len() < 3 {
        fractional.push('0');
    }
    let whole: i64 = whole.parse().ok()?;
    let fraction: i64 = if fractional.is_empty() {
        0
    } else {
        fractional.parse().ok()?
    };
    let value = whole.checked_mul(1000)?.checked_add(fraction)?;
    Some(if negative { -value } else { value })
}

fn inside_safe_area(bounds: Bounds, left: i64, top: i64, right: i64, bottom: i64) -> bool {
    bounds.min_x >= left && bounds.min_y >= top && bounds.max_x <= right && bounds.max_y <= bottom
}

fn format_milli(value: i64) -> String {
    let whole = value / 1000;
    let fraction = value.abs() % 1000;
    if fraction == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{fraction:03}")
            .trim_end_matches('0')
            .to_owned()
    }
}
