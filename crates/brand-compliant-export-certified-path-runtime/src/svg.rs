use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::str;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use thiserror::Error;

use crate::model::{BrandRuleManifest, BrandSourceValidationReport};
use crate::util::{
    BrandDigestError, canonical_record_digest, canonical_value_digest, is_sha256, sha256_hex,
};

const REPORT_SCHEMA: &str = "0.1.0";
const VALIDATOR_VERSION: &str = "0.1.0";
const MANIFEST_SCHEMA: &str = "0.1.0";
const MAX_SVG_BYTES: usize = 8 * 1024 * 1024;
const MAX_LOGO_BYTES: usize = 32 * 1024 * 1024;
const MAX_CANVAS_EDGE: u32 = 16_384;

#[derive(Debug, Error)]
pub enum BrandSvgError {
    #[error("brand manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("SVG exceeds the certified byte limit")]
    SvgTooLarge,
    #[error("approved logo exceeds the certified byte limit")]
    LogoTooLarge,
    #[error("SVG is not valid UTF-8")]
    InvalidUtf8,
    #[error("SVG XML is malformed: {0}")]
    Xml(String),
    #[error("SVG contains a forbidden document type, processing instruction or unsupported node")]
    ForbiddenNode,
    #[error("SVG root is missing or duplicated")]
    InvalidRoot,
    #[error("SVG contains an unsupported element: {0}")]
    UnsupportedElement(String),
    #[error("SVG contains a duplicate or unexpected brand element: {0}")]
    UnexpectedElement(String),
    #[error("SVG attribute is missing or invalid: {0}")]
    InvalidAttribute(String),
    #[error("embedded logo is missing, external or malformed")]
    InvalidEmbeddedLogo,
    #[error("text element must contain exactly one direct text segment")]
    InvalidTextShape,
    #[error(transparent)]
    Digest(#[from] BrandDigestError),
}

#[derive(Debug, Clone)]
struct ParsedSvg {
    width: u32,
    height: u32,
    view_box: String,
    fills: BTreeSet<String>,
    background: ParsedBackground,
    logo: ParsedLogo,
    typography: ParsedTypography,
}

#[derive(Debug, Clone)]
struct ParsedBackground {
    element_id: String,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    color: String,
}

#[derive(Debug, Clone)]
struct ParsedLogo {
    element_id: String,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    embedded_digest: String,
}

#[derive(Debug, Clone)]
struct ParsedTypography {
    element_id: String,
    x: u32,
    y: u32,
    font_family: String,
    font_size: u32,
    font_weight: u16,
    color: String,
    text_anchor: String,
    text: String,
}

#[derive(Debug)]
struct OpenText {
    attributes: BTreeMap<String, String>,
    text_segments: Vec<String>,
    nested: bool,
}

pub fn render_restricted_brand_svg(
    manifest: &BrandRuleManifest,
    approved_logo_png: &[u8],
) -> Result<Vec<u8>, BrandSvgError> {
    validate_manifest(manifest)?;
    if approved_logo_png.len() > MAX_LOGO_BYTES {
        return Err(BrandSvgError::LogoTooLarge);
    }
    let approved_digest = sha256_hex(approved_logo_png);
    if approved_digest != manifest.logo.approved_sha256 {
        return Err(BrandSvgError::InvalidManifest(
            "approved logo digest does not match the supplied PNG".to_owned(),
        ));
    }
    let logo = STANDARD.encode(approved_logo_png);
    let copy = xml_escape(&manifest.typography.approved_copy);
    let family = xml_escape(&manifest.typography.font_family);
    let svg = format!(
        concat!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">"#,
            r#"<rect id="{bg_id}" x="0" y="0" width="{w}" height="{h}" fill="{bg}"/>"#,
            r#"<image id="{logo_id}" href="data:image/png;base64,{logo}" x="{lx}" y="{ly}" width="{lw}" height="{lh}"/>"#,
            r#"<text id="{text_id}" x="{tx}" y="{ty}" font-family="{family}" font-size="{size}" font-weight="{weight}" fill="{text_color}" text-anchor="{anchor}">{copy}</text>"#,
            "</svg>"
        ),
        w = manifest.canvas_width_px,
        h = manifest.canvas_height_px,
        bg_id = manifest.background.element_id,
        bg = manifest.background.color,
        logo_id = manifest.logo.element_id,
        lx = manifest.logo.x_px,
        ly = manifest.logo.y_px,
        lw = manifest.logo.width_px,
        lh = manifest.logo.height_px,
        text_id = manifest.typography.element_id,
        tx = manifest.typography.x_px,
        ty = manifest.typography.y_px,
        family = family,
        size = manifest.typography.font_size_px,
        weight = manifest.typography.font_weight,
        text_color = manifest.typography.color,
        anchor = manifest.typography.text_anchor,
        copy = copy,
        logo = logo,
    );
    Ok(svg.into_bytes())
}

pub fn validate_brand_source(
    source_svg: &[u8],
    approved_logo_png: &[u8],
    manifest: &BrandRuleManifest,
) -> Result<BrandSourceValidationReport, BrandSvgError> {
    validate_manifest(manifest)?;
    if source_svg.len() > MAX_SVG_BYTES {
        return Err(BrandSvgError::SvgTooLarge);
    }
    if approved_logo_png.len() > MAX_LOGO_BYTES {
        return Err(BrandSvgError::LogoTooLarge);
    }
    str::from_utf8(source_svg).map_err(|_| BrandSvgError::InvalidUtf8)?;
    let parsed = parse_svg(source_svg, manifest)?;
    let manifest_digest = canonical_value_digest(manifest)?;
    let approved_logo_digest = sha256_hex(approved_logo_png);
    let palette: BTreeSet<String> = manifest
        .allowed_palette
        .iter()
        .map(|color| color.to_ascii_lowercase())
        .collect();
    let palette_violation_count = u64::try_from(
        parsed
            .fills
            .iter()
            .filter(|fill| !palette.contains(fill.as_str()))
            .count(),
    )
    .unwrap_or(u64::MAX);
    let canvas_dimensions_match = parsed.width == manifest.canvas_width_px
        && parsed.height == manifest.canvas_height_px
        && parsed.view_box
            == format!(
                "0 0 {} {}",
                manifest.canvas_width_px, manifest.canvas_height_px
            );
    let logo_digest_matches = approved_logo_digest == manifest.logo.approved_sha256
        && parsed.logo.embedded_digest == approved_logo_digest;
    let logo_geometry_matches = parsed.logo.element_id == manifest.logo.element_id
        && parsed.logo.x == manifest.logo.x_px
        && parsed.logo.y == manifest.logo.y_px
        && parsed.logo.width == manifest.logo.width_px
        && parsed.logo.height == manifest.logo.height_px;
    let logo_clear_space_satisfied = clear_space_satisfied(manifest);
    let typography_matches = parsed.typography.element_id == manifest.typography.element_id
        && parsed.typography.x == manifest.typography.x_px
        && parsed.typography.y == manifest.typography.y_px
        && parsed.typography.font_family == manifest.typography.font_family
        && parsed.typography.font_size == manifest.typography.font_size_px
        && parsed.typography.font_weight == manifest.typography.font_weight
        && parsed.typography.color == manifest.typography.color.to_ascii_lowercase()
        && parsed.typography.text_anchor == manifest.typography.text_anchor;
    let approved_copy_matches = parsed.typography.text == manifest.typography.approved_copy;
    let restricted_svg_profile = parsed.background.element_id == manifest.background.element_id
        && parsed.background.x == 0
        && parsed.background.y == 0
        && parsed.background.width == manifest.canvas_width_px
        && parsed.background.height == manifest.canvas_height_px
        && parsed.background.color == manifest.background.color.to_ascii_lowercase();
    let accepted = restricted_svg_profile
        && canvas_dimensions_match
        && palette_violation_count == 0
        && logo_digest_matches
        && logo_geometry_matches
        && logo_clear_space_satisfied
        && typography_matches
        && approved_copy_matches;
    let mut report = BrandSourceValidationReport {
        schema_version: REPORT_SCHEMA.to_owned(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        source_svg_digest: sha256_hex(source_svg),
        manifest_digest,
        approved_logo_digest,
        restricted_svg_profile,
        canvas_dimensions_match,
        palette_violation_count,
        logo_digest_matches,
        logo_geometry_matches,
        logo_clear_space_satisfied,
        typography_matches,
        approved_copy_matches,
        accepted,
        report_digest: String::new(),
    };
    report.report_digest = canonical_record_digest(&report, "report_digest")?;
    Ok(report)
}

pub fn validate_manifest(manifest: &BrandRuleManifest) -> Result<(), BrandSvgError> {
    if manifest.schema_version != MANIFEST_SCHEMA {
        return Err(BrandSvgError::InvalidManifest(
            "schema_version must be 0.1.0".to_owned(),
        ));
    }
    for (field, value) in [
        ("manifest_id", manifest.manifest_id.as_str()),
        (
            "background.element_id",
            manifest.background.element_id.as_str(),
        ),
        ("background.color", manifest.background.color.as_str()),
        ("logo.element_id", manifest.logo.element_id.as_str()),
        (
            "logo.approved_sha256",
            manifest.logo.approved_sha256.as_str(),
        ),
        (
            "typography.element_id",
            manifest.typography.element_id.as_str(),
        ),
        (
            "typography.approved_copy",
            manifest.typography.approved_copy.as_str(),
        ),
        (
            "typography.font_family",
            manifest.typography.font_family.as_str(),
        ),
        ("typography.color", manifest.typography.color.as_str()),
        (
            "typography.text_anchor",
            manifest.typography.text_anchor.as_str(),
        ),
    ] {
        if value.trim().is_empty() || value.contains('\0') {
            return Err(BrandSvgError::InvalidManifest(format!(
                "{field} must be non-empty and NUL-free"
            )));
        }
    }
    if !is_sha256(&manifest.logo.approved_sha256) {
        return Err(BrandSvgError::InvalidManifest(
            "logo.approved_sha256 must be lowercase SHA-256".to_owned(),
        ));
    }
    if manifest.canvas_width_px == 0
        || manifest.canvas_height_px == 0
        || manifest.canvas_width_px > MAX_CANVAS_EDGE
        || manifest.canvas_height_px > MAX_CANVAS_EDGE
        || manifest.logo.width_px == 0
        || manifest.logo.height_px == 0
        || manifest.typography.font_size_px == 0
        || manifest.typography.font_weight == 0
    {
        return Err(BrandSvgError::InvalidManifest(
            "canvas, logo and typography dimensions must be positive and bounded".to_owned(),
        ));
    }
    if !matches!(
        manifest.typography.text_anchor.as_str(),
        "start" | "middle" | "end"
    ) {
        return Err(BrandSvgError::InvalidManifest(
            "text_anchor must be start, middle or end".to_owned(),
        ));
    }
    if manifest.allowed_palette.is_empty() {
        return Err(BrandSvgError::InvalidManifest(
            "allowed_palette must not be empty".to_owned(),
        ));
    }
    let mut palette = BTreeSet::new();
    for color in &manifest.allowed_palette {
        validate_color(color)?;
        if !palette.insert(color.to_ascii_lowercase()) {
            return Err(BrandSvgError::InvalidManifest(
                "allowed_palette contains duplicates".to_owned(),
            ));
        }
    }
    validate_color(&manifest.background.color)?;
    validate_color(&manifest.typography.color)?;
    if !palette.contains(&manifest.background.color.to_ascii_lowercase())
        || !palette.contains(&manifest.typography.color.to_ascii_lowercase())
    {
        return Err(BrandSvgError::InvalidManifest(
            "background and typography colors must be in allowed_palette".to_owned(),
        ));
    }
    if !clear_space_satisfied(manifest) {
        return Err(BrandSvgError::InvalidManifest(
            "declared logo placement violates minimum clear space".to_owned(),
        ));
    }
    Ok(())
}

fn clear_space_satisfied(manifest: &BrandRuleManifest) -> bool {
    let clear = manifest.logo.minimum_clear_space_px;
    let Some(right) = manifest
        .logo
        .x_px
        .checked_add(manifest.logo.width_px)
        .and_then(|value| value.checked_add(clear))
    else {
        return false;
    };
    let Some(bottom) = manifest
        .logo
        .y_px
        .checked_add(manifest.logo.height_px)
        .and_then(|value| value.checked_add(clear))
    else {
        return false;
    };
    manifest.logo.x_px >= clear
        && manifest.logo.y_px >= clear
        && right <= manifest.canvas_width_px
        && bottom <= manifest.canvas_height_px
}

fn parse_svg(source: &[u8], manifest: &BrandRuleManifest) -> Result<ParsedSvg, BrandSvgError> {
    let mut reader = Reader::from_reader(Cursor::new(source));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut root: Option<(u32, u32, String)> = None;
    let mut background: Option<ParsedBackground> = None;
    let mut logo: Option<ParsedLogo> = None;
    let mut typography: Option<ParsedTypography> = None;
    let mut fills = BTreeSet::new();
    let mut depth = 0_usize;
    let mut open_text: Option<OpenText> = None;

    loop {
        match reader
            .read_event_into(&mut buffer)
            .map_err(|error| BrandSvgError::Xml(error.to_string()))?
        {
            Event::Decl(_) => {
                if root.is_some() || depth != 0 {
                    return Err(BrandSvgError::ForbiddenNode);
                }
            }
            Event::Start(start) => {
                let name = local_name(&start)?;
                if depth == 0 {
                    if name != "svg" || root.is_some() {
                        return Err(BrandSvgError::InvalidRoot);
                    }
                    let attrs = attributes(&reader, &start)?;
                    let xmlns = required(&attrs, "xmlns")?;
                    if xmlns != "http://www.w3.org/2000/svg" {
                        return Err(BrandSvgError::InvalidAttribute("xmlns".to_owned()));
                    }
                    let width = parse_u32(required(&attrs, "width")?, "width")?;
                    let height = parse_u32(required(&attrs, "height")?, "height")?;
                    let view_box = required(&attrs, "viewBox")?.to_owned();
                    ensure_only(&attrs, &["xmlns", "width", "height", "viewBox"])?;
                    root = Some((width, height, view_box));
                } else if depth == 1 && name == "text" {
                    if open_text.is_some() || typography.is_some() {
                        return Err(BrandSvgError::UnexpectedElement("text".to_owned()));
                    }
                    open_text = Some(OpenText {
                        attributes: attributes(&reader, &start)?,
                        text_segments: Vec::new(),
                        nested: false,
                    });
                } else {
                    if let Some(text) = &mut open_text {
                        text.nested = true;
                    }
                    return Err(BrandSvgError::UnsupportedElement(name));
                }
                depth = depth
                    .checked_add(1)
                    .ok_or_else(|| BrandSvgError::Xml("element depth overflow".to_owned()))?;
            }
            Event::Empty(start) => {
                if depth != 1 {
                    return Err(BrandSvgError::UnsupportedElement(local_name(&start)?));
                }
                let name = local_name(&start)?;
                let attrs = attributes(&reader, &start)?;
                match name.as_str() {
                    "rect" => {
                        if background.is_some() {
                            return Err(BrandSvgError::UnexpectedElement("rect".to_owned()));
                        }
                        let parsed = parse_background(&attrs)?;
                        fills.insert(parsed.color.clone());
                        background = Some(parsed);
                    }
                    "image" => {
                        if logo.is_some() {
                            return Err(BrandSvgError::UnexpectedElement("image".to_owned()));
                        }
                        logo = Some(parse_logo(&attrs)?);
                    }
                    _ => return Err(BrandSvgError::UnsupportedElement(name)),
                }
            }
            Event::Text(text) => {
                if let Some(open) = &mut open_text {
                    let decoded = text
                        .decode()
                        .map_err(|error| BrandSvgError::Xml(error.to_string()))?;
                    open.text_segments.push(decoded.into_owned());
                } else if !text.as_ref().iter().all(u8::is_ascii_whitespace) {
                    return Err(BrandSvgError::ForbiddenNode);
                }
            }
            Event::End(end) => {
                let name = String::from_utf8_lossy(end.local_name().as_ref()).into_owned();
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| BrandSvgError::Xml("closing element underflow".to_owned()))?;
                if name == "text" {
                    let open = open_text.take().ok_or(BrandSvgError::InvalidTextShape)?;
                    if open.nested || open.text_segments.len() != 1 {
                        return Err(BrandSvgError::InvalidTextShape);
                    }
                    let parsed = parse_typography(&open.attributes, &open.text_segments[0])?;
                    fills.insert(parsed.color.clone());
                    typography = Some(parsed);
                } else if name != "svg" {
                    return Err(BrandSvgError::UnsupportedElement(name));
                }
            }
            Event::DocType(_) | Event::PI(_) | Event::CData(_) | Event::Comment(_) => {
                return Err(BrandSvgError::ForbiddenNode);
            }
            Event::Eof => break,
            _ => return Err(BrandSvgError::ForbiddenNode),
        }
        buffer.clear();
    }
    if depth != 0 || open_text.is_some() {
        return Err(BrandSvgError::Xml(
            "SVG ended with an unclosed element".to_owned(),
        ));
    }
    let (width, height, view_box) = root.ok_or(BrandSvgError::InvalidRoot)?;
    let background = background
        .ok_or_else(|| BrandSvgError::UnexpectedElement(manifest.background.element_id.clone()))?;
    let logo =
        logo.ok_or_else(|| BrandSvgError::UnexpectedElement(manifest.logo.element_id.clone()))?;
    let typography = typography
        .ok_or_else(|| BrandSvgError::UnexpectedElement(manifest.typography.element_id.clone()))?;
    Ok(ParsedSvg {
        width,
        height,
        view_box,
        fills,
        background,
        logo,
        typography,
    })
}

fn parse_background(attrs: &BTreeMap<String, String>) -> Result<ParsedBackground, BrandSvgError> {
    ensure_only(attrs, &["id", "x", "y", "width", "height", "fill"])?;
    Ok(ParsedBackground {
        element_id: required(attrs, "id")?.to_owned(),
        x: parse_u32(required(attrs, "x")?, "rect.x")?,
        y: parse_u32(required(attrs, "y")?, "rect.y")?,
        width: parse_u32(required(attrs, "width")?, "rect.width")?,
        height: parse_u32(required(attrs, "height")?, "rect.height")?,
        color: canonical_color(required(attrs, "fill")?)?,
    })
}

fn parse_logo(attrs: &BTreeMap<String, String>) -> Result<ParsedLogo, BrandSvgError> {
    ensure_only(attrs, &["id", "href", "x", "y", "width", "height"])?;
    let href = required(attrs, "href")?;
    let encoded = href
        .strip_prefix("data:image/png;base64,")
        .ok_or(BrandSvgError::InvalidEmbeddedLogo)?;
    let bytes = STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| BrandSvgError::InvalidEmbeddedLogo)?;
    if bytes.len() > MAX_LOGO_BYTES || !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(BrandSvgError::InvalidEmbeddedLogo);
    }
    Ok(ParsedLogo {
        element_id: required(attrs, "id")?.to_owned(),
        x: parse_u32(required(attrs, "x")?, "image.x")?,
        y: parse_u32(required(attrs, "y")?, "image.y")?,
        width: parse_u32(required(attrs, "width")?, "image.width")?,
        height: parse_u32(required(attrs, "height")?, "image.height")?,
        embedded_digest: sha256_hex(&bytes),
    })
}

fn parse_typography(
    attrs: &BTreeMap<String, String>,
    text: &str,
) -> Result<ParsedTypography, BrandSvgError> {
    ensure_only(
        attrs,
        &[
            "id",
            "x",
            "y",
            "font-family",
            "font-size",
            "font-weight",
            "fill",
            "text-anchor",
        ],
    )?;
    Ok(ParsedTypography {
        element_id: required(attrs, "id")?.to_owned(),
        x: parse_u32(required(attrs, "x")?, "text.x")?,
        y: parse_u32(required(attrs, "y")?, "text.y")?,
        font_family: required(attrs, "font-family")?.to_owned(),
        font_size: parse_u32(required(attrs, "font-size")?, "font-size")?,
        font_weight: required(attrs, "font-weight")?
            .parse::<u16>()
            .map_err(|_| BrandSvgError::InvalidAttribute("font-weight".to_owned()))?,
        color: canonical_color(required(attrs, "fill")?)?,
        text_anchor: required(attrs, "text-anchor")?.to_owned(),
        text: text.to_owned(),
    })
}

fn attributes(
    reader: &Reader<Cursor<&[u8]>>,
    start: &BytesStart<'_>,
) -> Result<BTreeMap<String, String>, BrandSvgError> {
    let mut values = BTreeMap::new();
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| BrandSvgError::Xml(error.to_string()))?;
        let key = str::from_utf8(attribute.key.as_ref())
            .map_err(|_| BrandSvgError::InvalidUtf8)?
            .to_owned();
        let value = attribute
            .decode_and_unescape_value(reader.decoder())
            .map_err(|error| BrandSvgError::Xml(error.to_string()))?
            .into_owned();
        if values.insert(key.clone(), value).is_some() {
            return Err(BrandSvgError::InvalidAttribute(format!("duplicate {key}")));
        }
    }
    Ok(values)
}

fn local_name(start: &BytesStart<'_>) -> Result<String, BrandSvgError> {
    str::from_utf8(start.local_name().as_ref())
        .map(str::to_owned)
        .map_err(|_| BrandSvgError::InvalidUtf8)
}

fn required<'a>(attrs: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, BrandSvgError> {
    attrs
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| BrandSvgError::InvalidAttribute(key.to_owned()))
}

fn ensure_only(attrs: &BTreeMap<String, String>, allowed: &[&str]) -> Result<(), BrandSvgError> {
    let allowed: BTreeSet<&str> = allowed.iter().copied().collect();
    if let Some(key) = attrs.keys().find(|key| !allowed.contains(key.as_str())) {
        return Err(BrandSvgError::InvalidAttribute(format!(
            "unsupported {key}"
        )));
    }
    Ok(())
}

fn parse_u32(value: &str, field: &str) -> Result<u32, BrandSvgError> {
    value
        .parse::<u32>()
        .map_err(|_| BrandSvgError::InvalidAttribute(field.to_owned()))
}

fn validate_color(value: &str) -> Result<(), BrandSvgError> {
    canonical_color(value).map(|_| ())
}

fn canonical_color(value: &str) -> Result<String, BrandSvgError> {
    let lower = value.to_ascii_lowercase();
    if lower.len() != 7
        || !lower.starts_with('#')
        || !lower[1..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BrandSvgError::InvalidManifest(format!(
            "unsupported color {value}; expected #rrggbb"
        )));
    }
    Ok(lower)
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
