#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufReader, Cursor};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::str;

use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use quick_xml::encoding::Decoder;
use quick_xml::escape::unescape;
use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer, XmlVersion};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const REQUEST_SCHEMA: &str = "0.1.0";
const MIN_SUPPORTED_MINOR: u32 = 2;
const MAX_SUPPORTED_MINOR: u32 = 4;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_EXPORT_EDGE: u32 = 16_384;
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

#[derive(Debug, Error)]
pub enum InkscapeAdapterError {
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON failure: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
    #[error("XML failure: {0}")]
    Xml(String),
    #[error("invalid UTF-8 in SVG material: {0}")]
    InvalidUtf8(String),
    #[error("trusted executable digest must be 64 lowercase hexadecimal characters")]
    InvalidTrustedDigest,
    #[error("Inkscape executable digest does not match the trusted digest")]
    ExecutableDigestMismatch,
    #[error("Inkscape version command failed: {0}")]
    VersionCommandFailed(String),
    #[error("could not parse Inkscape version from: {0}")]
    VersionParseFailed(String),
    #[error("Inkscape version {major}.{minor} is outside the certified 1.2-1.4 range")]
    UnsupportedVersion { major: u32, minor: u32 },
    #[error("unsupported adapter request schema {actual}; expected {expected}")]
    UnsupportedRequestSchema {
        actual: String,
        expected: &'static str,
    },
    #[error("required request field is empty: {0}")]
    EmptyField(&'static str),
    #[error("replacement text exceeds the {MAX_TEXT_BYTES}-byte limit")]
    ReplacementTooLarge,
    #[error("replacement text contains a NUL character")]
    ReplacementContainsNul,
    #[error("export dimensions must be between 1 and {MAX_EXPORT_EDGE} pixels")]
    InvalidExportDimensions,
    #[error("source digest does not match the expected digest")]
    SourceDigestMismatch,
    #[error("source and output paths must be distinct")]
    PathCollision,
    #[error("output already exists: {0}")]
    OutputAlreadyExists(String),
    #[error("output path contains a parent-directory traversal component")]
    ParentTraversal,
    #[error("output path has no file name")]
    MissingOutputFileName,
    #[error("SVG document contains a DTD, which is forbidden")]
    DocumentTypeForbidden,
    #[error("SVG document does not contain a root svg element")]
    MissingSvgRoot,
    #[error("duplicate SVG element id: {0}")]
    DuplicateElementId(String),
    #[error("target SVG element was not found: {0}")]
    TargetNotFound(String),
    #[error("target SVG element has nested content and cannot be safely replaced")]
    NestedTargetContent,
    #[error("target SVG element must contain exactly one direct text segment")]
    InvalidTargetTextShape,
    #[error("SVG mutation changed material outside the declared text target")]
    UndeclaredDocumentChange,
    #[error("Inkscape export command failed: {0}")]
    ExportCommandFailed(String),
    #[error("PNG output is missing or malformed")]
    InvalidPng,
    #[error("PNG dimensions do not match the declared export dimensions")]
    PngDimensionMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InkscapeBinaryIdentity {
    pub application_id: String,
    pub executable_digest: String,
    pub version_text: String,
    pub version_major: u32,
    pub version_minor: u32,
    pub version_patch: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvgElementSnapshot {
    pub element_name: String,
    pub attributes: BTreeMap<String, String>,
    pub direct_text: String,
    pub has_nested_elements: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvgDocumentSnapshot {
    pub source_digest: String,
    pub width: Option<String>,
    pub height: Option<String>,
    pub view_box: Option<String>,
    pub elements: BTreeMap<String, SvgElementSnapshot>,
    pub snapshot_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PngInfo {
    pub width: u32,
    pub height: u32,
    pub artifact_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetTextAndExportRequest {
    pub schema_version: String,
    pub request_id: String,
    pub source_svg: PathBuf,
    pub expected_source_digest: String,
    pub target_element_id: String,
    pub replacement_text: String,
    pub editable_output_svg: PathBuf,
    pub raster_output_png: PathBuf,
    pub export_width: u32,
    pub export_height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InkscapeExecutionRecord {
    pub schema_version: String,
    pub request_id: String,
    pub request_digest: String,
    pub binary: InkscapeBinaryIdentity,
    pub pre_snapshot_digest: String,
    pub post_snapshot_digest: String,
    pub editable_output_digest: String,
    pub raster_output_digest: String,
    pub export_command_digest: String,
    pub target_element_id: String,
    pub replacement_text: String,
    pub export_width: u32,
    pub export_height: u32,
    pub verified: bool,
    pub record_digest: String,
}

pub struct VerifiedInkscape {
    executable: PathBuf,
    identity: InkscapeBinaryIdentity,
}

impl VerifiedInkscape {
    pub fn open(
        executable: impl AsRef<Path>,
        trusted_executable_digest: &str,
    ) -> Result<Self, InkscapeAdapterError> {
        validate_sha256(trusted_executable_digest)?;
        let executable = fs::canonicalize(executable)?;
        let actual_digest = sha256_file(&executable)?;
        if actual_digest != trusted_executable_digest {
            return Err(InkscapeAdapterError::ExecutableDigestMismatch);
        }

        let output = Command::new(&executable)
            .arg("--version")
            .output()
            .map_err(InkscapeAdapterError::Io)?;
        if !output.status.success() {
            return Err(InkscapeAdapterError::VersionCommandFailed(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        let version_text = if output.stdout.is_empty() {
            String::from_utf8_lossy(&output.stderr).trim().to_owned()
        } else {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        };
        let (version_major, version_minor, version_patch) = parse_inkscape_version(&version_text)?;
        if version_major != 1
            || !(MIN_SUPPORTED_MINOR..=MAX_SUPPORTED_MINOR).contains(&version_minor)
        {
            return Err(InkscapeAdapterError::UnsupportedVersion {
                major: version_major,
                minor: version_minor,
            });
        }

        Ok(Self {
            executable,
            identity: InkscapeBinaryIdentity {
                application_id: "org.inkscape.Inkscape".to_owned(),
                executable_digest: actual_digest,
                version_text,
                version_major,
                version_minor,
                version_patch,
            },
        })
    }

    pub fn identity(&self) -> &InkscapeBinaryIdentity {
        &self.identity
    }

    pub fn execute_set_text_and_export(
        &self,
        request: &SetTextAndExportRequest,
    ) -> Result<InkscapeExecutionRecord, InkscapeAdapterError> {
        validate_request(request)?;
        let source = canonical_existing_file(&request.source_svg)?;
        let editable_output = resolve_new_output(&request.editable_output_svg)?;
        let raster_output = resolve_new_output(&request.raster_output_png)?;
        if source == editable_output || source == raster_output || editable_output == raster_output
        {
            return Err(InkscapeAdapterError::PathCollision);
        }

        let pre = observe_svg(&source)?;
        if pre.source_digest != request.expected_source_digest {
            return Err(InkscapeAdapterError::SourceDigestMismatch);
        }

        rewrite_direct_text(
            &source,
            &editable_output,
            &request.target_element_id,
            &request.replacement_text,
        )?;
        let post = observe_svg(&editable_output)?;
        verify_declared_text_change(
            &pre,
            &post,
            &request.target_element_id,
            &request.replacement_text,
        )?;

        let (png, export_command_digest) = self.export_png(
            &editable_output,
            &raster_output,
            request.export_width,
            request.export_height,
        )?;
        let request_digest = canonical_json_sha256(&serde_json::to_value(request)?)?;
        let editable_output_digest = post.source_digest.clone();
        let mut record = InkscapeExecutionRecord {
            schema_version: REQUEST_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_digest,
            binary: self.identity.clone(),
            pre_snapshot_digest: pre.snapshot_digest,
            post_snapshot_digest: post.snapshot_digest,
            editable_output_digest,
            raster_output_digest: png.artifact_digest,
            export_command_digest,
            target_element_id: request.target_element_id.clone(),
            replacement_text: request.replacement_text.clone(),
            export_width: png.width,
            export_height: png.height,
            verified: true,
            record_digest: String::new(),
        };
        record.record_digest = execution_record_digest(&record)?;
        Ok(record)
    }

    fn export_png(
        &self,
        input_svg: &Path,
        output_png: &Path,
        width: u32,
        height: u32,
    ) -> Result<(PngInfo, String), InkscapeAdapterError> {
        let arguments = vec![
            input_svg.to_string_lossy().into_owned(),
            format!("--export-filename={}", output_png.to_string_lossy()),
            "--export-area-page".to_owned(),
            format!("--export-width={width}"),
            format!("--export-height={height}"),
        ];
        let command_material = serde_json::json!({
            "binary": self.identity,
            "arguments": arguments,
            "input_digest": sha256_file(input_svg)?,
        });
        let command_digest = canonical_json_sha256(&command_material)?;

        let output = Command::new(&self.executable)
            .args(&arguments)
            .output()
            .map_err(InkscapeAdapterError::Io)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            return Err(InkscapeAdapterError::ExportCommandFailed(format!(
                "status={} stdout={stdout:?} stderr={stderr:?}",
                output.status
            )));
        }

        let png = read_png_info(output_png)?;
        if png.width != width || png.height != height {
            return Err(InkscapeAdapterError::PngDimensionMismatch);
        }
        Ok((png, command_digest))
    }
}

pub fn observe_svg(path: impl AsRef<Path>) -> Result<SvgDocumentSnapshot, InkscapeAdapterError> {
    let path = path.as_ref();
    let source_digest = sha256_file(path)?;
    let file = fs::File::open(path)?;
    let mut reader = Reader::from_reader(BufReader::new(file));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut stack: Vec<OpenElement> = Vec::new();
    let mut elements = BTreeMap::new();
    let mut width = None;
    let mut height = None;
    let mut view_box = None;
    let mut root_seen = false;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
        match event {
            Event::Start(start) => {
                if let Some(parent) = stack.last_mut() {
                    parent.has_nested_elements = true;
                }
                let open = open_element(&start, reader.decoder())?;
                if stack.is_empty() && local_name(&open.element_name) == "svg" {
                    root_seen = true;
                    width = open.attributes.get("width").cloned();
                    height = open.attributes.get("height").cloned();
                    view_box = open.attributes.get("viewBox").cloned();
                }
                stack.push(open);
            }
            Event::Empty(empty) => {
                if let Some(parent) = stack.last_mut() {
                    parent.has_nested_elements = true;
                }
                let open = open_element(&empty, reader.decoder())?;
                if stack.is_empty() && local_name(&open.element_name) == "svg" {
                    root_seen = true;
                    width = open.attributes.get("width").cloned();
                    height = open.attributes.get("height").cloned();
                    view_box = open.attributes.get("viewBox").cloned();
                }
                insert_snapshot(open, &mut elements)?;
            }
            Event::Text(text) => {
                if let Some(current) = stack.last_mut() {
                    let decoded = text
                        .decode()
                        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
                    let unescaped = unescape(&decoded)
                        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
                    current.direct_text.push_str(&unescaped);
                }
            }
            Event::CData(cdata) => {
                if let Some(current) = stack.last_mut() {
                    let decoded = reader
                        .decoder()
                        .decode(cdata.as_ref())
                        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
                    current.direct_text.push_str(&decoded);
                }
            }
            Event::End(end) => {
                let open = stack.pop().ok_or_else(|| {
                    InkscapeAdapterError::Xml("closing element has no matching start".to_owned())
                })?;
                let end_name = decode_utf8(end.name().as_ref())?;
                if open.element_name != end_name {
                    return Err(InkscapeAdapterError::Xml(format!(
                        "mismatched closing element: expected {}, got {end_name}",
                        open.element_name
                    )));
                }
                insert_snapshot(open, &mut elements)?;
            }
            Event::DocType(_) => return Err(InkscapeAdapterError::DocumentTypeForbidden),
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    if !root_seen {
        return Err(InkscapeAdapterError::MissingSvgRoot);
    }
    if !stack.is_empty() {
        return Err(InkscapeAdapterError::Xml(
            "SVG ended with unclosed elements".to_owned(),
        ));
    }

    let mut snapshot = SvgDocumentSnapshot {
        source_digest,
        width,
        height,
        view_box,
        elements,
        snapshot_digest: String::new(),
    };
    snapshot.snapshot_digest = snapshot_digest(&snapshot)?;
    Ok(snapshot)
}

pub fn rewrite_direct_text(
    source_svg: impl AsRef<Path>,
    output_svg: impl AsRef<Path>,
    target_element_id: &str,
    replacement_text: &str,
) -> Result<(), InkscapeAdapterError> {
    if target_element_id.is_empty() {
        return Err(InkscapeAdapterError::EmptyField("target_element_id"));
    }
    validate_replacement(replacement_text)?;
    let source_svg = source_svg.as_ref();
    let output_svg = output_svg.as_ref();
    if source_svg == output_svg {
        return Err(InkscapeAdapterError::PathCollision);
    }
    if output_svg.exists() {
        return Err(InkscapeAdapterError::OutputAlreadyExists(
            output_svg.display().to_string(),
        ));
    }

    let source = fs::read(source_svg)?;
    let mut reader = Reader::from_reader(Cursor::new(source));
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Vec::new());
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    let mut target_depth = None;
    let mut target_count = 0usize;
    let mut target_text_count = 0usize;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
        match event {
            Event::Start(start) => {
                if target_depth.is_some() {
                    return Err(InkscapeAdapterError::NestedTargetContent);
                }
                let is_target =
                    element_id(&start, reader.decoder())?.is_some_and(|id| id == target_element_id);
                writer
                    .write_event(Event::Start(start.into_owned()))
                    .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
                depth += 1;
                if is_target {
                    target_count += 1;
                    if target_count > 1 {
                        return Err(InkscapeAdapterError::DuplicateElementId(
                            target_element_id.to_owned(),
                        ));
                    }
                    target_depth = Some(depth);
                }
            }
            Event::Empty(empty) => {
                let is_target =
                    element_id(&empty, reader.decoder())?.is_some_and(|id| id == target_element_id);
                if is_target {
                    return Err(InkscapeAdapterError::InvalidTargetTextShape);
                }
                writer
                    .write_event(Event::Empty(empty.into_owned()))
                    .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
            }
            Event::Text(text) => {
                if target_depth == Some(depth) {
                    target_text_count += 1;
                    if target_text_count > 1 {
                        return Err(InkscapeAdapterError::InvalidTargetTextShape);
                    }
                    writer
                        .write_event(Event::Text(BytesText::new(replacement_text)))
                        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
                } else {
                    writer
                        .write_event(Event::Text(text.into_owned()))
                        .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
                }
            }
            Event::CData(_) | Event::GeneralRef(_) if target_depth == Some(depth) => {
                return Err(InkscapeAdapterError::InvalidTargetTextShape);
            }
            Event::End(end) => {
                if target_depth == Some(depth) {
                    if target_text_count != 1 {
                        return Err(InkscapeAdapterError::InvalidTargetTextShape);
                    }
                    target_depth = None;
                }
                writer
                    .write_event(Event::End(end.into_owned()))
                    .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
                depth = depth.checked_sub(1).ok_or_else(|| {
                    InkscapeAdapterError::Xml("closing element underflow".to_owned())
                })?;
            }
            Event::DocType(_) => return Err(InkscapeAdapterError::DocumentTypeForbidden),
            Event::Eof => break,
            other => {
                if target_depth == Some(depth) {
                    return Err(InkscapeAdapterError::InvalidTargetTextShape);
                }
                writer
                    .write_event(other.into_owned())
                    .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
            }
        }
        buffer.clear();
    }

    if target_count == 0 {
        return Err(InkscapeAdapterError::TargetNotFound(
            target_element_id.to_owned(),
        ));
    }
    if target_depth.is_some() || depth != 0 {
        return Err(InkscapeAdapterError::Xml(
            "SVG ended before the target element closed".to_owned(),
        ));
    }
    fs::write(output_svg, writer.into_inner())?;
    Ok(())
}

pub fn read_png_info(path: impl AsRef<Path>) -> Result<PngInfo, InkscapeAdapterError> {
    let path = path.as_ref();
    let bytes = fs::read(path)?;
    if bytes.len() < 24
        || &bytes[..8] != PNG_SIGNATURE
        || &bytes[12..16] != b"IHDR"
        || u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| InkscapeAdapterError::InvalidPng)?,
        ) != 13
    {
        return Err(InkscapeAdapterError::InvalidPng);
    }
    let width = u32::from_be_bytes(
        bytes[16..20]
            .try_into()
            .map_err(|_| InkscapeAdapterError::InvalidPng)?,
    );
    let height = u32::from_be_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| InkscapeAdapterError::InvalidPng)?,
    );
    if width == 0 || height == 0 {
        return Err(InkscapeAdapterError::InvalidPng);
    }
    Ok(PngInfo {
        width,
        height,
        artifact_digest: sha256_bytes(&bytes),
    })
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<String, InkscapeAdapterError> {
    Ok(sha256_bytes(&fs::read(path)?))
}

fn validate_request(request: &SetTextAndExportRequest) -> Result<(), InkscapeAdapterError> {
    if request.schema_version != REQUEST_SCHEMA {
        return Err(InkscapeAdapterError::UnsupportedRequestSchema {
            actual: request.schema_version.clone(),
            expected: REQUEST_SCHEMA,
        });
    }
    for (name, value) in [
        ("request_id", request.request_id.as_str()),
        (
            "expected_source_digest",
            request.expected_source_digest.as_str(),
        ),
        ("target_element_id", request.target_element_id.as_str()),
    ] {
        if value.is_empty() {
            return Err(InkscapeAdapterError::EmptyField(name));
        }
    }
    validate_sha256(&request.expected_source_digest)?;
    validate_replacement(&request.replacement_text)?;
    if request.export_width == 0
        || request.export_height == 0
        || request.export_width > MAX_EXPORT_EDGE
        || request.export_height > MAX_EXPORT_EDGE
    {
        return Err(InkscapeAdapterError::InvalidExportDimensions);
    }
    Ok(())
}

fn validate_replacement(value: &str) -> Result<(), InkscapeAdapterError> {
    if value.len() > MAX_TEXT_BYTES {
        return Err(InkscapeAdapterError::ReplacementTooLarge);
    }
    if value.contains('\0') {
        return Err(InkscapeAdapterError::ReplacementContainsNul);
    }
    Ok(())
}

fn validate_sha256(digest: &str) -> Result<(), InkscapeAdapterError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err(InkscapeAdapterError::InvalidTrustedDigest);
    }
    Ok(())
}

fn parse_inkscape_version(text: &str) -> Result<(u32, u32, u32), InkscapeAdapterError> {
    for token in text.split_whitespace() {
        let candidate =
            token.trim_matches(|character: char| !character.is_ascii_digit() && character != '.');
        if candidate.is_empty()
            || !candidate.starts_with(|character: char| character.is_ascii_digit())
        {
            continue;
        }
        let mut components = candidate.split('.');
        let Some(major) = components
            .next()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(minor) = components
            .next()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let patch = components
            .next()
            .and_then(|value| {
                let digits: String = value
                    .chars()
                    .take_while(|character| character.is_ascii_digit())
                    .collect();
                (!digits.is_empty()).then_some(digits)
            })
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        return Ok((major, minor, patch));
    }
    Err(InkscapeAdapterError::VersionParseFailed(text.to_owned()))
}

fn verify_declared_text_change(
    pre: &SvgDocumentSnapshot,
    post: &SvgDocumentSnapshot,
    target_id: &str,
    replacement: &str,
) -> Result<(), InkscapeAdapterError> {
    if pre.width != post.width
        || pre.height != post.height
        || pre.view_box != post.view_box
        || pre.elements.len() != post.elements.len()
    {
        return Err(InkscapeAdapterError::UndeclaredDocumentChange);
    }

    for (id, before) in &pre.elements {
        let Some(after) = post.elements.get(id) else {
            return Err(InkscapeAdapterError::UndeclaredDocumentChange);
        };
        if id == target_id {
            if before.element_name != after.element_name
                || before.attributes != after.attributes
                || before.has_nested_elements
                || after.has_nested_elements
                || after.direct_text != replacement
            {
                return Err(InkscapeAdapterError::UndeclaredDocumentChange);
            }
        } else if before != after {
            return Err(InkscapeAdapterError::UndeclaredDocumentChange);
        }
    }

    if !pre.elements.contains_key(target_id) {
        return Err(InkscapeAdapterError::TargetNotFound(target_id.to_owned()));
    }
    Ok(())
}

fn execution_record_digest(
    record: &InkscapeExecutionRecord,
) -> Result<String, InkscapeAdapterError> {
    let mut value = serde_json::to_value(record)?;
    let object = value.as_object_mut().ok_or_else(|| {
        InkscapeAdapterError::Json(serde_json::Error::io(std::io::Error::other(
            "record did not serialize to an object",
        )))
    })?;
    object.insert("record_digest".to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

fn snapshot_digest(snapshot: &SvgDocumentSnapshot) -> Result<String, InkscapeAdapterError> {
    let mut value = serde_json::to_value(snapshot)?;
    let object = value.as_object_mut().ok_or_else(|| {
        InkscapeAdapterError::Json(serde_json::Error::io(std::io::Error::other(
            "snapshot did not serialize to an object",
        )))
    })?;
    object.insert("snapshot_digest".to_owned(), Value::String(String::new()));
    Ok(canonical_json_sha256(&value)?)
}

fn canonical_existing_file(path: &Path) -> Result<PathBuf, InkscapeAdapterError> {
    Ok(fs::canonicalize(path)?)
}

fn resolve_new_output(path: &Path) -> Result<PathBuf, InkscapeAdapterError> {
    if path.exists() {
        return Err(InkscapeAdapterError::OutputAlreadyExists(
            path.display().to_string(),
        ));
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(InkscapeAdapterError::ParentTraversal);
    }
    let file_name = path
        .file_name()
        .ok_or(InkscapeAdapterError::MissingOutputFileName)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        env::current_dir()?
    } else {
        fs::canonicalize(parent)?
    };
    Ok(parent.join(file_name))
}

#[derive(Debug)]
struct OpenElement {
    element_name: String,
    id: Option<String>,
    attributes: BTreeMap<String, String>,
    direct_text: String,
    has_nested_elements: bool,
}

fn open_element(
    start: &BytesStart<'_>,
    decoder: Decoder,
) -> Result<OpenElement, InkscapeAdapterError> {
    let element_name = decode_utf8(start.name().as_ref())?;
    let attributes = decode_attributes(start, decoder)?;
    let id = attributes.get("id").cloned();
    Ok(OpenElement {
        element_name,
        id,
        attributes,
        direct_text: String::new(),
        has_nested_elements: false,
    })
}

fn element_id(
    start: &BytesStart<'_>,
    decoder: Decoder,
) -> Result<Option<String>, InkscapeAdapterError> {
    Ok(decode_attributes(start, decoder)?.remove("id"))
}

fn decode_attributes(
    start: &BytesStart<'_>,
    decoder: Decoder,
) -> Result<BTreeMap<String, String>, InkscapeAdapterError> {
    let mut attributes = BTreeMap::new();
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?;
        let key = decode_utf8(attribute.key.as_ref())?;
        let value = attribute
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
            .map_err(|error| InkscapeAdapterError::Xml(error.to_string()))?
            .into_owned();
        attributes.insert(key, value);
    }
    Ok(attributes)
}

fn insert_snapshot(
    open: OpenElement,
    elements: &mut BTreeMap<String, SvgElementSnapshot>,
) -> Result<(), InkscapeAdapterError> {
    let Some(id) = open.id else {
        return Ok(());
    };
    if elements.contains_key(&id) {
        return Err(InkscapeAdapterError::DuplicateElementId(id));
    }
    elements.insert(
        id,
        SvgElementSnapshot {
            element_name: open.element_name,
            attributes: open.attributes,
            direct_text: open.direct_text,
            has_nested_elements: open.has_nested_elements,
        },
    );
    Ok(())
}

fn local_name(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, local)| local)
}

fn decode_utf8(bytes: &[u8]) -> Result<String, InkscapeAdapterError> {
    str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|error| InkscapeAdapterError::InvalidUtf8(error.to_string()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
