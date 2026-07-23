#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::str;

use ergaxiom_proof_kernel::{HashingError, canonical_json_sha256};
use roxmltree::{Document, NodeType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SCHEMA_VERSION: &str = "0.1.0";
const MAX_APPROVED_COPY_BYTES: usize = 16 * 1024;
const MAX_SVG_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedCopyPolicy {
    pub target_element_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedCopyReport {
    pub schema_version: String,
    pub approved_copy_digest: String,
    pub approved_copy_byte_count: u64,
    pub svg_artifact_digest: String,
    pub svg_byte_count: u64,
    pub target_element_id: String,
    pub target_element_name: String,
    pub extracted_copy_digest: String,
    pub extracted_copy_byte_count: u64,
    pub exact_match: bool,
    pub report_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovedCopyViolation {
    CopyMismatch {
        approved_digest: String,
        extracted_digest: String,
        approved_byte_count: u64,
        extracted_byte_count: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedCopyResult {
    pub schema_version: String,
    pub accepted: bool,
    pub report: ApprovedCopyReport,
    pub violations: Vec<ApprovedCopyViolation>,
    pub decision_digest: String,
}

#[derive(Debug, Error)]
pub enum ApprovedCopyError {
    #[error("target element id must not be empty")]
    EmptyTargetElementId,
    #[error("approved copy exceeds the {MAX_APPROVED_COPY_BYTES}-byte limit")]
    ApprovedCopyTooLarge,
    #[error("SVG exceeds the {MAX_SVG_BYTES}-byte limit")]
    SvgTooLarge,
    #[error("approved copy is not valid UTF-8")]
    InvalidApprovedCopyUtf8,
    #[error("SVG is not valid UTF-8")]
    InvalidSvgUtf8,
    #[error("approved copy contains a NUL character")]
    ApprovedCopyContainsNul,
    #[error("SVG document contains a DTD or entity declaration")]
    DocumentTypeForbidden,
    #[error("SVG parse failed: {0}")]
    SvgParse(String),
    #[error("SVG document root must be an svg element")]
    MissingSvgRoot,
    #[error("duplicate SVG element id: {0}")]
    DuplicateElementId(String),
    #[error("target SVG element was not found: {0}")]
    TargetNotFound(String),
    #[error("target SVG id resolves to more than one element: {0}")]
    DuplicateTarget(String),
    #[error("target SVG element must be a text element")]
    TargetIsNotText,
    #[error("target text element contains nested elements")]
    NestedTargetContent,
    #[error("target text element must contain exactly one direct text segment")]
    InvalidTargetTextShape,
    #[error("target text element contains unsupported direct child content")]
    UnsupportedTargetContent,
    #[error("integer overflow while evaluating approved copy")]
    SizeOverflow,
    #[error("failed to serialize approved-copy evidence: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Hashing(#[from] HashingError),
}

pub fn validate_approved_copy(
    approved_copy: &[u8],
    svg_bytes: &[u8],
    policy: &ApprovedCopyPolicy,
) -> Result<ApprovedCopyResult, ApprovedCopyError> {
    validate_inputs(approved_copy, svg_bytes, policy)?;
    let approved_text =
        str::from_utf8(approved_copy).map_err(|_| ApprovedCopyError::InvalidApprovedCopyUtf8)?;
    let svg_text = str::from_utf8(svg_bytes).map_err(|_| ApprovedCopyError::InvalidSvgUtf8)?;
    let extracted = extract_target_text(svg_text, &policy.target_element_id)?;
    let approved_digest = sha256_hex(approved_copy);
    let extracted_digest = sha256_hex(extracted.as_bytes());
    let exact_match = extracted == approved_text;

    let mut violations = Vec::new();
    if !exact_match {
        violations.push(ApprovedCopyViolation::CopyMismatch {
            approved_digest: approved_digest.clone(),
            extracted_digest: extracted_digest.clone(),
            approved_byte_count: byte_count(approved_copy.len())?,
            extracted_byte_count: byte_count(extracted.len())?,
        });
    }

    let mut report = ApprovedCopyReport {
        schema_version: SCHEMA_VERSION.to_owned(),
        approved_copy_digest: approved_digest,
        approved_copy_byte_count: byte_count(approved_copy.len())?,
        svg_artifact_digest: sha256_hex(svg_bytes),
        svg_byte_count: byte_count(svg_bytes.len())?,
        target_element_id: policy.target_element_id.clone(),
        target_element_name: "text".to_owned(),
        extracted_copy_digest: extracted_digest,
        extracted_copy_byte_count: byte_count(extracted.len())?,
        exact_match,
        report_digest: String::new(),
    };
    report.report_digest = report_digest(&report)?;

    let mut result = ApprovedCopyResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        accepted: violations.is_empty(),
        report,
        violations,
        decision_digest: String::new(),
    };
    result.decision_digest = decision_digest(&result)?;
    Ok(result)
}

fn validate_inputs(
    approved_copy: &[u8],
    svg_bytes: &[u8],
    policy: &ApprovedCopyPolicy,
) -> Result<(), ApprovedCopyError> {
    if policy.target_element_id.is_empty() {
        return Err(ApprovedCopyError::EmptyTargetElementId);
    }
    if approved_copy.len() > MAX_APPROVED_COPY_BYTES {
        return Err(ApprovedCopyError::ApprovedCopyTooLarge);
    }
    if svg_bytes.len() > MAX_SVG_BYTES {
        return Err(ApprovedCopyError::SvgTooLarge);
    }
    if approved_copy.contains(&0) {
        return Err(ApprovedCopyError::ApprovedCopyContainsNul);
    }
    let svg_text = str::from_utf8(svg_bytes).map_err(|_| ApprovedCopyError::InvalidSvgUtf8)?;
    let uppercase = svg_text.to_ascii_uppercase();
    if uppercase.contains("<!DOCTYPE") || uppercase.contains("<!ENTITY") {
        return Err(ApprovedCopyError::DocumentTypeForbidden);
    }
    Ok(())
}

fn extract_target_text<'a>(
    svg_text: &'a str,
    target_id: &str,
) -> Result<&'a str, ApprovedCopyError> {
    let document =
        Document::parse(svg_text).map_err(|error| ApprovedCopyError::SvgParse(error.to_string()))?;
    let root = document.root_element();
    if root.tag_name().name() != "svg" {
        return Err(ApprovedCopyError::MissingSvgRoot);
    }

    let mut ids = BTreeSet::new();
    let mut target = None;
    let mut target_count = 0_u8;
    for node in document.descendants().filter(|node| node.is_element()) {
        if let Some(id) = node.attribute("id") {
            if !ids.insert(id) {
                return Err(ApprovedCopyError::DuplicateElementId(id.to_owned()));
            }
            if id == target_id {
                target_count = target_count.saturating_add(1);
                target = Some(node);
            }
        }
    }
    if target_count == 0 {
        return Err(ApprovedCopyError::TargetNotFound(target_id.to_owned()));
    }
    if target_count != 1 {
        return Err(ApprovedCopyError::DuplicateTarget(target_id.to_owned()));
    }
    let target = target.ok_or_else(|| ApprovedCopyError::TargetNotFound(target_id.to_owned()))?;
    if target.tag_name().name() != "text" {
        return Err(ApprovedCopyError::TargetIsNotText);
    }

    let mut direct_text = None;
    let mut text_segments = 0_u8;
    for child in target.children() {
        match child.node_type() {
            NodeType::Text => {
                text_segments = text_segments.saturating_add(1);
                direct_text = child.text();
            }
            NodeType::Element => return Err(ApprovedCopyError::NestedTargetContent),
            NodeType::Comment => {}
            _ => return Err(ApprovedCopyError::UnsupportedTargetContent),
        }
    }
    if text_segments != 1 {
        return Err(ApprovedCopyError::InvalidTargetTextShape);
    }
    direct_text.ok_or(ApprovedCopyError::InvalidTargetTextShape)
}

fn byte_count(length: usize) -> Result<u64, ApprovedCopyError> {
    u64::try_from(length).map_err(|_| ApprovedCopyError::SizeOverflow)
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

fn report_digest(report: &ApprovedCopyReport) -> Result<String, ApprovedCopyError> {
    let mut value = serde_json::to_value(report)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other(
            "approved copy report is not an object",
        ))
    })?;
    object.insert(
        "report_digest".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(canonical_json_sha256(&value)?)
}

fn decision_digest(result: &ApprovedCopyResult) -> Result<String, ApprovedCopyError> {
    let mut value = serde_json::to_value(result)?;
    let object = value.as_object_mut().ok_or_else(|| {
        serde_json::Error::io(std::io::Error::other(
            "approved copy result is not an object",
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
    use super::sha256_hex;

    #[test]
    fn sha256_output_is_lowercase_hex() {
        let digest = sha256_hex(b"approved");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(digest, digest.to_ascii_lowercase());
    }
}
