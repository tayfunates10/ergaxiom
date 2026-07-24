use std::collections::BTreeSet;

use lopdf::{Dictionary, Document, Object};
use thiserror::Error;

use crate::model::{PdfBoxRecord, PdfNormalizationRecord, PrintSpecification};
use crate::util::{PrintDigestError, canonical_record_digest, sha256_hex};

const NORMALIZATION_SCHEMA: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum PrintPdfError {
    #[error("PDF parsing or writing failed: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("PDF I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("PDF must contain exactly one page")]
    PageCount,
    #[error("PDF is encrypted")]
    Encrypted,
    #[error("required PDF page dictionary entry is missing or malformed: {0}")]
    InvalidPageEntry(&'static str),
    #[error("normalized PDF bytes are malformed")]
    InvalidOutput,
    #[error("PDF normalization record does not bind the supplied artifacts")]
    NormalizationBindingMismatch,
    #[error("arithmetic overflow while computing print boxes")]
    GeometryOverflow,
    #[error(transparent)]
    Digest(#[from] PrintDigestError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrintPdfInspection {
    pub page_count: u32,
    pub pdf_version: String,
    pub media_box: Option<PdfBoxRecord>,
    pub trim_box: Option<PdfBoxRecord>,
    pub bleed_box: Option<PdfBoxRecord>,
    pub crop_box: Option<PdfBoxRecord>,
    pub vector_only: bool,
    pub fonts_outlined: bool,
    pub allowed_color_spaces_only: bool,
    pub transparency_absent: bool,
    pub external_actions_absent: bool,
}

pub fn normalize_print_pdf(
    raw_pdf: &[u8],
    specification: &PrintSpecification,
) -> Result<(Vec<u8>, PdfNormalizationRecord), PrintPdfError> {
    let mut document = Document::load_mem(raw_pdf)?;
    if document.is_encrypted() || document.trailer.get(b"Encrypt").is_ok() {
        return Err(PrintPdfError::Encrypted);
    }
    let pages = document.get_pages();
    if pages.len() != 1 {
        return Err(PrintPdfError::PageCount);
    }
    let page_id = *pages.values().next().ok_or(PrintPdfError::PageCount)?;
    let (media_box, trim_box, bleed_box, crop_box) = expected_boxes(specification)?;
    document.version = specification.required_pdf_version.clone();
    let page = document.get_object_mut(page_id)?.as_dict_mut()?;
    page.set("MediaBox", box_object(&media_box));
    page.set("TrimBox", box_object(&trim_box));
    page.set("BleedBox", box_object(&bleed_box));
    page.set("CropBox", box_object(&crop_box));
    let mut normalized = Vec::new();
    document.save_to(&mut normalized)?;
    if normalized.len() < 8 || !normalized.starts_with(b"%PDF-") {
        return Err(PrintPdfError::InvalidOutput);
    }
    let mut record = PdfNormalizationRecord {
        schema_version: NORMALIZATION_SCHEMA.to_owned(),
        raw_pdf_digest: sha256_hex(raw_pdf),
        normalized_pdf_digest: sha256_hex(&normalized),
        page_count: 1,
        media_box,
        trim_box,
        bleed_box,
        crop_box,
        record_digest: String::new(),
    };
    record.record_digest = canonical_record_digest(&record, "record_digest")?;
    verify_pdf_normalization(raw_pdf, &normalized, &record, specification)?;
    Ok((normalized, record))
}

pub fn verify_pdf_normalization(
    raw_pdf: &[u8],
    normalized_pdf: &[u8],
    record: &PdfNormalizationRecord,
    specification: &PrintSpecification,
) -> Result<(), PrintPdfError> {
    if record.schema_version != NORMALIZATION_SCHEMA
        || record.raw_pdf_digest != sha256_hex(raw_pdf)
        || record.normalized_pdf_digest != sha256_hex(normalized_pdf)
        || record.record_digest != canonical_record_digest(record, "record_digest")?
    {
        return Err(PrintPdfError::NormalizationBindingMismatch);
    }
    let expected = expected_boxes(specification)?;
    if record.page_count != 1
        || record.media_box != expected.0
        || record.trim_box != expected.1
        || record.bleed_box != expected.2
        || record.crop_box != expected.3
    {
        return Err(PrintPdfError::NormalizationBindingMismatch);
    }
    let inspection = inspect_print_pdf(normalized_pdf, specification)?;
    if inspection.page_count != 1
        || inspection.pdf_version != specification.required_pdf_version
        || inspection.media_box.as_ref() != Some(&record.media_box)
        || inspection.trim_box.as_ref() != Some(&record.trim_box)
        || inspection.bleed_box.as_ref() != Some(&record.bleed_box)
        || inspection.crop_box.as_ref() != Some(&record.crop_box)
    {
        return Err(PrintPdfError::NormalizationBindingMismatch);
    }
    Ok(())
}

pub fn inspect_print_pdf(
    pdf: &[u8],
    specification: &PrintSpecification,
) -> Result<PrintPdfInspection, PrintPdfError> {
    let document = Document::load_mem(pdf)?;
    let pages = document.get_pages();
    let page_count = u32::try_from(pages.len()).map_err(|_| PrintPdfError::PageCount)?;
    let Some(page_id) = pages.values().next().copied() else {
        return Ok(PrintPdfInspection {
            page_count,
            pdf_version: document.version,
            media_box: None,
            trim_box: None,
            bleed_box: None,
            crop_box: None,
            vector_only: false,
            fonts_outlined: false,
            allowed_color_spaces_only: false,
            transparency_absent: false,
            external_actions_absent: false,
        });
    };
    let page = document.get_object(page_id)?.as_dict()?;
    let media_box = read_box(page, b"MediaBox")?;
    let trim_box = read_box(page, b"TrimBox")?;
    let bleed_box = read_box(page, b"BleedBox")?;
    let crop_box = read_box(page, b"CropBox")?;
    let vector_only = document.get_page_images(page_id)?.is_empty();
    let fonts_outlined = document.get_page_fonts(page_id)?.is_empty();
    let annotations_absent = document.get_page_annotations(page_id)?.is_empty();
    let (resources, _) = document.get_page_resources(page_id)?;
    let resource_transparency_absent = resources.is_none_or(|resources| {
        resources.get(b"ExtGState").is_err() && resources.get(b"Pattern").is_err()
    });
    let content = document.get_and_decode_page_content(page_id)?;
    let mut used_color_spaces = BTreeSet::new();
    let mut graphics_state_operator_absent = true;
    for operation in content.operations {
        match operation.operator.as_str() {
            "rg" | "RG" => {
                used_color_spaces.insert("DeviceRGB".to_owned());
            }
            "g" | "G" => {
                used_color_spaces.insert("DeviceGray".to_owned());
            }
            "k" | "K" => {
                used_color_spaces.insert("DeviceCMYK".to_owned());
            }
            "cs" | "CS" => {
                if let Some(name) = operation
                    .operands
                    .first()
                    .and_then(|object| object.as_name().ok())
                {
                    used_color_spaces.insert(String::from_utf8_lossy(name).into_owned());
                } else {
                    used_color_spaces.insert("UNKNOWN".to_owned());
                }
            }
            "gs" => graphics_state_operator_absent = false,
            _ => {}
        }
    }
    let allowed: BTreeSet<&str> = specification
        .allowed_pdf_color_spaces
        .iter()
        .map(String::as_str)
        .collect();
    let allowed_color_spaces_only = used_color_spaces
        .iter()
        .all(|space| allowed.contains(space.as_str()));
    let dangerous_objects_absent = document
        .objects
        .values()
        .all(object_is_safe);
    let catalog_safe = document.catalog().is_ok_and(dictionary_is_safe);
    let encrypted = document.is_encrypted() || document.trailer.get(b"Encrypt").is_ok();
    Ok(PrintPdfInspection {
        page_count,
        pdf_version: document.version,
        media_box,
        trim_box,
        bleed_box,
        crop_box,
        vector_only,
        fonts_outlined,
        allowed_color_spaces_only,
        transparency_absent: resource_transparency_absent
            && graphics_state_operator_absent
            && dangerous_objects_absent,
        external_actions_absent: annotations_absent
            && catalog_safe
            && dangerous_objects_absent
            && !encrypted,
    })
}

pub fn expected_boxes(
    specification: &PrintSpecification,
) -> Result<(PdfBoxRecord, PdfBoxRecord, PdfBoxRecord, PdfBoxRecord), PrintPdfError> {
    let trim_width = mm_milli_to_pt_milli(i64::from(specification.trim_width_milli_mm))?;
    let trim_height = mm_milli_to_pt_milli(i64::from(specification.trim_height_milli_mm))?;
    let bleed = mm_milli_to_pt_milli(i64::from(specification.bleed_milli_mm))?;
    let media_width = trim_width
        .checked_add(
            bleed
                .checked_mul(2)
                .ok_or(PrintPdfError::GeometryOverflow)?,
        )
        .ok_or(PrintPdfError::GeometryOverflow)?;
    let media_height = trim_height
        .checked_add(
            bleed
                .checked_mul(2)
                .ok_or(PrintPdfError::GeometryOverflow)?,
        )
        .ok_or(PrintPdfError::GeometryOverflow)?;
    let media = PdfBoxRecord {
        left_milli_pt: 0,
        bottom_milli_pt: 0,
        right_milli_pt: media_width,
        top_milli_pt: media_height,
    };
    let trim = PdfBoxRecord {
        left_milli_pt: bleed,
        bottom_milli_pt: bleed,
        right_milli_pt: bleed
            .checked_add(trim_width)
            .ok_or(PrintPdfError::GeometryOverflow)?,
        top_milli_pt: bleed
            .checked_add(trim_height)
            .ok_or(PrintPdfError::GeometryOverflow)?,
    };
    Ok((media.clone(), trim, media.clone(), media))
}

fn mm_milli_to_pt_milli(value: i64) -> Result<i64, PrintPdfError> {
    let numerator = value
        .checked_mul(72_000)
        .ok_or(PrintPdfError::GeometryOverflow)?;
    Ok((numerator + 12_700) / 25_400)
}

fn box_object(record: &PdfBoxRecord) -> Object {
    Object::Array(vec![
        point_object(record.left_milli_pt),
        point_object(record.bottom_milli_pt),
        point_object(record.right_milli_pt),
        point_object(record.top_milli_pt),
    ])
}

fn point_object(value: i64) -> Object {
    if value % 1000 == 0 {
        Object::Integer(value / 1000)
    } else {
        Object::Real(value as f32 / 1000.0)
    }
}

fn read_box(
    dictionary: &Dictionary,
    key: &'static [u8],
) -> Result<Option<PdfBoxRecord>, PrintPdfError> {
    let Ok(value) = dictionary.get(key) else {
        return Ok(None);
    };
    let array = value
        .as_array()
        .map_err(|_| PrintPdfError::InvalidPageEntry("page box"))?;
    if array.len() != 4 {
        return Err(PrintPdfError::InvalidPageEntry("page box length"));
    }
    Ok(Some(PdfBoxRecord {
        left_milli_pt: object_to_milli_pt(&array[0])?,
        bottom_milli_pt: object_to_milli_pt(&array[1])?,
        right_milli_pt: object_to_milli_pt(&array[2])?,
        top_milli_pt: object_to_milli_pt(&array[3])?,
    }))
}

fn object_to_milli_pt(object: &Object) -> Result<i64, PrintPdfError> {
    let value = object
        .as_float()
        .map_err(|_| PrintPdfError::InvalidPageEntry("page box number"))?;
    if !value.is_finite() {
        return Err(PrintPdfError::InvalidPageEntry("finite page box number"));
    }
    Ok((value * 1000.0).round() as i64)
}

fn object_is_safe(object: &Object) -> bool {
    match object {
        Object::Dictionary(dictionary) => dictionary_is_safe(dictionary),
        Object::Stream(stream) => dictionary_is_safe(&stream.dict),
        _ => true,
    }
}

fn dictionary_is_safe(dictionary: &Dictionary) -> bool {
    for key in [
        b"AA".as_slice(),
        b"OpenAction".as_slice(),
        b"JavaScript".as_slice(),
        b"JS".as_slice(),
        b"Launch".as_slice(),
        b"EmbeddedFiles".as_slice(),
        b"AcroForm".as_slice(),
        b"SMask".as_slice(),
        b"ExtGState".as_slice(),
        b"Group".as_slice(),
    ] {
        if dictionary.get(key).is_ok() {
            return false;
        }
    }
    for key in [b"Type".as_slice(), b"S".as_slice(), b"Subtype".as_slice()] {
        if let Ok(name) = dictionary.get(key).and_then(Object::as_name) {
            if [
                b"Action".as_slice(),
                b"JavaScript".as_slice(),
                b"Launch".as_slice(),
                b"EmbeddedFile".as_slice(),
                b"FileAttachment".as_slice(),
            ]
            .contains(&name)
            {
                return false;
            }
        }
    }
    true
}
