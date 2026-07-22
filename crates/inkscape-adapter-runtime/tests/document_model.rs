use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_inkscape_adapter_runtime::{
    InkscapeAdapterError, observe_svg, read_png_info, rewrite_direct_text,
};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create(name: &str) -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ergaxiom-inkscape-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn observes_canvas_and_id_bound_elements() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("observe")?;
    let source = directory.join("source.svg");
    fs::write(&source, simple_svg("BEFORE"))?;

    let snapshot = observe_svg(&source)?;
    assert_eq!(snapshot.width.as_deref(), Some("1080"));
    assert_eq!(snapshot.height.as_deref(), Some("1080"));
    assert_eq!(snapshot.view_box.as_deref(), Some("0 0 1080 1080"));
    assert_eq!(
        snapshot
            .elements
            .get("headline")
            .map(|element| element.direct_text.as_str()),
        Some("BEFORE")
    );
    assert_eq!(snapshot.snapshot_digest.len(), 64);
    Ok(())
}

#[test]
fn rewrites_only_the_declared_direct_text_target() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("rewrite")?;
    let source = directory.join("source.svg");
    let output = directory.join("output.svg");
    fs::write(&source, simple_svg("BEFORE"))?;
    let before = observe_svg(&source)?;

    rewrite_direct_text(&source, &output, "headline", "APPROVED")?;
    let after = observe_svg(&output)?;

    assert_eq!(
        after
            .elements
            .get("headline")
            .map(|element| element.direct_text.as_str()),
        Some("APPROVED")
    );
    assert_eq!(
        before.elements.get("background"),
        after.elements.get("background")
    );
    assert_ne!(before.source_digest, after.source_digest);
    Ok(())
}

#[test]
fn duplicate_target_ids_fail_closed() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("duplicate")?;
    let source = directory.join("source.svg");
    let output = directory.join("output.svg");
    fs::write(
        &source,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><text id="headline">A</text><text id="headline">B</text></svg>"#,
    )?;

    let error = rewrite_direct_text(&source, &output, "headline", "APPROVED")
        .err()
        .ok_or("duplicate target should fail")?;
    assert!(matches!(error, InkscapeAdapterError::DuplicateElementId(_)));
    assert!(!output.exists());
    Ok(())
}

#[test]
fn nested_text_content_fails_closed() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("nested")?;
    let source = directory.join("source.svg");
    let output = directory.join("output.svg");
    fs::write(
        &source,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><text id="headline"><tspan>BEFORE</tspan></text></svg>"#,
    )?;

    let error = rewrite_direct_text(&source, &output, "headline", "APPROVED")
        .err()
        .ok_or("nested target should fail")?;
    assert!(matches!(error, InkscapeAdapterError::NestedTargetContent));
    assert!(!output.exists());
    Ok(())
}

#[test]
fn dtd_material_is_rejected() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("dtd")?;
    let source = directory.join("source.svg");
    fs::write(
        &source,
        r#"<!DOCTYPE svg [<!ENTITY x "unsafe">]><svg xmlns="http://www.w3.org/2000/svg"><text id="headline">&x;</text></svg>"#,
    )?;

    let error = observe_svg(&source)
        .err()
        .ok_or("DTD material should fail")?;
    assert!(matches!(error, InkscapeAdapterError::DocumentTypeForbidden));
    Ok(())
}

#[test]
fn png_ihdr_dimensions_are_read_independently() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("png")?;
    let png_path = directory.join("output.png");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    bytes.extend_from_slice(&13_u32.to_be_bytes());
    bytes.extend_from_slice(b"IHDR");
    bytes.extend_from_slice(&512_u32.to_be_bytes());
    bytes.extend_from_slice(&768_u32.to_be_bytes());
    fs::write(&png_path, bytes)?;

    let info = read_png_info(&png_path)?;
    assert_eq!(info.width, 512);
    assert_eq!(info.height, 768);
    assert_eq!(info.artifact_digest.len(), 64);
    Ok(())
}

fn simple_svg(headline: &str) -> String {
    format!(
        r##"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="1080" viewBox="0 0 1080 1080" id="root">
  <rect id="background" x="0" y="0" width="1080" height="1080" fill="#111827" />
  <text id="headline" x="540" y="540">{headline}</text>
</svg>
"##
    )
}
