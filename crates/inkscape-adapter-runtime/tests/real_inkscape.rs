#![cfg(feature = "real-inkscape-tests")]

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ergaxiom_inkscape_adapter_runtime::{
    SetTextAndExportRequest, VerifiedInkscape, observe_svg, read_png_info, sha256_file,
};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!(
            "ergaxiom-real-inkscape-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn real_inkscape_text_edit_and_png_export_are_independently_verified(
) -> Result<(), Box<dyn Error>> {
    let executable = env::var("ERGAXIOM_INKSCAPE")?;
    let executable_digest = env::var("ERGAXIOM_INKSCAPE_SHA256")?;
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/inkscape/social-post.svg");
    let directory = TestDirectory::create()?;
    let editable_output = directory.path.join("approved.svg");
    let raster_output = directory.path.join("approved.png");
    let source_digest = sha256_file(&fixture)?;
    let inkscape = VerifiedInkscape::open(executable, &executable_digest)?;

    let record = inkscape.execute_set_text_and_export(&SetTextAndExportRequest {
        schema_version: "0.1.0".to_owned(),
        request_id: "request.real-inkscape.0001".to_owned(),
        source_svg: fixture,
        expected_source_digest: source_digest,
        target_element_id: "headline".to_owned(),
        replacement_text: "APPROVED".to_owned(),
        editable_output_svg: editable_output.clone(),
        raster_output_png: raster_output.clone(),
        export_width: 512,
        export_height: 512,
    })?;

    assert!(record.verified);
    assert_eq!(record.binary.executable_digest, executable_digest);
    assert_eq!(record.export_width, 512);
    assert_eq!(record.export_height, 512);
    assert_eq!(record.record_digest.len(), 64);

    let post = observe_svg(&editable_output)?;
    assert_eq!(
        post.elements
            .get("headline")
            .map(|element| element.direct_text.as_str()),
        Some("APPROVED")
    );
    assert_eq!(
        post.elements
            .get("footer")
            .map(|element| element.direct_text.as_str()),
        Some("ERGAXIOM CONTROLLED FIXTURE")
    );

    let png = read_png_info(&raster_output)?;
    assert_eq!((png.width, png.height), (512, 512));
    assert_eq!(png.artifact_digest, record.raster_output_digest);
    Ok(())
}
