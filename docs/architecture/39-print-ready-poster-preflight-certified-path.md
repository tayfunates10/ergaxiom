# Print-Ready Poster Preflight Certified Path

## Scope

This path certifies one bounded poster profile. It accepts an immutable single-page SVG and a digest-bound print specification, exports a PDF through pinned Inkscape, independently parses the resulting PDF and issues an Acceptance Certificate only when every mandatory technical claim is proven.

The certified source profile is intentionally narrow:

- one flat vector poster page;
- `svg`, `g`, `rect` and `path` elements only;
- direct lowercase `#rrggbb` fills;
- absolute `M`, `L`, `H`, `V` and `Z` path commands;
- all text converted to outlined paths before execution;
- no raster images, live text, external references, scripts, filters, opacity, transforms, masks, clip paths or unsupported SVG structure.

Unsupported material remains `UNKNOWN` or fails validation. It is never approximated into acceptance.

## Normative inputs

The Work Contract binds:

1. the exact source SVG SHA-256;
2. the canonical print-specification SHA-256;
3. trim width and height in milli-millimetres;
4. bleed and safe margin in milli-millimetres;
5. the required bleed-background element;
6. the exact fill palette;
7. allowed PDF color spaces;
8. required PDF version;
9. pinned Inkscape identity.

Subjective composition quality stays outside hard acceptance.

## Typed plan

The planner emits exactly three mandatory steps:

1. `print.validate_source`;
2. `print.export_pdf_with_inkscape`;
3. `print.certify_preflight`.

Every step requires a contract-, capsule-, plan-, step-, operator-, executor- and device-bound capability token. Authorization receipts are consumed by the final execution trace assessment.

## Source validation

The independent SVG validator parses the source bytes and recomputes:

- width, height and `viewBox` against trim plus twice the bleed;
- full bleed coverage by the declared background rectangle;
- every non-background vector bound against bleed plus safe margin;
- exact palette membership;
- raster-image count;
- live-text count;
- unsupported path count;
- duplicate identifiers and forbidden structure.

The parser does not trust editor metadata, screenshots or declared success fields.

## Proof-bound execution

Execution occurs in an isolated workspace. The proof-bound Inkscape adapter:

- verifies the executable SHA-256 and supported version;
- verifies the immutable source digest;
- creates one isolated preflight layer without mutating the source;
- exports the editable copy as PDF;
- records action-boundary and export receipts;
- removes partial outputs on failure.

The raw PDF is evidence, not the final accepted delivery.

## PDF normalization and independent validation

The normalizer deterministically writes:

- `MediaBox` equal to the full bleed page;
- `TrimBox` inset by the declared bleed;
- `BleedBox` equal to `MediaBox`;
- `CropBox` equal to `MediaBox`;
- the certified PDF version.

A separate PDF parser then reopens the normalized bytes and independently verifies:

- exactly one page;
- all four page boxes;
- required PDF version;
- no raster image XObjects;
- no PDF font resources;
- only explicitly allowed color-space operators;
- no non-opaque transparency, soft masks or unsupported transparency groups;
- no annotations, JavaScript, launch actions, forms, embedded files or encryption.

A successful Inkscape return code or normalizer record is insufficient by itself.

## Trust separation

The Inkscape/preflight execution record is signed by a dedicated Ed25519 executor key. The final certifier:

1. verifies the executor signature against a trusted key registry;
2. recomputes source and PDF validation from the supplied bytes;
3. reproduces all artifact and normalization bindings;
4. reassesses the receipt-bound execution trace;
5. constructs the Evidence Bundle;
6. requires an independently accepted decision;
7. issues and immediately verifies an Ed25519 Acceptance Certificate with a separate acceptance-authority key.

Changing the source, specification, editable SVG, raw PDF, normalized PDF, execution record, page boxes, validation report or authorization trace invalidates certification.

## Failure behavior

The failure map provides concrete remediation for source structure, canvas, bleed, safe area, palette, raster material, live fonts, page count, boxes, PDF version, color space, transparency, external actions, source immutability and application identity.

The path does not claim general commercial-print certification, CMYK conversion, spot-color validation, overprint simulation, PDF/X compliance or unrestricted raster-image DPI analysis. Those capabilities require separate bounded profiles and validators.
