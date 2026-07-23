# Independent SVG Approved-Copy Validator

The approved-copy validator proves that a declared text element in an editable SVG contains the exact approved UTF-8 copy. It parses the delivered SVG independently of the Inkscape adapter and does not trust the execution record's replacement-text field, application state, layer name or executor success flag.

## Inputs and bindings

Version 1 consumes:

- the immutable approved-copy bytes,
- the complete editable SVG bytes, and
- the contract-bound target element ID.

The report binds the approved-copy SHA-256, SVG artifact SHA-256, target ID, extracted text SHA-256, byte counts, exact-match result and canonical report and decision digests.

## Independent document inspection

The validator uses a separate XML document implementation from the Inkscape execution adapter. It requires:

- a valid UTF-8 SVG document,
- an `svg` root element,
- globally unique element IDs,
- exactly one target element,
- a target whose local element name is `text`,
- no nested target elements such as `tspan`, and
- exactly one direct text segment.

XML character references are decoded by the independent parser before comparison, so `A &amp; B` is compared with the approved text `A & B`. Whitespace, punctuation, capitalization, Unicode code points and line endings otherwise remain exact and are not silently normalized.

## Fail-closed conditions

Validation rejects or blocks when:

- approved copy or SVG exceeds resource limits,
- either input is invalid UTF-8,
- approved copy contains NUL,
- DTD or entity declarations are present,
- the document root is not SVG,
- any element ID is duplicated,
- the target is missing or is not a text element,
- nested or ambiguous text structure is present, or
- extracted text differs by even one byte after XML reference decoding.

## Independence and claim boundary

This validator proves editable-document copy identity. It does not prove that the same glyphs are visibly rendered in the delivery PNG, that a font contains the expected glyphs, that text is legible, or that the target element is the correct semantic headline. Pixel bounds, clipping and contrast are separate validators. A later certification layer must bind this report to the same editable SVG, rendered PNG, Work Contract, Operator Plan and signed application execution package before issuing final acceptance.
