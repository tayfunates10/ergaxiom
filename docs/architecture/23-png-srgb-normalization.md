# Proof-Bound PNG sRGB Normalization

The real Inkscape CI export is structurally valid but contains no `sRGB` or `iCCP` chunk. Ergaxiom must not infer or silently claim a color profile from a file extension or from exporter success.

This phase permits insertion of one PNG `sRGB` chunk only after both the source vector material and the raster container satisfy a restricted proof profile.

## Source SVG proof profile

The SVG verifier accepts only material whose color declarations are explicitly constrained to sRGB-compatible syntax:

- hexadecimal colors,
- `rgb()` and `rgba()` values,
- `none` and `transparent`, and
- internal fragment paint-server references such as `url(#gradient)` whose stop colors are checked independently.

It rejects:

- DTD material,
- embedded raster images,
- external resource references,
- `<style>`, `<script>`, `<filter>`, `<foreignObject>` and color-profile elements,
- ICC, CMYK, Lab, LCH, OKLab, OKLCH and CSS `color()` syntax,
- custom CSS properties,
- non-sRGB color-interpolation declarations, and
- unsupported or ambiguous paint values.

The successful SVG evidence includes the source digest, element count, color-declaration count, internal paint-server reference count and a canonical evidence digest.

## Input PNG preconditions

The normalizer first runs the independent PNG validator. It refuses to operate when the PNG already contains any explicit or potentially competing color signal:

- `sRGB`,
- `iCCP`,
- `cICP`,
- `cHRM`,
- `gAMA`,
- `mDCV`,
- `cLLI`, or
- `eXIf`.

The input file and source SVG must reproduce trusted SHA-256 digests, the output must be a new path, and no parent-directory traversal is accepted.

## Deterministic mutation

The normalizer inserts exactly one one-byte `sRGB` chunk immediately after `IHDR`, with an explicit rendering-intent value and a newly calculated PNG CRC-32. No existing PNG chunk is rewritten.

Before and after normalization, all `IDAT` payload bytes are concatenated in stream order and hashed. Any digest difference fails the operation. The normalized PNG is then reparsed by the independent validator and must satisfy the exact original dimensions, bit depth and color type plus an `sRGB` profile requirement.

The execution record binds:

- request digest,
- SVG proof evidence,
- input and output PNG digests,
- input and output validator-report digests,
- input and output IDAT payload digests,
- rendering intent,
- inserted chunk CRC,
- dimensions and bit depth, and
- a canonical record digest.

## Claim boundary

Adding an `sRGB` chunk does not convert arbitrary pixels into sRGB. Ergaxiom performs this normalization only for a restricted SVG source profile rendered by the pinned Inkscape adapter and only when no competing PNG color metadata exists. Broader SVG features, embedded images, existing profiles or ambiguous color syntax remain blockers.

The normalizer preserves compressed image payload bytes; it does not yet independently decompress and colorimetrically evaluate every rendered pixel. Pixel decoding and rendered-content verification remain separate phases.
