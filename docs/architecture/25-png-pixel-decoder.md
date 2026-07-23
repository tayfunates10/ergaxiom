# Independent PNG Pixel Decoder

The pixel decoder is the first Ergaxiom layer that independently converts a validated PNG container into canonical RGBA pixel bytes. It is deliberately separate from Inkscape and from the PNG metadata normalizer.

## Prerequisite validation

Every input first passes the independent PNG artifact validator. Therefore the decoder inherits fail-closed checks for:

- PNG signature,
- complete chunk boundaries,
- every chunk CRC-32,
- critical-chunk recognition,
- IHDR, PLTE, IDAT and IEND ordering,
- non-empty consecutive IDAT payload,
- no trailing bytes after IEND, and
- valid declared bit-depth and color-type combinations.

## Version 1 decoding profile

The decoder accepts only:

- 8-bit samples,
- non-interlaced images,
- truecolor RGB, or
- truecolor with alpha RGBA.

Grayscale, indexed color, 16-bit samples and Adam7 interlace remain explicit blockers rather than being approximated.

## Independent pixel reconstruction

All IDAT chunks are concatenated in stream order and decoded as one zlib stream. The decoder requires:

- no more than 256 MiB of compressed IDAT payload,
- no more than 512 MiB of declared decompressed scanline data,
- no more than 100 million pixels,
- exactly the expected decompressed byte length,
- no bytes after the zlib stream, and
- PNG filter values only in the range 0 through 4.

The decoder independently reverses the None, Sub, Up, Average and Paeth filters. RGB pixels receive an explicit opaque alpha value; RGBA bytes are preserved.

## Evidence report

The deterministic pixel report binds:

- PNG artifact digest,
- structural-validator report digest,
- dimensions and declared pixel format,
- row-byte and pixel counts,
- non-opaque pixel count,
- combined IDAT payload digest,
- decompressed filtered-scanline digest,
- canonical RGBA pixel digest,
- per-filter row counts, and
- a canonical report digest.

## Real Inkscape acceptance test

The permanent Inkscape workflow exports a genuine PNG, adds proof-bound sRGB metadata, and decodes both files independently. Acceptance requires:

- different whole-file digests,
- identical IDAT payload digests,
- identical canonical RGBA digests,
- identical RGBA byte arrays,
- identical filter distributions, and
- identical non-opaque pixel counts.

This proves that the sRGB metadata normalization changes container metadata without changing rendered pixel bytes.

## Claim boundary

Version 1 proves container-to-RGBA decoding for its restricted PNG profile and produces trustworthy pixel material for later validators. It does not yet claim that the design satisfies logo geometry, safe-area containment, visual contrast, approved-copy rendering or other Graphic Designer requirements. Those checks must consume this decoded pixel evidence in separate independent validator phases.
