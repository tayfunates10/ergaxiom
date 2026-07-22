# Independent PNG Artifact Validator

The PNG artifact validator does not trust the exporting application or a file extension. It parses the complete PNG chunk stream and fails closed on structural ambiguity.

## Structural verification

The validator requires:

- the eight-byte PNG signature,
- exactly one first-position `IHDR` chunk,
- valid width, height, bit depth and color-type combinations,
- PNG compression and filter method zero,
- a supported interlace method,
- valid CRC-32 for every chunk,
- only recognized critical chunks,
- valid `PLTE` requirements for the declared color type,
- consecutive `IDAT` chunks with non-empty payload,
- exactly one zero-length `IEND`, and
- no bytes after `IEND`.

Unknown ancillary chunks remain observable in the chunk evidence list. Unknown critical chunks are rejected.

## Color-profile evidence

The validator recognizes:

- `sRGB` with its rendering intent,
- `iCCP` with its declared profile name, or
- an explicit absence of embedded profile evidence.

It rejects duplicate profile chunks, malformed profile chunks, profile chunks after image data and simultaneous `sRGB` plus `iCCP` claims.

Policy evaluation can require any embedded profile, a specific `sRGB` chunk or an exact ICC profile name. Missing profile evidence produces an explicit violation rather than an inferred default.

## Claim boundary

Version 1 verifies PNG structure, declared metadata, chunk integrity, dimensions, bit depth, color type and profile evidence. It does not yet decompress IDAT or prove that every scanline is decodable. Independent pixel decoding and rendered-content validators remain separate phases.
