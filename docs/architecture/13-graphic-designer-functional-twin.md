# Graphic Designer Functional Twin v1

## Scope

This phase implements the first Ergaxiom-owned professional document model. It does not control Photoshop, Illustrator or another desktop application. It executes the four Graphic Designer capsule operators inside the Occupational Twin and produces an editable master, a deterministic PNG and independent proof evidence.

## Trust chain

1. The raw Work Contract is canonically hashed again and must match `CompiledContract.seal.contract_digest`.
2. Contract input IDs, media types, immutability flags and SHA-256 digests must match the supplied logo, copy and brand profile bytes.
3. Canvas dimensions, color profile, logo geometry, clear-space threshold, text contrast threshold and output media type are read from mandatory contract constraints.
4. The compiled Operator Plan must be bound to the same contract and contain exactly:
   - `design.create_canvas`
   - `design.place_asset`
   - `design.compose_text`
   - `design.export_raster`
5. Each operator is compiled into a `TypedOperation` with exact plan input/output IDs and a content-digest postcondition.
6. `OperatorSimulationRuntime` executes those operations through `TwinWorkspace`; no parallel mutation path exists.
7. The final editable document and PNG are independently decoded and validated before `EvidenceRecord` values are produced.

## Deterministic document model

The editable master is canonical JSON with:

- explicit pixel canvas and sRGB profile,
- explicit safe-area rectangle,
- immutable-logo source identity and source geometry,
- placed logo bounds and colors,
- approved-copy source identity,
- exact copy string, text bounds, origin, scale and color.

The v1 renderer uses a built-in 5×7 bitmap font and a deterministic two-color logo pattern. This deliberately narrows typography and asset rendering while making every output reproducible without OS fonts, GPU drivers or application state.

## PNG and color profile

The runtime writes PNG directly:

- PNG signature and CRC-checked chunks,
- RGBA8 non-interlaced scanlines,
- deterministic stored-deflate zlib streams,
- `sRGB` rendering-intent chunk,
- `iCCP` chunk containing a deterministic ICC v2 monitor profile whose description is `sRGB IEC61966-2.1`.

The validator parses the PNG from bytes, checks every chunk CRC, decodes the zlib stream, validates the ICC header and description, reconstructs pixels and compares those pixels with an independent render.

## Validators

The report produces evidence for all mandatory social-post claims:

- `raster.dimensions` for width and height,
- `raster.icc_profile`,
- `document.logo_geometry` for aspect ratio and clear space,
- `document.text_bounds`,
- `raster.text_contrast.relative_luminance`,
- `raster.text_contrast.render_sampling`,
- `raster.media_type`.

Additional non-contract checks protect approved-copy integrity and full render reproducibility.

The first contrast validator uses declared text/background colors. The second uses actual pre-text pixels captured at rendered glyph coordinates. Both must pass the Work Contract threshold. Distinct validator IDs produce the two independent records required by the diverse contrast proof obligation.

## Fail-closed rules

- Mutating the raw contract after compilation fails the contract-digest gate.
- Mutating any approved input fails before workspace staging.
- A distorted logo placement fails before simulation.
- A low-contrast or out-of-safe-area design may execute deterministically, but its proof evidence becomes `FALSE` and Proof Kernel rejects acceptance.
- PNG, ICC, chunk CRC, rendered pixel or validation-report mutation is detected.
- Immutable source artifacts are never overwritten by the four design operations.

## Deliberate limitations

- The renderer is a functional twin, not a high-fidelity creative engine.
- Only opaque RGBA colors and `sRGB IEC61966-2.1` are supported.
- Safe areas are rectangular in v1.
- Logo rendering uses declared geometry/colors rather than decoding arbitrary SVG paths.
- Desktop application bridges remain a later phase and must preserve this proof boundary.
