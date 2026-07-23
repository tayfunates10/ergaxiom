# Real Inkscape Final Artifact Certification

This pipeline closes the bounded `social_media_static_post` evidence path over one real pinned-Inkscape execution. It replaces fabricated final-validator reports in the real integration path with reports produced from actual immutable inputs, editable SVG bytes and normalized PNG pixels.

## Real fixture

The fixture contains:

- an immutable approved-logo PNG,
- immutable approved copy,
- a white 240 × 300 SVG canvas,
- the approved-logo PNG embedded as a data URI in a declared 80 × 40 logo region, and
- one direct `text` element with the certified target ID.

The approved-logo bytes and digest are rebound into the Work Contract before execution. The changed contract is recompiled and a new sealed Operator Plan is synthesized through the deterministic typed planner. This prevents the real test from reusing a plan or certificate bound to different input bytes.

## Execution and normalization

The permanent workflow:

1. identifies and hashes the installed Inkscape executable,
2. executes the signed text replacement and PNG export,
3. verifies the signed execution record,
4. normalizes the raw PNG to the required sRGB delivery profile,
5. verifies the signed normalization record, and
6. issues the intermediate sRGB-certified delivery.

## Independent final validators

The final stage runs:

- approved-copy validation against the real editable SVG,
- logo geometry and clear-space validation against the real rendered PNG,
- rendered text safe-area and clipping validation,
- rendered text contrast validation, and
- cross-validator artifact and pixel binding.

The normalized PNG is decoded exactly once. The same `PngPixelReport.report_digest` and `rgba_pixel_digest` must appear in logo geometry, text bounds and rendered contrast results. Mixing independently valid reports from another decode fails closed.

The approved-logo PNG is decoded separately because it is the immutable comparison input, not the delivery raster.

## Final certificate

Accepted validator results are added to the Evidence Bundle together with:

- the final artifact binding,
- the final certification binding,
- the normalized raster,
- the signed execution evidence, and
- the signed normalization evidence.

Evidence Runtime reassesses the expanded bundle. Attestation Runtime then issues and immediately reverifies a new Ed25519 Acceptance Certificate over the final bundle digest.

## Real fail-closed checks

The same real fixture checks that certification or validation fails for:

- altered approved copy,
- altered approved-logo alpha mask,
- foreground touching a clipping boundary,
- insufficient contrast policy,
- mixed raster pixel evidence,
- an unknown attestation key, and
- mutation of the Evidence Bundle after certificate issuance.

## CI evidence artifacts

The permanent Inkscape workflow uploads:

- approved-logo PNG,
- source and editable SVG,
- raw and normalized PNG,
- each independent validator result,
- final artifact and certification bindings,
- final Evidence Bundle,
- final Acceptance Certificate,
- exact Inkscape executable digest, and
- a machine-readable digest summary.

The artifacts are retained for seven days. They are diagnostic evidence from the pinned CI fixture and are not a production signing-key substitute.

## Claim boundary

This path certifies one declared fixture and one restricted operator path. It does not certify arbitrary SVG nesting, external resources, filters, fonts, text shaping, color spaces or layouts.
