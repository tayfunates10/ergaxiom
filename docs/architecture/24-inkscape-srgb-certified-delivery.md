# Inkscape sRGB Certified Delivery

This phase promotes proof-bound sRGB normalization from an isolated transformation record into mandatory evidence for a new final Graphic Designer attestation.

## Trust chain

The certification path is intentionally layered:

1. the Graphic Designer functional twin satisfies the complete Work Contract proof set,
2. the pinned Inkscape adapter produces the editable SVG and raw PNG,
3. the Inkscape execution record is signed and independently verified,
4. the restricted SVG source is proven sRGB-compatible,
5. the profileless PNG is normalized by inserting one verified `sRGB` chunk,
6. the normalization record is signed with a separate Ed25519 key,
7. a separate verifier reproduces the source, raw PNG, normalized PNG, report and IDAT digests,
8. the previously issued Inkscape attestation is independently reverified with trusted keys,
9. all cross-layer digests and dimensions are bound into one delivery-binding artifact, and
10. the expanded evidence bundle is reassessed and receives a new final attestation.

## Required bindings

Certification stops unless:

- the supplied Work Contract requires exactly `sRGB IEC61966-2.1`,
- the compiled contract, plan and assurance level match the previous Inkscape certificate,
- the previous Inkscape certificate signature verifies against the supplied trusted key registry,
- the normalization source digest equals the certified editable SVG digest,
- the normalization input digest equals the certified raw PNG digest,
- the normalization dimensions equal the certified Inkscape export dimensions,
- the input and output IDAT payload digests are identical,
- the normalized PNG independently reports the declared `sRGB` rendering intent, and
- the signed normalization package and exact files verify independently.

## Final evidence additions

The final bundle adds:

- the signed normalization package,
- the independent normalization verification summary,
- the normalized PNG bytes, and
- a canonical cross-layer delivery binding.

Capability tokens are not consumed again. The new layer re-attests already authorized work with additional independently verified evidence.

## Attack behavior

The chain fails closed for:

- unknown normalization keys,
- normalization signature mutation,
- raw or normalized PNG mutation,
- material-path substitution,
- substituted source SVG,
- a forged or untrusted base attestation,
- contract or plan substitution,
- non-sRGB contract requirements,
- dimension mismatch, and
- any IDAT payload change.

## Claim boundary

The final attestation proves that the genuine Inkscape raster has an independently validated sRGB declaration whose insertion preserved compressed image payload bytes and whose source vector passed the restricted sRGB proof profile. Pixel decoding, logo-geometry detection, safe-area detection and independently sampled rendered contrast remain separate real-artifact validator phases.
