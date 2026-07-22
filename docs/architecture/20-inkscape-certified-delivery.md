# Inkscape Certified Delivery Binding

This phase binds real Inkscape execution evidence into Graphic Certified Delivery.

A delivery certificate must not rely only on an application-reported success flag. The certification runtime independently verifies the signed Inkscape execution record against the exact source SVG, editable SVG and raster PNG bytes before constructing the evidence bundle or issuing an attestation.

Required bindings:

- Ed25519 signature from a trusted Inkscape execution authority,
- canonical execution-record digest,
- exact request digest,
- exact source SVG digest,
- exact editable SVG digest,
- exact raster PNG digest,
- semantic pre/post SVG snapshot digests,
- one declared direct-text mutation and no other ID-bound SVG mutation,
- PNG signature and IHDR dimensions,
- approved copy equality,
- export dimensions equal the Graphic Design job canvas,
- Inkscape application ID and supported version range.

The verified execution material is included in the evidence bundle as evidence artifacts. The final attestation therefore commits to the application execution package as well as the delivered editable and raster artifacts.

No valid or trusted Inkscape execution package means no certified Inkscape delivery.
