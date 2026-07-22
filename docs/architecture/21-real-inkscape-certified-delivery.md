# Real Inkscape Execution Through Final Attestation

This phase joins the real Inkscape adapter and the Inkscape-specific certified-delivery runtime in one measured CI path.

The acceptance test:

1. installs Inkscape on the CI runner,
2. measures and pins the exact executable SHA-256,
3. creates a controlled SVG source document,
4. performs the declared direct-text mutation through the real Inkscape adapter,
5. exports a real PNG through the Inkscape CLI,
6. independently verifies SVG mutation boundaries and PNG dimensions,
7. signs the execution record with Ed25519,
8. verifies the signed record and exact source/editable/raster bytes,
9. consumes the authorized Graphic Designer capability tokens,
10. constructs the expanded evidence bundle,
11. issues a final attestation over that bundle, and
12. independently verifies the attestation against the same evidence material.

## Claim boundary

This phase proves that genuine Inkscape execution material is cryptographically and semantically bound into the final attestation. It does not yet promote the real Inkscape raster to the sole certified delivery artifact for every profession claim.

The existing functional twin still supplies the complete Graphic Designer proof set. The real Inkscape package supplies independently verified execution identity, source/editable/raster digests, declared text mutation, and PNG dimensions. A later real-artifact validator phase must re-evaluate color profile, logo geometry, safe-area containment, and rendered contrast directly on the Inkscape artifacts before those artifacts replace the twin outputs as the certified deliverables.
