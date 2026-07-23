# Final Inkscape Artifact Certified Delivery

This certification layer promotes independently verified final graphic artifacts into a new Ergaxiom Evidence Bundle and Acceptance Certificate. It extends, rather than replaces, the previously certified chain:

1. authorized functional-twin execution,
2. signed and independently verified Inkscape execution,
3. signed sRGB normalization with unchanged IDAT payloads,
4. independently decoded normalized pixels,
5. approved-copy identity,
6. logo geometry and clear space,
7. text bounds, safe area and clipping guard, and
8. rendered text contrast.

## Base certificate re-verification

The runtime does not trust the supplied sRGB delivery object. Before adding any new evidence, it independently verifies the existing attestation against its exact Evidence Bundle, contract, profession capsule, Operator Plan and assurance level. An unknown signing key, substituted bundle, changed plan or altered contract blocks extension.

## Artifact-derived expectations

The approved-copy and approved-logo digests are read from immutable input artifacts already present in the certified Evidence Bundle. The editable SVG and normalized PNG digests are read from the corresponding certified evidence artifacts and must equal the signed normalization binding.

Those values, together with the Inkscape target element ID, become the expectations passed into Final Graphic Artifact Verification. This prevents caller-selected digest substitution.

## Added evidence

The extended bundle includes deterministic JSON evidence artifacts for:

- approved-copy result,
- logo-geometry result,
- rendered text-bounds result,
- rendered-contrast result,
- cross-validator final-artifact binding, and
- final-certification binding.

The certification binding commits to the previous bundle digest, normalization binding digest, final-artifact binding digest, contract and capsule digests, plan ID and digest, assurance level, input IDs and every newly added evidence artifact ID.

## Reassessment and final signature

After the evidence artifacts are added, Evidence Runtime reassesses the complete bundle. Only an `ACCEPTED` decision can proceed. Attestation Runtime then issues a new Ed25519 Acceptance Certificate and immediately verifies it against the exact expanded bundle using a locally constructed trusted-key registry.

The output therefore contains both the previous certified sRGB delivery and the new final artifact certificate, preserving the complete chain of custody.

## Claim boundary

The certificate proves that the declared approved inputs, editable SVG, normalized PNG and accepted validator records are cryptographically bound to one authorized run. It does not discover design intent, judge subjective visual quality, certify arbitrary logo sources, perform OCR or expand the Profession Capsule. Those remain separate contract, planning, validator and profession-certification concerns.
