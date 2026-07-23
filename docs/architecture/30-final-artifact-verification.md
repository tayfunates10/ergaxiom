# Final Graphic Artifact Verification Binding

The final artifact verification runtime combines four independently produced validator decisions into one deterministic binding:

- editable-SVG approved-copy identity,
- rendered logo geometry and clear space,
- rendered text bounds and safe-area placement, and
- rendered text contrast.

It does not rerun those validators and does not trust their names alone. It verifies that every accepted result is bound to the exact approved inputs and final artifacts declared by the certification layer.

## Required bindings

The caller supplies contract-derived expectations for:

- approved-copy artifact SHA-256,
- approved-logo artifact SHA-256,
- certified editable SVG SHA-256,
- normalized delivery PNG SHA-256, and
- target SVG text-element ID.

The runtime then proves that:

- approved-copy evidence consumed the exact approved copy and editable SVG,
- the target ID equals the contract-bound text target,
- logo evidence consumed the exact approved logo,
- logo, text-bounds and contrast evidence all measured the same normalized PNG,
- all raster validators consumed the same independent pixel-decoder report and RGBA byte digest,
- rendered contrast covers the exact text analysis region used by the bounds validator,
- the text-bounds validator observed real foreground bounds, and
- every validator reports acceptance with an empty violation set.

All report and decision digests must be lowercase SHA-256 values. Missing, malformed or contradictory evidence fails closed.

## Deterministic output

The resulting binding contains:

- all approved-input and output artifact digests,
- all four validator report and decision digests,
- shared pixel-decoder and RGBA digests,
- text analysis, safe-area, observed-bounds and contrast regions,
- minimum measured dominant-pixel contrast,
- logo mask IoU,
- logo aspect-ratio error,
- clear-space intrusion count, and
- a canonical binding digest.

Identical accepted evidence produces an identical binding. Mutating an artifact digest, pixel-decode digest, region or validator decision invalidates the binding.

## Claim boundary

This runtime creates the authoritative cross-validator artifact binding, but version 1 does not itself issue an Ergaxiom Acceptance Certificate. A subsequent certification layer must add the validator result records and this binding to the Evidence Bundle, reassess the complete bundle through Evidence Runtime, and issue a new independently verifiable attestation.
