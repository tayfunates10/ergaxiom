# Background Cleanup Certified Path

## Scope

This path certifies one bounded Graphic Designer job: `image_background_cleanup`.

It does not infer a subject, learn a segmentation model, or guess ambiguous edges. The user or another trusted process must supply an explicitly approved PNG mask whose exact bytes are sealed into the Work Contract. The certified v1 mask profile is binary alpha: every mask pixel is either background (`alpha = 0`) or foreground (`alpha = 255`). Any other alpha value stops execution.

## Contract and plan

The Work Contract binds:

- the immutable source PNG digest,
- the immutable approved-mask PNG digest,
- exact source dimensions,
- a pinned Inkscape version for the integration probe,
- output destinations,
- twelve mandatory technical claims,
- strict E3 acceptance with no mandatory unknowns.

The typed Operator Plan contains three mandatory, receipt-bound steps:

1. `cleanup.apply_binary_mask@0.1.0`
2. `cleanup.inkscape_probe@0.1.0`
3. `cleanup.certify_delivery@0.1.0`

Each step has its own capability-token identity. The plan fails closed if the capsule operator allowlist, input/output profile, permissions, operator versions, dependencies or artifact IDs differ from the certified profile.

## Deterministic execution

The cleanup twin accepts only a restricted PNG profile:

- PNG container with valid chunk CRCs,
- 8-bit RGBA,
- non-interlaced,
- filter type 0 on every scanline,
- explicit sRGB signal,
- bounded pixel and compressed-payload sizes.

For each pixel:

- mask alpha `255`: copy the exact source RGBA sample,
- mask alpha `0`: preserve RGB and set output alpha to `0`,
- any other mask alpha: reject.

The producer records source, mask and output digests; pre-state, action-boundary and post-state digests; foreground/background counts; source immutability; and a canonical record digest.

## Independent validators

Validation uses the separate PNG container validator and pixel decoder rather than trusting the producer codec. It proves:

- exact output width and height,
- mask/source/output dimension equality,
- binary mask alpha,
- non-degenerate foreground and background coverage,
- zero visible mask-declared background pixels,
- zero changed mask-declared foreground RGBA samples,
- valid 8-bit RGBA PNG structure,
- restricted sRGB evidence,
- source immutability.

Every technical failure maps to a stable code, a human-readable explanation and a corrective action. Subjective edge quality is retained as a human-review preference and cannot create a technical acceptance result.

## Real application integration

The cleaned PNG is written to an isolated workspace, inserted into a minimal SVG through the proof-bound Inkscape adapter and exported at the exact source dimensions. The integration report binds:

- application ID,
- application version,
- executable SHA-256,
- cleaned PNG digest,
- probe PNG digest and size,
- probe dimensions,
- proof-bound adapter record digest.

An Inkscape process exit code alone is not proof. The adapter record must be verified and the generated PNG must pass independent structural inspection.

## Evidence and Acceptance Certificate

The final Evidence Bundle contains:

- immutable source and mask artifacts,
- cleaned and probe outputs,
- execution, validation and integration reports,
- the receipt-bound authorized execution trace,
- one independent proof result for every mandatory obligation.

`assess_bundle` recomputes trace conformance and contract acceptance. Only an `ACCEPTED` bundle with zero failed or unknown mandatory obligations can be signed. The Ed25519 Acceptance Certificate is then verified again against the exact Evidence Bundle and recomputed replay manifest.

## Threat model

The path rejects or blocks:

- missing or mismatched digests,
- unsupported PNG profiles,
- non-binary or dimension-mismatched masks,
- empty foreground/background coverage,
- changed foreground pixels,
- visible background pixels,
- source mutation,
- stale or mismatched execution records,
- unverified Inkscape identity or adapter records,
- unauthorized, incomplete or tampered traces,
- evidence or certificate binding changes.

## Non-goals

This path does not certify automatic subject discovery, matting quality, hair-edge reconstruction, semantic correctness of a user-approved mask, generative fill, shadow reconstruction or subjective visual quality. Those capabilities require separate contracts, validators and certification suites.
