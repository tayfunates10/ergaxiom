# Independent Rendered Logo Geometry Validator

The logo geometry validator compares a real rendered PNG against an independently decoded approved logo PNG. It does not trust SVG object metadata, application layer names, exporter success or an executor-provided geometry claim.

## Approved reference mask

The approved logo PNG is decoded through the independent PNG pixel decoder. Version 1 requires a transparent approved asset and derives a deterministic binary reference mask from its alpha channel using a policy-pinned threshold.

The validator records the approved artifact digest, pixel-decoder report digest, RGBA digest, mask dimensions, foreground count, foreground share and SHA-256 mask digest. Sparse or effectively fully opaque source assets fail before rendered geometry is evaluated.

## Rendered measurement

A policy declares the exact logo placement rectangle. The approved alpha mask is scaled into that rectangle with deterministic nearest-neighbour sampling. Rendered foreground pixels are detected independently by RGB distance from a locally measured background.

The validator reports:

- approved and rendered artifact bindings,
- expected and observed foreground counts,
- expected and observed occupied bounds,
- mask intersection and union counts,
- binary-mask intersection-over-union,
- expected and rendered aspect ratios,
- relative aspect-ratio error in parts per million,
- non-opaque logo pixels, and
- canonical report and decision digests.

A changed, stretched, cropped, enlarged or incomplete mark therefore cannot pass only because its declared placement rectangle is correct.

## Clear-space measurement

The logo rectangle is expanded by the required clear-space distance. A second outer ring is used only to measure the local background, preventing a uniformly contaminated clear-space area from redefining itself as the background.

Every pixel in the required clear-space band is compared with that independently sampled background. Unexpected foreground pixels are counted as clear-space intrusions. Logo, clear-space and background sample pixels must be opaque in version 1.

## Fail-closed conditions

Validation rejects or blocks when:

- decoded byte lengths do not match image dimensions,
- image or region resource limits are exceeded,
- the approved alpha mask is too sparse or too dense,
- surrounding rings leave the image,
- local background uniformity exceeds policy,
- rendered foreground is missing,
- mask IoU is below policy,
- occupied-bounds aspect ratio exceeds tolerance,
- clear-space intrusions exceed policy, or
- any evaluated delivery region contains unexpected alpha.

## Claim boundary

Version 1 validates a declared rendered placement against a transparent approved PNG. It does not discover logos automatically, prove brand color compliance, identify a logo in an arbitrary photograph, select the placement rectangle, or certify a non-transparent approved source. Those claims require separate signed planning evidence or independent validators.

The result is suitable for admission into the Graphic Designer Evidence Bundle only when the approved asset digest, rendered artifact digest, placement policy and validator decision are bound to the same Work Contract and Operator Plan.
