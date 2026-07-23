# Independent Rendered Text Bounds Validator

The rendered text-bounds validator consumes independently decoded RGBA pixels and checks a declared text-only analysis region against a declared safe area. It does not trust SVG text boxes, application layer metadata, exporter success or an executor-provided bounding rectangle as proof of visible placement.

## Measurement model

A policy declares:

- a text-specific analysis rectangle,
- a safe-area rectangle completely inside that analysis rectangle,
- a local background-ring thickness,
- a minimum RGB distance for visible foreground classification,
- minimum and maximum foreground coverage,
- required safe-area margin, and
- a clipping guard along the analysis boundary.

The complete background ring must remain inside the decoded image. Version 1 requires all evaluated analysis and background pixels to be opaque.

## Local background

The validator measures the immediately surrounding ring independently per RGB channel using deterministic 256-bin medians. Every ring pixel is compared with that median. Gradients, patterns, contamination or unrelated nearby objects that exceed the policy deviation fail closed.

## Visible foreground bounds

Pixels inside the analysis rectangle become foreground only when their RGB distance from the measured background meets the policy threshold. The validator then records:

- total foreground count and coverage,
- exact occupied pixel bounds,
- foreground pixels outside the safe area,
- left, top, right and bottom safe-area margins,
- foreground pixels within the analysis-boundary clipping guard,
- non-opaque pixel counts, and
- canonical report and decision digests.

The clipping guard is independent of the safe area. It detects a declared analysis rectangle that may already be cutting off rendered glyphs, even when the visible fragment remains inside a permissive safe area.

## Fail-closed conditions

Validation rejects or blocks when:

- the decoded RGBA length does not match image dimensions,
- analysis or safe-area geometry is invalid,
- the background ring leaves the image,
- the clipping guard is invalid,
- the analysis region exceeds resource limits,
- local background uniformity exceeds policy,
- foreground is missing or implausibly covers too much of the analysis region,
- any visible foreground lies outside the safe area,
- required safe-area margins are not met,
- visible foreground touches the clipping guard, or
- unexpected alpha appears in evaluated regions.

## Claim boundary

Version 1 proves the visible bounds and safe-area placement of foreground pixels inside a declared text-only region. It does not discover text automatically, perform OCR, prove approved-copy identity, distinguish text from an unrelated dark object, infer the correct safe area or establish typography quality. Those claims require separately bound planning evidence and independent validators.

The result may enter the Graphic Designer Evidence Bundle only when the analysis region, safe area, rendered artifact digest, Work Contract and Operator Plan are cryptographically bound to the same run.
