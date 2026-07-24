# Brand-Compliant Image Export Certified Path

## Scope

This path certifies one bounded Graphic Designer job: `brand_compliant_image_export`.

It does not infer a brand, invent layout rules, choose colors, rewrite copy or judge subjective visual quality. The requester must provide an immutable source SVG, an approved brand-rule manifest and the exact approved logo PNG. Missing or ambiguous technical rules block compilation.

## Restricted source profile

The v1 source contains exactly:

- one SVG root with exact width, height and viewBox,
- one full-canvas background rectangle,
- one embedded PNG logo whose decoded bytes match the approved SHA-256,
- one direct-text element with exact approved copy and typography attributes.

External references, DTDs, scripts, stylesheets, filters, nested text, undeclared elements, unsupported attributes and unapproved colors fail closed.

## Contract and plan

The Work Contract binds all three immutable inputs, exact canvas dimensions, palette, logo identity and geometry, minimum clear space, typography, copy, PNG delivery profile, source immutability and a pinned Inkscape identity.

The typed Operator Plan has three mandatory receipt-bound steps:

1. `brand.validate_source@0.1.0`
2. `brand.export_with_inkscape@0.1.0`
3. `brand.certify_delivery@0.1.0`

Each step has a separate capability-token identity. Undeclared operators, changed versions, permissions, artifacts or dependencies prevent planning.

## Execution and normalization

The proof-bound Inkscape adapter performs an idempotent allowlisted fill operation and exports a dimension-bound raw PNG while proving source immutability, application identity and adapter record integrity.

The raw PNG is then normalized by inserting one sRGB chunk. Normalization independently proves that:

- the input PNG had no prior sRGB or ICC signal,
- the output contains the exact declared sRGB rendering intent,
- all concatenated IDAT payload bytes are unchanged,
- input and output container reports and digests are bound,
- the normalization record reproduces canonically.

The normalized PNG, not the raw Inkscape PNG, is the delivery artifact.

## Independent validators

The final validator reparses the source SVG, decodes and hashes the embedded logo, validates exact geometry and typography, inspects the normalized PNG container, recomputes the normalization and checks the signed execution record. Caller-supplied acceptance flags are not trusted.

The mandatory proof set covers canvas width and height, restricted SVG structure, palette allowlist, logo identity, logo geometry, logo clear space, typography, approved copy, PNG media type, sRGB profile, source immutability and pinned Inkscape execution.

## Trust separation

The brand-export execution record is signed by a dedicated executor key. Capability tokens are issued by a separate policy authority. The final Acceptance Certificate is issued by a separate acceptance-authority key only after Evidence Bundle reassessment and authorized-trace verification.

## Non-goals

This path does not certify aesthetic quality, marketing effectiveness, semantic appropriateness, accessibility beyond declared rules, automatic brand extraction, generative layout, photographic fidelity, print production or PDF preflight. Those require separate contracts and validator suites.
