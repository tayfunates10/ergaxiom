# Proof-Bound Inkscape Operator Set

## Purpose

This component expands the bounded Inkscape path from one direct-text replacement into a typed design-operation surface without making Inkscape, its exit code or the renderer a source of truth.

The adapter supports only an explicitly restricted SVG profile. Unsupported structures are rejected instead of being interpreted heuristically.

## Operator surface

The Graphic Designer capsule pins these adapter capabilities at version `0.1.0`:

- `inkscape.canvas.resize`
- `inkscape.layer.create`
- `inkscape.asset.place`
- `inkscape.text.create`
- `inkscape.color.set_fill`
- `inkscape.object.transform`
- `inkscape.object.align`
- `inkscape.object.distribute`
- `inkscape.document.save_svg`
- `inkscape.export.profiled`

The profiled export operator supports PNG, restricted SVG and PDF. PNG dimensions are independently decoded. SVG exports are observed again through the semantic SVG reader. PDF exports must contain the expected PDF signature and are bound to the exact command and input digest.

## Execution boundary

Every request binds:

- the exact source SVG path and SHA-256 digest;
- a new isolated editable-output path;
- an ordered typed operation list;
- an explicit export list and output paths;
- the trusted Inkscape executable digest and parsed supported version.

The source is never edited in place. The adapter creates a partial isolated copy, verifies the source before each operation and rechecks the original source at the end. A source digest change aborts the request.

## Three semantic states per operation

Each operation records:

1. **Pre-state:** semantic SVG snapshot before the operation.
2. **Action-boundary state:** a fresh snapshot immediately before mutation. It must equal the pre-state.
3. **Post-state:** semantic snapshot after mutation.

The operation receipt binds all three snapshot digests, the typed operation digest, target IDs, changed-property allowlist, operator ID and pinned operator version.

A mismatch between the pre-state and action-boundary state is treated as a TOCTOU failure.

## Declared mutation model

The adapter computes the expected mutation envelope before changing material. The envelope may permit only:

- named root properties for canvas resize;
- named attributes or direct text on exact target IDs;
- explicitly declared element insertions;
- no undeclared removal;
- no unrelated element or property change.

After each operation, the semantic delta is recomputed independently. Any root, element, attribute, direct-text or structural change outside the envelope fails closed with `UndeclaredMutation`.

## Restricted SVG profile

The proof-bound path rejects or does not generate:

- DTD and entity declarations;
- script elements;
- `foreignObject`;
- JavaScript URLs;
- event-handler attributes;
- external HTTP or HTTPS references;
- unsupported nested text structures;
- unsupported target geometry;
- duplicate target identifiers;
- non-finite or out-of-range geometry.

Approved PNG and SVG assets are size-limited, SHA-256 bound and embedded as base64 data URIs so the editable output does not acquire an undeclared runtime network or filesystem dependency.

## Typography and geometry

Text creation requires explicit copy, font family, font size, font weight, fill, text anchor and position. The adapter creates a direct SVG text node; it does not guess typography from visual examples.

Transforms use explicit fixed-point milli-units for translation, rotation and scale. Alignment and distribution operate only over supported elements with observable numeric geometry and require explicit ordered target lists.

## Rollback and cleanup

Execution uses a new partial SVG and new export paths. On any failure, the adapter removes partial and unaccepted outputs. The final editable SVG is moved into place only after all operations and exports are verified and the original source is proven unchanged.

Receipts state the rollback strategy and bind the final editable digest, export digests and exact binary identity.

## Trust boundary

The following are not sufficient proof:

- an Inkscape success exit code;
- a generated file existing;
- a screenshot;
- the adapter declaring success;
- a renderer-side state field.

Acceptance requires the semantic receipts, independently checked output structure and the wider Evidence Bundle and Acceptance Certificate chain. This operator set produces bounded execution evidence; it does not independently certify subjective design quality.

## Permanent validation

The dedicated CI workflow performs:

- workspace formatting verification;
- adapter Clippy with warnings denied;
- capsule version-pin and rollback checks;
- deterministic unit and attack tests;
- a real pinned Inkscape regression that exercises canvas, layer, vector/raster asset, text, color, transform, align, distribute and PNG/SVG/PDF export operations.

The existing complete final-artifact certificate workflow remains a separate regression gate, ensuring the expanded adapter cannot weaken the previously certified static-social-post path.
