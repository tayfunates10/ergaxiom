# Deterministic Typed Operator Planner

The typed planner converts a fully compiled `social_media_static_post` Work Contract into the only Operator Plan currently supported by the certified Graphic Designer path.

## Trust boundary

The planner does not interpret prose and does not choose creative actions. It accepts:

- a caller-supplied plan identifier,
- a trusted caller-supplied UTC creation timestamp,
- the complete Work Contract JSON, and
- the pinned Graphic Designer Profession Capsule.

The Work Contract is recompiled through `ergaxiom-contract-runtime` before planning. The generated plan is then recompiled through `ergaxiom-operator-plan-runtime`. No plan is returned if either authoritative runtime rejects the material.

## Resolution behavior

Missing `plan_id` or `created_at` values produce `needs_resolution`. The planner never invents identifiers or reads the runtime clock, because either action would make replay and plan digests nondeterministic.

## Certified profile

Version 1 accepts exactly:

### Inputs

- `approved_logo`
- `brand_profile`
- `approved_copy`

Every input must be immutable.

### Outputs

- `editable_master`
- `delivery_raster`
- `evidence_bundle`

Every output must be required and must use the certified destination and media-type profile.

### Permissions

- read immutable `contract://inputs/*`
- write non-overwriting `contract://outputs/*`
- control the isolated design-editor workspace with network disabled

Additional inputs, outputs or permissions fail closed instead of being silently ignored.

## Operator sequence

The planner emits four mandatory steps in this order:

1. `design.create_canvas`
2. `design.place_asset`
3. `design.compose_text`
4. `design.export_raster`

Operator versions are read from the pinned capsule. The capsule job-type allowlist must contain exactly this sequence. Each step declares exact artifact bindings, dependencies and one deterministic capability-token identifier derived from the caller-supplied plan ID.

## Capability metadata

The plan digest also commits a capability-requirement map that binds every token identifier to:

- one step,
- one capability,
- one resource, and
- one access mode.

This map is later used by the capability issuer; the planner does not issue or sign tokens.

## CLI

```bash
cargo run -p ergaxiom-typed-planner-runtime \
  --bin ergaxiom-plan -- \
  examples/plans/static-social-post-plan-identity.json \
  compiled-contract.json \
  professions/graphic-designer/profession.json \
  compiled-plan.json
```

The CLI exits with code `0` for a planned result, `2` when identity resolution is required and `1` for invalid or unsupported material.

## Simulation gate

The integration suite feeds the generated plan directly into `compile_graphic_design_simulation`. This proves the planner output uses the artifact bindings and operator order required by the Occupational Twin without manual rewriting.

## Claim boundary

Version 1 supports one deterministic plan shape. It does not perform model-based planning, generate layouts, issue capability tokens, control Inkscape or select among alternative operator strategies.
