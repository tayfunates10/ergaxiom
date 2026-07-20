# Contract Runtime v1

## Purpose

The Contract Runtime converts a versioned Work Contract and Profession Capsule into a sealed, executable proof plan. It is the boundary between declarative professional requirements and the deterministic Proof Kernel.

The runtime does not interpret user intent, invent missing requirements, execute desktop actions, or decide whether a visual result is aesthetically good. Those responsibilities remain outside the trusted core.

## Compilation pipeline

1. Decode the Work Contract and Profession Capsule.
2. Require supported schema versions.
3. bind the contract to the exact capsule ID and version.
4. Resolve the declared job type.
5. Confirm that every job-type constraint exists and is mandatory.
6. Resolve every proof obligation to a real hard constraint.
7. Resolve every declared validator to the capsule registry.
8. Confirm that each validator explicitly supports the constraint.
9. Enforce executor, independent, or diverse validator requirements.
10. Confirm that declared evidence types are supported by the selected validator set.
11. Confirm that every mandatory constraint has a mandatory proof obligation.
12. Enforce the capsule's minimum assurance level and strict acceptance policy.
13. Canonically hash the full contract and capsule.
14. Produce a `CompiledContract` that can initialize the Proof Kernel.

Any failed step produces a compilation error. No partially compiled plan is executable.

## Validator sets

Work Contract schema `0.2.0` replaces a single `validator_id` with an explicit `validator_ids` set.

- `executor` requires at least one declared validator.
- `independent` requires at least one validator whose capsule class is independent or stronger.
- `diverse` requires at least two distinct independent validators.

A label such as `diverse` is therefore not accepted as a claim by itself. The contract must name the separate validators, and the capsule must define each validator's implementation version, supported claims, independence class, and evidence types.

## Evidence admission

A `ContractSession` checks every evidence record before it reaches the Proof Kernel:

- the proof obligation must exist;
- the validator must be authorized for that exact obligation;
- the validator version must match the sealed Profession Capsule;
- the evidence independence class must match the capsule declaration;
- the evidence must carry the active contract digest.

The final digest check, duplicate protection, truth-state accumulation, and acceptance decision remain inside the Proof Kernel.

## Graphic Designer contrast proof

The first Graphic Designer capsule now defines two independent contrast validators:

1. `raster.text_contrast.relative_luminance` calculates WCAG contrast from declared foreground and effective background regions.
2. `raster.text_contrast.render_sampling` independently samples rendered glyph and local background pixels.

The `minimum_text_contrast` obligation cannot reach `SATISFIED` until both approved validators return admissible `TRUE` evidence.

## Command-line inspection

The `ergaxiom-contract-check` binary compiles a Work Contract and Profession Capsule from disk and prints:

- contract and job identifiers;
- canonical contract and capsule digests;
- schema version;
- minimum assurance level;
- unresolved mandatory unknown count;
- proof-obligation count.

It is an inspection tool, not an executor.

## Deferred capabilities

Future versions will add:

- JSON Schema validation inside the Rust trust boundary;
- signed capsule and validator manifests;
- validator executable digests;
- evidence-type payload validation;
- revocation and expiry checks;
- transparency-log publication;
- capability-token issuance for execution bridges.
