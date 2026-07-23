# Deterministic Intent-to-Contract Compiler

The intent compiler is the first product-facing boundary before a Work Contract exists. Version 1 supports only the bounded Graphic Designer `social_media_static_post` job and deliberately accepts structured intent rather than unrestricted natural language.

## Why structured intent first

A language model may suggest values, but it cannot silently promote suggestions into hard acceptance constraints. The compiler therefore requires explicit, source-resolved fields for:

- contract identity and trusted creation time,
- original request and language,
- immutable approved logo, brand profile and approved copy artifacts,
- canvas width and height,
- certified color profile,
- logo clear space, and
- minimum text contrast.

Missing fields produce `needs_resolution`, a deterministic ordered list of questions, accepted source classes and a canonical resolution digest. No Work Contract is returned while mandatory intent remains unresolved.

## Certified v1 restrictions

The current compiler emits only:

- profession capsule `ergaxiom.profession.graphic-designer`,
- job type `social_media_static_post`,
- Windows isolated-workspace execution,
- denied network access,
- PNG delivery,
- assurance level `E3`, and
- the restricted `sRGB IEC61966-2.1` proof path.

These are capability-profile restrictions, not inferred user preferences. Unsupported color profiles and contrast thresholds below 4.5:1 fail before contract generation.

## Artifact requirements

Each approved input requires:

- a `contract://inputs/` URI,
- an independently identified MIME media type, and
- a lowercase SHA-256 digest.

The compiler never hashes hidden files or invents unresolved artifact identifiers. The orchestration layer must provide trusted upload and hashing results.

## Contract generation

When every mandatory field is resolved, the compiler builds the complete Work Contract with:

- eight hard constraints,
- eight proof obligations,
- diverse contrast validators,
- immutable input and non-overwrite output permissions,
- explicit approval policy,
- no unresolved unknowns, and
- metadata declaring deterministic compilation and no implicit defaults.

The generated contract is immediately compiled through `ergaxiom-contract-runtime` against the supplied real Profession Capsule. The returned contract and capsule digests therefore come from the same canonical runtime used by planning, capability authorization and evidence certification.

## CLI

```bash
cargo run -p ergaxiom-intent-contract-compiler-runtime \
  --bin ergaxiom-contract-compile -- \
  examples/intents/static-social-post.json \
  professions/graphic-designer/profession.json \
  /tmp/compiled-contract.json
```

The CLI exits with code `0` for a compiled contract, `2` when resolution is still required and `1` for invalid or unsupported input.

## Validation commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

These commands exercise the authoritative ownership, deterministic hashing, capsule-binding and unresolved-intent behavior before the compiler can be merged.

## Claim boundary

Version 1 does not interpret unrestricted prose, discover files, read brand rules, select a platform profile or generate timestamps. A future model-assisted interpretation service may propose structured values, but every proposal must retain provenance and pass this deterministic boundary before it can become a Work Contract.
