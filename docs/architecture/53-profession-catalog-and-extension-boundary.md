# Profession catalog and extension boundary

## Status

Ergaxiom now has one explicit, digest-bound catalog for installed Profession Capsules. This closes the previous build-time gap where foundation validation loaded only the Graphic Designer capsule from a hard-coded path.

The catalog is an allowlist, not a plugin loader and not an execution grant. A catalog entry records the exact capsule ID, version, confined repository path, canonical SHA-256 digest, lifecycle state, production flag and job certification states.

## Fail-closed inventory

Foundation validation discovers every `professions/*/profession.json` file and requires an exact one-to-one match with `professions/catalog.json`. It rejects:

- an unregistered capsule or a catalog path with no capsule;
- path traversal or symbolic-link traversal;
- duplicate capsule IDs, paths or ID/version bindings;
- a capsule ID, version or canonical digest mismatch;
- a catalog job inventory that differs from the capsule;
- missing operators, unsupported required constraints or lowered assurance policy;
- duplicate operator, validator, job, claim, evidence or capability values;
- a `profession_alpha` entry containing a non-certified job;
- a draft entry advertising a certified job;
- a production-enabled entry below `profession_alpha`; and
- a certified job without at least one schema-valid, capsule-bound example Work Contract.

Every example Work Contract is now discovered and validated. A contract must resolve to one exact catalog capsule ID/version and pass the existing constraint, proof-obligation, validator-independence, evidence-type, output and assurance checks.

The deterministic release manifest also records the catalog's canonical SHA-256 digest, so a release candidate cannot silently change its installed profession inventory while retaining the same release evidence.

## Adding a profession

The scaffold command creates a new capsule without copying or weakening the Graphic Designer capsule:

```bash
python tools/scaffold_profession.py \
  --slug video-editor \
  --display-name "Video Editor" \
  --job-type basic_video_edit
```

The generated entry is always `draft`, its job is `planned`, network access is denied, live learning is disabled and production execution is disabled. The command refuses to overwrite an existing profession and binds the new capsule through its canonical digest.

Promotion remains capability-gated:

1. define typed inputs, outputs, constraints, operators and independent validators;
2. implement deterministic compiler, planner, executor and evidence paths;
3. add schema-valid example Work Contracts and failure maps;
4. add regression, mutation, fuzz and adversarial tests;
5. demonstrate bounded real-application execution without self-verification;
6. reach an independently verified Acceptance Certificate for every advertised certified job; and
7. only then promote the catalog lifecycle and consider a separately governed production enablement.

## Trust boundary

Catalog membership cannot load arbitrary code, widen a Capability Token, bypass a Work Contract, lower a job's assurance minimum or make a planned job certified. Runtime implementations and adapter identities remain separately versioned, permission-scoped and evidence-bound.

The catalog is currently a repository and CI integrity boundary. It is not yet a signed runtime installation catalog, dynamic ABI, marketplace, hot-loading system or Profession Learning Laboratory. Those capabilities must preserve the same digest, permission, verification and rollback boundaries before they can be enabled.
