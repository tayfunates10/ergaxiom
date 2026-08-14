# Profession Learning Laboratory

## Purpose

The Profession Learning Laboratory is the only supported path for turning expert demonstrations into candidate operators. It is intentionally isolated from production execution and from production signing authority. Live user work is not a training channel and cannot mutate an installed production capsule.

This design implements Issue #40 through the Issue #79 delivery boundary while preserving the Graphic Designer certified paths unchanged.

## Trust boundaries

1. Expert demonstrations are accepted only with explicit environment identity, application identity, source provenance, license metadata, declared capability scope, preconditions, decision points, actions and postconditions.
2. Demonstrations run only in `occupational_twin` or `isolated_test`. A demonstration originating from production or live user work is rejected for certification.
3. Candidate synthesis is deterministic and proposal-only. A candidate is digest-bound to its source demonstrations.
4. Candidate signing uses the `candidate-operator` role and declares `production_key_access=false`. Production capsule signing is a different role: `production-capsule`.
5. Unsupported observations remain `UNKNOWN`. Any certification suite reporting an `UNKNOWN` blocks promotion.
6. Capability scope cannot expand beyond the demonstrations' declared scopes. Synthetic negative cases explicitly test scope escalation and production execution attempts.
7. Passing laboratory certification can authorize only a reviewed canary proposal. The laboratory never sets `eligible_for_production=true` and never edits `production_enabled` in the profession catalog.

## Promotion-state matrix

| State | Required evidence | Allowed execution | Catalog production flag | Next transition |
|---|---|---|---|---|
| `draft` | Catalog entry + draft capsule | none / isolated authoring | `false` | explicit candidate synthesis |
| `candidate` | Expert demonstration provenance + deterministic candidate digest | Occupational Twin / isolated test only | `false` | certification |
| `certified` | Regression + property/fuzz + adversarial suites, zero failures, zero UNKNOWN, independent human review | isolated only | `false` | canary |
| `canary` | Certified record + version binding + rollback target + revocation support | governed canary environment only | `false` | separate manual production release |
| `production` | **Outside laboratory authority**: explicit production release decision + production signer + all release gates | production | explicit human/governed change only | versioned upgrade or revocation |
| `revoked` | Revocation reason + affected version + evidence binding | denied | disabled by release authority | rollback |
| `rolled_back` | Previous trusted version + rollback evidence | governed previous version | explicit release authority | new candidate cycle |

There is no automatic edge from `candidate`, `certified` or `canary` to `production`.

## Exact certification evidence

A canary proposal is emitted only when all of the following are true:

- candidate digest recomputes exactly from the candidate body;
- candidate remains `proposal_only=true`;
- candidate signer role is `candidate-operator` and production-key access is false;
- executed environments are a non-empty subset of `occupational_twin` and `isolated_test`;
- no live user work is used for certification;
- `regression`, `property_fuzz` and `adversarial` suites are all present;
- every required suite executes at least one case with `failures=0` and `unknowns=0`;
- human review decision is `approve` and reviewer is independent from the candidate signer;
- canary installation and rollback are required;
- rollback target equals the pre-upgrade version;
- target version is not revoked;
- training provenance includes a source identifier and license for every required input.

Even after all conditions pass, the laboratory returns `eligible_for_production=false`, `automatic_production_allowed=false`, `manual_release_required=true` and `required_next_authority=production-capsule`.

## Schemas and canonical records

Normative learning records:

- `schemas/expert-demonstration.schema.json`
- `schemas/operator-candidate.schema.json`
- `schemas/operator-certification.schema.json`
- `schemas/capsule-lifecycle.schema.json`

The canonical extension demonstration lives in `examples/profession-learning/` and uses a deliberately small Technical Writer profession. The demonstration contains no live user data. Its candidate is deterministic and replayed byte-for-value by tests.

## Second-profession extension proof

`professions/technical-writer/profession.json` proves the extension mechanism without claiming a production profession. Its single job is `plain_text_revision`. The catalog entry is deliberately:

- `certification_level: draft`
- job status `planned`
- `production_enabled: false`

`tools/scaffold_profession.py` now gives every newly scaffolded profession the laboratory certification suite, a 100% minimum pass rate and required zero-failure regression, property/fuzz, adversarial, isolation and rollback tests. It still creates only draft/planned/production-disabled catalog state.

## Revocation and rollback

`revoke_version` is a pure lifecycle operation. Revoking the active canary forces rollback to the pre-declared safe target. If that rollback target is already revoked or missing, the operation fails closed rather than selecting another version heuristically.

A revoked target cannot pass certification for installation. New versions require a new candidate digest and a new certification record.

## Validation

The foundation workflow validates all JSON schemas, existing profession/catalog invariants, the existing Graphic Designer work-contract coverage, scaffold fail-closed behavior, deterministic candidate replay, schema-bound canonical records, negative attack cases, 512 seeded property/fuzz mutations, isolation, human review, no-auto-production, revocation and rollback.

The laboratory contains no function that writes a production capsule, flips a catalog entry to production, accesses production signing material or learns directly from live user work.
