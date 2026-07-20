# Trust and Verification Model

## Purpose

This document defines what Ergaxiom is allowed to trust, what it must verify, and when it must stop. It is normative for the proof kernel and all profession capsules.

## Trust hierarchy

From strongest to weakest:

1. **Formally checked proof** produced by an approved theorem prover or solver with pinned inputs.
2. **Deterministic independent measurement** from a versioned validator.
3. **Structured application state** obtained through an authenticated API or signed plugin.
4. **Operating-system automation state** such as UI Automation properties.
5. **Visual observation** confirmed by a second state source.
6. **Model interpretation** used only to propose hypotheses, never as final proof.

A weaker source cannot override a contradictory stronger source.

## Threats

### Hidden-state hallucination

The planner assumes a dialog, layer, file, account, or setting exists without observing it.

**Control:** every required state must have a source and freshness timestamp. Unobserved state is `UNKNOWN`.

### Self-verification

The same model or execution path creates an output and declares it correct.

**Control:** acceptance rules call independent validators. Critical checks require implementation diversity.

### Prompt or document injection

Untrusted content attempts to alter goals, permissions, policies, or tool use.

**Control:** content is data, not authority. Only the signed work contract and policy engine can authorize actions.

### Confused deputy

A low-authority skill causes a higher-authority bridge to perform an undeclared action.

**Control:** capability tokens are operation-scoped, resource-scoped, short-lived, and bound to a contract hash.

### Evidence substitution

Evidence from another file, run, or contract is attached to the current job.

**Control:** every evidence record binds the input hashes, output hashes, contract hash, operator-plan hash, environment digest, and run identifier.

### Time-of-check/time-of-use drift

A file or UI state changes after validation but before execution or delivery.

**Control:** immutable copies where possible; otherwise re-hash and revalidate at the execution boundary and before delivery.

### Visual false positive

A screenshot appears correct while the document model or exported artifact is incorrect.

**Control:** visual evidence cannot be the sole proof for structural, numeric, or file-format claims.

### Irreversible side effect

The agent deletes, sends, publishes, purchases, deploys, or modifies production state unexpectedly.

**Control:** irreversible operators require explicit policy permission, a preview, a fresh approval token, and a post-action receipt.

## Proof obligation lifecycle

Each hard constraint must progress through:

1. `DECLARED`
2. `BOUND` to concrete inputs and parameters
3. `EVALUATED` by an approved validator
4. `PASSED`, `FAILED`, or `UNKNOWN`
5. `SEALED` into the evidence bundle

A job can be accepted only when every mandatory obligation is `PASSED` and `SEALED`.

## Acceptance rule

A run is `ACCEPTED` only if all conditions hold:

- the work contract schema is valid,
- there are no unresolved mandatory unknowns,
- every executed operator is allowed by the contract and policy,
- the observed trace conforms to the approved plan or an explicitly approved recovery path,
- every mandatory proof obligation passed,
- all evidence records bind to the same run and artifacts,
- no validator conflict remains unresolved,
- the final artifacts still match their sealed hashes.

Otherwise the run is `REJECTED` or `UNRESOLVED`.

## Assurance levels

- **E0 — Generated:** artifact exists; no correctness claim.
- **E1 — Structurally valid:** format and basic integrity checks passed.
- **E2 — Contract verified:** all measurable hard constraints passed.
- **E3 — Independently verified:** critical constraints passed through an independent validator.
- **E4 — Diversely verified:** critical claims passed through two independent implementations or methods.
- **E5 — Standard attested:** applicable external standards and provenance requirements passed.

Assurance levels are cumulative. A profession capsule may require a minimum level per job type.

## Prohibited claims

Ergaxiom must not state:

- “100% correct” without naming the complete bounded set of verified claims,
- “perfect,” “best,” or “guaranteed to be liked” as objective truth,
- that subjective requirements were mathematically proven unless the user supplied an explicit measurable model,
- that an application action succeeded solely because a click was issued.

Preferred language:

> 38 of 38 declared hard constraints passed. Unresolved mandatory constraints: 0. Assurance level: E4.
