# Proof Kernel v1

## Purpose

The Proof Kernel is Ergaxiom's deterministic acceptance boundary. It does not plan work, operate applications, judge visual quality, or call a language model. Its only responsibility is deciding whether a sealed Work Contract has enough admissible evidence to be accepted.

## Non-negotiable invariants

1. `UNKNOWN` is distinct from `FALSE` and can never be silently coerced to success.
2. Every mandatory proof obligation must reach `SATISFIED` before acceptance.
3. A mandatory `FALSE` result rejects the work.
4. Conflicting `TRUE` and `FALSE` validator results invalidate the obligation and reject the work.
5. Evidence is bound to one sealed contract digest.
6. Evidence cannot be replayed across contracts.
7. An independent obligation cannot be satisfied by executor-only evidence.
8. A diverse obligation requires matching `TRUE` results from at least two distinct independent validators.
9. The achieved assurance level must be at least the contract minimum.
10. Unsafe policies that allow unresolved unknowns, missing mandatory proofs, or validator conflicts are rejected at construction time.

## Decision states

### `ACCEPTED`

All mandatory obligations are satisfied, no mandatory unknown remains, the assurance threshold is met, and no conflicting evidence exists.

### `BLOCKED`

The job is incomplete but has not been disproven. Examples include missing evidence, an unresolved contract question, insufficient validator independence, or an assurance level below the required minimum.

### `REJECTED`

At least one mandatory claim is false or has contradictory validator results.

## Obligation states

- `PENDING`: no evidence has been submitted.
- `INDETERMINATE`: evidence exists but cannot establish the claim at the required independence level.
- `SATISFIED`: admissible evidence establishes the claim.
- `FAILED`: admissible evidence establishes that the claim is false.
- `INVALIDATED`: validators contradict each other.

## Contract binding

Work Contracts and Profession Capsules are normalized as canonical JSON and hashed with SHA-256. Evidence records carry the sealed contract digest. The kernel rejects any record whose digest differs from the active contract seal.

Canonical hashing sorts JSON object keys recursively while preserving array order. This makes semantically equivalent object-key orderings produce the same digest while still detecting material contract changes.

## Trust boundary

The following components are outside the trusted Proof Kernel:

- language and vision models
- planners
- desktop automation
- application plugins
- executor-reported success messages
- screenshots without an approved validator

Those components may produce evidence candidates, but they cannot produce an acceptance decision directly.

## Current implementation scope

Proof Kernel v1 contains:

- Strong Kleene three-valued logic
- canonical JSON hashing
- immutable contract and capsule seals
- evidence replay protection
- proof-obligation accumulation
- validator independence enforcement
- deterministic acceptance decisions
- invariant-focused Rust tests

Cryptographic signatures, transparency logs, revocation, timestamp authority integration, and external proof-system adapters are planned for later phases.
