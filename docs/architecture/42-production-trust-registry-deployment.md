# Production Trust Registry Deployment Gate

## Status

This document defines the next bounded gate after governed P-256 rotation and revocation. It is intentionally a deployment and persistence boundary, not another in-memory registry model.

The current repository can canonically add, rotate, retire and revoke P-256 generations and can bind Capability Token and Acceptance Certificate verification to an exact registry revision and digest. It does not yet persist, authenticate, distribute, recover or atomically activate that registry across installed production components.

## Goal

Provide one fail-closed lifecycle for production trust state so that the provisioner, signer service, backend issuance authority and independent verifier consume the same authenticated registry snapshot and cannot silently downgrade, fork or roll back it.

## Required artifacts

A deployed trust state will contain only public material:

- schema version,
- monotonically increasing registry revision,
- canonical registry digest,
- complete governed P-256 key records,
- accepted caller-allowlist revision and digest,
- accepted signer-service executable digest and service policy digest,
- previous accepted state digest,
- activation time,
- minimum accepted revision,
- recovery policy identifier,
- trust-state signature metadata, and
- canonical trust-state envelope digest.

No CNG private key, seed, password, DPAPI blob or exportable private material may appear in these artifacts.

## Trust-state authority

Trust-state updates must be signed by a cryptographically separate governance authority. The Capability and Attestation signing keys must not be able to authorize their own registry entry, rotation, revocation or rollback.

The first production trust root must be established by an explicit offline bootstrap ceremony. Later updates must chain to the previously accepted state and must satisfy the configured governance threshold before activation.

## Persistence boundary

The signer and backend must load trust state from an administrator-controlled location with:

- restrictive filesystem ACLs,
- create-new temporary files,
- complete file synchronization before rename,
- same-volume atomic replacement,
- independently persisted accepted revision and digest,
- no renderer-writable path,
- no environment-variable replacement in production mode, and
- no silent fallback to embedded development trust.

A crash before atomic activation must leave the previously accepted state usable. A crash after activation must not permit the previous state to become current again unless a separately authorized recovery artifact explicitly allows it.

## Monotonic activation

Normal activation must reject:

- revision zero,
- a revision lower than or equal to the accepted revision,
- a previous-state digest that does not match the accepted state,
- an invalid governance signature,
- an unknown governance key,
- an expired or revoked governance key,
- registry digest mismatch,
- malformed key records,
- an active P-256 record without proven hardware assurance,
- multiple active generations for one logical identity at one issuance time,
- an allowlist or service-policy downgrade, and
- activation outside the declared validity interval.

## Recovery

Recovery is not ordinary rollback. It requires a distinct signed recovery artifact that binds:

- the damaged or unavailable state digest,
- the replacement state digest,
- the recovery reason digest,
- a recovery sequence number,
- the maximum permitted revision transition,
- the affected machine or deployment identity, and
- an expiry time.

A recovery artifact must not reactivate a revoked key or reduce the minimum accepted revision below the last uncompromised checkpoint.

## Signer-service startup

The hardened signer service must fail startup unless it can:

1. authenticate the persisted trust-state envelope,
2. verify the monotonic activation record,
3. resolve exactly one active generation for each enabled signing role,
4. open the corresponding generation-specific CNG key,
5. match its public-key digest and policy digest to the active registry record,
6. match its executable and service-policy identity to the trust state, and
7. bind the loaded trust-state digest into its per-instance identity.

Every returned production package must expose the loaded trust-state revision and digest through its public trust binding.

## Backend and verifier behavior

The backend issuance authority must reject a signer response whose trust-state revision or digest differs from its own accepted state. Independent verification must use an explicitly supplied accepted trust state and must not fetch mutable network trust during verification.

Historical artifacts may be verified against archived authenticated trust states, subject to revocation semantics. An archived state cannot be used for new issuance.

## Attack coverage

Permanent tests must cover:

- unsigned trust-state files,
- stale and skipped revisions,
- forked previous-state digests,
- registry/body digest mismatch,
- governance-role confusion,
- compromised signer key attempting self-authorization,
- active-generation ambiguity,
- revoked-key reactivation,
- allowlist and service-policy downgrade,
- partial write and crash before rename,
- replacement after file verification but before open,
- renderer-controlled path substitution,
- environment-variable downgrade,
- stale backend versus signer state,
- stale verifier state,
- unauthorized recovery,
- replayed recovery artifact, and
- recovery below the minimum uncompromised revision.

## Hardware claim boundary

This gate persists and authenticates public governance state. It does not by itself prove physical TPM assurance. A registry entry may become production-active only after the separate controlled-hardware evidence gate has accepted the key as `PROVEN_HARDWARE_BACKED`.

## Exit criteria

This gate is complete only when:

- trust-state schemas and canonical digests are implemented,
- a separate governance signature and verification path exists,
- guarded atomic persistence and monotonic activation are implemented,
- signer startup binds the accepted trust state to its service identity,
- backend issuance and independent verification reject state divergence,
- recovery is separately authorized and attack-tested,
- Linux platform-neutral and real Windows persistence/service tests pass, and
- no production path silently falls back to development or embedded trust.

## Explicitly out of scope

- Authenticode and commercial certificate chains,
- trusted timestamp services,
- signed installer update/rollback provenance,
- remote HSM/KMS operation,
- renderer-accessible trust mutation, and
- profession or adapter-specific issuance commands.
