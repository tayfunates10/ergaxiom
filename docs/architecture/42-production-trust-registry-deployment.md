# Production Trust Registry Deployment and Persistence

## Status

The bounded production trust-state lifecycle is implemented in `ergaxiom-windows-production-trust-state-runtime`.

The repository can now authenticate, persist, atomically activate, reload and separately recover a public production trust state that contains the governed P-256 registry, caller allowlist binding and signer-service deployment policy. The accepted trust-state digest is also included in the P-256 signer request binding, so a hardware-signed production package cannot be detached from the state under which it was issued.

This implementation now includes the hardened Windows Service Control Manager host and installer contract. It does **not** claim that a production governance ceremony has occurred, that governance private keys have operational custody controls, that the fixed service has been installed on a controlled production machine, or that a physical TPM has been independently proven.

## Implemented artifacts

A production trust state contains public material only:

- deployment identity,
- monotonically increasing state revision,
- previous accepted state digest,
- complete canonical P-256 registry snapshot,
- registry revision and digest,
- caller-allowlist revision and digest,
- signer-service executable digest,
- signer deployment-policy revision and digest,
- activation and validity times,
- minimum accepted revision,
- recovery-policy identifier,
- governance-policy digest,
- threshold governance signatures,
- canonical body and envelope digests, and
- an independently sealed public trust-state binding.

No CNG private key, seed, password, DPAPI blob or exportable private material is accepted in these artifacts.

## Separate trust-governance authority

Trust-state authorization uses a separate Ed25519 governance policy. Capability and Attestation P-256 keys cannot authorize their own registration, rotation, revocation, service policy or rollback.

The governance policy binds:

- policy identity and revision,
- signature threshold,
- canonical governance-key records,
- public-key digests,
- validity windows,
- active or revoked state, and
- the canonical policy digest.

Duplicate governance identities, public-key reuse, unknown signers, duplicate signatures, expired keys, revoked keys, algorithm substitution and signatures below threshold fail closed.

The repository implements the public policy and verification path. Generation and custody of real governance private keys remain an operational ceremony outside the repository's current evidence.

## Explicit offline bootstrap

The first accepted production state cannot be inferred from an embedded default or environment variable. Bootstrap requires an explicit offline expectation that pins:

- deployment identity,
- exact initial trust-state envelope digest, and
- exact governance-policy digest.

Bootstrap accepts only revision 1 with no previous-state digest. Once a checkpoint exists, bootstrap cannot be repeated.

## Monotonic normal activation

Normal activation requires:

1. the exact same deployment identity,
2. the next state revision to equal the accepted revision plus one,
3. the previous-state digest to equal the accepted state digest,
4. a valid governance threshold,
5. a canonical and digest-sealed P-256 registry snapshot,
6. no registry, allowlist, service-policy or minimum-revision downgrade,
7. exactly one valid active generation for each enabled logical identity, and
8. activation inside the declared validity window.

Stale revisions, skipped revisions, forked previous digests, unsigned states, invalid governance signatures, malformed registry records and downgrade attempts are rejected.

## Accepted checkpoint

The accepted checkpoint independently seals:

- deployment identity,
- accepted state and envelope digests,
- state revision,
- registry revision and digest,
- allowlist revision,
- service-policy revision,
- minimum accepted revision,
- last accepted recovery sequence, and
- checkpoint digest.

A persisted pointer is not trusted merely because it names a state file. On reload, the pointer seal, immutable file seal, envelope signatures, registry snapshot and checkpoint-to-state correspondence are all reverified.

## Atomic filesystem store

`ProductionTrustStateStore` accepts only an explicit absolute root path. There is no production environment-variable or embedded-development fallback.

The store uses:

- immutable digest-named state files under `states/`,
- immutable digest-named recovery files under `recoveries/`,
- one sealed `accepted.json` pointer as the activation point,
- create-new temporary files,
- complete file synchronization before activation,
- bounded file sizes and bounded reads,
- symbolic-link rejection,
- metadata stability checks during reads, and
- an atomic pointer replacement.

On Unix test environments the protected store receives mode `0700`. On Windows the root and child directories receive a protected DACL granting full inherited access only to LocalSystem, Built-in Administrators and the current owner.

Windows pointer activation uses `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` after the immutable state file has been flushed.

A crash or failure before pointer replacement leaves the previously accepted state current. An existing temporary pointer blocks activation rather than causing deletion or unsafe reuse.

## Separate recovery path

Recovery is not normal rollback. A recovery envelope uses a separate signing domain and binds:

- deployment and recovery-policy identity,
- damaged accepted state digest,
- replacement state digest,
- recovery-reason digest,
- monotonically increasing recovery sequence,
- minimum uncompromised revision,
- maximum allowed replacement revision, and
- expiry time.

Recovery rejects expired authorization, replayed recovery sequence, state-digest substitution, replacement below the minimum uncompromised revision and reactivation or mutation of a revoked P-256 generation.

The accepted checkpoint records the last recovery sequence so the same recovery authorization cannot be reused after restart.

## Signer-service startup binding

`TrustBoundProductionSignerService` validates a loaded accepted trust state before serving signing requests. Startup requires:

1. the exact caller-allowlist revision and digest,
2. the exact signer executable digest,
3. the exact service ID,
4. the exact signer deployment-policy revision and digest,
5. an enabled production identity,
6. exactly one active generation for that identity,
7. a backend descriptor for that generation, and
8. exact descriptor-to-registry provider, algorithm, encoding, export-policy, policy-digest and public-key binding.

A backend that silently opens generation 1 when generation 2 is active fails startup.

The startup authority is now hosted by a fixed SCM own-process LocalSystem service runtime with delayed automatic start, restricted privileges, failure actions, preshutdown handling and an administrator/System-only service DACL. The executable and manifest paths are bound before the service reports `SERVICE_RUNNING`. A controlled-machine elevated installation record and operational recovery exercise remain open.

## Cryptographic trust-state binding

`SignerRequestBinding` has a backward-compatible optional `trust_state_binding_digest` field. Existing artifacts without the field continue to use the earlier verification path.

The deployed signer path requires the accepted trust-state binding digest and includes it in:

- the signer request binding digest,
- the signed production envelope, and
- the P-256 hardware signature.

The returned deployed package also exposes the accepted state revision, registry revision/digest, service policy and binding digest. Backend verification rejects a response whose accepted state differs from its own state, even when the P-256 signature is otherwise cryptographically valid.

## Historical verification

Archived authenticated trust states can be supplied explicitly for historical verification. Verification does not fetch mutable network trust.

Archived states cannot authorize new issuance through the deployed service. Revoked P-256 generations continue to fail according to the registry's fail-closed revocation semantics.

## Attack coverage

Permanent tests cover:

- missing or insufficient governance signatures,
- governance algorithm, key and digest substitution,
- stale, duplicated and skipped state revisions,
- forked previous-state digests,
- registry/body/envelope/checkpoint digest mutation,
- active-generation ambiguity,
- allowlist and service-policy downgrade,
- explicit-bootstrap mismatch and repeated bootstrap,
- recovery expiry, replay and state substitution,
- recovery below the minimum uncompromised revision,
- revoked-key reactivation,
- relative-path and symbolic-link rejection,
- partial activation and stale temporary pointer behavior,
- immutable state-file conflict,
- backend/registry generation substitution,
- stale backend versus signer state,
- signed trust-state binding substitution, and
- forbidden secret-shaped fields.

The permanent workflow runs with `permissions: contents: read`. Ubuntu and Windows 2025 pass formatting, open-only CNG compilation, warnings-deny Clippy and the complete trust-state/signer attack set.

## Hardware claim boundary

Persistence and governance signatures authenticate public trust state. They do not prove physical TPM assurance.

A production registry still accepts only `PROVEN_HARDWARE_BACKED` descriptors, but hosted CI does not create that proof. A controlled-hardware evidence gate and reviewed promotion policy remain required.

## Implemented exit boundary

The repository now implements:

- canonical trust-state schemas and digests,
- a separate threshold governance-verification path,
- explicit offline bootstrap,
- exact monotonic activation,
- guarded atomic persistence,
- independently sealed accepted checkpoints,
- separately authorized recovery,
- signer startup binding to registry, allowlist, executable and service policy,
- backend rejection of trust-state divergence, and
- Linux and real Windows persistence/service attack tests.

## Remaining operational boundary before Issue #60 can close

- independently trusted physical-TPM evidence and promotion policy,
- controlled-hardware elevated provisioning with retained reviewed evidence,
- offline creation, custody, rotation and recovery procedures for governance private keys,
- secure packaging and administrator-controlled distribution of signed trust-state updates,
- elevated installation and validation of the fixed hardened service on controlled production hardware,
- machine recovery and backup procedures exercised on controlled hardware, and
- full desktop/backend orchestration through the installed service.

## Explicitly out of scope

- Authenticode and commercial certificate chains,
- trusted timestamp services,
- signed installer update/rollback provenance,
- remote HSM/KMS operation,
- renderer-accessible trust mutation, and
- profession or adapter-specific issuance commands.
