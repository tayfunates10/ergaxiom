# Key Governance and Deterministic Release Evidence

## Scope

This gate introduces a bounded public-verification and release-evidence layer. It does not load, persist or expose production private keys and does not claim that a Windows executable or installer is signed.

## Role-separated trust registry

`ergaxiom-key-governance-runtime` owns one deterministic registry for these issuer roles:

- capability authorization;
- execution evidence;
- normalization evidence;
- acceptance attestation;
- release signing.

Each Ed25519 public key is bound to one role, issuer ID, key ID and validity interval. Reusing the same public key under another identity or role is rejected. Registry mutations increment a monotonic revision, bind the previous registry digest and produce a canonical mutation receipt.

The registry supports:

- active keys;
- retired keys with a bounded historical verification interval;
- revoked keys that fail verification regardless of the signature creation time;
- guarded insertion, rotation and revocation against the exact prior revision and registry digest;
- deterministic registry reproduction from the same ordered mutation sequence.

A stale revision, altered prior digest, role mismatch, invalid interval, duplicated identity, public-key reuse or revoked key fails closed.

## Governed verification boundary

`ergaxiom-governed-verification-runtime` is the production-shaped entry point for governed verification while preserving compatibility with the existing capability and attestation runtimes.

For a Capability Token it:

1. decodes the signed token;
2. verifies supported Ed25519 metadata;
3. resolves the exact capability-role key at the signed issue time;
4. rejects revoked, not-yet-valid, expired or cross-role keys;
5. verifies the canonical payload signature independently;
6. only then delegates to the existing contract, capsule, plan, step, executor, device, grant and usage-limit authorizer.

For an Acceptance Certificate it:

1. resolves the exact attestation-role key at the certified issue time;
2. rejects revoked, not-yet-valid, expired or cross-role keys;
3. constructs a bounded compatibility verifier using the governed public material;
4. delegates to the existing certificate signature, replay-manifest and Evidence Bundle reassessment logic.

Revocation is intentionally fail-closed: a certificate or token signed before the revocation event is no longer accepted by the current registry. Historical audit systems that need a past trust view must retain and explicitly select a prior signed registry snapshot; the current runtime does not silently downgrade to one.

## Renderer and process boundary

The registry contains public verification material only. The Tauri renderer receives no private key, filesystem, shell, unrestricted process or secret-use capability from this gate. Adapters and child processes cannot use this registry to issue signatures.

Private-key use will require a later Windows-only signer service with DPAPI or TPM-backed non-exportable key protection and a separately authorized IPC protocol.

## Deterministic release evidence

`tools/release/generate_release_evidence.py` produces three artifacts from immutable inputs:

- an SPDX 2.3 JSON dependency inventory derived from `Cargo.lock` and the desktop `package-lock.json`;
- a canonical release manifest binding the source commit, lockfiles, toolchain versions and artifact bytes;
- a sorted `SHA256SUMS` file for the candidate and evidence files.

The generator rejects malformed source identities, missing lockfiles, duplicate artifact basenames and absent artifacts. Two runs over the same source, lockfiles, toolchain strings and artifact bytes must be byte-identical.

## Release eligibility

An unsigned candidate is always emitted with:

```text
release_eligible: false
```

and these blocking reasons:

- `AUTHENTICODE_NOT_VERIFIED`;
- `HARDWARE_BACKED_PRIVATE_KEY_NOT_VERIFIED`;
- `INSTALLER_PROVENANCE_NOT_VERIFIED`.

A checksum, successful build, artifact upload or deterministic manifest is not a code-signing proof. No current workflow may promote this candidate to a production release.

## Permanent CI

Permanent CI must:

- format, lint and test key governance and governed verification runtimes;
- attack-test role confusion, public-key reuse, stale registry updates, rotation windows and revocation;
- prove that real Capability Token and Acceptance Certificate signatures fail after revocation;
- reproduce SPDX, manifest and checksum output twice and compare the bytes;
- compile the real Windows Tauri executable;
- bind the executable to release evidence while retaining `release_eligible: false`;
- upload the unsigned candidate and evidence under names that cannot be confused with a signed release.

## Remaining Issue #39 work

This gate does not satisfy the complete Windows release-security issue. The remaining production gates include:

- DPAPI or TPM-backed non-exportable private keys;
- isolated signer service and authenticated IPC;
- separate production issuer credentials for every role;
- Authenticode signing for the host, desktop app, adapters and installer;
- trusted timestamping and certificate-chain verification;
- signed registry distribution and rollback protection;
- signed installer upgrade, downgrade and rollback attack tests;
- reproducible build comparison against signed release artifacts.
