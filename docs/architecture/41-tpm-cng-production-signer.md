# TPM/CNG Production Signer, Governed Key Generations and Authenticated Local Service

## Status

This document defines the bounded TPM/CNG production signer foundation implemented under Issue #60. The code provides a Windows CNG provider contract, a compile-time separated administrator provisioning surface, generation-bound public-only provisioning evidence, a governed P-256 rotation and revocation registry, caller and signer-service identity binding, an authenticated local named-pipe transport, a fail-closed signer-service authority and purpose-locked Capability Token and Acceptance Certificate issuance runtimes.

The repository does **not** claim that GitHub-hosted Windows runners prove a physical TPM or execute an elevated provisioning ceremony. Keys and receipts without an independently accepted hardware gate remain `UNPROVEN` and cannot become production-eligible.

## Fixed logical production identities

The production signer accepts only:

- Capability: `ergaxiom.policy-authority` / `capability-key-v1`
- Attestation: `ergaxiom.attestation-authority` / `attestation-key-v1`

Execution, normalization and release identities are rejected by this bounded service. Rotation does not change these logical issuer identities. Distinct physical P-256 keys are represented by monotonically increasing governed generations.

## Key policy

An eligible production key must match all of the following:

- provider: `Microsoft Platform Crypto Provider`
- algorithm: ECDSA P-256 with SHA-256
- public-key encoding: uncompressed SEC1 P-256
- signature encoding: fixed-width IEEE P1363 `r || s`
- export policy: non-exportable
- usage policy: signing only
- hardware requirement: mandatory

The provider probe requires the CNG hardware implementation flag and rejects a reported software implementation. There is no software-provider or DPAPI fallback in the production provider.

## Compile-time provisioning separation

The normal CNG runtime has no default features. In its normal signer build it can only:

1. derive the deterministic generation-aware persisted-key name,
2. open an already provisioned key,
3. validate the non-exportable and signing-only properties,
4. export the public ECC blob, and
5. sign an exact 32-byte SHA-256 digest through the live CNG handle.

Key creation, property mutation and finalization compile only when the explicit `provisioning` feature is enabled. The permanent workflow separately runs `cargo check --no-default-features` on Linux and Windows to prove that the open-only surface builds without provisioning code.

The existing DPAPI/Ed25519 signer remains available only for development, tests and backward verification of previously issued artifacts. It is not a fallback for the P-256 production path.

## Elevated administrator provisioner

`ergaxiom-windows-production-signer-provisioner` is a separate executable and links the CNG runtime with the `provisioning` feature. It:

- accepts only the Capability or Attestation role,
- accepts a positive governed generation, defaulting to generation 1,
- requires an elevated Windows process token before accessing CNG provisioning,
- optionally pins an expected public-key digest for idempotent reprovisioning checks,
- refuses to overwrite an existing evidence file,
- writes evidence through a create-new temporary file and same-directory atomic rename, and
- prints only public identifiers and digests.

The command surface does not accept a provider, algorithm, raw key name, export policy, signature encoding, private material or arbitrary payload. Those values are fixed by the production policy and canonical generation naming rule.

Hosted CI compiles and lints this executable on Windows but does not claim to run an elevated UAC ceremony or create a physical TPM key.

## Generation-aware CNG key names

Generation 1 preserves the original persisted-key name exactly, maintaining compatibility with the first bounded signer foundation. Generation 2 and later use a deterministic fixed-width suffix such as:

`Ergaxiom.Production.<identity-digest>.g00000000000000000002`

The provider round-trips the generation from the canonical name and rejects zero, shortened, malformed, non-canonical or identity-substituted names. A later generation therefore cannot silently reopen generation 1 or another issuer's key.

## CNG private-key boundary

The provisioner may create or reopen an ECDSA P-256 persisted key through the Microsoft Platform Crypto Provider. New keys receive a zero export policy and signing-only usage before finalization. A newly created handle is deleted if provisioning fails before finalization.

The normal signer reopens the exact generation-specific key and signs via `NCryptSignHash`. Ergaxiom-owned memory receives only the public ECC blob and the signature. No private-key byte buffer, seed, protected seed or exportable key material is produced by these runtimes.

## Provisioning statement and evidence

A successful provisioning ceremony produces a public-only evidence package containing:

- a canonical provisioning receipt,
- the fixed issuer role and logical identity,
- the governed key generation,
- provider, algorithm and encoding metadata,
- public key and public-key digest,
- export policy and provider implementation flags,
- policy digest and deterministic generation-specific persisted-key-name digest,
- provisioning time and whether the key was newly created,
- a P-256 key-possession signature over the sealed provisioning statement, and
- a canonical evidence digest.

Independent verification checks the receipt seal, statement-to-receipt bindings, generation-specific key-name digest, public-key digest, policy digest, evidence seal and P-256 key-possession signature. Generation, receipt, statement, signature and evidence substitutions fail closed. Secret-shaped fields are rejected.

Evidence documents created before the generation field existed are interpreted as generation 1 during verification. New evidence explicitly seals the generation. This preserves the original bounded artifact shape while preventing a generation-2 ceremony from being relabeled as generation 1 or 3.

A valid key-possession signature proves control of the persisted private key corresponding to the public key. It does **not** independently prove that the key is protected by a trustworthy physical TPM. Therefore `verify_contract` may validate an `UNPROVEN` receipt, while `verify_production_eligible` still rejects it until independent hardware evidence promotes the assurance state.

## Hardware assurance

The descriptor distinguishes:

- `PROVEN_HARDWARE_BACKED`
- `UNPROVEN`
- `REJECTED`

Cryptographic P-256 verification, provisioning evidence and key-possession proof can exercise an `UNPROVEN` descriptor, but production eligibility additionally requires `PROVEN_HARDWARE_BACKED`. Provider availability, successful key creation or a valid signature alone cannot upgrade assurance.

A dedicated physical-machine gate may run the opt-in CNG integration test with `ERGAXIOM_TPM_HARDWARE_TEST=1`; hosted CI does not set this variable and cannot silently promote hardware assurance.

## Governed P-256 key generations

`ProductionKeyRegistry` is a canonical public registry for Capability and Attestation P-256 verification keys. Each record binds:

- fixed logical role, issuer ID and key ID,
- positive generation,
- exact public key and public-key digest,
- provider, algorithm, encoding and export-policy metadata,
- hardware-assurance state and production-policy digest,
- validity window,
- `ACTIVE`, `RETIRED` or `REVOKED` status,
- optional successor generation,
- retirement or revocation time,
- revocation-reason digest, and
- canonical record digest.

Registry mutations are guarded by both the expected previous revision and exact previous registry digest. The registry rejects stale writes, duplicate generations, reused public-key material, role confusion, identity substitution and malformed public-key records.

Only `PROVEN_HARDWARE_BACKED` descriptors may enter the production registry. An `UNPROVEN` hosted-runner descriptor cannot be inserted merely because key possession or a CNG call succeeded.

## Rotation and revocation semantics

Initial registration creates generation 1 as `ACTIVE`. A guarded rotation:

1. requires the exact current generation, revision and registry digest,
2. validates a distinct successor public key,
3. retires the previous generation at the declared retirement boundary,
4. records the successor generation, and
5. activates the next generation at its declared not-before time.

Historical verification may resolve a `RETIRED` generation only inside its sealed validity interval. New governed issuance requires the selected generation to be `ACTIVE` and valid at the artifact's issuance time **before** the hardware signer is invoked.

Revocation is one-way. A revoked generation is rejected even for an artifact whose signature time predates the revocation mutation. This deliberately favors fail-closed emergency response over historical acceptance after a key has been declared compromised.

Every add, rotate and revoke operation emits a canonical mutation receipt binding the action, identity, generation, previous generation, previous registry digest, new revision, new registry digest and effective time.

## Production protocol

The production protocol is separate from the existing DPAPI/Ed25519 protocol. Its signed material binds:

- fixed role, issuer ID and logical key ID,
- canonical payload digest,
- production key-policy digest,
- authenticated caller identity digest,
- signer-service instance identity digest,
- exact provider, algorithm and public-key digest, and
- the signer request and envelope digests.

Independent verification rejects provider, algorithm, public-key, export-policy, caller, signer-instance, request, envelope and signature substitutions.

## Governed public trust snapshot

The original public signer snapshot remains available for backward verification. Governed production issuance additionally binds that signer snapshot to a `ProductionKeyTrustBinding` containing:

- fixed production identity,
- governed generation,
- public-key digest,
- canonical key-record digest,
- registry revision, and
- registry digest.

A verifier does not need private process handles. The combined governed snapshot also pins the allowlist revision and digest, authenticated caller identity digest and signer-service instance identity digest.

The caller authorization receipt is independently canonical-hash verified before these values are compared. Altering its authorization time, caller, allowlist or service fields without recomputing the sealed receipt therefore fails even when the remaining package is unchanged.

Any registry mutation makes an older trust snapshot stale because its revision and digest no longer match. A fresh snapshot must be produced from the accepted registry state before new issuance can continue.

## Caller identity

The signer derives caller identity from the connected named-pipe client rather than accepting identity fields from the request. The Windows boundary measures:

- client process ID,
- process creation time,
- Windows principal SID,
- session ID,
- full executable path, and
- stable executable SHA-256.

The executable is size-bounded and its metadata is checked before and after hashing. Reused PIDs, altered images and changed process identities fail closed.

## Signer-service identity

Every authorization is also bound to:

- fixed service ID,
- signer process ID and creation time,
- signer executable SHA-256,
- service start time, and
- a per-instance nonce.

Restarting or substituting the signer service changes the signed request-binding digest.

## Allowlist and replay order

The caller allowlist is canonical, revisioned and digest-sealed. Authorization requires one exact SID, optional session, executable path and executable digest match.

The service consumes caller authorization and request replay state **before** invoking the hardware backend. A backend or signing failure therefore cannot make the same request usable again.

## Named-pipe transport

The production transport uses one fixed local message-mode named pipe with:

- first-instance-only creation,
- remote-client rejection,
- bounded request and response sizes,
- explicit SDDL rather than the process default DACL,
- full access for LocalSystem and Built-in Administrators, and
- individually enumerated client rights that omit generic-write pipe-creation authority.

Windows permits named-pipe client impersonation only after data has been read from the pipe. The server therefore reads one bounded raw message first, derives the caller identity from the still-connected pipe handle, and only then decodes JSON or performs authorization. Caller identity is unavailable before this bounded read, and malformed input is never authorized merely because bytes were read.

## Governed purpose-locked Capability Token issuance

The governed Capability authority accepts only an unsigned domain draft. It internally:

1. validates token identifiers, bindings, time bounds, usage and nonce,
2. fixes the Capability issuer and logical key identity,
3. verifies the exact registry revision, digest, generation and key-record digest,
4. requires the governed generation to be `ACTIVE` at issuance time before signer invocation,
5. builds the canonical Capability Token payload,
6. derives the request ID from the canonical payload digest,
7. invokes the production signer transport,
8. validates the governed signer snapshot and sealed caller authorization receipt, and
9. returns a separate P-256 production-bound token type.

Governed authorization independently rechecks the registry-bound P-256 package before applying contract, plan, executor, device, grant and usage constraints. The existing direct-Ed25519, DPAPI signer-bound and fixed-snapshot P-256 APIs remain available for backward verification.

## Governed purpose-locked Acceptance Certificate issuance

The governed Attestation authority retains the existing Evidence Runtime gate. Before signer invocation it:

1. reassesses the exact Evidence Bundle,
2. requires `ACCEPTED` with zero failed or unknown mandatory obligations,
3. rebuilds and seals the Replay Manifest,
4. fixes the Attestation issuer and logical key identity,
5. verifies the exact registry revision, digest, generation and key-record digest,
6. requires the governed generation to be `ACTIVE` at issuance time,
7. derives the request ID from the canonical certificate-payload digest,
8. invokes and verifies the production signer package, and
9. returns a separate P-256 production-bound Acceptance Certificate package.

Independent governed verification rechecks the registry binding, signer trust, certificate payload, Replay Manifest and—when supplied—the complete Evidence Bundle and recomputed manifest. Existing Ed25519, DPAPI and fixed-snapshot P-256 certificate packages remain backward compatible.

## Validation

The permanent read-only Linux and Windows matrix covers:

- formatting and warnings-deny Clippy,
- open-only CNG builds with provisioning disabled,
- compilation and linting of the feature-gated administrator provisioner,
- generation-1 key-name compatibility and canonical later-generation naming,
- malformed, zero and identity-substituted generation-name rejection,
- generation-bound provisioning receipt, statement, key-possession signature and evidence attacks,
- guarded initial registration, rotation and revocation,
- stale registry revision and digest rejection,
- public-key reuse, role, identity, generation and record-digest substitution attacks,
- `UNPROVEN` registry insertion and production-eligibility rejection,
- active-only pre-signer issuance enforcement,
- governed Capability Token issuance and authorization,
- governed Acceptance Certificate issuance, Evidence Bundle reassessment and independent manifest verification,
- provider/software fallback and export-policy attacks,
- P-256 prehash verification,
- caller, service-instance, receipt-seal and replay substitution attacks,
- named-pipe ACL construction and bounded read-before-impersonation transport, and
- a real local Windows named-pipe round trip that derives the connected process identity.

The canonical Ubuntu and Windows matrix passed formatting, open-only build checks, warnings-deny Clippy and the complete governed test set. The workflow remains in permanent `contents: read` mode.

## Remaining boundary before Issue #60 can close

The following remain open:

- independently trusted physical-TPM evidence that can promote a key from `UNPROVEN` to `PROVEN_HARDWARE_BACKED`,
- an operational elevated provisioning ceremony on controlled hardware and custody of its evidence,
- persistent, signed and securely distributed registry/trust-snapshot storage and recovery,
- deployment of the authenticated production signer as a hardened Windows service, and
- full desktop/backend orchestration through the deployed service.

Authenticode, trusted timestamps, commercial certificate chains and signed installer upgrade/rollback provenance remain explicitly outside Issue #60 and belong to the following release-provenance gate.
