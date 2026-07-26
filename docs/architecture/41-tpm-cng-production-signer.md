# TPM/CNG Production Signer, Administrator Provisioning and Authenticated Local Service

## Status

This document defines the bounded TPM/CNG production signer foundation implemented under Issue #60. The code provides a Windows CNG provider contract, a compile-time separated administrator provisioning surface, sealed public-only provisioning evidence, a P-256 signer protocol, caller and signer-service identity binding, an authenticated local named-pipe transport, a fail-closed signer-service authority and purpose-locked Capability Token and Acceptance Certificate issuance runtimes.

The repository does **not** claim that GitHub-hosted Windows runners prove a physical TPM or execute an elevated provisioning ceremony. Keys and receipts without an independently accepted hardware gate remain `UNPROVEN` and cannot become production-eligible.

## Fixed production identities

The production signer accepts only:

- Capability: `ergaxiom.policy-authority` / `capability-key-v1`
- Attestation: `ergaxiom.attestation-authority` / `attestation-key-v1`

Execution, normalization and release identities are rejected by this bounded service.

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

1. derive the deterministic persisted-key name,
2. open an already provisioned key,
3. validate the non-exportable and signing-only properties,
4. export the public ECC blob, and
5. sign an exact 32-byte SHA-256 digest through the live CNG handle.

Key creation, property mutation and finalization compile only when the explicit `provisioning` feature is enabled. The normal workflow separately runs `cargo check --no-default-features` on Linux and Windows to prove that the open-only surface builds without provisioning code.

The existing DPAPI/Ed25519 signer remains available only for development, tests and backward verification of previously issued artifacts. It is not a fallback for the P-256 production path.

## Elevated administrator provisioner

`ergaxiom-windows-production-signer-provisioner` is a separate executable and links the CNG runtime with the `provisioning` feature. It:

- accepts only the Capability or Attestation role,
- requires an elevated Windows process token before accessing CNG provisioning,
- optionally pins an expected public-key digest for idempotent reprovisioning checks,
- refuses to overwrite an existing evidence file,
- writes evidence through a create-new temporary file and same-directory atomic rename, and
- prints only public identifiers and digests.

The command surface does not accept a provider, algorithm, key name, export policy, signature encoding, private material or arbitrary payload. Those values are fixed by the production policy.

Hosted CI compiles and lints this executable on Windows but does not claim to run an elevated UAC ceremony or create a physical TPM key.

## CNG private-key boundary

The provisioner may create or reopen an ECDSA P-256 persisted key through the Microsoft Platform Crypto Provider. New keys receive a zero export policy and signing-only usage before finalization. A newly created handle is deleted if provisioning fails before finalization.

The normal signer reopens the key through the deterministic name and signs via `NCryptSignHash`. Ergaxiom-owned memory receives only the public ECC blob and the signature. No private-key byte buffer, seed, protected seed or exportable key material is produced by these runtimes.

## Provisioning statement and evidence

A successful provisioning ceremony produces a public-only evidence package containing:

- a canonical provisioning receipt,
- the fixed issuer role and identity,
- provider, algorithm and encoding metadata,
- public key and public-key digest,
- export policy and provider implementation flags,
- policy digest and deterministic persisted-key-name digest,
- provisioning time and whether the key was newly created,
- a P-256 key-possession signature over the sealed provisioning statement, and
- a canonical evidence digest.

Independent verification checks the receipt seal, statement-to-receipt bindings, deterministic key-name digest, public-key digest, policy digest, evidence seal and P-256 key-possession signature. Receipt, statement, signature and evidence substitutions fail closed. Secret-shaped fields are rejected.

A valid key-possession signature proves control of the persisted private key corresponding to the public key. It does **not** independently prove that the key is protected by a trustworthy physical TPM. Therefore `verify_contract` may validate an `UNPROVEN` receipt, while `verify_production_eligible` still rejects it until independent hardware evidence promotes the assurance state.

## Hardware assurance

The descriptor distinguishes:

- `PROVEN_HARDWARE_BACKED`
- `UNPROVEN`
- `REJECTED`

Cryptographic P-256 verification, provisioning evidence and key-possession proof can exercise an `UNPROVEN` descriptor, but production eligibility additionally requires `PROVEN_HARDWARE_BACKED`. Provider availability, successful key creation or a valid signature alone cannot upgrade assurance.

A dedicated physical-machine gate may run the opt-in CNG integration test with `ERGAXIOM_TPM_HARDWARE_TEST=1`; hosted CI does not set this variable and cannot silently promote hardware assurance.

## Production protocol

The production protocol is separate from the existing DPAPI/Ed25519 protocol. Its signed material binds:

- fixed role, issuer ID and key ID,
- canonical payload digest,
- production key-policy digest,
- authenticated caller identity digest,
- signer-service instance identity digest,
- exact provider, algorithm and public-key digest, and
- the signer request and envelope digests.

Independent verification rejects provider, algorithm, public-key, export-policy, caller, signer-instance, request, envelope and signature substitutions.

## Public trust snapshot

A verifier does not need private process handles to validate a returned production package. A public trust snapshot pins:

- the fixed production identity,
- the expected public-key digest,
- allowlist revision and digest,
- authenticated caller identity digest, and
- signer-service instance identity digest.

The authorization receipt is independently canonical-hash verified before these values are compared. Altering its authorization time, caller, allowlist or service fields without recomputing the sealed receipt therefore fails even when the remaining package is unchanged.

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

## Purpose-locked Capability Token issuance

The production Capability authority accepts only an unsigned domain draft. It internally:

1. validates token identifiers, bindings, time bounds, usage and nonce,
2. fixes the Capability issuer and key identity,
3. builds the canonical Capability Token payload,
4. derives the request ID from the canonical payload digest,
5. invokes the production signer transport,
6. validates the public trust snapshot and sealed caller authorization receipt, and
7. returns a separate P-256 production-bound token type.

The existing direct-Ed25519 and DPAPI signer-bound token types and verification APIs remain unchanged. Production token authorization independently rechecks the P-256 package before applying contract, plan, executor, device, grant and usage constraints.

## Purpose-locked Acceptance Certificate issuance

The production Attestation authority retains the existing Evidence Runtime gate. Before any signer invocation it:

1. reassesses the exact Evidence Bundle,
2. requires `ACCEPTED` with zero failed or unknown mandatory obligations,
3. rebuilds and seals the Replay Manifest,
4. fixes the Attestation issuer and key identity,
5. derives the request ID from the canonical certificate-payload digest,
6. invokes and verifies the production signer package, and
7. returns a separate P-256 production-bound Acceptance Certificate package.

Independent production verification rechecks the signer trust snapshot, certificate payload, Replay Manifest and—when supplied—the complete Evidence Bundle and recomputed manifest. Existing Ed25519 certificate packages remain backward compatible.

## Validation

Permanent Linux and Windows CI covers:

- formatting and warnings-deny Clippy,
- open-only CNG builds with provisioning disabled,
- compilation and linting of the feature-gated administrator provisioner,
- fixed identity and policy substitution attacks,
- provider/software fallback and export-policy attacks,
- deterministic key naming and CNG handle-only signing contracts,
- provisioning receipt, statement, key-possession signature and evidence substitution attacks,
- the rule that valid `UNPROVEN` provisioning evidence cannot become production-eligible,
- P-256 prehash verification,
- caller, service-instance, receipt-seal and replay substitution attacks,
- named-pipe ACL construction and bounded read-before-impersonation transport,
- a real local Windows named-pipe round trip that derives the connected process identity,
- purpose-locked production Capability Token issuance and authorization, and
- purpose-locked production Acceptance Certificate issuance, Evidence Bundle reassessment and independent manifest verification.

The canonical Linux and Windows provisioning matrix passed formatting, open-only build checks, warnings-deny Clippy and the complete bounded test set. The workflow remains in permanent read-only mode.

## Remaining boundary before Issue #60 can close

The following remain open:

- independently trusted physical-TPM evidence that can promote a key from `UNPROVEN` to `PROVEN_HARDWARE_BACKED`,
- an operational elevated provisioning ceremony on controlled hardware and custody of its evidence,
- algorithm-agile governed key rotation and revocation for P-256 keys,
- deployment of the authenticated production signer as a hardened Windows service, and
- full desktop/backend orchestration and persisted trust-snapshot lifecycle.

Authenticode, trusted timestamps, commercial certificate chains and signed installer upgrade/rollback provenance remain explicitly outside Issue #60 and belong to the following release-provenance gate.
