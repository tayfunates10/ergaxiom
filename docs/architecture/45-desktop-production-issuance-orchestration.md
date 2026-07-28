# Desktop and Backend Production Issuance Orchestration

## Status

This document describes the first bounded orchestration slice of Issue #62. The backend can now bind its existing one-shot desktop approval policy to governed production Capability Token and Acceptance Certificate issuance.

This slice is platform-neutral and proves the authorization and governed-signature composition with an in-memory production signer service used only by tests. It does not yet claim that the Tauri executable loads administrator-provisioned production configuration or communicates with an installed Windows service.

## Existing backend authority remains authoritative

The production path reuses `BackendIssuancePolicy` rather than introducing a parallel approval mechanism. Before any production signer invocation, the backend independently verifies:

- the canonical desktop snapshot digest,
- the backend-issued approval record and approval digest,
- the exact approve or execute command receipt,
- the required desktop control state,
- the Work Contract and compiled-contract digest,
- the Operator Plan identity and digest,
- the trusted profession-capsule digest,
- the exact permission digest,
- the backend-owned executor and optional device identity,
- the selected plan step and operator,
- the single-use capability grant, and
- trusted backend time and bounded authorization expiry.

Capability issuance requires the exact `Approved` state and approve receipt. Attestation issuance requires the exact `Executed` state and execute receipt.

## Authorization is consumed before signing

Each exact issuance intent receives a canonical backend authorization record. The authorization is removed from the pending journal and placed into the consumed journal before the production transport is invoked.

This ordering is deliberate:

1. validate the exact backend state and issuance intent,
2. create the one-shot authorization,
3. consume the authorization,
4. invoke the governed production signer authority, and
5. independently verify the returned production-bound artifact.

If the signer service rejects the request, times out or returns an invalid package, the authorization remains consumed. Repeating the same intent under the same approval fails before a second signer call. This prevents retry-driven signature duplication and ensures signer availability cannot weaken backend replay policy.

## Governed production Capability issuance

`BackendAuthorizedProductionIssuanceAuthority` composes the backend authorization policy with `GovernedProductionCapabilityIssuanceAuthority`.

The caller supplies only a backend-owned `CapabilityTokenDraft`. The governed authority fixes and verifies:

- Capability issuer role,
- `ergaxiom.policy-authority` issuer identity,
- fixed Capability key identity,
- ECDSA P-256 with SHA-256,
- Microsoft Platform Crypto Provider policy,
- the active registry generation,
- the exact public-key digest,
- accepted caller and signer-service identity digests, and
- the current registry revision and digest.

The returned `ProductionSignerBoundCapabilityToken` is a separate production artifact type. Existing direct-Ed25519 and DPAPI signer-bound tokens remain verifiable for backward compatibility but are never relabelled as production artifacts.

## Governed production Attestation issuance

The backend independently reassesses the exact Evidence Bundle before authorizing Attestation issuance. It requires:

- decision status `Accepted`,
- zero failed mandatory obligations,
- zero unknown mandatory obligations,
- exact Evidence Bundle digest in the executed desktop snapshot,
- deterministic Replay Manifest reconstruction, and
- exact Replay Manifest digest in the executed snapshot.

Only then does `GovernedProductionAttestationIssuanceAuthority` invoke the fixed Attestation production identity. The resulting `ProductionSignerBoundAttestationPackage` is independently verified against:

- the exact governed trust snapshot,
- the exact production key registry,
- the Work Contract,
- the Operator Plan,
- the Evidence Bundle,
- the Replay Manifest, and
- the verified assurance level.

## No fallback boundary

The production backend authority owns only governed production Capability and Attestation authorities. It has no reference to:

- DPAPI signer clients,
- direct Ed25519 signing keys,
- software CNG providers,
- in-process production private keys, or
- renderer-selected signer configuration.

A production signer rejection therefore returns a production issuance error. It cannot silently issue an older artifact type or downgrade the provider, algorithm, role, key or generation.

## Renderer boundary

This slice does not add renderer commands. The intended Tauri boundary remains:

- renderer submits only the expected current snapshot digest and backend-issued approval digest,
- backend constructs signer drafts and request identities,
- renderer cannot submit trust-state paths, service paths, provider names, algorithms, roles, issuer IDs, key IDs or generations, and
- only bounded public state and error categories are returned to the UI.

## Permanent validation

The dedicated `Backend production issuance` workflow uses `permissions: contents: read` and runs on Ubuntu 24.04 and Windows Server 2025. It enforces:

- canonical workspace formatting,
- warnings-deny Clippy for all backend issuance targets and features,
- exact approved production Capability issuance,
- exact executed production Attestation issuance,
- independent final attestation verification,
- signer rejection after authorization consumption,
- identical-intent replay rejection without a second signer call, and
- all existing backend authorization attacks.

The test signer uses P-256 keys and the same production service, trust snapshot and registry contracts as the Windows transport boundary. It is not evidence of a physical TPM or installed SCM service.

## Remaining Issue #62 work

The following remains before the desktop product can claim a complete production path:

1. load a fixed administrator-provisioned backend deployment manifest from a protected absolute path,
2. authenticate accepted production trust state and deployment-policy bindings at application startup,
3. bind the installed backend executable path and SHA-256 to the signer caller allowlist,
4. replace the test transport with `ProductionSignerPipeClient`,
5. integrate production issuance into the Tauri approve and execute lifecycle,
6. persist approvals, tokens, receipts, Evidence Bundles, Replay Manifests and certificates as digest-addressed records,
7. verify the persisted state chain during application restart,
8. expose fail-closed production status to the renderer,
9. test service unavailable, restart, recovery and altered-backend-image cases on Windows, and
10. complete a controlled-machine installation and physical-TPM evidence ceremony.

Until those steps are complete, the existing desktop fixture must continue to report that production evidence and an Acceptance Certificate are not loaded.
