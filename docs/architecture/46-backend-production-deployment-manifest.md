# Backend Production Deployment Manifest

## Status

This document defines the administrator-provisioned configuration gate between the Tauri/backend process and the installed `ErgaxiomProductionSigner` service.

The manifest is public configuration only. It contains no private key material and does not grant the renderer an issuance API.

## Threat model

Production execution must remain disabled when any of the following changes without an administrator-approved deployment update:

- the backend executable path or SHA-256;
- the signer service manifest or signer executable;
- the signer caller allowlist revision or digest;
- the signer deployment policy revision or digest;
- the accepted production trust-state revision or binding;
- the production key registry revision or digest;
- the active Capability or Attestation key generation.

A self-computed JSON digest is not treated as sufficient authorization. The application must load the file with an installer-controlled expected manifest digest. Recomputing the digest after modifying the file therefore does not satisfy the external pin.

## Manifest bindings

`BackendProductionDeploymentManifest` binds:

- deployment and backend identifiers;
- the exact allowlisted caller identifier, principal SID and optional session;
- the exact backend executable absolute path and SHA-256;
- the exact signer service manifest absolute path and digest;
- the signer service executable SHA-256;
- caller allowlist revision and digest;
- deployment policy revision and digest;
- accepted trust-state revision, minimum accepted revision and binding digest;
- registry revision and digest;
- purpose-locked Capability and Attestation key trust bindings.

Capability and Attestation identities are fixed by the production signer runtime. Their public keys must be distinct and their trust bindings must refer to the same accepted registry snapshot.

## Provisioning

An administrator provisions the manifest only after `LoadedProductionSignerHostConfig` independently validates:

1. the signer service manifest seal and absolute paths;
2. the signer executable digest;
3. the trust-governance policy;
4. the caller allowlist;
5. the deployment policy;
6. the accepted trust checkpoint and state;
7. the deployment, executable, allowlist and policy bindings;
8. active governed Capability and Attestation generations.

The backend caller must appear exactly once in the allowlist and its path and SHA-256 must match the executable being provisioned.

## Startup loading

Production startup uses `load_pinned` with four backend-owned values:

- the fixed protected manifest path;
- the installer-pinned manifest digest;
- the current backend executable path;
- trusted current time.

The loader rejects relative paths, symbolic-link files, unstable reads, oversized files, executable substitution, stale trust state, stale allowlists, stale deployment policy and key-generation substitution.

After the pin is validated, the complete signer host configuration is loaded again from disk and compared with every manifest binding. No renderer-provided path, digest, role, key, provider or algorithm is accepted.

## Failure behavior

Any failure leaves production issuance unavailable. The backend must not fall back to DPAPI, direct Ed25519, software CNG, an in-process private key or development signer state.

Public UI status may distinguish configuration unavailable, signer configuration rejected, trust state rejected and backend image rejected, but it must not expose protected paths or secret-shaped configuration.

## Next gate

The next bounded slice will use this loaded deployment object to initialize the real `ProductionSignerPipeClient`, then persist approval, Capability, receipts, Evidence Bundle, Replay Manifest and Acceptance Certificate in a digest-addressed restart-verifiable state chain.
