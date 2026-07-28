# Tauri Production Startup Boundary

## Status

This boundary loads the administrator-provisioned backend production deployment manifest during Tauri startup without granting the renderer filesystem, signer-configuration or signing access.

It progresses Issue #62 after the governed issuance authority and backend deployment manifest gates.

## Fixed installer inputs

The desktop binary accepts two build-time installer constants:

- `ERGAXIOM_BACKEND_PRODUCTION_MANIFEST_PATH`
- `ERGAXIOM_BACKEND_PRODUCTION_MANIFEST_PIN_PATH`

Both values must be absolute paths. They are compiled into the backend binary and cannot be supplied by renderer IPC, command-line arguments or user preferences.

The pin file must be a regular non-symbolic-link file containing exactly one lowercase 64-character SHA-256 digest with no whitespace. The backend performs a bounded stable read and rejects a changed, malformed or substituted pin.

The manifest digest is deliberately stored outside the executable. Embedding the digest inside the executable would create a circular identity dependency because the deployment manifest already binds the final backend executable SHA-256.

## Startup verification

On Windows, startup:

1. reads the fixed external manifest digest pin;
2. resolves the current backend executable path;
3. obtains the trusted local epoch time;
4. loads the pinned `BackendProductionDeploymentManifest`;
5. rehashes and verifies the current backend executable;
6. loads the signer service manifest, governance policy, caller allowlist, deployment policy and accepted trust state;
7. verifies deployment, allowlist, trust-state, registry and active Capability/Attestation key-generation bindings; and
8. retains separate real `ProductionSignerPipeClient` instances for Capability and Attestation issuance.

On unsupported platforms the production boundary remains unavailable. Missing installer configuration is reported as unconfigured. Any malformed or mismatched installed state is reported as rejected.

The normal desktop control shell remains available so the public status can be inspected, but production issuance remains disabled.

## Renderer boundary

The renderer may call only `get_production_signer_status` and receives:

- a bounded phase and public code;
- whether configuration verification succeeded;
- whether backend pipe clients were initialized;
- public deployment, manifest, trust-state and registry digests/revisions; and
- active Capability and Attestation key generations.

The response excludes:

- manifest and executable paths;
- principal SID and session information;
- caller allowlist entries;
- governance keys;
- service process identity and nonce;
- pipe handles;
- signer requests; and
- all private signing material.

## Claim boundary

`configured` means that the installed public configuration and current backend image verified and that real pipe client objects were initialized. It does not claim that the Windows service is currently reachable and it does not enable production issuance.

The next gate must construct the deployed trust snapshots from an authenticated service exchange, route the exact approved Capability request through the installed service and preserve the deployed trust binding. Until that gate passes, `production_issuance_enabled` remains `false` and the existing local deterministic execution cannot claim production Capability or Acceptance Certificate output.
