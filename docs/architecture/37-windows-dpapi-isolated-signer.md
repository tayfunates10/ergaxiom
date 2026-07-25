# Windows DPAPI Isolated Signer Boundary

## Scope

This gate removes persisted Ed25519 private seed bytes from the Tauri renderer, adapters and ordinary desktop runtime. A dedicated Windows signer executable owns key generation, DPAPI protection, unprotection and signing.

The package implements Windows DPAPI `CurrentUser` protection and process isolation. It does not claim TPM-backed non-exportability, protection from arbitrary malicious code already running as the same Windows user, Authenticode, a commercial code-signing certificate, trusted timestamping or signed installer provenance.

## Components

### Platform-neutral protocol

`ergaxiom-windows-signer-protocol-runtime` defines the only accepted request and response shapes.

Accepted operations are:

- initialize one role-bound key identity;
- read its public verification key;
- sign one lowercase SHA-256 digest.

A signing request is converted into a canonical envelope containing:

- protocol schema and signing domain;
- request ID;
- issuer role;
- issuer ID;
- key ID;
- digest algorithm;
- exact digest.

The Ed25519 signature covers the entire envelope. Changing any field invalidates independent verification. Arbitrary message bytes, alternate algorithms, path-shaped identifiers and digest fields on non-signing operations fail closed.

The response enum intentionally carries the complete canonical envelope inline. The executable handles exactly one bounded response and exits, so the larger success variant is retained to avoid changing the public JSON schema or introducing nullable indirection across the trust boundary.

### Backend process client

`ergaxiom-windows-signer-client-runtime` launches an exact absolute executable path without a shell and communicates through one inherited stdin/stdout exchange. The client:

- validates the request before process launch;
- supplies no arbitrary command arguments in production mode;
- caps request, stdout and stderr sizes;
- rejects any stderr output;
- rejects non-JSON, non-zero or secret-shaped responses;
- exposes no filesystem, process or key-read API to a renderer.

The test-only store override requires the explicit `ERGAXIOM_SIGNER_TEST_MODE=1` environment binding. Production calls use the per-user default store.

This PR provides the backend-shaped client and executable boundary but does not yet add Tauri commands that invoke it. Wiring specific capability, execution, normalization, attestation or release issuance flows to the signer remains a separate authorization package.

### Windows signer executable

`ergaxiom-windows-signer` is a separate process. It reads at most one bounded JSON request, writes one bounded JSON response and exits.

For every key identity it:

1. validates role, issuer and key identifiers;
2. derives a canonical identity digest used as the filename;
3. generates a fresh 32-byte Ed25519 seed inside the signer process;
4. derives identity-specific optional entropy;
5. protects the seed with `CryptProtectData` and `CRYPTPROTECT_UI_FORBIDDEN`;
6. persists only public metadata and the DPAPI ciphertext;
7. zeroizes temporary plaintext buffers when they leave scope.

Unprotection uses `CryptUnprotectData` with the same identity entropy. The public key reconstructed from the unprotected seed must equal the persisted public key before a signature can be issued. DPAPI output buffers are copied into owned Rust memory and released immediately with the Win32 `LocalFree` function required by the API contract.

## Storage and replay controls

The production store is rooted under:

```text
%LOCALAPPDATA%\Ergaxiom\Signer\v1
```

Request-controlled values never become path components. Key records and replay markers use SHA-256 filenames.

Key creation uses a `create_new` lock, a uniquely named temporary file, `sync_all` and rename. Existing identities are never silently overwritten.

Every request ID is hashed into a persistent replay marker created with `create_new`. Reusing the same request ID fails even if the caller changes another request field. A failed request may consume its request ID; this is intentional fail-closed behavior.

## Response boundary

Successful responses contain only:

- role and key identity;
- public key;
- record digest;
- canonical signing envelope;
- envelope digest;
- Ed25519 signature metadata and signature.

Private seed bytes, DPAPI ciphertext, entropy and storage paths are never response fields. Public error responses contain a stable code and the generic message `signer request rejected`; internal operating-system errors are not serialized.

## Real Windows verification

Permanent Windows CI must prove:

- DPAPI roundtrip succeeds for the exact entropy;
- different entropy cannot unprotect the ciphertext;
- the persisted record does not contain the deterministic test seed;
- exact role-bound digest signatures verify independently;
- replay, duplicate initialization, role changes, key changes and test-store command-line use without explicit test mode fail closed;
- the real child process emits no stderr or secret-shaped JSON;
- the isolated signer executable compiles and is uploaded only as an explicitly unsigned diagnostic.

## Remaining Issue #39 work

This gate does not complete production release security. Remaining work includes:

- TPM or CNG hardware-provider non-exportable production keys;
- authenticated long-lived signer IPC and service identity hardening if one-shot invocation is replaced;
- production issuer provisioning and recovery procedures;
- Authenticode for the host, desktop application, adapters, signer and installer;
- trusted timestamp and certificate-chain verification;
- signed trust-registry distribution and rollback prevention;
- signed installer upgrade, downgrade and rollback attack tests;
- reproducible comparison against the final signed release artifacts.
