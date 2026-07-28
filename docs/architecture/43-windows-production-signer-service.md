# Hardened Windows Production Signer Service

## Status

The Windows Service Control Manager runtime, installer contract and accepted-trust-state startup orchestration are implemented and covered by the permanent Ubuntu and Windows matrix.

This does **not** claim that a production machine has already completed an elevated installation ceremony, that independently reviewed physical-TPM evidence exists, or that operational governance-key custody and signed trust-state distribution are complete.

## Service identity

The fixed service contract is:

- service name: `ErgaxiomProductionSigner`,
- display name: `Ergaxiom Production Signer`,
- service type: `SERVICE_WIN32_OWN_PROCESS`,
- account: `LocalSystem`,
- start mode: automatic delayed start,
- error control: severe,
- service SID type: unrestricted,
- required privilege list: only `SeChangeNotifyPrivilege`,
- preshutdown timeout: 10 seconds,
- failure actions: restart after 5 seconds, restart after 30 seconds, then no automatic action, and
- service-object DACL: protected full access for LocalSystem and Built-in Administrators only.

The service name, account, type, start policy, privilege list, failure policy and executable command line are not administrator-selectable fields in the normal runtime. Weakening one of these values invalidates the canonical service manifest.

## Canonical service manifest

`ProductionSignerServiceManifest` binds:

- deployment identity,
- exact executable path and SHA-256,
- accepted trust-store root,
- governance-policy path and digest,
- caller-allowlist path, revision and digest,
- signer deployment-policy path, revision and digest,
- named-pipe client principal SID,
- fixed SCM hardening values, and
- a canonical manifest digest.

Every path must be absolute. Quote injection, embedded NUL, relative paths and symbolic-link substitution fail closed. The manifest is emitted with create-new semantics and a complete file flush; an existing destination is never overwritten.

## Installation boundary

The dedicated `ergaxiom-windows-production-signer-service` executable exposes only:

- create a manifest from already accepted public configuration,
- validate an installed service against the manifest,
- install the fixed SCM service,
- uninstall the fixed SCM service, and
- enter SCM-dispatched service mode.

The command line does not accept a signing role, issuer, key identifier, generation, provider, algorithm, payload digest, request identifier or arbitrary named-pipe name.

Installation first validates the full signed trust-state/configuration tuple. It then creates the fixed own-process LocalSystem service, applies delayed start, the fixed privilege list, service SID, failure actions, preshutdown policy and protected service DACL. Failure during hardening causes the newly created service entry to be deleted rather than leaving a partially hardened service.

Validation reads the live SCM configuration and rejects binary-path, account, service-type, start-mode or error-control divergence.

## Fail-closed startup

Service startup performs the following sequence before reporting `SERVICE_RUNNING`:

1. load and authenticate the canonical service manifest,
2. re-hash the current executable and require the exact manifest path,
3. load and validate the separate trust-governance policy,
4. load and validate the caller allowlist,
5. load and validate the deployment policy,
6. load the atomically accepted signed trust state,
7. require exact deployment, executable, allowlist and service-policy bindings,
8. resolve exactly one active generation for every enabled signing identity,
9. probe Microsoft Platform Crypto Provider and reject software-provider flags,
10. open each exact generation-specific CNG key by expected public-key digest,
11. compare the complete public descriptor with the accepted registry record,
12. derive the current service process identity and per-instance nonce,
13. construct the trust-bound signer service, and
14. bind the protected first-instance local named pipe.

Any failure before step 14 prevents the service from reporting a running state. There is no embedded development registry, DPAPI fallback or software-CNG production fallback.

## Request loop and shutdown

Each connection is processed through the existing protected message-mode named-pipe boundary. Caller identity is derived from the connected pipe, authorization and replay are consumed before CNG signing, and responses expose only a sealed deployed package or a generic rejection code.

Every complete request read, response write and client exchange is bounded by a fixed five-second synchronous-I/O deadline. A watchdog owns a duplicated handle for the worker thread and invokes `CancelSynchronousIo` if an accepted client connects but does not complete the operation. The resulting cancellation is normalized to a public transport timeout, the active connection is disconnected, and the single protected pipe instance becomes available again.

A completed malformed message is rejected immediately as invalid JSON rather than being treated as an incomplete transport operation. Connection cleanup deliberately does not call `FlushFileBuffers`, because that API can wait for a client that has stopped reading a response; cleanup disconnects and closes the owned pipe handle instead.

Stop, shutdown and preshutdown controls set a process-wide stop state and wake a blocked named-pipe accept with a local connection. A worker blocked on accepted-client I/O is released by the bounded deadline, after which the service exits the request loop and reports the stopped state within the SCM preshutdown boundary.

## Attack coverage

Permanent tests cover:

- service-name, account, service-type and start-mode substitution,
- error-control and service-SID weakening,
- addition of `SeDebugPrivilege` or any other privilege,
- restart-policy and preshutdown-policy substitution,
- relative path and command-line quote injection,
- manifest digest and executable digest substitution,
- create-new manifest overwrite attempts,
- response seal mutation,
- current executable path and digest binding,
- an accepted client that connects and sends no request bytes,
- immediate rejection of a completed malformed message,
- connection cleanup while the client deliberately does not read the response,
- successful protected-pipe rebinding after timeout or rejection,
- Windows SCM FFI compilation,
- Windows service executable release compilation, and
- all existing production signer, trust-state, generation, Capability and Attestation attacks.

The permanent workflow uses `permissions: contents: read` and passes on Ubuntu 24.04 and Windows Server 2025.

## Operational boundary

The repository now contains an installable and fail-closed SCM service runtime. The following operational evidence remains required before Issue #60 can close:

- independently trusted physical-TPM promotion evidence,
- an elevated provisioning ceremony on controlled hardware,
- controlled custody, rotation, backup and recovery of trust-governance private keys,
- administrator-controlled packaging and distribution of signed trust-state updates,
- an actual elevated SCM installation and validation record from a controlled machine,
- service recovery and machine-rebuild exercises, and
- complete desktop/backend routing through the installed service.

Hosted CI deliberately does not install the fixed production service or claim physical TPM assurance.
