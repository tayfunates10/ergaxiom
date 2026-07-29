# Persistent production Capability authority

The production Capability issuance boundary must not reset replay protection when the desktop backend restarts or when a live signer trust lease is refreshed. `PersistentBackendProductionCapabilityAuthority` therefore owns one recovered `BackendIssuancePolicy` and an append-only `BackendIssuancePolicyStore`.

## Persistent policy chain

Each policy snapshot is a canonical JSON object addressed by its SHA-256 digest. The filename binds the zero-padded revision and state digest. Every non-initial record binds the previous state digest. Recovery requires exactly one initial root, one linear revision chain, stable bounded file reads, matching filenames and digests, and no duplicate, divergent, cyclic or orphaned records.

Published records are create-new and immutable by convention. A bounded pending file is written and synced first, then published with a hard link so an existing digest-addressed record cannot be replaced. Abandoned pending files are ignored during recovery, while unexpected published entries fail closed. The store root must be an absolute path and direct symbolic links are rejected.

## Capability issuance order

At the exact issuance time the backend:

1. validates the fresh `VerifiedProductionSignerTrustLease` against the accepted production trust state and deployment policy;
2. constructs the governed Capability authority only from the lease's Capability trust snapshot and captured registry;
3. independently validates the desktop snapshot, approval, command receipt, Work Contract, Operator Plan, permission grant, executor, device, time bounds and single-use token draft;
4. reserves the exact issuance intent and consumes its backend authorization;
5. persists that consumed authorization and intent reservation before invoking the signer service;
6. invokes the governed production signer and independently verifies the returned token against the lease trust and registry.

Persisting consumption before the signer side effect makes a transport or signer rejection terminal. Restarting the backend or obtaining a new live proof cannot replay the same approval and Capability intent.

## Recovery and failure behavior

A corrupted record, changed file during read, unexpected entry, invalid chain, concurrent store mutation, expired lease, repeated intent, stale approval, altered draft or signer rejection fails closed. There is no DPAPI, direct Ed25519, software-CNG or in-process production fallback.

The store directory is expected to be provisioned under an installer-controlled Windows directory with independently verified administrator-only DACL protection. This slice validates the logical and file-format chain but does not claim that every caller-selected directory is protected by Windows ACLs.

## Claim boundary

This slice establishes persistent, replay-safe production Capability issuance. It does not yet expose a renderer issuance command, wire the authority into the fixed Tauri startup store path, consume the issued token before executor invocation, persist the token and authorization receipt as job records, execute the Operator Plan, or create the Evidence Bundle and Acceptance Certificate chain.
