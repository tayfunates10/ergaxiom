# TPM/CNG Production Signer Policy and Identity Binding

## Status

This document defines the first bounded implementation slice of Issue #60. It introduces the platform-neutral production signer policy and identity-binding model. It does not yet claim that a real TPM key has been provisioned or used.

## Fixed production identities

The production path currently permits only two issuer identities:

- Capability: `ergaxiom.policy-authority` / `capability-key-v1`
- Attestation: `ergaxiom.attestation-authority` / `attestation-key-v1`

Execution, normalization and release roles remain outside this bounded slice.

## Production key policy

An eligible production key must match all of the following:

- provider: `Microsoft Platform Crypto Provider`
- algorithm: ECDSA P-256 with SHA-256
- public key encoding: uncompressed SEC1 P-256
- signature encoding: fixed-width IEEE P1363 `r || s`
- export policy: non-exportable
- hardware requirement: mandatory

A software provider, exportable policy, algorithm downgrade or substituted issuer identity fails closed.

## Hardware assurance rule

The policy distinguishes:

- `PROVEN_HARDWARE_BACKED`
- `UNPROVEN`
- `REJECTED`

Only `PROVEN_HARDWARE_BACKED` is eligible for production signing. Provider availability or a successful software-CNG operation is not sufficient evidence of TPM backing.

## Authenticated caller identity

Every accepted production signer request is designed to bind:

- caller process ID
- caller process creation time
- Windows principal SID
- Windows session ID
- caller executable path
- caller executable SHA-256

The process creation time prevents a reused PID from inheriting a previous authorization identity.

## Signer-service identity

Every request is also bound to:

- fixed service ID
- signer-service process ID
- signer-service process creation time
- signer-service executable SHA-256
- service start time
- per-instance nonce

Restarting or substituting the signer service changes the request-binding digest.

## Provisioning receipt

Provisioning returns a public-only canonical receipt binding:

- issuer role and identity
- provider and algorithm
- public key and public-key digest
- export policy
- provider implementation flags
- hardware assurance result
- production policy digest
- provisioning time

Secret-shaped fields are rejected from the receipt model.

## Not yet claimed

This slice does not yet implement:

- CNG key creation or signing
- TPM attestation evidence
- named-pipe ACLs and caller derivation
- ECDSA verification in signer-bound artifacts
- Capability or Acceptance Certificate issuance through CNG

Those remain required before Issue #60 can close.
