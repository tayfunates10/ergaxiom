# Controlled-Machine Production Signer Deployment Evidence

## Status

Ergaxiom can represent, seal and independently verify the public evidence produced by a controlled Windows production-signer installation and recovery exercise. Hosted CI validates the data model and attack contracts, but it does not substitute for an elevated ceremony on an independently controlled physical machine.

No installation or recovery receipt upgrades a key from `UNPROVEN` to `PROVEN_HARDWARE_BACKED` by itself. Physical-TPM promotion remains a separate reviewed decision bound to independently trusted evidence.

## Installation validation receipt

`ProductionSignerInstallationValidationReceipt` binds one observed installation ceremony to:

- the deployment identity and ceremony identifier,
- a domain-separated digest of the Windows machine identity,
- the canonical service manifest and manifest path,
- the trust-governance policy digest,
- the accepted production trust-state binding,
- the exact enabled Capability and Attestation identities,
- the live SCM service configuration and process identity,
- the active generation-specific CNG key observations,
- a live protected-pipe probe response, and
- a canonical receipt digest.

The receipt contains no raw Windows `MachineGuid`. The machine value is reduced through the fixed `windows-machine-guid-domain-sha256-v1` scheme before it enters the public evidence package.

Changing the machine-identity digest, manifest, trust-state binding, active key observation, service process or pipe result without resealing invalidates the receipt digest. Resealing cannot make a weakened service account, privilege set, failure policy, key ordering or trust binding acceptable because those fields are independently validated before the outer receipt digest is accepted.

## Machine-identity mutation contract

A mutation test must change the fixture value to a genuinely different valid SHA-256 string. Reassigning the value already present in the canonical fixture is a no-op and proves nothing. Permanent tests therefore compare distinct digests and require `InstallationReceiptDigestMismatch` when the outer receipt is not reviewed and resealed.

The machine digest is evidence of continuity for one controlled-machine record; it is not a device-attestation primitive, TPM endorsement identity or authorization secret. Knowledge of the digest grants no signing capability.

## Recovery exercise receipt

`ProductionSignerRecoveryExerciseReceipt` binds:

- one pre-recovery installation receipt,
- one post-recovery installation receipt,
- stop, restart and completion times,
- the deployment and recovery-exercise identities, and
- a canonical recovery receipt digest.

Verification requires the post-recovery service to be a distinct process instance while preserving the accepted deployment and trust-state lineage. Rollback, forked trust state, substituted deployment identity, unchanged process identity or inconsistent timing fails closed.

## Independent reviewer signatures

Installation and recovery receipts can be wrapped in threshold-signed deployment-evidence packages. Deployment reviewers use their own Ed25519 policy, separate from:

- Ed25519 trust-governance authorities, and
- ECDSA P-256 Capability and Attestation issuer keys.

Exact Ed25519 public-key reuse between deployment reviewers and trust-governance authorities is rejected. P-256 issuer identities remain bound through their complete SEC1 public keys, algorithm, role, issuer, key ID and generation; a coordinate extracted from a P-256 point is never treated as an Ed25519 reviewer key.

Reviewer signatures bind a domain-separated message for either installation or recovery evidence. Cross-domain signature reuse, below-threshold signatures, duplicate reviewers, expired or revoked reviewer keys, receipt mutation and signature-digest substitution fail closed.

## Evidence handling

The administrator-facing service executable supports create-new output for installation and recovery receipts and verification of separately signed evidence. Evidence paths must be absolute, regular, non-empty and bounded in size. Existing destinations are not overwritten.

Public evidence may contain executable digests, policy digests, public keys, service configuration and machine-identity digests. It must never contain:

- private CNG key material,
- trust-governance or reviewer private keys,
- raw machine GUID values,
- unrestricted command-line arguments,
- bearer credentials, or
- a claim of physical-TPM assurance that has not passed the separate promotion policy.

## Required controlled-machine ceremony

Before Issue #60 can close, an administrator-controlled Windows machine must retain reviewed evidence for:

1. exact release candidate and executable SHA-256,
2. accepted trust-state and governance-policy digests,
3. elevated fixed-identity CNG provisioning,
4. live SCM installation and hardening validation,
5. active Capability and Attestation key observations,
6. protected-pipe request and response verification,
7. service stop and restart recovery exercise,
8. machine rebuild or restoration exercise,
9. independent reviewer threshold signatures, and
10. physical-TPM evidence and promotion decision.

Hosted CI remains intentionally unable to satisfy these operational requirements.
