# Backend-Authorized Purpose-Locked Issuance

## Scope

This gate connects the existing purpose-locked Capability Token and Acceptance Certificate authorities to exact backend-owned approval and execution state.

It does not add a generic signing service. It does not expose signer configuration, roles, issuer identities, key identities, digests, request IDs, executable paths or signer-store paths to the renderer.

## Two distinct authorization phases

Capability Token issuance and Acceptance Certificate issuance occur at different lifecycle points and therefore use different backend gates.

### Capability issuance

Capability issuance requires:

1. an independently verified desktop snapshot in `Approved` state;
2. the exact backend approval record bound to that snapshot;
3. an applied `Approve` command receipt whose post-snapshot digest equals the current snapshot;
4. a non-expired approval;
5. an exact compiled Work Contract and Operator Plan matching the snapshot and approval;
6. a trusted Profession Capsule digest matching the compiled plan;
7. a single-use capability draft whose subject equals the backend-owned executor/device identity;
8. backend-current temporal bounds that do not exceed approval expiry;
9. an exact plan step/operator assignment containing the token ID;
10. a grant exactly equal to one permission in the compiled Work Contract.

Permission widening, a substituted step, operator, subject, device, contract, capsule, plan, snapshot, approval or receipt fails before the signer transport is invoked.

### Attestation issuance

Acceptance Certificate issuance requires:

1. an independently verified desktop snapshot in `Executed` state;
2. the original backend approval record;
3. an applied `Execute` command receipt whose post-snapshot digest equals the executed snapshot;
4. proof that execution occurred within the approval validity window;
5. exact contract, capsule and plan bindings;
6. an Evidence Bundle exposed by the authoritative executed snapshot;
7. independent Evidence Runtime reassessment returning `ACCEPTED` with zero failed or unknown mandatory obligations;
8. a Replay Manifest independently rebuilt from the exact bundle and draft manifest identity;
9. exact Evidence Bundle and Replay Manifest digests matching the executed snapshot;
10. an attestation draft timestamp equal to the trusted backend clock.

The purpose-locked Attestation authority repeats Evidence Bundle reassessment and Replay Manifest construction before invoking the isolated signer. The authorization policy therefore does not replace certificate-level independent verification.

## Authorization record

`BackendIssuanceAuthorization` binds:

- issuance kind;
- job and actor identity;
- snapshot digest;
- approval digest;
- command-receipt digest;
- contract and capsule digests;
- plan ID and plan digest;
- permission digest;
- exact issuance-intent digest;
- trusted issuance and expiry timestamps.

The authorization digest is canonical SHA-256 over the complete record with the digest field blanked.

## One-shot consumption

The runtime stores authorizations in a backend-owned pending journal. Consumption:

1. verifies the authorization schema and canonical digest;
2. verifies the expected issuance kind;
3. verifies expiry against the trusted backend clock;
4. requires the authorization to exist in the pending journal;
5. removes it from pending and records it as consumed before signer invocation.

A consumed authorization cannot be used again. The same exact intent under the same approval cannot be re-authorized. If the signer transport rejects or fails after consumption, the permission remains consumed and must not become reusable.

The current pending, consumed and authorized-intent journals are in-memory and scoped to one runtime process. Process restart durability, multi-user coordination and crash-recovery semantics are not claimed by this gate.

## Renderer boundary

No Tauri command is added for:

- Capability Token issuance;
- Acceptance Certificate issuance;
- authorization creation or consumption;
- arbitrary digest submission;
- role, issuer or key selection;
- signer executable or store configuration;
- key initialization or public-key lookup.

The current desktop fixture can continue to review, approve, execute, cancel and roll back. A later product gate may call this backend runtime internally after user-selected immutable inputs and real Evidence Bundles are available, but it must not widen the renderer request surface.

## Permanent verification

Linux and Windows CI exercise:

- exact approved capability issuance;
- exact executed attestation issuance;
- step and operator substitution;
- executor/device substitution;
- permission escalation;
- wrong command action and receipt binding;
- stale snapshot and expired approval;
- Evidence Bundle mutation;
- one-shot authorization consumption;
- duplicate intent authorization rejection;
- signer-failure fail-closed consumption;
- all existing purpose-locked signer, governed verification and certified-path regressions.

The Windows job also preserves the existing real DPAPI CurrentUser signer-process tests. The backend authorization policy itself is platform-neutral.

## Remaining work

This gate does not provide:

- direct renderer issuance;
- persistent multi-user authorization journals;
- production user-selected job persistence;
- TPM/CNG hardware-provider non-exportability;
- protection from arbitrary malicious code already running as the same Windows user;
- Authenticode, trusted timestamps or commercial certificate chains;
- signed installer upgrade, downgrade or rollback provenance.
