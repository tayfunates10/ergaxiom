# Purpose-Locked Acceptance Certificate Issuance

## Scope

This gate binds Acceptance Certificate issuance to the isolated Windows signer while preserving the existing Evidence Runtime reassessment and Replay Manifest verification boundary.

It adds a signer-bound Acceptance Certificate package alongside the existing direct-Ed25519 package. Existing certified paths and direct verification remain supported; no silent signature-semantics migration occurs.

The package covers Acceptance Certificate issuance only. It does not expose signer controls to the renderer, provide TPM/CNG hardware-backed non-exportability, add Authenticode or prove installer provenance.

## Fixed attestation authority

`ergaxiom-attestation-issuance-runtime` accepts only an `AttestationCertificateDraft` containing:

- manifest ID;
- certificate ID;
- trusted issuance timestamp.

The draft cannot contain:

- issuer role;
- issuer ID;
- key ID;
- arbitrary signing digest;
- signer request ID;
- executable path, command arguments or signer store path.

The authority supplies these values itself:

- role: `Attestation`;
- issuer: `ergaxiom.attestation-authority`;
- key ID: `attestation-key-v1`;
- digest: canonical SHA-256 of the complete Acceptance Certificate payload;
- request ID: deterministic domain prefix plus a bounded payload-digest prefix.

## Evidence reassessment before signing

The authority does not trust `claimed_decision` from an Evidence Bundle. Before constructing the certificate payload it:

1. invokes Evidence Runtime against the exact compiled Work Contract and Operator Plan;
2. requires the independently recomputed decision to be `ACCEPTED`;
3. requires zero failed and zero unknown mandatory obligations;
4. decodes the exact accepted Evidence Bundle;
5. builds the deterministic Replay Manifest;
6. computes and embeds the Replay Manifest digest;
7. constructs the fixed-identity Acceptance Certificate payload;
8. computes the canonical payload digest;
9. invokes the isolated signer only after all previous gates pass.

A rejected, malformed, mismatched or incomplete Evidence Bundle never reaches the signer transport.

## Signer-bound package

`SignerBoundAttestationPackage` contains:

1. the deterministic Replay Manifest;
2. the complete Acceptance Certificate payload;
3. the isolated signer's signed canonical envelope response.

The envelope binds the request ID, Attestation role, issuer ID, key ID, SHA-256 algorithm and exact canonical payload digest. The issuance authority independently verifies the response before returning the package.

The returned signer public key must equal the provisioned Attestation public key. A valid signature from a substituted key is rejected.

## Independent verification

`verify_signer_bound_attestation` performs these checks:

1. supported Replay Manifest and certificate schemas;
2. `ACCEPTED` decision and zero failed/unknown mandatory obligations;
3. exact Replay Manifest digest;
4. exact manifest/payload field agreement;
5. trusted key lookup by issuer and key ID;
6. signer-envelope signature verification;
7. Attestation role;
8. signer issuer and key ID equal to payload identity;
9. recomputed canonical payload SHA-256 equals the signed digest;
10. signer response public key equals the trusted registry key.

`verify_signer_bound_attestation_against_bundle` then independently reassesses the caller-supplied Evidence Bundle and rebuilds the Replay Manifest. Any bundle, trace, artifact, proof, manifest or payload substitution fails closed.

## Governed verification

`GovernedVerificationRuntime` resolves signer-bound certificates through the role-separated Attestation registry using:

- exact issuer ID;
- exact key ID;
- payload issuance time;
- Attestation role;
- active, non-revoked key state.

Revocation invalidates signer-bound certificates even if the cryptographic signature was created before the key was revoked.

## Replay boundary

The signer request ID is deterministically derived from the canonical certificate-payload digest. Reissuing identical payload material produces the same request ID, and the isolated signer rejects it through the persistent replay ledger.

Changing certificate identity, issuance time, Evidence Bundle material or Replay Manifest material changes the payload digest and request ID. Those changes still require a fresh independently accepted Evidence Bundle and exact verifier agreement.

## Renderer boundary

No Tauri invoke handler is added for signing, key initialization, key lookup, arbitrary digest submission or signer process configuration. The renderer cannot select Attestation role, issuer, key, digest, request ID, executable path or signer store.

A later gate may connect approved backend execution flows to the purpose-locked authority, but that wiring must carry a backend authorization policy and must not widen the signer input boundary.

## Permanent verification

Permanent Linux and Windows CI exercises:

- evidence reassessment before signer invocation;
- fixed Attestation role, issuer and key identity;
- role, issuer, key, digest and public-key substitution attacks;
- payload and Replay Manifest mutation;
- trusted and governed signer-bound verification;
- governed key revocation;
- a real DPAPI CurrentUser-protected Attestation key;
- the real isolated signer child process;
- identical-payload signer request replay rejection;
- existing direct-Ed25519 attestation and certified-path regressions.

## Remaining work

This gate does not:

- expose certificate issuance directly to the renderer;
- authorize issuance from arbitrary backend callers;
- provision production issuer recovery or ceremony procedures;
- provide TPM/CNG hardware-provider non-exportability;
- protect against arbitrary malicious code already running as the same Windows user;
- sign application, adapter or installer binaries;
- provide trusted timestamps, commercial certificate chains or signed upgrade/rollback provenance.
