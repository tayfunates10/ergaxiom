# Purpose-Locked Capability Token Issuance

## Scope

This gate binds Capability Token issuance to the isolated Windows signer while keeping all signer-controlled fields outside renderer and untrusted-caller input.

It adds a new signer-bound Capability Token format alongside the existing direct-Ed25519 token format. Existing tokens and verification paths remain supported; no silent signature-semantics migration occurs.

This package covers Capability Tokens only. Acceptance Certificate issuance, renderer command exposure, TPM or CNG hardware-backed keys, Authenticode and signed installer provenance remain separate work. The desktop Tauri invoke handler is not extended by this package, so no renderer-callable issuance command exists.

## Fixed issuance authority

`ergaxiom-capability-issuance-runtime` accepts a `CapabilityTokenDraft` containing only the work authorization material:

- token ID;
- executor and optional device binding;
- issue, not-before and expiry timestamps;
- maximum use count and nonce;
- exact contract, capsule, plan, step and operator bindings;
- exact capability grant.

The draft has no fields for:

- issuer role;
- issuer ID;
- key ID;
- arbitrary signing digest;
- signer request ID;
- executable path, command arguments or signer store path.

The authority supplies those values itself:

- role: `Capability`;
- issuer: `ergaxiom.policy-authority`;
- key ID: `capability-key-v1`;
- digest: canonical SHA-256 of the complete Capability Token payload;
- request ID: deterministic domain prefix plus a bounded payload-digest prefix.

## Signer-bound token

The new `SignerBoundCapabilityToken` contains:

1. the complete Capability Token payload;
2. the isolated signer's signed canonical envelope response.

The envelope binds the request ID, Capability role, issuer ID, key ID, SHA-256 algorithm and exact canonical payload digest. The signer response is independently verified before a token is returned.

The issuance authority also compares the signer's returned public key with the provisioned expected Capability public key. A valid signature from another key is rejected.

## Authorization

`CapabilityAuthorizer::authorize_signer_bound` performs the following sequence:

1. decode the signer-bound token;
2. resolve the trusted local public key by payload issuer and key ID;
3. independently verify the signer envelope signature;
4. require the Capability role;
5. require signer issuer and key ID to equal the payload identity;
6. recompute canonical payload SHA-256 and require an exact envelope-digest match;
7. require the response public key to equal the trusted registry key;
8. apply the existing time, contract, capsule, plan, step, operator, executor, device, grant, token-ID collision and usage-limit controls.

The existing direct-Ed25519 `authorize` method is unchanged.

## Governed verification

`GovernedVerificationRuntime` adds a signer-bound verification and authorization path. Before the legacy semantic authorization controls run, the key must resolve through the role-separated governed registry for:

- Capability role;
- exact issuer and key ID;
- payload issuance time;
- active, non-revoked key status.

Revocation therefore invalidates signer-bound tokens even when their cryptographic signatures were valid before revocation.

## Replay boundary

The request ID is deterministically derived from the canonical payload digest. Reissuing the identical payload produces the same signer request ID, and the isolated signer rejects it through the persistent replay ledger.

A different payload produces a different digest and request ID, while reuse of the same token ID with different signed material remains blocked by Capability Runtime's token-ID collision control.

## Real Windows verification

Permanent Windows CI exercises:

- a real DPAPI CurrentUser-protected Capability private key;
- the real isolated signer child process;
- purpose-locked payload construction;
- independently verified signer-bound token authorization;
- governed key registration and revocation;
- identical-payload signer request replay rejection;
- existing signer, capability, governed-verification and workspace regressions.

## Remaining work

This gate does not:

- expose Capability Token issuance directly to the renderer;
- migrate Acceptance Certificate issuance to the isolated signer;
- provision production issuers or recovery procedures;
- provide TPM or CNG hardware-provider non-exportability;
- protect against arbitrary malicious code already running as the same Windows user;
- sign application or installer binaries;
- provide trusted timestamps, certificate-chain verification or signed upgrade and rollback provenance.
