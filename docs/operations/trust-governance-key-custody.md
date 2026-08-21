# Trust-governance key custody, rotation and recovery

This procedure is part of Issue #77. It deliberately separates two different authorities:

- **TPM production signing keys** are the non-exportable Microsoft Platform Crypto Provider Capability and Attestation keys used by the installed signer service.
- **Trust-governance keys** authorize signed production trust-state and trust-recovery envelopes. They are not production signing keys and are not provisioned into the signer service TPM key namespace.

The two authorities must never reuse a public key, private key, key identifier, or custody path.

## Custody policy

`TrustGovernancePolicy` is the machine-readable public policy. Only its public key records, status, validity windows, threshold and policy digest may be distributed to production hosts.

Trust-governance private material is an offline/operator authority and must not be:

- committed to the repository;
- stored in GitHub Actions secrets for routine hosted CI;
- uploaded as workflow artifacts;
- copied into `ErgaxiomProductionSigner` configuration/state directories;
- exposed to the desktop renderer, adapters, production Capability/Attestation signer API, or named-pipe request surface;
- backed up together with a production host image.

Production governance should use multiple independently controlled participants and a threshold of at least two approvals/signatures. The public policy may contain more active governance keys than the threshold, but one participant must not control enough independent custody shares/accounts to satisfy the threshold alone.

Backups are custody-system/operator backups of governance authority material, not Ergaxiom application backups. Ergaxiom public recovery evidence records only public key identifiers/digests, policy digests, signed envelope digests, approval digests and recovery receipts. Never place a private key, seed, mnemonic, raw recovery share, passphrase or decrypted keystore in repository evidence.

## Routine trust-state distribution

1. Build the next `ProductionTrustStateBody` from the reviewed registry, caller allowlist, signer executable digest, service policy, revision bounds and recovery policy ID.
2. Review the body digest independently before signing.
3. Obtain the configured `TrustGovernancePolicy.signature_threshold` distinct governance signatures over the exact trust-state domain/body digest.
4. Build the canonical `ProductionTrustStateEnvelope` and independently verify every signature and the policy digest.
5. Publish/distribute the envelope and public governance policy through the administrator-controlled trust-state path.
6. On the signer host, load the envelope only through the production trust-state runtime. The accepted checkpoint binds state/envelope/registry/allowlist/service-policy digests and minimum accepted revision.
7. Capture installation evidence after activation. The installation receipt must bind the exact accepted trust-state binding before production signing resumes.

A missing signature, duplicate signer, revoked/expired governance key, policy-digest substitution, stale revision or threshold failure is terminal and must not fall back to an unsigned/local policy.

## Governance-key rotation

Governance-key rotation changes the review/signing authority and is separate from Capability/Attestation TPM key rotation.

1. Create the replacement governance key under independent custody; publish only its public key and digest.
2. Prepare a new `TrustGovernancePolicy` revision containing the intended active/revoked records and threshold. Do not silently mutate the previous policy in place.
3. Have the existing trusted governance quorum approve the transition and record the old/new policy digests in the change record.
4. Distribute the new policy and a trust-state envelope whose `governance_policy_digest` matches it exactly.
5. Verify the new policy/envelope on the controlled signer host before changing the accepted checkpoint.
6. Capture installation evidence after activation and run the service recovery exercise so restart persistence of the new trust authority is proven.
7. Retain old public governance records and transition evidence for audit. Do not reuse the retired public key as a new governance identity or as a production TPM signing key.

If the old policy cannot safely authorize a normal rotation, use the recovery procedure below rather than weakening threshold or accepting an unsigned policy.

## Revocation

When a governance key is suspected compromised:

1. stop production trust-state promotion and, when the accepted state can no longer be trusted, stop production issuance;
2. produce a non-sensitive revocation/recovery reason digest;
3. mark the affected governance key revoked in the next reviewed governance policy revision;
4. require remaining uncompromised participants to satisfy the approved recovery quorum;
5. replace any production trust state whose authorization depended on the compromised authority;
6. distribute the replacement policy/state and independently verify policy, signatures, revision bounds and digests;
7. capture the recovery and installation evidence before production resumes.

A revoked governance key is never restored by changing its validity dates. Recovery creates a new authority state and preserves the revoked record as history.

## Threshold recovery

The repository's `ProductionTrustRecoveryBody` binds:

- deployment and recovery policy IDs;
- damaged and replacement trust-state digests;
- recovery reason digest;
- monotonically increasing recovery sequence;
- minimum uncompromised revision;
- maximum allowed replacement revision;
- expiry time.

`ProductionTrustRecoveryEnvelope` binds that body to the exact governance-policy digest and a canonical set of `TrustGovernanceSignature` values. Verification must satisfy the policy threshold with distinct valid governance keys before the recovery can be accepted.

Operational recovery procedure:

1. identify the last independently reviewed uncompromised checkpoint and its digest;
2. prepare the exact replacement trust state and compute its digest;
3. create a bounded recovery body with a new recovery sequence and short review-validity window;
4. obtain distinct governance signatures meeting the recovery policy threshold;
5. independently verify the recovery envelope, replacement trust-state envelope and governance policy before copying them to the controlled host;
6. activate through the trust-state store's recovery path so stale/forked sequences and revision violations fail closed;
7. validate the installed LocalSystem signer against the recovered accepted trust-state binding;
8. perform the real service restart/recovery drill and retain its receipt;
9. record the public governance-recovery receipt and exact signed-distribution digest used by the Issue #77 physical hardware gate.

No recovery procedure may lower the threshold merely because a participant is unavailable. If quorum cannot be met, production remains blocked until the approved external governance recovery process restores a valid quorum.

## Backup and disaster-recovery rule

There is **no application-level private-key backup** for TPM Capability/Attestation keys, and there is **no repository/CI backup** for trust-governance private keys. Disaster recovery restores public policies, signed trust-state/recovery envelopes, accepted checkpoints and audit receipts, then requires the appropriate external custodians to authorize new authority material.

Loss of a non-exportable TPM key requires a new TPM generation and trust-state update. Loss of a governance participant requires governance rotation/recovery under the existing approved threshold; it does not authorize exporting another participant's private key or reducing quorum.

## Evidence required for review

A governance operation is reviewable only when the evidence set identifies the old/new policy or trust-state digests, affected key IDs/public-key digests, threshold, distinct participant approvals/signatures, recovery sequence when applicable, signed-distribution digest, resulting accepted trust-state binding, installation receipt and restart/recovery receipt. Secret material must never appear in that evidence set.
