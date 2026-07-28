# Purpose-Locked Live Signer-Service Identity Proof

## Goal

Authenticate the live installed `ErgaxiomProductionSigner` instance before the desktop backend treats the configured production boundary as reachable. The client never supplies an arbitrary digest to be signed.

## Challenge

The backend creates a cryptographically random 32-byte nonce and a challenge valid for at most 30 seconds. The challenge is sealed and binds:

- request ID and nonce;
- deployment and service IDs;
- signer executable digest;
- deployment-policy revision/digest;
- accepted trust-state revision/binding digest;
- registry revision/digest; and
- active Attestation generation/public-key digest.

## Service behavior

The named-pipe host authenticates the caller first. For `PROVE_IDENTITY`, the service validates the challenge against its in-memory accepted trust state, constructs the proof payload internally, hashes the canonical typed payload and only then invokes the existing governed Attestation signing path. There is no wire field that lets the caller choose the digest.

The payload binds the challenge, authenticated caller digest, base process identity, trust-bound service identity, accepted trust-state binding, deployment policy and active Attestation key binding.

## Client verification

The client verifies the response seal, nonce and lifetime; reconstructs the expected trust-bound service identity; verifies the deployed signed package against the accepted registry and Attestation key; and requires the signed request digest to equal the typed payload digest.

## Claim boundary

A valid proof authenticates one live signer process instance for one caller and one short-lived challenge. It does not authorize a Capability request and does not enable production issuance. Replay, nonce substitution, expiry, service restart, trust-state divergence or Attestation rotation invalidate the proof.
