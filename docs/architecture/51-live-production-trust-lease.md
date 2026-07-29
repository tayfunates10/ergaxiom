# Live production signer trust lease

The desktop/backend must not treat a startup-time service identity observation as an unlimited production signing authority. A verified identity proof is converted into a short-lived, dual-role trust lease only after the proof is checked against the accepted trust state and deployment policy at the current trusted time.

The lease binds the proof digest, authenticated caller digest, exact signer process identity, accepted trust-state binding, deployment policy revision and digest, caller allowlist, registry snapshot, and the active Capability and Attestation key generations. Both governed trust snapshots are independently validated against the accepted registry.

The lease is invalid at or after the identity challenge expiry. A disabled role, stale proof, caller substitution, signer-instance substitution, trust-state divergence, policy divergence, registry rotation mismatch, or key-role substitution fails closed.

This slice does not expose an issuance command and does not enable `production_issuance_enabled`. The next orchestration layer must require a valid lease at the exact Capability or Attestation issuance boundary and must retain backend authorization replay state across lease refreshes.
