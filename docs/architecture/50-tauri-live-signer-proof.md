# Tauri Live Production Signer Proof

## Startup gate

After the administrator-controlled deployment configuration and DACL chain are verified, the Rust backend creates a 32-byte nonce with the operating-system CSPRNG. The nonce is encoded as lowercase SHA-256-shaped hexadecimal text and is never supplied by the renderer.

The backend builds a purpose-locked challenge valid for at most 30 seconds and calls `ProductionSignerPipeClient::prove_identity`. The response must bind the exact backend caller allowlist entry, accepted deployment/trust state, registry and active Attestation generation. Production issuance remains disabled regardless of proof success in this slice.

## Single-use state

Only one identity challenge may be active. Every challenge digest is retired after the exchange, including transport failures. A bounded retired set rejects reuse without allowing unbounded memory growth.

## Restart and recovery

The first valid live proof establishes the process-instance baseline. A different signed service identity is treated as a restart and changes the public phase to `recovery_required`. The new instance is accepted only after a second fresh recovery challenge proves the same pending identity. A moving or repeatedly restarting service never clears the gate.

## Renderer boundary

Public status exposes only bounded booleans, phase codes, public configuration digests/revisions and the last successful proof time. Process IDs, creation times, instance nonce, executable paths, principal SID, pipe identity and proof digest remain backend-only.

## Failure behavior

Missing service or transport failure maps to `service_unavailable`. Invalid proof, challenge, caller binding, clock, nonce or replay state maps to `service_rejected`. All paths keep `production_issuance_enabled` false.
