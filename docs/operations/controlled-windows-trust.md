# Controlled Windows trust, TPM/CNG and signer operations

This runbook is the operational contract for Issue #77 and complements the production trust contracts from Issues #39 and #60. Source-complete and hardware-executed are separate gates. A green hosted CI run is never physical TPM evidence.

## Release gate semantics

`tools/windows/controlled_trust_gate.py` emits only the hardware/operational gate. It does not declare the whole product release-ready.

- `PROVEN_HARDWARE_BACKED` requires one bound evidence set from a controlled Windows machine.
- Missing, incomplete, malformed, substituted, hosted-runner or software-backed evidence yields `UNKNOWN` and `hardware_operational_eligible=false`.
- A physical evidence file committed to the repository is not, by itself, authoritative. Release evidence consumes the artifact digest from the controlled-hardware workflow or an equivalent reviewed outside-CI ceremony.
- Hosted GitHub runners are verifier/test environments only. They never execute the promotion ceremony and never upload a physical-TPM artifact.

## Physical TPM promotion evidence

The JSON contract is `schemas/windows-physical-tpm-promotion-evidence.schema.json`. Promotion binds all of the following:

1. controlled Windows execution context and elevated Administrator status;
2. machine identity digest plus a reviewed machine-inventory digest;
3. a reviewed physical-hardware attestation digest and operator-quorum digest;
4. Windows TPM present/ready/enabled/activated observations;
5. exact `Microsoft Platform Crypto Provider` identity;
6. CNG hardware implementation flag present and software flag absent;
7. Capability and Attestation generations, public-key digests and provisioning-evidence digests;
8. non-exportable signing policy and key-possession evidence for both roles;
9. exact installation, recovery and governance-recovery receipt file digests;
10. a canonical ceremony digest over the complete public evidence document.

The provider hardware bit is necessary but not sufficient to claim that a machine is approved physical hardware. The controlled runner label plus reviewed machine/hardware/operator digests are separate mandatory inputs. This prevents hosted or generic virtualized CNG observations from silently upgrading themselves.

## Elevated provisioning ceremony

Preferred execution is the manually dispatched `Controlled Windows trust` workflow with `run_controlled_hardware=true`. The hardware job can only target a runner carrying all labels:

`self-hosted`, `windows`, `x64`, `ergaxiom-controlled-tpm`

The job is additionally bound to the `controlled-windows-production` GitHub Environment. Repository/environment configuration must provide reviewed values for signer manifest path, governance recovery receipt path, machine inventory digest, physical hardware attestation digest, operator quorum digest, and the next Capability/Attestation generations.

The ceremony fails before promotion unless the process is elevated, `Get-Tpm` reports a ready TPM, both CNG provisioning operations succeed, the provider/export/key-possession fields match policy, the signer is installed/validated as `LocalSystem`, installation evidence is captured, and the service recovery exercise succeeds.

Only public evidence is uploaded. Provisioning output contains public keys, hashes, policy statements and proof-of-possession signatures; no CNG signing-key material is exported.

## Signer service installation and recovery

The existing signer host remains the authority for SCM configuration. Installation validation checks the exact service identity and command line, `LocalSystem`, delayed automatic start, restricted privilege set, service SID, restart actions, service DACL, running process identity, executable path/digest, trust-state binding, caller allowlist and active CNG generations.

The recovery exercise captures before/after receipts around a real service restart. Validation requires the same deployment, machine, manifest, governance policy, trust state, enabled key identities and executable while requiring a new process identity. Substituting the machine, service process, executable, key generation or trust state is a hard failure.

## Governance-key custody and rotation

CNG Capability and Attestation keys use the Microsoft Platform Crypto Provider and a non-exportable signing-only policy. There is no private-key backup path. Backup material is public metadata only: registry snapshot, public key, policy digest, provisioning receipt, evidence digest, signed trust-state distribution and ceremony receipts.

Rotation procedure:

1. obtain quorum authorization for the planned next generation;
2. provision the next generation on approved physical TPM hardware;
3. verify the provisioning and physical-promotion evidence before registry mutation;
4. use the guarded registry rotation path with the expected revision and registry digest;
5. distribute the replacement signed trust state and verify its digest on the controlled signer host;
6. validate the active generation and capture installation evidence;
7. run and capture a recovery exercise;
8. retain old public records as retired history; never reuse the old public key for another role/generation.

Revocation procedure:

1. create an incident/revocation reason digest without placing sensitive incident material in public evidence;
2. quorum-authorize the revocation/recovery action;
3. revoke the affected generation using the guarded registry base revision/digest;
4. provision a fresh generation on approved hardware;
5. distribute the replacement trust state;
6. capture the governance recovery receipt, installation receipt and recovery receipt;
7. run the controlled trust gate before production issuance resumes.

The governance recovery receipt schema requires an increasing generation, public-only backup policy, old/new registry/trust digests, replacement provisioning/public-key binding, signed distribution digest, and at least two distinct quorum approvals. A missing receipt is release-blocking `UNKNOWN`.

## Hardware-executed acceptance ceremony

Source-complete acceptance can be reviewed and tested in normal CI. Hardware-executed acceptance remains incomplete until an operator performs this exact final ceremony on the controlled machine:

1. review and publish the machine inventory, physical hardware attestation and operator-quorum digests into the protected GitHub Environment;
2. confirm the self-hosted runner is the intended physical Windows machine and has the `ergaxiom-controlled-tpm` label;
3. ensure the runner account can perform the elevated ceremony and the signer manifest/trust paths are administrator-controlled;
4. manually dispatch `Controlled Windows trust` with `run_controlled_hardware=true`;
5. review the uploaded `controlled-windows-trust-<run_id>` artifact;
6. independently verify both provisioning evidence documents, `installation.json`, `recovery.json`, the governance recovery receipt, `physical-tpm-evidence.json`, and `controlled-trust-gate.json`;
7. record the exact artifact digests in release evidence.

Until those steps produce a successful controlled-hardware artifact, physical TPM assurance is **UNKNOWN**. No hosted CI result can substitute for it.
