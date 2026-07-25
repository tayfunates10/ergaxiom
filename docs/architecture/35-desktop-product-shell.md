# Desktop Product Shell and Control Authority

## Scope

This gate extends the Windows-first Tauri 2 and React product shell with a narrowly scoped writable control lifecycle for the bounded Graphic Designer static-post workflow. The renderer remains an inspection and request surface; the Rust backend is the sole authority for approval, execution, cancellation, rollback and command receipts.

## Authoritative data path

The desktop backend constructs and verifies each snapshot through the existing Rust boundaries:

1. structured intent is compiled by `ergaxiom-intent-contract-compiler-runtime`;
2. the generated Work Contract is recompiled and sealed by Contract Runtime;
3. `ergaxiom-typed-planner-runtime` synthesizes the four-step Operator Plan;
4. Operator Plan Runtime recompiles and seals that plan;
5. Graphic Designer Twin prepares the deterministic Occupational Twin result;
6. Desktop Shell Runtime validates every displayed digest and derives the UI authority status;
7. Desktop Control Authority owns the lifecycle state and exposes execution material only after exact approval;
8. every returned snapshot, approval record and command receipt is independently digest-verified before IPC response.

The React renderer never computes an authoritative status, approval identity, command receipt or acceptance decision. It submits only the currently displayed digest tuple and renders the verified backend response.

## Digest-bound approval

The approval request contains exactly:

- current snapshot digest;
- sealed Work Contract digest;
- sealed Operator Plan digest;
- capability and permission requirement digest.

The backend rejects stale snapshot digests, altered tuples, unresolved mandatory fields, non-passed contract or plan state and invalid approval transitions. A successful approval record includes the job and actor identity, issue and expiry timestamps, the complete digest tuple and a canonical approval digest. Product Alpha approval lifetime is bounded to fifteen minutes; the runtime rejects unbounded or expired approvals.

## Execution lifecycle

The backend control state is one of:

- `awaiting_approval`;
- `approved`;
- `executed`;
- `cancelled`;
- `rolled_back`.

Execution requires the exact backend approval digest and the current approved snapshot. Before execution, plan steps remain pending and validator or replay evidence is not exposed. After execution, the deterministic Twin step digests, validator reports and replay manifest become visible. Cancellation is permitted only before execution. Rollback is permitted only after one completed execution and requires the same exact approval binding.

Every applied transition creates a canonical command receipt binding:

- action and command identity;
- local actor and job identity;
- pre-snapshot digest;
- post-snapshot digest;
- approval digest when required;
- trusted backend timestamp;
- receipt digest.

Renderer mutation, replay of an old snapshot or alteration of any receipt field fails closed.

## Required views

The shell contains:

- immutable input staging and unresolved mandatory questions;
- Work Contract identity and digest;
- exact pre-execution approval bindings for contract, plan and permission set;
- backend approval review with the complete tuple;
- sealed Operator Plan identity;
- execution timeline with before and after workspace digests;
- backend command receipt audit table;
- validator results and actionable failure text;
- Evidence Bundle, replay manifest and Acceptance Certificate inspection;
- Profession Capsule, adapter and trusted-key status.

## Capability boundary

The `main` window receives only five custom commands plus Tauri core defaults:

- `get_desktop_shell_snapshot`;
- `approve_desktop_job`;
- `start_desktop_job_execution`;
- `cancel_desktop_job`;
- `rollback_desktop_job`.

The window receives no filesystem, shell, unrestricted network, arbitrary process-execution or signing-key capability. The commands operate only on the in-memory locally sealed Product Alpha fixture and cannot authorize arbitrary applications or files.

## Acceptance semantics

Execution success is not Acceptance Certificate success. The UI may display `verified_accepted` only when all of these values originate in one digest-verified Rust snapshot:

- certificate signature verified;
- Evidence Bundle verified;
- certificate decision accepted;
- zero mandatory unknowns;
- zero mandatory failures.

The current control lifecycle intentionally contains no final production Evidence Bundle or Acceptance Certificate. It can approve and execute the deterministic Twin while remaining `ready`, never certified accepted.

## Testing and packaging

Permanent CI runs:

- Rust formatting, Clippy and attack tests for Desktop Shell Runtime;
- stale snapshot, altered tuple, expired approval, receipt mutation and invalid transition fixtures;
- Tauri backend lifecycle tests for approval, execution, cancellation and rollback;
- TypeScript checking, frontend action-gate tests and production Vite build;
- a Windows `tauri build --no-bundle` compile and capability configuration validation.

## Claim boundary

This gate provides an in-memory digest-bound Windows Product Alpha control lifecycle. Approval and receipts are canonical hashes, not production signatures. It does not add persistent jobs, user-selected artifacts, unrestricted natural-language interpretation, DPAPI or TPM key storage, revocation, release signing, signed installers or production Acceptance Certificate issuance. Those remain separately gated by Issue #39.
