# Desktop Product Shell

## Scope

This gate adds the Windows-first Tauri 2 and React product shell for the bounded Graphic Designer static-post workflow. The shell is a control and inspection surface, not a new trust authority.

## Authoritative data path

The read-only desktop command constructs one deterministic snapshot through the existing Rust boundaries:

1. structured intent is compiled by `ergaxiom-intent-contract-compiler-runtime`;
2. the generated Work Contract is recompiled and sealed by Contract Runtime;
3. `ergaxiom-typed-planner-runtime` synthesizes the four-step Operator Plan;
4. Operator Plan Runtime recompiles and seals that plan;
5. Graphic Designer Twin executes the plan through Occupational Twin and Operator Simulation Runtime;
6. independent Twin validators produce report digests;
7. Desktop Shell Runtime validates every displayed digest and derives the UI authority status;
8. the Tauri command re-verifies the complete snapshot digest before returning it over IPC.

The React renderer never computes an authoritative status. It renders the Rust-derived snapshot and additionally applies fail-closed display guards.

## Required views

The shell contains:

- immutable input staging and unresolved mandatory questions;
- Work Contract identity and digest;
- exact pre-execution approval bindings for contract, plan and permission set;
- sealed Operator Plan identity;
- execution timeline with before and after workspace digests;
- validator results and actionable failure text;
- Evidence Bundle, replay manifest and Acceptance Certificate inspection;
- Profession Capsule, adapter and trusted-key status.

## Capability boundary

The `main` window receives only the custom `get_desktop_shell_snapshot` command plus Tauri core defaults. It receives no filesystem, shell, unrestricted network, process-execution or signing-key capability.

The snapshot command is read-only. Approval and real execution controls remain disabled until future commands are added behind their own narrowly scoped permissions and exact digest-bound approval records.

## Acceptance semantics

The UI may display `verified_accepted` only when all of these values originate in one digest-verified Rust snapshot:

- certificate signature verified;
- Evidence Bundle verified;
- certificate decision accepted;
- zero mandatory unknowns;
- zero mandatory failures.

Changing frontend state, JSON or labels cannot create a valid snapshot digest. A missing backend, malformed digest, contradictory certificate or IPC failure produces a blocked fail-closed display.

The current deterministic Twin snapshot intentionally contains no final signed Evidence Bundle or Acceptance Certificate. It therefore demonstrates the complete product flow through simulation and validation while remaining `ready`, not accepted.

## Testing and packaging

Permanent CI must run:

- Rust formatting, Clippy and tests for Desktop Shell Runtime;
- TypeScript type checking, frontend unit tests and production Vite build;
- Tauri Rust tests and a Windows `tauri build --no-bundle` compile;
- capability configuration validation performed by Tauri build tooling.

The frontend tests prove that a renderer-only status mutation cannot forge acceptance and that approval or execution controls remain locked until their exact prerequisites are verified.

## Claim boundary

This gate provides a production-shaped, accessible, keyboard-navigable desktop shell and proves its read-only trust boundary. It does not add unrestricted natural-language interpretation, user-driven artifact selection, writable approvals, real execution controls, production signing-key loading or a signed Windows release installer. Those remain separate capability-gated work.
