# Repository Layout

Ergaxiom is a polyglot monorepo. The proof kernel, platform bridges, model-assisted services and desktop UI remain separated so that trust boundaries are visible in both code and ownership.

```text
ergaxiom/
├── apps/
│   ├── desktop/                 # Tauri + React product shell
│   └── windows-*/               # Provisioning and signer-service executables
├── crates/
│   ├── proof-kernel/            # Three-valued acceptance and canonical hashing
│   ├── *-runtime/               # Typed contract, plan, execution and evidence boundaries
│   ├── *-certified-path-runtime/# Bounded profession certification chains
│   └── windows-*/               # Windows bridge, trust and signer boundaries
├── hosts/                       # Controlled .NET UI Automation hosts and targets
├── schemas/                     # Normative machine-readable contracts
├── professions/
│   ├── catalog.json             # Digest-bound installed-capsule allowlist
│   └── */profession.json        # Versioned profession capsules
├── examples/                    # Example intents, plans and Work Contracts
├── fixtures/                    # Pinned real-application fixtures
├── tools/                       # Validation, release evidence and safe scaffolding
├── docs/                        # Architecture, threat model and roadmap
└── .github/workflows/           # CI and security automation
```

## Trust boundary rules

### `crates/proof-kernel`

This is the authoritative acceptance boundary. It must not depend on a language model, UI automation implementation or application-specific SDK.

### Compiler and planner runtimes

Intent compilers and planners may propose only the typed profiles they explicitly implement. Their outputs remain untrusted until the Contract Runtime and Operator Plan Runtime independently compile and seal them.

### Execution bridges and certified-path runtimes

Bridges execute capability-scoped operations and report observed state. Certified-path runtimes may assemble evidence, but acceptance still requires independent Evidence Runtime reassessment and governed attestation issuance.

### Independent validator runtimes

Validators must declare:

- supported claims,
- implementation version,
- deterministic or stochastic behavior,
- independence class,
- required evidence inputs,
- measurement uncertainty or tolerance,
- failure and unknown semantics.

Critical validators must not share the same hidden implementation path as the operator they verify.

### `professions/*`

A profession capsule references operators and validators by stable IDs and pinned versions. Every installed capsule must also appear in `professions/catalog.json` with its exact canonical digest and job inventory. A capsule or catalog entry cannot grant broader system permissions than the installed policy allows.

### `apps/desktop`

The renderer displays backend-produced state and submits bounded approval/control requests. It cannot read signing material, select signer identities, load arbitrary capsules or create accepted evidence.

## Dependency direction

Allowed high-level direction:

```text
UI → backend commands → typed contracts → proof kernel
planner → cataloged profession capsule → operator interfaces
bridges → signed trace events → execution/evidence runtimes
validators → proof results → evidence runtime → attestation runtime
```

Forbidden direction:

```text
proof kernel → language model
proof kernel → desktop UI
proof kernel → application-specific SDK
validator → executor's unverified success flag
profession catalog → unrestricted dynamic code loading
```

## Profession extension order

Directories are created only when they contain executable code, tests or a normative specification. The project does not add empty placeholder trees solely to appear complete.

1. Scaffold a draft, production-disabled catalog entry.
2. Define typed jobs, operators, constraints, validators and assurance policy.
3. Add example Work Contracts and deterministic compiler/planner profiles.
4. Implement isolated execution and independent evidence paths.
5. Add mutation, fuzz, adversarial and real-application regressions.
6. Promote a job only after its bounded path reaches an independently verified certificate.
