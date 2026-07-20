# Repository Layout

Ergaxiom is a polyglot monorepo. The proof kernel, platform bridges, model-assisted services and desktop UI remain separated so that trust boundaries are visible in both code and ownership.

```text
ergaxiom/
├── apps/
│   └── desktop/                 # Tauri + React user interface
├── crates/
│   ├── proof-kernel/            # Rust acceptance and evidence core
│   ├── contract-model/          # Canonical typed contract model
│   ├── policy-engine/           # Capability and permission decisions
│   └── trace-model/             # Execution trace and conformance types
├── bridges/
│   ├── windows/                 # C#/.NET Windows execution bridge
│   └── applications/            # Versioned application-specific adapters
├── services/
│   ├── contract-compiler/       # Model-assisted intent-to-contract service
│   ├── planner/                 # Typed operator-plan synthesis
│   └── perception/              # Visual interpretation, never final proof
├── schemas/                     # Normative machine-readable contracts
├── professions/                 # Versioned profession capsules
├── validators/                  # Independent deterministic validators
├── examples/                    # Example contracts and evidence bundles
├── evals/                       # Certification, adversarial and regression tasks
├── tools/                       # Repository and schema validation tools
├── docs/                        # Architecture, threat model and roadmap
└── .github/workflows/           # CI and security automation
```

## Trust boundary rules

### `crates/proof-kernel`

This is the authoritative acceptance boundary. It must not depend on a language model, UI automation implementation or application-specific SDK.

### `services/*`

Services may use probabilistic models to interpret or propose. Their outputs are untrusted until converted into typed structures and accepted by deterministic policy and proof checks.

### `bridges/*`

Bridges execute capability-scoped operations and report observed state. They cannot issue final acceptance decisions.

### `validators/*`

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

A profession capsule references operators and validators by stable IDs and pinned versions. A capsule cannot grant itself broader system permissions than the installed policy allows.

## Dependency direction

Allowed high-level direction:

```text
UI → services → typed contracts → proof kernel
planner → profession capsule → operator interfaces
bridges → trace events → proof kernel
validators → proof results → proof kernel
```

Forbidden direction:

```text
proof kernel → language model
proof kernel → desktop UI
proof kernel → application-specific SDK
validator → executor's unverified success flag
```

## Initial implementation order

Directories are created only when they contain executable code, tests or a normative specification. The project will not add empty placeholder trees solely to appear complete.

1. Stabilize schemas and foundation validation.
2. Implement Rust contract and proof types.
3. Implement acceptance-state property tests.
4. Add isolated workspace and trace model.
5. Add the first independent image validators.
6. Add Windows and application bridges after the proof boundary exists.
