# Windows UI Automation Host v1

## Purpose

The Windows UI Automation host is the first production-oriented platform adapter behind the proof-bound Windows Bridge Protocol. It does not decide acceptance. It observes a Windows application, performs one bounded UI Automation action and reports the exact pre-state digest consumed by the action boundary.

## Runtime modes

The host supports three modes:

- `--stdio`: newline-delimited JSON request/response protocol over standard input and output,
- `--pipe <name>`: one current-user-only named-pipe session,
- `--self-test`: deterministic canonical JSON and protocol-envelope checks.

Protocol mode writes only JSON responses to standard output. Diagnostics and self-test messages use standard error.

## Supported control surface

v1 accepts only `UI_AUTOMATION` requests with a matching UI Automation selector. The selector must contain:

- a non-empty Automation ID,
- a supported control type.

The initial supported control types are Button, CheckBox, ComboBox, Edit, Hyperlink, List, ListItem, MenuItem, RadioButton, TabItem, Text, TreeItem and Window.

The initial supported actions are:

- `SET_VALUE` through `ValuePattern`,
- `INVOKE` through `InvokePattern`,
- `SELECT` through `SelectionItemPattern`.

Unsupported patterns, read-only targets and mismatched selection IDs fail closed.

## Process and executable identity

`application.instance_id` must use `pid:<positive integer>`.

Before target discovery, the host verifies:

- process name,
- executable file version,
- SHA-256 of the executable bytes,
- process instance ID.

The request application identity must exactly match the observed identity. The host does not continue after partial identity matches.

## Stable target resolution

The host obtains the process main window and creates the UI Automation root with `AutomationElement.FromHandle`. It searches descendant elements using both:

- `AutomationElement.AutomationIdProperty`,
- `AutomationElement.ControlTypeProperty`.

The resulting stable target ID is `ControlType/AutomationId` and is included in every observed state and adapter event.

## Cross-language state digest

Observed state is serialized with the same canonicalization rule as Proof Kernel:

- object keys are recursively sorted with ordinal comparison,
- array order is preserved,
- UTF-8 JSON is emitted without indentation,
- SHA-256 is encoded as lower-case hexadecimal.

The built-in self-test uses a fixed Unicode vector and an expected digest generated from the Rust canonical JSON rules. This prevents silent C# and Rust hashing divergence.

## Observation model

An observed state contains:

- exact application identity,
- stable target ID,
- sorted observable UI properties,
- artifact digest map,
- observation timestamp,
- canonical state digest.

Properties currently include Automation ID, control type, enabled/offscreen state and accessible name. Pattern-specific properties include current value/read-only state, toggle state and selection state.

## TOCTOU boundary

State digests include observation time, so a second observation cannot reproduce the first digest solely by re-reading the same UI. The host therefore uses a single-use observation cache:

1. `observe` resolves the target, measures state, computes the canonical digest and stores that observation.
2. `execute` must reference a digest produced by the same running host.
3. The cached observation is consumed exactly once.
4. The host resolves and observes the target again at the action boundary.
5. Application identity, target ID, properties and artifact digests must be identical to the cached state.
6. Only then is the UI Automation pattern invoked.
7. The adapter transition reports the original consumed pre-state digest.

Unknown, expired or already consumed pre-state digests fail closed. The cache is bounded to 128 recent observations.

## Adapter event

The event digest binds canonical JSON containing:

- action payload,
- consumed pre-state digest,
- host executable SHA-256,
- request ID,
- stable target ID.

The Rust Windows Bridge runtime later binds this event digest into the signed bridge record and independently verifies post-state success.

## Transport boundary

Stdio mode is intended for supervised subprocess execution. Named-pipe mode creates one byte-mode duplex server restricted to the current Windows user. The host validates pipe names and rejects path separators and colon characters.

Named-pipe current-user isolation is not a replacement for the higher-level capability receipt, plan binding and signed bridge record. Those controls remain in the Rust runtime.

## Automated verification

The Windows workflow performs:

1. .NET restore,
2. C# formatting verification,
3. Release build with warnings as errors,
4. built-in canonical JSON and protocol self-tests,
5. win-x64 framework-dependent publish,
6. a Rust integration test that starts the published host as a subprocess and validates one JSONL error response,
7. artifact upload for inspection.

## Deliberate limitations

- CI does not yet automate a real third-party design application.
- v1 does not support screenshots, OCR or visual-region verification.
- the host supports one named-pipe client and one command stream per process.
- target process access can fail across Windows integrity levels or protected processes.
- application-specific native APIs and signed plugins remain preferred over UI Automation where available.
- post-state acceptance remains exclusively in the Rust Windows Bridge and proof pipeline.
