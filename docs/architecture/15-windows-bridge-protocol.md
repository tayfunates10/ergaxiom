# Windows Bridge Protocol v1

## Scope

This phase defines the proof boundary for constrained Windows execution. It does not yet ship a production UI Automation host, accessibility host or native application plugin. It defines what every future Windows adapter must observe, consume, execute, report and sign before its result can participate in verified work.

## Non-negotiable rule

A click, keystroke, command invocation or API return is not proof of success.

The bridge may report `SUCCEEDED` only when independently observed post-state satisfies every declared postcondition. An adapter event remains evidence that an action was attempted, not evidence that the intended effect occurred.

## Control-method priority

Requests explicitly identify one method:

1. native document/application model,
2. application API,
3. signed application plugin,
4. CLI,
5. Windows UI Automation,
6. accessibility state,
7. visually confirmed interaction,
8. coordinate fallback.

Each method has a matching selector type. A CLI request cannot carry a UI Automation selector, and a coordinate fallback cannot be disguised as a native-object request.

## Authorization boundary

Before observing or acting, the bridge verifies:

- exact compiled Work Contract and Operator Plan binding,
- exact step and operator identity,
- executor and optional device identity,
- canonical Authorization Receipt digest,
- token identity declared by the plan step,
- exact capability grant present in the sealed Work Contract,
- exact request/receipt grant equality.

The bridge consumes an Authorization Receipt produced by Capability Runtime. It does not accept an unverified token ID or caller-provided permission claim.

## Application identity

Every request and observed state includes:

- application ID,
- application version,
- executable digest,
- process/application instance ID.

Observation from another executable, version or instance fails before action. This prevents a selector match in an unexpected or replaced application from being treated as the intended target.

## State observation and TOCTOU

The adapter first returns a canonical pre-state containing application identity, stable target ID, observed properties, artifact digests and trusted observation time.

The request carries the expected pre-state digest. The adapter action must report the exact pre-state digest it consumed at the action boundary. The bridge rejects when:

- the observed digest differs from the request,
- the adapter consumed a different digest,
- application or stable target identity changed.

This detects time-of-check/time-of-use changes at the critical execution boundary.

## Postconditions

Every request must include at least one independently observable postcondition:

- property equality,
- artifact digest equality,
- stable target identity equality.

Visual and coordinate fallbacks must include a property or artifact effect assertion. Stable-region identity alone is insufficient because it proves only that the same region was observed, not that the requested effect occurred.

After action, the bridge observes state again and independently evaluates all postconditions. Failed assertions create indexed violations and a signed `FAILED` record. They never become success through model confidence or adapter optimism.

## Signed record

The bridge signs canonical record payload bytes with Ed25519. The payload binds:

- request digest,
- Authorization Receipt digest,
- observed and consumed pre-state digests,
- observed post-state digest,
- adapter event digest,
- independently computed status and violations,
- bridge identity and record time.

The verifier independently recomputes request policy, receipt/plan/contract bindings, state digests, TOCTOU equality, postcondition result and signature validity. Package, state, payload or signature mutation is detected.

## Adapter contract

A platform adapter implements two operations:

- `observe(request)` returns canonical observable state,
- `execute(request, expected_pre_state_digest)` performs the bounded action and reports the actually consumed pre-state digest plus an adapter-event digest.

The adapter cannot decide acceptance. It cannot omit post-state observation. It cannot convert a failed assertion into success.

## Automated adversarial coverage

The protocol suite exercises real Ed25519 capability authorization and a deterministic adapter across these boundaries:

- independently verified UI Automation success,
- stale expected pre-state rejection before action,
- adapter-side TOCTOU mismatch rejection,
- executable/application identity mismatch rejection,
- request grant mismatch rejection before observation,
- control-method and selector mismatch rejection,
- signed `FAILED` records for unmet postconditions,
- coordinate fallback rejection without an observable effect,
- coordinate fallback acceptance only after effect observation,
- signed-record payload mutation detection,
- post-state mutation detection,
- deterministic package reproduction for identical inputs and keys.

## Deliberate limitations

- v1 defines protocol and verifier behavior, not a production Windows service.
- executable and adapter-event digests are supplied by the host and must later be backed by signed host identity and measured binaries.
- screenshot/vision evidence formats are not yet standardized.
- UI Automation element snapshots and application-specific native models will be added as separate adapters behind this protocol.
- Windows privilege isolation, named-pipe authentication and host process hardening remain required before real desktop execution.
