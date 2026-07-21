# Windows UI Automation Rust Client Integration v1

## Purpose

This runtime connects the proof-bound Rust Windows Bridge to the Windows-only .NET UI Automation host. It owns host process trust, JSONL transport and the exact state-machine required to preserve a single host observation across the Bridge Runtime execution boundary.

## Why priming is required

`execute_windows_bridge` expects the request to already contain the exact pre-state digest. It then asks its adapter for that pre-state before authorizing the action transition.

A fresh host `observe` command cannot be sent at that moment because observed state includes a timestamp and therefore receives a new digest. The client uses a priming sequence:

1. `prime(request)` sends one host `observe` command.
2. The caller copies the returned digest into `request.expected_pre_state_digest`.
3. Bridge Runtime calls adapter `observe`.
4. The client returns the locally primed state without another host command.
5. Bridge Runtime calls adapter `execute` with that digest.
6. The host consumes its matching single-use cached observation and performs the TOCTOU check.
7. Bridge Runtime calls adapter `observe` again.
8. The client sends a fresh host `observe` command for post-state verification.

The expected command sequence is therefore exactly `observe`, `execute`, `observe`.

## Client state machine

The Rust client has four internal states:

- `Idle`: no active transaction,
- `Primed`: host pre-state exists and has not been delivered to Bridge Runtime,
- `PreStateDelivered`: Bridge Runtime has received the pre-state and may request execution,
- `AwaitingPostState`: execution succeeded and the next observation must come from the host.

Request ID and pre-state digest are checked at every transition. Any out-of-order call, request substitution or digest substitution resets the client to `Idle` and fails closed.

## Host response validation

Every response is checked for:

- exact command kind,
- success/failure consistency,
- mandatory success payload,
- mandatory structured error on failure,
- absence of an error object on success,
- consumed pre-state equality on execute.

Host error codes and messages are preserved in typed `HostRejected` errors until the existing `WindowsBridgeAdapter` trait boundary, where they are rendered as deterministic text.

## Process trust

On Windows, `ChildJsonLineTransport`:

1. validates the configured trusted digest syntax,
2. reads the host executable bytes,
3. computes SHA-256,
4. refuses to spawn on mismatch,
5. starts the host with `--stdio`,
6. pipes stdin/stdout and inherits stderr,
7. writes one compact JSON command per line,
8. accepts one newline-terminated JSON response per command,
9. enforces a one-megabyte response limit,
10. terminates and reaps the child on drop.

The host binary cannot be replaced silently between deployment configuration and process launch without triggering the digest mismatch.

## Verification coverage

Cross-platform fake-transport tests cover:

- exact observe/execute/observe sequencing,
- no runtime use without priming,
- request ID substitution,
- host rejection preservation,
- consumed digest substitution,
- non-UIA request rejection before transport use.

The Windows workflow additionally:

- publishes the real .NET host,
- computes the published executable SHA-256,
- starts it through the digest-pinned Rust transport,
- verifies structured `PROCESS_NOT_FOUND` propagation,
- verifies that an incorrect trusted digest prevents process start.

## Deliberate limitations

- v1 proves process transport and state sequencing but does not yet automate a visible WPF test target.
- process startup has no configurable timeout yet.
- one Rust client owns one host process and one active transaction.
- named-pipe client transport is not implemented in Rust v1.
- final action acceptance remains in Windows Bridge Runtime after independent post-state validation and signed record construction.
