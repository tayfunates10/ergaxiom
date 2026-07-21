# Windows UI Automation Real Action Verification v1

## Purpose

This phase proves that the Rust Windows UIA client, the .NET UI Automation host and the signed Windows Bridge Runtime can perform and independently verify one real Windows UI action against a controlled visible WPF application.

## Controlled target

The test target is a Windows-only WPF executable with a visible main window and one editable TextBox:

- Automation ID: `copy-field`,
- UI Automation control type: `Edit`,
- initial ValuePattern value: `BEFORE`.

The target writes a readiness file only after `ContentRendered`. The Rust test does not attempt discovery until that marker exists. The target executable has a fixed file version of `1.0.0.0`; its SHA-256 is computed from the published bytes during the test.

## End-to-end sequence

1. Compile the Graphic Designer Work Contract and a one-step `design.compose_text` Operator Plan.
2. Issue and cryptographically verify a single-use capability token for the exact plan step.
3. Produce the canonical Authorization Receipt used by Windows Bridge Runtime.
4. Start the published WPF target and wait for the render readiness marker.
5. Build exact application identity from process ID, configured process name, fixed file version and published executable digest.
6. Start the published UI Automation host through the digest-pinned Rust child-process transport.
7. Prime the Rust UIA client with a real host observation.
8. Confirm the pre-state ValuePattern property is `BEFORE`.
9. Copy the observed digest into the sealed Windows Bridge request.
10. Run `execute_windows_bridge` with the real Rust UIA client adapter.
11. The host consumes the same single-use pre-state, rechecks semantic UI state and invokes `ValuePattern.SetValue("APPROVED")`.
12. The client requests a fresh post-state observation.
13. Windows Bridge independently evaluates `value == APPROVED`.
14. Windows Bridge signs the record with Ed25519.
15. An independent verifier recomputes request, receipt, application, target, state, TOCTOU, postcondition and signature bindings.

## Acceptance conditions

The test succeeds only when all of the following are true:

- the target process remains alive until discovery,
- host and target executable identities match the request,
- the primed state reports `BEFORE`,
- the host reports consuming the exact primed digest,
- the post-state reports `APPROVED`,
- the signed bridge status is `SUCCEEDED`,
- there are zero postcondition violations,
- independent signed-package verification returns `SUCCEEDED`.

A UI Automation method return alone is never accepted as success.

## CI boundary

The Windows workflow restores, formats, builds and publishes both the host and target. It then runs:

- the existing host JSONL protocol test,
- digest-pinned Rust client transport tests,
- the real WPF action test through the signed Bridge Runtime.

Both published executable directories are retained as a short-lived CI artifact for inspection.

## Deliberate limitations

- the target is controlled and does not represent a third-party design application.
- v1 validates `ValuePattern.SetValue`; InvokePattern and SelectionItemPattern remain protocol-tested but do not yet have visible target scenarios.
- the GitHub Windows runner must provide a desktop session capable of creating a WPF main window and exposing UI Automation.
- screenshot and visual evidence remain outside this phase.
- production application adapters still require application-specific selectors, version support matrices and recovery logic.
