# Ergaxiom Windows UIA Test Target

This Windows-only WPF application is a controlled automation target for end-to-end Ergaxiom tests.

It opens one visible window containing an editable TextBox with:

- Automation ID: `copy-field`
- UI Automation control type: `Edit`
- initial value: `BEFORE`

The optional command line form below writes a readiness marker only after the window content has rendered:

```powershell
Ergaxiom.WindowsUiaTestTarget.exe --ready-file C:\temp\ergaxiom-uia-ready.txt
```

The Rust integration test launches this executable, waits for the marker, computes the executable SHA-256, builds an exact Windows application identity, primes the real UI Automation host, executes `SET_VALUE` through the signed Windows Bridge Runtime and independently verifies the post-state value `APPROVED`.

This program exists only for deterministic CI and development verification. It is not a production application adapter.
