# Ergaxiom Windows UI Automation Host

This project is the Windows-only execution adapter for `UI_AUTOMATION` requests produced by the Ergaxiom Windows Bridge runtime.

## Build

```powershell
dotnet restore .\hosts\windows-uia\Ergaxiom.WindowsUiaHost.csproj
dotnet build .\hosts\windows-uia\Ergaxiom.WindowsUiaHost.csproj -c Release
```

## Self-test

```powershell
dotnet run --project .\hosts\windows-uia\Ergaxiom.WindowsUiaHost.csproj -c Release -- --self-test
```

The self-test checks the C# implementation against a fixed canonical JSON SHA-256 vector compatible with the Rust Proof Kernel and validates the JSON protocol envelope.

## Stdio service

```powershell
.\Ergaxiom.WindowsUiaHost.exe --stdio
```

The process reads one JSON command per line and writes exactly one JSON response per line. Protocol logs never use standard output.

Supported command kinds:

- `observe`: resolves and records the current target state,
- `execute`: consumes a prior state digest once and performs the bounded UI Automation action after a semantic TOCTOU check.

## Named-pipe service

```powershell
.\Ergaxiom.WindowsUiaHost.exe --pipe ergaxiom-uia-session
```

The pipe accepts one duplex client and is restricted to the current Windows user. The Rust capability, plan and receipt checks remain mandatory outside the host.

## Request requirements

- `control_method` must be `UI_AUTOMATION`.
- `selector.selector` must be `UI_AUTOMATION`.
- `application.instance_id` must use `pid:<positive integer>`.
- process name, executable version and executable SHA-256 must exactly match the request.
- target selection uses both Automation ID and Control Type.
- `execute` requires a pre-state digest returned by the same running host instance.

## Supported actions

- `SET_VALUE` using `ValuePattern`,
- `INVOKE` using `InvokePattern`,
- `SELECT` using `SelectionItemPattern`.

The host reports an attempted transition only. Final post-state verification, signed bridge records and work acceptance remain responsibilities of the Rust Windows Bridge and proof pipeline.
