# Lab: ETW Minimal Controlled Trace

## Status

Draft implementation. Designed as the first controlled ETW trace session lab after provider inventory.

## Source

- Chapter: `chapters/ch10-management-diagnostics-tracing.md`
- Appendix: `appendices/app-f-etw-provider-field-guide.md`
- Builds on: `labs/ch10-etw-provider-inventory/`

## Goal

Create a short ETW trace session for a known provider, generate a controlled PowerShell activity, stop the session, and interpret the resulting trace as bounded telemetry evidence.

The core lesson:

> A trace session proves what that session captured under its provider/filter/buffer configuration. It is not universal historical truth.

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: Recommended; required on some systems for `logman start`.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Low-risk but creates a temporary `.etl` file and a short trace session.

## Tested environment

Fill this after running the lab.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| Architecture |  |
| Admin/elevation |  |
| Defender/EDR state |  |
| PowerShell version |  |
| logman version | built-in |

## Requirements

- PowerShell.
- Built-in `logman`.
- Built-in `tracerpt` for optional CSV conversion.

## Files

| File | Purpose |
|---|---|
| `scripts/run-minimal-etw-trace.ps1` | Starts/stops trace session and generates controlled activity |
| `expected-output/expected-trace-artifacts.md` | Expected ETL/CSV artifacts |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/ch10-etw-minimal-trace.mmd` | Trace-session evidence diagram |

## Steps

1. Run PowerShell as administrator if possible.

2. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\run-minimal-etw-trace.ps1
```

3. Review the output folder printed by the script.

4. Inspect:

- `trace.etl`
- `trace-report.csv` if conversion succeeded
- `trace-summary.txt`
- `logman-start.txt`
- `logman-stop.txt`

5. Complete `verification/verification-record.md`.

## Expected observations

- A temporary trace session named `InternalsNoteBookEtwLab` starts and stops.
- The script emits simple PowerShell activity during the capture window.
- An `.etl` file is created.
- `tracerpt` may produce CSV/XML output depending on provider rendering and permissions.
- Captured fields vary by provider, OS build, and tool rendering.

See `expected-output/expected-trace-artifacts.md`.

## Evidence to save

- Output folder file list.
- Trace start/stop output.
- ETL path and size.
- Optional CSV summary.
- Completed verification record.

Do not commit raw ETL from sensitive systems.

## Cleanup

The script attempts to stop the trace session. If interrupted, run:

```powershell
logman stop InternalsNoteBookEtwLab -ets
```

Delete the output folder if it contains sensitive data.

## Interpretation notes

### What this proves

- A controlled ETW trace session was created for a provider.
- Activity occurred during the capture window.
- The session produced trace artifacts.

### What it does not prove

- It does not prove all provider events were captured.
- It does not prove Event Log persistence.
- It does not prove EDR coverage.
- It does not prove historical activity outside the capture window.

### Correct report language

Weak:

> ETW proves PowerShell activity is always logged.

Better:

> This `logman` session captured trace data while controlled PowerShell activity occurred. The evidence is scoped to the provider/session configuration, capture window, and tool rendering.

## Creative extension

Run the same lab twice:

1. elevated PowerShell;
2. non-elevated PowerShell.

Compare session start success, event volume, and output conversion. Use the difference to document privilege requirements for collection.

## Open questions

- Does your system allow non-admin trace session creation?
- Which fields survive `tracerpt` conversion?
- Does active EDR add concurrent trace sessions?
- What changed from provider inventory to actual trace capture?

