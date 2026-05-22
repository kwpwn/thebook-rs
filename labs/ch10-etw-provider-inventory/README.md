# Lab: ETW Provider Inventory

## Status

Draft implementation. Safe first ETW lab for provider/channel/session inventory.

## Source

- Chapter: `chapters/ch10-management-diagnostics-tracing.md`
- Appendix: `appendices/app-f-etw-provider-field-guide.md`
- Supports: ETW provider discovery, Event Log vs ETW boundaries, provider field verification.

## Goal

Inventory ETW providers, inspect selected provider metadata, list active trace sessions, and write a bounded evidence statement.

The core lesson:

> Provider availability is not telemetry coverage. Active sessions, filters, channels, and event persistence determine what evidence exists.

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: Recommended for fuller session/provider visibility.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Read-only inventory.

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
| Tooling | logman, Get-WinEvent |

## Requirements

- PowerShell.
- Built-in `logman`.
- Built-in `Get-WinEvent`.

## Files

| File | Purpose |
|---|---|
| `scripts/capture-etw-inventory.ps1` | Captures provider/session/channel metadata |
| `expected-output/expected-inventory.md` | Expected output files and interpretation |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/ch10-etw-provider-inventory.mmd` | ETW inventory evidence diagram |

## Steps

1. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\capture-etw-inventory.ps1
```

2. Review the output folder printed by the script.

3. Inspect:

- `logman-providers.txt`
- `active-trace-sessions.txt`
- `eventlog-providers.csv`
- `selected-provider-*.txt`

4. Pick one provider from the selected-provider output and write:

```text
Provider exists: yes/no
Active session collecting it: observed/not observed/unknown
Event Log channel linked: yes/no/unknown
Fields verified: no, inventory only
```

5. Complete `verification/verification-record.md`.

## Expected observations

- Many providers are listed.
- Active sessions vary by system and security tooling.
- Some providers have Event Log channel metadata.
- Inventory output does not prove events were emitted or captured.

See `expected-output/expected-inventory.md`.

## Evidence to save

- Script output folder.
- Selected provider notes.
- Active trace session notes.
- Completed verification record.

Do not commit raw provider/session inventory from enterprise systems if it reveals security tooling or internal product names.

## Cleanup

No state cleanup required. This lab is read-only.

## Interpretation notes

### What this proves

- The system exposed provider/session/channel metadata through built-in tools at observation time.
- Selected providers could be inspected for metadata.
- Active sessions could be listed.

### What it does not prove

- It does not prove events were emitted.
- It does not prove events were captured.
- It does not prove event fields are stable across builds.
- It does not prove EDR coverage.

### Correct report language

Weak:

> This provider exists, so the behavior is logged.

Better:

> The provider was listed on this build, but this inventory does not show that a session captured relevant events. Coverage requires session/channel/event evidence.

## Creative extension

Choose a provider relevant to a chapter claim and create a verification record for its schema on two Windows builds.

Compare provider name/GUID, event list, task/opcode names, field/template hints, and channel links.

## Open questions

- Which active sessions are present before you start any lab?
- Which providers link to Event Log channels?
- Which provider metadata changes between Windows 10 and Windows 11?
- Which event fields are rendered differently by different tools?

