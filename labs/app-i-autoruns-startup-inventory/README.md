# Lab: Autoruns Startup Inventory and Evidence Boundaries

## Status

Draft implementation. Designed as the first startup-configuration evidence lab.

## Source

- Chapter: `chapters/ch01-concepts-and-tools.md`
- Related section: `Lab 1.4 — Xem Registry Startup/Autorun Configuration Locations`
- Appendix: `appendices/app-i-sysinternals-practical-lab-manual.md`
- Supports: Ch.7 security, Ch.10 diagnostics, Ch.12 startup/shutdown, Appendix D forensics.

## Goal

Create and remove a harmless HKCU Run entry, observe it with Autoruns or `autorunsc`, and write a correct evidence statement.

The core lesson:

> Startup configuration is evidence of a configured execution opportunity. It is not proof that execution happened.

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: No for HKCU Run; recommended for full Autoruns inventory.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Low-risk but modifies current-user startup configuration during the lab.

## Tested environment

Fill this after running the lab.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| Architecture |  |
| Secure Boot |  |
| VBS/HVCI |  |
| Defender/EDR state |  |
| Autoruns / autorunsc version |  |
| PowerShell version |  |

## Requirements

- PowerShell.
- Autoruns or `autorunsc.exe` from Sysinternals.
- Access to `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`.

## Files

| File | Purpose |
|---|---|
| `scripts/set-hkcu-run-marker.ps1` | Creates or removes a harmless HKCU Run marker |
| `expected-output/expected-autoruns-findings.md` | Expected Autoruns/registry observations |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/app-i-autoruns-startup-inventory.mmd` | Config vs execution evidence diagram |

## Steps

1. Capture current startup inventory:

```powershell
autorunsc.exe -accepteula -a l -ct > "$env:TEMP\autoruns-before.csv"
```

If you prefer GUI, open Autoruns and save an `.ARN` or CSV export.

2. Create a harmless HKCU Run marker:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\set-hkcu-run-marker.ps1 -Action Create
```

3. Confirm the registry value exists:

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |
    Select-Object InternalsNoteBookRunMarker
```

4. Capture Autoruns again:

```powershell
autorunsc.exe -accepteula -a l -ct > "$env:TEMP\autoruns-after-create.csv"
```

5. Compare the before/after files or search for:

```text
InternalsNoteBookRunMarker
```

6. Remove the marker:

```powershell
.\scripts\set-hkcu-run-marker.ps1 -Action Remove
```

7. Capture final inventory:

```powershell
autorunsc.exe -accepteula -a l -ct > "$env:TEMP\autoruns-after-remove.csv"
```

8. Complete `verification/verification-record.md`.

## Expected observations

- Before create: marker absent.
- After create: marker present under current-user Logon/Run locations.
- After remove: marker absent again.
- Autoruns may display publisher/signature status for the referenced executable.
- No execution is proven unless you collect logon/process creation evidence separately.

See `expected-output/expected-autoruns-findings.md`.

## Evidence to save

- `autoruns-before.csv`
- `autoruns-after-create.csv`
- `autoruns-after-remove.csv`
- PowerShell output.
- Registry query output.
- Completed verification record.

Do not commit raw Autoruns output if it exposes usernames, paths, internal software, security tooling, or enterprise policy.

## Cleanup

Run:

```powershell
.\scripts\set-hkcu-run-marker.ps1 -Action Remove
```

Then verify:

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |
    Select-Object InternalsNoteBookRunMarker
```

The selected property should be empty or absent.

## Interpretation notes

### What Autoruns proves here

- A startup configuration entry exists or existed at capture time.
- The entry points to a command path/value.
- The entry is in a known autorun location.

### What Autoruns does not prove

- It does not prove the command executed.
- It does not prove the user logged on after the entry was created.
- It does not prove malicious intent.
- It does not prove the referenced file still exists or ran successfully.

### Correct report language

Weak:

> Autoruns proves this program persisted and executed.

Better:

> Autoruns shows an HKCU Run configuration entry named `InternalsNoteBookRunMarker` at capture time. This is persistence configuration evidence. Execution would require correlation with logon time, process creation, Prefetch/Amcache/ShimCache/UserAssist where applicable, Event Logs, EDR telemetry, or other runtime artifacts.

## Creative extension

Build a three-column evidence matrix:

| Question | Evidence needed | This lab provides |
|---|---|---|
| Was startup configured? | Autoruns/registry | Yes |
| Did logon happen after configuration? | logon/session evidence | No |
| Did target process execute? | process creation/runtime artifacts | No |

Then repeat the lab after a sign-out/sign-in and compare Autoruns with process/runtime artifacts.

## Open questions

- Which Autoruns category contains your marker?
- Does `autorunsc` output differ from the GUI export?
- Does your EDR/Defender create telemetry when the Run key is created?
- What additional artifacts would prove execution after logon?

