# Lab: Procmon Controlled File and Registry Trace

## Status

Draft implementation. Designed as the first controlled telemetry lab after baseline capture.

## Source

- Chapter: `chapters/ch01-concepts-and-tools.md`
- Original section: `Lab 1.2 — Quan sát System Calls với Process Monitor`
- Appendix: `appendices/app-i-sysinternals-practical-lab-manual.md`
- Related concepts: Win32 API to kernel operations, file I/O, registry I/O, telemetry limits, evidence correlation.

## Goal

Generate a small, controlled set of file and registry operations, observe them with Process Monitor, and write a disciplined interpretation that separates:

- operation telemetry,
- artifact state,
- process attribution,
- and unknowns.

This lab is intentionally more controlled than "open Notepad and save a file" because a scripted action gives you known expected events and a repeatable cleanup path.

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: Recommended for Procmon; the scripted action itself can run as normal user.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Low-risk but still creates files, registry keys, and Procmon artifacts.

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
| Procmon version |  |
| PowerShell version |  |

## Requirements

- Process Monitor from Sysinternals.
- PowerShell.
- Write access to `%TEMP%`.
- Registry write access under `HKCU:\Software`.

## Files

| File | Purpose |
|---|---|
| `scripts/do-controlled-activity.ps1` | Creates predictable file and registry activity |
| `expected-output/expected-events.md` | Expected Procmon event patterns |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/app-i-procmon-controlled-trace.mmd` | Trace interpretation pipeline |

## Steps

1. Open Process Monitor as administrator.

2. Stop capture with `Ctrl+E`.

3. Clear existing events with `Ctrl+X`.

4. Add filters:

| Column | Relation | Value | Action |
|---|---|---|---|
| Process Name | is | `powershell.exe` or `pwsh.exe` | Include |
| Path | contains | `InternalsNoteBookProcmonLab` | Include |
| Path | contains | `Software\InternalsNoteBookProcmonLab` | Include |

If your shell is different, filter by `Path contains InternalsNoteBookProcmonLab` first, then refine by PID.

5. Start capture with `Ctrl+E`.

6. Run the controlled activity:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\do-controlled-activity.ps1
```

7. Stop capture after the script prints `done`.

8. Save the Procmon capture as `.PML` outside the repo, or export a filtered CSV/TXT summary if you want to keep a sanitized artifact.

9. Compare observed events with `expected-output/expected-events.md`.

10. Complete `verification/verification-record.md`.

## Expected observations

You should see event patterns for:

- directory create/open/query under `%TEMP%\InternalsNoteBookProcmonLab`;
- file create/write/read/query/close for `controlled-file.txt`;
- registry create/set/query/delete under `HKCU\Software\InternalsNoteBookProcmonLab`;
- process attribution to the PowerShell process that ran the script.

Exact event order, additional metadata queries, and result codes vary by Windows build, PowerShell version, security product, and Procmon configuration.

## Evidence to save

- Procmon `.PML` or sanitized CSV/TXT export.
- Console output from the script.
- Filter configuration notes.
- PID of the PowerShell process.
- Completed verification record.

## Cleanup

The script deletes its test file and registry key by default. If cleanup fails:

```powershell
Remove-Item "$env:TEMP\InternalsNoteBookProcmonLab" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\InternalsNoteBookProcmonLab" -Recurse -Force -ErrorAction SilentlyContinue
```

Stop Procmon capture before leaving the lab.

## Interpretation notes

### What Procmon proves here

- Procmon observed file and registry operations from a process during the capture window.
- The script's known actions provide a ground truth for expected operation classes.
- Path, operation, result, timestamp, process, and stack fields can be correlated into an evidence note.

### What Procmon does not prove

- It does not prove every kernel operation on the machine.
- It does not prove physical disk persistence.
- It does not prove historical behavior outside the capture window.
- It does not prove maliciousness.
- It does not replace USN/MFT/Event Log/ETW/EDR correlation for serious investigations.

### Better report language

Weak:

> Procmon proves the file was maliciously written.

Better:

> Procmon observed `powershell.exe` performing `CreateFile` and `WriteFile` operations on `<path>` during the capture window. The script-controlled context makes this expected activity. Persistence and intent require additional evidence.

## Creative extension

Run the lab twice:

1. once with only path/process filters;
2. once with stack capture enabled and symbols configured.

Compare how much attribution improves when stack data is available. Then write down the cost: noise, symbol dependency, larger PML files, and possible privacy exposure.

## Open questions

- Which unexpected metadata queries appear before or after your controlled write?
- Does Defender/EDR add extra file or registry operations around the test artifact?
- How much does stack capture change file size and interpretation quality?
- Which fields would you normalize into a detection pipeline?

