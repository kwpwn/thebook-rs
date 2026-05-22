# Lab: Alternate Data Streams and File Artifact Boundaries

## Status

Draft implementation. Designed as the first Ch.11 file-artifact lab.

## Source

- Chapter: `chapters/ch11-caching-file-systems.md`
- Supports: NTFS streams, path vs identity, file artifact interpretation, Sysinternals Streams.

## Goal

Create a normal file and an alternate data stream (ADS), observe the difference with PowerShell and Sysinternals Streams, then write a bounded file-artifact conclusion.

The core lesson:

> A path can have multiple named streams. Seeing the default stream is not the same as enumerating all file content associated with that file record.

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: No.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Low-risk; creates a temporary test file under `%TEMP%`.

## Tested environment

Fill this after running the lab.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| File system | NTFS / ReFS / other |
| Architecture |  |
| Defender/EDR state |  |
| Streams version |  |
| PowerShell version |  |

## Requirements

- PowerShell.
- Optional: `streams.exe` from Sysinternals.
- NTFS volume recommended.

## Files

| File | Purpose |
|---|---|
| `scripts/create-ads-artifact.ps1` | Creates and removes a file with ADS |
| `expected-output/expected-streams.md` | Expected stream observations |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/ch11-ads-streams-file-artifacts.mmd` | Stream evidence diagram |

## Steps

1. Create the test artifact:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\create-ads-artifact.ps1 -Action Create
```

2. Record the printed file path.

3. Read the default stream:

```powershell
Get-Content "$env:TEMP\InternalsNoteBookAdsLab\sample.txt"
```

4. Read the ADS:

```powershell
Get-Content "$env:TEMP\InternalsNoteBookAdsLab\sample.txt" -Stream "research"
```

5. List streams with PowerShell:

```powershell
Get-Item "$env:TEMP\InternalsNoteBookAdsLab\sample.txt" -Stream *
```

6. Optional Streams check:

```bat
streams.exe -accepteula "%TEMP%\InternalsNoteBookAdsLab\sample.txt"
```

7. Remove the test artifact:

```powershell
.\scripts\create-ads-artifact.ps1 -Action Remove
```

8. Complete `verification/verification-record.md`.

## Expected observations

- Default stream contains visible normal content.
- ADS named `research` contains separate content.
- Directory listing may not make ADS obvious.
- PowerShell `-Stream *` or Sysinternals Streams should enumerate the ADS.
- Removing the file removes associated streams.

See `expected-output/expected-streams.md`.

## Evidence to save

- Script output.
- `Get-Item -Stream *` output.
- Optional `streams.exe` output.
- Completed verification record.

## Cleanup

Run:

```powershell
.\scripts\create-ads-artifact.ps1 -Action Remove
```

Verify the directory is gone:

```powershell
Test-Path "$env:TEMP\InternalsNoteBookAdsLab"
```

Expected: `False`.

## Interpretation notes

### What this proves

- NTFS can store multiple named streams for one file.
- Stream-aware tooling is required to enumerate ADS.
- Default stream content alone is incomplete file-content evidence.

### What it does not prove

- It does not prove maliciousness.
- It does not prove execution.
- It does not prove all file systems behave the same way.
- It does not prove forensic recovery after deletion.

### Correct report language

Weak:

> The file is clean because normal read shows harmless text.

Better:

> The default stream contains harmless text, but stream enumeration also found a named `research` stream. Full file-content interpretation requires stream-aware collection.

## Creative extension

Capture Procmon while creating the ADS and compare:

- normal file write;
- ADS write path syntax;
- metadata queries;
- cleanup operations.

Then write a note connecting Ch.6 I/O telemetry and Ch.11 file-system artifact interpretation.

## Open questions

- Does your EDR/AV scan ADS content at creation time?
- Does the file system support ADS on your test volume?
- How does copying the file to a non-NTFS volume change stream preservation?
- What artifacts remain after deletion?

