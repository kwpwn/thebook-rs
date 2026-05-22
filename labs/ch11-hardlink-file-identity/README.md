# Lab: Hardlink File Identity

## Status

Draft implementation. Designed as the second Ch.11 file artifact lab after ADS.

## Source

- Chapter: `chapters/ch11-caching-file-systems.md`
- Supports: path vs identity, hard links, file IDs, forensic artifact interpretation.

## Goal

Create two paths that point to the same file content through a hard link, modify one path, and observe why path alone is not file identity.

The core lesson:

> A path is a name. File identity requires file ID/link count/metadata correlation.

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: No.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Low-risk; creates temporary files under `%TEMP%`.

## Tested environment

Fill this after running the lab.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| File system | NTFS / ReFS / other |
| Architecture |  |
| PowerShell version |  |
| fsutil available | Yes / No |

## Requirements

- PowerShell.
- Built-in `fsutil` recommended.
- NTFS volume recommended.

## Files

| File | Purpose |
|---|---|
| `scripts/create-hardlink-artifact.ps1` | Creates/removes hardlink artifact |
| `expected-output/expected-hardlink-observations.md` | Expected observations |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/ch11-hardlink-file-identity.mmd` | Path vs identity diagram |

## Steps

1. Create artifact:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\create-hardlink-artifact.ps1 -Action Create
```

2. Record printed paths.

3. Read both paths:

```powershell
Get-Content "$env:TEMP\InternalsNoteBookHardlinkLab\original.txt"
Get-Content "$env:TEMP\InternalsNoteBookHardlinkLab\alias.txt"
```

4. Modify one path:

```powershell
Add-Content "$env:TEMP\InternalsNoteBookHardlinkLab\alias.txt" "written through alias"
```

5. Read the other path again:

```powershell
Get-Content "$env:TEMP\InternalsNoteBookHardlinkLab\original.txt"
```

6. Inspect hardlink/file ID data:

```powershell
fsutil hardlink list "$env:TEMP\InternalsNoteBookHardlinkLab\original.txt"
fsutil file queryFileID "$env:TEMP\InternalsNoteBookHardlinkLab\original.txt"
fsutil file queryFileID "$env:TEMP\InternalsNoteBookHardlinkLab\alias.txt"
```

7. Remove artifact:

```powershell
.\scripts\create-hardlink-artifact.ps1 -Action Remove
```

8. Complete `verification/verification-record.md`.

## Expected observations

- Both paths show the same content.
- Writing through `alias.txt` changes content seen through `original.txt`.
- `fsutil hardlink list` shows both names.
- File ID should match for both paths on NTFS.

See `expected-output/expected-hardlink-observations.md`.

## Evidence to save

- Script output.
- Before/after content reads.
- `fsutil hardlink list` output.
- File ID outputs.
- Completed verification record.

## Cleanup

Run:

```powershell
.\scripts\create-hardlink-artifact.ps1 -Action Remove
```

Verify:

```powershell
Test-Path "$env:TEMP\InternalsNoteBookHardlinkLab"
```

Expected: `False`.

## Interpretation notes

### What this proves

- Two paths can name the same file identity.
- Path-based evidence can be incomplete.
- File ID/link count helps correlate names to one underlying file.

### What it does not prove

- It does not prove historical access through either path.
- It does not prove maliciousness.
- It does not prove behavior on non-NTFS file systems.
- It does not replace USN/MFT timeline evidence.

### Correct report language

Weak:

> These are two different files because they have different paths.

Better:

> The two paths resolved to the same file identity/link set at observation time. Path-level reporting alone would overcount or misattribute the artifact.

## Creative extension

Capture Procmon during the write through `alias.txt`. Compare the path Procmon sees with the file identity evidence from `fsutil`.

## Open questions

- Does your file system support hard links?
- Does your tool report link count?
- Which path appears in telemetry when writing through the alias?
- How would USN Journal represent the rename/link/write sequence?

