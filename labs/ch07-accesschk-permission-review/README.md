# Lab: AccessChk Permission Review

## Status

Draft implementation. Designed as the first permission and ACL interpretation lab for Ch.7.

## Source

- Chapter: `chapters/ch07-security.md`
- Appendix: `appendices/app-i-sysinternals-practical-lab-manual.md`
- Supports: tokens, DACLs, access checks, integrity and privilege caveats.

## Goal

Create a controlled file artifact, inspect its permissions with built-in tooling and optional Sysinternals AccessChk, then write a correct access-control conclusion.

The core lesson:

> A permission listing describes configured access policy. It does not prove access was attempted, granted, denied, or used.

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: No for the default file lab.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Low-risk; creates a temporary file and directory under `%TEMP%`.

## Tested environment

Fill this after running the lab.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| Architecture |  |
| File system |  |
| Account type |  |
| Defender/EDR state |  |
| AccessChk version |  |
| PowerShell version |  |

## Requirements

- PowerShell.
- Built-in `icacls`.
- Optional: `accesschk.exe` from Sysinternals.

## Files

| File | Purpose |
|---|---|
| `scripts/create-permission-artifact.ps1` | Creates/removes a controlled file artifact |
| `expected-output/expected-permissions.md` | Expected permission observations |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/ch07-accesschk-permission-review.mmd` | Permission evidence diagram |

## Steps

1. Create the artifact:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\create-permission-artifact.ps1 -Action Create
```

2. Record the printed path.

3. Inspect permissions with built-in tooling:

```powershell
$path = "$env:TEMP\InternalsNoteBookAclLab\controlled.txt"
icacls $path
Get-Acl $path | Format-List
```

4. Optional AccessChk review:

```bat
accesschk.exe -accepteula -q -v "%TEMP%\InternalsNoteBookAclLab\controlled.txt"
```

5. Optional directory review:

```bat
accesschk.exe -accepteula -q -v "%TEMP%\InternalsNoteBookAclLab"
```

6. Remove the artifact:

```powershell
.\scripts\create-permission-artifact.ps1 -Action Remove
```

7. Complete `verification/verification-record.md`.

## Expected observations

- File exists under `%TEMP%\InternalsNoteBookAclLab`.
- ACL output shows owner, inherited ACEs, and explicit/inherited permissions depending on parent directory policy.
- AccessChk may normalize permissions differently from `icacls`.
- Output describes configured permission state, not historical access.

See `expected-output/expected-permissions.md`.

## Evidence to save

- Script output.
- `icacls` output.
- `Get-Acl` summary.
- Optional AccessChk output.
- Completed verification record.

Do not commit raw output if it exposes usernames, domain names, hostnames, internal paths, or enterprise policy.

## Cleanup

Run:

```powershell
.\scripts\create-permission-artifact.ps1 -Action Remove
```

Verify:

```powershell
Test-Path "$env:TEMP\InternalsNoteBookAclLab"
```

Expected: `False`.

## Interpretation notes

### What this proves

- The file had the listed owner and ACL at observation time.
- Built-in and Sysinternals tools can present overlapping but differently formatted permission evidence.
- Permission evidence can support access-risk analysis.

### What it does not prove

- It does not prove the file was accessed.
- It does not prove access would always succeed for every token state.
- It does not prove a privilege was enabled or used.
- It does not prove effective access against PPL, integrity policy, share permissions, or other boundaries not represented by the file DACL alone.

### Correct report language

Weak:

> Everyone permission proves everyone accessed the file.

Better:

> The file ACL at observation time allowed `<principal/right>` according to `<tool>`. This is configured access exposure. Actual access requires process/token/runtime evidence.

## Creative extension

Create a second file with inheritance disabled and compare:

- inherited vs explicit ACEs;
- owner;
- `icacls` formatting vs AccessChk formatting;
- how your report wording changes.

Keep this as a permission interpretation lab, not an exploitation lab.

## Open questions

- Which ACEs are inherited from `%TEMP%`?
- Does AccessChk show the same effective rights as `icacls`?
- Which principal would matter for a service process vs an interactive user?
- What runtime evidence would prove access was attempted?

