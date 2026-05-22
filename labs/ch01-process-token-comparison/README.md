# Lab: Process Token Comparison

## Status

Draft implementation. Designed as the first security-context lab.

## Source

- Chapter: `chapters/ch01-concepts-and-tools.md`
- Original section: `Lab 1.1 — Quan sát Process Hierarchy và Token`
- Supports: Ch.3 process model, Ch.7 security, Appendix I Process Explorer workflow.

## Goal

Compare standard-user and elevated process tokens, then write a precise statement about integrity level and privileges.

The core lesson:

> Admin membership, elevated token, integrity level, and specific privileges are related but not identical.

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: Yes for elevated comparison.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Read-only.

## Tested environment

Fill this after running the lab.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| Architecture |  |
| UAC state |  |
| Account type | Local admin / domain user / standard user |
| Process Explorer version |  |
| PowerShell version |  |

## Requirements

- PowerShell.
- Process Explorer from Sysinternals.
- Ability to launch one normal PowerShell and one elevated PowerShell.

## Files

| File | Purpose |
|---|---|
| `scripts/capture-token-context.ps1` | Captures `whoami /all` and process identity context |
| `expected-output/expected-token-differences.md` | Expected comparison points |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/ch01-process-token-comparison.mmd` | Token comparison diagram |

## Steps

1. Open normal PowerShell.

2. Run:

```powershell
.\scripts\capture-token-context.ps1 -Label standard
```

3. Open PowerShell as administrator.

4. Run:

```powershell
.\scripts\capture-token-context.ps1 -Label elevated
```

5. Open Process Explorer.

6. Find both PowerShell processes.

7. Compare:

- Integrity level.
- User.
- Groups.
- Privileges.
- Parent process.
- Command line.

8. Save sanitized notes or screenshots.

9. Complete `verification/verification-record.md`.

## Expected observations

- Standard PowerShell should usually run at Medium integrity.
- Elevated PowerShell should usually run at High integrity.
- Elevated token should expose more enabled/available privileges.
- Admin group membership alone does not mean every process is elevated.
- Some privileges may exist but be disabled until explicitly enabled.

See `expected-output/expected-token-differences.md`.

## Evidence to save

- `whoami /all` output for standard context.
- `whoami /all` output for elevated context.
- Process Explorer Security tab notes or sanitized screenshots.
- Process Explorer parent/command-line notes.
- Completed verification record.

## Cleanup

Close PowerShell and Process Explorer.

## Interpretation notes

### What this proves

- Two processes under the same user can have different integrity levels and privilege states.
- UAC splits normal and elevated admin contexts.
- Process Explorer and `whoami /all` can corroborate token-level observations.

### What it does not prove

- It does not prove the user is SYSTEM.
- It does not prove a privilege is actively used.
- It does not prove an access attempt would succeed without checking ACLs and enabled privilege state.
- It does not describe PPL-protected access by itself.

### Correct report language

Weak:

> The user is admin, so the process has all privileges.

Better:

> The elevated PowerShell process ran at High integrity and showed additional privileges compared with the standard PowerShell process. Specific access still depends on ACLs, enabled privilege state, integrity policy, and target protection level.

## Creative extension

Use Process Explorer to inspect a service-hosted process and compare it with user PowerShell.

Write down:

- user account;
- integrity level;
- session;
- service relationship;
- privileges that differ.

Do not assume SYSTEM means unrestricted access to PPL-protected processes.

## Open questions

- Which privileges are present but disabled?
- Does your elevated shell have `SeDebugPrivilege`?
- How does domain policy change group and privilege output?
- Which Process Explorer fields are point-in-time snapshots?

