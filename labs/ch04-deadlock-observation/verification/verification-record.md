# Verification Record: Deadlock Observation

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | CH04-LAB-DEADLOCK-OBSERVATION |
| Related file/section | `labs/ch04-deadlock-observation/README.md` |
| Claim | A two-thread critical-section lock-order inversion can be observed as a deadlock using console output and stack/lock evidence. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture | x64 |
| VM / hardware |  |
| Tool versions | Process Explorer: ; WinDbg: ; compiler: |
| Symbol path |  |
| Commands / steps | Built and ran `deadlock_demo.exe`; captured thread stacks and optional `!locks`. |
| Expected observation | Thread A waits for cs2 while holding cs1; thread B waits for cs1 while holding cs2. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | Stack/lock visibility depends on symbols and debugger/tool context. |
| Follow-up | Compare with fixed lock ordering variant. |

---

## Evidence notes

```text
Paste concise console and stack/lock observations here.
Do not paste usernames, hostnames, proprietary EDR details, or sensitive paths.
```

---

## Conclusion wording

> On `<build/config>`, two worker threads showed opposite lock ownership/wait relationships. This supports a user-mode lock-order deadlock with `<confidence>` confidence. It does not imply kernel scheduler failure.

