# Verification Record: Ch.4 Thread Wait Reasons

Use this record after running the lab in a real Windows VM.

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | CH04-LAB-WAIT-REASONS |
| Related file/section | `labs/ch04-thread-wait-reasons/README.md` |
| Claim | Different blocking primitives produce distinguishable wait-state evidence when correlated with TID, stack, and tool view. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture | x64 |
| VM / hardware |  |
| Secure Boot | Enabled / Disabled / Unknown |
| VBS | Enabled / Disabled / Unknown |
| HVCI | Enabled / Disabled / Unknown |
| Defender / EDR state |  |
| Tool versions | Process Explorer: ; WinDbg: ; compiler: |
| Symbol path |  |
| Commands / steps | Build and run `src/wait_reasons_demo.c`; inspect threads in Process Explorer; optional WinDbg thread stack/fields. |
| Expected observation | `event-waiter`, `alertable-sleeper`, and `delay-sleeper` show distinct wait evidence when matched by TID and stack. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | Tool labels and enum names may vary across Windows/tool versions. |
| Follow-up | Compare Windows 10 22H2 vs Windows 11 23H2/24H2 labels. |

---

## Evidence notes

```text
Paste concise console output, Process Explorer notes, or WinDbg output here.
Do not paste hostnames, usernames, proprietary EDR details, or sensitive paths.
```

---

## Conclusion wording

> On `<build/config>`, `<tool/version>` showed `<observation>`. This supports the wait-reason interpretation with `<confidence>` confidence. The result may differ across Windows builds, Process Explorer versions, symbol state, and debugger context.

