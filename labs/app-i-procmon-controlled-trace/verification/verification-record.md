# Verification Record: Procmon Controlled Trace

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | APP-I-LAB-PROCMON-CONTROLLED |
| Related file/section | `labs/app-i-procmon-controlled-trace/README.md` |
| Claim | Procmon can observe controlled file and registry operations from a known PowerShell process during a bounded capture window. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture |  |
| VM / hardware |  |
| Secure Boot | Enabled / Disabled / Unknown |
| VBS | Enabled / Disabled / Unknown |
| HVCI | Enabled / Disabled / Unknown |
| Defender / EDR state |  |
| Tool versions | Procmon: ; PowerShell: |
| Symbol path | Optional |
| Commands / steps | Ran `scripts/do-controlled-activity.ps1` while Procmon captured with path/process filters. |
| Expected observation | File and registry operation patterns appear under `InternalsNoteBookProcmonLab` paths with matching PowerShell PID. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | Procmon is capture-window operation telemetry, not complete historical truth. |
| Follow-up | Repeat with stack capture and compare attribution quality/noise. |

---

## Evidence notes

```text
Paste concise Procmon event summaries or exported rows here.
Do not paste usernames, hostnames, proprietary EDR details, tokens, or sensitive paths.
```

---

## Conclusion wording

> On `<build/config>`, Procmon `<version>` observed `<operation classes>` from `<process/PID>` under `<test paths>`. This supports the controlled trace workflow with `<confidence>` confidence. It does not prove persistence, intent, or behavior outside the capture window.

