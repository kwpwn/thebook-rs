# Verification Record: ETW Minimal Controlled Trace

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | CH10-LAB-ETW-MINIMAL-TRACE |
| Related file/section | `labs/ch10-etw-minimal-trace/README.md` |
| Claim | A short `logman` ETW session can capture scoped trace artifacts for controlled PowerShell activity. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture |  |
| VM / hardware |  |
| Admin/elevation |  |
| Defender / EDR state |  |
| Tool versions | PowerShell: ; logman: built-in ; tracerpt: built-in |
| Symbol path | Not required |
| Commands / steps | Ran `run-minimal-etw-trace.ps1`; reviewed ETL/summary/conversion artifacts. |
| Expected observation | `logman start` and `stop` succeed; ETL file is created; optional CSV conversion may succeed. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | Session/provider/filter/capture-window scoped; conversion may omit/render fields differently. |
| Follow-up | Verify provider-specific event IDs/fields on target build. |

---

## Evidence notes

```text
Paste concise trace-summary.txt and selected converted rows here.
Do not paste sensitive command lines, usernames, hostnames, or proprietary EDR details.
```

---

## Conclusion wording

> On `<build/config>`, `logman` captured `<artifact>` for provider `<provider>` during controlled activity. This supports scoped ETW trace collection with `<confidence>` confidence. It does not prove global telemetry coverage.

