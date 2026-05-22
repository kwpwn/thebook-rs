# Verification Record: Sysinternals Baseline Capture

Use this record after running the baseline workflow.

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | APP-I-LAB-BASELINE |
| Related file/section | `labs/app-i-sysinternals-baseline/README.md` |
| Claim | A baseline package was captured and can be used for later process/service/driver/minifilter/startup diffs. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture |  |
| VM / hardware |  |
| Secure Boot | Enabled / Disabled / Unknown |
| VBS | Enabled / Disabled / Unknown |
| HVCI | Enabled / Disabled / Unknown |
| Defender / EDR state |  |
| Tool versions | PowerShell: ; Sysinternals: |
| Symbol path | Not required |
| Commands / steps | Ran `scripts/capture-baseline.ps1`; captured Process Explorer/Autoruns/optional Procmon exports. |
| Expected observation | Baseline directory contains context, process, service, driver, minifilter, network, and optional Sysinternals artifacts. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | Snapshot in time; not proof of historical execution or hidden kernel state. |
| Follow-up | Re-run after a controlled change and compare deltas. |

---

## Evidence notes

```text
Paste concise file list, selected context fields, or summary notes here.
Do not paste usernames, hostnames, proprietary EDR details, tokens, or sensitive paths.
```

---

## Conclusion wording

> On `<build/config>`, the baseline captured `<artifact list>`. This supports later comparison for process/service/driver/minifilter/startup state with `<confidence>` confidence. It is a point-in-time baseline and does not prove historical execution or hidden state.

