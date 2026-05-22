# Verification Record: Autoruns Startup Inventory

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | APP-I-LAB-AUTORUNS-STARTUP |
| Related file/section | `labs/app-i-autoruns-startup-inventory/README.md` |
| Claim | Autoruns/autorunsc can observe a controlled HKCU Run startup configuration entry, but that observation alone does not prove execution. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture |  |
| VM / hardware |  |
| Secure Boot | Enabled / Disabled / Unknown |
| VBS | Enabled / Disabled / Unknown |
| HVCI | Enabled / Disabled / Unknown |
| Defender / EDR state |  |
| Tool versions | Autoruns/autorunsc: ; PowerShell: |
| Symbol path | Not required |
| Commands / steps | Ran `set-hkcu-run-marker.ps1 -Action Create`; captured Autoruns before/after; removed marker. |
| Expected observation | Marker absent before, present after create, absent after remove. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | Configuration evidence only; execution needs separate runtime/logon artifacts. |
| Follow-up | Repeat with logoff/logon and collect process/event artifacts. |

---

## Evidence notes

```text
Paste concise Autoruns rows, registry query output, and cleanup confirmation here.
Do not paste usernames, hostnames, proprietary EDR details, or sensitive paths.
```

---

## Conclusion wording

> On `<build/config>`, Autoruns `<version>` showed `<marker state>` for `InternalsNoteBookRunMarker` under HKCU Run. This supports the startup-configuration observation with `<confidence>` confidence. It does not prove execution.

