# Verification Record: ETW Provider Inventory

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | CH10-LAB-ETW-PROVIDER-INVENTORY |
| Related file/section | `labs/ch10-etw-provider-inventory/README.md` |
| Claim | Built-in tools can inventory ETW provider metadata and active trace sessions, but provider availability does not prove telemetry coverage. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture |  |
| VM / hardware |  |
| Admin/elevation |  |
| Defender / EDR state |  |
| Tool versions | PowerShell: ; logman: built-in |
| Symbol path | Not required |
| Commands / steps | Ran `capture-etw-inventory.ps1`; reviewed provider/session/channel outputs. |
| Expected observation | Provider metadata and active trace session inventory files are created. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | Inventory does not prove event emission, capture, field stability, or EDR coverage. |
| Follow-up | Run controlled trace session and verify event fields for a specific provider/build. |

---

## Evidence notes

```text
Paste concise provider/session observations here.
Do not paste proprietary EDR/session names or internal product details unless sanitized.
```

---

## Conclusion wording

> On `<build/config>`, built-in tooling listed `<provider/session metadata>`. This supports ETW inventory with `<confidence>` confidence. It does not prove relevant events were emitted or captured.

