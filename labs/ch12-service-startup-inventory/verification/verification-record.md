# Verification Record: Service Startup Inventory

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | CH12-LAB-SERVICE-STARTUP-INVENTORY |
| Related file/section | `labs/ch12-service-startup-inventory/README.md` |
| Claim | Service startup configuration, current runtime state, hosting process, and service events are separate evidence classes. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture |  |
| VM / hardware |  |
| Admin/elevation |  |
| Defender / EDR state |  |
| Tool versions | PowerShell: ; sc.exe: built-in |
| Symbol path | Not required |
| Commands / steps | Ran `capture-service-inventory.ps1`; reviewed services/config/state/process/event outputs. |
| Expected observation | Output separates start mode, current state, process ID/path, and recent SCM events. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | Log retention, permissions, service triggers, and shared hosts affect interpretation. |
| Follow-up | Correlate with Autoruns, Process Explorer, Event Logs, and boot timeline. |

---

## Evidence notes

```text
Paste concise selected-service comparison here.
Do not paste hostnames, usernames, internal service names, or proprietary EDR details unless sanitized.
```

---

## Conclusion wording

> On `<build/config>`, service `<name>` had startup config `<mode>` and current state `<state>` with `<process/event evidence>`. This supports service evidence separation with `<confidence>` confidence. It does not by itself prove boot-time execution.

