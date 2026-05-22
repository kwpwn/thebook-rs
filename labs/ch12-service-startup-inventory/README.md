# Lab: Service Startup Inventory and Execution Boundaries

## Status

Draft implementation. Designed as the first service startup evidence lab for Ch.12.

## Source

- Chapter: `chapters/ch12-startup-shutdown.md`
- Appendix: `appendices/app-i-sysinternals-practical-lab-manual.md`
- Supports: SCM, service configuration, startup type, service state, Event Log correlation.

## Goal

Inventory Windows services with built-in tools, select a harmless service, and distinguish service configuration from service execution state.

The core lesson:

> Service startup configuration is not the same as service execution. Startup type, current state, process hosting, and event evidence answer different questions.

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: Recommended for complete service metadata; read-only workflow by default.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Read-only if you do not change service configuration.

## Tested environment

Fill this after running the lab.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| Architecture |  |
| Admin/elevation |  |
| Defender/EDR state |  |
| PowerShell version |  |

## Requirements

- PowerShell.
- Built-in `sc.exe`.
- Optional: Autoruns for service/driver startup inventory.
- Optional: Process Explorer for service-host process correlation.

## Files

| File | Purpose |
|---|---|
| `scripts/capture-service-inventory.ps1` | Captures service configuration/state/process evidence |
| `expected-output/expected-service-evidence.md` | Expected evidence classes |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/ch12-service-startup-inventory.mmd` | Service evidence diagram |

## Steps

1. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\capture-service-inventory.ps1
```

2. Review the output folder printed by the script.

3. Inspect:

- `services.csv`
- `running-services.csv`
- `service-processes.csv`
- `sc-query-all.txt`
- `sc-qc-selected.txt`
- `system-service-events.xml` if event query succeeds.

4. Pick one selected service from `sc-qc-selected.txt`.

5. Write four separate statements:

```text
Configured startup type:
Current state:
Hosting process/PID:
Recent service event evidence:
```

6. Optional: open Process Explorer and correlate the service to its process when possible.

7. Complete `verification/verification-record.md`.

## Expected observations

- Service configuration includes start mode/start type.
- Runtime state can be running/stopped/paused independently of startup type.
- Some services share a `svchost.exe` host process.
- Event Log evidence may show service control events but query availability varies by permissions/log retention.

See `expected-output/expected-service-evidence.md`.

## Evidence to save

- Script output folder.
- Selected service notes.
- Optional Autoruns export for Services/Drivers tabs.
- Optional Process Explorer screenshot/notes.
- Completed verification record.

## Cleanup

No state cleanup required. This lab is read-only.

## Interpretation notes

### What this proves

- Service configuration and current service state can be captured separately.
- Running services can be correlated to process IDs where available.
- Event evidence can support timing but depends on log retention and query scope.

### What it does not prove

- It does not prove a service started at boot unless boot/log event timing supports it.
- It does not prove a service binary executed malicious behavior.
- It does not prove driver load for kernel drivers without driver/service/event corroboration.

### Correct report language

Weak:

> Auto-start service proves it ran.

Better:

> The service was configured for automatic startup and was running at observation time. Execution timing requires service control/event/process evidence.

## Creative extension

Compare one `Auto`, one `Manual`, and one `Disabled` service:

- configured startup type;
- current state;
- PID/process host;
- recent events.

Use the comparison to write a mini service evidence matrix.

## Open questions

- Which auto-start services are currently stopped?
- Which running services are manual-triggered?
- Which services share one `svchost.exe`?
- Which event IDs are present for service start/stop on your build?

