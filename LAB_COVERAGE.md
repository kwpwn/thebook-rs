# Lab Coverage Summary

This file is the quick map from chapters to extracted lab artifacts.

---

## Coverage by chapter

| Chapter / appendix | Lab coverage | Status |
|---|---|---|
| Ch.1 Concepts and Tools | `ch01-process-token-comparison`, baseline/procmon/autoruns/winobj labs | Strong practical base |
| Ch.2 System Architecture | Indirect via baseline/process/service labs | Needs architecture-specific lab |
| Ch.3 Processes and Jobs | Baseline, WinObj namespace | Needs handle inheritance/process tree lab |
| Ch.4 Threads | `ch04-thread-wait-reasons`, `ch04-deadlock-observation` | Good thread foundation |
| Ch.5 Memory Management | `ch05-vmmap-memory-layout`, `ch05-windbg-vad-corroboration` | Good memory foundation |
| Ch.6 I/O System | Procmon, WinObj, ADS/hardlink partial | Needs device/file handle lab |
| Ch.7 Security | `ch01-process-token-comparison`, `ch07-accesschk-permission-review` | Good token/ACL base |
| Ch.8 System Mechanisms | WinObj, thread waits, deadlock | Needs APC/symlink/named event variants |
| Ch.9 Virtualization Technologies | None direct | Needs VBS/HVCI state observation lab |
| Ch.10 Diagnostics/Tracing | `ch10-etw-provider-inventory`, `ch10-etw-minimal-trace`, Procmon | Good ETW/telemetry base |
| Ch.11 Caching/File Systems | `ch11-ads-streams-file-artifacts`, `ch11-hardlink-file-identity`, Procmon | Good file artifact base |
| Ch.12 Startup/Shutdown | `ch12-service-startup-inventory`, Autoruns | Needs boot logging/timeline lab |
| Appendix C WinDbg | VAD corroboration, thread labs optional | Needs dump triage lab |
| Appendix F ETW | Provider inventory, minimal trace | Needs provider-specific records |
| Appendix I Sysinternals | Baseline, Procmon, Autoruns, WinObj, VMMap, AccessChk | Strong |

---

## Extracted labs

| Lab | Primary evidence skill |
|---|---|
| `app-i-sysinternals-baseline` | Baseline inventory |
| `app-i-procmon-controlled-trace` | Operation telemetry |
| `app-i-autoruns-startup-inventory` | Startup configuration |
| `app-i-winobj-object-namespace` | Object namespace and handles |
| `ch01-process-token-comparison` | Token/security context |
| `ch04-thread-wait-reasons` | Thread wait interpretation |
| `ch04-deadlock-observation` | Lock ownership/wait causality |
| `ch05-vmmap-memory-layout` | Memory layout |
| `ch05-windbg-vad-corroboration` | Cross-tool memory corroboration |
| `ch07-accesschk-permission-review` | ACL/permission interpretation |
| `ch10-etw-provider-inventory` | Provider/session inventory |
| `ch10-etw-minimal-trace` | Session-scoped ETW capture |
| `ch11-ads-streams-file-artifacts` | Stream-aware file content |
| `ch11-hardlink-file-identity` | Path vs file identity |
| `ch12-service-startup-inventory` | Service config/state/process/event separation |

---

## Best next labs

1. `ch11-usn-file-timeline`
2. `ch04-threadpool-attribution`
3. `ch12-boot-logging-evidence`
4. `ch03-handle-inheritance`
5. `ch09-vbs-hvci-state-observation`
6. `app-c-dump-triage-workflow`

