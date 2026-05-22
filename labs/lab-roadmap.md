# Lab Roadmap

This file turns the lab folder into a learning path. Use it to decide what to run next and what evidence skill each lab trains.

---

## Recommended order

| Order | Lab | Skill trained | Best before reading |
|---|---|---|---|
| 1 | [Sysinternals Baseline Capture](app-i-sysinternals-baseline/README.md) | Build a trustworthy before-state | Any practical chapter |
| 2 | [Procmon Controlled Trace](app-i-procmon-controlled-trace/README.md) | Interpret operation telemetry without overclaiming | Ch.6, Ch.10, Ch.11 |
| 3 | [Autoruns Startup Inventory](app-i-autoruns-startup-inventory/README.md) | Separate startup config from execution evidence | Ch.10, Ch.12 |
| 4 | [WinObj Object Namespace](app-i-winobj-object-namespace/README.md) | Observe named objects and handle attribution | Ch.3, Ch.6, Ch.8 |
| 5 | [Process Token Comparison](ch01-process-token-comparison/README.md) | Compare integrity, groups, and privilege state | Ch.1, Ch.7 |
| 6 | [AccessChk Permission Review](ch07-accesschk-permission-review/README.md) | Interpret ACLs as configured access policy | Ch.7 |
| 7 | [VMMap Memory Layout](ch05-vmmap-memory-layout/README.md) | Classify heap, private, mapped, stack, and image regions | Ch.5 |
| 8 | [ADS and Streams](ch11-ads-streams-file-artifacts/README.md) | Enumerate default stream vs alternate streams | Ch.11 |
| 9 | [Hardlink File Identity](ch11-hardlink-file-identity/README.md) | Separate path from file identity | Ch.11 |
| 10 | [Thread Wait Reasons](ch04-thread-wait-reasons/README.md) | Correlate thread waits with role, stack, and tool view | Ch.4, Ch.8 |
| 11 | [Deadlock Observation](ch04-deadlock-observation/README.md) | Prove deadlock with ownership/wait evidence | Ch.4 |
| 12 | [WinDbg VAD Corroboration](ch05-windbg-vad-corroboration/README.md) | Cross-check VMMap with debugger memory evidence | Ch.5, Appendix C |
| 13 | [ETW Provider Inventory](ch10-etw-provider-inventory/README.md) | Inventory providers/sessions without overclaiming coverage | Ch.10, Appendix F |
| 14 | [ETW Minimal Trace](ch10-etw-minimal-trace/README.md) | Run a scoped trace session and interpret ETL artifacts | Ch.10, Appendix F |
| 15 | [Service Startup Inventory](ch12-service-startup-inventory/README.md) | Separate service config, state, process, and event evidence | Ch.12 |

---

## Evidence skills matrix

| Skill | Baseline | Procmon | Autoruns | WinObj | Token | ACL | VMMap | ADS | Thread waits | ETW | Service |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Point-in-time inventory | Yes | Partial | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Before/after diff | Yes | Yes | Yes | Yes | Yes | Partial | Partial | Yes | Partial | Partial | Yes |
| Runtime attribution | Partial | Yes | No | Yes | Yes | No | Yes | No | Yes | Partial | Yes |
| Configuration evidence | Partial | Partial | Yes | No | No | Yes | No | No | No | Partial | Yes |
| Execution evidence | Partial | Partial | No | Partial | Partial | No | Partial | No | Yes | Partial | Partial |
| Object/handle evidence | Partial | No | No | Yes | No | Partial | Partial | No | Partial | No | No |
| Security-context evidence | Partial | No | Partial | Partial | Yes | Yes | No | No | Partial | Partial | Partial |
| Memory-region evidence | No | No | No | No | No | No | Yes | No | Partial | No | No |
| File-content artifact evidence | Partial | Yes | No | No | No | Partial | Partial | Yes | No | No | No |
| Provider/session metadata | No | No | No | No | No | No | No | No | No | Yes | No |
| Telemetry caveats | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Cleanup discipline | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |

---

## Chapter coverage

| Chapter / appendix | Current lab support | Gap |
|---|---|---|
| Ch.1 Concepts and Tools | Baseline, Procmon, Autoruns, WinObj, Token | Add Process Explorer process tree lab |
| Ch.3 Processes and Jobs | Baseline, WinObj | Add process tree + handle inheritance lab |
| Ch.4 Threads | Thread Wait Reasons, Deadlock | Add thread pool lab |
| Ch.5 Memory Management | VMMap, WinDbg VAD | Add PTE/protection deep dive |
| Ch.6 I/O System | Procmon, WinObj | Add device namespace / file handle lab |
| Ch.7 Security | Token, ACL, Autoruns partial | Add impersonation/integrity lab |
| Ch.8 System Mechanisms | WinObj, Thread Wait Reasons | Add named event/symlink/APC conceptual labs |
| Ch.10 Diagnostics/Tracing | Baseline, Procmon, ETW inventory, ETW minimal trace | Add WPR/WPA lab |
| Ch.11 Caching/File Systems | Procmon, ADS, Hardlink identity | Add USN controlled lab |
| Ch.12 Startup/Shutdown | Autoruns, Service startup | Add boot logging lab |
| Appendix C WinDbg | Thread Wait optional, VAD corroboration | Add process/thread dump triage lab |
| Appendix I Sysinternals | Baseline, Procmon, Autoruns, WinObj | Add VMMap/RAMMap/AccessChk/Sigcheck labs |

---

## Next best lab candidates

1. **Thread Pool Attribution** — callback attribution beyond start address.
2. **USN File Timeline** — file identity and journal evidence.
3. **Impersonation Context** — thread token vs process token evidence.
4. **WPR/WPA Trace Review** — richer trace capture and visual analysis.
5. **Boot Logging Evidence** — boot-start visibility and cleanup.
6. **Process Handle Inheritance** — parent/child handle visibility.

---

## Publication rule

A lab should not become the only evidence for a chapter claim unless it has:

- explicit tested environment;
- expected vs actual observation;
- cleanup;
- caveats;
- verification record;
- a conclusion sentence that separates evidence from inference.
