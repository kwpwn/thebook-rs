# Roadmap — Windows Internals VN Researcher Edition

Theo cấu trúc của **Windows Internals 7th Edition**.

---

## Trạng thái

| Ký hiệu | Nghĩa |
|---|---|
| ✅ | Draft complete |
| 🔄 | Đang viết / cần verification |
| ⬜ | Stub / chưa triển khai |

---

## Part 1

| # | Chapter | WI Source | Trạng thái | File |
|---|---|---|---|---|
| 1 | Concepts and Tools | WI7 Ch.1 | ✅ Draft complete; needs reference/lab verification pass | [ch01](chapters/ch01-concepts-and-tools.md) |
| 2 | System Architecture | WI7 Ch.2 | ✅ Draft complete; has TODO URL verification items | [ch02](chapters/ch02-system-architecture.md) |
| 3 | Processes and Jobs | WI7 Ch.3 | ✅ Draft complete; has TODO references | [ch03](chapters/ch03-processes-and-jobs.md) |
| 4 | Threads | WI7 Ch.4 | ✅ Draft complete; has TODO references | [ch04](chapters/ch04-threads.md) |
| 5 | Memory Management | WI7 Ch.5 | ✅ Draft complete; has TODO references | [ch05](chapters/ch05-memory-management.md) |
| 6 | I/O System | WI7 Ch.6 | ✅ Draft complete; needs lab extraction | [ch06](chapters/ch06-io-system.md) |
| 7 | Security | WI7 Ch.7 | ✅ Draft complete; needs lab extraction | [ch07](chapters/ch07-security.md) |

## Part 2

| # | Chapter | WI Source | Trạng thái | File |
|---|---|---|---|---|
| 8 | System Mechanisms | WI7 Ch.8 | ✅ Draft complete; needs lab extraction | [ch08](chapters/ch08-system-mechanisms.md) |
| 9 | Virtualization Technologies | WI7 Ch.9 | ✅ Draft complete; needs build/config verification | [ch09](chapters/ch09-virtualization-technologies.md) |
| 10 | Management, Diagnostics, Tracing | WI7 Ch.10 | ✅ Draft complete; needs provider/event verification | [ch10](chapters/ch10-management-diagnostics-tracing.md) |
| 11 | Caching and File Systems | WI7 Ch.11 | ✅ Draft complete; needs artifact/lab verification | [ch11](chapters/ch11-caching-file-systems.md) |
| 12 | Startup and Shutdown | WI7 Part 2 Ch.12 | ✅ Draft complete; needs boot/build verification | [ch12](chapters/ch12-startup-shutdown.md) |

---

## Thứ tự học được khuyến nghị

### Lộ trình 1: Security Researcher / Malware Analyst

```
Ch1 → Ch2 → Ch3 → Ch4 → Ch7 → Ch5 → Ch8 → Ch6 → Ch10 → Ch11 → Ch12
```

- Ch1-2: Nền tảng mental model
- Ch3-4: Process/Thread là vũ khí chính của malware
- Ch7: Security model để hiểu privilege/token
- Ch5: Memory để hiểu injection/shellcode
- Ch8: Mechanism như APC, DPC để hiểu advanced techniques
- Ch6: I/O để hiểu driver và filter
- Ch10: ETW/tracing để hiểu detection
- Ch11: File systems/cache để hiểu artifacts, minifilters, forensic evidence
- Ch12: Boot/startup để hiểu persistence, driver load, sensor readiness

### Lộ trình 2: Kernel Developer / Exploit Dev

```
Ch1 → Ch2 → Ch5 → Ch4 → Ch3 → Ch6 → Ch8 → Ch9 → Ch11 → Ch12
```

- Ưu tiên memory và threading trước
- Virtualization sau khi nắm kernel
- Ch11/Ch12 giúp nối memory/I/O với file system, driver load, boot debugging

### Lộ trình 3: Blue Team / Detection Engineering

```
Ch1 → Ch2 → Ch3 → Ch7 → Ch10 → Ch6 → Ch11 → Ch12 → Ch4 → Ch8
```

- Ưu tiên security model và telemetry
- I/O system để hiểu minifilter (EDR hook point)
- Ch11 để hiểu file telemetry, cache, MFT/USN/VSS artifacts
- Ch12 để hiểu boot/startup visibility gaps, driver/service persistence, shutdown evidence

---

## Nội dung mỗi chapter

Mỗi chapter bao gồm **19 mục** đánh số từ 0 đến 18:

| Section | Nội dung |
|---|---|
| 0 | Chapter map (link với WI source) |
| 1 | Researcher mindset |
| 2 | Big picture |
| 3 | Key terms (bảng Việt-Anh) |
| 4 | Core internals |
| 5 | Windows components / structures |
| 6 | Trust boundaries |
| 7 | Attack surface map |
| 8 | Abuse patterns (khái niệm) |
| 9 | Defender / EDR telemetry |
| 10 | Forensic artifacts |
| 11 | Debugging và reversing notes |
| 12 | Safe local labs |
| 13 | Common researcher mistakes |
| 14 | Windows version notes |
| 15 | Summary |
| 16 | Research questions |
| 17 | References |
| 18 | Illustration plan |

---


## Appendix roadmap table

| Appendix | File | Status | Priority | Depends on |
|---|---|---|---|---|
| Appendix A — Windows Networking Internals | [appendices/app-a-windows-networking-internals.md](appendices/app-a-windows-networking-internals.md) | ⬜ Stub | High | Ch.6, Ch.7, Ch.10, Ch.11 |
| Appendix B — EDR/AV Telemetry Architecture | [appendices/app-b-edr-av-telemetry-architecture.md](appendices/app-b-edr-av-telemetry-architecture.md) | ⬜ Stub | High | Ch.6, Ch.7, Ch.8, Ch.10, Ch.11, Ch.12 |
| Appendix C — Kernel Debugging Field Guide | [appendices/app-c-kernel-debugging-field-guide.md](appendices/app-c-kernel-debugging-field-guide.md) | ✅ Draft complete; needs command/reference verification | High | Ch.2, Ch.3, Ch.4, Ch.5, Ch.6, Ch.8 |
| Appendix D — Windows Forensics Artifact Matrix | [appendices/app-d-windows-forensics-artifact-matrix.md](appendices/app-d-windows-forensics-artifact-matrix.md) | ⬜ Stub | High | Ch.3, Ch.5, Ch.7, Ch.10, Ch.11, Ch.12 |
| Appendix E — Windows Research Lab Setup | [appendices/app-e-windows-research-lab-setup.md](appendices/app-e-windows-research-lab-setup.md) | ✅ Draft complete; should be finalized before lab extraction | High | Ch.1, all labs |
| Appendix F — ETW Provider Field Guide | [appendices/app-f-etw-provider-field-guide.md](appendices/app-f-etw-provider-field-guide.md) | ✅ Draft implementation; needs provider verification | Medium | Ch.8, Ch.10, Ch.11, Ch.12 |
| Appendix G — Driver Research Methodology | [appendices/app-g-driver-research-methodology.md](appendices/app-g-driver-research-methodology.md) | ⬜ Stub | Medium | Ch.6, Ch.9, Ch.11, Ch.12 |
| Appendix H — Windows Exploit Mitigation Overview | [appendices/app-h-windows-exploit-mitigation-overview.md](appendices/app-h-windows-exploit-mitigation-overview.md) | ⬜ Stub | Medium | Ch.3, Ch.4, Ch.5, Ch.7, Ch.9 |
| Appendix I — Sysinternals Practical Lab Manual | [appendices/app-i-sysinternals-practical-lab-manual.md](appendices/app-i-sysinternals-practical-lab-manual.md) | ✅ Draft complete; needs lab extraction links | Medium | Ch.1–12 labs |
| Appendix J — Windows 11 Delta Notes | [appendices/app-j-windows-11-delta-notes.md](appendices/app-j-windows-11-delta-notes.md) | ⬜ Stub | Medium | Ch.1–12 |

---

## Stabilization roadmap

1. Finalize Appendix E as the repeatable lab setup baseline.
2. Finalize Appendix I as the Sysinternals practical lab manual.
3. Finalize Appendix C as the read-only WinDbg field guide.
4. Extract chapter labs into `labs/` using `labs/templates/lab-template.md`.
5. Run a reference verification pass over TODO references and URL caveats.
6. Add verification records for build/config-sensitive claims.
7. Implement remaining appendix stubs in this order: F, D, B, A, G, H, J.

Current lab extraction status:

| Area | Extracted lab coverage |
|---|---|
| Baseline workflow | `labs/app-i-sysinternals-baseline/` |
| Procmon telemetry | `labs/app-i-procmon-controlled-trace/` |
| Startup inventory | `labs/app-i-autoruns-startup-inventory/` |
| Object namespace | `labs/app-i-winobj-object-namespace/` |
| Token/security context | `labs/ch01-process-token-comparison/` |
| Permission/ACL review | `labs/ch07-accesschk-permission-review/` |
| ETW provider inventory | `labs/ch10-etw-provider-inventory/` |
| ETW minimal trace | `labs/ch10-etw-minimal-trace/` |
| Service startup evidence | `labs/ch12-service-startup-inventory/` |
| Thread waits | `labs/ch04-thread-wait-reasons/` |
| Deadlock observation | `labs/ch04-deadlock-observation/` |
| Memory layout | `labs/ch05-vmmap-memory-layout/` |
| WinDbg VAD corroboration | `labs/ch05-windbg-vad-corroboration/` |
| File streams/artifacts | `labs/ch11-ads-streams-file-artifacts/` |
| Hardlink file identity | `labs/ch11-hardlink-file-identity/` |

---

## Phụ lục (dự kiến)

- `glossary.md` — Bảng thuật ngữ toàn dự án
- `labs/` — Lab độc lập (lab dài, nhiều bước)
- `assets/diagrams/` — Mermaid diagram files
- `assets/screenshots/` — Screenshot từ VM
- `style-guide.md` — Quy chuẩn viết và triển khai
- `quality-gates.md` — Tiêu chuẩn chất lượng và publication gates
- `evidence-language.md` — Quy chuẩn diễn đạt evidence/inference/confidence
- `publication-gaps.md` — Gap còn lại trước publication-ready
- `verification-template.md` — Template khóa claim theo build/config

---

*Cập nhật khi chapter mới được hoàn thành.*
