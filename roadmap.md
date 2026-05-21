# Roadmap — Windows Internals VN Researcher Edition

Theo cấu trúc của **Windows Internals 7th Edition**.

---

## Trạng thái

| Ký hiệu | Nghĩa |
|---|---|
| ✅ | Hoàn thành |
| 🔄 | Đang viết |
| ⬜ | Chưa bắt đầu |

---

## Part 1

| # | Chapter | WI Source | Trạng thái | File |
|---|---|---|---|---|
| 1 | Concepts and Tools | WI7 Ch.1 | ✅ | [ch01](chapters/ch01-concepts-and-tools.md) |
| 2 | System Architecture | WI7 Ch.2 | ✅ | [ch02](chapters/ch02-system-architecture.md) |
| 3 | Processes and Jobs | WI7 Ch.3 | ✅ | [ch03](chapters/ch03-processes-and-jobs.md) |
| 4 | Threads | WI7 Ch.4 | ✅ | [ch04](chapters/ch04-threads.md) |
| 5 | Memory Management | WI7 Ch.5 | ✅ | [ch05](chapters/ch05-memory-management.md) |
| 6 | I/O System | WI7 Ch.6 | ✅ | [ch06](chapters/ch06-io-system.md) |
| 7 | Security | WI7 Ch.7 | ✅ | [ch07](chapters/ch07-security.md) |

## Part 2

| # | Chapter | WI Source | Trạng thái | File |
|---|---|---|---|---|
| 8 | System Mechanisms | WI7 Ch.8 | ✅ | [ch08](chapters/ch08-system-mechanisms.md) |
| 9 | Virtualization Technologies | WI7 Ch.9 | ✅ | [ch09](chapters/ch09-virtualization-technologies.md) |
| 10 | Management, Diagnostics, Tracing | WI7 Ch.10 | ✅ | [ch10](chapters/ch10-management-diagnostics-tracing.md) |
| 11 | Caching and File Systems | WI7 Ch.11 | ✅ | [ch11](chapters/ch11-caching-file-systems.md) |
| 12 | Startup and Shutdown | WI7 Part 2 Ch.12 | ✅ | [ch12](chapters/ch12-startup-shutdown.md) |

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

Mỗi chapter bao gồm **18 section**:

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
| Appendix A — Windows Networking Internals | [appendices/app-a-windows-networking-internals.md](appendices/app-a-windows-networking-internals.md) | Planned | High | Ch.6, Ch.7, Ch.10, Ch.11 |
| Appendix B — EDR/AV Telemetry Architecture | [appendices/app-b-edr-av-telemetry-architecture.md](appendices/app-b-edr-av-telemetry-architecture.md) | Planned | High | Ch.6, Ch.7, Ch.8, Ch.10, Ch.11, Ch.12 |
| Appendix C — Kernel Debugging Field Guide | [appendices/app-c-kernel-debugging-field-guide.md](appendices/app-c-kernel-debugging-field-guide.md) | Planned | High | Ch.2, Ch.3, Ch.4, Ch.5, Ch.6, Ch.8 |
| Appendix D — Windows Forensics Artifact Matrix | [appendices/app-d-windows-forensics-artifact-matrix.md](appendices/app-d-windows-forensics-artifact-matrix.md) | Planned | High | Ch.3, Ch.5, Ch.7, Ch.10, Ch.11, Ch.12 |
| Appendix E — Windows Research Lab Setup | [appendices/app-e-windows-research-lab-setup.md](appendices/app-e-windows-research-lab-setup.md) | Planned | High | Ch.1, all labs |
| Appendix F — ETW Provider Field Guide | [appendices/app-f-etw-provider-field-guide.md](appendices/app-f-etw-provider-field-guide.md) | Planned | Medium | Ch.8, Ch.10, Ch.11, Ch.12 |
| Appendix G — Driver Research Methodology | [appendices/app-g-driver-research-methodology.md](appendices/app-g-driver-research-methodology.md) | Planned | Medium | Ch.6, Ch.9, Ch.11, Ch.12 |
| Appendix H — Windows Exploit Mitigation Overview | [appendices/app-h-windows-exploit-mitigation-overview.md](appendices/app-h-windows-exploit-mitigation-overview.md) | Planned | Medium | Ch.3, Ch.4, Ch.5, Ch.7, Ch.9 |
| Appendix I — Sysinternals Practical Lab Manual | [appendices/app-i-sysinternals-practical-lab-manual.md](appendices/app-i-sysinternals-practical-lab-manual.md) | Planned | Medium | Ch.1–12 labs |
| Appendix J — Windows 11 Delta Notes | [appendices/app-j-windows-11-delta-notes.md](appendices/app-j-windows-11-delta-notes.md) | Planned | Medium | Ch.1–12 |

---

## Appendix roadmap (post-core)

- Appendix A — Windows Networking Internals
- Appendix B — EDR/AV Telemetry Architecture
- Appendix C — Kernel Debugging Field Guide
- Appendix D — Windows Forensics Artifact Matrix
- Appendix E — Windows Research Lab Setup
- Appendix F — ETW Provider Field Guide
- Appendix G — Driver Research Methodology
- Appendix H — Windows Exploit Mitigation Overview
- Appendix I — Sysinternals Practical Lab Manual
- Appendix J — Windows 11 Delta Notes

Chưa tạo file appendix trong pass này; đây là kế hoạch mở rộng sau khi 12 core chapters ổn định.

---

## Phụ lục (dự kiến)

- `glossary.md` — Bảng thuật ngữ toàn dự án
- `labs/` — Lab độc lập (lab dài, nhiều bước)
- `assets/diagrams/` — Mermaid diagram files
- `assets/screenshots/` — Screenshot từ VM

---

*Cập nhật khi chapter mới được hoàn thành.*
