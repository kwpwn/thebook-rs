# Windows Internals VN — Researcher Edition

Tài liệu nghiên cứu chuyên sâu về Windows Internals bằng tiếng Việt, viết theo cấu trúc của **Windows Internals 7th Edition (Part 1 & Part 2)**, nhưng được giải thích lại theo hướng thực chiến và nghiên cứu bảo mật.

---

## Mục tiêu

Tài liệu này không phải một bản dịch. Đây là một **hướng dẫn nghiên cứu độc lập** giúp bạn:

- Hiểu cơ chế nội bộ của Windows ở mức kernel và executive
- Phân tích bề mặt tấn công (attack surface) của từng subsystem
- Quan sát hành vi hệ thống bằng công cụ thực tế
- Kết nối lý thuyết với kỹ thuật bảo mật tấn công/phòng thủ
- Xây dựng tư duy của một security researcher thực sự

---

## Đối tượng đọc

| Vai trò | Lợi ích |
|---|---|
| Sinh viên bảo mật thông tin | Hiểu nền tảng OS để học exploit/malware/blue team |
| Windows API learner | Hiểu tại sao API hoạt động như vậy |
| Reverse engineer | Hiểu context khi disassemble Windows binary |
| Malware analyst | Hiểu các technique malware lợi dụng |
| Blue team / Detection engineer | Biết cần monitor gì và tại sao |
| Kernel researcher mới bắt đầu | Nền tảng để đọc kernel code và symbol |
| Exploit developer | Hiểu OS để khai thác lỗ hổng đúng mục tiêu |
| EDR/AV architect | Hiểu hook point và telemetry source |

---

## Cấu trúc thư mục

```
README.md           ← File này
sources.md          ← Nguồn tham khảo chính
roadmap.md          ← Roadmap theo chapter
glossary.md         ← Bảng thuật ngữ Việt-Anh
style-guide.md      ← Quy chuẩn viết, lab, reference, verification
quality-gates.md    ← Tiêu chuẩn nâng draft thành publication-ready
evidence-language.md← Quy chuẩn diễn đạt evidence, inference, confidence
publication-gaps.md ← Danh sách gap còn lại trước publication-ready
LAB_COVERAGE.md     ← Bản đồ coverage chapter-to-lab

chapters/           ← Nội dung từng chapter
  ch01-concepts-and-tools.md
  ch02-system-architecture.md
  ch03-processes-and-jobs.md
  ch04-threads.md
  ch05-memory-management.md
  ch06-io-system.md
  ch07-security.md
  ch08-system-mechanisms.md
  ch09-virtualization-technologies.md
  ch10-management-diagnostics-tracing.md
  ch11-caching-file-systems.md
  ch12-startup-shutdown.md

labs/               ← Lab thực hành độc lập và template triển khai
assets/
  diagrams/         ← Mermaid diagrams (render được)
  screenshots/      ← Screenshot từ VM cá nhân
```

---

## Cách sử dụng

1. Đọc `roadmap.md` để nắm bức tranh toàn cảnh
2. Đọc từng chapter theo thứ tự — mỗi chapter xây dựng trên chapter trước
3. Dùng `labs/README.md` và `labs/templates/lab-template.md` để chuyển lab trong chapter thành artifact có thể chạy lại
4. Tra `glossary.md` khi gặp thuật ngữ không quen
5. Mở WinDbg/ProcMon/Process Explorer song song khi đọc
6. Dùng `verification-template.md` khi cần khóa claim theo Windows build/config cụ thể

---

## Môi trường được khuyến nghị

- Windows 10 22H2 hoặc Windows 11 23H2 trong VMware/Hyper-V
- Windows SDK + WDK đã cài đặt
- Sysinternals Suite (toàn bộ)
- WinDbg Preview (từ Microsoft Store)
- x64dbg
- Visual Studio Community (để compile code C/C++ trong lab)

---

## Nguồn gốc cấu trúc

Tài liệu này đi theo cấu trúc chapter của:
> **Windows Internals, 7th Edition** — Pavel Yosifovich, Alex Ionescu, Mark E. Russinovich, David A. Solomon (Microsoft Press)

Mọi giải thích là **độc lập, gốc**, không copy từ sách. Đọc song song với sách để đạt hiệu quả tốt nhất.

---

## Trạng thái

> Draft core complete. 12 chapter lõi đã có nội dung chính; tài liệu đang ở giai đoạn ổn định hóa: chuẩn hóa reference, tách lab thành artifact, thêm verification theo build/config, và hoàn thiện appendix. Xem `roadmap.md` để biết trạng thái chi tiết.

---

## Post-book researcher appendices

- [Appendices Index](appendices/index.md)
- [Appendix A — Windows Networking Internals](appendices/app-a-windows-networking-internals.md)
- [Appendix B — EDR/AV Telemetry Architecture](appendices/app-b-edr-av-telemetry-architecture.md)
- [Appendix C — Kernel Debugging Field Guide](appendices/app-c-kernel-debugging-field-guide.md)
- [Appendix D — Windows Forensics Artifact Matrix](appendices/app-d-windows-forensics-artifact-matrix.md)
- [Appendix E — Windows Research Lab Setup](appendices/app-e-windows-research-lab-setup.md)
- [Appendix F — ETW Provider Field Guide](appendices/app-f-etw-provider-field-guide.md)
- [Appendix G — Driver Research Methodology](appendices/app-g-driver-research-methodology.md)
- [Appendix H — Windows Exploit Mitigation Overview](appendices/app-h-windows-exploit-mitigation-overview.md)
- [Appendix I — Sysinternals Practical Lab Manual](appendices/app-i-sysinternals-practical-lab-manual.md)
- [Appendix J — Windows 11 Delta Notes](appendices/app-j-windows-11-delta-notes.md)

---

## Post-book expansion plan

Sau 12 chapter core, roadmap mở rộng hiện chia làm hai nhóm:

**Draft có nội dung chính:**

- Appendix C — Kernel Debugging Field Guide
- Appendix E — Windows Research Lab Setup
- Appendix I — Sysinternals Practical Lab Manual

**Stub cần triển khai:**

- Appendix A — Windows Networking Internals
- Appendix B — EDR/AV Telemetry Architecture
- Appendix D — Windows Forensics Artifact Matrix
- Appendix F — ETW Provider Field Guide
- Appendix G — Driver Research Methodology
- Appendix H — Windows Exploit Mitigation Overview
- Appendix J — Windows 11 Delta Notes

Ưu tiên triển khai tiếp theo: Appendix E → Appendix I → Appendix C → Appendix F → Appendix D → Appendix B → Appendix A/G/H/J.

---

*Viết cho cộng đồng bảo mật Việt Nam. Không dùng cho mục đích thương mại.*
