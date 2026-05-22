# Style Guide — Windows Internals VN

File này là quy chuẩn triển khai để giữ tài liệu nhất quán khi mở rộng chapter, appendix, lab, diagram, và reference.

---

## 1. Ngôn ngữ và thuật ngữ

- Viết giải thích chính bằng tiếng Việt.
- Giữ thuật ngữ Windows/API/debugger bằng tiếng Anh khi dịch sẽ làm mất nghĩa.
- Lần đầu dùng thuật ngữ quan trọng nên viết dạng: `thuật ngữ Việt (English term)`.
- Tên command, API, structure, event, provider, registry key, path, symbol giữ nguyên trong backticks.
- Không kết luận tuyệt đối với behavior phụ thuộc build/config. Dùng dạng: "trên build/config đã kiểm tra", "thường", "cần verify".

---

## 2. Cấu trúc chapter

Mỗi chapter dùng 19 mục đánh số từ 0 đến 18:

| Section | Nội dung |
|---|---|
| 0 | Chapter map |
| 1 | Researcher mindset |
| 2 | Big picture |
| 3 | Key terms |
| 4 | Core internals |
| 5 | Windows components / structures |
| 6 | Trust boundaries |
| 7 | Attack surface map |
| 8 | Abuse patterns — concept level |
| 9 | Defender / EDR telemetry |
| 10 | Forensic artifacts |
| 11 | Debugging and reversing notes |
| 12 | Safe local labs |
| 13 | Common researcher mistakes |
| 14 | Windows version notes |
| 15 | Summary |
| 16 | Research questions |
| 17 | References |
| 18 | Illustration plan |

Nếu một chapter chưa đủ một mục, ghi rõ `Status: stub` hoặc `Needs verification`, không để người đọc hiểu nhầm là đã hoàn tất.

---

## 3. Lab format

Lab trong chapter có thể ở dạng ngắn, nhưng lab triển khai trong `labs/` phải có đủ:

- Goal
- Scope and safety
- Tested environment
- Requirements
- Steps
- Expected observations
- Evidence to save
- Cleanup
- Interpretation notes
- Open questions

Không dùng lab trên production machine. Mọi lab có kernel debugging, boot setting, driver, raw disk, dump, hoặc telemetry collection phải yêu cầu VM snapshot trước khi chạy.

---

## 4. Reference policy

Ưu tiên nguồn theo `sources.md`:

1. Microsoft Learn / SDK / WDK / Sysinternals / WinDbg docs.
2. Windows Internals book references.
3. Controlled lab observations.
4. Trusted researcher blogs/talks.
5. Offensive research only as supplemental context.

Các claim sau phải có source hoặc lab verification:

- Private structures and offsets.
- Event IDs and ETW provider names/fields.
- VBS/HVCI/PPL/Credential Guard behavior.
- NTFS/ReFS/USN/VSS details.
- Boot, shutdown, crash, hibernation behavior.
- EDR/AV telemetry visibility claims.

Không để `TODO: verify URL` hoặc `TODO: primary reference` trong chapter/appendix được đánh dấu publication-ready. Với draft complete, TODO phải được phản ánh trong roadmap hoặc verification backlog.

---

## 5. Verification notes

Khi khóa một claim, ghi tối thiểu:

- Windows version/build.
- Edition and architecture.
- Secure Boot / VBS / HVCI / Defender state.
- Tool versions.
- Symbol path/debugger version nếu dùng WinDbg.
- Command hoặc lab đã chạy.
- Observation.
- Confidence.
- Known limits.

Dùng `verification-template.md` cho chapter hoặc appendix có nhiều claim build-specific.

---

## 6. Diagrams and screenshots

- Mermaid diagram có thể đặt inline trong chapter hoặc tách vào `assets/diagrams/`.
- Screenshot từ VM đặt dưới `assets/screenshots/`, tránh chứa hostname, username, token, key, internal path nhạy cảm.
- Mỗi screenshot nên có companion note: source chapter/lab, Windows build, tool version, timestamp, và mục đích minh họa.
