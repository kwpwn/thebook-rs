# Quality Gates — Windows Internals VN

File này định nghĩa tiêu chuẩn để nâng tài liệu từ draft sang publication-ready.

---

## Gate 1 — Draft complete

Một chapter hoặc appendix đạt mức draft complete khi:

- Có mục tiêu và scope rõ.
- Có đủ cấu trúc section theo `style-guide.md`.
- Có core internals hoặc workflow chính.
- Có labs hoặc ít nhất lab backlog.
- Có references ban đầu.
- Có caveat cho claim phụ thuộc build/config.

Draft complete được phép còn TODO, nhưng TODO phải xuất hiện trong roadmap hoặc verification backlog.

---

## Gate 2 — Lab-backed

Một chapter/appendix đạt mức lab-backed khi:

- Ít nhất một lab đã được tách sang `labs/`.
- Lab có README, expected output, cleanup, interpretation notes.
- Nếu có code, code có thể build hoặc đã được syntax-check bằng tool phù hợp.
- Lab có verification record.
- Lab phân biệt rõ observation, inference, and unknowns.

Reference examples:

- `labs/ch04-thread-wait-reasons/`
- `labs/app-i-sysinternals-baseline/`

---

## Gate 3 — Reference verified

Một chapter/appendix đạt mức reference verified khi:

- Không còn `TODO: verify URL`.
- Không còn `TODO: Primary references`.
- Official docs được ưu tiên khi có.
- Blog/offensive source được ghi là supplemental nếu không phải nguồn chính.
- Claim về private structures, ETW, VBS/HVCI, NTFS, boot, security boundary có source hoặc lab verification.

---

## Gate 4 — Build/config verified

Một chapter/appendix đạt mức build/config verified khi:

- Claim build-specific có verification record.
- Windows build, edition, architecture, VBS/HVCI/Secure Boot/security product state được ghi rõ.
- Tool versions được ghi rõ.
- Observation có expected vs actual.
- Confidence và caveat được ghi.

---

## Gate 5 — Publication-ready

Một chapter/appendix đạt publication-ready khi:

- Đạt Gate 1-4.
- Không có TODO nội dung quan trọng.
- Links và references đã kiểm tra.
- Labs có cleanup đầy đủ.
- Screenshots/diagrams được link hoặc có plan rõ.
- Summary giúp người đọc biết dùng kiến thức vào research workflow nào.
- Final wording không overclaim.
- Evidence wording follows `evidence-language.md`.

---

## Current priority

| Work item | Target gate | Reason |
|---|---|---|
| Ch.4 thread wait lab | Gate 2 | Lab mẫu cho process/thread observations |
| Ch.4 deadlock observation | Gate 2 | Lock ownership/wait causality mẫu |
| Appendix I baseline lab | Gate 2 | Field workflow mẫu cho mọi lab sau |
| Appendix I Procmon controlled trace | Gate 2 | Telemetry interpretation mẫu cho I/O/registry labs |
| Appendix I Autoruns startup inventory | Gate 2 | Startup configuration vs execution evidence mẫu |
| Appendix I WinObj object namespace | Gate 2 | Object namespace and handle attribution mẫu |
| Ch.1 Process token comparison | Gate 2 | Security context and privilege interpretation mẫu |
| Ch.7 AccessChk permission review | Gate 2 | Permission-state vs access-occurrence mẫu |
| Ch.5 VMMap memory layout | Gate 2 | Memory-region evidence and intent-boundary mẫu |
| Ch.5 WinDbg VAD corroboration | Gate 2 | Cross-tool memory evidence mẫu |
| Ch.11 ADS streams file artifacts | Gate 2 | File-content artifact and stream-enumeration mẫu |
| Ch.11 hardlink file identity | Gate 2 | Path-vs-identity evidence mẫu |
| Ch.10 ETW provider inventory | Gate 2 | Provider availability vs telemetry coverage mẫu |
| Ch.10 ETW minimal trace | Gate 2 | Session-scoped trace evidence mẫu |
| Ch.12 Service startup inventory | Gate 2 | Service config/state/execution-boundary mẫu |
| Appendix F ETW provider field guide | Gate 1 | ETW/provider/session evidence model draft |
| Appendix E lab setup | Gate 3 | Nền repeatability cho toàn bộ tài liệu |
| Appendix C WinDbg guide | Gate 3 | Tooling backbone cho kernel/process/memory chapters |
| Ch.2/3/4/5 references | Gate 3 | Đang còn TODO reference |
| Ch.10 ETW/provider claims | Gate 4 | Provider/event fields phụ thuộc build/config |
| Ch.11/12 forensic and boot claims | Gate 4 | Artifact interpretation dễ overclaim |

---

## Review checklist

Before marking any file publication-ready:

1. Search for `TODO`, `TBD`, `verify`, and `Primary references`.
2. Check that labs have cleanup and expected observations.
3. Check that references match `sources.md` priority.
4. Check that claims distinguish evidence from inference.
5. Check that build/config caveats are present.
6. Run markdown/link checks if available.
7. Run code/script syntax checks for lab artifacts.
