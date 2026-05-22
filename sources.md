# Nguồn tham khảo (Sources)

Danh sách nguồn tài liệu chính được sử dụng trong dự án này.

---

## Source priority

Khi có mâu thuẫn hoặc chi tiết version-specific, ưu tiên nguồn theo thứ tự:

1. Official Microsoft Learn / Windows SDK / WDK / Sysinternals / WinDbg docs
2. Windows Internals book chapter references
3. Controlled lab observations trên target Windows build
4. Trusted researcher blogs/talks
5. Advanced/offensive research links chỉ dùng như supplemental context và phải manual verify

Các claim về private structures, Event IDs, ETW providers, VBS/HVCI, NTFS internals, và boot behavior phải được kiểm tra theo build/configuration cụ thể.

---

## Sách

| Tên | Tác giả | Ghi chú |
|---|---|---|
| Windows Internals, 7th Ed. Part 1 | Yosifovich, Ionescu, Russinovich, Solomon | Nguồn cấu trúc chính |
| Windows Internals, 7th Ed. Part 2 | Russinovich, Solomon, Ionescu | Nguồn cấu trúc chính |
| Windows Kernel Programming | Pavel Yosifovich | Driver development |
| The Art of Memory Forensics | Ligh, Case, Levy, Walters | Memory forensics |
| Rootkits and Bootkits | Matrosov, Rodionov, Bratus | Low-level persistence |

---

## Tài liệu chính thức Microsoft

- **Microsoft Learn (Windows Internals)**: https://learn.microsoft.com/en-us/windows/win32/
- **Windows Driver Kit (WDK) docs**: https://learn.microsoft.com/en-us/windows-hardware/drivers/
- **Windows SDK reference**: https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list
- **WinDbg documentation**: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- **Event Tracing for Windows (ETW)**: https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing
- **Windows Security Center docs**: https://learn.microsoft.com/en-us/windows/security/

---

## Sysinternals

- **Sysinternals Suite**: https://learn.microsoft.com/en-us/sysinternals/
- **Process Monitor**: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- **Process Explorer**: https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
- **WinObj**: https://learn.microsoft.com/en-us/sysinternals/downloads/winobj
- **Autoruns**: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- **VMMap**: https://learn.microsoft.com/en-us/sysinternals/downloads/vmmap
- **RAMMap**: https://learn.microsoft.com/en-us/sysinternals/downloads/rammap

---

## Blog và Research đáng tin

| Nguồn | Nội dung |
|---|---|
| https://connormcgarr.github.io | Kernel exploitation/memory research; supplemental, verify manually |
| https://j00ru.vexillium.org | Windows kernel research |
| https://secret.club | Browser/kernel/hypervisor research; supplemental, verify manually |
| https://windows-internals.com | Blog chính thức từ tác giả sách |
| https://googleprojectzero.blogspot.com | Browser + kernel 0-days |
| https://www.tiraniddo.dev | James Forshaw - Windows security |
| https://www.alex-ionescu.com | Alex Ionescu - kernel internals |
| https://blog.xpnsec.com | Adam Chester - advanced/offensive research; supplemental, verify manually |
| https://elasticsecurity.com/blog | EDR telemetry, detection |

---

## Công cụ phân tích

| Công cụ | Mục đích | Link |
|---|---|---|
| WinDbg Preview | Kernel debugging | Microsoft Store |
| x64dbg | User-mode debugging | https://x64dbg.com |
| Sysinternals Suite | System analysis | Sysinternals |
| PE-bear | PE file analysis | GitHub |
| IDA Free / Ghidra | Disassembly | IDA / NSA |
| API Monitor | API call tracing | rohitab.com |
| ETWExplorer | ETW provider browsing | GitHub |
| EtwTi-explorer | ETW Threat Intelligence | GitHub |

---


## Chapter-specific official source categories

- **BCD / BCDEdit / Boot options**: Microsoft Learn BCDEdit and Boot Configuration Data documentation
- **Secure Boot / Measured Boot / TPM / ELAM**: Microsoft Learn Windows security, Secure Boot, Measured Boot, TPM, and Early Launch Anti-Malware documentation
- **NTFS / ReFS / USN / VSS**: Microsoft Learn file systems, change journals, Volume Shadow Copy Service, and ReFS documentation
- **WPR / WPA / GFlags / IFEO**: Windows Performance Toolkit and Debugging Tools for Windows documentation
- **ETW / WMI / Event Log**: Microsoft Learn Event Tracing for Windows, WMI/CIM, and Windows Event Log documentation
- **WinDbg command references**: Microsoft Learn debugger command reference, public symbols, and controlled lab validation

---

## Verification artifacts

Khi một claim phụ thuộc Windows build/config, ghi record bằng `verification-template.md` và link lại từ chapter hoặc appendix liên quan.

Tối thiểu record:

- Windows build, edition, architecture.
- Secure Boot / VBS / HVCI / Defender state.
- Tool versions and symbol path.
- Command/lab steps.
- Expected vs actual observation.
- Confidence and caveats.

---

## Symbol và PDB

- **Microsoft Symbol Server**: `srv*https://msdl.microsoft.com/download/symbols`
- Cách cấu hình trong WinDbg: `.sympath srv*c:\symbols*https://msdl.microsoft.com/download/symbols`

---

## Specification và RFC liên quan

- **PE/COFF Format**: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- **COM Specification**: https://learn.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal
- **NTFS Specification**: Tham khảo libyal/ntfs project trên GitHub
