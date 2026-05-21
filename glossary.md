# Bảng thuật ngữ — Windows Internals VN

Tra cứu nhanh các thuật ngữ kỹ thuật Windows. Thuật ngữ tiếng Anh được giữ nguyên trong ngoặc vì đây là chuẩn dùng trong tool, code, và tài liệu thực tế.

---

## A

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Access Control Entry (ACE) | Mục kiểm soát truy cập | Một rule trong ACL |
| Access Control List (ACL) | Danh sách kiểm soát truy cập | DACL + SACL |
| Access Token | Token truy cập | Đại diện danh tính của process/thread |
| Address Space Layout Randomization (ASLR) | Ngẫu nhiên hóa không gian địa chỉ | Mitigation chống exploit |
| Alertable wait | Chờ có thể báo hiệu | Thread có thể nhận APC khi đang chờ |
| Asynchronous Procedure Call (APC) | Lệnh gọi thủ tục bất đồng bộ | Cơ chế inject code vào thread |
| Atom Table | Bảng nguyên tử | Shared string table cho window messages |

## B

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Base Service | Dịch vụ nền | Windows service chạy trong svchost |
| Boot Loader | Trình khởi động | BOOTMGR → winload.exe → ntoskrnl |
| BSOD (Blue Screen of Death) | Màn hình xanh chết chóc | Kernel panic của Windows |

## C

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Callback | Hàm gọi ngược | Hàm được gọi khi sự kiện xảy ra |
| Child Process | Tiến trình con | Process được tạo bởi process khác |
| Control Flow Guard (CFG) | Bảo vệ luồng điều khiển | Mitigation chống ROP/JOP |
| Context Switch | Chuyển ngữ cảnh | CPU chuyển từ thread này sang thread khác |
| Critical Section | Vùng tới hạn | Mutex trong user mode |
| CSRSS (Client/Server Runtime Subsystem) | Hệ thống con client/server | Win32 subsystem process |

## D

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| DACL (Discretionary ACL) | ACL tùy ý | Kiểm soát ai được phép truy cập |
| Data Execution Prevention (DEP) | Ngăn chặn thực thi dữ liệu | No-execute (NX/XD) |
| Deferred Procedure Call (DPC) | Lệnh gọi thủ tục trì hoãn | Kernel interrupt handler deferred work |
| Desktop | Desktop (kernel object) | Container cho windows trong một session |
| Device Driver | Driver thiết bị | Kernel module quản lý hardware/virtual device |
| Device Object | Đối tượng thiết bị | Kernel object đại diện cho device |
| Driver Object | Đối tượng driver | Kernel object đại diện cho driver |
| DLL (Dynamic Link Library) | Thư viện liên kết động | Shared code loaded vào process |
| DLL Injection | Lớp kỹ thuật nạp DLL vào process khác | Thuật ngữ dùng để hiểu detection/research context; không phải hướng dẫn triển khai |

## E

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| EPROCESS | Cấu trúc tiến trình kernel | Kernel struct đại diện process |
| ETHREAD | Cấu trúc luồng kernel | Kernel struct đại diện thread |
| ETW (Event Tracing for Windows) | Theo dõi sự kiện Windows | Framework telemetry của Windows |
| Event Object | Đối tượng sự kiện | Kernel synchronization primitive |
| Executive | Executive (Windows) | Lớp quản lý cao nhất trong ntoskrnl |

## F

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Fiber | Sợi | User-mode cooperative thread |
| File Object | Đối tượng file | Kernel object đại diện file đang mở |
| Filter Driver | Driver bộ lọc | Driver can thiệp vào I/O pipeline |
| Handle | Handle | Tham chiếu đến kernel object |
| Handle Table | Bảng handle | Per-process bảng lưu handle |

## G–H

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| GDI (Graphics Device Interface) | Giao diện thiết bị đồ họa | Win32 graphics API |
| Hardware Abstraction Layer (HAL) | Lớp trừu tượng hóa phần cứng | hal.dll — trừu tượng CPU/firmware |
| Heap | Vùng nhớ heap | Vùng cấp phát động trong process |
| Hypervisor | Hypervisor (ảo hóa) | VBS/Hyper-V layer dưới Windows |

## I

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Impersonation | Mạo danh | Thread chạy với token của user khác |
| I/O Request Packet (IRP) | Gói yêu cầu I/O | Cơ chế giao tiếp I/O trong kernel |
| Integrity Level | Mức toàn vẹn | Low/Medium/High/System — UAC model |
| Interrupt | Ngắt | Tín hiệu phần cứng hoặc phần mềm |
| Interrupt Request Level (IRQL) | Mức yêu cầu ngắt | Ưu tiên thực thi trong kernel |

## J–K

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Job Object | Đối tượng công việc | Container nhóm các process |
| Kernel | Kernel | Lõi hệ điều hành, ring 0 |
| Kernel Mode | Chế độ kernel | Ring 0, full hardware access |
| Kernel Object | Đối tượng kernel | Resource được quản lý bởi Object Manager |

## L

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| LPC (Local Procedure Call) | Lệnh gọi thủ tục nội bộ | IPC mechanism giữa processes |
| LSASS (Local Security Authority Subsystem) | Hệ thống con cơ quan bảo mật | Quản lý xác thực, credential |

## M

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Memory-Mapped File | File ánh xạ bộ nhớ | Map file vào virtual address space |
| Minifilter | Minifilter | Filter driver framework của Windows |
| Mutex | Mutex | Mutual exclusion object |
| MiniDump | MiniDump | Crash dump ở dạng nhỏ |

## N

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Named Pipe | Pipe có tên | IPC channel dạng file |
| Native API | API gốc | NtXxx/ZwXxx — lớp dưới Win32 |
| NTFS | NTFS | Windows filesystem |
| NTLM | NTLM | Windows authentication protocol |

## O

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Object | Đối tượng | Kernel-managed resource |
| Object Manager | Trình quản lý đối tượng | Kernel component quản lý mọi object |
| Object Namespace | Không gian tên đối tượng | `\Device\`, `\BaseNamedObjects\`… |

## P

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Page | Trang | Đơn vị quản lý bộ nhớ (4KB) |
| Page Fault | Lỗi trang | Truy cập trang chưa có trong RAM |
| Page Table | Bảng trang | Bảng dịch địa chỉ ảo → vật lý |
| Paged Pool | Pool có thể phân trang | Vùng kernel memory có thể swap |
| Parent Process | Tiến trình cha | Process đã tạo ra process con |
| PEB (Process Environment Block) | Khối môi trường tiến trình | User-mode struct của process |
| Physical Memory | Bộ nhớ vật lý | RAM thực sự |
| Portable Executable (PE) | File thực thi di động | .exe/.dll format |
| PPL (Protected Process Light) | Tiến trình bảo vệ nhẹ | Cơ chế bảo vệ process khỏi tamper |
| Privilege | Đặc quyền | Quyền đặc biệt trong access token |
| Process | Tiến trình | Container cho thread, virtual memory |
| Process Hollowing | Lớp kỹ thuật thay thế image/runtime của process | Dùng như threat-model/detection term; không phải hướng dẫn triển khai |

## R

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Registry | Registry | Database cấu hình Windows |
| Registry Hive | Kho registry | File vật lý chứa một phần registry |
| RPC (Remote Procedure Call) | Lệnh gọi thủ tục từ xa | IPC/network communication protocol |

## S

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| SACL (System ACL) | ACL hệ thống | Audit logging access |
| Section Object | Đối tượng section | Shared memory / mapped file object |
| Security Descriptor | Mô tả bảo mật | Chứa owner, DACL, SACL của object |
| Security Reference Monitor (SRM) | Monitor tham chiếu bảo mật | Kernel component enforce access check |
| Semaphore | Semaphore | Counting synchronization primitive |
| Service | Dịch vụ | Background process managed by SCM |
| Service Control Manager (SCM) | Trình quản lý dịch vụ | services.exe quản lý Windows services |
| Session | Session | Isolation unit cho user session |
| SID (Security Identifier) | Định danh bảo mật | ID duy nhất cho user/group |
| SMSS (Session Manager Subsystem) | Trình quản lý session | smss.exe — khởi động session |
| Stack | Stack | Vùng nhớ cho call stack của thread |
| Symbolic Link | Liên kết tượng trưng | Object namespace alias |
| System Call (Syscall) | Lệnh gọi hệ thống | Cơ chế user→kernel transition |
| System Service Descriptor Table (SSDT) | Bảng mô tả dịch vụ hệ thống | Bảng syscall numbers của Windows |

## T

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| TEB (Thread Environment Block) | Khối môi trường luồng | User-mode struct của thread |
| Thread | Luồng | Đơn vị thực thi trong process |
| Thread Pool | Vùng luồng | Pool thread dùng chung |
| Token | Token | Access token — danh tính của subject |
| Trust Level | Mức tin cậy | Protected process trust hierarchy |

## U

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| UAC (User Account Control) | Kiểm soát tài khoản người dùng | Elevation prompt mechanism |
| Unicode | Unicode | Chuẩn encoding mặc định của Windows |
| User Mode | Chế độ người dùng | Ring 3, giới hạn hardware access |

## V

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| VBS (Virtualization-Based Security) | Bảo mật dựa trên ảo hóa | Hypervisor-protected memory regions |
| Virtual Address Space | Không gian địa chỉ ảo | Per-process memory map |
| Virtual Memory | Bộ nhớ ảo | Abstraction layer trên RAM vật lý |
| VAD (Virtual Address Descriptor) | Mô tả địa chỉ ảo | Kernel structure mô tả vùng nhớ |

## W

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Window Station | Trạm cửa sổ | Container cho Desktops trong session |
| WoW64 | WoW64 | 32-bit process trên 64-bit Windows |
| Working Set | Tập làm việc | RAM pages đang dùng của process |


## Additions from Chapters 9–12

| Thuật ngữ (English) | Tiếng Việt | Ghi chú |
|---|---|---|
| Alternate Data Stream (ADS) | Luồng dữ liệu thay thế | Named `$DATA` stream trong NTFS; artifact/visibility concern |
| Boot Configuration Data (BCD) | Dữ liệu cấu hình boot | Store cấu hình Windows Boot Manager/loader |
| Credential Guard | Bảo vệ credential bằng VBS | Isolate credential material trong VTL1 trustlet khi enabled |
| Early Launch Anti-Malware (ELAM) | Anti-malware khởi chạy sớm | Driver security classification early boot |
| ETW Provider | Provider ETW | Component phát event ETW |
| ETW Session | Phiên ETW | Collector/session enable provider và buffer events |
| Event Log Channel | Kênh Event Log | Application/System/Security/Operational/Admin channel |
| GFlags | Global Flags | Debug/diagnostic flags; có thể thay đổi runtime behavior |
| Hard Link | Liên kết cứng | Nhiều directory entries trỏ cùng file record |
| HVCI | Hypervisor-Protected Code Integrity | Memory Integrity; enforce kernel code integrity with hypervisor support |
| IFEO | Image File Execution Options | Registry-based per-image debug/diagnostic settings |
| Junction | Junction directory | Directory reparse point redirecting to another path |
| Measured Boot | Boot đo lường | Measurements extended into TPM PCRs for attestation |
| NTFS Symbolic Link | Symlink file system | File system reparse-point based symbolic link |
| Object Manager Symbolic Link | Symlink object namespace | Object Manager alias như `\??\C:` tới device path |
| ReFS | Resilient File System | File system focused on resiliency/integrity; not NTFS |
| Reparse Point | Điểm xử lý lại đường dẫn | NTFS metadata triggering special path processing |
| Secure Boot | Boot an toàn | UEFI verifies signed boot components |
| Secure Kernel | Kernel bảo mật | VTL1 secure-world kernel component under VBS |
| USN Journal | Nhật ký thay đổi USN | NTFS change journal; metadata changes, not content |
| Virtual Trust Level (VTL) | Mức tin cậy ảo | Hypervisor-enforced trust level: VTL0/VTL1 |
| Volume Shadow Copy Service (VSS) | Dịch vụ snapshot volume | Point-in-time volume snapshots |
| Windows Defender Application Control (WDAC) | Kiểm soát ứng dụng Windows Defender | Policy-based code execution control |
| Windows OS Loader (winload.efi) | Bộ nạp OS Windows | Loads kernel/HAL/boot drivers during boot |
| Windows Performance Analyzer (WPA) | Công cụ phân tích hiệu năng Windows | Analyze ETL traces from WPR |
| Windows Performance Recorder (WPR) | Công cụ ghi trace hiệu năng Windows | Records ETW-based performance traces |
| Windows Recovery Environment (WinRE) | Môi trường phục hồi Windows | Offline repair/recovery environment |
| WMI Provider | Provider WMI | Component backing WMI/CIM classes/events |

---

*Bảng thuật ngữ này được cập nhật theo từng chapter mới.*
