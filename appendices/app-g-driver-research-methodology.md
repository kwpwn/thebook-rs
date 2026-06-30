# Appendix G: Driver Research Methodology

> **Framing note:** Appendix này là methodology guide cho Windows kernel driver research từ góc nhìn security researcher — không phải hướng dẫn exploit development. Mục tiêu: hiểu driver architecture để identify attack surface, biết điểm nào EDR dùng để monitor, và biết tại sao một số visibility gap tồn tại ở kernel layer. Mọi lab trong appendix này chỉ thực hiện trên VM có snapshot, không phải production system.

---

## Status

Draft implementation.

---

## 0. Depends on

Ch.6 (I/O system, IRP, device stack, IOCTL), Ch.9 (VBS/HVCI — code signing enforcement), Ch.11, Ch.12.

---

## 1. Researcher Mindset

**Driver research không chỉ là "tìm CVE".**

Driver là kernel-mode code. Bug trong driver là bug trong Ring 0 — attacker có thể dùng để đạt kernel-mode code execution, disable security software, hoặc đọc/ghi bất kỳ memory nào trong system.

Với security researcher, driver research có nhiều mục đích:

| Mục đích | Cụ thể |
|---|---|
| **BYOVD research** | Identify signed driver có vulnerable IOCTL → kernel code execution path |
| **EDR architecture** | Hiểu kernel callback driver của EDR: điểm nào nó observe, blind spot nào |
| **Kernel attack surface** | Mỗi device object với weak ACL là attack surface cho user-mode → kernel privilege escalation |
| **Telemetry gap analysis** | Hiểu tại sao minifilter không thấy tất cả I/O; callback không cover tất cả cases |
| **Defensive driver development** | Viết EDR sensor đúng cách, không tạo vulnerability |

**Ba câu hỏi đúng với mọi driver:**

1. **Driver tạo device object nào?** — Tên, ACL, accessible từ đâu (user mode, kernel mode only?)
2. **IOCTL dispatch table expose gì?** — Input/output method, buffer validation, privilege check
3. **Driver chạy ở IRQL nào?** — Có lock, có potential deadlock, có memory constraint gì?

---

## 2. Windows Driver Model Overview

### 2.1 WDM vs WDF

| Framework | Full name | Đặc điểm | Dùng khi nào |
|---|---|---|---|
| **WDM** | Windows Driver Model | Low-level, manual IRP handling, no framework overhead | Legacy drivers, drivers cần full control over IRP lifecycle |
| **KMDF** | Kernel-Mode Driver Framework (WDF) | Abstraction trên WDM; automatic IRP completion, power management, PnP handling | Modern kernel drivers; recommended cho mới |
| **UMDF** | User-Mode Driver Framework (WDF) | Chạy trong user mode (trong `Wudfrd.exe` host process); crash không BSOD | Drivers không cần kernel access (HID, USB non-critical) |

**Security implication của UMDF:** UMDF driver crash không BSOD system. Nhưng vẫn có elevated privilege hơn standard user process. Bug trong UMDF driver = privilege escalation trong user-mode host.

### 2.2 Driver Types

```
Driver type hierarchy:
  Bus driver          ← enumerate devices trên bus (PCI, USB, ACPI)
      └── Function driver    ← implement device functionality (NIC, disk, HID)
              └── Filter driver   ← sit above or below function driver; intercept IRP
                      └── Minifilter    ← file system filter (standardized filter model)
```

| Type | Role | Ví dụ | Security relevance |
|---|---|---|---|
| **Bus driver** | Enumerate child devices, manage bus power | `acpi.sys`, `pci.sys`, `usbhub.sys` | PnP attack surface; ACPI table manipulation |
| **Function driver** | Implement device class functionality | `ndis.sys` (network), `disk.sys`, `kbdclass.sys` | Device-specific vulnerabilities; raw device access |
| **Upper filter** | Sit above function driver in stack | EDR file monitor (upper filter trên storage) | Intercept operations before function driver |
| **Lower filter** | Sit below function driver | Disk encryption driver (intercept before disk) | Intercept after function driver, before hardware |
| **Minifilter** | File system filter với standardized model | CrowdStrike, Defender minifilter | Standard EDR file monitoring mechanism; altitude determines order |
| **NDIS filter** | Network stack filter | Packet capture, firewall | Packet-level network interception |
| **WFP callout** | WFP-integrated network filter | Windows Firewall, network EDR | Connection-level network inspection |

### 2.3 Device Stack

Mỗi device có một stack của driver objects:

```
\Device\MyDevice
        ↑
   Upper filter driver object(s)
        ↑
   Function driver object (FDO)
        ↑
   Lower filter driver object(s)
        ↑
   PDO (Physical Device Object — từ bus driver)
```

IRP đi **top-down** khi gửi, **bottom-up** khi complete. Mỗi driver trong stack có thể:
- Complete IRP và return (IRP không tiếp tục đi xuống)
- Pass IRP xuống tới driver tiếp theo
- Modify IRP rồi pass xuống
- Queue IRP để xử lý async

**WinDbg command để xem device stack:**
```windbg
!devstack \Device\MyDevice
!drvobj \Driver\MyDriver 7
!devobj \Device\MyDevice
```

### 2.4 Driver Signing

| Signing type | Yêu cầu | Khi nào dùng |
|---|---|---|
| **WHQL** | Microsoft-signed (Windows Hardware Quality Labs testing) | Production kernel drivers; mandatory cho 64-bit Windows 8+ in non-test mode |
| **EV certificate** | Extended Validation code signing certificate | Kernel drivers từ Windows 10 1607+ (WHQL no longer sole requirement, but EV required for submission) |
| **Attestation signing** | Faster Microsoft signing without full HLK testing | Drivers submitted via Hardware Dev Center |
| **Test signing** | Self-signed hoặc any cert; `bcdedit /set testsigning on` | Development và research VM only |
| **Cross-signed** | Legacy signing; cross-cert chain to Microsoft root | Legacy drivers (Windows 7 era) |

**HVCI impact:** HVCI (Hypervisor-Protected Code Integrity) enforce rằng mọi kernel-mode page được execute phải đã qua code integrity check. Driver phải pass HVCI compatibility check. Kernel exploit technique dùng unsigned shellcode bị block khi HVCI enabled.

---

## 3. Driver Entry Points

### 3.1 DriverEntry và DriverObject

```c
// Mọi driver bắt đầu tại DriverEntry — equivalent của main() cho driver
NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,   // kernel structure đại diện driver
    PUNICODE_STRING RegistryPath   // path trong registry HKLM\SYSTEM\...\Services\<name>
)
{
    // 1. Đăng ký dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = MyDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = MyDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_READ]           = MyDispatchRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE]          = MyDispatchWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDispatchIoctl;
    
    // 2. Đăng ký unload routine
    DriverObject->DriverUnload = MyDriverUnload;
    
    // 3. Tạo device object
    IoCreateDevice(
        DriverObject,
        0,                          // DeviceExtension size
        &deviceName,               // \Device\MyDevice
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &gDeviceObject
    );
    
    // 4. Tạo symbolic link để user mode access được
    IoCreateSymbolicLink(&symLinkName, &deviceName);
    // \DosDevices\MyDevice → \Device\MyDevice
    // → user mode có thể CreateFile("\\\\.\\MyDevice", ...)
    
    return STATUS_SUCCESS;
}
```

### 3.2 Major Function Dispatch Table

| Major function code | Triggered by | Researcher notes |
|---|---|---|
| `IRP_MJ_CREATE` | `CreateFile()` trên device | First gate: security check, access mask validation |
| `IRP_MJ_CLOSE` | `CloseHandle()` — handle count → 0 | Cleanup resources |
| `IRP_MJ_CLEANUP` | `CloseHandle()` — last handle for file object | Flush pending operations |
| `IRP_MJ_READ` | `ReadFile()` | Data exfiltration surface nếu driver read từ sensitive resource |
| `IRP_MJ_WRITE` | `WriteFile()` | Arbitrary kernel write nếu buffer not validated |
| `IRP_MJ_DEVICE_CONTROL` | `DeviceIoControl()` | **Primary IOCTL attack surface** — custom codes, complex handlers |
| `IRP_MJ_INTERNAL_DEVICE_CONTROL` | Kernel-mode only IOCTL | Không accessible từ user mode trực tiếp |
| `IRP_MJ_POWER` | Power management | Power state transitions |
| `IRP_MJ_PNP` | Plug and Play events | Device arrival/removal |
| `IRP_MJ_SYSTEM_CONTROL` | WMI requests | WMI data provider interface |

### 3.3 IOCTL CTL_CODE Macro

```c
// CTL_CODE macro tạo IOCTL code 32-bit
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

// Ví dụ:
#define IOCTL_MY_OP CTL_CODE(
    FILE_DEVICE_UNKNOWN,  // DeviceType: 0x22
    0x800,                // Function: custom range 0x800-0xFFF
    METHOD_BUFFERED,      // Buffer method
    FILE_ANY_ACCESS       // Access: không check
)
```

**Buffer Methods:**

| Method | Cơ chế | Security implication |
|---|---|---|
| `METHOD_BUFFERED` | Kernel copy input vào system buffer; copy output ra | Safest — kernel control buffer size; driver access `Irp->AssociatedIrp.SystemBuffer` |
| `METHOD_IN_DIRECT` | Input: buffered; Output: MDL-locked user buffer | Nếu driver không validate MDL lock, potential issue |
| `METHOD_OUT_DIRECT` | Input: system buffer; Output: MDL-locked user buffer read | Output buffer phải writable bởi user |
| `METHOD_NEITHER` | Driver nhận trực tiếp user-mode pointers | **Highest risk** — driver phải dùng `ProbeForRead`/`ProbeForWrite` + try/except; thiếu sót = kernel read/write arbitrary memory |

---

## 4. IOCTL Security Research

### 4.1 Flow từ User Mode đến Driver

```
DeviceIoControl(
    hDevice,          // handle từ CreateFile("\\\\.\\MyDevice")
    IOCTL_CODE,       // 32-bit code
    InputBuffer,      // user-mode input buffer
    InputSize,
    OutputBuffer,     // user-mode output buffer
    OutputSize,
    &BytesReturned,
    NULL
)
    ↓
kernel32.dll!DeviceIoControl()
    ↓ NtDeviceIoControlFile() syscall
    ↓
I/O Manager tạo IRP:
  IRP.Parameters.DeviceIoControl.IoControlCode = IOCTL_CODE
  IRP.Parameters.DeviceIoControl.InputBufferLength = InputSize
  IRP.Parameters.DeviceIoControl.OutputBufferLength = OutputSize
  (buffer handling depends on METHOD_*)
    ↓
Driver's MajorFunction[IRP_MJ_DEVICE_CONTROL] dispatch routine
    ↓
Handler đọc IOCTL code, dispatch internal
    ↓
Complete IRP với NTSTATUS + BytesWritten
```

### 4.2 Device Object ACL

Khi driver tạo device object, ACL mặc định của device object kiểm soát ai có thể mở handle:

```c
// Cách 1: Default ACL (thường chỉ SYSTEM và admins)
IoCreateDevice(DriverObject, 0, &deviceName, ..., &gDeviceObject);

// Cách 2: Security descriptor explicit
SECURITY_DESCRIPTOR sd;
InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE);  // dacl = custom ACL

// Cách 3: SDDL trong INF file (preferred modern approach)
// AddReg section trong .inf:
// HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
// GA = GENERIC_ALL, SY = SYSTEM, BA = Builtin Admins
```

**Misconfigured ACL:**
- Nếu device object ACL cho phép `FILE_ANY_ACCESS` từ low-privilege user → user có thể open handle và gửi IOCTL
- Vulnerable IOCTL handler + user-accessible device = privilege escalation từ user mode
- Tool: `accesschk.exe -kd \Device\*` — kiểm tra device object permissions

### 4.3 Common IOCTL Vulnerability Classes

| Bug class | Mô tả | Ví dụ pseudocode |
|---|---|---|
| **Unchecked buffer size** | Driver tin tưởng `InputBufferLength` không validate đủ nhỏ | `memcpy(kernelBuf, userInput, inputLen)` — nếu kernelBuf nhỏ hơn inputLen → kernel heap overflow |
| **Type confusion** | Cast input buffer vào struct không validate magic/version | Attacker craft struct với malicious field values |
| **ProbeForRead/Write missing** | METHOD_NEITHER mà không probe user pointer | Driver dereference user pointer trong kernel → TOCTOU hoặc kernel read |
| **Integer overflow in size** | `size_t total = a * b` — overflow nếu a, b lớn | Allocate nhỏ, copy nhiều → heap overflow |
| **TOCTOU** | Probe user pointer lần 1, đọc value lần 2 — giá trị thay đổi ở giữa | Race condition exploit |
| **NULL pointer dereference** | Không validate con trỏ trước khi dereference | Attacker map NULL page (user mode 32-bit) → controlled kernel NULL deref |
| **Use-After-Free** | Đối tượng được free nhưng vẫn được reference trong callback | Timing attack giữa free và use |

**Anatomy của vulnerable IOCTL (pseudocode — educational):**

```c
// VULNERABLE — đừng dùng trong production
NTSTATUS BadIoctlHandler(PDEVICE_OBJECT DevObj, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    
    if (code == IOCTL_MY_OPERATION) {
        // BUG 1: Không kiểm tra InputBufferLength
        MY_INPUT_STRUCT* input = (MY_INPUT_STRUCT*)Irp->AssociatedIrp.SystemBuffer;
        
        // BUG 2: Dùng size từ user-controlled input, không validate
        ULONG copySize = input->requestedSize;  // attacker controls this!
        
        PVOID kernelBuffer = ExAllocatePool(NonPagedPool, 64);  // fixed 64 bytes
        RtlCopyMemory(kernelBuffer, input->data, copySize);     // if copySize > 64 → overflow
        
        // BUG 3: Không check return value của alloc
    }
}

// CORRECT pattern
NTSTATUS GoodIoctlHandler(PDEVICE_OBJECT DevObj, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    
    // Validate minimum input size
    if (inputLen < sizeof(MY_INPUT_STRUCT)) {
        return CompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    
    MY_INPUT_STRUCT* input = (MY_INPUT_STRUCT*)Irp->AssociatedIrp.SystemBuffer;
    
    // Validate user-supplied size against actual input length
    if (input->requestedSize > inputLen - offsetof(MY_INPUT_STRUCT, data)) {
        return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);
    }
    
    // Safe to proceed
}
```

---

## 5. Kernel Driver Static Analysis

### 5.1 Tools

| Tool | Dùng cho | Notes |
|---|---|---|
| **IDA Pro** | Disassembly, decompilation (Hex-Rays), scripting | Industry standard; expensive; best kernel symbol support |
| **Binary Ninja** | Disassembly + BNIL IL; good for scripting | Modern UI; cheaper; improving kernel support |
| **Ghidra** | Free NSA-developed decompiler | Free; good for initial analysis; less accurate decompilation than Hex-Rays |
| **WinDbg + .NET extension** | Dynamic analysis + static symbol lookup | Best for live kernel + symbol correlation |
| **dumpbin.exe** (VS SDK) | PE header, imports, exports | Quick check từ command line |

### 5.2 Static Analysis Workflow

**Bước 1: Kiểm tra signature và imports**

```powershell
# Kiểm tra signature
Get-AuthenticodeSignature "C:\Windows\System32\drivers\example.sys" | 
  Select-Object Status, SignerCertificate

# Check imports — thấy kernel APIs driver dùng
dumpbin /imports example.sys | findstr /i "ExAllocate IoCreate Probe Zw Nt"
```

**Key imports để tìm:**

| Import | Ý nghĩa |
|---|---|
| `ExAllocatePoolWithTag` | Kernel heap alloc — check sau đó là size validation? |
| `IoCreateDevice` | Tạo device object — check security descriptor |
| `IoCreateSymbolicLink` | Expose device đến user mode |
| `ProbeForRead` / `ProbeForWrite` | Validate user pointer — thiếu = potential vulnerability |
| `MmMapLockedPagesSpecifyCache` | Map MDL → memory access |
| `ZwReadVirtualMemory` / `ZwWriteVirtualMemory` | Kernel-level memory read/write — red flag cho BYOVD candidates |
| `MmCopyMemory` | Copy arbitrary kernel memory |

**Bước 2: Tìm IOCTL dispatch trong IDA/Ghidra**

```
Trong IDA:
1. Tìm DriverEntry function (entry point hoặc export)
2. Tìm MajorFunction array assignment:
   - Thường pattern: mov [rax + offset], rbx  ; rax = DriverObject
3. Follow function pointer cho IRP_MJ_DEVICE_CONTROL (index 14 = 0xE trong array)
4. Trong dispatch function, tìm switch statement trên IoControlCode
5. Analyze mỗi case — kiểm tra buffer size validation
```

**Bước 3: Check ProbeForRead/Write trong METHOD_NEITHER handlers**

```
Trong IDA/Ghidra:
1. Với METHOD_NEITHER IOCTL, driver nhận trực tiếp user pointer
2. Tìm call đến ProbeForRead hoặc ProbeForWrite trước khi dereference
3. Tìm try/except (SEH frame) quanh pointer dereference
4. Nếu thiếu một trong hai → potential vulnerability
```

**Bước 4: Enumerate device objects**

```windbg
# Tìm tất cả device của driver
!drvobj \Driver\DriverName 3

# Xem device cụ thể
!devobj \Device\DeviceName

# Xem device security descriptor
dt nt!_DEVICE_OBJECT <addr>
  +0x040 SecurityDescriptor
```

---

## 6. Dynamic Analysis và Live Debugging

### 6.1 Setup: Kernel Debugging với WinDbg

**VMware setup:**
```
VM Settings → Add → Serial Port
  Connection Type: Named Pipe
  Pipe: \\.\pipe\com_1
  "This end is the server"
  "The other end is an application"
  
Trên VM (PowerShell as Admin):
  bcdedit /debug on
  bcdedit /dbgsettings serial debugport:1 baudrate:115200
  Restart-Computer
  
WinDbg (host):
  File → Attach to Kernel → COM
  Port: \\.\pipe\com_1
  Baud: 115200
  Pipe: checked
```

**WinDbg Preview via Network (KDNET — easier):**
```powershell
# Trên VM
bcdedit /dbgsettings net hostip:<host_ip> port:50000 key:1.2.3.4
bcdedit /debug on
Restart-Computer

# WinDbg (host)
# File → Attach to Kernel → Net
# Port: 50000, Key: 1.2.3.4
```

### 6.2 Breakpoints trên Driver

```windbg
; Sau khi driver load, set breakpoint trên IOCTL handler
bp DriverName!DriverDispatchIoControl

; Hoặc theo address (tìm từ lm)
lm m DriverName          ; xem base address
bp DriverName+0x1234     ; offset từ IDA analysis

; Break khi driver load
sxe ld:DriverName.sys

; Khi hit IOCTL breakpoint, xem IRP
dt nt!_IRP @rcx          ; rcx = IRP parameter trong dispatch routine
!irp @rcx                ; dump IRP structure
r                        ; xem registers

; Xem IO_STACK_LOCATION
dt nt!_IO_STACK_LOCATION poi(@rcx+0x70)
; +0x070 Tail.Overlay.CurrentStackLocation

; Continue
g
```

### 6.3 Monitoring Driver Load

```windbg
; Break khi bất kỳ image load
sxe ld

; Chỉ break cho driver cụ thể
sxe ld:targetdriver.sys

; Sau khi driver load:
lm m targetdriver   ; verify loaded
!drvobj \Driver\TargetDriver 3
```

```powershell
# Sysmon Event 6: Driver loaded
# Check: System log, Image, Hashes, Signed, Signature
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | 
  Where-Object { $_.Id -eq 6 } | 
  Select-Object -First 10 |
  Format-List TimeCreated, Message
```

### 6.4 IOCTL Fuzzing (Conceptual)

IOCTL fuzzing gửi random/mutated data đến driver IOCTL handler để tìm crash:

```
Approach cơ bản:
1. Enumerate IOCTL codes — manual (IDA) hoặc bruteforce
   DeviceIoControl(hDev, ioctl_code, ...) với code từ 0x220000 đến 0x22FFFF
   
2. Fuzz buffer size: gửi IOCTL với InputBufferLength từ 0 đến 4096
   → Tìm crash với specific size (buffer overflow boundary)
   
3. Fuzz buffer content: random bytes trong valid-size buffer
   → Tìm crash với specific byte patterns (type confusion, pointer deref)
   
4. Monitor: WinDbg hoặc VM crash dump
   → BSOD với DRIVER_IRQL_NOT_LESS_OR_EQUAL, ACCESS_VIOLATION, etc.
   
Tools: ioctlbf (open source), custom PowerShell/C# fuzzer
```

---

## 7. BYOVD (Bring Your Own Vulnerable Driver)

### 7.1 Concept

BYOVD là kỹ thuật attacker dùng driver đã signed (legitimate) nhưng có vulnerability để đạt kernel execution:

```
Attacker có admin access
    ↓
Load signed vulnerable driver (admin + SeLoadDriverPrivilege)
  CreateService() + StartService() hoặc NtLoadDriver()
    ↓
Exploit vulnerability trong driver IOCTL interface
  (từ user mode, vì device ACL thường cho admin)
    ↓
Kernel code execution (Ring 0)
    ↓
Patch EPROCESS.Protection (disable PPL lsass)
Patch kernel callback table (disable EDR callbacks)
Disable minifilter
    ↓
Dump credentials, disable AV, install rootkit
```

### 7.2 Common Vulnerable Driver Classes

| Vulnerability class | Ví dụ capability | Tại sao nguy hiểm |
|---|---|---|
| **Physical memory read/write IOCTL** | IOCTL nhận physical address + size → read/write RAM trực tiếp | Patch kernel structures, bypass PPL, disable callbacks |
| **Virtual memory read/write** | Cross-process `ReadVirtualMemory` / `WriteVirtualMemory` qua kernel | Bypass process memory protections; read lsass memory |
| **MSR read/write** | Read/write Model-Specific Registers | Control SYSCALL handler, hypervisor interaction |
| **Port I/O** | In/out instructions đến I/O ports | Hardware-level control; SMM attack vector |
| **MmMapIoSpace abuse** | Map physical memory range vào kernel virtual address | Same as physical read/write |

### 7.3 Detection và Mitigation

**Detection:**
```powershell
# Sysmon Event 6 — Driver load với hash và signature
# Alert trên: driver load từ unusual path, known-bad hash

# Check against loldrivers.io blocklist
# loldrivers.io publish list của known vulnerable signed drivers

# PsSetLoadImageNotifyRoutine trong kernel:
# EDR driver callback fires khi ANY .sys file loads
# Can correlate file hash với blocklist

# Windows Event 7045 (System) khi service created:
Get-WinEvent -LogName System | Where-Object { $_.Id -eq 7045 } |
  Select-Object TimeCreated, Message | Format-List
```

**Mitigation:**
- **HVCI (Hypervisor-Protected Code Integrity):** Prevent unsigned kernel code. Không ngăn load signed vulnerable driver, nhưng ngăn inject shellcode sau khi exploit.
- **Microsoft Vulnerable Driver Blocklist:** Windows maintain blocklist của known vulnerable drivers. HVCI enforce blocklist.
- **Driver signing policy:** `bcdedit /set loadoptions DISABLE_INTEGRITY_CHECKS` disabled trong production.
- **Audit driver installs:** Monitor Event 7045, alert trên unexpected driver names/paths.

```powershell
# Kiểm tra HVCI status
$ci = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue
if ($ci.Enabled -eq 1) { "HVCI Enabled" } else { "HVCI Disabled or not configured" }

# Kiểm tra driver blocklist enforcement
$dg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" -ErrorAction SilentlyContinue
```

---

## 8. Kernel Callbacks như Research Target

### 8.1 EDR Callback Registration

EDR kernel driver đăng ký callback để monitor system events:

```c
// Process creation callback
PsSetCreateProcessNotifyRoutineEx(MyProcessCallback, FALSE);

// Thread creation callback
PsSetCreateThreadNotifyRoutine(MyThreadCallback);

// Image load callback
PsSetLoadImageNotifyRoutine(MyImageCallback);

// Object handle callback
OB_CALLBACK_REGISTRATION reg = { ... };
ObRegisterCallbacks(&reg, &RegistrationHandle);

// Registry callback
CmRegisterCallback(MyRegistryCallback, NULL, &cookie);
```

### 8.2 Enumerate Callbacks với WinDbg

```windbg
; Process create callbacks (maximum 64 callbacks)
; Callbacks stored trong PspCreateProcessNotifyRoutine array (internal name may vary by build)
; Extension !pscallbacks available via WDK debugger extensions

; Method 1: extension command (nếu available)
!pscallbacks

; Method 2: manual enumeration — find array
x nt!PspCreate*Notify*
; hoặc
x nt!Psp*Notify*

; Xem callback entries
dq nt!PspCreateProcessNotifyRoutine L40h

; Mỗi entry là pointer (encoded/hashed — attacker bypass cần decode)
; Routine pointer thường encoded: ptr XOR nt!ExpLookupHandleTableEntry (varies by build)

; Image load callbacks
dq nt!PspLoadImageNotifyRoutine L40h

; Thread create callbacks
dq nt!PspCreateThreadNotifyRoutine L40h

; Object callbacks (ObRegisterCallbacks)
dt nt!_OBJECT_TYPE poi(nt!PsProcessType)
  → CallbackList là linked list của registered callbacks
```

### 8.3 Callback Tampering — Researcher Awareness

Attacker với kernel access có thể:
- Zero out entries trong callback arrays → callback không fire
- Patch callback function pointer → redirect đến NOP sled
- Modify `CallbackList` trong `OBJECT_TYPE` → handle callback không fire

**Detection của tampering:**
- EDR có thể self-monitor: periodic re-verify callback registration
- Hypervisor-based monitoring (VTL1) có thể detect write đến callback arrays trong VTL0
- HVCI không prevent patching callback data structures — chỉ prevent execute unsigned code

```windbg
; Verify callback entries match expected drivers
; Mỗi entry sau khi decode phải trỏ vào valid module
lm                    ; list loaded modules và address ranges
; So sánh callback addresses với module ranges
```

### 8.4 Minifilter Altitude và Ordering

Minifilter attach tại specific altitude — số cao hơn = higher in stack = sees I/O trước:

```
Altitude ranges:
  420000-429999: FSFilter Activity Monitor
  360000-369999: FSFilter Undelete
  340000-349999: FSFilter Anti-Virus ← EDR file protection
  320000-329999: FSFilter Replication
  260000-269999: FSFilter Quota Management
  180000-189999: FSFilter Imaging
  140000-149999: FSFilter Encryption ← disk encryption
  ...

Ví dụ:
  CrowdStrike Falcon: altitude 327680
  Microsoft Defender: altitude 328010
  Symantec: altitude 86100 (older)
```

```powershell
# Enumerate registered minifilters
fltmc.exe instances

# Hoặc
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\FltMgr\Instances" -ErrorAction SilentlyContinue
```

---

## 9. Driver Research Tools

| Tool | Category | Key use | Notes |
|---|---|---|---|
| **WinDbg / WinDbg Preview** | Dynamic analysis | Kernel debugging, crash dump analysis, live inspection | Essential; kết hợp với VM |
| **IDA Pro** | Static analysis | Disassembly + Hex-Rays decompilation | Industry standard; supports .sys files well |
| **Ghidra** | Static analysis | Free decompiler từ NSA | Good starting point; free |
| **Binary Ninja** | Static analysis | Modern UI + BNIL; good scripting | $$ but cheaper than IDA |
| **OSR Driver Loader** | Driver loading | Load test/unsigned drivers trong test-signed environment | OSR Online tool; VM only |
| **DriverView (Nirsoft)** | Enumeration | List all loaded kernel drivers với details | Free; easy GUI |
| **driverquery.exe** | Enumeration | Built-in Windows tool; quick driver inventory | `driverquery /v /fo csv` |
| **fltmc.exe** | Minifilter | List registered minifilters và altitudes | Built-in |
| **accesschk.exe** | Permission audit | Check device object ACLs | Sysinternals; essential |
| **WinObj** | Object namespace | Browse `\Device\` namespace | Sysinternals |
| **Process Monitor** | Dynamic | IRP-level file I/O visibility | Sysinternals; minifilter-based |
| **SysInternals LiveKd** | Memory | Kernel dump từ live system không pause | Read-only kernel inspection |
| **loldrivers.io** | Intel | Database của known vulnerable signed drivers | Reference cho BYOVD research |

---

## 10. Labs

> **Lưu ý:** Mọi lab liên quan đến driver analysis phải chỉ thực hiện trên **Windows VM có snapshot**. Không thực hiện kernel debugging hay load test driver trên production system.

### Lab G.1 — Enumerate All Loaded Kernel Drivers

**Goal:** Thấy toàn bộ kernel drivers hiện tại và phân loại.

**Requirements:**
- Windows 10/11 VM
- PowerShell (admin)
- DriverView (Nirsoft, optional)

**Steps:**
1. Dùng built-in `driverquery`:
   ```
   driverquery /v /fo csv > C:\Temp\drivers.csv
   ```
   Mở CSV — xem Name, DisplayName, Type, State, StartMode, Path

2. PowerShell — lọc theo type:
   ```powershell
   driverquery /fo csv | ConvertFrom-Csv | 
     Where-Object { $_.Type -eq "Kernel" -and $_.State -eq "Running" } |
     Sort-Object 'Module Name' |
     Select-Object 'Module Name', 'Display Name', 'Link Date', Path |
     Format-Table -AutoSize
   ```

3. So sánh với known-good baseline:
   ```powershell
   # Drivers không có Microsoft signature — potential third-party
   Get-ChildItem C:\Windows\System32\drivers\*.sys | 
     Get-AuthenticodeSignature | 
     Where-Object { $_.Status -ne "Valid" -or $_.SignerCertificate.Subject -notmatch "Microsoft" } |
     Select-Object Path, Status
   ```

4. Cross-reference với WinDbg nếu kernel debugging active:
   ```windbg
   lm type driver    ; list loaded drivers với addresses
   ```

**Expected:** Thấy 150-300 drivers trên typical Windows 10/11. Phần lớn Microsoft-signed. Third-party: antivirus, VPN, graphics, storage. Bất kỳ unsigned hoặc unknown path đáng điều tra thêm.

**Cleanup:** `Remove-Item C:\Temp\drivers.csv`

---

### Lab G.2 — Browse Device Namespace với WinObj

**Goal:** Thấy device objects trong Object Manager namespace.

**Requirements:**
- WinObj.exe (Sysinternals) — run as Administrator

**Steps:**
1. Mở WinObj.exe as Administrator
2. Browse `\Device\` — xem tất cả device objects
3. Tìm các device phổ biến:
   - `\Device\HarddiskVolume3` (hoặc number khác) — disk volume
   - `\Device\Tcp`, `\Device\Udp` — network
   - `\Device\KsecDD` — kernel security device (lsass dùng)
   - `\Device\PhysicalMemory` — RAW memory device (quan trọng về security)
4. Click vào một device để xem properties (Type, Security Descriptor)
5. Browse `\GLOBAL??` — xem drive letter symlinks:
   - `C:` → `\Device\HarddiskVolume3`
   - `PhysicalDrive0` → `\Device\Harddisk0\DR0`
6. Tìm `accesschk.exe -kd \Device\*`:
   ```
   accesschk.exe -kd \Device\
   ```
   Xem access rights của mỗi device — SYSTEM Only? Authenticated Users? Everyone?

**Expected:** `\Device\PhysicalMemory` thường chỉ accessible bởi SYSTEM (nếu Windows enforce) hoặc restricted kernel mode. Third-party driver devices thường accessible bởi Authenticated Users (nếu intended cho user-mode clients).

**Cleanup:** Không cần.

---

### Lab G.3 — Trace IOCTL Calls với Process Monitor

**Goal:** Thấy file-level và IRP-level activity của driver interaction.

**Requirements:**
- Process Monitor (Sysinternals) — run as Administrator
- Windows 10/11 VM

**Steps:**
1. Mở Process Monitor as Administrator
2. Filter: `Path contains \Device\` hoặc `Operation contains IRP`
3. Thực hiện một số device interactions:
   ```powershell
   # Đọc disk sectors (qua legitimate API)
   $disk = [System.IO.File]::Open("\\.\PhysicalDrive0", "Open", "Read")
   $buf = New-Object byte[] 512
   $disk.Read($buf, 0, 512)
   $disk.Close()
   ```
4. Quan sát trong Process Monitor:
   - Tên operation
   - Path (device path)
   - Result
   - Detail (IOCTL code nếu có)
5. Filter chỉ process của mình: `Process Name is powershell.exe`

**Expected:** Thấy IRP CREATE, IRP READ, IRP CLOSE cho `\Device\Harddisk0\DR0` hoặc tương tự.

**Cleanup:** Không cần.

---

### Lab G.4 — Basic Driver Inspection trong WinDbg (VM Only)

**Goal:** Kết nối WinDbg đến VM, inspect một driver.

**Requirements:**
- Windows 10/11 VM với kernel debugging enabled
- WinDbg Preview trên host
- VM snapshot trước khi thực hiện

**Steps:**

1. Trên VM (PowerShell as Admin):
   ```
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   ```
   Tạo serial port trong VM settings → Named pipe → `\\.\pipe\com_1`
   
2. Restart VM; kết nối WinDbg:
   - File → Attach to Kernel → COM Port: `\\.\pipe\com_1`, Baud: 115200, Pipe: checked

3. Sau khi connected, load symbols:
   ```windbg
   .sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
   .reload /f
   ```

4. List loaded drivers:
   ```windbg
   lm type driver
   ```

5. Inspect một driver (ví dụ: NTFS):
   ```windbg
   !drvobj \Driver\Ntfs 7
   !devobj \Device\HarddiskVolume3
   dt nt!_DRIVER_OBJECT <address from lm output>
   ```

6. Xem dispatch table của driver:
   ```windbg
   dt nt!_DRIVER_OBJECT <addr>
   ; xem MajorFunction array
   dq <addr>+offset_of_MajorFunction L1ch  ; 0x1c = 28 entries
   ```

7. Continue VM khi done:
   ```windbg
   g
   ```

**Expected:** Thấy DRIVER_OBJECT structure, dispatch table addresses, device objects. Dispatch table entries point vào code within driver module (verify với `lm`).

**Cleanup:** Restore VM snapshot sau lab.

---

## 11. References

### Microsoft WDK / Documentation
- [Windows Driver Model (WDK Docs)](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/)
- [Windows Driver Framework (WDF)](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/)
- [KMDF Driver Development Guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/kernel-mode-driver-framework-design-guide)
- [I/O Request Packets (IRPs)](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/i-o-request-packets)
- [IOCTL Design Guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes)
- [Driver Signing Policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)
- [Minifilter Driver Design](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)
- [HVCI and Driver Compatibility](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/updating-driver-code-to-load-properly-with-hvci)

### Research Resources
- [OSR Online (osronline.com)](https://www.osronline.com) — kernel driver development articles, WDK tutorials
- [j00ru.vexillium.org](https://j00ru.vexillium.org) — syscall tables, kernel research, driver analysis
- [Alex Ionescu (ionescu007.github.io)](https://ionescu007.github.io) — Windows internals deep dives
- [loldrivers.io](https://www.loldrivers.io) — Living Off The Land Drivers — database of vulnerable signed drivers
- [tiraniddo.dev](https://www.tiraniddo.dev) — James Forshaw; Windows kernel, ALPC, privilege escalation research
- [Windows Internals 7th Ed., Part 2 — Ch. on I/O System (driver model)](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)

### Tools
- [WinDbg Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
- [OSR Driver Loader](https://www.osronline.com/article.cfm%5earticle=157.htm)
- [DriverView — Nirsoft](https://www.nirsoft.net/utils/driverview.html)

---

*Appendix G hoàn thành. Xem tiếp: [Appendix H — Windows Exploit Mitigation Overview](app-h-windows-exploit-mitigation-overview.md)*
