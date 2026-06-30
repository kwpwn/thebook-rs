# Appendix J: Windows 11 Delta Notes

> **Framing note:** Appendix này ghi lại những thay đổi từ Windows 10 sang Windows 11 và qua các Windows 11 versions (21H2, 22H2, 23H2, 24H2) liên quan đến Windows Internals research, security, và EDR/AV architecture. Đây không phải changelog đầy đủ — đây là *researcher-relevant delta*: những gì thay đổi ảnh hưởng đến phân tích, detection, attack surface modeling, và lab setup.

---

## Status

Draft implementation. Một số chi tiết version-specific cần verification với actual build symbols và changelogs chính thức.

---

## Depends on

Ch.1–12 (toàn bộ core content); Appendix C (Kernel Debugging), Appendix E (Lab Setup), Appendix H (Exploit Mitigations).

---

## 0. Chapter Map

| Mục | Nội dung |
|-----|----------|
| 1 | Researcher Mindset |
| 2 | Windows 11 Hardware Requirements và Security Implications |
| 3 | Changes by Version |
| 4 | Syscall Number Changes |
| 5 | Kernel Structure Changes |
| 6 | Driver và Signing Changes |
| 7 | ETW Provider Changes |
| 8 | Smart App Control — Deep Dive |
| 9 | SMB Signing Enforced by Default |
| 10 | Security Research Lab Implications |
| 11 | Version Comparison Table |
| 12 | Labs |
| 13 | References |

---

## 1. Researcher Mindset

### Tại sao version delta quan trọng với researcher

Một trong những sai lầm phổ biến nhất của researcher là "hardcode assumptions từ một Windows version cụ thể."

**Ví dụ cụ thể:**
- Syscall number của `NtAllocateVirtualMemory` trên Windows 10 22H2 ≠ Windows 11 23H2
- `EPROCESS.MitigationFlags` offset thay đổi giữa major builds
- Code targeting `EPROCESS.Protection` tại hardcoded offset sẽ crash hoặc silently fail trên version khác
- Detection rule dựa vào event schema của ETW provider có thể miss events nếu field names thay đổi

**Nguyên tắc quan trọng:**
1. **Luôn dùng symbols**: `dt nt!_EPROCESS` với symbols đúng build — không hardcode offset
2. **Xác nhận syscall numbers**: Parse ntdll.dll của build đang target hoặc tra j00ru syscall table
3. **Test detection rules trên multiple builds**: Event field names và IDs có thể thay đổi
4. **Verify mitigation behavior**: Behavior của ACG, CET, HVCI có thể có corner cases khác nhau per build

**Windows 11 không chỉ là Windows 10 với new UI:**
- Hardware requirements tạo ra security baseline đồng đều hơn
- HVCI và VBS bật default trên nhiều hardware hơn
- Smart App Control là OS-level policy change lớn
- SMB signing changes ảnh hưởng network lateral movement modeling

---

## 2. Windows 11 Hardware Requirements và Security Implications

### 2.1 TPM 2.0 — Trusted Platform Module

**Yêu cầu**: Windows 11 bắt buộc TPM 2.0. Đây là hardware security chip với:
- Cryptographic key storage trong protected hardware enclave
- Measured boot attestation (PCR values)
- Secure storage cho BitLocker keys, Credential Guard keys
- Random number generation

**Security implications:**
- **Credential Guard** có thể enforce mà không cần configuration phức tạp: TPM 2.0 cung cấp secure key storage cho LSAISO (lsa isolated process)
- **BitLocker** đơn giản hơn: khóa stored trong TPM, auto-unlock on trusted boot
- **Measured boot**: Mỗi boot stage hash được extend vào PCR register; TPM attestation có thể verify integrity của boot sequence
- **PTT (Platform Trust Technology)**: Intel firmware TPM — không phải dedicated chip nhưng equivalent functionality. AMD có fTPM tương tự.

**Researcher implication:**
- Credential dumping tấn công LSASS memory sẽ không recover Credential Guard-protected credentials — chúng nằm trong LSAISO process, isolated bởi VTL 1, backed bởi TPM
- Pre-boot attacks (bootkit) khó hơn vì Secure Boot + measured boot chain
- Forensic recovery của BitLocker volumes cần TPM bypass hoặc recovery key

### 2.2 UEFI Secure Boot (bắt buộc)

**Yêu cầu**: Windows 11 yêu cầu UEFI với Secure Boot enabled. CSM (Compatibility Support Module — legacy BIOS emulation) phải disabled.

**Security implications:**
- Boot chain phải được signed: UEFI firmware → bootloader (`bootmgr.efi`) → Windows Boot Manager → Kernel
- Unsigned bootloader bị từ chối bởi UEFI firmware
- UEFI Secure Boot keys: Microsoft keys pre-installed; third-party keys có thể added
- Bootkit phải được signed hoặc exploit UEFI vulnerability để persist

**Researcher implication:**
- Kernel debugging yêu cầu disable Secure Boot trong UEFI settings (hoặc enable test-signing mode)
- BYOVD drivers phải be signed — nhưng existing signed vulnerable drivers vẫn là vector
- Memory forensics từ Secure Boot system cần account for VBS/measured boot state

### 2.3 CPU Requirements

**Windows 11 supported CPUs**: Intel 8th gen (Coffee Lake, 2017)+, AMD Zen 2+, Qualcomm Snapdragon 850+

**Security relevance của CPU requirements:**
- **Intel 8th gen+**: Tiger Lake (11th gen)+ có CET (Control-flow Enforcement Technology) hardware support
- **AMD Zen 3+**: CET support
- **MBEC (Mode-Based Execute Control)**: Cho phép HVCI chạy hiệu quả hơn (EPT split pages for user/kernel execute distinction) — không cần emulation trong VTL 1
- **VT-x / AMD-V bắt buộc**: Hyper-V yêu cầu hardware virtualization → VBS enabled on all hardware

**Kết quả thực tế:**
Windows 11 baseline = hardware đủ mạnh để chạy HVCI efficiently + CET phổ biến hơn. Security posture baseline của Windows 11 fleet cao hơn nhiều so với mixed Windows 10 fleet.

---

## 3. Changes by Version

### 3.1 Windows 11 21H2 (Build 22000) — Initial Release

**Security-relevant changes:**

**HVCI default expansion:**
- HVCI (Hypervisor-Protected Code Integrity) enabled by default trên hardware thỏa mãn: MBEC support + VT-x + IOMMU
- Nhiều OEM shipped hardware với HVCI on out-of-box
- Impact: Nhiều unsigned kernel code exploitation paths bị block theo mặc định

**Credential Guard default:**
- Trên Enterprise và Education SKUs, Credential Guard enabled by default
- Requires TPM 2.0 + UEFI Secure Boot (both required by Windows 11)
- lsass credentials isolated in LSAISO process (VTL 1)

**Win32k syscall filtering improvements:**
- AppContainer processes (UWP, sandboxed apps) có Win32k syscall filter mở rộng hơn
- Giảm Win32k attack surface từ sandboxed processes

**Microsoft Pluton preview:**
- Trên select hardware (Lenovo ThinkPad Z, Surface Pro 9 với SQ3): Pluton security chip tích hợp trong CPU die
- Keys stored in Pluton không accessible qua DMA hoặc firmware attacks
- Protected from "remove chip from motherboard" physical attacks

**Kernel stack protection:**
- Shadow stack support expanded trong kernel for CET-capable hardware
- Kernel shadow stacks protect kernel return addresses từ ROP attacks targeting kernel mode

### 3.2 Windows 11 22H2 (Build 22621)

**Smart App Control (SAC) — Major new feature:**

SAC là OS-level application allow-listing mechanism. Xem Section 8 cho deep-dive.

- Unsigned executables blocked nếu SAC mode = On
- Cloud intelligence + local ML model đánh giá reputation
- Three states: Evaluation → On → Off (one-way degradation to Off)
- Off = cannot re-enable without OS reinstall

**Enhanced Phishing Protection:**
- SmartScreen integration với Windows Security Center
- Detect khi user nhập credential vào non-HTTPS form hoặc suspicious domain
- Warns about password reuse (password entered matches known Windows credential)
- Detect password đang gõ vào non-trusted application (Notepad, Word document form)

**Microsoft Defender Tamper Protection improvements:**
- Tamper Protection ngăn chặn modification của Defender settings
- Mở rộng: ngăn attacker disable Defender qua registry, Group Policy, WMI
- Requires cloud connection hoặc Intune management

**CFG và shadow stack hardening:**
- CFG enforcement stricter trên nhiều system binaries
- Export suppression: functions được mark để không accessible qua indirect call từ non-CFG code
- Shadow stack coverage expanded

**Kernel changes:**
- EPROCESS field additions (MitigationFlags2, ProcessRundown improvements)
- Security baseline policy tightening

### 3.3 Windows 11 23H2 (Build 22631)

**SMB Signing enforced by default — Major network security change:**

Windows 11 23H2 enforce SMB signing trên outbound SMB client connections by default. Xem Section 9 cho chi tiết.

**Windows Protected Print Mode:**
- New print architecture: print drivers chạy trong user-mode (như Win32 service), không phải trong print spooler kernel/privileged context
- Loại bỏ toàn bộ class vulnerability: kernel-mode print driver exploitation
- PrintNightmare class vulnerabilities chạy trong spooler context — Protected Print Mode sandbox này
- Legacy drivers không tương thích; requires new-model drivers
- Preview trong 23H2, enforcement trajectory ongoing

**Passkeys và WebAuthn:**
- Built-in passkey manager trong Windows credentials store
- FIDO2/WebAuthn credential management qua Windows Hello
- Eliminates phishing surface của password authentication khi passkeys used
- EDR implication: credential theft via keylogger không capture passkey (no password entered)

**Admin Protection:**
- Experimental feature (some builds): standard user với Admin rights nhận **separate admin token** chỉ khi cần
- Khác với UAC: UAC là một consent dialog; Admin Protection là separate token isolation
- Giảm token abuse risk — admin không có elevated token available all the time
- Trạng thái: preview/experimental trong 23H2

**Security baseline adjustments:**
- Default audit policies expanded
- Additional event logging enabled by default
- PowerShell Script Block Logging improvements

### 3.4 Windows 11 24H2 (Build 26100)

**Recall (AI feature) — Privacy và security considerations:**
- Recall chụp screenshot định kỳ và OCR để tạo searchable timeline của activities
- Screenshots stored locally, encrypted với device keys
- Privacy concern: sensitive data (passwords, PII, keys) có thể appear trong screenshots
- Security concern: attacker với local access có thể access Recall database → exfiltrate activity history
- Microsoft added protections: Recall requires Windows Hello authentication để view; database encrypted at rest
- Researcher note: Recall database là forensic artifact source mới — activity timeline với significant detail

**Windows Protected Print finalized:**
- Protected Print Mode từ preview (23H2) → available across more SKUs
- Legacy GDI print driver model deprecated path clearer

**NTLM deprecation:**
- NTLMv1 disabled by default trên 24H2 (NTLMv2 still functional)
- Kerberos được ưu tiên rõ ràng hơn
- Implication: NTLM relay attacks against NTLMv1 no longer viable against default config
- NTLMv2 relay still possible nếu SMB signing không enforce (nhưng 23H2+ enforce SMB signing client-side)

**SMB over QUIC:**
- SMB transport over QUIC protocol (UDP-based, TLS 1.3)
- No VPN needed for remote SMB access over internet
- Security: TLS 1.3 + certificate-based auth; monitoring needs to account for QUIC traffic

**Sudo for Windows:**
- `sudo <command>` trong non-elevated terminal → runs command elevated
- Similar to Linux sudo UX
- Security implication: new code path cho privilege elevation; audit trail via Event Log (4688 với high integrity)

**Kernel improvements:**
- Additional CFI (Control Flow Integrity) enforcement
- Syscall table changes (verify với symbols)
- VBS/HVCI defaults expanded on supported hardware

---

## 4. Syscall Number Changes

### 4.1 Tại sao syscall numbers thay đổi

Windows không public contract cho syscall numbers — chúng là **implementation detail** của ntoskrnl.exe. Microsoft có thể (và do) thay đổi syscall numbers giữa builds khi:
- Thêm mới syscall vào bảng (shifts numbers)
- Reorder bảng cho optimization
- Security changes trong syscall dispatch

**Hệ quả:**
- Code hardcode syscall number (`mov eax, 0x55; syscall`) sẽ gọi sai function trên build khác
- Direct syscall implementation cần maintain syscall number table cho mỗi Windows build
- Detection rule dựa vào syscall number pattern cần account for this

### 4.2 Lấy syscall numbers — methods

**Method 1: Parse ntdll.dll**

ntdll.dll chứa syscall stubs. Mỗi stub có pattern:
```
4C 8B D1          mov r10, rcx
B8 XX XX XX XX   mov eax, <syscall_number>
F6 04 25 ...      test byte ptr [...]
75 03             jne <next>
0F 05             syscall
C3                ret
```
Parse binary → extract syscall number cho từng `NtXxx` function.

```powershell
# PowerShell — extract syscall numbers từ ntdll.dll
$ntdll = [System.IO.File]::ReadAllBytes("C:\Windows\System32\ntdll.dll")
$text = [System.Text.StringBuilder]::new()

# Simplified: tìm pattern B8 XX XX XX XX 0F 05
for ($i = 0; $i -lt $ntdll.Length - 6; $i++) {
    if ($ntdll[$i] -eq 0x4C -and $ntdll[$i+1] -eq 0x8B -and $ntdll[$i+2] -eq 0xD1 -and
        $ntdll[$i+3] -eq 0xB8) {
        $sysno = [BitConverter]::ToUInt32($ntdll, $i+4)
        # Name resolution cần separate step (export table parsing)
        Write-Host "Syscall number: 0x{0:X4}" -f $sysno
    }
}
```

**Method 2: WinDbg**
```windbg
; List all Nt* exports với their syscall numbers
x ntdll!Nt*

; Disassemble specific stub
uf ntdll!NtCreateFile
; Output sẽ show: mov eax, <syscall_number>
```

**Method 3: j00ru syscall table**
- URL: https://j00ru.vexillium.org/syscalls/nt/64/
- Maintained table của syscall numbers cho mọi NT/Win version
- Verify trước khi use — cần confirm với actual DLL của build bạn đang target

### 4.3 Windows 10 → Windows 11 syscall changes (pattern)

Syscall numbers không tăng đơn thuần — họ shift khi có syscalls mới được inserted. Một số syscalls quan trọng:

| Syscall | Win10 22H2 (approximate) | Win11 22H2 (approximate) | Ghi chú |
|---|---|---|---|
| `NtCreateFile` | 0x0055 | Verify với symbols | Common I/O syscall |
| `NtAllocateVirtualMemory` | 0x0018 | Verify với symbols | Memory allocation |
| `NtCreateProcess` / `NtCreateUserProcess` | 0x004D / 0x00C8 | Verify | Process creation |
| `NtWriteVirtualMemory` | 0x003A | Verify | Cross-process write |
| `NtQueueApcThread` | 0x0045 | Verify | APC injection |

> **Quan trọng**: Các số trên là approximate và cần verification với `uf ntdll!NtXxx` hoặc j00ru table cho exact build. Không dùng hardcoded numbers trong production code.

---

## 5. Kernel Structure Changes

### 5.1 EPROCESS changes

`EPROCESS` là kernel structure mô tả một process. Nó **thay đổi giữa builds**:
- Fields mới được added (usually tại end, nhưng không guaranteed)
- Existing fields có thể shift offset
- Flags fields (MitigationFlags, MitigationFlags2, Flags, Flags2) có bits mới thêm vào

**Cách làm đúng — luôn dùng symbols:**
```windbg
; Load symbols cho build đang debug (tự động từ Microsoft Symbol Server)
.symfix
.reload /f

; Dump EPROCESS structure với symbols
dt nt!_EPROCESS

; Tìm specific field
dt nt!_EPROCESS <addr> MitigationFlags
dt nt!_EPROCESS <addr> Protection
dt nt!_EPROCESS <addr> Flags
```

**Fields quan trọng theo research angle:**

| Field | Mục đích | Thay đổi khi nào |
|---|---|---|
| `Protection` | PPL type và signer level (PS_PROTECTION struct) | Stable structure, nhưng Signer values thêm |
| `MitigationFlags` | Process mitigation bitmask (DEP, CFG, CET, etc.) | Bits thêm khi mitigation mới added |
| `MitigationFlags2` | Extended mitigation flags | Added Win10 1607; bits expand per build |
| `WoW64Process` | Pointer đến WoW64 structure nếu 32-bit process trên 64-bit OS | Offset thay đổi thường xuyên |
| `Job` | Pointer đến Job object nếu process trong job | Relatively stable |
| `Peb` | Pointer đến PEB trong user space | Stable |
| `Token` | EX_FAST_REF đến Token object | Stable |
| `ActiveProcessLinks` | LIST_ENTRY cho process linked list (DKOM target) | Stable |

### 5.2 KPROCESS và KTHREAD changes

`KPROCESS` (scheduling component của process, embedded trong EPROCESS) và `KTHREAD` (scheduling component của thread) cũng thay đổi:

```windbg
dt nt!_KPROCESS
dt nt!_KTHREAD
```

**Fields thêm vào Windows 11:**
- Shadow stack control fields trong KTHREAD
- CET-related fields
- Additional scheduling fields

### 5.3 PEB và TEB changes

PEB và TEB (user-mode structures) cũng evolve:

```windbg
dt ntdll!_PEB
dt ntdll!_TEB
```

**PEB additions quan trọng:**
- `LeapSecondFlags` và related timing fields
- Additional loader fields (Ldr pointers)
- CFG-related fields

**Cách access PEB từ process:**
```windbg
!peb
; Hoặc
dt ntdll!_PEB @$peb
```

### 5.4 Mitigation policy fields expansion

`EPROCESS.MitigationFlags` và `EPROCESS.MitigationFlags2` expand thường xuyên:

```windbg
; Xem từng bit của MitigationFlags
dt nt!_EPROCESS <addr> MitigationFlags
; Output: một bitfield với tên từng flag
```

Ví dụ flags (approximate, verify với symbols):
```
ControlFlowGuardEnabled          : 1
ControlFlowGuardExportSuppressionEnabled : 0
ControlFlowGuardStrict           : 0
DisallowStrippedImages           : 0
ForceRelocateImages              : 0
HighEntropyASLREnabled           : 1
StackRandomizationDisabled       : 0
ExtensionPointDisable            : 0
DisableDynamicCode               : 0     // ACG
DisableDynamicCodeAllowOptOut    : 0
DisableDynamicCodeAllowRemoteDowngrade : 0
AuditDisableDynamicCode          : 0
DisallowWin32kSystemCalls        : 0
AuditDisallowWin32kSystemCalls   : 0
EnableFilteredWin32kAPIs         : 0
AuditFilteredWin32kAPIs          : 0
```

---

## 6. Driver và Signing Changes

### 6.1 HVCI impact on drivers

Với HVCI enabled by default trên Windows 11 hardware:

**Drivers KHÔNG compatible với HVCI bị từ chối:**
- Drivers dùng `ExAllocatePool` + mark result executable
- Drivers modify code pages của chính mình
- Drivers dùng non-executable memory cho code
- Drivers không WHQL-signed (cross-signing deprecated)

**Kết quả cho ecosystem:**
- Nhiều legacy third-party drivers (gaming anti-cheat, hardware utilities, old security software) fail to load
- Vendors phải rewrite drivers theo HVCI-compatible way
- Từ user perspective: driver compatibility issues phổ biến hơn trên Windows 11 trong 2021-2023; ngày càng được giải quyết

### 6.2 Cross-Signing deprecation

Microsoft cross-signing certificates (cho driver signing) không được cấp mới từ 2015. Sau đó:
- Driver cần phải EV code signing + Windows Hardware Dev Center (WHDC) submission
- Hoặc test-signing mode (không secure)
- Old cross-signed drivers: có whitelist của existing signatures; mới phải qua WHCP

**Security impact:**
- Barrier để load malicious kernel driver tăng lên đáng kể
- BYOVD vẫn possible với *existing* signed vulnerable drivers
- loldrivers.io database tracking known vulnerable signed drivers

### 6.3 Driver blocklist

Microsoft maintain và update kernel driver blocklist (enforced via HVCI + Windows Security):
- `C:\Windows\System32\CodeIntegrity\SIPolicy.p7b` — Windows version
- Microsoft Defender periodically update blocklist
- Attacker must use drivers NOT on blocklist → narrows BYOVD options over time
- CVE disclosures of driver vulnerabilities → driver gets added to blocklist

```powershell
# Check driver blocklist status / policy
Get-CimInstance -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object CodeIntegrityPolicyEnforcementStatus
```

### 6.4 Recommended driver model: KMDF

Microsoft increasingly recommend KMDF (Kernel-Mode Driver Framework) over WDM (Windows Driver Model):
- KMDF provides safe wrappers cho nhiều kernel operations
- Built-in object lifecycle management
- Power management handled by framework
- Security: KMDF code paths more HVCI-compatible by design

---

## 7. ETW Provider Changes

### 7.1 Provider landscape evolves

Mỗi Windows build có thể add, modify, hoặc remove ETW providers. Không có stable canonical list across all builds.

**Cách inventory providers trên current build:**
```powershell
# List tất cả registered ETW providers
logman query providers | Out-File C:\Temp\etw-providers.txt

# Query specific provider info
logman query providers "Microsoft-Windows-Kernel-Process"

# Via Get-ETWProvider (nếu có):
# [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetProviderNames()
```

### 7.2 Microsoft-Windows-Threat-Intelligence changes

ETW-TI là provider quan trọng nhất cho EDR:
- Requires PPL process để subscribe
- Coverage của ReadVirtualMemory, AllocExecVirtualMemory, MapViewOfSection, etc.
- Windows 11 additions: thêm events cho memory scanning, thread context observation

**Verify provider events trên current build:**
```powershell
# Xem event schema
$session = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession
$provider = New-Object System.Diagnostics.Eventing.Reader.ProviderMetadata(
    "Microsoft-Windows-Threat-Intelligence")
$provider.Events | Select-Object Id, Description | Sort-Object Id
```

### 7.3 Notable provider additions trong Windows 11

| Provider | Khi nào added | Purpose |
|---|---|---|
| `Microsoft-Windows-Security-Mitigations` | Win10 1709+ | Mitigation block events |
| `Microsoft-Windows-SmartScreen` | Win10 (expanded W11) | SAC + SmartScreen decision events |
| `Microsoft-Windows-CodeIntegrity` | Older; expanded W11 | Code integrity check results, blocked loads |
| `Microsoft-Windows-Kernel-Audit-API-Calls` | Win10 1803+ | Expanded audit of security-sensitive APIs |
| `Microsoft-Windows-Win32k` | Win10+ | Win32k operation events |

---

## 8. Smart App Control — Deep Dive

### 8.1 Cơ chế kỹ thuật

Smart App Control (SAC) là OS-level application control, implemented ở kernel qua Code Integrity infrastructure:

```
Execution flow với SAC On:
  1. Process create attempt
  2. Windows loader → Image validation
  3. CI.dll (Code Integrity driver) nhận image hash
  4. CI.dll query: cloud reputation service OR local ML model
  5. Decision: ALLOW (good reputation / signed by trusted cert) or BLOCK
  6. Nếu BLOCK: process create fails với appropriate error
  7. Event logged in CodeIntegrity Operational event log
```

**Components:**
- **CI.dll** (Code Integrity driver, kernel mode): Core enforcement
- **SmartScreen Filter** (user-mode component): Cloud reputation query
- **Local ML model**: Offline evaluation for unsigned/unknown files
- **Sigcheck criteria**: Microsoft Authenticode signature OR explicit SAC approval

### 8.2 SAC States

```
Evaluation Mode (default trên new installation):
  - Học behavior của user
  - Monitor unsigned app executions
  - Không block (chỉ log)
  - Tự động chuyển → On hoặc Off sau evaluation period

On Mode:
  - Enforce: unsigned executables không có good reputation → BLOCKED
  - Signed executables từ trusted publisher → ALLOWED
  - "Good reputation" từ cloud: widely seen + no malicious behavior

Off Mode:
  - SAC disabled
  - KHÔNG THỂ re-enable mà không reinstall OS
  - Một khi Off, forever Off (trong installation này)
```

**Registry state:**
```
HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy
  VerifiedAndReputablePolicyState : DWORD
    0 = Off
    1 = Evaluation
    2 = On
```

> **Quan trọng**: Write vào registry key này yêu cầu kernel / SYSTEM và bị Tamper Protection protect. Không đơn giản disable từ user mode.

### 8.3 Interaction với AppLocker và WDAC

| Feature | Level | Enforcement | Bypass surface |
|---|---|---|---|
| **SAC** | OS built-in, kernel | CI.dll + cloud | Reputation abuse; code signing |
| **AppLocker** | Group Policy | AppLocker driver + rules | Rule gaps; DLL injection; PowerShell |
| **WDAC** | Group Policy / MDM | CI.dll + local policy | Policy gaps; vulnerable driver (trong kernel) |

SAC và WDAC đều dùng CI.dll — nhưng:
- SAC = cloud-backed, dynamic, reputation-based
- WDAC = admin-defined static policy (hash, path, certificate rules)
- Chúng có thể coexist (most restrictive wins)

### 8.4 EDR và SAC interaction

**SAC là complementary layer, không replacement cho EDR:**
- SAC block execution của unknown/unsigned files — reduce initial footprint
- SAC không detect behavior sau khi known-good process executes (LOL binaries — living off the land)
- EDR cần detect behavior: `mshta.exe`, `wscript.exe`, `powershell.exe`, `certutil.exe` — tất cả đều có good reputation, SAC cho pass
- Kết hợp: SAC giảm threat surface → EDR tập trung vào living-off-the-land và known-good-but-abused patterns

### 8.5 Research considerations

**SAC bypass research** — mục đích phòng thủ:
- Code signing với stolen certificate → bypass reputation check (thực ra bypass trust model)
- Reputation abuse: build "good reputation" cho malicious tool rồi weaponize
- Tìm gaps trong SAC's scope: script files, certain binary types, loaded DLLs
- SAC không check *DLLs* — chỉ check initial executable image trong nhiều configurations

**Detection của SAC bypass attempt:**
- `CodeIntegrity/Operational` event log: blocked image events
- `Microsoft-Windows-SmartScreen` ETW: reputation query results
- Process create cho unknown/new hash followed by block = signal

---

## 9. SMB Signing Enforced by Default (Windows 11 23H2+)

### 9.1 Thay đổi

Từ Windows 11 23H2, Windows SMB client **enforce signing** trên outbound connections by default:
- SMB 3.1.1 session signing required
- Server phải sign: nếu server không support signing → connection fail (or negotiate unsigned per policy)
- Default: `RequireSecuritySignature = True` cho SMB client

```powershell
# Verify SMB client signing config
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
# Expected trên 23H2+: RequireSecuritySignature = True
```

### 9.2 Security impact

**NTLM relay via SMB** là classic lateral movement technique:
1. Attacker position → MITM hoặc coerced authentication
2. Victim sends NTLM authentication to "server" (actually attacker)
3. Attacker relay to real target, authenticate as victim
4. No SMB signing → replay possible

**Với SMB signing enforced:**
- Session signing cryptographically binds SMB session đến authentication
- Replaying NTLM auth từ signed session không work (signature key changes)
- NTLM relay via SMB significantly harder

**Khi nào vẫn vulnerable:**
- Attacker là real server (not MITM) — relay to *different* service
- NTLM relay to non-SMB services (HTTP, LDAP) — không ảnh hưởng bởi SMB signing
- Legacy systems hoặc explicit policy disable signing

### 9.3 Defender configuration check

```powershell
# Server-side signing config
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature

# Check signing trên active session
Get-SmbConnection | Select-Object ServerName, Signed

# Audit policy
Get-SmbClientConfiguration | Format-List
```

### 9.4 Implication cho lab và research

- Network lateral movement labs phải account for này
- Test environment cần explicit policy changes để reproduce older behavior
- `Set-SmbClientConfiguration -RequireSecuritySignature $false` (requires admin) — disable for testing

---

## 10. Security Research Lab Implications

### 10.1 VM Setup cho Windows 11

**Hyper-V (recommended):**
```
New-VM -Name "Win11-Research" -Generation 2 -MemoryStartupBytes 8GB
Add-VMTPMDevice -VMName "Win11-Research"  # Adds virtual TPM 2.0
Set-VMFirmware -VMName "Win11-Research" -EnableSecureBoot On
```

**VMware Workstation Pro:**
- Hardware → Add → Trusted Platform Module
- Options → Advanced → Enable VT-x/AMD-V (nested)
- Enable nested VT-x cho nested VBS (nếu cần test HVCI inside VM)

**Snapshot strategy:**
1. Clean install snapshot (before Windows activation + updates)
2. Post-update snapshot (fully updated, security tools installed)
3. Pre-lab snapshot (reset point before each lab)

### 10.2 Kernel Debugging trên Windows 11

Mechanism giống Windows 10 — nhưng cần account for:

**Setup:**
```powershell
# Trên target (Windows 11 VM):
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.100 port:50001 key:1.2.3.4
shutdown /r /t 0

# Trên host WinDbg:
# File → Attach to kernel → Net → host IP, port, key
```

**Secure Boot compatibility:**
- Test signing mode: `bcdedit /set testsigning on` — disable Secure Boot first trong UEFI
- Kernel debugging implicitly disables some security features (VBS may be limited in debug mode)
- For HVCI research: need kernel debugging mode compatible với HVCI — check Microsoft docs for specific setup

**Symbol download cho Windows 11 builds:**
```
.symfix C:\Symbols
.sympath+ SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload /f
```

### 10.3 EPROCESS offsets cho current build

Không bao giờ hardcode. Luôn dump tại runtime:
```windbg
; Dump full EPROCESS structure để get current offsets
dt nt!_EPROCESS

; Specific fields:
?? #FIELD_OFFSET(nt!_EPROCESS, Protection)
?? #FIELD_OFFSET(nt!_EPROCESS, MitigationFlags)
?? #FIELD_OFFSET(nt!_EPROCESS, Token)
```

### 10.4 Disabling SAC trong research environment

SAC interfere với nhiều lab exercises (loading unsigned tools, testing execution techniques):

```powershell
# Method: Disable SAC (one-way operation — reinstall to re-enable Evaluation)
# Settings → Privacy & Security → Windows Security → App & Browser Control
# → Smart App Control → Turn Off

# Verify:
$sacState = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" `
    -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue
Write-Host "SAC state: $($sacState.VerifiedAndReputablePolicyState)"
# 0 = Off, 1 = Evaluation, 2 = On
```

---

## 11. Version Comparison Table

| Feature / Behavior | Win10 22H2 | Win11 21H2 | Win11 22H2 | Win11 23H2 | Win11 24H2 |
|---|---|---|---|---|---|
| **HVCI default** | Optional/OEM | More OEMs | More common | Expanded default | Expanded default |
| **VBS default** | Optional | More common | More common | Default on eligible HW | Default |
| **Smart App Control** | No | No | Yes (On/Eval/Off) | Yes | Yes (enhanced) |
| **Credential Guard default** | Optional | Enterprise/Edu SKUs | More SKUs | More | Default on eligible |
| **SMB client signing required** | No | No | No | Yes (23H2) | Yes |
| **CET (user mode)** | On CET HW | On CET HW | On CET HW + expanded | Yes | Yes |
| **Kernel Shadow Stack** | Limited | Expanded | Expanded | Broader | Broader |
| **NTLMv1** | Active | Active | Active | Deprecated (off) | Deprecated (off) |
| **Protected Print Mode** | No | No | No | Preview | GA |
| **Pluton** | No | Preview HW | Select HW | Select HW | Expanding |
| **Recall** | No | No | No | No | Yes (opt-out) |
| **Sudo for Windows** | No | No | No | No | Yes |
| **TPM 2.0 required** | Optional | Required | Required | Required | Required |
| **UEFI Secure Boot required** | Optional | Required | Required | Required | Required |
| **Syscall numbers** | Win10 22H2 set | Changed | Changed | Changed | Changed |

---

## 12. Labs

### Lab J.1 — Kiểm tra Windows 11 VBS và HVCI Status

**Goal**: Xác định VBS và HVCI trạng thái trên hệ thống hiện tại.

**Steps:**
```powershell
# 1. Qua WMI
$dg = Get-CimInstance -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard

$vbsStatus = switch ($dg.VirtualizationBasedSecurityStatus) {
    0 { "Not Enabled" }
    1 { "Enabled but not running" }
    2 { "Running" }
}
$hvciStatus = switch ($dg.HypervisorEnforcedCodeIntegrityStatus) {
    0 { "Not running" }
    1 { "Audit mode" }
    2 { "Enforced mode" }
}

Write-Host "VBS: $vbsStatus"
Write-Host "HVCI: $hvciStatus"

# 2. Services running
Write-Host "`nVBS Services running:"
$dg.VirtualizationBasedSecurityServicesRunning | ForEach-Object {
    switch ($_) {
        1 { "  [ON] Credential Guard" }
        2 { "  [ON] HVCI" }
        4 { "  [ON] System Guard Secure Launch" }
        8 { "  [ON] SMM Firmware Measurement" }
        default { "  [??] Unknown service: $_" }
    }
}

# 3. Registry check
$policy = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -ErrorAction SilentlyContinue
Write-Host "`nRegistry EnableVBS: $($policy.EnableVirtualizationBasedSecurity)"
Write-Host "Registry HVCI: $($policy.HypervisorEnforcedCodeIntegrity)"
```

**Expected**: Windows 11 trên supported hardware: VBS Running, HVCI Enforced. VM có thể show "Not running" nếu không có nested virtualization.

---

### Lab J.2 — Check Smart App Control State

**Goal**: Xác định SAC state trên hệ thống.

**Steps:**
```powershell
# 1. Registry check
$sacPolicies = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
)

foreach ($regPath in $sacPolicies) {
    if (Test-Path $regPath) {
        $val = Get-ItemProperty $regPath -Name "VerifiedAndReputablePolicyState" `
            -ErrorAction SilentlyContinue
        $stateStr = switch ($val.VerifiedAndReputablePolicyState) {
            0 { "Off" }
            1 { "Evaluation" }
            2 { "On (Enforcing)" }
            default { "Unknown: $_" }
        }
        Write-Host "SAC State: $stateStr"
    }
}

# 2. Windows Security Center check
$wsc = New-Object -ComObject WSCProductList
# Note: WSC COM interface — may require admin
# Alternative: check via Defender API

# 3. Event log check — recent SAC decisions
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" `
    -MaxEvents 20 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(3076, 3077, 3089) } |
    Select-Object TimeCreated, Id, Message |
    Format-Table -AutoSize
```

**Expected**: Trên fresh Windows 11 install: SAC = Evaluation. Nếu đã configure: On hoặc Off.

---

### Lab J.3 — Verify SMB Signing Configuration

**Goal**: Confirm SMB signing status client và server.

**Steps:**
```powershell
# Client config
Write-Host "=== SMB Client Configuration ==="
Get-SmbClientConfiguration | Select-Object `
    RequireSecuritySignature, EnableSecuritySignature, `
    SigningRequired, ConnectionCountPerIPAddress |
    Format-List

# Server config
Write-Host "=== SMB Server Configuration ==="
Get-SmbServerConfiguration | Select-Object `
    RequireSecuritySignature, EnableSecuritySignature |
    Format-List

# Active connections và signing status
Write-Host "=== Active SMB Connections ==="
Get-SmbConnection | Select-Object ServerName, ShareName, Signed, Dialect |
    Format-Table -AutoSize

# Check negotiated signing on specific connection
# (nếu có active SMB connection)
```

**Expected trên Windows 11 23H2+**: `RequireSecuritySignature = True` cho client.

---

### Lab J.4 — Compare EPROCESS Field Offsets

**Goal**: Thực hành sử dụng symbols để get structure offsets, không hardcode.

**Requirements**: WinDbg, kernel debugger attached (hoặc full memory dump)

**Steps:**
```windbg
; Bước 1: Load symbols
.symfix
.reload /f nt

; Bước 2: Dump EPROCESS structure
dt nt!_EPROCESS

; Bước 3: Lấy offset của các fields quan trọng
?? #FIELD_OFFSET(nt!_EPROCESS, Token)
?? #FIELD_OFFSET(nt!_EPROCESS, Protection)
?? #FIELD_OFFSET(nt!_EPROCESS, MitigationFlags)
?? #FIELD_OFFSET(nt!_EPROCESS, ActiveProcessLinks)
?? #FIELD_OFFSET(nt!_EPROCESS, ImageFileName)
?? #FIELD_OFFSET(nt!_EPROCESS, Peb)

; Bước 4: Tìm EPROCESS của một process cụ thể
!process 0 0 notepad.exe

; Bước 5: Dump fields tại runtime
dt nt!_EPROCESS <addr> Protection
dt nt!_EPROCESS <addr> MitigationFlags
```

**Expected**: Offsets sẽ khác nhau giữa Windows 10 và Windows 11 builds. Ghi lại và compare nếu có access to multiple builds.

**Note**: Nếu không có kernel debugger, có thể dùng PDB symbols file của ntoskrnl.exe với symbol parsing tool để extract offsets offline.

---

## 13. References

### Microsoft Official

- [What's new in Windows 11 — each version](https://learn.microsoft.com/en-us/windows/whats-new/) — Microsoft Learn
- [Windows 11 security features](https://learn.microsoft.com/en-us/windows/security/introduction) — Microsoft Learn  
- [Smart App Control documentation](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview) — Microsoft Learn
- [Windows security baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines) — Microsoft Learn
- [SMB signing changes](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview) — Microsoft Learn
- [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard) — Microsoft Learn
- [HVCI documentation](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) — Microsoft Learn

### Syscall References

- [j00ru NT syscall table (64-bit)](https://j00ru.vexillium.org/syscalls/nt/64/) — comprehensive build-by-build syscall numbers
- [j00ru Win32k syscall table](https://j00ru.vexillium.org/syscalls/win32k/64/) — Win32k kernel syscalls

### Security Research

- [Microsoft Security Blog](https://msrc.microsoft.com/blog/) — MSRC announcements, mitigation updates
- [Windows Kernel Internals Blog](https://techcommunity.microsoft.com/category/windows/blog/windowsosplatform) — Microsoft developer blog về kernel changes
- [loldrivers.io](https://www.loldrivers.io/) — vulnerable driver database (BYOVD research reference)

### Tools

- **WinDbg** with Microsoft Symbol Server — essential cho structure offset verification
- **ntdll-dumper scripts** — multiple open-source tools để parse ntdll.dll syscall stubs
- **DriverQuery** (built-in) — `driverquery /fo csv /v > drivers.csv` — enumerate loaded drivers
- **msinfo32.exe** — System Information GUI, shows VBS/HVCI status

---

*Appendix J hoàn thành. Liên quan: [Appendix H — Exploit Mitigations](app-h-windows-exploit-mitigation-overview.md) · [Appendix C — Kernel Debugging](app-c-kernel-debugging-field-guide.md) · [Appendix E — Lab Setup](app-e-windows-research-lab-setup.md)*
