# Verification Record: WinObj Object Namespace

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | APP-I-LAB-WINOBJ-NAMESPACE |
| Related file/section | `labs/app-i-winobj-object-namespace/README.md` |
| Claim | A process-created named Event and Mutex/Mutant can be observed in Object Manager namespace tooling and correlated with process handles while handles remain open. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture | x64 |
| VM / hardware |  |
| Secure Boot | Enabled / Disabled / Unknown |
| VBS | Enabled / Disabled / Unknown |
| HVCI | Enabled / Disabled / Unknown |
| Defender / EDR state |  |
| Tool versions | WinObj: ; Handle: ; Process Explorer: ; compiler: |
| Symbol path | Not required |
| Commands / steps | Built and ran `named_objects_demo.exe`; inspected object names with WinObj/Handle/Process Explorer; exited process and re-checked. |
| Expected observation | Named Event and Mutant/Mutex visible while process holds handles; objects disappear after handles close unless another process holds them. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | Namespace view may vary by session, integrity, and tool permissions. |
| Follow-up | Run two instances and observe `ERROR_ALREADY_EXISTS`; test handle lifetime by opening from another process. |

---

## Evidence notes

```text
Paste concise console output, WinObj notes, Handle output, or Process Explorer handle observations here.
Do not paste usernames, hostnames, proprietary EDR details, or sensitive paths.
```

---

## Conclusion wording

> On `<build/config>`, `<tool/version>` showed named object `<name>` while `<process/PID>` held a handle. This supports live namespace-state observation with `<confidence>` confidence. It does not by itself prove intent, family attribution, or historical execution.

