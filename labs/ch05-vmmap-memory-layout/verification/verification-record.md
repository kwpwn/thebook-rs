# Verification Record: VMMap Memory Layout

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | CH05-LAB-VMMAP-LAYOUT |
| Related file/section | `labs/ch05-vmmap-memory-layout/README.md` |
| Claim | VMMap can distinguish controlled image, heap, private, mapped-file, and stack regions in a live process. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture | x64 |
| VM / hardware |  |
| Secure Boot | Enabled / Disabled / Unknown |
| VBS | Enabled / Disabled / Unknown |
| HVCI | Enabled / Disabled / Unknown |
| Defender / EDR state |  |
| Tool versions | VMMap: ; compiler: |
| Symbol path | Not required |
| Commands / steps | Built and ran `memory_layout_demo.exe`; inspected with VMMap; correlated printed addresses to VMMap categories. |
| Expected observation | Heap/private/mapped-file/stack/image regions are visible and broadly match controlled allocations. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | VMMap is a user-mode view; deeper VAD/PTE truth requires debugger/kernel evidence. |
| Follow-up | Compare with WinDbg `!vad` and executable private memory variant. |

---

## Evidence notes

```text
Paste concise address-to-category mapping notes here.
Do not paste usernames, hostnames, proprietary EDR details, or sensitive paths unless sanitized.
```

---

## Conclusion wording

> On `<build/config>`, VMMap `<version>` showed `<region categories>` for `memory_layout_demo.exe`. This supports memory layout interpretation with `<confidence>` confidence. It does not prove intent or injection without content/protection/thread/context evidence.

