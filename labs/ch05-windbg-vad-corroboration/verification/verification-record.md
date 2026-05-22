# Verification Record: WinDbg VAD Corroboration

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | CH05-LAB-WINDBG-VAD-CORROBORATION |
| Related file/section | `labs/ch05-windbg-vad-corroboration/README.md` |
| Claim | VMMap and WinDbg can be correlated by address to increase confidence in memory-region classification. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture | x64 |
| Debugger mode |  |
| VM / hardware |  |
| Symbol path |  |
| Tool versions | WinDbg: ; VMMap: ; compiler: |
| Commands / steps | Ran `memory_layout_demo.exe`; captured VMMap view; attached WinDbg; ran `!address` and optional `!vad`. |
| Expected observation | Printed addresses correlate to heap/private/mapped/stack evidence across tools. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | Debugger mode, symbols, dump completeness, and Windows build affect output. |
| Follow-up | Compare executable private memory variant. |

---

## Evidence notes

```text
Paste concise address correlation notes here.
Do not paste hostnames, usernames, proprietary EDR details, or sensitive paths unless sanitized.
```

---

## Conclusion wording

> On `<build/config>`, VMMap and WinDbg both classified `<address/range>` as `<category>`. This supports memory-region classification with `<confidence>` confidence. It does not prove intent or injection.

