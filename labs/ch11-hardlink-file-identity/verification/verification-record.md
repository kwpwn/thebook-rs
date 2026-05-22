# Verification Record: Hardlink File Identity

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | CH11-LAB-HARDLINK-FILE-IDENTITY |
| Related file/section | `labs/ch11-hardlink-file-identity/README.md` |
| Claim | Different paths can refer to the same file identity through hard links. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| File system |  |
| Architecture |  |
| Tool versions | PowerShell: ; fsutil: built-in |
| Commands / steps | Created hardlink artifact; read/modified paths; queried hardlink list and file IDs; cleaned up. |
| Expected observation | Both paths share content and file identity/link set. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | File-system dependent; does not prove historical access path. |
| Follow-up | Correlate with Procmon and USN Journal evidence. |

---

## Evidence notes

```text
Paste concise hardlink/file ID outputs here.
Do not paste usernames or sensitive paths unless sanitized.
```

---

## Conclusion wording

> On `<build/filesystem>`, `<path A>` and `<path B>` shared `<file identity evidence>`. This supports path-vs-identity interpretation with `<confidence>` confidence. It does not prove which path was historically used.

