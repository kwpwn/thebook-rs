# Verification Record: ADS and Streams

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | CH11-LAB-ADS-STREAMS |
| Related file/section | `labs/ch11-ads-streams-file-artifacts/README.md` |
| Claim | A file can contain an alternate data stream that is not visible through default stream reads and requires stream-aware enumeration. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| File system |  |
| Architecture |  |
| Defender / EDR state |  |
| Tool versions | PowerShell: ; Streams: |
| Symbol path | Not required |
| Commands / steps | Ran `create-ads-artifact.ps1 -Action Create`; read default stream; read ADS; enumerated streams; cleaned up. |
| Expected observation | Default stream and `research` ADS contain different content; stream enumeration lists both. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | ADS behavior depends on file system and copy/acquisition tooling. |
| Follow-up | Copy to non-NTFS volume and compare preservation. |

---

## Evidence notes

```text
Paste concise stream enumeration output here.
Do not paste sensitive paths or proprietary security product details.
```

---

## Conclusion wording

> On `<build/config/filesystem>`, stream-aware tooling showed a named ADS `research` on `sample.txt`. This supports the stream-aware file artifact claim with `<confidence>` confidence. It does not prove maliciousness or execution.

