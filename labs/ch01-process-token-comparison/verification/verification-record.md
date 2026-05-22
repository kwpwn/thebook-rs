# Verification Record: Process Token Comparison

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | CH01-LAB-TOKEN-COMPARISON |
| Related file/section | `labs/ch01-process-token-comparison/README.md` |
| Claim | Standard and elevated processes can have different integrity levels, group states, and privilege sets even for the same user. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| Architecture |  |
| VM / hardware |  |
| UAC state |  |
| Account type |  |
| Defender / EDR state |  |
| Tool versions | Process Explorer: ; PowerShell: |
| Symbol path | Not required |
| Commands / steps | Ran `capture-token-context.ps1` in standard and elevated PowerShell; compared with Process Explorer Security tab. |
| Expected observation | Standard context has medium integrity; elevated context has high integrity and different group/privilege state. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | Domain/UAC/local policy can change exact privileges and group states. |
| Follow-up | Compare with service process and PPL-protected target access. |

---

## Evidence notes

```text
Paste concise comparison notes here.
Do not paste domain names, hostnames, usernames, tokens, or proprietary EDR details unless sanitized.
```

---

## Conclusion wording

> On `<build/config>`, standard and elevated PowerShell showed `<observed token differences>`. This supports the split-token/security-context model with `<confidence>` confidence. Exact privilege state depends on account type and local/domain policy.

