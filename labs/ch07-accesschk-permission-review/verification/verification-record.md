# Verification Record: AccessChk Permission Review

---

## Verification record

| Field | Value |
|---|---|
| Claim ID | CH07-LAB-ACCESSCHK-PERMISSION |
| Related file/section | `labs/ch07-accesschk-permission-review/README.md` |
| Claim | Built-in tools and AccessChk can inspect configured file permissions, but permission state alone does not prove access occurred. |
| Source type | Lab observation |
| Windows build |  |
| Edition |  |
| File system |  |
| Architecture |  |
| VM / hardware |  |
| Account type |  |
| Defender / EDR state |  |
| Tool versions | PowerShell: ; AccessChk: |
| Symbol path | Not required |
| Commands / steps | Created artifact; ran `icacls`, `Get-Acl`, optional `accesschk`; removed artifact. |
| Expected observation | Permission tools show owner/ACE/right information for the controlled file. |
| Actual observation |  |
| Artifacts saved |  |
| Confidence | Low / Medium / High |
| Limits / caveats | ACL view alone excludes runtime access attempts, enabled privileges, integrity policy, and other boundaries. |
| Follow-up | Compare effective access from standard vs elevated token. |

---

## Evidence notes

```text
Paste concise permission output or normalized summary here.
Do not paste domain names, hostnames, usernames, or sensitive paths unless sanitized.
```

---

## Conclusion wording

> On `<build/config>`, `<tool/version>` showed `<principal/right>` on `<artifact>`. This supports configured permission-state analysis with `<confidence>` confidence. It does not prove access occurred.

