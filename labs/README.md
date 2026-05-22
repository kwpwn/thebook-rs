# Labs Index

`labs/` chứa các lab được tách ra từ chapter thành artifact có thể chạy lại. Chapter vẫn giữ lab ở dạng học nhanh; thư mục này dùng cho phiên bản triển khai có checklist, môi trường test, expected output, evidence, và cleanup.

See `lab-roadmap.md` for recommended order, evidence skills, and current coverage gaps.

---

## Lab status

| Area | Status | Source |
|---|---|---|
| Ch.1 Concepts and Tools | Token comparison lab draft exists | `labs/ch01-process-token-comparison/README.md` |
| Ch.2 System Architecture | Backlog | `chapters/ch02-system-architecture.md` |
| Ch.3 Processes and Jobs | Backlog | `chapters/ch03-processes-and-jobs.md` |
| Ch.4 Threads | Wait reason and deadlock labs draft exist | `labs/ch04-thread-wait-reasons/README.md`, `labs/ch04-deadlock-observation/README.md` |
| Ch.5 Memory Management | VMMap and WinDbg corroboration labs draft exist | `labs/ch05-vmmap-memory-layout/README.md`, `labs/ch05-windbg-vad-corroboration/README.md` |
| Ch.6 I/O System | Backlog | `chapters/ch06-io-system.md` |
| Ch.7 Security | AccessChk permission lab draft exists | `labs/ch07-accesschk-permission-review/README.md` |
| Ch.8 System Mechanisms | Backlog | `chapters/ch08-system-mechanisms.md` |
| Ch.9 Virtualization Technologies | Backlog | `chapters/ch09-virtualization-technologies.md` |
| Ch.10 Management, Diagnostics, Tracing | ETW provider inventory lab draft exists | `labs/ch10-etw-provider-inventory/README.md` |
| Ch.11 Caching and File Systems | ADS and hardlink identity labs draft exist | `labs/ch11-ads-streams-file-artifacts/README.md`, `labs/ch11-hardlink-file-identity/README.md` |
| Ch.12 Startup and Shutdown | Service startup inventory lab draft exists | `labs/ch12-service-startup-inventory/README.md` |
| Appendix E Lab Setup | Draft source exists | `appendices/app-e-windows-research-lab-setup.md` |
| Appendix I Sysinternals | Baseline lab draft exists | `labs/app-i-sysinternals-baseline/README.md` |
| Appendix I Procmon controlled trace | Draft exists | `labs/app-i-procmon-controlled-trace/README.md` |
| Appendix I Autoruns startup inventory | Draft exists | `labs/app-i-autoruns-startup-inventory/README.md` |
| Appendix I WinObj object namespace | Draft exists | `labs/app-i-winobj-object-namespace/README.md` |

---

## Conversion workflow

1. Pick one lab from a chapter.
2. Copy the structure from `templates/lab-template.md`.
3. Add exact Windows build/config and tool versions.
4. Move code snippets into a `src/` subfolder when the lab needs compilation.
5. Add expected observations and cleanup.
6. Save screenshots under `assets/screenshots/` only after sanitizing sensitive data.
7. Add a verification record when the lab proves a build-specific claim.

---

## Naming convention

Use:

```text
labs/chXX-short-topic/README.md
labs/chXX-short-topic/src/
labs/chXX-short-topic/expected-output/
```

Example:

```text
labs/ch04-thread-wait-reasons/README.md
```

---

## Reference implementation

Use `ch04-thread-wait-reasons` as the first quality bar for future lab extraction:

- Runnable source code lives under `src/`.
- Expected console shape lives under `expected-output/`.
- Build/config evidence lives under `verification/`.
- Shared diagram lives under `assets/diagrams/`.
- README separates observation, interpretation, cleanup, and limits.

Use `app-i-sysinternals-baseline` as the first field-workflow lab:

- Captures built-in Windows inventory through PowerShell.
- Leaves space for Sysinternals GUI/CLI artifacts.
- Teaches raw evidence vs interpretation.
- Produces a baseline package for later before/after diffs.

Use `app-i-procmon-controlled-trace` as the first telemetry interpretation lab:

- Generates controlled file and registry operations.
- Shows how Procmon evidence should be filtered and interpreted.
- Separates observed operation telemetry from persistence, intent, and historical claims.

Use `app-i-autoruns-startup-inventory` as the first startup evidence lab:

- Creates and removes a harmless HKCU Run marker.
- Shows Autoruns before/after inventory.
- Teaches configuration evidence vs execution evidence.

Use `app-i-winobj-object-namespace` as the first Object Manager lab:

- Creates named Event and Mutex objects with predictable names.
- Shows namespace and handle attribution through WinObj/Handle/Process Explorer.
- Teaches live object evidence vs intent/family attribution.

Use `ch01-process-token-comparison` as the first security-context lab:

- Compares standard and elevated process tokens.
- Separates admin membership, integrity level, privilege state, and access.
- Supports Ch.7 before deeper ACL/token/PPL material.

Use `ch05-vmmap-memory-layout` as the first memory layout lab:

- Allocates heap, private memory, mapped file, and thread stack regions.
- Uses VMMap to classify regions by evidence layer.
- Teaches memory type vs intent boundaries.

Use `ch05-windbg-vad-corroboration` as the debugger-backed memory lab:

- Correlates VMMap and WinDbg by address.
- Teaches cross-tool confidence and debugger caveats.

Use `ch11-ads-streams-file-artifacts` as the first file artifact lab:

- Creates default stream and ADS content.
- Uses stream-aware enumeration.
- Teaches default stream vs full file-content evidence.

Use `ch11-hardlink-file-identity` as the path-vs-identity lab:

- Creates two paths to the same file identity.
- Uses hardlink and file ID evidence.
- Teaches path evidence boundaries.

Use `ch04-deadlock-observation` as the second thread lab:

- Creates a controlled lock-order deadlock.
- Uses stack/lock evidence.
- Teaches hung process vs deadlock causality.

Use `ch07-accesschk-permission-review` as the first permission lab:

- Creates a controlled file artifact.
- Reviews ACLs with built-in tooling and optional AccessChk.
- Teaches configured permission state vs access occurrence.

Use `ch10-etw-provider-inventory` as the first ETW lab:

- Inventories providers and active trace sessions.
- Separates provider availability from telemetry coverage.
- Supports Appendix F provider-field verification.

Use `ch10-etw-minimal-trace` as the first controlled ETW capture lab:

- Starts and stops a scoped `logman` session.
- Generates controlled PowerShell activity.
- Teaches ETL evidence as session-scoped telemetry.

Use `ch12-service-startup-inventory` as the first service/startup lab:

- Captures service configuration, state, process, and event classes separately.
- Teaches startup type vs execution evidence.
