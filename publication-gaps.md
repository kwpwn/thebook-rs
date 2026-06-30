# Publication Gaps

This file tracks the highest-value remaining work before the project can be treated as publication-ready.

---

## Current strengths

- Core chapters have substantial draft content.
- All 10 appendices now have meaningful draft content (A/B/D/G/H/J implemented 2026-06-30).
- Lab system exists with repeatable structure, verification records, expected outputs, and diagrams.
- Evidence wording, quality gates, style guide, and verification template exist.

---

## Highest-priority gaps

| Priority | Gap | Why it matters | Best next action |
|---|---|---|---|
| 1 | Reference TODOs in Ch.2/3/4/5 | Draft claims still have unresolved source quality issues | Replace TODO references with verified official/book/source links |
| 2 | ~~Appendix stubs A/B/D/G/H/J~~ **DONE 2026-06-30** | All 6 stubs implemented as full draft documents | Verify content against live Windows builds |
| 3 | ETW/provider build verification | Ch.10 and detection claims are build/config sensitive | Add provider-specific records and WPR/WPA review |
| 4 | WinDbg corroboration depth | Memory/thread/process claims need more debugger-backed evidence | Add process/thread dump triage lab |
| 5 | Service startup evidence | Ch.12 needs boot/logon timing correlation beyond inventory | Add boot logging or service event timeline lab |
| 6 | File identity timeline evidence | Ch.11 needs timeline evidence beyond hardlinks | Add USN lab |
| 7 | Screenshots | Assets folders have structure but no sanitized real screenshots | Add screenshot notes after running labs |
| 8 | Glossary expansion | New lab concepts add terms not all reflected in glossary | Update glossary from lab terms |

---

## Lab coverage status

| Area | Status |
|---|---|
| Baseline | Covered by `app-i-sysinternals-baseline` |
| Procmon file/registry telemetry | Covered by `app-i-procmon-controlled-trace` |
| Autoruns startup config | Covered by `app-i-autoruns-startup-inventory` |
| Object namespace | Covered by `app-i-winobj-object-namespace` |
| Token comparison | Covered by `ch01-process-token-comparison` |
| ACL/permission review | Covered by `ch07-accesschk-permission-review` |
| Thread wait reasons | Covered by `ch04-thread-wait-reasons` |
| VMMap memory layout | Covered by `ch05-vmmap-memory-layout` |
| ADS/file streams | Covered by `ch11-ads-streams-file-artifacts` |
| ETW provider inventory | Covered by `ch10-etw-provider-inventory` |
| ETW minimal trace | Covered by `ch10-etw-minimal-trace` |
| WinDbg VAD corroboration | Covered by `ch05-windbg-vad-corroboration` |
| Service startup config/execution | Covered by `ch12-service-startup-inventory` |
| Hardlink file identity | Covered by `ch11-hardlink-file-identity` |
| Deadlock observation | Covered by `ch04-deadlock-observation` |
| Threadpool attribution | Missing |
| USN file identity timeline | Missing |

---

## Recommended next build sequence

1. `labs/ch11-usn-file-timeline/`
2. `labs/ch04-threadpool-attribution/`
3. `labs/ch12-boot-logging-evidence/`
4. `labs/ch03-handle-inheritance/`
5. Appendix F provider-specific verification records.
6. WPR/WPA trace review lab.
7. Reference TODO cleanup pass for Ch.2-5.

---

## Stop condition for publication-ready core

The core book can be called publication-ready when:

- every chapter reaches Gate 3 from `quality-gates.md`;
- build/config-sensitive claims reach Gate 4 or are explicitly scoped as unverified;
- at least one lab-backed evidence path exists for Ch.1, Ch.3, Ch.4, Ch.5, Ch.6, Ch.7, Ch.10, Ch.11, and Ch.12;
- no linked appendix is a bare stub without status warning;
- references and glossary are internally consistent.
