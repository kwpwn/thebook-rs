# Changelog

## 2026-05-23 — Documentation stabilization and lab system

### Added

- `style-guide.md` for writing, lab, reference, and verification conventions.
- `quality-gates.md` for draft-to-publication readiness gates.
- `evidence-language.md` for evidence/inference/confidence wording.
- `verification-template.md` for build/config-specific claim verification.
- `labs/README.md` and `labs/lab-roadmap.md`.
- `assets/README.md`, `assets/diagrams/README.md`, and `assets/screenshots/README.md`.

### Added labs

- `labs/app-i-sysinternals-baseline/`
- `labs/app-i-procmon-controlled-trace/`
- `labs/app-i-autoruns-startup-inventory/`
- `labs/app-i-winobj-object-namespace/`
- `labs/ch01-process-token-comparison/`
- `labs/ch04-thread-wait-reasons/`
- `labs/ch05-vmmap-memory-layout/`
- `labs/ch11-ads-streams-file-artifacts/`

### Updated

- `README.md` now describes draft status, quality surfaces, and realistic appendix state.
- `roadmap.md` now separates draft complete, verification needs, appendix stubs, and extracted lab coverage.
- `appendices/index.md` now distinguishes stub appendices from draft-complete appendices.
- Stub appendix files now say `Stub` instead of `Planned`.
- `sources.md` now includes verification artifact guidance.

### Validation

- C lab samples syntax-checked with `x86_64-w64-mingw32-gcc -Wall -Wextra -fsyntax-only`.
- PowerShell lab scripts parsed with PowerShell parser.
- `git diff --check` passed.

### Research update: ETW field guide

- Expanded Appendix F from stub to ETW Provider Field Guide draft.
- Added `labs/ch10-etw-provider-inventory/` for read-only provider/session/channel inventory.
- Updated roadmap, appendix index, quality gates, lab roadmap, and publication gaps to reflect ETW inventory coverage.

### Major update: controlled tracing and startup evidence

- Added `labs/ch10-etw-minimal-trace/` for a scoped `logman` trace session and ETL artifact workflow.
- Added `labs/ch12-service-startup-inventory/` for service configuration/state/process/event evidence separation.
- Updated lab roadmap, project roadmap, publication gaps, and quality gates to reflect Ch.10 and Ch.12 lab-backed coverage.

### Major update: debugger, file identity, and deadlock coverage

- Added `labs/ch05-windbg-vad-corroboration/` for VMMap-to-WinDbg memory evidence correlation.
- Added `labs/ch11-hardlink-file-identity/` for path vs file identity evidence.
- Added `labs/ch04-deadlock-observation/` for lock ownership/wait deadlock evidence.
- Added `LAB_COVERAGE.md` as the quick chapter-to-lab coverage map.
