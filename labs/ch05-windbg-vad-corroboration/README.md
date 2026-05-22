# Lab: WinDbg VAD Corroboration

## Status

Draft implementation. Designed as the debugger-backed follow-up to `ch05-vmmap-memory-layout`.

## Source

- Chapter: `chapters/ch05-memory-management.md`
- Appendix: `appendices/app-c-kernel-debugging-field-guide.md`
- Builds on: `labs/ch05-vmmap-memory-layout/`

## Goal

Correlate VMMap's user-mode memory categories with WinDbg's process/VAD view for the same controlled process.

The core lesson:

> VMMap is a useful view, but debugger-backed VAD inspection gives a different evidence layer. Agreement between layers increases confidence; disagreement becomes a research question.

## Scope and safety

- VM required: Recommended.
- Snapshot required: Recommended before kernel debugging setup.
- Admin required: Yes for many debugger workflows.
- Kernel debugger required: Optional; user-mode WinDbg can still inspect process address space, but VAD commands require kernel/debugger context.
- Network required: No except symbol download if not cached.
- Production-safe: No. Use a lab machine for debugger workflows.

## Tested environment

Fill this after running the lab.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| Architecture | x64 |
| Debugger mode | user-mode / local kernel / remote kernel / dump |
| Symbol path |  |
| WinDbg version |  |
| VMMap version |  |
| Target program | `memory_layout_demo.exe` |

## Requirements

- Built target from `labs/ch05-vmmap-memory-layout/src/memory_layout_demo.c`.
- WinDbg Preview or classic WinDbg.
- Microsoft public symbols.
- Optional: VMMap export/screenshot from the previous lab.

## Files

| File | Purpose |
|---|---|
| `expected-output/expected-windbg-vad-notes.md` | Expected debugger observations |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/ch05-windbg-vad-corroboration.mmd` | Cross-tool evidence diagram |

## Steps

1. Start `memory_layout_demo.exe` from `labs/ch05-vmmap-memory-layout/src`.

2. Record printed PID and addresses:

- `heap_block`
- `private_block`
- `mapped_view`
- `worker_tid`

3. Capture VMMap screenshot/export if not already captured.

4. Attach WinDbg to the process for user-mode address inspection:

```windbg
.symfix
.reload
|
!address
!address <private_block>
!address <mapped_view>
~*
```

5. If using kernel debugger or a dump with enough memory, correlate VAD:

```windbg
!process 0 0 memory_layout_demo.exe
.process /r /p <eprocess>
!vad <eprocess> 4
```

6. Search for the ranges containing `private_block` and `mapped_view`.

7. Write a two-layer interpretation:

```text
VMMap view:
WinDbg !address / !vad view:
Agreement:
Disagreement:
Caveat:
```

8. Complete `verification/verification-record.md`.

## Expected observations

- `private_block` should map to private committed memory in VMMap and a private/user allocation in debugger view.
- `mapped_view` should map to mapped-file backed memory or section-backed view.
- Worker thread should add stack evidence.
- Debugger command availability depends on attach mode and dump/live context.

See `expected-output/expected-windbg-vad-notes.md`.

## Evidence to save

- Console output from `memory_layout_demo.exe`.
- VMMap category notes.
- WinDbg `!address` output for target addresses.
- Optional kernel `!vad` excerpts.
- Completed verification record.

## Cleanup

Detach debugger cleanly if attached live. Press Enter in the demo process to release memory and exit.

## Interpretation notes

### What this proves

- Cross-tool memory interpretation can be grounded by address correlation.
- VMMap and WinDbg expose different layers of process memory state.
- Corroboration improves confidence in memory-region classification.

### What it does not prove

- It does not prove maliciousness.
- It does not prove injection.
- It does not prove content semantics without reading memory and understanding context.
- It does not prove private structure offsets are stable across builds.

### Correct report language

Weak:

> VMMap says private memory, therefore injected shellcode.

Better:

> VMMap and WinDbg both identified the address range as private committed memory in the controlled process. In this lab, the region was created by `VirtualAlloc`. In real analysis, content, protection, thread usage, VAD, and process context are needed before inferring injection.

## Creative extension

Rerun `memory_layout_demo.exe` after changing its private allocation to executable permissions. Compare:

- VMMap protection/category;
- WinDbg `!address` protection;
- whether your report wording becomes stronger or only higher-priority for review.

## Open questions

- Does user-mode `!address` agree with VMMap for all printed addresses?
- Does kernel `!vad` show backing information for the mapped file?
- What debugger context is required to make `!vad` reliable on your build?
- How do symbols affect command output?

