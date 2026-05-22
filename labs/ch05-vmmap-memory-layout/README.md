# Lab: VMMap Memory Layout

## Status

Draft implementation. Designed as the first memory-layout lab for Ch.5.

## Source

- Chapter: `chapters/ch05-memory-management.md`
- Appendix: `appendices/app-i-sysinternals-practical-lab-manual.md`
- Supports: process address space, private memory, image mappings, mapped files, heap/stack, working set interpretation.

## Goal

Run a controlled process that allocates several memory types, inspect it with VMMap, and write a bounded interpretation of memory regions.

The core lesson:

> Memory type is evidence about allocation/backing, not intent. Private executable memory, mapped files, heap, and stack require context before security conclusions.

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: No.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Low-risk; creates a temporary mapped file and allocates process memory.

## Tested environment

Fill this after running the lab.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| Architecture | x64 |
| Secure Boot |  |
| VBS/HVCI |  |
| Defender/EDR state |  |
| VMMap version |  |
| Compiler |  |

## Requirements

- VMMap from Sysinternals.
- Visual Studio Developer Command Prompt or another compiler that can build Win32 C code.

## Files

| File | Purpose |
|---|---|
| `src/memory_layout_demo.c` | Allocates heap, private virtual memory, mapped file, and a thread stack |
| `expected-output/expected-vmmap-observations.md` | Expected VMMap interpretation points |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/ch05-vmmap-memory-layout.mmd` | Memory evidence diagram |

## Build

Using Visual Studio Developer Command Prompt:

```bat
cd labs\ch05-vmmap-memory-layout\src
cl /W4 /nologo memory_layout_demo.c
```

Expected artifact:

```text
memory_layout_demo.exe
```

## Steps

1. Run:

```bat
memory_layout_demo.exe
```

2. Record:

- PID.
- private allocation address.
- mapped view address.
- heap allocation address.
- worker thread ID.

3. Open VMMap.

4. Select `memory_layout_demo.exe`.

5. Inspect categories:

- Image.
- Private Data.
- Heap.
- Stack.
- Mapped File.
- Shareable / mapped regions if shown by your VMMap version.

6. Search or correlate addresses printed by the program.

7. Save a sanitized VMMap screenshot or export.

8. Press Enter in the demo console to clean up.

9. Complete `verification/verification-record.md`.

## Expected observations

- The executable and DLLs appear as image-backed regions.
- Heap allocation appears under heap-related categories.
- `VirtualAlloc` allocation appears as private committed memory.
- File mapping appears as mapped-file backed memory.
- Worker thread creates an additional stack region.
- VMMap categories are a user-mode tool view; WinDbg/VAD can corroborate deeper kernel memory state.

See `expected-output/expected-vmmap-observations.md`.

## Evidence to save

- Console output with PID and addresses.
- VMMap screenshot/export.
- Notes mapping printed addresses to VMMap categories.
- Completed verification record.

## Cleanup

Press Enter in the console. The program unmaps the view, closes handles, frees heap/private memory, and deletes the temp file.

If cleanup fails, delete:

```text
%TEMP%\InternalsNoteBookMemoryLayout.bin
```

## Interpretation notes

### What this proves

- Different allocation mechanisms produce distinguishable memory-region evidence.
- VMMap can help map a process's memory layout into image, heap, stack, private, and mapped-file categories.
- Address correlation improves interpretation quality.

### What it does not prove

- It does not prove maliciousness.
- It does not prove private memory contains shellcode.
- It does not prove disk persistence.
- It does not replace WinDbg/VAD/PTE analysis when kernel-level truth is needed.

### Correct report language

Weak:

> Private memory means injection.

Better:

> VMMap showed private committed memory at `<address>` in `<process>`. In this controlled lab, that region was created by `VirtualAlloc`. In real investigations, content, protection, thread start/stack evidence, VAD state, and process context are needed before inferring injection.

## Creative extension

Change the `VirtualAlloc` protection from `PAGE_READWRITE` to `PAGE_EXECUTE_READWRITE`, rerun VMMap, and compare how your interpretation changes.

Do not label executable private memory as malicious by default. Record it as a higher-signal condition that requires context.

## Open questions

- Which VMMap category contains the mapped file in your version?
- Does the heap address printed by the program map cleanly to VMMap's heap view?
- How does a second worker thread change stack regions?
- What additional evidence would distinguish JIT memory from injected code?

