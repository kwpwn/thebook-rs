# Lab: Deadlock Observation

## Status

Draft implementation. Designed as the second thread lab after wait reasons.

## Source

- Chapter: `chapters/ch04-threads.md`
- Related section: `Lab 3 — Deadlock demonstration`
- Supports: synchronization, wait chains, thread stacks, debugger interpretation.

## Goal

Create a controlled two-thread deadlock, observe blocked stacks, and write a precise deadlock evidence statement.

The core lesson:

> A deadlock conclusion requires ownership/wait correlation, not just "the process is hung."

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: No.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Low-risk; creates a local process that intentionally hangs until closed.

## Tested environment

Fill this after running the lab.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| Architecture | x64 |
| Process Explorer version |  |
| WinDbg version |  |
| Compiler |  |

## Requirements

- Visual Studio Developer Command Prompt or another compiler that can build Win32 C code.
- Process Explorer.
- Optional: WinDbg.

## Files

| File | Purpose |
|---|---|
| `src/deadlock_demo.c` | Creates a two-critical-section deadlock |
| `expected-output/expected-deadlock-observations.md` | Expected wait/stack observations |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/ch04-deadlock-observation.mmd` | Deadlock wait cycle diagram |

## Build

```bat
cd labs\ch04-deadlock-observation\src
cl /W4 /nologo deadlock_demo.c
```

## Steps

1. Run:

```bat
deadlock_demo.exe
```

2. Record PID and thread IDs.

3. Wait until the console prints that both threads are attempting the second lock.

4. Open Process Explorer.

5. Inspect the process Threads tab and thread stacks if symbols are available.

6. Optional WinDbg:

```windbg
~*k
!locks
```

`!locks` works best when debugger can inspect critical section state; output varies by debugger version and target context.

7. Close the console window or terminate the demo after collecting evidence.

8. Complete `verification/verification-record.md`.

## Expected observations

- Thread A holds `cs1` and waits for `cs2`.
- Thread B holds `cs2` and waits for `cs1`.
- Both worker threads stop making progress.
- Stack traces should show blocking in critical-section acquisition paths.

See `expected-output/expected-deadlock-observations.md`.

## Evidence to save

- Console output with PID/TIDs.
- Process Explorer thread stack notes.
- Optional WinDbg `~*k` and `!locks` output.
- Completed verification record.

## Cleanup

Terminate `deadlock_demo.exe` after evidence collection. This is expected; the process intentionally deadlocks.

## Interpretation notes

### What this proves

- A controlled lock-order inversion can create a deadlock.
- Thread stacks and lock ownership/wait evidence can support a deadlock conclusion.
- "Hung process" is a symptom; deadlock is a causal interpretation requiring evidence.

### What it does not prove

- It does not prove all hangs are deadlocks.
- It does not prove kernel scheduler failure.
- It does not prove maliciousness.

### Correct report language

Weak:

> The process is frozen, so Windows scheduler failed.

Better:

> Two worker threads are blocked in critical-section acquisition paths with opposite lock ownership/wait relationships. This supports a user-mode deadlock caused by lock-order inversion.

## Creative extension

Fix the code by enforcing a single lock acquisition order, rerun, and show that the deadlock disappears. Keep the fixed version as a separate variant so the failure case remains reproducible.

## Open questions

- Does Process Explorer show enough stack detail without symbols?
- Does `!locks` identify both critical sections?
- What changes if you use mutex handles instead of critical sections?
- How would Wait Chain Traversal report this deadlock?

