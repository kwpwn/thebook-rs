# Lab: Ch.4 Thread Wait Reasons

## Status

Draft implementation. Needs real VM observation record before marking tested.

## Source

- Chapter: `chapters/ch04-threads.md`
- Original section: `Lab 2 — Quan sát wait reason`
- Related chapter concepts: thread state, dispatcher wait, alertable wait, thread telemetry.

## Goal

Observe how different blocking operations produce different thread wait states and wait reasons, then learn how to avoid over-interpreting a single `WaitReason` value.

This lab turns a small thread demo into a repeatable evidence workflow:

- One thread waits on a manual-reset event.
- One thread performs an alertable wait with `SleepEx`.
- One thread sleeps with `Sleep`.
- The observer records PID/TID, Process Explorer view, optional WinDbg view, and interpretation caveats.

## Scope and safety

- VM required: Recommended.
- Snapshot required: Recommended, not mandatory.
- Admin required: No for running the program; possibly yes for full Process Explorer visibility.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: No. Run in a lab VM because debugger/tools and screenshots may expose local system details.

## Tested environment

Fill this table after running the lab. Do not mark the lab `Tested` until this exists.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| Architecture | x64 |
| Hypervisor |  |
| Secure Boot |  |
| VBS/HVCI |  |
| Defender/EDR state |  |
| Tool versions | Process Explorer, WinDbg, compiler |

## Requirements

- Windows VM.
- Visual Studio Developer Command Prompt or any C compiler that can build Win32 C code.
- Sysinternals Process Explorer.
- Optional: WinDbg Preview with Microsoft public symbols.

## Files

| File | Purpose |
|---|---|
| `src/wait_reasons_demo.c` | Runnable demo program |
| `expected-output/sample-console.txt` | Example console output shape |
| `verification/verification-record.md` | Build/config-specific evidence record |
| `../../assets/diagrams/ch04-thread-wait-reasons.mmd` | Wait-state observation diagram |

## Build

Using Visual Studio Developer Command Prompt:

```bat
cd labs\ch04-thread-wait-reasons\src
cl /W4 /nologo wait_reasons_demo.c
```

Expected artifact:

```text
wait_reasons_demo.exe
```

## Steps

1. Start the demo:

```bat
wait_reasons_demo.exe
```

2. Record the PID and the printed thread IDs.

3. Open Process Explorer.

4. Find `wait_reasons_demo.exe`.

5. Open process properties, then the `Threads` tab.

6. Add or inspect columns for TID, Start Address, State, Wait Reason, CPU, and Context Switch Delta when available.

7. Match the printed TIDs to the three worker roles:

| Role | Blocking call | Expected high-level interpretation |
|---|---|---|
| event-waiter | `WaitForSingleObject` | Waiting for dispatcher object signal |
| alertable-sleeper | `SleepEx(INFINITE, TRUE)` | Waiting in alertable state; APC-deliverable |
| delay-sleeper | repeated `Sleep(1000)` | Delayed execution / timer-based sleep |

8. Optional WinDbg user-mode check:

```windbg
~*                 ; list threads
~<thread-index>s   ; switch to a target thread
k                  ; stack should show the wait path
```

9. Optional kernel-debugger check, if already configured:

```windbg
!process 0 0 wait_reasons_demo.exe
!process <eprocess> 4
!thread <ethread>
dt nt!_KTHREAD <ethread> State WaitReason Alertable
```

## Expected observations

- The main thread waits for console input.
- `event-waiter` should remain blocked until the event is signaled.
- `alertable-sleeper` should remain in an alertable wait.
- `delay-sleeper` should repeatedly enter a sleep/delay wait.
- Process Explorer and WinDbg may use labels that differ by Windows version/tool version. Treat labels as evidence from that tool layer, not universal truth.

See `expected-output/sample-console.txt` for the expected console shape.

## Evidence to save

- Console output with PID and TIDs.
- Process Explorer Threads tab screenshot or text note.
- Optional WinDbg output:
  - `~*`
  - selected thread stacks
  - kernel `!thread` / `_KTHREAD` fields if available.
- Completed `verification/verification-record.md`.

Do not commit screenshots containing usernames, hostnames, internal paths, or proprietary security product details unless sanitized.

## Cleanup

1. Press Enter in the console to signal the event, set the stop flag, and exit.
2. Confirm `wait_reasons_demo.exe` has exited.
3. Close Process Explorer or WinDbg.
4. Delete `wait_reasons_demo.exe` and `.obj` if you want a clean source tree.

## Interpretation notes

### What the observation proves

- A thread can be in a waiting state for different reasons depending on the blocking primitive.
- A wait reason is useful context when correlated with stack, TID, process role, and API path.
- Alertable wait matters because user-mode APC delivery depends on alertability for standard APC delivery.

### What it does not prove

- It does not prove that a particular wait reason is globally stable across all Windows builds.
- It does not prove maliciousness or benignness.
- It does not prove what an EDR sees unless the EDR's collection layer is also measured.

### Common false positives

- Tool labels can differ from raw kernel enum names.
- Main thread wait can distract from worker-thread observations.
- Thread start address may point to a runtime wrapper rather than the user callback.
- EDR, debugger, or symbol state can change visibility.
- This lab intentionally avoids forced thread termination so cleanup remains clean.

## Creative extension

Add a fourth worker that calls `WaitForSingleObjectEx(hEvent, INFINITE, TRUE)` and compare it with `WaitForSingleObject`. This creates a controlled contrast between non-alertable and alertable dispatcher waits.

Do not add APC injection to this baseline lab. Keep APC delivery as a separate lab so the evidence question stays clean.

## Open questions

- Which exact wait reason labels does your Process Explorer version show?
- Does WinDbg report the same high-level interpretation as Process Explorer?
- How do labels change between Windows 10 22H2 and Windows 11 23H2/24H2?
