# Lab: WinObj Controlled Object Namespace

## Status

Draft implementation. Designed as the first Object Manager namespace lab.

## Source

- Chapter: `chapters/ch01-concepts-and-tools.md`
- Related section: `Lab 1.3 — Browse Object Namespace với WinObj`
- Appendix: `appendices/app-i-sysinternals-practical-lab-manual.md`
- Supports: Ch.3 process handles, Ch.4 thread sync objects, Ch.6 device namespace, Ch.8 Object Manager, malware single-instance mutex analysis.

## Goal

Create named kernel dispatcher objects with predictable names, observe them in WinObj/Handle/Process Explorer, and write a correct evidence statement.

The core lesson:

> A named object proves namespace state at observation time. It does not by itself prove intent, malware family, or historical execution.

## Scope and safety

- VM required: No.
- Snapshot required: No.
- Admin required: Recommended for complete WinObj/Handle visibility, but not required to create current-session objects.
- Kernel debugger required: No.
- Network required: No.
- Production-safe: Low-risk; creates named Event/Mutex objects while the demo process is running.

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
| WinObj version |  |
| Handle version |  |
| Compiler |  |

## Requirements

- WinObj from Sysinternals.
- Optional: `handle.exe` from Sysinternals.
- Optional: Process Explorer.
- Visual Studio Developer Command Prompt or another compiler that can build Win32 C code.

## Files

| File | Purpose |
|---|---|
| `src/named_objects_demo.c` | Creates named Event and Mutex objects |
| `expected-output/expected-objects.md` | Expected namespace and handle observations |
| `verification/verification-record.md` | Evidence record |
| `../../assets/diagrams/app-i-winobj-object-namespace.mmd` | Object namespace evidence diagram |

## Build

Using Visual Studio Developer Command Prompt:

```bat
cd labs\app-i-winobj-object-namespace\src
cl /W4 /nologo named_objects_demo.c
```

Expected artifact:

```text
named_objects_demo.exe
```

## Steps

1. Start the demo:

```bat
named_objects_demo.exe
```

2. Record the printed PID and object names.

3. Open WinObj.

4. Browse:

```text
\BaseNamedObjects
```

Depending on session isolation and tool view, you may need to inspect session-specific paths as exposed by WinObj.

5. Search for:

```text
InternalsNoteBook_ObjectLab_Event
InternalsNoteBook_ObjectLab_Mutex
```

6. Optional Handle check:

```bat
handle.exe -a -p <PID> InternalsNoteBook_ObjectLab
```

7. Optional Process Explorer check:

- Open process properties for `named_objects_demo.exe`.
- Inspect Handles tab.
- Search for `InternalsNoteBook_ObjectLab`.

8. Press Enter in the demo console to release handles and exit.

9. Re-check WinObj/Handle. The objects should disappear when no handles remain.

10. Complete `verification/verification-record.md`.

## Expected observations

- While the process is running, named Event and Mutant/Mutex objects should be visible through at least one tool view.
- `handle.exe` or Process Explorer should attribute handles to the demo PID.
- After process exit, objects should disappear if no other process opened them.
- Tool naming may differ: Windows object type for mutex is often shown as `Mutant`.

See `expected-output/expected-objects.md`.

## Evidence to save

- Console output with PID and object names.
- WinObj screenshot or note.
- Optional `handle.exe` output.
- Optional Process Explorer Handles tab screenshot or text note.
- Completed verification record.

Do not commit screenshots containing usernames, hostnames, internal paths, or proprietary security product details unless sanitized.

## Cleanup

Press Enter in the demo console. The program closes object handles before exiting.

If the process is closed forcefully, objects should still be cleaned up when the process terminates unless another process has opened handles to them.

## Interpretation notes

### What this proves

- A user-mode process can create named kernel objects in the Object Manager namespace.
- Named object visibility can be correlated with process handles.
- Object lifetime depends on open handles, not just the original creator's source code.

### What it does not prove

- It does not prove maliciousness.
- It does not prove a malware family from object name alone.
- It does not prove historical execution after the object disappears.
- It does not prove all objects are visible to the same tools under every integrity/session/PPL/security configuration.

### Correct report language

Weak:

> This mutex proves malware X ran.

Better:

> During live observation, a named Mutant object matching `<name>` was present and a handle was attributed to `<process/PID>`. This supports current runtime presence of that object. Family attribution or historical execution requires additional evidence.

## Creative extension

Run two copies of the demo. The second process should detect that the mutex already exists by checking `GetLastError() == ERROR_ALREADY_EXISTS`.

Use this to model the common "single-instance mutex" pattern without tying it to malware. Then write two interpretations:

- software engineering interpretation: duplicate instance prevention;
- malware-analysis interpretation: possible campaign/family marker, only when supported by other evidence.

## Open questions

- Does WinObj show the object under `\BaseNamedObjects` or a session-specific view?
- Does `handle.exe` show type `Mutant` or `Mutex`?
- What happens if a second process opens the same named object and the first exits?
- Which access rights does the process hold for each object?

