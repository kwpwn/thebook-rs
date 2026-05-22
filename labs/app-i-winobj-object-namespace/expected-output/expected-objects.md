# Expected Object Namespace Findings

## Demo console

Expected shape:

```text
[lab] pid=1234
[lab] event=Local\InternalsNoteBook_ObjectLab_Event
[lab] mutex=Local\InternalsNoteBook_ObjectLab_Mutex
[lab] mutex created by this process
[lab] inspect with WinObj, Handle, or Process Explorer now
[lab] press Enter to close handles and exit
```

If another instance already created the mutex:

```text
[lab] mutex already existed before this process opened it
```

## Object names

Win32 name:

```text
Local\InternalsNoteBook_ObjectLab_Event
Local\InternalsNoteBook_ObjectLab_Mutex
```

Likely Object Manager view:

```text
\BaseNamedObjects\InternalsNoteBook_ObjectLab_Event
\BaseNamedObjects\InternalsNoteBook_ObjectLab_Mutex
```

Depending on session/tool view, WinObj may expose a session-specific namespace.

## Object types

Expected types:

| Win32 API | Object type commonly shown |
|---|---|
| `CreateEventW` | Event |
| `CreateMutexW` | Mutant / Mutex |

## Correct conclusion

Correct:

> A named Event and Mutant/Mutex were observed while `named_objects_demo.exe` was running, and handles could be attributed to the demo process.

Incorrect:

> The object name alone proves malware or historical execution.

