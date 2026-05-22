# Expected VMMap Observations

Exact category names and grouping vary by VMMap version.

## Console output

Expected shape:

```text
[lab] pid=1234
[worker] tid=5678 stack active
[lab] heap_block=000001...
[lab] private_block=000002... size=1MB protection=PAGE_READWRITE
[lab] mapped_view=000003... file=C:\Users\<user>\AppData\Local\Temp\InternalsNoteBookMemoryLayout.bin
[lab] worker_tid=5678
```

## VMMap categories

Likely observations:

| Program action | Expected VMMap evidence |
|---|---|
| EXE/DLL load | Image-backed regions |
| `HeapAlloc` | Heap category or heap-backed allocation |
| `VirtualAlloc(PAGE_READWRITE)` | Private Data / private committed memory |
| `CreateFileMapping` + `MapViewOfFile` | Mapped File / shareable mapped region |
| worker thread | Additional Stack region |

## Correct conclusion

Correct:

> VMMap showed memory regions consistent with the controlled allocation mechanisms used by the demo process.

Incorrect:

> Private memory is automatically injection.

