# Expected WinDbg / VAD Notes

## Address correlation table

Fill this after running the lab.

| Printed address | VMMap category | WinDbg `!address` | WinDbg `!vad` if available | Interpretation |
|---|---|---|---|---|
| `heap_block` | Heap |  |  | Controlled heap allocation |
| `private_block` | Private Data |  |  | Controlled `VirtualAlloc` |
| `mapped_view` | Mapped File |  |  | Controlled file mapping |
| worker stack | Stack |  |  | Controlled worker thread |

## Expected conclusion

Correct:

> VMMap and WinDbg were used as separate evidence layers and correlated by address.

Incorrect:

> One tool's memory category is enough to infer intent.

