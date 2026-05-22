# Expected Deadlock Observations

## Console output

Expected shape:

```text
[main] pid=1234
[main] thread-a tid=1111
[main] thread-b tid=2222
[thread-a] acquired cs1, sleeping before cs2
[thread-b] acquired cs2, sleeping before cs1
[thread-a] attempting cs2
[thread-b] attempting cs1
```

The process should stop progressing after both `attempting` lines.

## Stack evidence

Expected stack theme:

- thread A blocked while entering `g_cs2`;
- thread B blocked while entering `g_cs1`;
- main thread waiting for worker thread handles.

Exact function names vary by Windows version and symbols.

## Correct conclusion

Correct:

> The two worker threads are blocked in opposite lock acquisition paths, supporting a lock-order deadlock.

Incorrect:

> Any hung process is a deadlock.

