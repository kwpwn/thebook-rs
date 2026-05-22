# Expected Stream Observations

## Default stream

```text
default stream content
```

## Alternate stream

```text
alternate stream content
```

## PowerShell stream enumeration

Expected stream names:

```text
:$DATA
research
```

Exact formatting depends on PowerShell version.

## Streams.exe

Expected output should mention:

```text
sample.txt:
   :research:$DATA
```

## Correct conclusion

Correct:

> Stream-aware enumeration found a named ADS attached to the test file.

Incorrect:

> The default stream alone represents all file content.

