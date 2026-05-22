# Expected Hardlink Observations

## Paths

```text
%TEMP%\InternalsNoteBookHardlinkLab\original.txt
%TEMP%\InternalsNoteBookHardlinkLab\alias.txt
```

## Expected behavior

- Reading either path returns the same content.
- Writing through one path changes content observed through the other path.
- `fsutil hardlink list` reports both names.
- `fsutil file queryFileID` should match for both paths on NTFS.

## Correct conclusion

Correct:

> Two paths referenced the same file identity at observation time.

Incorrect:

> Different paths always mean different files.

