# Expected Autoruns Findings

## Registry location

Expected key:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Expected value name:

```text
InternalsNoteBookRunMarker
```

Expected value data:

```text
%SystemRoot%\System32\cmd.exe /c rem InternalsNoteBookRunMarker
```

PowerShell may expand `%SystemRoot%` into a concrete path such as:

```text
C:\Windows\System32\cmd.exe /c rem InternalsNoteBookRunMarker
```

## Autoruns category

Expected broad category:

```text
Logon
```

Exact naming depends on Autoruns/autorunsc version.

## Before/after expectation

| Capture | Expected marker state |
|---|---|
| before | absent |
| after create | present |
| after remove | absent |

## Correct conclusion

The correct conclusion is:

> The marker was present in a current-user Run location during the after-create capture and absent after cleanup.

Do not conclude execution unless runtime evidence is collected separately.

