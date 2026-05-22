# Expected Permission Observations

Exact ACLs depend on user profile path, domain policy, inherited permissions, and Windows edition.

## Expected file

```text
%TEMP%\InternalsNoteBookAclLab\controlled.txt
```

## Built-in tools

Useful commands:

```powershell
icacls "%TEMP%\InternalsNoteBookAclLab\controlled.txt"
Get-Acl "$env:TEMP\InternalsNoteBookAclLab\controlled.txt" | Format-List
```

Expected dimensions:

- owner;
- inherited ACEs;
- explicit ACEs if any;
- rights such as read, write, modify, full control;
- inheritance flags.

## AccessChk

Useful command:

```bat
accesschk.exe -accepteula -q -v "%TEMP%\InternalsNoteBookAclLab\controlled.txt"
```

Expected dimensions:

- principal names;
- effective-looking rights format;
- possible formatting differences from `icacls`.

## Correct conclusion

Correct:

> The file ACL exposed configured permissions at observation time.

Incorrect:

> The ACL proves a principal actually accessed the file.

