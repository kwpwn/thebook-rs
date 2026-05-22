# Expected ETW Inventory Output

## Folder shape

```text
%TEMP%\InternalsNoteBookEtwInventory\<timestamp>\
  context.txt
  windows-version.txt
  logman-providers.txt
  active-trace-sessions.txt
  eventlog-providers.csv
  selected-provider-Microsoft-Windows-Kernel-Process.txt
  selected-provider-Microsoft-Windows-Kernel-File.txt
  selected-provider-Microsoft-Windows-Security-Auditing.txt
  selected-provider-Microsoft-Windows-PowerShell.txt
```

## Expected interpretation

`logman-providers.txt` lists provider names/GUIDs visible to `logman`.

`active-trace-sessions.txt` lists currently active ETW sessions; content varies widely by system.

`eventlog-providers.csv` lists providers visible through Event Log metadata APIs.

`selected-provider-*.txt` contains provider metadata when available; field detail varies by provider/build/tool rendering.

## Correct conclusion

Correct:

> The provider inventory shows provider metadata and active session state at observation time.

Incorrect:

> The provider inventory proves relevant events are being captured.

