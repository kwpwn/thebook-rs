# Expected Trace Artifacts

## Folder shape

```text
%TEMP%\InternalsNoteBookEtwTrace\<timestamp>\
  pre-clean-stop.txt
  logman-start.txt
  logman-stop.txt
  trace.etl
  trace-summary.txt
  tracerpt.txt
  trace-report.csv       optional, if conversion succeeds
```

## Expected summary fields

```text
session=InternalsNoteBookEtwLab
provider=Microsoft-Windows-PowerShell
start_exit=0
stop_exit=0
etl_size=<non-zero ideally>
```

## Correct conclusion

Correct:

> A trace session was started and stopped, producing an ETL artifact under the configured provider/session.

Incorrect:

> ETW globally captured all PowerShell behavior on the machine.

