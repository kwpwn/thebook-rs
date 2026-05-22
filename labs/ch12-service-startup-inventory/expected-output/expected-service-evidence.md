# Expected Service Evidence

## Output files

```text
%TEMP%\InternalsNoteBookServiceInventory\<timestamp>\
  context.txt
  services.csv
  running-services.csv
  service-processes.csv
  sc-query-all.txt
  sc-qc-selected.txt
  system-service-events.xml
```

## Evidence classes

| File | Evidence class |
|---|---|
| `services.csv` | Service configuration and current status summary |
| `running-services.csv` | Current running service subset |
| `service-processes.csv` | Service state, start mode, PID, image path, account |
| `sc-qc-selected.txt` | SCM config and query output for selected services |
| `system-service-events.xml` | Recent Service Control Manager event evidence if available |

## Correct conclusion

Correct:

> The service was configured as `<start mode>` and had current state `<state>` at observation time.

Incorrect:

> The startup type alone proves execution at boot.

