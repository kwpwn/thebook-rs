# Lab: Sysinternals Baseline Capture

## Status

Draft implementation. Designed as a baseline workflow before deeper process, thread, memory, I/O, startup, and forensics labs.

## Source

- Appendix: `appendices/app-i-sysinternals-practical-lab-manual.md`
- Related sections: baseline first, preserve raw artifacts, Process Explorer, Procmon, Autoruns.
- Supports: Ch.1, Ch.3, Ch.4, Ch.6, Ch.7, Ch.10, Ch.11, Ch.12.

## Goal

Create a repeatable baseline package that captures the normal state of a Windows research machine before experiments.

This lab is intentionally not a single-tool exercise. It teaches the research habit that makes later internals work trustworthy:

- Identify the machine and security context.
- Capture process, service, driver, minifilter, startup, and quick telemetry views.
- Save raw outputs separately from interpretation.
- Write a short evidence note that says what is known, what is inferred, and what remains unknown.

## Scope and safety

- VM required: No, but recommended for repeatability.
- Snapshot required: No, but recommended before state-changing experiments.
- Admin required: Recommended for full inventory.
- Kernel debugger required: No.
- Network required: Optional. Avoid unnecessary network lookups if you want a quiet baseline.
- Production-safe: Read-only intent, but Sysinternals tools can create EULA/settings/log artifacts. Treat output as sensitive.

## Tested environment

Fill this after running the lab.

| Field | Value |
|---|---|
| Windows build |  |
| Edition |  |
| Architecture |  |
| Host type | VM / physical / cloud |
| Secure Boot |  |
| VBS/HVCI |  |
| Defender/EDR state |  |
| Sysinternals version/source |  |
| PowerShell version |  |

## Requirements

- PowerShell.
- Sysinternals Suite from Microsoft.
- Optional GUI tools:
  - Process Explorer.
  - Process Monitor.
  - Autoruns.
  - WinObj.
- Optional CLI tools:
  - `autorunsc.exe`
  - `handle.exe`
  - `pslist.exe`
  - `sigcheck.exe`

## Files

| File | Purpose |
|---|---|
| `scripts/capture-baseline.ps1` | Creates a timestamped baseline folder and saves built-in Windows inventory |
| `expected-output/baseline-folder-shape.txt` | Expected output directory shape |
| `verification/verification-record.md` | Evidence record for the captured baseline |
| `../../assets/diagrams/app-i-sysinternals-baseline.mmd` | Baseline evidence pipeline diagram |

## Output directory

Default output:

```text
C:\Labs\Logs\SysinternalsBaseline\<timestamp>\
```

The script accepts `-OutRoot` if you want a different location.

## Steps

1. Open PowerShell.

2. Run the baseline script:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\capture-baseline.ps1
```

3. If Sysinternals CLI tools are available, run them into the same output directory. Example:

```powershell
$out = Get-ChildItem C:\Labs\Logs\SysinternalsBaseline | Sort-Object Name -Descending | Select-Object -First 1
autorunsc.exe -accepteula -a * -ct > "$($out.FullName)\autoruns-baseline.csv"
handle.exe -accepteula -a > "$($out.FullName)\handle-baseline.txt"
pslist.exe -accepteula -t > "$($out.FullName)\pslist-tree.txt"
sigcheck.exe -accepteula -nobanner -q -m C:\Windows\System32\notepad.exe > "$($out.FullName)\sigcheck-notepad.txt"
```

4. Open Process Explorer.

5. Save or screenshot:

- Full process tree.
- A normal user process properties page.
- An elevated process properties page, if available.
- One process token/security tab.
- One process threads tab.

6. Open Autoruns.

7. Export startup inventory as `.ARN` or CSV into the same baseline folder.

8. Optional quiet Procmon baseline:

- Start Procmon elevated.
- Clear current events.
- Capture 30 seconds while idle.
- Save `.PML` into the baseline folder.
- Stop capture immediately.

9. Fill `verification/verification-record.md`.

10. Write a short conclusion note:

```text
This baseline represents <machine/build/config> at <time>.
It supports later diffs for process/service/driver/minifilter/startup state.
It does not prove historical execution, hidden kernel state, or physical disk persistence.
```

## Expected observations

- Built-in inventory files are created by the PowerShell script.
- GUI Sysinternals outputs add richer screenshots/exports.
- `fltmc` shows minifilter stack and altitudes.
- `driverquery` and `sc query` show driver/service inventory.
- Autoruns shows startup configuration, not proof of startup execution.
- Procmon shows observed operations during the capture window only.

See `expected-output/baseline-folder-shape.txt`.

## Evidence to save

- `system-context.txt`
- `process-list.csv`
- `services.csv`
- `drivers.csv`
- `fltmc.txt`
- `sc-query-drivers.txt`
- `netstat.txt`
- Autoruns export.
- Process Explorer screenshots/exports.
- Optional Procmon `.PML`.
- Completed verification record.

## Cleanup

1. Stop Procmon capture if used.
2. Close Sysinternals tools.
3. Keep the baseline folder as evidence, or archive it outside the repo if it contains sensitive data.
4. Do not commit raw `.PML`, dumps, screenshots with usernames/hostnames, or proprietary EDR details.

## Interpretation notes

### What the baseline proves

- The captured machine had the listed processes, services, drivers, minifilters, startup entries, and network endpoints at capture time.
- The baseline is usable for later diffs when an experiment changes state.
- The baseline records tool/version context that helps interpret later observations.

### What it does not prove

- It does not prove no hidden process/driver/rootkit exists.
- It does not prove startup entries executed.
- It does not prove a file write persisted to disk.
- It does not prove EDR visibility unless EDR telemetry is separately collected.

### Researcher rule

Never write: "Autoruns proves malware executed."

Write instead: "Autoruns shows a startup configuration entry. Execution requires correlation with process creation, service control, task scheduler, event logs, or other runtime evidence."

## Creative extension

Turn this baseline into a "before/after diff lab":

1. Capture baseline.
2. Install or run one harmless test tool.
3. Capture the same inventory again.
4. Diff process, service, driver, Autoruns, and Procmon evidence.
5. Write a mini incident note that separates configuration, execution, and persistence.

This extension makes the lab useful for detection engineering, incident response, and malware-analysis hygiene without introducing offensive behavior.

## Open questions

- Which Sysinternals tools create EULA registry values on first run?
- Which minifilters are present on your machine before any experiment?
- How much background Procmon noise appears during a 30-second idle capture?
- Which baseline fields change after reboot without any deliberate experiment?

