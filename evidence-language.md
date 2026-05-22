# Evidence Language Guide

Use this guide when writing chapter summaries, lab conclusions, incident-style notes, and forensic interpretations.

The goal is not to sound cautious for its own sake. The goal is to make claims match the evidence layer.

---

## Core rule

Every conclusion should answer four questions:

1. What was directly observed?
2. Which tool/layer observed it?
3. What does it support?
4. What does it not prove?

Recommended shape:

```text
<Tool/layer> observed <fact> on <build/config/time>.
This supports <bounded conclusion>.
It does not by itself prove <common overclaim>.
Confidence: <low|medium|high>, because <reason>.
```

---

## Claim ladder

| Strength | Use when | Example |
|---|---|---|
| Observed | Direct tool output or artifact | Procmon observed `WriteFile` by PID 1234. |
| Supports | Evidence points toward a bounded conclusion | The trace supports that the process wrote to that path during capture. |
| Consistent with | Evidence matches a hypothesis but is not enough | The named mutex is consistent with a single-instance pattern. |
| Suggests | Evidence is weak or incomplete | The timing suggests startup-related execution, but process creation logs are needed. |
| Proves | Only when alternatives are ruled out | The before/after registry export proves the value existed during the second capture. |

Avoid `proves` unless the claim is narrow and the evidence actually excludes alternatives.

---

## Common overclaims

| Weak wording | Better wording |
|---|---|
| Autoruns proves malware executed. | Autoruns shows startup configuration. Execution requires runtime/logon evidence. |
| Procmon proves persistence. | Procmon observed operations during the capture window. Persistence needs durable artifact checks. |
| A mutex proves malware family X. | The named object is consistent with that family only if corroborated by binary, path, behavior, or threat intel. |
| Admin means SYSTEM. | The process token shows a specific user, integrity level, groups, and privileges. |
| Thread start address is safe because it is in a module. | Module-backed start address reduces concern but stack/VAD/context are still needed. |
| No event means no activity. | No event in this source means this source did not observe it under this configuration. |
| The file was deleted, so evidence is gone. | Deletion affects namespace visibility; journals, cache, memory, backups, and logs may remain. |

---

## Tool-specific wording

### Process Explorer

Use:

```text
Process Explorer showed <process/thread/handle/token> at observation time.
```

Avoid:

```text
Process Explorer proves this was always running.
```

### Procmon

Use:

```text
Procmon observed <operation> by <process/PID> on <path> during the capture window.
```

Avoid:

```text
Procmon proves every file operation that happened on the system.
```

### Autoruns

Use:

```text
Autoruns showed a startup configuration entry at capture time.
```

Avoid:

```text
Autoruns proves the program executed.
```

### WinObj / Handle

Use:

```text
WinObj/Handle showed a named object and/or handle while the process was alive.
```

Avoid:

```text
The object name alone proves attribution.
```

### WinDbg

Use:

```text
WinDbg showed <structure/field/stack> under <symbol/build/context> conditions.
```

Avoid:

```text
This private structure field is universally stable.
```

### Event Logs / ETW

Use:

```text
This provider/channel recorded <event> with <fields> under the configured session/channel state.
```

Avoid:

```text
No event means no behavior.
```

---

## Confidence rubric

| Confidence | Criteria |
|---|---|
| High | Multiple independent sources agree; build/config recorded; expected and actual match; alternatives considered. |
| Medium | One strong source or two partial sources; build/config mostly recorded; some caveats remain. |
| Low | Single source; incomplete context; tool limitations significant; needs corroboration. |

---

## Mini templates

### Lab conclusion

```text
On <Windows build/config>, <tool version> observed <direct observation>.
This supports <bounded claim> with <confidence> confidence.
It does not prove <limit>.
Next corroboration: <artifact/tool>.
```

### Forensic note

```text
Evidence:
- <artifact/tool/time>: <fact>

Inference:
- <bounded interpretation>

Unknown:
- <what still needs collection>

Confidence:
- <low|medium|high>, because <reason>
```

### Detection engineering note

```text
Signal:
- <event/provider/tool field>

Detection idea:
- <logic>

Required correlation:
- <process/file/user/time/context>

False positives:
- <expected benign causes>

Known gaps:
- <bypass/layer/config limits>
```

