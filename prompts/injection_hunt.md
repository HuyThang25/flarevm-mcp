---
name: injection_hunt
description: Scan all processes for code injection.
arguments: []
---

Scan all running processes on FlareVM for code injection.

## Workflow

1. `check_connection`.
2. `injection_scan_all` (orchestrates Hollows Hunter sweep + targeted PE-sieve).
3. For each suspicious PID, `pe_sieve_scan` with detail and `download_file` dumps.
4. For each dump, `die_analyze` and `floss_extract_strings` to identify the injected payload.
5. Cross-reference with `list_processes` for parent-child anomalies.
6. Report: process tree of injectors, payload identification, suggested IOCs.

## Example output

```
Suspicious PIDs: 4312 (explorer.exe), 5188 (svchost.exe)
PID 4312: shellcode at 0x7FF8`12340000 (4 KB), Cobalt Strike pattern
PID 5188: hollowed PE replaced with custom loader
IOCs: hxxps://1.2.3.4/jquery-3.3.1.min.js (Cobalt malleable C2)
```
