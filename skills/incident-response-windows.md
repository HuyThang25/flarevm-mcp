---
name: incident-response-windows
description: Run a Windows incident-response sweep on a live FlareVM (or compromised lookalike) using the flarevm MCP server. Use when the user reports suspected compromise, asks to find injected processes, audit persistence, or hunt for malicious activity on a Windows host.
---

# Windows incident response

When the user asks to investigate a Windows machine for compromise, drive the `flarevm` MCP server through this sweep.

## Steps

1. `flarevm.check_connection` — confirm reachability.
2. **Persistence audit** — `flarevm.persistence_audit` for autoruns, scheduled tasks, services, WMI subscriptions. Flag unsigned binaries and recent modifications under `%TEMP%` or `%APPDATA%`.
3. **Process inspection** — `flarevm.list_processes` and look for:
   - Unsigned processes with network connections.
   - Suspicious parent-child relationships (e.g. `winword.exe` -> `powershell.exe`).
   - Processes running from user-writable paths.
4. **Injection sweep** — `flarevm.injection_scan_all` (Hollows Hunter + per-PID PE-sieve).
5. **Network capture** — `flarevm.tshark_capture` for 60s to spot beaconing.
6. **Artifact extraction** — `flarevm.download_file` for any suspicious binaries; triage them with `die_analyze` + `yara_scan`.
7. Produce an IR report: indicators by host, recommended containment (kill PIDs, remove persistence, block IOCs).

## What to avoid

- Do not detonate unknown binaries during IR — only static / live-process inspection.
- Do not modify the system without explicit user confirmation.
