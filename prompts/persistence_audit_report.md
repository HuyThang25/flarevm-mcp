---
name: persistence_audit_report
description: Generate a Windows persistence audit report.
arguments: []
---

Generate a Windows persistence audit report from FlareVM.

## Workflow

1. `check_connection`.
2. `persistence_audit` (Autorunsc + scheduled tasks + services + WMI subscriptions).
3. Filter results: highlight unsigned binaries, recent modifications, suspicious paths (`%TEMP%`, `%APPDATA%`).
4. For each suspicious entry, `download_file` the binary and run `die_analyze` + `yara_scan`.
5. Output a markdown report grouped by persistence mechanism.

## Example output

```
## Run Keys
- HKCU\...\Run\Updater -> %APPDATA%\svc.exe (UNSIGNED, modified today)

## Scheduled Tasks
- \Microsoft\Windows\... -> wscript.exe c:\temp\loader.vbs

## Services
- (none suspicious)

## WMI Subscriptions
- __EventFilter "BotFilter82" -> ActiveScriptEventConsumer
```
