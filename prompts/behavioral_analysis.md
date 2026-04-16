---
name: behavioral_analysis
description: Detonation walkthrough with FakeNet, ProcMon, and Regshot.
arguments:
  - name: sample_path
    description: Path to sample on Kali host
    required: true
  - name: duration
    description: Detonation duration (seconds)
    required: false
---

Perform behavioral (dynamic) analysis of `{sample_path}` for `{duration}` seconds.

## Workflow

1. `check_connection` and confirm FlareVM snapshot is clean.
2. `upload_file` to `C:\temp\sample.bin`.
3. Start collectors:
   - `fakenet_start` with the default config.
   - `procmon_start` with filter on the sample's PID.
   - `regshot_baseline`.
4. `execute_with_monitoring` to detonate the sample.
5. Stop collectors: `procmon_stop`, `fakenet_stop`, `regshot_compare`.
6. `download_file` artifacts (PCAP, PML, regshot diff) to Kali.
7. Summarize: network IOCs, persistence, file/registry mutations, child processes.

## Example output

```
Duration: 30s
Network: 3 DNS queries, 2 HTTP POSTs to evil[.]example
Persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater
File drops: %APPDATA%\Updater\svc.exe (copy of self)
Child processes: cmd.exe /c whoami, powershell -enc ...
```
