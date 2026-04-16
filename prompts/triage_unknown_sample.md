---
name: triage_unknown_sample
description: Full static triage workflow for an unknown malware sample on FlareVM.
arguments:
  - name: sample_path
    description: Path to sample on Kali host
    required: true
---

Perform a full static triage of the malware sample at `{sample_path}` using the flarevm MCP server.

## Workflow

1. `check_connection` to ensure FlareVM is reachable.
2. `upload_file` from `{sample_path}` to `C:\temp\sample.bin`.
3. `triage_full` (or run individually):
   - `die_analyze` for packer / compiler ID.
   - `floss_extract_strings` for stack and decoded strings.
   - `capa_analyze` for capability fingerprint.
   - `yara_scan` against `C:\Tools\yara\rules`.
4. Search output for IOCs: URLs, IPs, mutexes, registry keys, file paths, flag patterns.
5. Produce a triage report: hash, packer, capabilities, suspicious strings, recommended next steps.

## Example output

```
SHA256: 9a4b...
Packer: UPX 3.96
Capabilities: persistence (Run key), inject into explorer.exe, HTTP C2
Strings of interest: hxxp://evil[.]example/c2, mutex Global\Sample123
Next steps: behavioral_analysis, then unpack and re-triage.
```
