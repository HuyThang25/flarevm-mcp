---
name: unpack_workflow
description: Step-by-step unpacking flow with fallbacks.
arguments:
  - name: sample_path
    description: Path to packed sample on FlareVM
    required: true
---

Attempt to unpack the packed binary at `{sample_path}`.

## Workflow

1. `die_analyze` to fingerprint the packer.
2. If UPX: `unpack_detect_and_try`.
3. Known packer with public unpacker: run via `execute_powershell`.
4. Generic fallback: `pe_sieve_scan` after detonation to dump unpacked PE from memory.
5. Manual: `x64dbg_launch_gui`, breakpoint on `VirtualAlloc` / `WriteProcessMemory`, dump.
6. Re-run `die_analyze`, `floss_extract_strings`, `capa_analyze` on the unpacked image.
7. Report: original packer, unpacker used, OEP if known, capability diff.

## Example output

```
Original: UPX 4.0.2
Unpacker: upx -d (success)
Unpacked size: 412 KB -> 1.2 MB
New strings: kernel32!CreateRemoteThread, ntdll!NtMapViewOfSection
New capabilities: process injection, anti-debug
```
