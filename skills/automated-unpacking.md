---
name: automated-unpacking
description: Automatically unpack a packed Windows binary using FlareVM tooling. Use when the user has a sample identified as packed (UPX, Themida, ASPack, custom) and wants the unpacked image for further analysis.
---

# Automated unpacking

Drive the `flarevm` MCP server through an iterative unpack loop.

## Steps

1. `flarevm.check_connection`.
2. `flarevm.die_analyze` on the sample — record the packer name and version.
3. Call `flarevm.unpack_detect_and_try`:
   - Handles UPX automatically (`upx -d`).
   - Reports the result; if successful, jump to step 6.
4. **If still packed:** detonate under monitoring with `flarevm.execute_with_monitoring`, then `flarevm.pe_sieve_scan --pid <NEW_PID>` to dump the unpacked image from memory.
5. **If pe-sieve fails:** open in `flarevm.x64dbg_launch_gui`, suggest the user set breakpoints on `VirtualAlloc`, `WriteProcessMemory`, `NtMapViewOfSection`, then dump.
6. Re-run `die_analyze`, `floss_extract_strings`, and `capa_analyze` on the unpacked image.
7. Diff the capability set vs. the packed original; report the original packer, unpacker used, OEP if known, and new capabilities revealed.

## What to avoid

- Do not stop after the first unpack — many samples are multi-layer packed. Iterate until DIE no longer reports a packer.
- Do not run on the analyst host. Always work inside FlareVM.
