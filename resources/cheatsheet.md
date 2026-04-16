# FlareVM MCP Cheatsheet

## Quick triage (5 commands)
```
check_connection
upload_file kali_path=/tmp/sample.bin remote_path=C:\temp\sample.bin
die_analyze C:\temp\sample.bin
floss_extract_strings C:\temp\sample.bin --min 6
capa_analyze C:\temp\sample.bin
yara_scan C:\temp\sample.bin --rules C:\Tools\yara\rules
```

## Detonation
```
fakenet_start
procmon_start --filter pid=<PID>
regshot_baseline
execute_with_monitoring C:\temp\sample.bin --timeout 60
procmon_stop
fakenet_stop
regshot_compare
```

## Unpacking
```
die_analyze C:\temp\sample.bin                 # identify packer
unpack_detect_and_try C:\temp\sample.bin       # UPX auto
pe_sieve_scan --pid <RUNNING_PID>              # dump from memory
x64dbg_launch_gui C:\temp\sample.bin           # manual unpack
```

## Injection hunt
```
injection_scan_all
list_processes
pe_sieve_scan --pid <PID> --detail
```

## Persistence audit
```
persistence_audit
list_scheduled_tasks
list_services --filter unsigned
```

## Network
```
tshark_capture --interface 0 --duration 60 --output C:\temp\out.pcap
fakenet_start --config <inline JSON>
```

## .NET decompilation
```
dnspy_decompile C:\temp\sample.exe --output C:\temp\src
```

## YARA
```
yara_scan <file> --rules <dir>          # default: C:\Tools\yara\rules
```

## Common tool flags
| Tool       | Useful flags                       |
|------------|------------------------------------|
| die        | `-j` JSON, `-d` deep, `-r` recursive |
| floss      | `-n 6` min len, `--no-static-strings` |
| capa       | `-j` JSON, `-vv` verbose, `--shellcode` |
| yara       | `-r` recursive, `-s` show strings  |
| pe-sieve   | `/pid N /imp 3 /shellc 3 /data 3`  |
| autorunsc  | `-a *` all, `-h` hashes, `-c` CSV  |
| tshark     | `-i N -a duration:60 -w out.pcap`  |

## Flag detection regex
```
[A-Z]{3,6}\{[a-zA-Z0-9_!@#$%^&*]+\}
flag\{.*?\}
ctf\{.*?\}
```

## File transfer
- Upload: SMB share `\\<flarevm-ip>\KaliShare` -> `C:\Share`
- Download: same share, reverse direction

## Safety reminders
- Always snapshot the FlareVM before detonation.
- Run FakeNet to keep traffic off the analyst host.
- Never copy a sample out of `C:\temp` unencrypted.
