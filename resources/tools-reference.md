# FlareVM Tool Reference

Complete listing of every tool the MCP server invokes, with paths and purpose.

## Static analysis

| Tool | Path | What it does |
|------|------|--------------|
| **DIE** | `C:\Tools\die\diec.exe` | Detect packer, compiler, language. Output JSON with `-j`. |
| **FLOSS** | `C:\Tools\FLOSS\floss.exe` | Extract static, stack, decoded, and tight-loop strings. |
| **CAPA** | `C:\Tools\capa\capa.exe` | Identify program capabilities via rule matching (MITRE ATT&CK). |
| **YARA** | `C:\ProgramData\chocolatey\bin\yara64.exe` | Pattern-match samples against rule sets. Default rules: `C:\Tools\yara_rules`. |
| **Strings** | `C:\Tools\cygwin\bin\strings.exe` | ASCII / Unicode strings dump. |
| **dnSpy console** | `C:\Tools\dnSpy\dnSpy.Console.exe` | Decompile .NET assemblies to C#. |

## Behavioral / monitoring

| Tool | Path | What it does |
|------|------|--------------|
| **ProcMon** | `C:\Tools\ProcessMonitor\Procmon64.exe` | Capture process / file / registry / network events to PML. |
| **Autorunsc** | `C:\Tools\sysinternals\autorunsc.exe` | Enumerate every persistence location on Windows. |
| **FakeNet-NG** | `C:\Tools\fakenet\fakenet.exe` | Sinkhole DNS, HTTP, HTTPS; respond with canned content. |
| **TShark** | `C:\ProgramData\chocolatey\bin\tshark.exe` | CLI Wireshark; capture and dissect PCAP. |
| **Regshot** | (PowerShell-based snapshot) | Diff registry before/after detonation. |

## Memory / injection

| Tool | Path | What it does |
|------|------|--------------|
| **PE-sieve** | `C:\ProgramData\chocolatey\bin\pe-sieve.exe` | Scan a process for in-memory PE anomalies; dump implants. |
| **Hollows Hunter** | `C:\Tools\hollows_hunter\hollows_hunter64.exe` | System-wide PE-sieve sweep. |

## Unpacking / debugging

| Tool | Path | What it does |
|------|------|--------------|
| **UPX** | `C:\ProgramData\chocolatey\bin\upx.exe` | Pack / unpack UPX-compressed binaries. |
| **x64dbg** | `C:\ProgramData\chocolatey\bin\x64dbg.exe` | x86/x64 ring-3 debugger (GUI). |
| **NirCmd** | `C:\Tools\nircmd.exe` | GUI automation helper (close windows, send keys). |

## IDA Pro proxy

The server proxies a subset of calls to an IDA MCP plugin running on FlareVM
at `http://localhost:13337` (JSON-RPC). Tools include `ida_decompile`,
`ida_list_functions`, `ida_get_xrefs_to`, etc.

## Adding a new tool

1. Add the path to `TOOL_PATHS` in `server.py`.
2. Add a `Tool(...)` entry in `list_tools()`.
3. Implement `_handle_<name>(args)` and dispatch in `call_tool()`.
4. Document the flags in this file and `cheatsheet.md`.
