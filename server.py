#!/usr/bin/env python3
r"""
FlareVM MCP Server - Enhanced malware analysis bridge.

Controls a Windows FlareVM malware analysis VM (192.168.100.10) via WinRM.
Runs on Kali Linux. Exposes 48 tools to Claude Code for malware analysis.

Transport: MCP stdio (stdin/stdout)
Control: WinRM (pywinrm, plaintext transport)
File transfer: SMB only (//FlareVM/KaliShare -> C:\Share)
GUI tools: Windows Scheduled Tasks for interactive session
IDA Pro: Proxy to IDA MCP server on FlareVM (HTTP JSON-RPC port 13337)
"""

import asyncio
import hashlib
import ntpath
import json
import logging
import os
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

import keyring
import winrm
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
    Prompt,
    PromptArgument,
    PromptMessage,
    GetPromptResult,
    Resource,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Configuration — environment variables override defaults
FLAREVM_HOST = os.environ.get("FLAREVM_HOST", "192.168.100.10")
FLAREVM_USER = os.environ.get("FLAREVM_USER", "xtemp")
FLAREVM_PASSWORD = None  # loaded lazily from keyring or FLAREVM_PASSWORD env

SMB_SHARE_NAME = os.environ.get("FLAREVM_SMB_SHARE", "KaliShare")
SMB_SHARE_PATH = "//{}/{}".format(FLAREVM_HOST, SMB_SHARE_NAME)
SMB_LOCAL_PATH = os.environ.get("FLAREVM_SMB_LOCAL_PATH", "C:\\Share")

IDA_MCP_PORT = 13337

TOOL_PATHS = {
    "die": "C:\\Tools\\die\\diec.exe",
    "floss": "C:\\Tools\\FLOSS\\floss.exe",
    "capa": "C:\\Tools\\capa\\capa.exe",
    "yara": "C:\\Tools\\yara\\yara64.exe",
    "procmon": "C:\\Tools\\sysinternals\\Procmon.exe",
    "autorunsc": "C:\\Tools\\sysinternals\\autorunsc.exe",
    "strings": "C:\\Tools\\sysinternals\\strings.exe",
    "pe_sieve": "C:\\Tools\\pe-sieve\\pe-sieve64.exe",
    "hollows_hunter": "C:\\Tools\\hollows_hunter\\hollows_hunter64.exe",
    "upx": "C:\\Tools\\upx\\upx.exe",
    "dnspy": "C:\\Tools\\dnSpy\\dnSpy.Console.exe",
    "fakenet": "C:\\Tools\\fakenet\\fakenet.exe",
    "nircmd": "C:\\Tools\\nircmd.exe",
    "x64dbg": "C:\\ProgramData\\chocolatey\\bin\\x64dbg.exe",
    "tshark": "C:\\ProgramData\\chocolatey\\bin\\tshark.exe",
}

LOG = logging.getLogger("flarevm-mcp")
logging.basicConfig(level=logging.INFO, stream=sys.stderr)

executor = ThreadPoolExecutor(max_workers=4)

# ---------------------------------------------------------------------------
# WinRM session management
# ---------------------------------------------------------------------------

_session = None


def _get_password():
    global FLAREVM_PASSWORD
    if FLAREVM_PASSWORD is None:
        FLAREVM_PASSWORD = keyring.get_password("flarevm", FLAREVM_USER)
        if not FLAREVM_PASSWORD:
            FLAREVM_PASSWORD = os.environ.get("FLAREVM_PASSWORD", "infected")
    return FLAREVM_PASSWORD


def get_session():
    global _session
    if _session is None:
        _session = winrm.Session(
            FLAREVM_HOST,
            auth=(FLAREVM_USER, _get_password()),
            transport="plaintext",
        )
    return _session


def run_ps(command, timeout=120):
    """Run PowerShell command via WinRM synchronously. Returns (stdout, stderr, status_code)."""
    sess = get_session()
    result = sess.run_ps(command)
    stdout = result.std_out.decode("utf-8", errors="replace").strip()
    stderr = result.std_err.decode("utf-8", errors="replace").strip()
    return stdout, stderr, result.status_code


async def run_ps_async(command, timeout=120):
    """Run PowerShell via WinRM asynchronously using ThreadPoolExecutor."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, lambda: run_ps(command, timeout))


async def run_ps_script(script, timeout=300, script_name="mcp_script.ps1"):
    """Run a long PowerShell script that exceeds the WinRM 8KB command-line limit.

    Strategy: stage the script as a local temp file, ship it via SMB (already
    proven working), then invoke `powershell -File`. Falls back to inline
    execution if the script is short enough.
    """
    if len(script) < 4000:
        return await run_ps_async(script, timeout=timeout)

    remote_path = "C:\\temp\\" + script_name

    # Stage locally
    local_tmp = "/tmp/" + script_name
    with open(local_tmp, "w", encoding="utf-8") as f:
        f.write(script)

    # SMB upload + Move-Item to final destination (mirrors _handle_upload_file)
    smb_cmd = [
        "smbclient", SMB_SHARE_PATH,
        "-U", "{}%{}".format(FLAREVM_USER, _get_password()),
        "-c", 'put "{}" "{}"'.format(local_tmp, script_name),
    ]
    proc = subprocess.run(smb_cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError("SMB script upload failed: {}".format(proc.stderr))

    move_cmd = (
        'New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null; '
        'Move-Item -Path "{src}\\{name}" -Destination "{dst}" -Force'
    ).format(src=SMB_LOCAL_PATH, name=script_name, dst=remote_path)
    _, stderr, code = await run_ps_async(move_cmd, timeout=30)
    if code != 0:
        raise RuntimeError("Failed to move script into place: {}".format(stderr))

    # Cleanup local copy
    try:
        os.remove(local_tmp)
    except OSError:
        pass

    return await run_ps_async(
        'powershell.exe -ExecutionPolicy Bypass -File "{}"'.format(remote_path),
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# IDA RPC helper
# ---------------------------------------------------------------------------

async def ida_rpc_call(method, params=None):
    """JSON-RPC call to IDA MCP on FlareVM port 13337 via WinRM PowerShell."""
    payload = {"jsonrpc": "2.0", "method": method, "id": 1}
    if params:
        payload["params"] = params
    payload_json = json.dumps(payload).replace('"', '\\"')
    ps = (
        '$body = "{}"\n'
        "$resp = Invoke-WebRequest -Uri 'http://127.0.0.1:{}/jsonrpc' "
        "-Method POST -ContentType 'application/json' -Body $body -UseBasicParsing\n"
        "$resp.Content"
    ).format(payload_json, IDA_MCP_PORT)
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    if code != 0:
        raise RuntimeError("IDA RPC error: {} {}".format(stderr, stdout))
    return json.loads(stdout)


# ---------------------------------------------------------------------------
# GUI app launcher via Scheduled Task
# ---------------------------------------------------------------------------

async def launch_gui_app(exe_path, arguments="", task_name="MCP_App",
                         wait_port=None, wait_timeout=60):
    """Launch a GUI application in the interactive user session via Scheduled Task."""
    ps = """
$action = New-ScheduledTaskAction -Execute "{exe}" -Argument "{args}"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(2)
$principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\\{user}" -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 120)
Unregister-ScheduledTask -TaskName "{task}" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "{task}" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
Start-ScheduledTask -TaskName "{task}"
Write-Output "Scheduled task '{task}' started"
""".format(exe=exe_path, args=arguments.replace('"', '`"'),
           user=FLAREVM_USER, task=task_name)
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        raise RuntimeError("Failed to launch GUI app: {} {}".format(stderr, stdout))

    if wait_port is not None:
        ps_wait = """
$timeout = {timeout}
$elapsed = 0
while ($elapsed -lt $timeout) {{
    $result = Test-NetConnection 127.0.0.1 -Port {port} -WarningAction SilentlyContinue
    if ($result.TcpTestSucceeded) {{
        Write-Output "Port {port} is ready after $elapsed seconds"
        exit 0
    }}
    Start-Sleep -Seconds 2
    $elapsed += 2
}}
Write-Output "Timeout waiting for port {port} after $timeout seconds"
exit 1
""".format(port=wait_port, timeout=wait_timeout)
        stdout2, stderr2, code2 = await run_ps_async(ps_wait, timeout=wait_timeout + 30)
        if code2 != 0:
            return stdout + "\nWARNING: " + stdout2
        return stdout + "\n" + stdout2

    return stdout


# ---------------------------------------------------------------------------
# FakeNet config generator
# ---------------------------------------------------------------------------

def generate_fakenet_config(kali_ip=None, excluded_ports=None, excluded_processes=None):
    """Generate a FakeNet-NG INI config with triple-layer protection for the analyst host.

    The HostBlackList is the primary shield: ALL traffic to/from Kali bypasses
    interception regardless of port. Port and process blacklists are
    defense-in-depth.

    Args:
        kali_ip: IP of the analyst Kali machine (default: 192.168.110.134)
        excluded_ports: Defense-in-depth port list (default: WinRM, SMB, IDA MCP)
        excluded_processes: Process names that handle control traffic
    """
    if kali_ip is None:
        kali_ip = "192.168.110.134"
    if excluded_ports is None:
        excluded_ports = [5985, 5986, 445, 139, 13337]
    if excluded_processes is None:
        excluded_processes = ["svchost.exe", "System", "smbd.exe", "wsmprovhost.exe"]
    blacklist_ports = ",".join(str(p) for p in excluded_ports)
    blacklist_procs = ",".join(excluded_processes)
    return """[FakeNet]
DivertTraffic: Yes
NetworkMode: SingleHost

[Diverter]
# PRIMARY SHIELD: never intercept traffic to/from analyst host
HostBlackList: {kali_ip}
# Process exclusions (WinRM/SMB host processes)
ProcessBlackList: {blacklist_procs}
# Port blacklist (defense-in-depth)
DefaultTCPListener: RawTCPListener
DefaultUDPListener: RawUDPListener
BlackListPortsTCP: {blacklist_ports}
BlackListPortsUDP:

[RawTCPListener]
Enabled: True
Port: 1337
Protocol: TCP
Listener: RawListener
UseSSL: No
Timeout: 10

[RawUDPListener]
Enabled: True
Port: 1337
Protocol: UDP
Listener: RawListener
Timeout: 10

[DNSListener]
Enabled: True
Port: 53
Protocol: UDP
Listener: DNSListener
ResponseA: 192.0.2.123
ResponseAAAA: ::1
ResponseMX: mail.evil.com
ResponseTXT: FAKENET
NXDomains: 0

[HTTPListener80]
Enabled: True
Port: 80
Protocol: TCP
Listener: HTTPListener
UseSSL: No
Webroot: C:\\Tools\\fakenet\\defaultFiles\\
DumpHTTPPosts: Yes
DumpHTTPPostsFilePrefix: http

[HTTPListener443]
Enabled: True
Port: 443
Protocol: TCP
Listener: HTTPListener
UseSSL: Yes
Webroot: C:\\Tools\\fakenet\\defaultFiles\\
DumpHTTPPosts: Yes
DumpHTTPPostsFilePrefix: https

[SMTPListener]
Enabled: True
Port: 25
Protocol: TCP
Listener: SMTPListener

[FTPListener]
Enabled: True
Port: 21
Protocol: TCP
Listener: FTPListener
UseSSL: No

[IRCListener]
Enabled: True
Port: 6667
Protocol: TCP
Listener: IRCListener
""".format(
        kali_ip=kali_ip,
        blacklist_procs=blacklist_procs,
        blacklist_ports=blacklist_ports,
    )


# ---------------------------------------------------------------------------
# Tool helper: resolve tool path on FlareVM
# ---------------------------------------------------------------------------

async def resolve_tool_path(tool_key, fallback_name=None):
    """Find a tool on FlareVM. Check known path first, then where.exe."""
    known = TOOL_PATHS.get(tool_key)
    if known:
        ps = 'if (Test-Path "{}") {{ Write-Output "{}" }} else {{ $p = (where.exe {} 2>$null | Select-Object -First 1); if ($p) {{ Write-Output $p }} else {{ Write-Output "NOT_FOUND" }} }}'.format(
            known, known, fallback_name or tool_key
        )
    else:
        ps = '$p = (where.exe {} 2>$null | Select-Object -First 1); if ($p) {{ Write-Output $p }} else {{ Write-Output "NOT_FOUND" }}'.format(
            fallback_name or tool_key
        )
    stdout, _, _ = await run_ps_async(ps, timeout=15)
    path = stdout.strip().split("\n")[0].strip() if stdout.strip() else "NOT_FOUND"
    if path == "NOT_FOUND":
        raise FileNotFoundError("Tool '{}' not found on FlareVM".format(tool_key))
    return path


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

app = Server("flarevm-mcp")


def _text(content):
    """Helper to return a list with a single TextContent."""
    return [TextContent(type="text", text=str(content))]


# ========================== TOOL DEFINITIONS ==============================

@app.list_tools()
async def list_tools():
    return [
        # --- System & File Transfer ---
        Tool(
            name="check_connection",
            description="Test WinRM connection to FlareVM. Returns hostname, OS info, and IP.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="execute_powershell",
            description="Execute a PowerShell command on FlareVM.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "PowerShell command to execute"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)", "default": 120},
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="read_file",
            description="Read a file from FlareVM. Returns file content.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Absolute path on FlareVM"},
                    "encoding": {"type": "string", "description": "Encoding (default utf-8)", "default": "utf-8"},
                    "max_bytes": {"type": "integer", "description": "Max bytes to read (default 1MB)", "default": 1048576},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="upload_file",
            description="Upload a file from Kali to FlareVM via SMB with SHA256 verification.",
            inputSchema={
                "type": "object",
                "properties": {
                    "local_path": {"type": "string", "description": "Path on Kali"},
                    "remote_path": {"type": "string", "description": "Destination path on FlareVM"},
                },
                "required": ["local_path", "remote_path"],
            },
        ),
        Tool(
            name="download_file",
            description="Download a file from FlareVM to Kali via SMB.",
            inputSchema={
                "type": "object",
                "properties": {
                    "remote_path": {"type": "string", "description": "Path on FlareVM"},
                    "local_path": {"type": "string", "description": "Destination path on Kali"},
                },
                "required": ["remote_path", "local_path"],
            },
        ),
        Tool(
            name="get_file_hash",
            description="Calculate MD5/SHA1/SHA256 hash of a file on FlareVM.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path on FlareVM"},
                    "algorithm": {"type": "string", "description": "Hash algorithm: MD5, SHA1, SHA256 (default SHA256)", "default": "SHA256"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="list_processes",
            description="List running processes on FlareVM with optional name filter.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "description": "Process name filter (wildcard supported)", "default": ""},
                },
                "required": [],
            },
        ),
        Tool(
            name="take_screenshot",
            description="Take a screenshot of FlareVM desktop via nircmd and scheduled task.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_path": {"type": "string", "description": "Output path on FlareVM (default C:\\temp\\screenshot.png)", "default": "C:\\temp\\screenshot.png"},
                },
                "required": [],
            },
        ),
        # --- Static Analysis ---
        Tool(
            name="die_analyze",
            description="Run DetectItEasy (DIE) for packer/compiler detection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="floss_extract_strings",
            description="Run FLOSS for obfuscated string recovery.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                    "min_length": {"type": "integer", "description": "Minimum string length (default 4)", "default": 4},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="capa_analyze",
            description="Run CAPA for capability detection and ATT&CK mapping.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                    "verbose": {"type": "boolean", "description": "Verbose output", "default": False},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="yara_scan",
            description="Scan a file with YARA rules.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                    "rules_path": {"type": "string", "description": "Path to YARA rules (default C:\\Tools\\yara\\rules\\)", "default": "C:\\Tools\\yara\\rules\\"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="strings_extract",
            description="Extract printable strings from a file using Sysinternals strings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                    "min_length": {"type": "integer", "description": "Minimum string length (default 6)", "default": 6},
                    "encoding": {"type": "string", "description": "Encoding: a=ASCII, u=Unicode, b=both (default b)", "default": "b"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="entropy_analysis",
            description="Calculate per-section entropy for PE files to detect packing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to PE file on FlareVM"},
                },
                "required": ["file_path"],
            },
        ),
        # --- Dynamic Analysis: Process Monitoring ---
        Tool(
            name="procmon_start",
            description="Start Process Monitor with optional process filter.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_path": {"type": "string", "description": "PML output path (default C:\\temp\\procmon.pml)", "default": "C:\\temp\\procmon.pml"},
                    "process_filter": {"type": "string", "description": "Process name to filter on (optional)"},
                },
                "required": [],
            },
        ),
        Tool(
            name="procmon_stop",
            description="Stop ProcMon and export results to CSV with summary.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pml_path": {"type": "string", "description": "PML file path (default C:\\temp\\procmon.pml)", "default": "C:\\temp\\procmon.pml"},
                    "csv_path": {"type": "string", "description": "CSV output path (default C:\\temp\\procmon.csv)", "default": "C:\\temp\\procmon.csv"},
                },
                "required": [],
            },
        ),
        Tool(
            name="procmon_export_csv",
            description="Export a PML file to CSV format.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pml_path": {"type": "string", "description": "PML file path"},
                    "csv_path": {"type": "string", "description": "CSV output path"},
                },
                "required": ["pml_path", "csv_path"],
            },
        ),
        Tool(
            name="process_hacker_info",
            description="Get detailed info about a process: modules, threads, handles, connections.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID"},
                },
                "required": ["pid"],
            },
        ),
        # --- Dynamic Analysis: Network ---
        Tool(
            name="monitor_network_realtime",
            description="Monitor network connections for a duration, returning new connections and DNS cache.",
            inputSchema={
                "type": "object",
                "properties": {
                    "duration": {"type": "integer", "description": "Monitoring duration in seconds (default 30)", "default": 30},
                },
                "required": [],
            },
        ),
        Tool(
            name="fakenet_start",
            description="Start FakeNet-NG with WinRM-safe config (excludes management ports).",
            inputSchema={
                "type": "object",
                "properties": {
                    "extra_excluded_ports": {"type": "string", "description": "Comma-separated additional ports to exclude", "default": ""},
                },
                "required": [],
            },
        ),
        Tool(
            name="fakenet_stop",
            description="Stop FakeNet-NG and retrieve captured logs.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="wireshark_capture",
            description="Start/stop packet capture with tshark.",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "description": "start or stop", "enum": ["start", "stop"]},
                    "duration": {"type": "integer", "description": "Capture duration in seconds (for start)", "default": 60},
                    "output_path": {"type": "string", "description": "PCAP output path", "default": "C:\\temp\\capture.pcap"},
                    "interface": {"type": "string", "description": "Capture interface (default 1)", "default": "1"},
                },
                "required": ["action"],
            },
        ),
        # --- Dynamic Analysis: Registry ---
        Tool(
            name="regshot_snapshot",
            description="Registry before/after snapshot and comparison.",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "description": "first, second, or compare", "enum": ["first", "second", "compare"]},
                },
                "required": ["action"],
            },
        ),
        # --- Dynamic Analysis: Debuggers ---
        Tool(
            name="x64dbg_load",
            description="Load a binary in x64dbg via scheduled task (interactive session).",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to executable on FlareVM"},
                    "arguments": {"type": "string", "description": "Command-line arguments", "default": ""},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="x64dbg_run_script",
            description="Save and execute an x64dbg script.",
            inputSchema={
                "type": "object",
                "properties": {
                    "script": {"type": "string", "description": "x64dbg script content"},
                    "script_path": {"type": "string", "description": "Where to save script on FlareVM", "default": "C:\\temp\\x64dbg_script.txt"},
                },
                "required": ["script"],
            },
        ),
        Tool(
            name="windbg_analyze_dump",
            description="Analyze a crash/memory dump with WinDbg (cdb.exe command-line).",
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_file": {"type": "string", "description": "Path to dump file on FlareVM"},
                    "commands": {"type": "string", "description": "WinDbg commands to run (default: !analyze -v)", "default": "!analyze -v"},
                },
                "required": ["dump_file"],
            },
        ),
        # --- Dynamic Analysis: Frida ---
        Tool(
            name="frida_list_processes",
            description="List processes visible to Frida on FlareVM.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="frida_spawn_and_attach",
            description="Spawn a process and attach Frida with a script.",
            inputSchema={
                "type": "object",
                "properties": {
                    "executable": {"type": "string", "description": "Path to executable on FlareVM"},
                    "script": {"type": "string", "description": "Frida JavaScript script content"},
                    "timeout": {"type": "integer", "description": "Script timeout in seconds (default 30)", "default": 30},
                },
                "required": ["executable", "script"],
            },
        ),
        Tool(
            name="frida_attach_pid",
            description="Attach Frida to a running process by PID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID to attach to"},
                    "script": {"type": "string", "description": "Frida JavaScript script content"},
                    "timeout": {"type": "integer", "description": "Script timeout in seconds (default 30)", "default": 30},
                },
                "required": ["pid", "script"],
            },
        ),
        Tool(
            name="frida_run_script",
            description="Execute an inline Frida script against a process (by name or PID).",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Process name or PID"},
                    "script": {"type": "string", "description": "Frida JavaScript script content"},
                    "timeout": {"type": "integer", "description": "Script timeout in seconds (default 30)", "default": 30},
                },
                "required": ["target", "script"],
            },
        ),
        # --- Injection & Unpacking Detection ---
        Tool(
            name="pe_sieve_scan",
            description="Scan a process for code injection/hollowing with PE-sieve.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID to scan"},
                    "output_dir": {"type": "string", "description": "Output directory", "default": "C:\\temp\\pe_sieve_output"},
                },
                "required": ["pid"],
            },
        ),
        Tool(
            name="hollows_hunter_scan",
            description="Scan ALL running processes for injection/hollowing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_dir": {"type": "string", "description": "Output directory", "default": "C:\\temp\\hollows_output"},
                },
                "required": [],
            },
        ),
        Tool(
            name="upx_unpack",
            description="Attempt UPX unpacking of a packed executable.",
            inputSchema={
                "type": "object",
                "properties": {
                    "packed_file": {"type": "string", "description": "Path to packed file"},
                    "output_file": {"type": "string", "description": "Output path for unpacked file"},
                },
                "required": ["packed_file", "output_file"],
            },
        ),
        Tool(
            name="unpack_detect_and_try",
            description="Composite: detect packer, check entropy, attempt automated unpacking.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to potentially packed file"},
                },
                "required": ["file_path"],
            },
        ),
        # --- .NET Analysis ---
        Tool(
            name="dnspy_decompile",
            description="Decompile a .NET assembly with dnSpy Console.",
            inputSchema={
                "type": "object",
                "properties": {
                    "assembly_path": {"type": "string", "description": "Path to .NET assembly on FlareVM"},
                    "output_dir": {"type": "string", "description": "Output directory for decompiled source", "default": "C:\\temp\\decompiled"},
                },
                "required": ["assembly_path"],
            },
        ),
        # --- GUI Tool Launchers ---
        Tool(
            name="ida_launch_and_wait",
            description="Launch IDA Pro with a binary and wait for MCP server (port 13337) to be ready.",
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to binary to load in IDA"},
                    "ida_path": {"type": "string", "description": "Path to IDA executable", "default": "C:\\Tools\\IDA Pro\\ida64.exe"},
                },
                "required": ["binary_path"],
            },
        ),
        Tool(
            name="windbg_launch",
            description="Launch WinDbg GUI with a dump file in interactive session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_file": {"type": "string", "description": "Path to dump file"},
                    "windbg_path": {"type": "string", "description": "Path to WinDbg", "default": "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe"},
                },
                "required": ["dump_file"],
            },
        ),
        # --- IDA Pro Proxy ---
        Tool(
            name="ida_get_metadata",
            description="Get metadata from IDA Pro (binary info, architecture, etc.).",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="ida_list_functions",
            description="List functions in the binary loaded in IDA Pro.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "description": "Optional name filter", "default": ""},
                    "count": {"type": "integer", "description": "Max functions to return", "default": 100},
                },
                "required": [],
            },
        ),
        Tool(
            name="ida_decompile_function",
            description="Decompile a function in IDA Pro (Hex-Rays).",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_name": {"type": "string", "description": "Function name or address"},
                },
                "required": ["function_name"],
            },
        ),
        Tool(
            name="ida_disassemble_function",
            description="Get disassembly of a function in IDA Pro.",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_name": {"type": "string", "description": "Function name or address"},
                },
                "required": ["function_name"],
            },
        ),
        Tool(
            name="ida_list_strings",
            description="List strings found by IDA Pro.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "description": "Optional string filter (regex)", "default": ""},
                    "count": {"type": "integer", "description": "Max strings to return", "default": 200},
                },
                "required": [],
            },
        ),
        Tool(
            name="ida_set_comment",
            description="Set a comment in IDA Pro at a given address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address (hex string like 0x401000)"},
                    "comment": {"type": "string", "description": "Comment text"},
                },
                "required": ["address", "comment"],
            },
        ),
        Tool(
            name="ida_rename_function",
            description="Rename a function in IDA Pro.",
            inputSchema={
                "type": "object",
                "properties": {
                    "old_name": {"type": "string", "description": "Current function name or address"},
                    "new_name": {"type": "string", "description": "New function name"},
                },
                "required": ["old_name", "new_name"],
            },
        ),
        # --- Composite Playbooks ---
        Tool(
            name="triage_full",
            description="Complete static analysis pipeline: hashes, DIE, entropy, CAPA, FLOSS, YARA.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file on FlareVM"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="behavioral_full",
            description="Complete behavioral analysis: regshot, procmon, FakeNet, network monitoring, execute, collect.",
            inputSchema={
                "type": "object",
                "properties": {
                    "executable": {"type": "string", "description": "Path to executable on FlareVM"},
                    "arguments": {"type": "string", "description": "Command-line arguments", "default": ""},
                    "duration": {"type": "integer", "description": "Execution duration in seconds (default 30)", "default": 30},
                },
                "required": ["executable"],
            },
        ),
        Tool(
            name="persistence_audit",
            description="Full persistence mechanism scan: autoruns, registry, tasks, services, WMI, startup.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="injection_scan_all",
            description="Scan all processes for code injection using hollows_hunter + pe-sieve.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
    ]


# ========================== TOOL HANDLERS =================================

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        # --- System & File Transfer ---
        if name == "check_connection":
            return await _handle_check_connection(arguments)
        elif name == "execute_powershell":
            return await _handle_execute_powershell(arguments)
        elif name == "read_file":
            return await _handle_read_file(arguments)
        elif name == "upload_file":
            return await _handle_upload_file(arguments)
        elif name == "download_file":
            return await _handle_download_file(arguments)
        elif name == "get_file_hash":
            return await _handle_get_file_hash(arguments)
        elif name == "list_processes":
            return await _handle_list_processes(arguments)
        elif name == "take_screenshot":
            return await _handle_take_screenshot(arguments)
        # --- Static Analysis ---
        elif name == "die_analyze":
            return await _handle_die_analyze(arguments)
        elif name == "floss_extract_strings":
            return await _handle_floss_extract_strings(arguments)
        elif name == "capa_analyze":
            return await _handle_capa_analyze(arguments)
        elif name == "yara_scan":
            return await _handle_yara_scan(arguments)
        elif name == "strings_extract":
            return await _handle_strings_extract(arguments)
        elif name == "entropy_analysis":
            return await _handle_entropy_analysis(arguments)
        # --- Dynamic Analysis: Process Monitoring ---
        elif name == "procmon_start":
            return await _handle_procmon_start(arguments)
        elif name == "procmon_stop":
            return await _handle_procmon_stop(arguments)
        elif name == "procmon_export_csv":
            return await _handle_procmon_export_csv(arguments)
        elif name == "process_hacker_info":
            return await _handle_process_hacker_info(arguments)
        # --- Dynamic Analysis: Network ---
        elif name == "monitor_network_realtime":
            return await _handle_monitor_network_realtime(arguments)
        elif name == "fakenet_start":
            return await _handle_fakenet_start(arguments)
        elif name == "fakenet_stop":
            return await _handle_fakenet_stop(arguments)
        elif name == "wireshark_capture":
            return await _handle_wireshark_capture(arguments)
        # --- Dynamic Analysis: Registry ---
        elif name == "regshot_snapshot":
            return await _handle_regshot_snapshot(arguments)
        # --- Dynamic Analysis: Debuggers ---
        elif name == "x64dbg_load":
            return await _handle_x64dbg_load(arguments)
        elif name == "x64dbg_run_script":
            return await _handle_x64dbg_run_script(arguments)
        elif name == "windbg_analyze_dump":
            return await _handle_windbg_analyze_dump(arguments)
        # --- Dynamic Analysis: Frida ---
        elif name == "frida_list_processes":
            return await _handle_frida_list_processes(arguments)
        elif name == "frida_spawn_and_attach":
            return await _handle_frida_spawn_and_attach(arguments)
        elif name == "frida_attach_pid":
            return await _handle_frida_attach_pid(arguments)
        elif name == "frida_run_script":
            return await _handle_frida_run_script(arguments)
        # --- Injection & Unpacking ---
        elif name == "pe_sieve_scan":
            return await _handle_pe_sieve_scan(arguments)
        elif name == "hollows_hunter_scan":
            return await _handle_hollows_hunter_scan(arguments)
        elif name == "upx_unpack":
            return await _handle_upx_unpack(arguments)
        elif name == "unpack_detect_and_try":
            return await _handle_unpack_detect_and_try(arguments)
        # --- .NET Analysis ---
        elif name == "dnspy_decompile":
            return await _handle_dnspy_decompile(arguments)
        # --- GUI Tool Launchers ---
        elif name == "ida_launch_and_wait":
            return await _handle_ida_launch_and_wait(arguments)
        elif name == "windbg_launch":
            return await _handle_windbg_launch(arguments)
        # --- IDA Pro Proxy ---
        elif name == "ida_get_metadata":
            return await _handle_ida_get_metadata(arguments)
        elif name == "ida_list_functions":
            return await _handle_ida_list_functions(arguments)
        elif name == "ida_decompile_function":
            return await _handle_ida_decompile_function(arguments)
        elif name == "ida_disassemble_function":
            return await _handle_ida_disassemble_function(arguments)
        elif name == "ida_list_strings":
            return await _handle_ida_list_strings(arguments)
        elif name == "ida_set_comment":
            return await _handle_ida_set_comment(arguments)
        elif name == "ida_rename_function":
            return await _handle_ida_rename_function(arguments)
        # --- Composite Playbooks ---
        elif name == "triage_full":
            return await _handle_triage_full(arguments)
        elif name == "behavioral_full":
            return await _handle_behavioral_full(arguments)
        elif name == "persistence_audit":
            return await _handle_persistence_audit(arguments)
        elif name == "injection_scan_all":
            return await _handle_injection_scan_all(arguments)
        else:
            return _text("Unknown tool: {}".format(name))
    except Exception as e:
        tb = traceback.format_exc()
        LOG.error("Tool %s failed: %s", name, tb)
        return _text("ERROR in tool '{}' with args {}:\n{}\n\n{}".format(
            name, json.dumps(arguments, default=str), str(e), tb
        ))


# ========================== HANDLER IMPLEMENTATIONS =======================

# 1. check_connection
async def _handle_check_connection(args):
    ps = r"""
$hostname = $env:COMPUTERNAME
$os = (Get-WmiObject Win32_OperatingSystem).Caption
$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notmatch '^169\.254\.' -and $_.AddressState -eq 'Preferred' } | Select-Object -ExpandProperty IPAddress
$ip = if ($ips) { $ips -join ', ' } else { 'none' }
$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-Output "=== FlareVM Connection OK ==="
Write-Output "Hostname: $hostname"
Write-Output "OS: $os"
Write-Output "IP: $ip"
Write-Output "Uptime: $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
Write-Output "User: $env:USERNAME"
"""
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        return _text("Connection FAILED: {} {}".format(stderr, stdout))
    return _text(stdout)


# 2. execute_powershell
async def _handle_execute_powershell(args):
    command = args["command"]
    timeout = args.get("timeout", 120)
    stdout, stderr, code = await run_ps_async(command, timeout=timeout)
    result = ""
    if stdout:
        result += stdout
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    result += "\n--- Exit Code: {} ---".format(code)
    return _text(result)


# 3. read_file
async def _handle_read_file(args):
    file_path = args["file_path"]
    encoding = args.get("encoding", "utf-8")
    max_bytes = args.get("max_bytes", 1048576)
    ps = """
$path = "{path}"
if (-not (Test-Path $path)) {{ Write-Error "File not found: $path"; exit 1 }}
$size = (Get-Item $path).Length
if ($size -gt {max_bytes}) {{
    $bytes = [System.IO.File]::ReadAllBytes($path)[0..{max_minus1}]
    $text = [System.Text.Encoding]::GetEncoding("{enc}").GetString($bytes)
    Write-Output "--- TRUNCATED (showing first {max_bytes} of $size bytes) ---"
    Write-Output $text
}} else {{
    Get-Content -Path $path -Raw -Encoding {enc_ps}
}}
""".format(
        path=file_path.replace('"', '`"'),
        max_bytes=max_bytes,
        max_minus1=max_bytes - 1,
        enc=encoding,
        enc_ps="UTF8" if encoding == "utf-8" else "Default",
    )
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    if code != 0:
        return _text("ERROR: {} {}".format(stderr, stdout))
    return _text(stdout)


# 4. upload_file (SMB only — single transport, SHA256 verified)
async def _handle_upload_file(args):
    local_path = args["local_path"]
    remote_path = args["remote_path"]

    if not os.path.isfile(local_path):
        return _text("ERROR: local file not found: {}".format(local_path))

    # Local SHA256
    h = hashlib.sha256()
    with open(local_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    local_hash = h.hexdigest()
    file_size = os.path.getsize(local_path)
    filename = os.path.basename(local_path)

    # Step 1: SMB put → //FlareVM/KaliShare → C:\Share\<filename>
    smb_cmd = [
        "smbclient", SMB_SHARE_PATH,
        "-U", "{}%{}".format(FLAREVM_USER, _get_password()),
        "-c", 'put "{}" "{}"'.format(local_path, filename),
    ]
    proc = subprocess.run(smb_cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        return _text("SMB upload failed:\n{}\n{}".format(proc.stderr, proc.stdout))

    # Step 2: Move from share to final destination on FlareVM
    ps_move = """
$src = "{smb_local}\\{filename}"
$dst = "{remote}"
$dstDir = [System.IO.Path]::GetDirectoryName($dst)
if (-not (Test-Path $dstDir)) {{ New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }}
Move-Item -Path $src -Destination $dst -Force
""".format(
        smb_local=SMB_LOCAL_PATH,
        filename=filename,
        remote=remote_path.replace('"', '`"'),
    )
    stdout, stderr, code = await run_ps_async(ps_move, timeout=60)
    if code != 0:
        return _text("Move from SMB share failed:\n{}\n{}".format(stderr, stdout))

    # Step 3: Verify SHA256 on remote
    ps_verify = '(Get-FileHash -Path "{}" -Algorithm SHA256).Hash'.format(
        remote_path.replace('"', '`"')
    )
    stdout, _, _ = await run_ps_async(ps_verify, timeout=60)
    remote_hash = stdout.strip().lower()
    if remote_hash != local_hash.lower():
        return _text(
            "HASH MISMATCH!\nPath: {}\nLocal:  {}\nRemote: {}".format(
                remote_path, local_hash, remote_hash
            )
        )

    return _text(
        "Upload OK (SMB)\n"
        "Path:   {}\n"
        "Size:   {:,} bytes\n"
        "SHA256: {}\n"
        "Verified: ✓".format(remote_path, file_size, local_hash)
    )


# 5. download_file (SMB only — single transport)
async def _handle_download_file(args):
    remote_path = args["remote_path"]
    local_path = args["local_path"]

    # Step 1: Confirm file exists and get size
    ps_size = """
$p = "{path}"
if (-not (Test-Path $p)) {{ Write-Error "File not found: $p"; exit 1 }}
(Get-Item $p).Length
""".format(path=remote_path.replace('"', '`"'))
    stdout, stderr, code = await run_ps_async(ps_size, timeout=30)
    if code != 0:
        return _text("Remote file error: {}\n{}".format(stderr, stdout))
    file_size = int(stdout.strip())

    # Step 2: Stage on the SMB share (Windows path → use ntpath, not os.path)
    filename = ntpath.basename(remote_path)
    ps_stage = 'Copy-Item -Path "{}" -Destination "{}\\{}" -Force'.format(
        remote_path.replace('"', '`"'), SMB_LOCAL_PATH, filename
    )
    stdout, stderr, code = await run_ps_async(ps_stage, timeout=120)
    if code != 0:
        return _text("Failed to stage on SMB share: {}\n{}".format(stderr, stdout))

    # Step 3: SMB get → local destination
    os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
    smb_cmd = [
        "smbclient", SMB_SHARE_PATH,
        "-U", "{}%{}".format(FLAREVM_USER, _get_password()),
        "-c", 'get "{}" "{}"'.format(filename, local_path),
    ]
    proc = subprocess.run(smb_cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        return _text("SMB download failed:\n{}\n{}".format(proc.stderr, proc.stdout))

    # Step 4: Cleanup staged copy
    await run_ps_async(
        'Remove-Item -Path "{}\\{}" -Force -ErrorAction SilentlyContinue'.format(
            SMB_LOCAL_PATH, filename
        ),
        timeout=15,
    )

    return _text(
        "Download OK (SMB)\n"
        "Remote: {}\n"
        "Local:  {}\n"
        "Size:   {:,} bytes".format(remote_path, local_path, file_size)
    )


# 6. get_file_hash
async def _handle_get_file_hash(args):
    file_path = args["file_path"]
    algorithm = args.get("algorithm", "SHA256")
    ps = """
$path = "{path}"
if (-not (Test-Path $path)) {{ Write-Error "File not found: $path"; exit 1 }}
$md5 = (Get-FileHash -Path $path -Algorithm MD5).Hash
$sha1 = (Get-FileHash -Path $path -Algorithm SHA1).Hash
$sha256 = (Get-FileHash -Path $path -Algorithm SHA256).Hash
$size = (Get-Item $path).Length
Write-Output "=== File Hashes ==="
Write-Output "File: $path"
Write-Output "Size: $size bytes"
Write-Output "MD5:    $md5"
Write-Output "SHA1:   $sha1"
Write-Output "SHA256: $sha256"
""".format(path=file_path.replace('"', '`"'))
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    if code != 0:
        return _text("ERROR: {} {}".format(stderr, stdout))
    return _text(stdout)


# 7. list_processes
async def _handle_list_processes(args):
    proc_filter = args.get("filter", "")
    if proc_filter:
        ps = 'Get-Process -Name "{}" -ErrorAction SilentlyContinue | Format-Table Id, ProcessName, CPU, WorkingSet64, Path -AutoSize | Out-String -Width 200'.format(proc_filter)
    else:
        ps = 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 | Format-Table Id, ProcessName, CPU, WorkingSet64, Path -AutoSize | Out-String -Width 200'
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        return _text("ERROR: {} {}".format(stderr, stdout))
    return _text("=== Running Processes ===\n" + stdout)


# 8. take_screenshot
async def _handle_take_screenshot(args):
    output_path = args.get("output_path", "C:\\temp\\screenshot.png")
    # Ensure temp directory exists
    await run_ps_async('New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null', timeout=10)
    # Use nircmd via scheduled task for interactive session screenshot
    result = await launch_gui_app(
        TOOL_PATHS["nircmd"],
        arguments='savescreenshot "{}"'.format(output_path),
        task_name="MCP_Screenshot",
    )
    # Wait a moment for file to be written
    await asyncio.sleep(2)
    ps_check = """
if (Test-Path "{path}") {{
    $size = (Get-Item "{path}").Length
    Write-Output "Screenshot saved: {path} ($size bytes)"
}} else {{
    Write-Output "WARNING: Screenshot file not found at {path}"
}}
""".format(path=output_path)
    stdout, _, _ = await run_ps_async(ps_check, timeout=15)
    return _text(stdout)


# 9. die_analyze
async def _handle_die_analyze(args):
    file_path = args["file_path"]
    die_path = await resolve_tool_path("die", "diec")
    ps = '& "{}" -d "{}" 2>&1'.format(die_path, file_path.replace('"', '`"'))
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== DetectItEasy Analysis ===\nFile: {}\n\n{}".format(file_path, stdout)
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 10. floss_extract_strings
async def _handle_floss_extract_strings(args):
    file_path = args["file_path"]
    min_length = args.get("min_length", 4)
    floss_path = await resolve_tool_path("floss", "floss")
    ps = '& "{}" -n {} "{}" 2>&1'.format(floss_path, min_length, file_path.replace('"', '`"'))
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== FLOSS String Extraction ===\nFile: {}\nMin length: {}\n\n{}".format(
        file_path, min_length, stdout
    )
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 11. capa_analyze
async def _handle_capa_analyze(args):
    file_path = args["file_path"]
    verbose = args.get("verbose", False)
    capa_path = await resolve_tool_path("capa", "capa")
    v_flag = "-v" if verbose else ""
    ps = '& "{}" {} "{}" 2>&1'.format(capa_path, v_flag, file_path.replace('"', '`"'))
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== CAPA Capability Analysis ===\nFile: {}\n\n{}".format(file_path, stdout)
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 12. yara_scan
async def _handle_yara_scan(args):
    file_path = args["file_path"]
    rules_path = args.get("rules_path", "C:\\Tools\\yara\\rules\\")
    # Find YARA executable
    ps_find = """
$paths = @("C:\\Tools\\yara\\yara64.exe", "C:\\ProgramData\\chocolatey\\bin\\yara64.exe")
foreach ($p in $paths) { if (Test-Path $p) { Write-Output $p; exit 0 } }
$w = where.exe yara64 2>$null | Select-Object -First 1
if ($w) { Write-Output $w } else { Write-Output "NOT_FOUND" }
"""
    yara_stdout, _, _ = await run_ps_async(ps_find, timeout=15)
    yara_path = yara_stdout.strip().split("\n")[0].strip()
    if yara_path == "NOT_FOUND":
        return _text("YARA not found on FlareVM")

    ps = '& "{yara}" -r "{rules}" "{file}" 2>&1'.format(
        yara=yara_path,
        rules=rules_path.replace('"', '`"'),
        file=file_path.replace('"', '`"'),
    )
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== YARA Scan ===\nFile: {}\nRules: {}\n\n".format(file_path, rules_path)
    if stdout.strip():
        result += "Matches:\n" + stdout
    else:
        result += "No matches found."
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 13. strings_extract
async def _handle_strings_extract(args):
    file_path = args["file_path"]
    min_length = args.get("min_length", 6)
    encoding = args.get("encoding", "b")
    strings_path = await resolve_tool_path("strings", "strings")
    enc_flag = ""
    if encoding == "a":
        enc_flag = "-a"
    elif encoding == "u":
        enc_flag = "-u"
    else:
        enc_flag = ""  # default is both in Sysinternals strings

    ps = '& "{}" -accepteula -n {} {} "{}" 2>&1'.format(
        strings_path, min_length, enc_flag, file_path.replace('"', '`"')
    )
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    lines = stdout.split("\n") if stdout else []
    result = "=== Strings Extraction ===\nFile: {}\nTotal strings found: {}\n\n{}".format(
        file_path, len(lines), stdout
    )
    return _text(result)


# 14. entropy_analysis
async def _handle_entropy_analysis(args):
    file_path = args["file_path"]
    ps = """
$pyScript = @'
import pefile, math, sys
try:
    pe = pefile.PE(sys.argv[1])
    print("=== PE Section Entropy Analysis ===")
    print("File: " + sys.argv[1])
    print("")
    print("{:8s} {:>10s} {:>10s} {:>8s} {:>6s}".format("Section", "VirtSize", "RawSize", "Entropy", "Status"))
    print("-" * 50)
    total_entropy = 0
    for s in pe.sections:
        data = s.get_data()
        ent = 0
        if data:
            for i in range(256):
                p = data.count(bytes([i])) / len(data)
                if p > 0:
                    ent -= p * math.log2(p)
        name = s.Name.decode(errors='replace').strip('\\x00')
        status = "PACKED" if ent > 7.0 else ("HIGH" if ent > 6.5 else "OK")
        print("{:8s} {:10d} {:10d} {:8.2f} {:>6s}".format(name, s.Misc_VirtualSize, s.SizeOfRawData, ent, status))
        total_entropy += ent
    avg = total_entropy / len(pe.sections) if pe.sections else 0
    print("")
    print("Average entropy: {:.2f}".format(avg))
    if avg > 7.0:
        print("VERDICT: Likely PACKED (high average entropy)")
    elif avg > 6.0:
        print("VERDICT: Possibly packed or compressed sections")
    else:
        print("VERDICT: Likely NOT packed")
    # Import count
    imports = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports += len(entry.imports)
    print("\\nImport count: {} {}".format(imports, "(suspiciously low - may be packed)" if imports < 10 else "(normal)"))
except Exception as e:
    print("Error: " + str(e))
'@
$pyScript | Out-File -FilePath C:\\temp\\entropy_check.py -Encoding utf8
python C:\\temp\\entropy_check.py "{file_path}" 2>&1
""".format(file_path=file_path.replace('"', '`"'))
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    if code != 0:
        return _text("Entropy analysis failed: {} {}".format(stderr, stdout))
    return _text(stdout)


# 15. procmon_start
async def _handle_procmon_start(args):
    output_path = args.get("output_path", "C:\\temp\\procmon.pml")
    process_filter = args.get("process_filter", "")
    procmon_path = await resolve_tool_path("procmon", "Procmon")

    await run_ps_async('New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null', timeout=10)

    # Kill any existing procmon
    await run_ps_async('Stop-Process -Name Procmon* -Force -ErrorAction SilentlyContinue', timeout=15)
    await asyncio.sleep(1)

    if process_filter:
        # Create a ProcMon Configuration (PMC) file with filter
        pmc_script = """
# Create a simple Procmon filter config
$filterXml = @"
<procmon>
  <filters>
    <filter>
      <column>Process Name</column>
      <relation>is</relation>
      <action>include</action>
      <value>{filter}</value>
    </filter>
    <filter>
      <column>Process Name</column>
      <relation>is</relation>
      <action>exclude</action>
      <value>Procmon.exe</value>
    </filter>
    <filter>
      <column>Process Name</column>
      <relation>is</relation>
      <action>exclude</action>
      <value>Procmon64.exe</value>
    </filter>
    <filter>
      <column>Process Name</column>
      <relation>is</relation>
      <action>exclude</action>
      <value>System</value>
    </filter>
  </filters>
</procmon>
"@
$filterXml | Out-File -FilePath "C:\\temp\\procmon_filter.pmc" -Encoding UTF8
Start-Process -FilePath "{procmon}" -ArgumentList "/BackingFile `"{output}`" /LoadConfig `"C:\\temp\\procmon_filter.pmc`" /Minimized /Quiet /AcceptEula" -NoNewWindow
Write-Output "ProcMon started with filter: {filter}"
Write-Output "Output: {output}"
""".format(filter=process_filter, procmon=procmon_path, output=output_path)
    else:
        pmc_script = """
Start-Process -FilePath "{procmon}" -ArgumentList "/BackingFile `"{output}`" /Minimized /Quiet /AcceptEula" -NoNewWindow
Write-Output "ProcMon started (no filter)"
Write-Output "Output: {output}"
""".format(procmon=procmon_path, output=output_path)

    stdout, stderr, code = await run_ps_async(pmc_script, timeout=30)
    if code != 0:
        return _text("ProcMon start failed: {} {}".format(stderr, stdout))
    return _text(stdout)


# 16. procmon_stop
async def _handle_procmon_stop(args):
    pml_path = args.get("pml_path", "C:\\temp\\procmon.pml")
    csv_path = args.get("csv_path", "C:\\temp\\procmon.csv")
    procmon_path = await resolve_tool_path("procmon", "Procmon")

    ps = """
# Terminate ProcMon
& "{procmon}" /Terminate 2>&1 | Out-Null
Start-Sleep -Seconds 3

# Export PML to CSV
& "{procmon}" /OpenLog "{pml}" /SaveAs "{csv}" /AcceptEula 2>&1 | Out-Null
Start-Sleep -Seconds 5

# Parse CSV and generate summary
if (Test-Path "{csv}") {{
    $lines = Get-Content "{csv}" -TotalCount 10001
    $total = $lines.Count - 1
    $fileOps = ($lines | Select-String -Pattern "CreateFile|WriteFile|ReadFile|DeleteFile|SetDispositionInformationFile" | Measure-Object).Count
    $regOps = ($lines | Select-String -Pattern "RegOpenKey|RegSetValue|RegQueryValue|RegCreateKey|RegDeleteKey" | Measure-Object).Count
    $netOps = ($lines | Select-String -Pattern "TCP|UDP|Send|Recv" | Measure-Object).Count
    $procOps = ($lines | Select-String -Pattern "Process Create|Process Start|Thread Create|Load Image" | Measure-Object).Count

    Write-Output "=== ProcMon Summary ==="
    Write-Output "PML: {pml}"
    Write-Output "CSV: {csv}"
    Write-Output "Total events (up to 10000): $total"
    Write-Output ""
    Write-Output "--- Operation Breakdown ---"
    Write-Output "File operations:     $fileOps"
    Write-Output "Registry operations: $regOps"
    Write-Output "Network operations:  $netOps"
    Write-Output "Process operations:  $procOps"
    Write-Output ""

    # Show unique processes
    $procs = $lines | ForEach-Object {{ ($_ -split ',')[1] }} | Sort-Object -Unique | Where-Object {{ $_ -and $_ -ne '"Process Name"' }}
    Write-Output "--- Unique Processes ---"
    $procs | ForEach-Object {{ Write-Output "  $_" }}
}} else {{
    Write-Output "WARNING: CSV export file not found at {csv}"
    Write-Output "PML file exists: $(Test-Path '{pml}')"
}}
""".format(procmon=procmon_path, pml=pml_path, csv=csv_path)

    stdout, stderr, code = await run_ps_async(ps, timeout=120)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 17. procmon_export_csv
async def _handle_procmon_export_csv(args):
    pml_path = args["pml_path"]
    csv_path = args["csv_path"]
    procmon_path = await resolve_tool_path("procmon", "Procmon")
    ps = """
& "{procmon}" /OpenLog "{pml}" /SaveAs "{csv}" /AcceptEula 2>&1
Start-Sleep -Seconds 5
if (Test-Path "{csv}") {{
    $size = (Get-Item "{csv}").Length
    Write-Output "Exported successfully: {csv} ($size bytes)"
}} else {{
    Write-Output "Export failed - CSV not created"
}}
""".format(procmon=procmon_path, pml=pml_path, csv=csv_path)
    stdout, stderr, code = await run_ps_async(ps, timeout=120)
    return _text(stdout)


# 18. process_hacker_info
async def _handle_process_hacker_info(args):
    pid = args["pid"]
    ps = """
$pid = {pid}
$proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
if (-not $proc) {{ Write-Error "Process $pid not found"; exit 1 }}

$wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$pid"

Write-Output "=== Process Details: $($proc.ProcessName) (PID: $pid) ==="
Write-Output ""
Write-Output "--- Basic Info ---"
Write-Output "Name:         $($proc.ProcessName)"
Write-Output "PID:          $pid"
Write-Output "Parent PID:   $($wmi.ParentProcessId)"
Write-Output "Command Line: $($wmi.CommandLine)"
Write-Output "Path:         $($proc.Path)"
Write-Output "Start Time:   $($proc.StartTime)"
Write-Output "CPU Time:     $($proc.TotalProcessorTime)"
Write-Output "Working Set:  $([math]::Round($proc.WorkingSet64/1MB, 2)) MB"
Write-Output "Thread Count: $($proc.Threads.Count)"
Write-Output "Handle Count: $($proc.HandleCount)"
Write-Output ""

Write-Output "--- Loaded Modules ---"
$proc.Modules | Select-Object -First 30 | ForEach-Object {{
    Write-Output "  $($_.ModuleName) - $($_.FileName) ($([math]::Round($_.ModuleMemorySize/1KB))KB)"
}}
if ($proc.Modules.Count -gt 30) {{
    Write-Output "  ... and $($proc.Modules.Count - 30) more modules"
}}
Write-Output ""

Write-Output "--- Network Connections ---"
$connections = Get-NetTCPConnection -OwningProcess $pid -ErrorAction SilentlyContinue
if ($connections) {{
    $connections | ForEach-Object {{
        Write-Output "  $($_.State): $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"
    }}
}} else {{
    Write-Output "  No TCP connections"
}}

$udp = Get-NetUDPEndpoint -OwningProcess $pid -ErrorAction SilentlyContinue
if ($udp) {{
    $udp | ForEach-Object {{
        Write-Output "  UDP: $($_.LocalAddress):$($_.LocalPort)"
    }}
}}
""".format(pid=pid)
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        return _text("ERROR: {} {}".format(stderr, stdout))
    return _text(stdout)


# 19. monitor_network_realtime
async def _handle_monitor_network_realtime(args):
    duration = args.get("duration", 30)
    ps = """
$duration = {duration}
$allConnections = @()
$startTime = Get-Date

Write-Output "=== Network Monitoring ({duration}s) ==="
Write-Output "Start time: $startTime"
Write-Output ""

# Get baseline connections
$baseline = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
$baselineUdp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess

$newConnections = @()
$elapsed = 0

while ($elapsed -lt $duration) {{
    Start-Sleep -Seconds 1
    $elapsed++

    $current = Get-NetTCPConnection -ErrorAction SilentlyContinue
    foreach ($conn in $current) {{
        $key = "$($conn.LocalPort)-$($conn.RemoteAddress):$($conn.RemotePort)"
        $existing = $baseline | Where-Object {{
            $_.LocalPort -eq $conn.LocalPort -and $_.RemoteAddress -eq $conn.RemoteAddress -and $_.RemotePort -eq $conn.RemotePort
        }}
        if (-not $existing) {{
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $entry = "$($conn.State): $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [PID:$($conn.OwningProcess) $($proc.ProcessName)]"
            if ($entry -notin $newConnections) {{
                $newConnections += $entry
            }}
        }}
    }}
}}

Write-Output "--- New TCP Connections ---"
if ($newConnections.Count -gt 0) {{
    $newConnections | ForEach-Object {{ Write-Output "  $_" }}
}} else {{
    Write-Output "  No new connections detected"
}}
Write-Output ""

Write-Output "--- DNS Cache ---"
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 50
if ($dnsCache) {{
    $dnsCache | ForEach-Object {{
        Write-Output "  $($_.Entry) -> $($_.Data) (TTL: $($_.TimeToLive))"
    }}
}} else {{
    Write-Output "  DNS cache empty or unavailable"
}}
Write-Output ""

Write-Output "--- Current Listening Ports ---"
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {{
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Output "  :$($_.LocalPort) [PID:$($_.OwningProcess) $($proc.ProcessName)]"
}}

Write-Output ""
Write-Output "Monitoring completed at $(Get-Date)"
""".format(duration=duration)
    stdout, stderr, code = await run_ps_async(ps, timeout=duration + 60)
    return _text(stdout)


# 20. fakenet_start
async def _handle_fakenet_start(args):
    extra = args.get("extra_excluded_ports", "")
    excluded = [5985, 5986, 445, 139, 13337]
    if extra:
        for p in extra.split(","):
            p = p.strip()
            if p.isdigit():
                excluded.append(int(p))

    config = generate_fakenet_config(excluded)

    # Write config to FlareVM
    config_escaped = config.replace("'", "''")
    ps_write = """
New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null
@'
{config}
'@ | Out-File -FilePath "C:\\temp\\fakenet_mcp.ini" -Encoding ASCII
Write-Output "Config written to C:\\temp\\fakenet_mcp.ini"
""".format(config=config_escaped)
    stdout, stderr, code = await run_ps_async(ps_write, timeout=30)
    if code != 0:
        return _text("Failed to write FakeNet config: {} {}".format(stderr, stdout))

    # Launch FakeNet via scheduled task (needs interactive session for DNS interception)
    fakenet_path = await resolve_tool_path("fakenet", "fakenet")
    result = await launch_gui_app(
        fakenet_path,
        arguments='-c "C:\\temp\\fakenet_mcp.ini"',
        task_name="MCP_FakeNet",
    )
    await asyncio.sleep(3)

    return _text("=== FakeNet-NG Started ===\n"
                 "Config: C:\\temp\\fakenet_mcp.ini\n"
                 "Excluded ports: {}\n"
                 "Task: {}\n\n"
                 "FakeNet is now intercepting network traffic.\n"
                 "Use fakenet_stop to retrieve logs.".format(
                     ",".join(str(p) for p in excluded), result
                 ))


# 21. fakenet_stop
async def _handle_fakenet_stop(args):
    ps = """
# Kill FakeNet
Stop-Process -Name "fakenet*" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "python*" -Force -ErrorAction SilentlyContinue  # FakeNet runs via Python sometimes
Start-Sleep -Seconds 2

Write-Output "=== FakeNet-NG Stopped ==="
Write-Output ""

# Find FakeNet output directory
$logDirs = @(
    "C:\\Tools\\fakenet\\fakenet_logs",
    "$env:LOCALAPPDATA\\FakeNet-NG\\logs",
    "C:\\temp\\fakenet_logs"
)

$foundLogs = $false
foreach ($logDir in $logDirs) {
    $latest = Get-ChildItem -Path $logDir -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        $foundLogs = $true
        Write-Output "--- Log Directory: $($latest.FullName) ---"
        Write-Output ""

        # DNS queries
        $dnsLog = Get-ChildItem -Path $latest.FullName -Filter "*dns*" -ErrorAction SilentlyContinue
        if ($dnsLog) {
            Write-Output "--- DNS Queries ---"
            Get-Content $dnsLog.FullName -TotalCount 50 -ErrorAction SilentlyContinue
            Write-Output ""
        }

        # HTTP requests
        $httpLogs = Get-ChildItem -Path $latest.FullName -Filter "*http*" -ErrorAction SilentlyContinue
        if ($httpLogs) {
            Write-Output "--- HTTP Activity ---"
            foreach ($h in $httpLogs) {
                Write-Output "File: $($h.Name) ($($h.Length) bytes)"
                if ($h.Length -lt 10000) {
                    Get-Content $h.FullName -ErrorAction SilentlyContinue
                }
            }
            Write-Output ""
        }

        # All log files
        Write-Output "--- All Captured Files ---"
        Get-ChildItem -Path $latest.FullName -Recurse | ForEach-Object {
            Write-Output "  $($_.Name) - $($_.Length) bytes - $($_.LastWriteTime)"
        }

        # Main FakeNet log
        $mainLog = Join-Path $latest.FullName "fakenet.log"
        if (Test-Path $mainLog) {
            Write-Output ""
            Write-Output "--- FakeNet Main Log (last 100 lines) ---"
            Get-Content $mainLog -Tail 100 -ErrorAction SilentlyContinue
        }
        break
    }
}

if (-not $foundLogs) {
    Write-Output "No FakeNet log directory found. Checking running log files..."
    Get-ChildItem -Path "C:\\temp" -Filter "fakenet*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "  $($_.Name) - $($_.Length) bytes"
    }
}
"""
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 22. wireshark_capture
async def _handle_wireshark_capture(args):
    action = args["action"]
    output_path = args.get("output_path", "C:\\temp\\capture.pcap")
    interface = args.get("interface", "1")

    if action == "start":
        duration = args.get("duration", 60)
        # Find tshark
        ps_find = """
$paths = @("C:\\ProgramData\\chocolatey\\bin\\tshark.exe", "C:\\Program Files\\Wireshark\\tshark.exe")
foreach ($p in $paths) { if (Test-Path $p) { Write-Output $p; exit 0 } }
$w = where.exe tshark 2>$null | Select-Object -First 1
if ($w) { Write-Output $w } else { Write-Output "NOT_FOUND" }
"""
        tshark_stdout, _, _ = await run_ps_async(ps_find, timeout=15)
        tshark_path = tshark_stdout.strip().split("\n")[0].strip()
        if tshark_path == "NOT_FOUND":
            return _text("tshark not found on FlareVM")

        ps = 'Start-Process -FilePath "{}" -ArgumentList "-i {} -w `"{}`" -a duration:{}" -NoNewWindow -PassThru | Select-Object Id | Format-List'.format(
            tshark_path, interface, output_path, duration
        )
        stdout, stderr, code = await run_ps_async(ps, timeout=30)
        return _text("=== Packet Capture Started ===\n"
                     "Interface: {}\nDuration: {}s\nOutput: {}\n{}".format(
                         interface, duration, output_path, stdout
                     ))
    else:  # stop
        ps = """
Stop-Process -Name "tshark" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "dumpcap" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
if (Test-Path "{path}") {{
    $size = (Get-Item "{path}").Length
    Write-Output "=== Packet Capture Stopped ==="
    Write-Output "File: {path}"
    Write-Output "Size: $size bytes"
}} else {{
    Write-Output "Capture stopped but PCAP file not found at {path}"
}}
""".format(path=output_path)
        stdout, stderr, code = await run_ps_async(ps, timeout=30)
        return _text(stdout)


# 23. regshot_snapshot
async def _handle_regshot_snapshot(args):
    action = args["action"]

    if action == "first":
        ps = """
New-Item -ItemType Directory -Path "C:\\temp" -Force | Out-Null
Write-Output "=== Registry Snapshot: BEFORE ==="
Write-Output "Exporting HKLM..."
reg export HKLM "C:\\temp\\regshot_hklm_before.reg" /y 2>&1 | Out-Null
Write-Output "Exporting HKCU..."
reg export HKCU "C:\\temp\\regshot_hkcu_before.reg" /y 2>&1 | Out-Null

# Also snapshot scheduled tasks and services
Get-ScheduledTask | Select-Object TaskName, State | Out-File "C:\\temp\\tasks_before.txt" -Encoding UTF8
Get-Service | Select-Object Name, Status, StartType | Out-File "C:\\temp\\services_before.txt" -Encoding UTF8
Get-ChildItem "C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" -ErrorAction SilentlyContinue | Out-File "C:\\temp\\startup_before.txt" -Encoding UTF8

$hklmSize = (Get-Item "C:\\temp\\regshot_hklm_before.reg").Length
$hkcuSize = (Get-Item "C:\\temp\\regshot_hkcu_before.reg").Length
Write-Output "HKLM export: $([math]::Round($hklmSize/1MB, 2)) MB"
Write-Output "HKCU export: $([math]::Round($hkcuSize/1MB, 2)) MB"
Write-Output "Baseline snapshot complete."
""".format(user=FLAREVM_USER)
        stdout, stderr, code = await run_ps_async(ps, timeout=180)
        return _text(stdout)

    elif action == "second":
        ps = """
Write-Output "=== Registry Snapshot: AFTER ==="
Write-Output "Exporting HKLM..."
reg export HKLM "C:\\temp\\regshot_hklm_after.reg" /y 2>&1 | Out-Null
Write-Output "Exporting HKCU..."
reg export HKCU "C:\\temp\\regshot_hkcu_after.reg" /y 2>&1 | Out-Null

Get-ScheduledTask | Select-Object TaskName, State | Out-File "C:\\temp\\tasks_after.txt" -Encoding UTF8
Get-Service | Select-Object Name, Status, StartType | Out-File "C:\\temp\\services_after.txt" -Encoding UTF8
Get-ChildItem "C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" -ErrorAction SilentlyContinue | Out-File "C:\\temp\\startup_after.txt" -Encoding UTF8

$hklmSize = (Get-Item "C:\\temp\\regshot_hklm_after.reg").Length
$hkcuSize = (Get-Item "C:\\temp\\regshot_hkcu_after.reg").Length
Write-Output "HKLM export: $([math]::Round($hklmSize/1MB, 2)) MB"
Write-Output "HKCU export: $([math]::Round($hkcuSize/1MB, 2)) MB"
Write-Output "Post-execution snapshot complete."
""".format(user=FLAREVM_USER)
        stdout, stderr, code = await run_ps_async(ps, timeout=180)
        return _text(stdout)

    elif action == "compare":
        ps = r"""
Write-Output "=== Registry Comparison ==="
Write-Output ""

# Compare HKCU (smaller, faster, more interesting for malware)
Write-Output "--- HKCU Changes ---"
if ((Test-Path "C:\temp\regshot_hkcu_before.reg") -and (Test-Path "C:\temp\regshot_hkcu_after.reg")) {
    $before = Get-Content "C:\temp\regshot_hkcu_before.reg" -Encoding Unicode -ErrorAction SilentlyContinue
    $after = Get-Content "C:\temp\regshot_hkcu_after.reg" -Encoding Unicode -ErrorAction SilentlyContinue
    $diff = Compare-Object $before $after -ErrorAction SilentlyContinue | Select-Object -First 100
    if ($diff) {
        $added = ($diff | Where-Object { $_.SideIndicator -eq '=>' }).Count
        $removed = ($diff | Where-Object { $_.SideIndicator -eq '<=' }).Count
        Write-Output "Added/Modified lines: $added"
        Write-Output "Removed lines: $removed"
        Write-Output ""
        $diff | ForEach-Object {
            $indicator = if ($_.SideIndicator -eq '=>') { "[+ADD]" } else { "[-DEL]" }
            $line = $_.InputObject
            if ($line -match '^\[' -or $line -match '^"') {
                Write-Output "$indicator $line"
            }
        }
    } else {
        Write-Output "No HKCU changes detected."
    }
} else {
    Write-Output "Before/after HKCU snapshots not found."
}

Write-Output ""
Write-Output "--- Scheduled Task Changes ---"
if ((Test-Path "C:\temp\tasks_before.txt") -and (Test-Path "C:\temp\tasks_after.txt")) {
    $tbefore = Get-Content "C:\temp\tasks_before.txt"
    $tafter = Get-Content "C:\temp\tasks_after.txt"
    $tdiff = Compare-Object $tbefore $tafter -ErrorAction SilentlyContinue
    if ($tdiff) {
        $tdiff | ForEach-Object {
            $indicator = if ($_.SideIndicator -eq '=>') { "[+NEW]" } else { "[-DEL]" }
            Write-Output "$indicator $($_.InputObject)"
        }
    } else {
        Write-Output "No task changes."
    }
}

Write-Output ""
Write-Output "--- Service Changes ---"
if ((Test-Path "C:\temp\services_before.txt") -and (Test-Path "C:\temp\services_after.txt")) {
    $sbefore = Get-Content "C:\temp\services_before.txt"
    $safter = Get-Content "C:\temp\services_after.txt"
    $sdiff = Compare-Object $sbefore $safter -ErrorAction SilentlyContinue
    if ($sdiff) {
        $sdiff | ForEach-Object {
            $indicator = if ($_.SideIndicator -eq '=>') { "[+NEW]" } else { "[-DEL]" }
            Write-Output "$indicator $($_.InputObject)"
        }
    } else {
        Write-Output "No service changes."
    }
}

Write-Output ""
Write-Output "--- Startup Folder Changes ---"
if ((Test-Path "C:\temp\startup_before.txt") -and (Test-Path "C:\temp\startup_after.txt")) {
    $supbefore = Get-Content "C:\temp\startup_before.txt"
    $supafter = Get-Content "C:\temp\startup_after.txt"
    $supdiff = Compare-Object $supbefore $supafter -ErrorAction SilentlyContinue
    if ($supdiff) {
        $supdiff | ForEach-Object {
            $indicator = if ($_.SideIndicator -eq '=>') { "[+NEW]" } else { "[-DEL]" }
            Write-Output "$indicator $($_.InputObject)"
        }
    } else {
        Write-Output "No startup folder changes."
    }
}

Write-Output ""
Write-Output "--- HKLM Run Keys (current) ---"
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($items) {
        Write-Output "  $key :"
        $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Output "    $($_.Name) = $($_.Value)"
        }
    }
}

Write-Output ""
Write-Output "Comparison complete."
"""
        stdout, stderr, code = await run_ps_async(ps, timeout=180)
        result = stdout
        if stderr:
            result += "\n--- Warnings ---\n" + stderr
        return _text(result)

    return _text("Unknown regshot action: {}. Use 'first', 'second', or 'compare'.".format(action))


# 24. x64dbg_load
async def _handle_x64dbg_load(args):
    file_path = args["file_path"]
    arguments = args.get("arguments", "")
    x64dbg_path = await resolve_tool_path("x64dbg", "x64dbg")
    dbg_args = '"{}"'.format(file_path)
    if arguments:
        dbg_args += " " + arguments
    result = await launch_gui_app(
        x64dbg_path,
        arguments=dbg_args,
        task_name="MCP_x64dbg",
    )
    return _text("=== x64dbg Launched ===\nBinary: {}\nArguments: {}\n{}".format(
        file_path, arguments, result
    ))


# 25. x64dbg_run_script
async def _handle_x64dbg_run_script(args):
    script = args["script"]
    script_path = args.get("script_path", "C:\\temp\\x64dbg_script.txt")
    # Write script to file
    script_escaped = script.replace("'", "''")
    ps = """
@'
{script}
'@ | Out-File -FilePath "{path}" -Encoding ASCII
Write-Output "Script saved to {path}"
""".format(script=script_escaped, path=script_path)
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        return _text("Failed to write script: {} {}".format(stderr, stdout))

    # Execute script via x64dbg command line
    ps_run = """
# x64dbg supports script execution via command line
# The script file will be picked up by the running x64dbg instance
$x64dbg = Get-Process -Name "x64dbg" -ErrorAction SilentlyContinue
if (-not $x64dbg) {{
    $x64dbg = Get-Process -Name "x96dbg" -ErrorAction SilentlyContinue
}}
if ($x64dbg) {{
    Write-Output "x64dbg is running (PID: $($x64dbg.Id))"
    Write-Output "Script saved to: {path}"
    Write-Output "Load the script in x64dbg: scriptload `"{path}`""
}} else {{
    Write-Output "WARNING: x64dbg does not appear to be running."
    Write-Output "Script saved to: {path}"
    Write-Output "Start x64dbg first, then load the script manually."
}}
""".format(path=script_path)
    stdout2, _, _ = await run_ps_async(ps_run, timeout=15)
    return _text(stdout + "\n" + stdout2)


# 26. windbg_analyze_dump
async def _handle_windbg_analyze_dump(args):
    dump_file = args["dump_file"]
    commands = args.get("commands", "!analyze -v")
    # Find cdb.exe
    ps_find = """
$paths = @(
    "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe",
    "C:\\Tools\\WinDbg\\cdb.exe",
    "C:\\Program Files\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe"
)
foreach ($p in $paths) { if (Test-Path $p) { Write-Output $p; exit 0 } }
$w = where.exe cdb 2>$null | Select-Object -First 1
if ($w) { Write-Output $w } else { Write-Output "NOT_FOUND" }
"""
    cdb_stdout, _, _ = await run_ps_async(ps_find, timeout=15)
    cdb_path = cdb_stdout.strip().split("\n")[0].strip()
    if cdb_path == "NOT_FOUND":
        return _text("cdb.exe (WinDbg command-line) not found on FlareVM")

    # Build command string (semicolon-separated, ending with q to quit)
    cmd_str = commands.strip()
    if not cmd_str.endswith(";q") and not cmd_str.endswith("; q"):
        cmd_str += "; q"

    ps = '& "{}" -z "{}" -c "{}" 2>&1'.format(
        cdb_path, dump_file.replace('"', '`"'), cmd_str.replace('"', '`"')
    )
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = "=== WinDbg Analysis ===\nDump: {}\nCommands: {}\n\n{}".format(
        dump_file, commands, stdout
    )
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 27. frida_list_processes
async def _handle_frida_list_processes(args):
    ps = 'frida-ps 2>&1'
    stdout, stderr, code = await run_ps_async(ps, timeout=30)
    if code != 0:
        return _text("Frida error: {} {}".format(stderr, stdout))
    return _text("=== Frida Process List ===\n" + stdout)


# 28. frida_spawn_and_attach
async def _handle_frida_spawn_and_attach(args):
    executable = args["executable"]
    script = args["script"]
    timeout = args.get("timeout", 30)
    # Write script to temp file
    script_escaped = script.replace("'", "''")
    ps = """
$scriptContent = @'
{script}
'@
$scriptPath = "C:\\temp\\frida_spawn_script.js"
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
Write-Output "Script saved to $scriptPath"
$output = & frida -f "{exe}" -l $scriptPath --no-pause --timeout {timeout} 2>&1
Write-Output $output
""".format(script=script_escaped, exe=executable.replace('"', '`"'), timeout=timeout)
    stdout, stderr, code = await run_ps_async(ps, timeout=timeout + 60)
    result = "=== Frida Spawn & Attach ===\nExecutable: {}\n\n{}".format(executable, stdout)
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    return _text(result)


# 29. frida_attach_pid
async def _handle_frida_attach_pid(args):
    pid = args["pid"]
    script = args["script"]
    timeout = args.get("timeout", 30)
    script_escaped = script.replace("'", "''")
    ps = """
$scriptContent = @'
{script}
'@
$scriptPath = "C:\\temp\\frida_attach_script.js"
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
Write-Output "Script saved to $scriptPath"
$output = & frida -p {pid} -l $scriptPath --no-pause --timeout {timeout} 2>&1
Write-Output $output
""".format(script=script_escaped, pid=pid, timeout=timeout)
    stdout, stderr, code = await run_ps_async(ps, timeout=timeout + 60)
    result = "=== Frida Attach (PID: {}) ===\n\n{}".format(pid, stdout)
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    return _text(result)


# 30. frida_run_script
async def _handle_frida_run_script(args):
    target = args["target"]
    script = args["script"]
    timeout = args.get("timeout", 30)
    script_escaped = script.replace("'", "''")
    # Determine if target is PID (numeric) or process name
    try:
        pid = int(target)
        target_flag = "-p {}".format(pid)
    except ValueError:
        target_flag = '-n "{}"'.format(target)

    ps = """
$scriptContent = @'
{script}
'@
$scriptPath = "C:\\temp\\frida_run_script.js"
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
$output = & frida {target_flag} -l $scriptPath --no-pause --timeout {timeout} 2>&1
Write-Output $output
""".format(script=script_escaped, target_flag=target_flag, timeout=timeout)
    stdout, stderr, code = await run_ps_async(ps, timeout=timeout + 60)
    result = "=== Frida Script Execution ===\nTarget: {}\n\n{}".format(target, stdout)
    if stderr:
        result += "\n--- STDERR ---\n" + stderr
    return _text(result)


# 31. pe_sieve_scan
async def _handle_pe_sieve_scan(args):
    pid = args["pid"]
    output_dir = args.get("output_dir", "C:\\temp\\pe_sieve_output")
    pe_sieve_path = await resolve_tool_path("pe_sieve", "pe-sieve64")
    ps = """
New-Item -ItemType Directory -Path "{output}" -Force | Out-Null
$result = & "{tool}" /pid {pid} /dir "{output}" /shellc /iat 3 /data 3 2>&1
Write-Output "=== PE-sieve Scan (PID: {pid}) ==="
Write-Output ""
Write-Output $result
Write-Output ""
Write-Output "--- Output Files ---"
Get-ChildItem -Path "{output}" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {{
    Write-Output "  $($_.Name) - $($_.Length) bytes"
}}
""".format(tool=pe_sieve_path, pid=pid, output=output_dir)
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 32. hollows_hunter_scan
async def _handle_hollows_hunter_scan(args):
    output_dir = args.get("output_dir", "C:\\temp\\hollows_output")
    hh_path = await resolve_tool_path("hollows_hunter", "hollows_hunter64")
    ps = """
New-Item -ItemType Directory -Path "{output}" -Force | Out-Null
$result = & "{tool}" /dir "{output}" /shellc /iat 3 2>&1
Write-Output "=== Hollows Hunter Scan (All Processes) ==="
Write-Output ""
Write-Output $result
Write-Output ""
Write-Output "--- Output Files ---"
Get-ChildItem -Path "{output}" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {{
    Write-Output "  $($_.Name) - $($_.Length) bytes"
}}
""".format(tool=hh_path, output=output_dir)
    stdout, stderr, code = await run_ps_async(ps, timeout=120)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 33. upx_unpack
async def _handle_upx_unpack(args):
    packed_file = args["packed_file"]
    output_file = args["output_file"]
    upx_path = await resolve_tool_path("upx", "upx")
    ps = '& "{}" -d "{}" -o "{}" 2>&1'.format(
        upx_path, packed_file.replace('"', '`"'), output_file.replace('"', '`"')
    )
    stdout, stderr, code = await run_ps_async(ps, timeout=60)
    result = "=== UPX Unpack ===\nInput: {}\nOutput: {}\n\n{}".format(
        packed_file, output_file, stdout
    )
    if code == 0:
        # Verify output
        ps_check = """
if (Test-Path "{out}") {{
    $size = (Get-Item "{out}").Length
    Write-Output "Unpacked file size: $size bytes"
    $hash = (Get-FileHash -Path "{out}" -Algorithm SHA256).Hash
    Write-Output "SHA256: $hash"
}} else {{
    Write-Output "Output file not created"
}}
""".format(out=output_file)
        check_stdout, _, _ = await run_ps_async(ps_check, timeout=15)
        result += "\n" + check_stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 34. unpack_detect_and_try
async def _handle_unpack_detect_and_try(args):
    file_path = args["file_path"]
    report_parts = ["=== Automated Unpack: Detect & Try ===", "File: {}".format(file_path), ""]

    # Step 1: DIE analysis
    try:
        die_result = await _handle_die_analyze({"file_path": file_path})
        die_text = die_result[0].text if die_result else "DIE analysis failed"
        report_parts.append("--- Step 1: Packer Detection (DIE) ---")
        report_parts.append(die_text)
        report_parts.append("")
    except Exception as e:
        die_text = str(e)
        report_parts.append("DIE failed: " + die_text)

    # Step 2: Entropy analysis
    try:
        ent_result = await _handle_entropy_analysis({"file_path": file_path})
        ent_text = ent_result[0].text if ent_result else "Entropy analysis failed"
        report_parts.append("--- Step 2: Entropy Analysis ---")
        report_parts.append(ent_text)
        report_parts.append("")
    except Exception as e:
        ent_text = str(e)
        report_parts.append("Entropy analysis failed: " + ent_text)

    # Step 3: Try UPX if detected
    die_lower = die_text.lower()
    if "upx" in die_lower:
        report_parts.append("--- Step 3: UPX Detected - Attempting Unpack ---")
        basename = ntpath.splitext(ntpath.basename(file_path))[0]
        output_file = "C:\\temp\\{}_unpacked.exe".format(basename)
        try:
            upx_result = await _handle_upx_unpack({
                "packed_file": file_path,
                "output_file": output_file,
            })
            report_parts.append(upx_result[0].text if upx_result else "UPX unpack failed")
        except Exception as e:
            report_parts.append("UPX unpack failed: " + str(e))
        report_parts.append("")

        # Run FLOSS on unpacked binary
        if await _file_exists(output_file):
            report_parts.append("--- Step 4: FLOSS on Unpacked Binary ---")
            try:
                floss_result = await _handle_floss_extract_strings({
                    "file_path": output_file, "min_length": 6
                })
                report_parts.append(floss_result[0].text if floss_result else "FLOSS failed")
            except Exception as e:
                report_parts.append("FLOSS failed: " + str(e))
    elif "aspack" in die_lower or "mpress" in die_lower or "packed" in die_lower or "PACKED" in ent_text:
        report_parts.append("--- Step 3: Packer Detected - Attempting Runtime Unpack ---")
        # Run the binary briefly, then pe-sieve
        ps_run = """
$proc = Start-Process -FilePath "{file}" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 5
Write-Output "Started process PID: $($proc.Id)"
$proc.Id
""".format(file=file_path.replace('"', '`"'))
        try:
            stdout, _, code = await run_ps_async(ps_run, timeout=30)
            lines = stdout.strip().split("\n")
            pid_str = lines[-1].strip()
            if pid_str.isdigit():
                pid = int(pid_str)
                report_parts.append("Process started with PID: {}".format(pid))

                # PE-sieve scan
                try:
                    sieve_result = await _handle_pe_sieve_scan({
                        "pid": pid,
                        "output_dir": "C:\\temp\\unpack_pe_sieve",
                    })
                    report_parts.append(sieve_result[0].text if sieve_result else "pe-sieve failed")
                except Exception as e:
                    report_parts.append("pe-sieve failed: " + str(e))

                # Kill the process
                await run_ps_async("Stop-Process -Id {} -Force -ErrorAction SilentlyContinue".format(pid), timeout=10)

                # Check for dumped modules
                ps_check = """
$dumps = Get-ChildItem -Path "C:\\temp\\unpack_pe_sieve" -Filter "*.dll","*.exe" -ErrorAction SilentlyContinue
if ($dumps) {
    Write-Output "Dumped modules:"
    $dumps | ForEach-Object { Write-Output "  $($_.Name) - $($_.Length) bytes" }
} else {
    Write-Output "No modules dumped by pe-sieve"
}
"""
                check_stdout, _, _ = await run_ps_async(ps_check, timeout=15)
                report_parts.append(check_stdout)
            else:
                report_parts.append("Failed to start process: " + stdout)
        except Exception as e:
            report_parts.append("Runtime unpack failed: " + str(e))
    else:
        report_parts.append("--- Step 3: No Known Packer Detected ---")
        report_parts.append("Binary does not appear to be packed with a known packer.")
        report_parts.append("Running FLOSS on original binary for string recovery.")
        try:
            floss_result = await _handle_floss_extract_strings({
                "file_path": file_path, "min_length": 6
            })
            report_parts.append(floss_result[0].text if floss_result else "FLOSS failed")
        except Exception as e:
            report_parts.append("FLOSS failed: " + str(e))

    return _text("\n".join(report_parts))


async def _file_exists(path):
    """Check if a file exists on FlareVM."""
    stdout, _, code = await run_ps_async('Test-Path "{}"'.format(path.replace('"', '`"')), timeout=10)
    return stdout.strip().lower() == "true"


# 35. dnspy_decompile
async def _handle_dnspy_decompile(args):
    assembly_path = args["assembly_path"]
    output_dir = args.get("output_dir", "C:\\temp\\decompiled")
    dnspy_path = await resolve_tool_path("dnspy", "dnSpy.Console")
    ps = """
New-Item -ItemType Directory -Path "{output}" -Force | Out-Null
$result = & "{tool}" -o "{output}" "{assembly}" 2>&1
Write-Output "=== dnSpy Decompilation ==="
Write-Output "Assembly: {assembly}"
Write-Output "Output: {output}"
Write-Output ""
Write-Output $result
Write-Output ""
Write-Output "--- Decompiled Files ---"
Get-ChildItem -Path "{output}" -Recurse -File | Select-Object -First 50 | ForEach-Object {{
    Write-Output "  $($_.FullName.Replace('{output}\\', '')) ($($_.Length) bytes)"
}}
$totalFiles = (Get-ChildItem -Path "{output}" -Recurse -File | Measure-Object).Count
Write-Output ""
Write-Output "Total decompiled files: $totalFiles"
""".format(tool=dnspy_path, assembly=assembly_path.replace('"', '`"'), output=output_dir)
    stdout, stderr, code = await run_ps_async(ps, timeout=180)
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 36. ida_launch_and_wait
async def _handle_ida_launch_and_wait(args):
    binary_path = args["binary_path"]
    ida_path = args.get("ida_path", "C:\\Tools\\IDA Pro\\ida64.exe")

    result = await launch_gui_app(
        ida_path,
        arguments='"{}"'.format(binary_path),
        task_name="MCP_IDA",
        wait_port=IDA_MCP_PORT,
        wait_timeout=60,
    )

    # Try to get initial metadata
    metadata = ""
    try:
        meta_result = await ida_rpc_call("get_metadata")
        if "result" in meta_result:
            metadata = "\n--- IDA Metadata ---\n" + json.dumps(meta_result["result"], indent=2)
    except Exception as e:
        metadata = "\nNote: Could not fetch metadata yet: " + str(e)

    return _text("=== IDA Pro Launched ===\nBinary: {}\n{}\n{}".format(
        binary_path, result, metadata
    ))


# 37. windbg_launch
async def _handle_windbg_launch(args):
    dump_file = args["dump_file"]
    windbg_path = args.get("windbg_path", "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe")

    # Check if windbg exists at the specified path, try alternatives
    ps_find = """
$paths = @(
    "{windbg}",
    "C:\\Tools\\WinDbg\\windbg.exe",
    "C:\\Program Files\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe"
)
foreach ($p in $paths) {{ if (Test-Path $p) {{ Write-Output $p; exit 0 }} }}
$w = where.exe windbg 2>$null | Select-Object -First 1
if ($w) {{ Write-Output $w }} else {{ Write-Output "NOT_FOUND" }}
""".format(windbg=windbg_path)
    stdout, _, _ = await run_ps_async(ps_find, timeout=15)
    actual_path = stdout.strip().split("\n")[0].strip()
    if actual_path == "NOT_FOUND":
        return _text("WinDbg not found on FlareVM")

    result = await launch_gui_app(
        actual_path,
        arguments='-z "{}"'.format(dump_file),
        task_name="MCP_WinDbg",
    )
    return _text("=== WinDbg Launched ===\nDump: {}\n{}".format(dump_file, result))


# 38. ida_get_metadata
async def _handle_ida_get_metadata(args):
    result = await ida_rpc_call("get_metadata")
    if "result" in result:
        return _text("=== IDA Pro Metadata ===\n" + json.dumps(result["result"], indent=2))
    return _text("IDA RPC response: " + json.dumps(result, indent=2))


# 39. ida_list_functions
async def _handle_ida_list_functions(args):
    params = {}
    if args.get("filter"):
        params["filter"] = args["filter"]
    if args.get("count"):
        params["count"] = args["count"]
    result = await ida_rpc_call("list_functions", params if params else None)
    if "result" in result:
        funcs = result["result"]
        if isinstance(funcs, list):
            lines = ["=== IDA Functions ({} found) ===".format(len(funcs)), ""]
            for f in funcs:
                if isinstance(f, dict):
                    lines.append("  {}: {} (size: {})".format(
                        f.get("address", "?"), f.get("name", "?"), f.get("size", "?")
                    ))
                else:
                    lines.append("  " + str(f))
            return _text("\n".join(lines))
        return _text(json.dumps(funcs, indent=2))
    return _text("IDA RPC response: " + json.dumps(result, indent=2))


# 40. ida_decompile_function
async def _handle_ida_decompile_function(args):
    result = await ida_rpc_call("decompile_function", {"function_name": args["function_name"]})
    if "result" in result:
        return _text("=== Decompiled: {} ===\n\n{}".format(
            args["function_name"], result["result"]
        ))
    return _text("IDA RPC response: " + json.dumps(result, indent=2))


# 41. ida_disassemble_function
async def _handle_ida_disassemble_function(args):
    result = await ida_rpc_call("disassemble_function", {"function_name": args["function_name"]})
    if "result" in result:
        return _text("=== Disassembly: {} ===\n\n{}".format(
            args["function_name"], result["result"]
        ))
    return _text("IDA RPC response: " + json.dumps(result, indent=2))


# 42. ida_list_strings
async def _handle_ida_list_strings(args):
    params = {}
    if args.get("filter"):
        params["filter"] = args["filter"]
    if args.get("count"):
        params["count"] = args["count"]
    result = await ida_rpc_call("list_strings", params if params else None)
    if "result" in result:
        strings = result["result"]
        if isinstance(strings, list):
            lines = ["=== IDA Strings ({} found) ===".format(len(strings)), ""]
            for s in strings:
                if isinstance(s, dict):
                    lines.append("  {}: {}".format(s.get("address", "?"), s.get("value", "?")))
                else:
                    lines.append("  " + str(s))
            return _text("\n".join(lines))
        return _text(json.dumps(strings, indent=2))
    return _text("IDA RPC response: " + json.dumps(result, indent=2))


# 43. ida_set_comment
async def _handle_ida_set_comment(args):
    result = await ida_rpc_call("set_comment", {
        "address": args["address"],
        "comment": args["comment"],
    })
    if "result" in result:
        return _text("Comment set at {}: {}".format(args["address"], args["comment"]))
    return _text("IDA RPC response: " + json.dumps(result, indent=2))


# 44. ida_rename_function
async def _handle_ida_rename_function(args):
    result = await ida_rpc_call("rename_function", {
        "old_name": args["old_name"],
        "new_name": args["new_name"],
    })
    if "result" in result:
        return _text("Function renamed: {} -> {}".format(args["old_name"], args["new_name"]))
    return _text("IDA RPC response: " + json.dumps(result, indent=2))


# 45. triage_full
async def _handle_triage_full(args):
    file_path = args["file_path"]
    report = ["=" * 60, "FULL STATIC TRIAGE REPORT", "=" * 60, "File: {}".format(file_path), ""]

    # 1. Hashes
    report.append("--- 1. File Hashes ---")
    try:
        hash_result = await _handle_get_file_hash({"file_path": file_path})
        report.append(hash_result[0].text if hash_result else "Hash calculation failed")
    except Exception as e:
        report.append("Hash error: " + str(e))
    report.append("")

    # 2. DIE
    report.append("--- 2. Packer/Compiler Detection (DIE) ---")
    try:
        die_result = await _handle_die_analyze({"file_path": file_path})
        report.append(die_result[0].text if die_result else "DIE failed")
    except Exception as e:
        report.append("DIE error: " + str(e))
    report.append("")

    # 3. Entropy
    report.append("--- 3. Section Entropy ---")
    try:
        ent_result = await _handle_entropy_analysis({"file_path": file_path})
        report.append(ent_result[0].text if ent_result else "Entropy analysis failed")
    except Exception as e:
        report.append("Entropy error: " + str(e))
    report.append("")

    # 4. CAPA
    report.append("--- 4. Capability Detection (CAPA) ---")
    try:
        capa_result = await _handle_capa_analyze({"file_path": file_path})
        report.append(capa_result[0].text if capa_result else "CAPA failed")
    except Exception as e:
        report.append("CAPA error: " + str(e))
    report.append("")

    # 5. FLOSS
    report.append("--- 5. String Recovery (FLOSS) ---")
    try:
        floss_result = await _handle_floss_extract_strings({
            "file_path": file_path, "min_length": 6
        })
        report.append(floss_result[0].text if floss_result else "FLOSS failed")
    except Exception as e:
        report.append("FLOSS error: " + str(e))
    report.append("")

    # 6. YARA
    report.append("--- 6. YARA Rule Matching ---")
    try:
        yara_result = await _handle_yara_scan({"file_path": file_path})
        report.append(yara_result[0].text if yara_result else "YARA failed")
    except Exception as e:
        report.append("YARA error: " + str(e))
    report.append("")

    report.append("=" * 60)
    report.append("END OF TRIAGE REPORT")
    report.append("=" * 60)

    return _text("\n".join(report))


# 46. behavioral_full
async def _handle_behavioral_full(args):
    executable = args["executable"]
    arguments = args.get("arguments", "")
    duration = args.get("duration", 30)

    report = ["=" * 60, "FULL BEHAVIORAL ANALYSIS REPORT", "=" * 60,
              "Executable: {}".format(executable),
              "Arguments: {}".format(arguments),
              "Duration: {}s".format(duration), ""]

    # 1. Registry baseline
    report.append("--- Step 1: Registry Baseline ---")
    try:
        reg1 = await _handle_regshot_snapshot({"action": "first"})
        report.append(reg1[0].text if reg1 else "Failed")
    except Exception as e:
        report.append("Regshot baseline error: " + str(e))
    report.append("")

    # 2. Start ProcMon
    report.append("--- Step 2: Start ProcMon ---")
    try:
        pm_start = await _handle_procmon_start({
            "output_path": "C:\\temp\\behavioral_procmon.pml",
            "process_filter": ntpath.basename(executable),
        })
        report.append(pm_start[0].text if pm_start else "Failed")
    except Exception as e:
        report.append("ProcMon start error: " + str(e))
    report.append("")

    # 3. Start FakeNet
    report.append("--- Step 3: Start FakeNet ---")
    try:
        fn_start = await _handle_fakenet_start({})
        report.append(fn_start[0].text if fn_start else "Failed")
    except Exception as e:
        report.append("FakeNet start error: " + str(e))
    report.append("")

    # 4. Start network monitoring (in parallel with execution)
    report.append("--- Step 4: Execute Malware ---")
    exec_cmd = '"{}"'.format(executable)
    if arguments:
        exec_cmd += " " + arguments
    ps_exec = """
$proc = Start-Process -FilePath "{exe}" -ArgumentList '{args}' -PassThru -WindowStyle Hidden
Write-Output "Started: $($proc.ProcessName) (PID: $($proc.Id))"
$proc.Id
""".format(exe=executable.replace('"', '`"'), args=arguments.replace("'", "''"))
    try:
        stdout, stderr, code = await run_ps_async(ps_exec, timeout=30)
        report.append(stdout)
        mal_pid = None
        lines = stdout.strip().split("\n")
        pid_str = lines[-1].strip()
        if pid_str.isdigit():
            mal_pid = int(pid_str)
    except Exception as e:
        report.append("Execution error: " + str(e))
        mal_pid = None
    report.append("")

    # 5. Wait for duration
    report.append("--- Step 5: Monitoring for {}s ---".format(duration))
    await asyncio.sleep(duration)
    report.append("Monitoring period complete.")
    report.append("")

    # 6. Kill malware process
    if mal_pid:
        await run_ps_async("Stop-Process -Id {} -Force -ErrorAction SilentlyContinue".format(mal_pid), timeout=10)
        report.append("Malware process (PID: {}) terminated.".format(mal_pid))
    report.append("")

    # 7. Stop FakeNet and collect logs
    report.append("--- Step 6: FakeNet Results ---")
    try:
        fn_stop = await _handle_fakenet_stop({})
        report.append(fn_stop[0].text if fn_stop else "Failed")
    except Exception as e:
        report.append("FakeNet stop error: " + str(e))
    report.append("")

    # 8. Stop ProcMon and export
    report.append("--- Step 7: ProcMon Results ---")
    try:
        pm_stop = await _handle_procmon_stop({
            "pml_path": "C:\\temp\\behavioral_procmon.pml",
            "csv_path": "C:\\temp\\behavioral_procmon.csv",
        })
        report.append(pm_stop[0].text if pm_stop else "Failed")
    except Exception as e:
        report.append("ProcMon stop error: " + str(e))
    report.append("")

    # 9. Registry after + compare
    report.append("--- Step 8: Registry Changes ---")
    try:
        reg2 = await _handle_regshot_snapshot({"action": "second"})
        report.append(reg2[0].text if reg2 else "Failed")
        report.append("")
        reg_cmp = await _handle_regshot_snapshot({"action": "compare"})
        report.append(reg_cmp[0].text if reg_cmp else "Failed")
    except Exception as e:
        report.append("Regshot compare error: " + str(e))
    report.append("")

    # 10. Network state
    report.append("--- Step 9: Post-Execution Network State ---")
    ps_net = """
Write-Output "--- Active Connections ---"
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Output "  $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) [$($proc.ProcessName)]"
}
Write-Output ""
Write-Output "--- DNS Cache ---"
Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {
    Write-Output "  $($_.Entry) -> $($_.Data)"
}
"""
    try:
        net_stdout, _, _ = await run_ps_async(ps_net, timeout=30)
        report.append(net_stdout)
    except Exception as e:
        report.append("Network state error: " + str(e))

    report.append("")
    report.append("=" * 60)
    report.append("END OF BEHAVIORAL ANALYSIS REPORT")
    report.append("=" * 60)

    return _text("\n".join(report))


# 47. persistence_audit
async def _handle_persistence_audit(args):
    ps = r"""
Write-Output "============================================================"
Write-Output "PERSISTENCE MECHANISM AUDIT"
Write-Output "============================================================"
Write-Output ""

# 1. Autoruns (if available)
Write-Output "--- 1. Autoruns Analysis ---"
$autorunsc = "C:\Tools\sysinternals\autorunsc.exe"
if (Test-Path $autorunsc) {
    $ar = & $autorunsc -accepteula -a * -c -nobanner 2>&1 | Select-Object -First 100
    $ar | ForEach-Object { Write-Output "  $_" }
} else {
    Write-Output "  autorunsc.exe not found, using manual checks"
}
Write-Output ""

# 2. Registry Run Keys
Write-Output "--- 2. Registry Run Keys ---"
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)
foreach ($key in $runKeys) {
    $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($items) {
        Write-Output "  $key :"
        $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Output "    $($_.Name) = $($_.Value)"
        }
    }
}
Write-Output ""

# 3. Scheduled Tasks
Write-Output "--- 3. Scheduled Tasks (non-Microsoft) ---"
Get-ScheduledTask | Where-Object {
    $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled'
} | Select-Object -First 30 | ForEach-Object {
    $action = ($_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue)
    Write-Output "  Task: $($_.TaskName)"
    Write-Output "  Path: $($_.TaskPath)"
    Write-Output "  State: $($_.State)"
    $actions = $_.Actions
    foreach ($a in $actions) {
        Write-Output "  Action: $($a.Execute) $($a.Arguments)"
    }
    Write-Output ""
}
Write-Output ""

# 4. Services
Write-Output "--- 4. Services (non-standard) ---"
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notmatch 'C:\\Windows\\system32\\svchost' -and $_.PathName -notmatch 'C:\\Windows\\servicing'
} | Select-Object -First 30 | ForEach-Object {
    Write-Output "  $($_.Name) [$($_.State)] - $($_.PathName)"
}
Write-Output ""

# 5. WMI Event Subscriptions
Write-Output "--- 5. WMI Event Subscriptions ---"
$consumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
$filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
$bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
if ($consumers) {
    Write-Output "  Event Consumers:"
    $consumers | ForEach-Object { Write-Output "    $($_.Name): $($_.CommandLineTemplate)" }
}
if ($filters) {
    Write-Output "  Event Filters:"
    $filters | ForEach-Object { Write-Output "    $($_.Name): $($_.Query)" }
}
if ($bindings) {
    Write-Output "  Bindings:"
    $bindings | ForEach-Object { Write-Output "    Filter=$($_.Filter) -> Consumer=$($_.Consumer)" }
}
if (-not $consumers -and -not $filters) {
    Write-Output "  No WMI event subscriptions found."
}
Write-Output ""

# 6. Startup Folders
Write-Output "--- 6. Startup Folders ---"
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
foreach ($sp in $startupPaths) {
    Write-Output "  $sp :"
    $items = Get-ChildItem -Path $sp -ErrorAction SilentlyContinue
    if ($items) {
        $items | ForEach-Object { Write-Output "    $($_.Name) ($($_.Length) bytes)" }
    } else {
        Write-Output "    (empty)"
    }
}
Write-Output ""

# 7. DLL search order hijacking indicators
Write-Output "--- 7. Suspicious DLLs in PATH ---"
$env:PATH -split ';' | Where-Object { $_ -and $_ -notmatch 'Windows|System32|Program Files' } | ForEach-Object {
    $dlls = Get-ChildItem -Path $_ -Filter "*.dll" -ErrorAction SilentlyContinue | Select-Object -First 5
    if ($dlls) {
        Write-Output "  $_ :"
        $dlls | ForEach-Object { Write-Output "    $($_.Name)" }
    }
}
Write-Output ""
Write-Output "============================================================"
Write-Output "END OF PERSISTENCE AUDIT"
Write-Output "============================================================"
"""
    # Script is too long for inline command — write to file then invoke
    stdout, stderr, code = await run_ps_script(
        ps, timeout=180, script_name="persistence_audit.ps1"
    )
    result = stdout
    if stderr:
        result += "\n--- Warnings ---\n" + stderr
    return _text(result)


# 48. injection_scan_all
async def _handle_injection_scan_all(args):
    report = ["=" * 60, "INJECTION SCAN - ALL PROCESSES", "=" * 60, ""]

    # Step 1: Hollows Hunter scan
    report.append("--- Step 1: Hollows Hunter (All Processes) ---")
    try:
        hh_result = await _handle_hollows_hunter_scan({
            "output_dir": "C:\\temp\\injection_scan_hh"
        })
        hh_text = hh_result[0].text if hh_result else "Failed"
        report.append(hh_text)
    except Exception as e:
        hh_text = ""
        report.append("Hollows Hunter error: " + str(e))
    report.append("")

    # Step 2: Parse hollows_hunter output for suspicious PIDs
    ps_parse = r"""
$scanDir = "C:\temp\injection_scan_hh"
$suspiciousPids = @()
if (Test-Path $scanDir) {
    # Look for process-specific subdirectories (format: pid_processname)
    Get-ChildItem -Path $scanDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $dirName = $_.Name
        if ($dirName -match '^(\d+)_') {
            $pid = $Matches[1]
            $files = (Get-ChildItem -Path $_.FullName -File -ErrorAction SilentlyContinue | Measure-Object).Count
            if ($files -gt 0) {
                $suspiciousPids += $pid
                Write-Output "SUSPICIOUS: PID $pid ($dirName) - $files artifacts"
            }
        }
    }
}
if ($suspiciousPids.Count -eq 0) {
    Write-Output "NO_SUSPICIOUS_PIDS"
}
"""
    parse_stdout, _, _ = await run_ps_async(ps_parse, timeout=30)

    # Step 3: Detailed pe-sieve on suspicious PIDs
    if "NO_SUSPICIOUS_PIDS" not in parse_stdout:
        report.append("--- Step 2: Detailed PE-sieve on Suspicious Processes ---")
        for line in parse_stdout.strip().split("\n"):
            if line.startswith("SUSPICIOUS:"):
                # Extract PID
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "PID" and i + 1 < len(parts):
                        pid_str = parts[i + 1].strip("()")
                        if pid_str.isdigit():
                            report.append("\n  Scanning PID {}...".format(pid_str))
                            try:
                                sieve_result = await _handle_pe_sieve_scan({
                                    "pid": int(pid_str),
                                    "output_dir": "C:\\temp\\injection_scan_sieve_{}".format(pid_str),
                                })
                                report.append(sieve_result[0].text if sieve_result else "Failed")
                            except Exception as e:
                                report.append("  PE-sieve error: " + str(e))
                        break
    else:
        report.append("--- Step 2: No Suspicious Processes Found ---")
        report.append("Hollows Hunter did not detect any code injection indicators.")

    report.append("")
    report.append("=" * 60)
    report.append("END OF INJECTION SCAN")
    report.append("=" * 60)

    return _text("\n".join(report))


# ========================== MCP PROMPTS ===================================

PROMPT_DEFS = [
    {
        "name": "triage_unknown_sample",
        "description": "Full static triage workflow for an unknown malware sample on FlareVM.",
        "arguments": [
            {"name": "sample_path", "description": "Path to sample on Kali host", "required": True},
        ],
    },
    {
        "name": "behavioral_analysis",
        "description": "Detonation walkthrough with FakeNet, ProcMon, and Regshot.",
        "arguments": [
            {"name": "sample_path", "description": "Path to sample on Kali host", "required": True},
            {"name": "duration", "description": "Detonation duration (seconds)", "required": False},
        ],
    },
    {
        "name": "unpack_workflow",
        "description": "Step-by-step unpacking flow with fallback strategies.",
        "arguments": [
            {"name": "sample_path", "description": "Path to packed sample on FlareVM", "required": True},
        ],
    },
    {
        "name": "injection_hunt",
        "description": "Scan all running processes for code injection indicators.",
        "arguments": [],
    },
    {
        "name": "persistence_audit_report",
        "description": "Generate a Windows persistence audit report (autoruns + scheduled tasks + services).",
        "arguments": [],
    },
]


def _prompt_body(name: str, args: dict) -> str:
    sample = args.get("sample_path", "<sample>")
    duration = args.get("duration", "30")
    if name == "triage_unknown_sample":
        return (
            "Perform a full static triage of the malware sample at `{path}` using the flarevm MCP server.\n\n"
            "Workflow:\n"
            "1. `check_connection` to ensure FlareVM is reachable.\n"
            "2. `upload_file` from `{path}` to `C:\\temp\\sample.bin`.\n"
            "3. `triage_full` (or run individually):\n"
            "   - `die_analyze` for packer/compiler ID.\n"
            "   - `floss_extract_strings` for stack/decoded strings.\n"
            "   - `capa_analyze` for capability fingerprint.\n"
            "   - `yara_scan` against C:\\Tools\\yara\\rules.\n"
            "4. Search output for IOCs: URLs, IPs, mutexes, registry keys, file paths, flag patterns.\n"
            "5. Produce a triage report: hash, packer, capabilities, suspicious strings, recommended next steps.\n"
        ).format(path=sample)
    if name == "behavioral_analysis":
        return (
            "Perform behavioral (dynamic) analysis of `{path}` for {dur} seconds.\n\n"
            "Workflow:\n"
            "1. `check_connection` and confirm FlareVM snapshot is clean.\n"
            "2. `upload_file` to `C:\\temp\\sample.bin`.\n"
            "3. Start collectors:\n"
            "   - `fakenet_start` with the default config.\n"
            "   - `procmon_start` with filter on the sample's PID.\n"
            "   - `regshot_baseline` for registry comparison.\n"
            "4. `execute_with_monitoring` to detonate the sample for {dur}s.\n"
            "5. Stop collectors: `procmon_stop`, `fakenet_stop`, `regshot_compare`.\n"
            "6. `download_file` artifacts (PCAP, PML, regshot diff) to Kali.\n"
            "7. Summarize: network IOCs, persistence, file/registry mutations, child processes.\n"
        ).format(path=sample, dur=duration)
    if name == "unpack_workflow":
        return (
            "Attempt to unpack the packed binary at `{path}` on FlareVM.\n\n"
            "Workflow:\n"
            "1. `die_analyze` to fingerprint the packer (UPX, Themida, ASPack, etc.).\n"
            "2. If UPX: `unpack_detect_and_try` (calls `upx -d` automatically).\n"
            "3. If known packer with public unpacker: run via `execute_powershell`.\n"
            "4. Generic fallback: `pe_sieve_scan` after detonation to dump unpacked PE from memory.\n"
            "5. If still packed: open in `x64dbg_launch_gui`, set breakpoint on `VirtualAlloc`/`WriteProcessMemory`, dump from memory.\n"
            "6. Re-run `die_analyze`, `floss_extract_strings`, `capa_analyze` on the unpacked image.\n"
            "7. Report: original packer, unpacker used, OEP if known, capability diff.\n"
        ).format(path=sample)
    if name == "injection_hunt":
        return (
            "Scan all running processes on FlareVM for code injection.\n\n"
            "Workflow:\n"
            "1. `check_connection`.\n"
            "2. `injection_scan_all` (orchestrates Hollows Hunter sweep + targeted PE-sieve).\n"
            "3. For each suspicious PID, `pe_sieve_scan` with detail and `download_file` dumps.\n"
            "4. For each dump, `die_analyze` and `floss_extract_strings` to identify the injected payload.\n"
            "5. Cross-reference with `list_processes` for parent-child anomalies.\n"
            "6. Report: process tree of injectors, payload identification, suggested IOCs.\n"
        )
    if name == "persistence_audit_report":
        return (
            "Generate a Windows persistence audit report from FlareVM.\n\n"
            "Workflow:\n"
            "1. `check_connection`.\n"
            "2. `persistence_audit` (Autorunsc + scheduled tasks + services + WMI subscriptions).\n"
            "3. Filter results: highlight unsigned binaries, recent modifications, suspicious paths (`%TEMP%`, `%APPDATA%`).\n"
            "4. For each suspicious entry, `download_file` the binary and run `die_analyze` + `yara_scan`.\n"
            "5. Output a markdown report grouped by persistence mechanism (Run keys, scheduled tasks, services, WMI).\n"
        )
    return "Unknown prompt: " + name


@app.list_prompts()
async def list_prompts():
    out = []
    for p in PROMPT_DEFS:
        out.append(Prompt(
            name=p["name"],
            description=p["description"],
            arguments=[
                PromptArgument(
                    name=a["name"],
                    description=a["description"],
                    required=a.get("required", False),
                )
                for a in p["arguments"]
            ],
        ))
    return out


@app.get_prompt()
async def get_prompt(name: str, arguments: dict = None):
    args = arguments or {}
    body = _prompt_body(name, args)
    return GetPromptResult(
        description=next((p["description"] for p in PROMPT_DEFS if p["name"] == name), name),
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(type="text", text=body),
            )
        ],
    )


# ========================== MCP RESOURCES =================================

CHEATSHEET_TEXT = """# FlareVM MCP Cheatsheet

## Quick triage
- check_connection
- upload_file (kali_path -> C:\\temp\\sample.bin)
- triage_full (DIE + FLOSS + CAPA + YARA)

## Detonation
- fakenet_start / fakenet_stop
- procmon_start / procmon_stop
- regshot_baseline / regshot_compare
- execute_with_monitoring

## Unpacking
- die_analyze (identify packer)
- unpack_detect_and_try (UPX auto)
- pe_sieve_scan (dump from memory)
- x64dbg_launch_gui (manual unpack)

## Injection hunt
- injection_scan_all (Hollows Hunter + PE-sieve)
- list_processes
- pe_sieve_scan --pid <PID>

## Persistence
- persistence_audit (autorunsc + tasks + services)
- list_scheduled_tasks
- list_services

## Network
- tshark_capture (PCAP capture)
- fakenet_start (DNS+HTTP+HTTPS sinkhole)

## Tool flags
- die: -j (JSON output), -d (deep)
- floss: -n 6 (min length), --no-static-strings
- capa: -j (JSON), -vv (verbose)
- yara: -r (recursive), -s (show strings)
- pe-sieve: /pid <N> /imp 3 /shellc 3 /data 3
"""

YARA_INDEX_TEXT = """# YARA Rules Index

Default rules directory: `C:\\Tools\\yara\\rules\\`

## Recommended rule sources
- Florian Roth signature-base: https://github.com/Neo23x0/signature-base
- YaraRules Project: https://github.com/Yara-Rules/rules
- Elastic Protections Artifacts: https://github.com/elastic/protections-artifacts
- ReversingLabs YARA rules: https://github.com/reversinglabs/reversinglabs-yara-rules

## Common malware family rules to keep
- Cobalt Strike beacon detection
- Metasploit shellcode patterns
- Common loader patterns (DonutLoader, Shellter)
- Ransomware family heuristics (LockBit, BlackCat, Conti)
- Stealer families (RedLine, Raccoon, Vidar)

## Use via MCP
- yara_scan(file_path, rules_dir="C:\\Tools\\yara\\rules") -> matches per rule
"""

TOOLS_REFERENCE_TEXT = """# FlareVM Tool Reference

| Tool | Path | Purpose |
|------|------|---------|
| DIE | C:\\Tools\\die\\diec.exe | Packer / compiler identification |
| FLOSS | C:\\Tools\\FLOSS\\floss.exe | Stacked / decoded string extraction |
| CAPA | C:\\Tools\\capa\\capa.exe | Capability fingerprinting |
| YARA | C:\\Tools\\yara\\yara64.exe | Signature scanning |
| ProcMon | C:\\Tools\\sysinternals\\Procmon.exe | Behavioral monitoring |
| Autorunsc | C:\\Tools\\sysinternals\\autorunsc.exe | Persistence enumeration |
| Strings | C:\\Tools\\sysinternals\\strings.exe | ASCII/Unicode strings |
| PE-sieve | C:\\Tools\\pe-sieve\\pe-sieve64.exe | In-memory PE anomaly scan |
| Hollows Hunter | C:\\Tools\\hollows_hunter\\hollows_hunter64.exe | System-wide injection sweep |
| UPX | C:\\Tools\\upx\\upx.exe | UPX unpack/pack |
| dnSpy | C:\\Tools\\dnSpy\\dnSpy.Console.exe | .NET decompilation |
| FakeNet-NG | C:\\Tools\\fakenet\\fakenet.exe | Network sinkhole |
| NirCmd | C:\\Tools\\nircmd.exe | GUI automation |
| x64dbg | C:\\ProgramData\\chocolatey\\bin\\x64dbg.exe | Debugger |
| TShark | C:\\ProgramData\\chocolatey\\bin\\tshark.exe | CLI Wireshark |
"""


RESOURCE_DEFS = [
    ("flarevm://tools/inventory", "FlareVM tools inventory", "text/plain"),
    ("flarevm://config/fakenet-default", "Default FakeNet-NG config", "text/plain"),
    ("flarevm://docs/yara-rules", "YARA rules index", "text/markdown"),
    ("flarevm://docs/cheatsheet", "FlareVM MCP cheatsheet", "text/markdown"),
    ("flarevm://status/connection", "FlareVM connection status", "text/plain"),
]


@app.list_resources()
async def list_resources():
    return [
        Resource(uri=u, name=n, description=n, mimeType=m)
        for (u, n, m) in RESOURCE_DEFS
    ]


@app.read_resource()
async def read_resource(uri):
    uri_s = str(uri)
    if uri_s == "flarevm://docs/cheatsheet":
        return CHEATSHEET_TEXT
    if uri_s == "flarevm://docs/yara-rules":
        rules_text = YARA_INDEX_TEXT
        try:
            ps = r"if (Test-Path 'C:\Tools\yara\rules') { Get-ChildItem -Path 'C:\Tools\yara\rules' -Recurse -Filter *.yar* -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName } else { Write-Output 'NO_RULES_DIR' }"
            stdout, _, _ = await run_ps_async(ps, timeout=20)
            if stdout and "NO_RULES_DIR" not in stdout:
                rules_text += "\n## Installed rules\n\n" + stdout
        except Exception:
            pass
        return rules_text
    if uri_s == "flarevm://config/fakenet-default":
        try:
            return generate_fakenet_config()
        except Exception as e:
            return "Error generating config: " + str(e)
    if uri_s == "flarevm://tools/inventory":
        lines = ["# FlareVM Tools Inventory\n"]
        # Build a single PowerShell script that tests all paths at once.
        checks = []
        for key, path in TOOL_PATHS.items():
            esc = path.replace("'", "''")
            checks.append("Write-Output ('{0}|{1}|' + (Test-Path '{2}'))".format(key, path, esc))
        ps = "\n".join(checks)
        try:
            stdout, _, _ = await run_ps_async(ps, timeout=30)
            for line in stdout.splitlines():
                parts = line.strip().split("|")
                if len(parts) == 3:
                    status = "OK" if parts[2].lower() == "true" else "MISSING"
                    lines.append("- **{}** [{}] `{}`".format(parts[0], status, parts[1]))
        except Exception as e:
            lines.append("(connection error: {})".format(e))
            for k, p in TOOL_PATHS.items():
                lines.append("- **{}** `{}`".format(k, p))
        lines.append("\n" + TOOLS_REFERENCE_TEXT)
        return "\n".join(lines)
    if uri_s == "flarevm://status/connection":
        try:
            res = await _handle_check_connection({})
            return res[0].text if res else "No response"
        except Exception as e:
            return "Connection error: " + str(e)
    return "Unknown resource: " + uri_s


# ========================== MAIN ==========================================

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main_sync():
    """Synchronous entry point for console_scripts."""
    asyncio.run(main())


if __name__ == "__main__":
    main_sync()
