#!/usr/bin/env python3
import asyncio
import keyring
import base64
import json
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types
import winrm
from pathlib import Path
import hashlib
import re
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor

FLAREVM_HOST = "192.168.100.10"
FLAREVM_USER = "xtemp"
FLAREVM_PASSWORD = keyring.get_password("flarevm", FLAREVM_USER)

if not FLAREVM_PASSWORD:
    raise ValueError("Password not found in keyring")

# SMB share configuration
SMB_SHARE_NAME = "KaliShare"
SMB_SHARE_PATH = f"//{FLAREVM_HOST}/{SMB_SHARE_NAME}"
SMB_LOCAL_PATH = "C:\\Share"

session = winrm.Session(
    FLAREVM_HOST,
    auth=(FLAREVM_USER, FLAREVM_PASSWORD),
    transport='plaintext'
)

# Thread pool for blocking I/O operations
executor = ThreadPoolExecutor(max_workers=4)

app = Server("flarevm-remote")

# Helper function to run PowerShell commands asynchronously
async def run_ps_async(command: str, timeout: int = 120):
    """Run PowerShell command asynchronously with timeout"""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(executor, session.run_ps, command),
            timeout=timeout
        )
        return result
    except asyncio.TimeoutError:
        raise Exception(f"PowerShell command timed out after {timeout} seconds")

# ========== IDA Pro Helper Function ==========
def ida_rpc_call(method: str, params: dict = None):
    """Make MCP tool call to IDA Pro MCP server via WinRM"""
    
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": method,
            "arguments": params or {}
        },
        "id": 1
    }
    
    ps_script = f'''
$body = @'
{json.dumps(payload)}
'@
    
try {{
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:13337/mcp" `
        -Method POST `
        -Body $body `
        -ContentType "application/json" `
        -UseBasicParsing
    
    $response.Content
}} catch {{
    Write-Output "Error: $($_.Exception.Message)"
}}
'''
    
    result = session.run_ps(ps_script)
    response_text = result.std_out.decode('utf-8', errors='replace').strip()
    
    try:
        response_json = json.loads(response_text)
        if "error" in response_json:
            return {"error": response_json["error"]["message"]}
        
        if "result" in response_json:
            result_data = response_json["result"]
            if isinstance(result_data, dict) and "content" in result_data:
                content_items = result_data["content"]
                if content_items and len(content_items) > 0:
                    return content_items[0]["text"]
            return result_data
        return response_json
    except json.JSONDecodeError:
        return {"error": f"Failed to parse response: {response_text}"}

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        # ========== File Transfer ==========
        types.Tool(
            name="upload_file",
            description="Upload file from Kali to FlareVM",
            inputSchema={
                "type": "object",
                "properties": {
                    "local_path": {"type": "string", "description": "Path on Kali"},
                    "remote_path": {"type": "string", "description": "Destination path on FlareVM"}
                },
                "required": ["local_path", "remote_path"]
            }
        ),
        types.Tool(
            name="download_file",
            description="Download file from FlareVM to Kali",
            inputSchema={
                "type": "object",
                "properties": {
                    "remote_path": {"type": "string", "description": "Path on FlareVM"},
                    "local_path": {"type": "string", "description": "Destination path on Kali"}
                },
                "required": ["remote_path", "local_path"]
            }
        ),
        
        # ========== Basic System Tools ==========
        types.Tool(
            name="check_connection",
            description="Check WinRM connection to FlareVM",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        types.Tool(
            name="execute_powershell",
            description="Execute PowerShell command on FlareVM",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string"}
                },
                "required": ["command"]
            }
        ),
        types.Tool(
            name="read_file",
            description="Read file content from FlareVM",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="get_file_hash",
            description="Calculate file hash",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "algorithm": {"type": "string", "enum": ["MD5", "SHA1", "SHA256"], "default": "SHA256"}
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="list_processes",
            description="List running processes",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {"type": "string"}
                }
            }
        ),
        
        # ========== Dynamic Analysis ==========
        types.Tool(
            name="procmon_start",
            description="Start Process Monitor capture with filters",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_file": {"type": "string", "description": "PML output file path"},
                    "process_filter": {"type": "string", "description": "Process name to monitor (optional)"}
                },
                "required": ["output_file"]
            }
        ),
        types.Tool(
            name="procmon_stop",
            description="Stop Process Monitor and get summary",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_file": {"type": "string", "description": "PML file to analyze"}
                },
                "required": ["output_file"]
            }
        ),
        types.Tool(
            name="procmon_export_csv",
            description="Export Process Monitor logs to CSV",
            inputSchema={
                "type": "object",
                "properties": {
                    "pml_file": {"type": "string"},
                    "csv_file": {"type": "string"}
                },
                "required": ["pml_file", "csv_file"]
            }
        ),
        types.Tool(
            name="execute_with_monitoring",
            description="Execute program with full monitoring (procmon, network, registry)",
            inputSchema={
                "type": "object",
                "properties": {
                    "executable": {"type": "string"},
                    "arguments": {"type": "string"},
                    "duration": {"type": "integer", "default": 30, "description": "Monitoring duration in seconds"}
                },
                "required": ["executable"]
            }
        ),
        types.Tool(
            name="process_hacker_info",
            description="Get detailed process information using Process Hacker",
            inputSchema={
                "type": "object",
                "properties": {
                    "process_name_or_pid": {"type": "string"}
                },
                "required": ["process_name_or_pid"]
            }
        ),
        types.Tool(
            name="monitor_network_realtime",
            description="Monitor network connections for duration",
            inputSchema={
                "type": "object",
                "properties": {
                    "duration": {"type": "integer", "default": 10},
                    "process_filter": {"type": "string"}
                }
            }
        ),
        types.Tool(
            name="regshot_snapshot",
            description="Take registry snapshot (before/after/compare)",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["first", "second", "compare"]},
                    "output_dir": {"type": "string"}
                },
                "required": ["action", "output_dir"]
            }
        ),
        types.Tool(
            name="autoruns_analyze",
            description="Analyze autostart programs",
            inputSchema={
                "type": "object",
                "properties": {
                    "verify_signatures": {"type": "boolean", "default": True}
                }
            }
        ),
        types.Tool(
            name="fakenet_start",
            description="Start FakeNet-NG network simulation",
            inputSchema={
                "type": "object",
                "properties": {
                    "config_file": {"type": "string"}
                }
            }
        ),
        types.Tool(
            name="fakenet_stop",
            description="Stop FakeNet-NG and get logs",
            inputSchema={"type": "object", "properties": {}}
        ),
        
        # ========== Advanced Static Analysis ==========
        types.Tool(
            name="die_analyze",
            description="Analyze file with DetectItEasy console version (DIEC) - packer/compiler detection with deep scan",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"}
                },
                "required": ["file_path"]
            }
        ),
        types.Tool(
            name="floss_extract_strings",
            description="Extract obfuscated strings with FLOSS",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "min_length": {"type": "integer", "default": 4}
                },
                "required": ["file_path"]
            }
        ),
        types.Tool(
            name="capa_analyze",
            description="Identify capabilities with CAPA",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"}
                },
                "required": ["file_path"]
            }
        ),
        types.Tool(
            name="x64dbg_load",
            description="Load executable in x64dbg (opens GUI)",
            inputSchema={
                "type": "object",
                "properties": {
                    "executable": {"type": "string"},
                    "script_file": {"type": "string", "description": "Optional x64dbg script"}
                },
                "required": ["executable"]
            }
        ),
        types.Tool(
            name="x64dbg_run_script",
            description="Create and execute x64dbg script",
            inputSchema={
                "type": "object",
                "properties": {
                    "script_content": {"type": "string", "description": "x64dbg script commands"},
                    "save_path": {"type": "string", "default": "C:\\temp\\x64dbg_script.txt"}
                },
                "required": ["script_content"]
            }
        ),
        types.Tool(
            name="windbg_analyze_dump",
            description="Analyze crash dump with WinDbg",
            inputSchema={
                "type": "object",
                "properties": {
                    "dump_file": {"type": "string"},
                    "commands": {"type": "string", "description": "WinDbg commands (e.g., !analyze -v)"}
                },
                "required": ["dump_file"]
            }
        ),
        
        # ========== Frida Integration ==========
        types.Tool(
            name="frida_list_processes",
            description="List running processes for Frida injection",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="frida_spawn_and_attach",
            description="Spawn process and attach Frida",
            inputSchema={
                "type": "object",
                "properties": {
                    "executable": {"type": "string"},
                    "script_path": {"type": "string", "description": "Frida JavaScript file"}
                },
                "required": ["executable", "script_path"]
            }
        ),
        types.Tool(
            name="frida_attach_pid",
            description="Attach Frida to running process",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer"},
                    "script_path": {"type": "string"}
                },
                "required": ["pid", "script_path"]
            }
        ),
        types.Tool(
            name="frida_run_script",
            description="Execute Frida script on process",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Process name or PID"},
                    "script_content": {"type": "string", "description": "Frida JavaScript code"}
                },
                "required": ["target", "script_content"]
            }
        ),
        
        # ========== IDA Pro Tools ==========
        types.Tool(
            name="ida_get_metadata",
            description="Get metadata about binary in IDA",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="ida_list_functions",
            description="List functions in binary",
            inputSchema={
                "type": "object",
                "properties": {
                    "offset": {"type": "integer", "default": 0},
                    "count": {"type": "integer", "default": 50}
                },
                "required": ["offset", "count"]
            }
        ),
        types.Tool(
            name="ida_decompile_function",
            description="Decompile function",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string"}
                },
                "required": ["address"]
            }
        ),
        types.Tool(
            name="ida_disassemble_function",
            description="Get assembly for function",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_address": {"type": "string"}
                },
                "required": ["start_address"]
            }
        ),
        types.Tool(
            name="ida_list_strings",
            description="List strings in binary",
            inputSchema={
                "type": "object",
                "properties": {
                    "offset": {"type": "integer", "default": 0},
                    "count": {"type": "integer", "default": 100}
                },
                "required": ["offset", "count"]
            }
        ),
        types.Tool(
            name="ida_set_comment",
            description="Set comment at address",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "comment": {"type": "string"}
                },
                "required": ["address", "comment"]
            }
        ),
        types.Tool(
            name="ida_rename_function",
            description="Rename function",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_address": {"type": "string"},
                    "new_name": {"type": "string"}
                },
                "required": ["function_address", "new_name"]
            }
        ),
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    import traceback
    try:
        # ========== File Transfer ==========
        if name == "upload_file":
            local_path = Path(arguments["local_path"])
            remote_path = arguments["remote_path"]

            # Get file size and calculate hash before transfer
            file_size = local_path.stat().st_size
            with open(local_path, "rb") as f:
                file_content = f.read()
                local_sha256 = hashlib.sha256(file_content).hexdigest()

            status_messages = []
            transfer_method = "WinRM"

            # For large files (>8KB), use SMB. For small files, use WinRM
            if file_size > 8192:
                transfer_method = "SMB"
                status_messages.append(f"File size: {file_size:,} bytes - using SMB transfer")

                # Upload to SMB share using smbclient
                filename = os.path.basename(str(local_path))
                smb_temp_path = f"{SMB_LOCAL_PATH}\\{filename}"

                try:
                    # Use smbclient to upload file
                    smb_cmd = [
                        'smbclient',
                        SMB_SHARE_PATH,
                        '-U', f'{FLAREVM_USER}%{FLAREVM_PASSWORD}',
                        '-c', f'put "{local_path}" "{filename}"'
                    ]

                    status_messages.append("Uploading via SMB...")
                    result = subprocess.run(smb_cmd, capture_output=True, text=True, check=True)
                    status_messages.append("SMB upload complete")

                    # Move file from share to final destination
                    if smb_temp_path != remote_path:
                        move_cmd = f'Move-Item -Path "{smb_temp_path}" -Destination "{remote_path}" -Force'
                        await run_ps_async(move_cmd, timeout=30)
                        status_messages.append(f"Moved to final destination: {remote_path}")

                except subprocess.CalledProcessError as e:
                    return [types.TextContent(type="text", text=f"SMB upload failed: {e.stderr}")]
            else:
                # Small file - use WinRM with base64
                status_messages.append(f"File size: {file_size:,} bytes - using WinRM transfer")
                file_data_b64 = base64.b64encode(file_content).decode('utf-8')

                cmd = f'''
$base64 = @"
{file_data_b64}
"@
$bytes = [System.Convert]::FromBase64String($base64)
[System.IO.File]::WriteAllBytes("{remote_path}", $bytes)
'''
                await run_ps_async(cmd, timeout=30)
                status_messages.append("WinRM upload complete")

            # Verify checksum
            cmd = f'''
$hash = Get-FileHash -Path "{remote_path}" -Algorithm SHA256
$remoteSize = (Get-Item "{remote_path}").Length
@{{
    FileSize = $remoteSize
    SHA256 = $hash.Hash
}} | ConvertTo-Json
'''
            result = await run_ps_async(cmd, timeout=30)
            output = result.std_out.decode('utf-8', errors='replace')

            # Parse and verify checksum
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                remote_info = json.loads(json_match.group())
                remote_sha256 = remote_info['SHA256'].lower()
                remote_size = remote_info['FileSize']

                checksum_match = "✓ VERIFIED" if local_sha256.lower() == remote_sha256 else "✗ MISMATCH"
                size_match = "✓" if file_size == remote_size else "✗"

                status_log = "\n".join(status_messages)

                return [types.TextContent(type="text", text=f'''File uploaded successfully!

Transfer Method: {transfer_method}
{status_log}

Source: {local_path}
Destination: {remote_path}
Size: {file_size:,} bytes {size_match}
Local SHA256:  {local_sha256}
Remote SHA256: {remote_sha256}
Checksum: {checksum_match}
''')]

            return [types.TextContent(type="text", text=f"Uploaded to {remote_path}\n\n{output}")]
        
        elif name == "download_file":
            remote_path = arguments["remote_path"]
            local_path = Path(arguments["local_path"])

            # Download file as base64
            cmd = f'''
$bytes = [System.IO.File]::ReadAllBytes("{remote_path}")
[System.Convert]::ToBase64String($bytes)
'''
            result = await run_ps_async(cmd, timeout=120)
            file_data_b64 = result.std_out.decode('utf-8', errors='replace').strip()

            # Decode and save
            file_data = base64.b64decode(file_data_b64)
            with open(local_path, "wb") as f:
                f.write(file_data)

            return [types.TextContent(type="text", text=f"File downloaded to {local_path}")]
        
        # ========== Dynamic Analysis ==========
        elif name == "procmon_start":
            output_file = arguments["output_file"]
            process_filter = arguments.get("process_filter", "")

            filter_arg = f"/ProcessName {process_filter}" if process_filter else ""

            cmd = f'''
$procmon = "C:\\Tools\\sysinternals\\Procmon.exe"
if (Test-Path $procmon) {{
    Start-Process $procmon -ArgumentList "/BackingFile {output_file} /Minimized /Quiet {filter_arg}"
    Start-Sleep -Seconds 2
    "Process Monitor started. Output: {output_file}"
}} else {{
    "Process Monitor not found"
}}
'''
            result = await run_ps_async(cmd, timeout=30)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]

        elif name == "procmon_stop":
            cmd = '''
$procmon = Get-Process Procmon* -ErrorAction SilentlyContinue
if ($procmon) {
    $procmon | Stop-Process -Force
    "Process Monitor stopped"
} else {
    "Process Monitor not running"
}
'''
            result = await run_ps_async(cmd, timeout=30)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]
        
        elif name == "execute_with_monitoring":
            executable = arguments["executable"]
            args_str = arguments.get("arguments", "")
            duration = arguments.get("duration", 30)

            cmd = f'''
# Start procmon
$procmonLog = "C:\\temp\\procmon_$(Get-Date -Format 'yyyyMMdd_HHmmss').pml"
Start-Process "C:\\Tools\\sysinternals\\Procmon.exe" -ArgumentList "/BackingFile $procmonLog /Minimized /Quiet"
Start-Sleep -Seconds 2

# Take before snapshot
$netstatBefore = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

# Execute target
$proc = Start-Process "{executable}" -ArgumentList "{args_str}" -PassThru

# Monitor for duration
Start-Sleep -Seconds {duration}

# Get after state
$netstatAfter = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

# Stop procmon
Get-Process Procmon* -ErrorAction SilentlyContinue | Stop-Process -Force

# Return summary
@{{
    ProcessId = $proc.Id
    ProcessName = $proc.Name
    ProcmonLog = $procmonLog
    NetworkConnections = ($netstatAfter | Where-Object {{$_.OwningProcess -eq $proc.Id}} | ConvertTo-Json)
}} | ConvertTo-Json
'''
            timeout_val = duration + 60  # Add buffer for setup/teardown
            result = await run_ps_async(cmd, timeout=timeout_val)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]

        elif name == "autoruns_analyze":
            cmd = '''
$autoruns = "C:\\Tools\\sysinternals\\autorunsc.exe"
if (Test-Path $autoruns) {
    & $autoruns -accepteula -a * -c -h
} else {
    "Autoruns not found"
}
'''
            result = await run_ps_async(cmd, timeout=60)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]
        
        # ========== Static Analysis ==========
        elif name == "die_analyze":
            file_path = arguments["file_path"]
            cmd = f'''
$diec = "C:\\Tools\\die\\diec.exe"
if (Test-Path $diec) {{
    & $diec -d "{file_path}"
}} else {{
    "DetectItEasy (diec) not found"
}}
'''
            result = await run_ps_async(cmd, timeout=60)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]

        elif name == "floss_extract_strings":
            file_path = arguments["file_path"]
            min_len = arguments.get("min_length", 4)
            cmd = f'''
$floss = "C:\\Tools\\FLOSS\\floss.exe"
if (Test-Path $floss) {{
    & $floss -n {min_len} "{file_path}"
}} else {{
    "FLOSS not found"
}}
'''
            result = await run_ps_async(cmd, timeout=120)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]

        elif name == "capa_analyze":
            file_path = arguments["file_path"]
            cmd = f'''
$capa = "C:\\Tools\\capa\\capa.exe"
if (Test-Path $capa) {{
    & $capa "{file_path}"
}} else {{
    "CAPA not found"
}}
'''
            result = await run_ps_async(cmd, timeout=180)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]

        elif name == "x64dbg_load":
            executable = arguments["executable"]
            cmd = f'''
$x64dbg = "C:\\ProgramData\\chocolatey\\bin\\x64dbg.exe"
if (Test-Path $x64dbg) {{
    Start-Process $x64dbg -ArgumentList '"{executable}"'
    "x64dbg launched with {executable}"
}} else {{
    "x64dbg not found"
}}
'''
            result = await run_ps_async(cmd, timeout=30)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]

        elif name == "x64dbg_run_script":
            script_content = arguments["script_content"]
            save_path = arguments.get("save_path", "C:\\temp\\x64dbg_script.txt")

            cmd = f'''
$scriptContent = @"
{script_content}
"@
Set-Content -Path "{save_path}" -Value $scriptContent
"Script saved to {save_path}. Load in x64dbg: File > Script > Open > {save_path}"
'''
            result = await run_ps_async(cmd, timeout=30)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]
        
        # ========== Frida ==========
        elif name == "frida_list_processes":
            cmd = '''
frida-ps
'''
            result = await run_ps_async(cmd, timeout=30)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]

        elif name == "frida_run_script":
            target = arguments["target"]
            script_content = arguments["script_content"]

            # Save script
            script_path = "C:\\temp\\frida_script.js"
            cmd = f'''
$scriptContent = @"
{script_content}
"@
Set-Content -Path "{script_path}" -Value $scriptContent

# Run frida
frida -n "{target}" -l "{script_path}" --no-pause
'''
            result = await run_ps_async(cmd, timeout=120)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]
        
        # ========== IDA Pro ==========
        elif name.startswith("ida_"):
            method_name = name.replace("ida_", "")
            result = ida_rpc_call(method_name, arguments)
            
            if isinstance(result, dict) and "error" in result:
                return [types.TextContent(type="text", text=f"IDA Error: {result['error']}")]
            
            return [types.TextContent(type="text", text=str(result))]
        
        # ========== Basic Tools ==========
        elif name == "check_connection":
            cmd = '''
$info = @{
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
    OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    Architecture = $env:PROCESSOR_ARCHITECTURE
    IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne "127.0.0.1"} | Select-Object -First 1).IPAddress
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}
$info | ConvertTo-Json
'''
            result = await run_ps_async(cmd, timeout=30)
            output = result.std_out.decode('utf-8', errors='replace')
            return [types.TextContent(type="text", text=f"✓ Connection successful!\n\n{output}")]

        elif name == "execute_powershell":
            result = await run_ps_async(arguments["command"], timeout=120)
            output = result.std_out.decode('utf-8', errors='replace') if result.std_out else "Done"
            if result.std_err:
                output += f"\n\nErrors:\n{result.std_err.decode('utf-8', errors='replace')}"
            return [types.TextContent(type="text", text=output)]

        elif name == "read_file":
            cmd = f"Get-Content -Path '{arguments['path']}' -Raw"
            result = await run_ps_async(cmd, timeout=60)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]

        elif name == "get_file_hash":
            algo = arguments.get("algorithm", "SHA256")
            cmd = f"Get-FileHash -Path '{arguments['path']}' -Algorithm {algo} | ConvertTo-Json"
            result = await run_ps_async(cmd, timeout=30)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]

        elif name == "list_processes":
            filter_str = arguments.get("filter", "")
            filter_clause = f"| Where-Object {{$_.Name -like '*{filter_str}*'}}" if filter_str else ""
            cmd = f"Get-Process {filter_clause} | Select-Object Id, Name, CPU, WS, Path | ConvertTo-Json"
            result = await run_ps_async(cmd, timeout=30)
            return [types.TextContent(type="text", text=result.std_out.decode('utf-8', errors='replace'))]
        
        else:
            return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        error_details = f"""Error executing tool '{name}':

Exception Type: {type(e).__name__}
Error Message: {str(e)}

Traceback:
{traceback.format_exc()}

Arguments:
{json.dumps(arguments, indent=2)}
"""
        return [types.TextContent(type="text", text=error_details)]

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
