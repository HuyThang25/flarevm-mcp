# FlareVM MCP Server

A Model Context Protocol (MCP) server that provides remote access to Windows malware analysis tools on [FlareVM](https://github.com/mandiant/flare-vm) through a unified interface. This enables AI agents and security analysts to perform comprehensive malware analysis and reverse engineering tasks without manual tool interaction.

## What is FlareVM MCP?

**FlareVM MCP** is a bridge between your analysis environment (typically Kali Linux) and an isolated Windows malware analysis VM (FlareVM). It exposes 40+ malware analysis tools through the MCP protocol, allowing:

- **Remote file operations** - Upload/download samples and artifacts
- **Static analysis** - Packer detection (DIE), capability analysis (CAPA), string extraction (FLOSS)
- **Dynamic analysis** - Process monitoring, network surveillance, registry tracking
- **Debuggers** - x64dbg scripting, WinDbg crash analysis
- **Instrumentation** - Frida hooks for runtime API monitoring
- **IDA Pro integration** - Decompilation and annotation via RPC

### Architecture Overview

```
┌─────────────────────────────────┐
│   AI Agent / Claude Code        │
│  (Kali Linux / Local Machine)   │
└────────────────┬────────────────┘
                 │
              MCP (stdio)
                 │
        ┌────────▼─────────┐
        │  FlareVM MCP     │
        │  Server          │
        │  (Python/FastMCP)│
        └────────┬─────────┘
                 │
    ┌────────────┼────────────────────────┐
    │            │                        │
  WinRM      SMB Share            IDA RPC
    │            │                (localhost)
    │            │                        │
┌───▼────────────▼─────────────────────┐ │
│      FlareVM (Windows VM)            │ │
│  ┌──────────────────────────────────┐ │ │
│  │ Malware Analysis Tools:          │ │ │
│  │ - Procmon (process monitoring)   │ │ │
│  │ - DIE (packer detection)         │ │ │
│  │ - FLOSS (string extraction)      │ │ │
│  │ - CAPA (capability analysis)     │ │ │
│  │ - x64dbg (debugger)              │ │ │
│  │ - WinDbg (dump analysis)         │ │ │
│  │ - Frida (dynamic instrumentation)│ │ │
│  │ - FakeNet-NG (network sim)       │ │ │
│  │ - Autoruns (persistence)         │ │ │
│  │ - Regshot (registry monitoring)  │ │ │
│  │ - IDA Pro (reverse engineering)  │ │ │
│  └──────────────────────────────────┘ │ │
│                                        │ │
│  IDA Pro Server (port 13337)──────────┘ │
└────────────────────────────────────────┘
```

## Current Features

### File Transfer Operations
- **`upload_file`** - Upload files from Kali to FlareVM (>8KB uses SMB, <8KB uses WinRM)
- **`download_file`** - Download analysis artifacts back to Kali
- Automatic SHA256 checksum verification for integrity

### Basic System Tools
- **`check_connection`** - Verify WinRM connectivity and get system info
- **`execute_powershell`** - Run arbitrary PowerShell commands
- **`read_file`** - Read file contents remotely
- **`get_file_hash`** - Calculate MD5/SHA1/SHA256 hashes
- **`list_processes`** - Enumerate running processes with optional filtering

### Dynamic Analysis
- **`procmon_start`** - Start Process Monitor with optional process filtering
- **`procmon_stop`** - Stop Process Monitor capture
- **`procmon_export_csv`** - Export PML logs to CSV for analysis
- **`execute_with_monitoring`** - Execute binary with full monitoring (procmon + network)
- **`monitor_network_realtime`** - Real-time network connection monitoring
- **`process_hacker_info`** - Detailed process information via Process Hacker
- **`regshot_snapshot`** - Registry snapshot (before/after/compare analysis)
- **`autoruns_analyze`** - Analyze autostart programs and persistence

### Static Analysis
- **`die_analyze`** - Detect compiler/packer with DetectItEasy (DIEC)
- **`floss_extract_strings`** - Extract obfuscated strings with FLOSS
- **`capa_analyze`** - Identify malware capabilities with CAPA framework

### Dynamic Instrumentation
- **`frida_list_processes`** - List processes available for Frida injection
- **`frida_spawn_and_attach`** - Spawn and attach Frida to process
- **`frida_attach_pid`** - Attach to running process by PID
- **`frida_run_script`** - Execute Frida instrumentation scripts

### Debugging & Analysis
- **`x64dbg_load`** - Launch executable in x64dbg GUI
- **`x64dbg_run_script`** - Create and execute x64dbg scripts
- **`windbg_analyze_dump`** - Analyze crash dumps with WinDbg

### Network Simulation
- **`fakenet_start`** - Start FakeNet-NG network simulation
- **`fakenet_stop`** - Stop FakeNet-NG and retrieve logs

### IDA Pro Integration
- **`ida_get_metadata`** - Get metadata about loaded binary
- **`ida_list_functions`** - List functions with pagination
- **`ida_decompile_function`** - Decompile function to pseudocode
- **`ida_disassemble_function`** - Get assembly listing
- **`ida_list_strings`** - List strings in binary
- **`ida_set_comment`** - Add/modify comments in IDA
- **`ida_rename_function`** - Rename functions

## System Requirements

### Host Machine (Kali/Analysis)
- Python 3.10+
- `python3-winrm` - Windows Remote Management library
- `smbclient` - For large file transfers
- `python-keyring` - For credential storage
- `fastmcp` - MCP server framework

### FlareVM (Windows Analysis VM)
- **OS**: Windows 10/11
- **WinRM**: Enabled and configured for remote access
- **SMB Share**: Optional but recommended (named `KaliShare`)
- **Tools Required**:
  - Procmon (SysInternals)
  - x64dbg
  - WinDbg
  - DIE (DetectItEasy)
  - FLOSS
  - CAPA
  - Frida for Windows
  - FakeNet-NG
  - Autoruns (SysInternals)
  - Regshot
  - IDA Pro (optional, for IDA tools)

## Installation

### 1. Prerequisites Setup

```bash
# Install required Python packages
pip install pywinrm fastmcp keyring

# Install smbclient for large file transfers
sudo apt-get install smbclient

# Verify Python version
python3 --version  # Should be 3.10+
```

### 2. Clone Repository

```bash
cd /home/kali
git clone https://github.com/zixuantemp/flarevm-mcp.git
cd flarevm-mcp
```

### 3. Configure Credentials

```bash
# Store FlareVM credentials in system keyring
python3 << 'EOF'
import keyring

# Configure based on your FlareVM setup
FLAREVM_HOST = "192.168.100.10"  # Adjust to your VM IP
FLAREVM_USER = "xtemp"            # Adjust to your username
FLAREVM_PASSWORD = "your_password" # Your password

# Store password securely
keyring.set_password("flarevm", FLAREVM_USER, FLAREVM_PASSWORD)
print(f"✓ Credentials stored for {FLAREVM_USER}@{FLAREVM_HOST}")
EOF
```

### 4. Update Configuration

Edit `server.py` to match your environment:

```python
FLAREVM_HOST = "192.168.100.10"      # Your FlareVM IP
FLAREVM_USER = "xtemp"                # Your Windows username
SMB_SHARE_NAME = "KaliShare"          # Your SMB share name
SMB_LOCAL_PATH = "C:\\Share"          # SMB mount point on FlareVM
```

### 5. Configure MCP Server

For use with Claude Code or other MCP clients, add to your MCP config:

**For Claude Code** (`~/.claude/claude.json`):
```json
{
  "mcp_servers": {
    "flarevm": {
      "command": "python3",
      "args": ["/home/kali/mcp-flare/server.py"],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

**For other MCP clients**, configure according to their documentation.

### 6. Verify Installation

```bash
# Test connection
python3 << 'EOF'
import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, '/home/kali/mcp-flare')

async def test():
    # This will attempt to load the server
    print("✓ Server module loads successfully")
    print("✓ All dependencies installed")

asyncio.run(test())
EOF
```

## Configuration Guide

### WinRM Setup on FlareVM

1. **Enable WinRM**:
```powershell
# On FlareVM, run as Administrator:
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
Restart-Service WinRM
```

2. **Verify connectivity from Kali**:
```bash
python3 << 'EOF'
import winrm

session = winrm.Session(
    "192.168.100.10",
    auth=("xtemp", "password"),
    transport='plaintext'
)

result = session.run_ps("Write-Output 'Hello from FlareVM'")
print(result.std_out.decode())
EOF
```

### SMB Share Setup (Optional)

For large file transfers (>8KB), configure SMB share on FlareVM:

1. Create share:
```powershell
New-Item -Path "C:\Share" -ItemType Directory -Force
New-SmbShare -Name "KaliShare" -Path "C:\Share" -FullAccess "Everyone"
```

2. Test from Kali:
```bash
smbclient //192.168.100.10/KaliShare -U xtemp -c "ls"
```

### IDA Pro Integration

If using IDA Pro tools:

1. Install IDA Pro on FlareVM
2. Install IDA Pro MCP plugin: https://github.com/mandiant/ida-pro-mcp
3. Start IDA Pro with MCP server listening on `localhost:13337`
4. Verify on FlareVM:
```powershell
netstat -ano | findstr :13337
```

## Usage Examples

### 1. Quick Malware Triage

```python
# Using with Claude Code or Python
from mcp_client import MCPClient

client = MCPClient("flarevm")

# Upload sample
client.call("upload_file", {
    "local_path": "/home/kali/samples/malware.exe",
    "remote_path": "C:\\temp\\sample.exe"
})

# Get static analysis
die_result = client.call("die_analyze", {
    "file_path": "C:\\temp\\sample.exe"
})
print(f"Packer: {die_result}")

# Extract strings
strings = client.call("floss_extract_strings", {
    "file_path": "C:\\temp\\sample.exe"
})

# Get capabilities
capa_result = client.call("capa_analyze", {
    "file_path": "C:\\temp\\sample.exe"
})
```

### 2. Behavioral Analysis with Monitoring

```python
# Monitor process execution
result = client.call("execute_with_monitoring", {
    "executable": "C:\\temp\\sample.exe",
    "arguments": "--test",
    "duration": 30
})

# Download procmon logs
client.call("download_file", {
    "remote_path": result["ProcmonLog"],
    "local_path": "/home/kali/analysis/procmon_logs.pml"
})
```

### 3. API Hooking with Frida

```python
# Hook Windows API during execution
frida_script = """
Interceptor.attach(Module.findExportByName("kernel32.dll", "CreateProcessW"), {
    onEnter: function(args) {
        console.log("[*] CreateProcess called with: " + args[1].readUtf16String());
    }
});
"""

result = client.call("frida_run_script", {
    "target": "sample.exe",
    "script_content": frida_script
})
```

### 4. Interactive Debugging with x64dbg

```python
# Load in debugger
client.call("x64dbg_load", {
    "executable": "C:\\temp\\sample.exe"
})

# Create breakpoint script
script = """
bp 0x00401000
BreakOnDll(kernel32.dll, false)
bp CreateProcessW
"""

client.call("x64dbg_run_script", {
    "script_content": script
})
```

### 5. IDA Pro Analysis

```python
# Decompile function
decomp = client.call("ida_decompile_function", {
    "address": "0x00401000"
})

# Add comment
client.call("ida_set_comment", {
    "address": "0x00401000",
    "comment": "Entry point - possible C2 setup"
})

# Rename function
client.call("ida_rename_function", {
    "function_address": "0x00401050",
    "new_name": "decrypt_config"
})
```

### 6. Persistence Analysis

```python
# Check autostart programs
autoruns = client.call("autoruns_analyze")

# Take registry snapshots
before = client.call("regshot_snapshot", {
    "action": "first",
    "output_dir": "C:\\temp\\regshot"
})

# Run malware
client.call("execute_with_monitoring", {
    "executable": "C:\\temp\\sample.exe",
    "duration": 30
})

# Compare after
after = client.call("regshot_snapshot", {
    "action": "second",
    "output_dir": "C:\\temp\\regshot"
})

comparison = client.call("regshot_snapshot", {
    "action": "compare",
    "output_dir": "C:\\temp\\regshot"
})
```

## Suggested Setups

### Setup 1: Minimal Analysis Lab

**Components**:
- Kali Linux VM (4GB RAM, 20GB storage)
- FlareVM Windows 10 (8GB RAM, 50GB storage)
- Network: Isolated lab network (no internet)
- Storage: Shared folder for samples/logs

**Tools Enabled**:
- Procmon, x64dbg, DIE, FLOSS, CAPA

**Best For**: Quick triage, static analysis, basic dynamic analysis

**Estimated Setup Time**: 2-3 hours

### Setup 2: Advanced Research Lab

**Components**:
- Kali Linux (dedicated host, 8GB+ RAM)
- Multiple FlareVM snapshots (one per sample type)
- IDA Pro for reverse engineering
- Network: Isolated + FakeNet for network-connected malware
- Storage: 500GB+ for analysis artifacts

**Tools Enabled**:
- All tools: Procmon, x64dbg, WinDbg, DIE, FLOSS, CAPA, Frida, IDA Pro, FakeNet

**Workflow**:
1. Static analysis (DIE, FLOSS, CAPA)
2. Behavioral analysis (Procmon, network monitoring)
3. Interactive debugging (x64dbg, Frida)
4. Deep reverse engineering (IDA Pro)

**Best For**: Professional malware analysis, research, threat intelligence

**Estimated Setup Time**: 8-10 hours

### Setup 3: Automated Analysis Pipeline

**Components**:
- Kali Linux (automation host)
- FlareVM (automated analysis)
- Message queue (Redis/RabbitMQ optional)
- Database (SQLite/MongoDB) for results

**Workflow**:
```
Sample Upload → Static Analysis → Dynamic Analysis → Report Generation
```

**Best For**: Bulk sample analysis, honeypot integration, SOC automation

**Estimated Setup Time**: 1-2 days

## API Reference

### Tool Categories

#### File Transfer
- `upload_file(local_path, remote_path)`
- `download_file(remote_path, local_path)`

#### System Operations
- `check_connection()`
- `execute_powershell(command)`
- `read_file(path)`
- `get_file_hash(path, algorithm)`
- `list_processes(filter?)`

#### Dynamic Analysis
- `procmon_start(output_file, process_filter?)`
- `procmon_stop()`
- `procmon_export_csv(pml_file, csv_file)`
- `execute_with_monitoring(executable, arguments?, duration?)`
- `monitor_network_realtime(duration?, process_filter?)`
- `process_hacker_info(process_name_or_pid)`
- `regshot_snapshot(action, output_dir)`
- `autoruns_analyze(verify_signatures?)`

#### Static Analysis
- `die_analyze(file_path)`
- `floss_extract_strings(file_path, min_length?)`
- `capa_analyze(file_path)`

#### Debugging
- `x64dbg_load(executable, script_file?)`
- `x64dbg_run_script(script_content, save_path?)`
- `windbg_analyze_dump(dump_file, commands?)`

#### Frida Instrumentation
- `frida_list_processes()`
- `frida_spawn_and_attach(executable, script_path)`
- `frida_attach_pid(pid, script_path)`
- `frida_run_script(target, script_content)`

#### Network Simulation
- `fakenet_start(config_file?)`
- `fakenet_stop()`

#### IDA Pro
- `ida_get_metadata()`
- `ida_list_functions(offset, count)`
- `ida_decompile_function(address)`
- `ida_disassemble_function(start_address)`
- `ida_list_strings(offset, count)`
- `ida_set_comment(address, comment)`
- `ida_rename_function(function_address, new_name)`

## Future Enhancements

### Short-term (v0.2)
- [ ] Memory dump analysis (MiniDumpWriteDump + analysis)
- [ ] Sandbox integration (Cuckoo/ANY.run API)
- [ ] Volatility 3 integration for memory forensics
- [ ] Output file standardization (JSON reports)
- [ ] Tool availability checking before execution

### Mid-term (v0.3)
- [ ] Batch processing API (analyze multiple samples)
- [ ] Result caching and deduplication
- [ ] Custom YARA rule execution
- [ ] Binary diffing tool integration (Bindiff)
- [ ] Ghidra integration as IDA Pro alternative
- [ ] Improved error handling and retry logic
- [ ] Progress streaming for long operations

### Long-term (v0.4+)
- [ ] Machine learning-based threat classification
- [ ] Collaborative analysis workspace
- [ ] Full CI/CD pipeline integration
- [ ] Cloud-based FlareVM orchestration
- [ ] Performance profiling and optimization
- [ ] Advanced reporting and visualization
- [ ] Integration with threat intelligence feeds

### Research Directions
- Multi-VM cluster analysis (distribute across multiple FlareVMs)
- Automated exploit development assistance
- Behavior pattern recognition and anomaly detection
- Malware family clustering

## Troubleshooting

### Connection Issues

**Problem**: "could not read Username for ... No such device or address"
```
Solution: Verify FlareVM IP is reachable
ping 192.168.100.10
```

**Problem**: "WinRM connection timeout"
```
Solution: Enable WinRM on FlareVM
Run as Administrator on FlareVM:
  Enable-PSRemoting -Force
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

**Problem**: "Keyring password not found"
```
Solution: Store credentials in keyring
python3 -c "import keyring; keyring.set_password('flarevm', 'xtemp', 'password')"
```

### File Transfer Issues

**Problem**: "SMB connection failed"
```
Solution:
1. Verify SMB share exists: net share
2. Check network connectivity: ping
3. Verify credentials: smbclient -U user
```

**Problem**: "File upload verification failed"
```
Solution: Check available disk space on remote machine
diskspace C:\temp\
```

### Tool Execution

**Problem**: "Tool not found" error
```
Solution: Verify tool path in server.py matches your FlareVM installation
Check: C:\Tools\sysinternals\Procmon.exe
```

**Problem**: "Permission denied" on file operations
```
Solution: Ensure running WinRM as user with appropriate permissions
Run: whoami on FlareVM
```

## Security Considerations

### Isolation
- Always run FlareVM on isolated network (no internet unless needed)
- Use separate credentials for analysis vs. production systems
- Snapshot FlareVM before executing unknown binaries

### Credential Management
- Use system keyring (not hardcoded passwords)
- Rotate credentials regularly
- Use least-privilege user account for WinRM

### Network Security
- Restrict WinRM to trusted networks only
- Use VPN if connecting over untrusted networks
- Monitor WinRM traffic for anomalies

### Malware Safety
- **NEVER** execute unknown binaries on host machine
- **ALWAYS** use FlareVM for suspected malware
- Verify VM snapshots before behavioral analysis
- Use FakeNet for network-connected malware

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for new functionality
4. Update documentation
5. Submit pull request

## License

This project is provided as-is for security research and malware analysis purposes.

## References

- [FlareVM GitHub](https://github.com/mandiant/flare-vm)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [WinRM Documentation](https://docs.microsoft.com/en-us/windows/win32/winrm/about-windows-remote-management)
- [Frida Dynamic Instrumentation](https://frida.re/)
- [IDA Pro MCP Plugin](https://github.com/mandiant/ida-pro-mcp)

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review tool-specific documentation

---

**Last Updated**: 2025-11-20
**Version**: 0.1.0
