# Security Policy

## Security model

This MCP server bridges a **trusted analyst host** (Kali) to a **deliberately
hostile execution environment** (FlareVM). Treat them accordingly.

| Side | Trust | Notes |
|------|-------|-------|
| Kali (where this server runs) | Trusted | Never executes the malware. |
| FlareVM (target of WinRM)     | Hostile | Assume compromised after any detonation. Snapshot before, revert after. |

The boundary is enforced by:
- A separate VM with no shared filesystem (only an SMB share for file transfer).
- FakeNet running inside FlareVM so callbacks never reach the analyst LAN.
- No outbound routing from FlareVM to internet (host-only network strongly
  recommended).

## Credential handling

- The FlareVM password is read from the OS keyring (`keyring` library) under
  service name `flarevm`, username = the configured FlareVM user.
- Fallback is the `FLAREVM_PASSWORD` environment variable.
- The password is **never logged**, **never echoed**, and is not included in
  any tool response.
- If you see the password in a transcript, that is a bug — please report it.

## Input validation

- All PowerShell commands constructed from user input use single-quoted
  strings with `'` doubled to `''` (PowerShell escape). Helper:
  `_ps_escape(s)` and the inline `.replace('"', '`"')` for double-quoted
  contexts in the static-analysis handlers.
- File paths uploaded to FlareVM are basenamed before being concatenated to
  `C:\temp\` to prevent path traversal.

## FakeNet host protection

The default FakeNet config (`generate_fakenet_config()`) sets
`HostBlackList` to the analyst host IP, so even a misconfigured FakeNet
cannot intercept Kali traffic.

## Known limits

- WinRM is configured for `plaintext` transport over an isolated host-only
  network. **Do not expose the FlareVM WinRM port to any untrusted network.**
- The IDA proxy talks to `localhost:13337` on FlareVM only.

## Reporting a vulnerability

Open a private GitHub security advisory at
https://github.com/zixuantemp/flarevm-mcp/security/advisories/new

Please include:
- A description of the issue and the impact.
- Steps to reproduce.
- Affected version (`flarevm-mcp --version` or `git rev-parse HEAD`).
- Suggested fix if you have one.

We aim to acknowledge within 7 days and ship a fix or mitigation within 30.
