Install FlareVM following https://github-com.translate.goog/mandiant/flare-vm

Install IDA Pro (9+). Place in `C:\Tools\IDA Pro`

Install ida mcp plugin
```
pip install git+https://github.com/mrexodia/ida-pro-mcp
ida-pro-mcp --install
```
Replace code in `C:\Python313\Lib\site-packages\ida_pro_mcp\mcp-plugin.py` to auto start ida
From
```py
      def init(self):
          self.server = Server()
          hotkey = MCP.wanted_hotkey.replace("-", "+")
          if sys.platform == "darwin":
              hotkey = hotkey.replace("Alt", "Option")
          print(f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server")

```
To
```py
      def init(self):
          self.server = Server()
          hotkey = MCP.wanted_hotkey.replace("-", "+")
          if sys.platform == "darwin":
              hotkey = hotkey.replace("Alt", "Option")
          print(f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server")

          def auto_start_mcp():
              try:
                  self.server.start()
              except Exception as e:
                  print(f"[MCP] Auto-start failed: {e}")
              return -1

          ida_kernwin.register_timer(1000, auto_start_mcp)
          return idaapi.PLUGIN_KEEP
```


Setup SMB share folder
```
New-Item -ItemType Directory -Force -Path C:\temp | Out-Null; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareWks -Type DWord -Value 1; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareServer -Type DWord -Value 1; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Type DWord -Value 1; Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"; Restart-Service LanmanServer -Force
```

Insall module pefile
```
pip install pefile
```

Setup yara rule
https://github.com/HuyThang25/flarevm-mcp/blob/main/resources/yara-rules-index.md
