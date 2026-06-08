# YARA Rules Index

Default rules directory on FlareVM: `C:\Tools\yara_rules\`

## Recommended rule sources

| Source | URL | Coverage |
|--------|-----|----------|
| Florian Roth signature-base | https://github.com/Neo23x0/signature-base | APT, generic malware, webshells |
| YaraRules Project | https://github.com/Yara-Rules/rules | Broad community rules |
| Elastic Protections Artifacts | https://github.com/elastic/protections-artifacts | Modern threats |
| ReversingLabs YARA rules | https://github.com/reversinglabs/reversinglabs-yara-rules | Curated, low FP |
| InQuest awesome-yara | https://github.com/InQuest/awesome-yara | Meta-list |

## Family-specific rules to keep

- **Cobalt Strike** beacon detection (signature-base/yara/apt_cobaltbaltstrike.yar)
- **Metasploit** shellcode patterns
- **Loaders**: DonutLoader, Shellter, PEzor
- **Ransomware**: LockBit, BlackCat, Conti, Royal
- **Stealers**: RedLine, Raccoon, Vidar, LummaC2
- **RATs**: AsyncRAT, njRAT, QuasarRAT
- **Living-off-the-land** binaries (LOLBins) abuse rules

## Use via MCP

```
yara_scan(
    file_path="C:\\temp\\sample.bin",
    rules_dir="C:\\Tools\\yara_rules"
)
```

Returns list of rule matches with strings and metadata.

## Updating rules

```powershell
cd C:\Tools\yara_rules
git clone https://github.com/Neo23x0/signature-base
git clone https://github.com/Yara-Rules/rules yararules
```
