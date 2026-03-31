<div align="center">
    
# EndpointTriage

**Automated forensic artifact collector for Windows endpoint incident response.**

PowerShell-based triage script that collects volatile and non-volatile forensic artifacts from Windows endpoints, flags suspicious indicators, and outputs a structured triage package with an HTML summary report.

Built for SOC analysts and incident responders who need fast, repeatable endpoint collection without deploying heavyweight forensic suites.

</div>

---

## Artifact Collection

| Phase | Category | Artifacts Collected | ATT&CK Reference |
|-------|----------|-------------------|------------------|
| 1 | System Info | OS version, uptime, install date, hardware, environment variables | — |
| 2 | Processes | Running processes with hashes, command lines, owners, parent-child tree | — |
| 3 | Network | TCP connections, UDP endpoints, DNS cache, ARP table, adapters | — |
| 4 | Scheduled Tasks | Non-Microsoft tasks with actions, triggers, run-as context | T1053.005 |
| 5 | Persistence | Registry Run keys, services, startup folder, WMI subscriptions, IFEO, AppInit_DLLs | T1547.001, T1543.003, T1546.003, T1546.012, T1546.010 |
| 6 | File System | Recently modified files in key directories with suspicious extension flagging | — |
| 7 | Event Logs | Security, System, PowerShell, Sysmon, Defender — filtered to IR-relevant Event IDs | — |
| 8 | Users | Local accounts, privileged group membership | — |
| 9 | Additional | Loaded drivers, named pipes (C2 indicators), firewall rules | — |
| 10 | Report | Consolidated HTML triage report with collection summary | — |

## Suspicious Indicator Flags

The script automatically flags artifacts that commonly appear in compromises:

**Processes:**
- `TEMP_EXEC` — Process running from Temp/Downloads directories
- `PUBLIC_DIR` — Process running from `C:\Users\Public\`
- `SUSPICIOUS_CLI` — Encoded commands, `IEX`, `Invoke-Expression` in command line
- `OFFICE_CHILD` — `cmd.exe`/`powershell.exe` spawned by Office applications

**Named Pipes:**
- Known C2 framework pipe name patterns (Cobalt Strike, Meterpreter, PsExec)

**Files:**
- Suspicious extension detection (`.exe`, `.dll`, `.ps1`, `.bat`, `.hta`, `.iso`, etc.)
- Hidden file attribute flagging

## Quick Start

```powershell
# Full triage with defaults (24h lookback, all artifacts)
.\Invoke-EndpointTriage.ps1

# Custom lookback window and output path
.\Invoke-EndpointTriage.ps1 -HoursBack 48 -OutputPath "D:\IR\Cases"

# Fast mode — skip event logs and process hashing
.\Invoke-EndpointTriage.ps1 -SkipEventLogs -SkipHashing

# Limit event log extraction
.\Invoke-EndpointTriage.ps1 -EventLogLimit 500
```

**Requires:** Run as Administrator for full artifact collection. The script will still collect what it can without elevation, but event logs, WMI subscriptions, and some process owners will be incomplete.

## Output Structure

```
TriageOutput/
└── HOSTNAME_20260330_141500/
    ├── triage_report.html          # Consolidated HTML report
    ├── system/
    │   ├── system_info.csv
    │   ├── environment_variables.csv
    │   ├── local_users.csv
    │   ├── group_membership.csv
    │   └── loaded_drivers.csv
    ├── processes/
    │   ├── running_processes.csv    # Full process listing with hashes
    │   └── process_tree.txt         # Parent-child relationship map
    ├── network/
    │   ├── tcp_connections.csv
    │   ├── udp_endpoints.csv
    │   ├── dns_cache.csv
    │   ├── arp_table.csv
    │   ├── named_pipes.csv
    │   ├── network_adapters.csv
    │   └── firewall_rules.csv
    ├── persistence/
    │   ├── persistence_items.csv    # All persistence with ATT&CK mapping
    │   └── scheduled_tasks.csv
    ├── eventlogs/
    │   ├── Security.csv
    │   ├── System.csv
    │   ├── Microsoft-Windows-PowerShell_Operational.csv
    │   ├── Microsoft-Windows-Sysmon_Operational.csv
    │   └── Microsoft-Windows-Windows Defender_Operational.csv
    └── filesystem/
        └── recent_file_modifications.csv
```

## Event Log Coverage

Each log source targets specific Event IDs relevant to incident response:

| Log Source | Event IDs | Purpose |
|-----------|-----------|---------|
| Security | 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4728, 1102 | Logons, process creation, privilege use, account changes, log clearing |
| System | 7045, 7040, 7034, 1001, 1014, 6005, 6006, 6008 | Service installs, crashes, DNS failures, boot events |
| PowerShell | 4103, 4104, 4105, 4106 | Script block logging, module logging |
| Sysmon | 1, 3, 7, 8, 10, 11, 12, 13, 15, 22, 23, 25 | Process create, network, image load, registry, DNS, file ops |
| Defender | 1006–1009, 1116–1119 | Malware detection and remediation |

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-OutputPath` | String | `.\TriageOutput` | Base directory for triage output |
| `-HoursBack` | Int | `24` | Lookback window (1–720 hours) |
| `-EventLogLimit` | Int | `200` | Max events per log source (10–5000) |
| `-SkipEventLogs` | Switch | `$false` | Skip event log collection for faster triage |
| `-SkipHashing` | Switch | `$false` | Skip SHA256 hashing of process executables |

## Use Cases

- **SOC Triage:** First-response artifact collection when an alert fires on an endpoint
- **Purple Team Validation:** Verify that your detections and telemetry capture the expected artifacts after running attack simulations
- **Baseline Collection:** Capture a known-good state for comparison during future investigations
- **Forensic Preservation:** Collect volatile artifacts (processes, connections, DNS cache) before they're lost

## Roadmap

### v1.1 — Wazuh Integration
- [ ] `-WazuhExport` switch to ship triage findings as JSON to Wazuh server (syslog/1514)
- [ ] Custom Wazuh decoder + ruleset for EndpointTriage alert ingestion
- [ ] Active Response mode — Wazuh triggers triage automatically when a rule fires

### v1.2 — Enhanced Forensics
- [ ] Prefetch file collection and parsing
- [ ] Amcache / ShimCache extraction
- [ ] PowerShell ConsoleHost history capture (`ConsoleHost_history.txt`)
- [ ] Alternate Data Stream (ADS) detection on recent files
- [ ] Browser history extraction (Chrome, Edge, Firefox)

### v1.3 — Reporting & Analysis
- [ ] Sigma rule matching against collected event logs
- [ ] YARA scanning of flagged process executables (pairs with YaraForge)
- [ ] Timeline generation — merge all artifacts into a unified chronological view
- [ ] Differential triage — compare two triage packages to highlight changes (baseline vs incident)
- [ ] JSON export format for SIEM ingestion

### Future
- [ ] Remote collection mode (WinRM/PSRemoting to triage multiple endpoints)
- [ ] Linux triage module (auditd, cron, systemd, /proc enumeration)
- [ ] Integration with EndpointForge for continuous monitoring + on-demand triage workflow
- [ ] VirusTotal hash lookup for flagged process executables

## Dependencies

- Windows PowerShell 5.1+ or PowerShell 7+
- Administrator privileges recommended
- No external modules required — uses only built-in Windows cmdlets

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) for details. 

<div align="center">
    
## Author

**RG-Nebula** — [github.com/Rootless-Ghost](https://github.com/Rootless-Ghost)

</div>
