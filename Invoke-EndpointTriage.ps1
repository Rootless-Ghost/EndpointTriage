<#
.SYNOPSIS
    Invoke-EndpointTriage.ps1 — Automated forensic artifact collector for Windows endpoint triage.

.DESCRIPTION
    Collects volatile and non-volatile forensic artifacts from a Windows endpoint during
    incident response. Outputs a structured triage package with individual CSV/TXT files
    and a consolidated HTML summary report.

    Artifact Categories:
      - System Information & Uptime
      - Running Processes (with hashes, paths, command lines, owners)
      - Network Connections (with owning process resolution)
      - Scheduled Tasks (filtered to non-Microsoft)
      - Startup & Persistence Items (Run keys, services, startup folder)
      - Registry Persistence Checks (MITRE ATT&CK T1547, T1053, T1546)
      - Recent File Modifications (configurable lookback window)
      - Windows Event Log Extraction (Security, System, PowerShell, Sysmon)
      - Local Users & Group Membership
      - DNS Cache Snapshot
      - Loaded Drivers
      - Named Pipes (common C2 indicator)
      - ARP Table

.PARAMETER OutputPath
    Base directory for triage output. Defaults to .\TriageOutput.

.PARAMETER HoursBack
    Lookback window in hours for recent file modifications and event logs. Default: 24.

.PARAMETER EventLogLimit
    Maximum number of events to pull per log source. Default: 200.

.PARAMETER SkipEventLogs
    Skip event log collection (faster triage when logs aren't needed).

.PARAMETER SkipHashing
    Skip file hash computation for processes (faster but less forensic value).

.EXAMPLE
    .\Invoke-EndpointTriage.ps1
    Runs full triage with defaults, outputs to .\TriageOutput\<hostname>_<timestamp>\

.EXAMPLE
    .\Invoke-EndpointTriage.ps1 -HoursBack 48 -OutputPath "D:\IR\Cases"
    Collects artifacts with a 48-hour lookback window, outputs to D:\IR\Cases\

.EXAMPLE
    .\Invoke-EndpointTriage.ps1 -SkipEventLogs -SkipHashing
    Fast triage — skips event logs and process hashing for speed.

.NOTES
    Author  : Nebula (Rootless-Ghost)
    Tool    : EndpointTriage
    Version : 1.0.0
    License : MIT
    GitHub  : https://github.com/Rootless-Ghost/EndpointTriage

    Requires: Run as Administrator for full artifact collection.
    Some artifacts (event logs, process owners) require elevated privileges.
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Base directory for triage output")]
    [string]$OutputPath = ".\TriageOutput",

    [Parameter(HelpMessage = "Lookback window in hours for recent artifacts")]
    [ValidateRange(1, 720)]
    [int]$HoursBack = 24,

    [Parameter(HelpMessage = "Max events per log source")]
    [ValidateRange(10, 5000)]
    [int]$EventLogLimit = 200,

    [Parameter(HelpMessage = "Skip event log collection")]
    [switch]$SkipEventLogs,

    [Parameter(HelpMessage = "Skip process file hashing")]
    [switch]$SkipHashing
)

# ============================================================================
# CONFIGURATION & SETUP
# ============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# Triage metadata
$TriageStart = Get-Date
$Hostname = $env:COMPUTERNAME
$Timestamp = $TriageStart.ToString("yyyyMMdd_HHmmss")
$CasePath = Join-Path $OutputPath "${Hostname}_${Timestamp}"
$LookbackTime = $TriageStart.AddHours(-$HoursBack)

# Create output directory structure
$Dirs = @{
    Root       = $CasePath
    Processes  = Join-Path $CasePath "processes"
    Network    = Join-Path $CasePath "network"
    Persistence = Join-Path $CasePath "persistence"
    EventLogs  = Join-Path $CasePath "eventlogs"
    FileSystem = Join-Path $CasePath "filesystem"
    System     = Join-Path $CasePath "system"
}

foreach ($dir in $Dirs.Values) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# Collection tracking
$CollectionResults = [System.Collections.ArrayList]::new()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-TriageBanner {
    $banner = @"

    ╔══════════════════════════════════════════════════════════════╗
    ║              EndpointTriage v1.0.0                          ║
    ║              Windows Forensic Artifact Collector            ║
    ║              github.com/Rootless-Ghost/EndpointTriage       ║
    ╚══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Write-Phase {
    param([string]$Name, [string]$Description)
    Write-Host "`n[*] " -ForegroundColor Yellow -NoNewline
    Write-Host "$Name" -ForegroundColor White -NoNewline
    Write-Host " — $Description" -ForegroundColor Gray
}

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $color = switch ($Type) {
        "OK"    { "Green" }
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        default { "Gray" }
    }
    Write-Host "    [$Type] " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Add-CollectionResult {
    param(
        [string]$Category,
        [string]$Artifact,
        [string]$Status,
        [int]$Count = 0,
        [string]$File = ""
    )
    $null = $CollectionResults.Add([PSCustomObject]@{
        Category  = $Category
        Artifact  = $Artifact
        Status    = $Status
        Count     = $Count
        File      = $File
        Timestamp = (Get-Date).ToString("HH:mm:ss")
    })
}

function Get-SafeHash {
    param([string]$FilePath)
    if ($SkipHashing) { return "SKIPPED" }
    try {
        if (Test-Path $FilePath -ErrorAction SilentlyContinue) {
            return (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
        }
        return "FILE_NOT_FOUND"
    }
    catch {
        return "ACCESS_DENIED"
    }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================================================
# PHASE 1: SYSTEM INFORMATION
# ============================================================================

function Get-SystemInformation {
    Write-Phase "Phase 1" "System Information & Environment"

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $bios = Get-CimInstance -ClassName Win32_BIOS
        $tz = Get-TimeZone
        $uptime = (Get-Date) - $os.LastBootUpTime

        $sysInfo = [PSCustomObject]@{
            Hostname           = $Hostname
            Domain             = $cs.Domain
            OSName             = $os.Caption
            OSVersion          = $os.Version
            OSBuild            = $os.BuildNumber
            Architecture       = $os.OSArchitecture
            InstallDate        = $os.InstallDate
            LastBoot           = $os.LastBootUpTime
            Uptime             = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
            CurrentUser        = $env:USERNAME
            SystemManufacturer = $cs.Manufacturer
            SystemModel        = $cs.Model
            SerialNumber       = $bios.SerialNumber
            TotalMemoryGB      = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            TimeZone           = $tz.Id
            UTCOffset          = $tz.BaseUtcOffset.ToString()
            TriageTimestamp     = $TriageStart.ToString("yyyy-MM-dd HH:mm:ss")
            TriageUser         = "$env:USERDOMAIN\$env:USERNAME"
            IsAdmin            = Test-IsAdmin
            PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
        }

        $outFile = Join-Path $Dirs.System "system_info.csv"
        $sysInfo | Export-Csv -Path $outFile -NoTypeInformation
        Add-CollectionResult "System" "System Information" "OK" 1 "system/system_info.csv"
        Write-Status "Collected system info — Up $($uptime.Days)d $($uptime.Hours)h, $($os.Caption)" "OK"

        # Environment variables (can reveal persistence or suspicious paths)
        $envFile = Join-Path $Dirs.System "environment_variables.csv"
        Get-ChildItem Env: | Select-Object Name, Value |
            Export-Csv -Path $envFile -NoTypeInformation
        Add-CollectionResult "System" "Environment Variables" "OK" (Get-ChildItem Env:).Count "system/environment_variables.csv"
        Write-Status "Captured environment variables" "OK"

        return $sysInfo
    }
    catch {
        Write-Status "Failed to collect system info: $_" "ERROR"
        Add-CollectionResult "System" "System Information" "ERROR"
        return $null
    }
}

# ============================================================================
# PHASE 2: RUNNING PROCESSES
# ============================================================================

function Get-ProcessArtifacts {
    Write-Phase "Phase 2" "Running Processes (with hashes, owners, command lines)"

    try {
        $processes = Get-CimInstance -ClassName Win32_Process | ForEach-Object {
            $proc = $_
            $owner = try {
                $ownerInfo = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction Stop
                if ($ownerInfo.Domain -and $ownerInfo.User) {
                    "$($ownerInfo.Domain)\$($ownerInfo.User)"
                } else { "N/A" }
            } catch { "ACCESS_DENIED" }

            $hash = if ($proc.ExecutablePath) {
                Get-SafeHash -FilePath $proc.ExecutablePath
            } else { "NO_PATH" }

            # Flag suspicious characteristics
            $suspicious = [System.Collections.ArrayList]::new()
            if ($proc.ExecutablePath -and $proc.ExecutablePath -match '\\(Temp|tmp|AppData\\Local\\Temp|Downloads)\\') {
                $null = $suspicious.Add("TEMP_EXEC")
            }
            if ($proc.ExecutablePath -and $proc.ExecutablePath -match '\\Users\\Public\\') {
                $null = $suspicious.Add("PUBLIC_DIR")
            }
            if ($proc.CommandLine -and $proc.CommandLine -match '(-enc|-encodedcommand|frombase64|iex|invoke-expression)') {
                $null = $suspicious.Add("SUSPICIOUS_CLI")
            }
            if ($proc.ParentProcessId -and $proc.Name -match '^(cmd|powershell|pwsh)\.exe$') {
                $parentProc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($proc.ParentProcessId)" -ErrorAction SilentlyContinue
                if ($parentProc -and $parentProc.Name -match '(winword|excel|outlook|onenote)\.exe') {
                    $null = $suspicious.Add("OFFICE_CHILD")
                }
            }

            [PSCustomObject]@{
                PID           = $proc.ProcessId
                PPID          = $proc.ParentProcessId
                Name          = $proc.Name
                Path          = $proc.ExecutablePath
                CommandLine   = $proc.CommandLine
                Owner         = $owner
                SHA256        = $hash
                CreationDate  = $proc.CreationDate
                WorkingSetMB  = [math]::Round($proc.WorkingSetSize / 1MB, 2)
                ThreadCount   = $proc.ThreadCount
                HandleCount   = $proc.HandleCount
                Flags         = ($suspicious -join "; ")
            }
        }

        $outFile = Join-Path $Dirs.Processes "running_processes.csv"
        $processes | Export-Csv -Path $outFile -NoTypeInformation

        $flaggedCount = ($processes | Where-Object { $_.Flags -ne "" }).Count
        Add-CollectionResult "Processes" "Running Processes" "OK" $processes.Count "processes/running_processes.csv"
        Write-Status "Captured $($processes.Count) processes ($flaggedCount flagged)" "OK"

        # Process tree (parent-child relationships)
        $treeFile = Join-Path $Dirs.Processes "process_tree.txt"
        $procLookup = @{}
        foreach ($p in $processes) { $procLookup[$p.PID] = $p }

        $treeOutput = [System.Text.StringBuilder]::new()
        $null = $treeOutput.AppendLine("# Process Tree — $Hostname @ $($TriageStart.ToString('yyyy-MM-dd HH:mm:ss'))")
        $null = $treeOutput.AppendLine("# Format: PID | Name | Owner | Path")
        $null = $treeOutput.AppendLine("#" + "=" * 80)

        $rootProcs = $processes | Where-Object {
            -not $procLookup.ContainsKey($_.PPID) -or $_.PID -eq 0
        } | Sort-Object Name

        foreach ($root in $rootProcs) {
            $null = $treeOutput.AppendLine("`n[$($root.PID)] $($root.Name) — $($root.Owner)")
            $children = $processes | Where-Object { $_.PPID -eq $root.PID -and $_.PID -ne $root.PID } | Sort-Object Name
            foreach ($child in $children) {
                $flag = if ($child.Flags) { " *** $($child.Flags)" } else { "" }
                $null = $treeOutput.AppendLine("  ├── [$($child.PID)] $($child.Name) — $($child.Owner)$flag")
                $grandchildren = $processes | Where-Object { $_.PPID -eq $child.PID -and $_.PID -ne $child.PID } | Sort-Object Name
                foreach ($gc in $grandchildren) {
                    $gcFlag = if ($gc.Flags) { " *** $($gc.Flags)" } else { "" }
                    $null = $treeOutput.AppendLine("  │   ├── [$($gc.PID)] $($gc.Name) — $($gc.Owner)$gcFlag")
                }
            }
        }

        Set-Content -Path $treeFile -Value $treeOutput.ToString()
        Add-CollectionResult "Processes" "Process Tree" "OK" $rootProcs.Count "processes/process_tree.txt"
        Write-Status "Built process tree" "OK"

        return $processes
    }
    catch {
        Write-Status "Process collection error: $_" "ERROR"
        Add-CollectionResult "Processes" "Running Processes" "ERROR"
        return @()
    }
}

# ============================================================================
# PHASE 3: NETWORK CONNECTIONS
# ============================================================================

function Get-NetworkArtifacts {
    Write-Phase "Phase 3" "Network Connections, DNS Cache & ARP"

    try {
        # Active TCP connections
        $connections = Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            $conn = $_
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue

            [PSCustomObject]@{
                LocalAddress   = $conn.LocalAddress
                LocalPort      = $conn.LocalPort
                RemoteAddress  = $conn.RemoteAddress
                RemotePort     = $conn.RemotePort
                State          = $conn.State
                PID            = $conn.OwningProcess
                ProcessName    = if ($proc) { $proc.Name } else { "UNKNOWN" }
                ProcessPath    = if ($proc) { $proc.Path } else { "N/A" }
                CreationTime   = $conn.CreationTime
            }
        }

        $outFile = Join-Path $Dirs.Network "tcp_connections.csv"
        $connections | Export-Csv -Path $outFile -NoTypeInformation

        $established = ($connections | Where-Object { $_.State -eq "Established" }).Count
        $listening = ($connections | Where-Object { $_.State -eq "Listen" }).Count
        Add-CollectionResult "Network" "TCP Connections" "OK" $connections.Count "network/tcp_connections.csv"
        Write-Status "Captured $($connections.Count) TCP connections ($established established, $listening listening)" "OK"

        # UDP endpoints
        $udp = Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort    = $_.LocalPort
                PID          = $_.OwningProcess
                ProcessName  = if ($proc) { $proc.Name } else { "UNKNOWN" }
            }
        }

        $udpFile = Join-Path $Dirs.Network "udp_endpoints.csv"
        $udp | Export-Csv -Path $udpFile -NoTypeInformation
        Add-CollectionResult "Network" "UDP Endpoints" "OK" $udp.Count "network/udp_endpoints.csv"
        Write-Status "Captured $($udp.Count) UDP endpoints" "OK"

        # DNS cache
        $dnsFile = Join-Path $Dirs.Network "dns_cache.csv"
        try {
            $dns = Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, RecordName, RecordType, Status, Data, TimeToLive
            $dns | Export-Csv -Path $dnsFile -NoTypeInformation
            Add-CollectionResult "Network" "DNS Cache" "OK" $dns.Count "network/dns_cache.csv"
            Write-Status "Captured $($dns.Count) DNS cache entries" "OK"
        }
        catch {
            Write-Status "DNS cache collection failed: $_" "WARN"
            Add-CollectionResult "Network" "DNS Cache" "WARN"
        }

        # ARP table
        $arpFile = Join-Path $Dirs.Network "arp_table.csv"
        try {
            $arp = Get-NetNeighbor -ErrorAction Stop | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias
            $arp | Export-Csv -Path $arpFile -NoTypeInformation
            Add-CollectionResult "Network" "ARP Table" "OK" $arp.Count "network/arp_table.csv"
            Write-Status "Captured $($arp.Count) ARP entries" "OK"
        }
        catch {
            Write-Status "ARP collection failed: $_" "WARN"
            Add-CollectionResult "Network" "ARP Table" "WARN"
        }

        # Network adapter configuration
        $adapterFile = Join-Path $Dirs.Network "network_adapters.csv"
        Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed |
            Export-Csv -Path $adapterFile -NoTypeInformation
        Add-CollectionResult "Network" "Network Adapters" "OK" (Get-NetAdapter).Count "network/network_adapters.csv"

        return $connections
    }
    catch {
        Write-Status "Network collection error: $_" "ERROR"
        Add-CollectionResult "Network" "TCP Connections" "ERROR"
        return @()
    }
}

# ============================================================================
# PHASE 4: SCHEDULED TASKS
# ============================================================================

function Get-ScheduledTaskArtifacts {
    Write-Phase "Phase 4" "Scheduled Tasks (non-Microsoft filtered)"

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.TaskName -notmatch '^(User_Feed|OneDrive|MicrosoftEdge)'
        } | ForEach-Object {
            $task = $_
            $info = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue

            [PSCustomObject]@{
                TaskName       = $task.TaskName
                TaskPath       = $task.TaskPath
                State          = $task.State
                Author         = $task.Author
                Description    = $task.Description
                Actions        = ($task.Actions | ForEach-Object {
                    if ($_.Execute) { "$($_.Execute) $($_.Arguments)" } else { "N/A" }
                }) -join " | "
                Triggers       = ($task.Triggers | ForEach-Object { $_.ToString() }) -join " | "
                LastRunTime    = if ($info) { $info.LastRunTime } else { "N/A" }
                NextRunTime    = if ($info) { $info.NextRunTime } else { "N/A" }
                LastResult     = if ($info) { $info.LastTaskResult } else { "N/A" }
                RunAsUser      = $task.Principal.UserId
                RunLevel       = $task.Principal.RunLevel
            }
        }

        $outFile = Join-Path $Dirs.Persistence "scheduled_tasks.csv"
        $tasks | Export-Csv -Path $outFile -NoTypeInformation
        Add-CollectionResult "Persistence" "Scheduled Tasks" "OK" $tasks.Count "persistence/scheduled_tasks.csv"
        Write-Status "Found $($tasks.Count) non-Microsoft scheduled tasks" "OK"

        return $tasks
    }
    catch {
        Write-Status "Scheduled task collection error: $_" "ERROR"
        Add-CollectionResult "Persistence" "Scheduled Tasks" "ERROR"
        return @()
    }
}

# ============================================================================
# PHASE 5: PERSISTENCE MECHANISMS
# ============================================================================

function Get-PersistenceArtifacts {
    Write-Phase "Phase 5" "Registry Persistence & Startup Items (ATT&CK T1547/T1546)"

    $persistence = [System.Collections.ArrayList]::new()

    # Registry Run keys — most common persistence vector
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    )

    foreach ($key in $runKeys) {
        try {
            if (Test-Path $key) {
                $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                $props.PSObject.Properties | Where-Object {
                    $_.Name -notmatch '^(PS|$)'
                } | ForEach-Object {
                    $null = $persistence.Add([PSCustomObject]@{
                        Category    = "Registry Run Key"
                        Location    = $key
                        Name        = $_.Name
                        Value       = $_.Value
                        ATTACKRef   = "T1547.001"
                    })
                }
            }
        }
        catch {
            Write-Status "Cannot read $key" "WARN"
        }
    }

    # Services — T1543.003
    try {
        $services = Get-CimInstance -ClassName Win32_Service | Where-Object {
            $_.PathName -and $_.PathName -notmatch '(System32|SysWOW64)\\(svchost|services|lsass|wininit)'
        } | ForEach-Object {
            $null = $persistence.Add([PSCustomObject]@{
                Category    = "Service"
                Location    = "Services"
                Name        = "$($_.Name) [$($_.StartMode)]"
                Value       = $_.PathName
                ATTACKRef   = "T1543.003"
            })
        }
    }
    catch {
        Write-Status "Service enumeration failed: $_" "WARN"
    }

    # Startup folder items
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($sp in $startupPaths) {
        if (Test-Path $sp) {
            Get-ChildItem -Path $sp -ErrorAction SilentlyContinue | ForEach-Object {
                $null = $persistence.Add([PSCustomObject]@{
                    Category    = "Startup Folder"
                    Location    = $sp
                    Name        = $_.Name
                    Value       = $_.FullName
                    ATTACKRef   = "T1547.001"
                })
            }
        }
    }

    # WMI event subscriptions — T1546.003
    try {
        $wmiSubs = Get-CimInstance -Namespace "root\subscription" -ClassName __EventConsumer -ErrorAction Stop
        foreach ($sub in $wmiSubs) {
            $null = $persistence.Add([PSCustomObject]@{
                Category    = "WMI Event Subscription"
                Location    = "root\subscription"
                Name        = $sub.Name
                Value       = if ($sub.CommandLineTemplate) { $sub.CommandLineTemplate } else { $sub.ScriptText }
                ATTACKRef   = "T1546.003"
            })
        }
    }
    catch {
        Write-Status "WMI subscription check failed (may need admin)" "WARN"
    }

    # Image File Execution Options — T1546.012 (debugger hijacking)
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $ifeoPath) {
        Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {
            $debugger = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($debugger) {
                $null = $persistence.Add([PSCustomObject]@{
                    Category    = "IFEO Debugger"
                    Location    = $_.PSPath
                    Name        = $_.PSChildName
                    Value       = $debugger
                    ATTACKRef   = "T1546.012"
                })
            }
        }
    }

    # AppInit_DLLs — T1546.010
    $appInitPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )
    foreach ($aip in $appInitPaths) {
        try {
            if (Test-Path $aip) {
                $val = (Get-ItemProperty -Path $aip -ErrorAction SilentlyContinue).AppInit_DLLs
                if ($val -and $val.Trim() -ne "") {
                    $null = $persistence.Add([PSCustomObject]@{
                        Category    = "AppInit_DLLs"
                        Location    = $aip
                        Name        = "AppInit_DLLs"
                        Value       = $val
                        ATTACKRef   = "T1546.010"
                    })
                }
            }
        }
        catch {}
    }

    $outFile = Join-Path $Dirs.Persistence "persistence_items.csv"
    $persistence | Export-Csv -Path $outFile -NoTypeInformation
    Add-CollectionResult "Persistence" "Persistence Mechanisms" "OK" $persistence.Count "persistence/persistence_items.csv"
    Write-Status "Found $($persistence.Count) persistence items across registry, services, startup, WMI, IFEO" "OK"

    return $persistence
}

# ============================================================================
# PHASE 6: RECENT FILE MODIFICATIONS
# ============================================================================

function Get-RecentFileArtifacts {
    Write-Phase "Phase 6" "Recent File Modifications (last ${HoursBack}h)"

    $suspiciousDirs = @(
        "$env:TEMP",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:PUBLIC",
        "$env:APPDATA",
        "$env:LOCALAPPDATA\Temp",
        "$env:ProgramData",
        "C:\Windows\Temp"
    )

    $suspiciousExtensions = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta',
                              '.scr', '.pif', '.wsf', '.msi', '.jar', '.lnk', '.iso', '.img')

    $recentFiles = [System.Collections.ArrayList]::new()

    foreach ($dir in $suspiciousDirs) {
        if (-not (Test-Path $dir)) { continue }

        try {
            Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue -Depth 3 |
                Where-Object { $_.LastWriteTime -ge $LookbackTime } |
                ForEach-Object {
                    $isSuspiciousExt = $_.Extension -in $suspiciousExtensions
                    $null = $recentFiles.Add([PSCustomObject]@{
                        FullPath       = $_.FullName
                        Name           = $_.Name
                        Extension      = $_.Extension
                        SizeKB         = [math]::Round($_.Length / 1KB, 2)
                        Created        = $_.CreationTime
                        Modified       = $_.LastWriteTime
                        Accessed       = $_.LastAccessTime
                        Directory      = $_.DirectoryName
                        SuspiciousExt  = $isSuspiciousExt
                        Hidden         = $_.Attributes -band [System.IO.FileAttributes]::Hidden
                    })
                }
        }
        catch {
            Write-Status "Cannot scan $dir — $_" "WARN"
        }
    }

    $outFile = Join-Path $Dirs.FileSystem "recent_file_modifications.csv"
    $recentFiles | Sort-Object Modified -Descending | Export-Csv -Path $outFile -NoTypeInformation

    $suspCount = ($recentFiles | Where-Object { $_.SuspiciousExt }).Count
    Add-CollectionResult "FileSystem" "Recent File Mods" "OK" $recentFiles.Count "filesystem/recent_file_modifications.csv"
    Write-Status "Found $($recentFiles.Count) recently modified files ($suspCount with suspicious extensions)" "OK"

    return $recentFiles
}

# ============================================================================
# PHASE 7: EVENT LOG EXTRACTION
# ============================================================================

function Get-EventLogArtifacts {
    if ($SkipEventLogs) {
        Write-Phase "Phase 7" "Event Logs — SKIPPED (flag set)"
        Add-CollectionResult "EventLogs" "Event Logs" "SKIPPED"
        return
    }

    Write-Phase "Phase 7" "Event Log Extraction (last ${HoursBack}h, limit ${EventLogLimit}/source)"

    if (-not (Test-IsAdmin)) {
        Write-Status "Not running as admin — event log access may be limited" "WARN"
    }

    # Target event IDs mapped to ATT&CK
    $logQueries = @(
        @{
            LogName  = "Security"
            IDs      = @(4624, 4625, 4648, 4672, 4688, 4689, 4697, 4698, 4699, 4702, 4720, 4722, 4724, 4728, 4732, 4756, 1102)
            Desc     = "Logons, process creation, privilege use, account changes, log cleared"
        },
        @{
            LogName  = "System"
            IDs      = @(7045, 7040, 7034, 7036, 1001, 1014, 6005, 6006, 6008)
            Desc     = "Service installs, crashes, DNS failures, boot events"
        },
        @{
            LogName  = "Microsoft-Windows-PowerShell/Operational"
            IDs      = @(4103, 4104, 4105, 4106)
            Desc     = "Script block logging, module logging"
        },
        @{
            LogName  = "Microsoft-Windows-Sysmon/Operational"
            IDs      = @(1, 3, 7, 8, 10, 11, 12, 13, 15, 22, 23, 25)
            Desc     = "Process create, network, image load, registry, DNS, file delete"
        },
        @{
            LogName  = "Microsoft-Windows-Windows Defender/Operational"
            IDs      = @(1006, 1007, 1008, 1009, 1116, 1117, 1118, 1119)
            Desc     = "Malware detection, remediation actions"
        }
    )

    foreach ($query in $logQueries) {
        $safeName = $query.LogName -replace '[/\\]', '_'
        try {
            $filterHash = @{
                LogName   = $query.LogName
                ID        = $query.IDs
                StartTime = $LookbackTime
            }

            $events = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $EventLogLimit -ErrorAction Stop |
                Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message,
                    @{N='RecordId'; E={$_.RecordId}},
                    @{N='UserId'; E={$_.UserId?.Value}}

            $outFile = Join-Path $Dirs.EventLogs "${safeName}.csv"
            $events | Export-Csv -Path $outFile -NoTypeInformation
            Add-CollectionResult "EventLogs" $query.LogName "OK" $events.Count "eventlogs/${safeName}.csv"
            Write-Status "$($query.LogName): $($events.Count) events — $($query.Desc)" "OK"
        }
        catch [System.Exception] {
            if ($_.Exception.Message -match "No events were found") {
                Write-Status "$($query.LogName): No matching events in window" "INFO"
                Add-CollectionResult "EventLogs" $query.LogName "EMPTY" 0
            }
            elseif ($_.Exception.Message -match "Could not find") {
                Write-Status "$($query.LogName): Log source not present" "WARN"
                Add-CollectionResult "EventLogs" $query.LogName "NOT_FOUND" 0
            }
            else {
                Write-Status "$($query.LogName): $($_.Exception.Message)" "WARN"
                Add-CollectionResult "EventLogs" $query.LogName "ERROR" 0
            }
        }
    }
}

# ============================================================================
# PHASE 8: USER & GROUP ENUMERATION
# ============================================================================

function Get-UserArtifacts {
    Write-Phase "Phase 8" "Local Users & Group Membership"

    try {
        $users = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, LastLogon,
            PasswordLastSet, PasswordRequired, PasswordExpires, SID, Description

        $outFile = Join-Path $Dirs.System "local_users.csv"
        $users | Export-Csv -Path $outFile -NoTypeInformation
        Add-CollectionResult "System" "Local Users" "OK" $users.Count "system/local_users.csv"
        Write-Status "Found $($users.Count) local user accounts" "OK"

        # Group membership for key groups
        $groups = @("Administrators", "Remote Desktop Users", "Remote Management Users",
                    "Backup Operators", "Hyper-V Administrators")
        $groupMembers = [System.Collections.ArrayList]::new()

        foreach ($group in $groups) {
            try {
                $members = Get-LocalGroupMember -Group $group -ErrorAction Stop
                foreach ($m in $members) {
                    $null = $groupMembers.Add([PSCustomObject]@{
                        Group       = $group
                        Name        = $m.Name
                        ObjectClass = $m.ObjectClass
                        SID         = $m.SID
                    })
                }
            }
            catch {}
        }

        $groupFile = Join-Path $Dirs.System "group_membership.csv"
        $groupMembers | Export-Csv -Path $groupFile -NoTypeInformation
        Add-CollectionResult "System" "Group Membership" "OK" $groupMembers.Count "system/group_membership.csv"
        Write-Status "Enumerated membership for privileged groups" "OK"
    }
    catch {
        Write-Status "User enumeration failed: $_" "ERROR"
        Add-CollectionResult "System" "Local Users" "ERROR"
    }
}

# ============================================================================
# PHASE 9: ADDITIONAL ARTIFACTS
# ============================================================================

function Get-AdditionalArtifacts {
    Write-Phase "Phase 9" "Drivers, Named Pipes & Additional Indicators"

    # Loaded drivers
    try {
        $drivers = Get-CimInstance -ClassName Win32_SystemDriver | Select-Object Name, DisplayName,
            PathName, State, StartMode, Description
        $driverFile = Join-Path $Dirs.System "loaded_drivers.csv"
        $drivers | Export-Csv -Path $driverFile -NoTypeInformation
        Add-CollectionResult "System" "Loaded Drivers" "OK" $drivers.Count "system/loaded_drivers.csv"
        Write-Status "Captured $($drivers.Count) loaded drivers" "OK"
    }
    catch {
        Write-Status "Driver enumeration failed: $_" "WARN"
        Add-CollectionResult "System" "Loaded Drivers" "WARN"
    }

    # Named pipes — common C2/lateral movement indicator
    try {
        $pipes = Get-ChildItem -Path "\\.\pipe\" -ErrorAction Stop | Select-Object Name
        $pipeFile = Join-Path $Dirs.Network "named_pipes.csv"
        $pipes | Export-Csv -Path $pipeFile -NoTypeInformation

        # Flag known-suspicious pipe names
        $suspPipes = $pipes | Where-Object {
            $_.Name -match '(cobaltstrike|beacon|meterpreter|psexec|msagent_|postex_|status_|MSSE-|win_svc|ntsvcs|DserNamePipe|SearchTextHarvester|msrpc_|winsock)'
        }
        if ($suspPipes) {
            Write-Status "ALERT: $($suspPipes.Count) potentially suspicious named pipes detected!" "WARN"
        }

        Add-CollectionResult "Network" "Named Pipes" "OK" $pipes.Count "network/named_pipes.csv"
        Write-Status "Captured $($pipes.Count) named pipes" "OK"
    }
    catch {
        Write-Status "Named pipe enumeration failed: $_" "WARN"
        Add-CollectionResult "Network" "Named Pipes" "WARN"
    }

    # Firewall rules
    try {
        $fwRules = Get-NetFirewallRule -Enabled True -ErrorAction Stop |
            Select-Object DisplayName, Direction, Action, Profile, Description
        $fwFile = Join-Path $Dirs.Network "firewall_rules.csv"
        $fwRules | Export-Csv -Path $fwFile -NoTypeInformation
        Add-CollectionResult "Network" "Firewall Rules" "OK" $fwRules.Count "network/firewall_rules.csv"
        Write-Status "Captured $($fwRules.Count) active firewall rules" "OK"
    }
    catch {
        Write-Status "Firewall rule export failed: $_" "WARN"
        Add-CollectionResult "Network" "Firewall Rules" "WARN"
    }
}

# ============================================================================
# PHASE 10: HTML SUMMARY REPORT
# ============================================================================

function New-TriageReport {
    Write-Phase "Phase 10" "Generating HTML Triage Report"

    $TriageEnd = Get-Date
    $Duration = $TriageEnd - $TriageStart

    $reportHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Endpoint Triage Report — $Hostname</title>
    <style>
        :root {
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --green: #3fb950;
            --yellow: #d29922;
            --red: #f85149;
            --orange: #db6d28;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            border: 1px solid var(--border);
            background: var(--surface);
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        .header h1 {
            color: var(--accent);
            font-size: 1.8rem;
            margin-bottom: 0.5rem;
        }
        .header .meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 0.5rem;
            margin-top: 1rem;
            font-size: 0.9rem;
            color: var(--text-muted);
        }
        .meta span { display: block; }
        .meta strong { color: var(--text); }
        .section {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        .section h2 {
            background: rgba(88, 166, 255, 0.1);
            padding: 0.8rem 1.2rem;
            font-size: 1.1rem;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
        }
        .section-body { padding: 1.2rem; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        th {
            text-align: left;
            padding: 0.6rem 0.8rem;
            background: rgba(255, 255, 255, 0.04);
            border-bottom: 1px solid var(--border);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }
        td {
            padding: 0.5rem 0.8rem;
            border-bottom: 1px solid rgba(48, 54, 61, 0.5);
            word-break: break-all;
            max-width: 400px;
        }
        tr:hover { background: rgba(255, 255, 255, 0.02); }
        .status-ok { color: var(--green); font-weight: 600; }
        .status-warn { color: var(--yellow); font-weight: 600; }
        .status-error { color: var(--red); font-weight: 600; }
        .status-skipped { color: var(--text-muted); }
        .badge {
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 10px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .badge-red { background: rgba(248, 81, 73, 0.15); color: var(--red); }
        .badge-yellow { background: rgba(210, 153, 34, 0.15); color: var(--yellow); }
        .badge-green { background: rgba(63, 185, 80, 0.15); color: var(--green); }
        .footer {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
            margin-top: 2rem;
            padding: 1rem;
            border-top: 1px solid var(--border);
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Endpoint Triage Report</h1>
        <div class="meta">
            <span><strong>Hostname:</strong> $Hostname</span>
            <span><strong>Collection Start:</strong> $($TriageStart.ToString('yyyy-MM-dd HH:mm:ss'))</span>
            <span><strong>Duration:</strong> $($Duration.Minutes)m $($Duration.Seconds)s</span>
            <span><strong>Collected By:</strong> $env:USERDOMAIN\$env:USERNAME</span>
            <span><strong>Lookback Window:</strong> ${HoursBack} hours</span>
            <span><strong>Admin:</strong> $(if (Test-IsAdmin) { 'Yes' } else { 'No — some artifacts may be incomplete' })</span>
        </div>
    </div>

    <div class="section">
        <h2>Collection Summary</h2>
        <div class="section-body">
            <table>
                <thead>
                    <tr><th>Category</th><th>Artifact</th><th>Status</th><th>Count</th><th>File</th><th>Time</th></tr>
                </thead>
                <tbody>
"@

    foreach ($r in $CollectionResults) {
        $statusClass = switch ($r.Status) {
            "OK"    { "status-ok" }
            "WARN"  { "status-warn" }
            "ERROR" { "status-error" }
            default { "status-skipped" }
        }
        $reportHtml += @"
                    <tr>
                        <td>$($r.Category)</td>
                        <td>$($r.Artifact)</td>
                        <td class="$statusClass">$($r.Status)</td>
                        <td>$($r.Count)</td>
                        <td>$($r.File)</td>
                        <td>$($r.Timestamp)</td>
                    </tr>
"@
    }

    $reportHtml += @"
                </tbody>
            </table>
        </div>
    </div>

    <div class="footer">
        EndpointTriage v1.0.0 — github.com/Rootless-Ghost/EndpointTriage<br>
        Report generated $($TriageEnd.ToString('yyyy-MM-dd HH:mm:ss'))
    </div>
</div>
</body>
</html>
"@

    $reportPath = Join-Path $CasePath "triage_report.html"
    Set-Content -Path $reportPath -Value $reportHtml -Encoding UTF8
    Add-CollectionResult "Report" "HTML Summary" "OK" 1 "triage_report.html"
    Write-Status "Triage report saved to $reportPath" "OK"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-TriageBanner

Write-Host "  Hostname      : $Hostname" -ForegroundColor White
Write-Host "  Output Path   : $CasePath" -ForegroundColor White
Write-Host "  Lookback      : $HoursBack hours" -ForegroundColor White
Write-Host "  Admin Context : $(if (Test-IsAdmin) { 'YES' } else { 'NO — run as admin for full collection' })" -ForegroundColor $(if (Test-IsAdmin) { 'Green' } else { 'Yellow' })
Write-Host "  Skip Logs     : $SkipEventLogs" -ForegroundColor White
Write-Host "  Skip Hashing  : $SkipHashing" -ForegroundColor White
Write-Host "`n  Starting triage at $($TriageStart.ToString('yyyy-MM-dd HH:mm:ss'))..." -ForegroundColor Cyan

# Execute all phases
$sysInfo = Get-SystemInformation
$processes = Get-ProcessArtifacts
$connections = Get-NetworkArtifacts
$tasks = Get-ScheduledTaskArtifacts
$persistence = Get-PersistenceArtifacts
$recentFiles = Get-RecentFileArtifacts
Get-EventLogArtifacts
Get-UserArtifacts
Get-AdditionalArtifacts
New-TriageReport

# Final summary
$TriageEnd = Get-Date
$Duration = $TriageEnd - $TriageStart
$okCount = ($CollectionResults | Where-Object { $_.Status -eq "OK" }).Count
$warnCount = ($CollectionResults | Where-Object { $_.Status -eq "WARN" }).Count
$errCount = ($CollectionResults | Where-Object { $_.Status -eq "ERROR" }).Count
$totalArtifacts = ($CollectionResults | Measure-Object -Property Count -Sum).Sum

Write-Host "`n" + "=" * 66 -ForegroundColor Cyan
Write-Host "  TRIAGE COMPLETE" -ForegroundColor Green
Write-Host "=" * 66 -ForegroundColor Cyan
Write-Host "  Duration       : $($Duration.Minutes)m $($Duration.Seconds)s" -ForegroundColor White
Write-Host "  Total Artifacts: $totalArtifacts items across $($CollectionResults.Count) categories" -ForegroundColor White
Write-Host "  Status         : " -ForegroundColor White -NoNewline
Write-Host "$okCount OK " -ForegroundColor Green -NoNewline
Write-Host "$warnCount WARN " -ForegroundColor Yellow -NoNewline
Write-Host "$errCount ERROR" -ForegroundColor Red
Write-Host "  Output         : $CasePath" -ForegroundColor White
Write-Host "  Report         : $(Join-Path $CasePath 'triage_report.html')" -ForegroundColor Cyan
Write-Host "=" * 66 -ForegroundColor Cyan
Write-Host ""
