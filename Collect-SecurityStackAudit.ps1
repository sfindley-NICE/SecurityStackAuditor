<#
.SYNOPSIS
    Endpoint Security & Performance Stack Collector.

.DESCRIPTION
    Enumerates every running process on this machine, samples live CPU usage over a
    configurable window, classifies processes against a large table of known
    EDR / AV / VPN / DLP / PAM / MDM / log-forwarding vendors (falling back to a
    publisher-keyword heuristic for anything not explicitly mapped), and captures
    system info, registered AV/Firewall products, VPN-related network adapters, and
    security-related services.

    Output is a single well-structured JSON file (plus a companion CSV of the process
    table) designed to be handed to Claude for analysis -- e.g. "which security tools
    are overlapping / redundant on this machine, and what's the performance cost?"
    This mirrors the manual audit process used to produce the original
    "Endpoint Security Stack Audit" report, so any coworker can reproduce the same
    data collection without re-deriving the methodology by hand.

    Safe to run without elevation. Running "as Administrator" is recommended: several
    EDR/AV processes run as SYSTEM and block module (path/company/description) access
    from a non-elevated session, so an elevated run captures fuller metadata.

.PARAMETER SampleSeconds
    Total wall-clock duration of the live CPU sampling window. Default 30.

.PARAMETER SampleIntervalSeconds
    How often to sample within that window. Default 2. SampleSeconds / SampleIntervalSeconds
    determines how many samples are averaged.

.PARAMETER OutputDir
    Folder to write the JSON/CSV output to. Defaults to the current user's Desktop.

.PARAMETER IncludeAllProcesses
    By default, the JSON only includes processes matched to a known/heuristic security
    vendor, plus the top 25 non-matched processes by CPU and top 25 by RAM (for context
    on what else is competing for resources). Pass this switch to include every running
    process instead -- useful for deep-dives, but produces a much larger file.

.PARAMETER IncludeCommandLines
    By default, command lines are NOT captured, to avoid accidentally collecting secrets
    or tokens passed as arguments to arbitrary user applications. Pass this switch to
    additionally capture command lines, but ONLY for processes already classified as
    security-related (never for arbitrary/unmatched processes).

.PARAMETER Quiet
    Suppress the progress messages written to the console.

.EXAMPLE
    .\Collect-SecurityStackAudit.ps1
    Runs a default 30-second sample and writes JSON + CSV to the Desktop.

.EXAMPLE
    .\Collect-SecurityStackAudit.ps1 -SampleSeconds 60 -IncludeAllProcesses -OutputDir C:\Temp
    Longer sample, full process list, custom output folder.

.NOTES
    Privacy: this script reads process names, file paths, publisher/signer metadata,
    CPU/RAM usage, and (only when -IncludeCommandLines is passed) command lines of
    already-flagged security tools. It does not read file contents, browser history,
    documents, or credentials. Review the script before running it -- that's true of
    anything a coworker hands you.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#>
[CmdletBinding()]
param(
    [int]$SampleSeconds = 30,
    [int]$SampleIntervalSeconds = 2,
    [string]$OutputDir = (Join-Path $env:USERPROFILE 'Desktop'),
    [switch]$IncludeAllProcesses,
    [switch]$IncludeCommandLines,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$CollectionWarnings = New-Object System.Collections.Generic.List[string]

function Write-Status {
    param([string]$Message)
    if (-not $Quiet) { Write-Host $Message -ForegroundColor Cyan }
}

function Add-CollectionWarning {
    param([string]$Message)
    $CollectionWarnings.Add($Message) | Out-Null
    Write-Warning $Message
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Known security/management vendor process map.
# Pattern is matched case-insensitively against the bare process name (no .exe).
# ---------------------------------------------------------------------------
$VendorMap = @(
    # Microsoft Defender for Endpoint / Defender AV / DLP
    @{ Pattern = '^MsSense$';                                   Vendor = 'Microsoft';                     Product = 'Defender for Endpoint';        Category = 'EDR';               Role = 'EDR sensor' }
    @{ Pattern = '^MsMpEng$';                                   Vendor = 'Microsoft';                     Product = 'Defender Antivirus';           Category = 'AV';                Role = 'Real-time antimalware scan engine' }
    @{ Pattern = '^MpDlpService$';                              Vendor = 'Microsoft';                     Product = 'Defender / Purview DLP';       Category = 'DLP';               Role = 'Data-loss prevention' }
    @{ Pattern = '^(SenseTracer|SenseNdr|SenseCncProxy|SenseIR|MpDefenderCoreService)$'; Vendor = 'Microsoft'; Product = 'Defender for Endpoint';   Category = 'EDR';               Role = 'EDR submodule (tracing/network/IR)' }
    @{ Pattern = '^SecurityHealth(Service|Systray)$';           Vendor = 'Microsoft';                     Product = 'Windows Security';             Category = 'AV';                Role = 'Windows Security Center UI/health' }

    # Rapid7
    @{ Pattern = '^ir_agent$';                                  Vendor = 'Rapid7';                        Product = 'Insight Agent';                Category = 'EDR';               Role = 'Insight Agent core (EDR / vuln mgmt / log collection)' }
    @{ Pattern = '^Sysmon(64)?$';                                Vendor = 'Microsoft Sysinternals (often Rapid7-deployed)'; Product = 'Sysmon';       Category = 'Telemetry';         Role = 'Kernel event telemetry' }
    @{ Pattern = '^rapid7_events_monitor$';                     Vendor = 'Rapid7';                        Product = 'InsightIDR';                   Category = 'Telemetry';         Role = 'Event stream monitor' }
    @{ Pattern = '^MVArmorService(32|64)?$';                    Vendor = 'Rapid7';                        Product = 'Insight Agent';                Category = 'EDR';               Role = 'Endpoint service / plugins' }
    @{ Pattern = '^rapid7_velociraptor$';                       Vendor = 'Rapid7';                        Product = 'Velociraptor';                 Category = 'DFIR';              Role = 'Forensic endpoint visibility' }

    # Palo Alto Networks
    @{ Pattern = '^cyserver$';                                  Vendor = 'Palo Alto Networks';            Product = 'Cortex XDR';                   Category = 'EDR';               Role = 'Cortex XDR core engine' }
    @{ Pattern = '^cortex-xdr-payload$';                        Vendor = 'Palo Alto Networks';            Product = 'Cortex XDR';                   Category = 'EDR';               Role = 'Protection payload / hooks' }
    @{ Pattern = '^tlaworker$';                                 Vendor = 'Palo Alto Networks';            Product = 'Cortex XDR';                   Category = 'EDR';               Role = 'Local ML analysis worker' }
    @{ Pattern = '^(cysandbox|cytray|xdrhealth)$';              Vendor = 'Palo Alto Networks';            Product = 'Cortex XDR';                   Category = 'EDR';               Role = 'Sandbox / tray / health helper' }
    @{ Pattern = '^PanGP[SA]$';                                 Vendor = 'Palo Alto Networks';            Product = 'GlobalProtect';                Category = 'VPN';               Role = 'VPN client service/agent' }

    # Fortinet
    @{ Pattern = '^FortiESNAC$';                                Vendor = 'Fortinet';                      Product = 'FortiClient';                  Category = 'NAC';               Role = 'Network access control' }
    @{ Pattern = '^FortiSSLVPNdaemon$';                         Vendor = 'Fortinet';                      Product = 'FortiClient';                  Category = 'VPN';               Role = 'SSL VPN daemon' }
    @{ Pattern = '^FortiVPN$';                                  Vendor = 'Fortinet';                      Product = 'FortiClient';                  Category = 'VPN';               Role = 'VPN controller' }
    @{ Pattern = '^(FortiTcs|FCDBLog|FortiTray|FortiUSBmon|FortiClient)$'; Vendor = 'Fortinet';            Product = 'FortiClient';                  Category = 'VPN/ZTNA';          Role = 'ZTNA / logging / tray / USB control' }

    # Cisco
    @{ Pattern = '^acumbrellaagent$';                           Vendor = 'Cisco';                         Product = 'Umbrella';                     Category = 'DNS Security';      Role = 'DNS-layer security' }
    @{ Pattern = '^vpnagent$';                                  Vendor = 'Cisco';                         Product = 'Secure Client / AnyConnect';   Category = 'VPN';               Role = 'VPN agent' }
    @{ Pattern = '^csc_ui$';                                    Vendor = 'Cisco';                         Product = 'Secure Client';                Category = 'VPN';               Role = 'Client UI' }

    # BeyondTrust
    @{ Pattern = '^DefendpointService$';                        Vendor = 'BeyondTrust';                   Product = 'Privilege Management (Avecto)';Category = 'PAM';               Role = 'Privilege elevation broker' }
    @{ Pattern = '^Avecto\.IC3\.Client\.Host$';                 Vendor = 'BeyondTrust';                   Product = 'Privilege Management';         Category = 'PAM';               Role = 'Cloud policy adapter' }
    @{ Pattern = '^PMC\.PackageManager$';                       Vendor = 'BeyondTrust';                   Product = 'Privilege Management';         Category = 'PAM';               Role = 'Package manager' }

    # MDM / device management
    @{ Pattern = '^(IntuneWindowsAgent|Microsoft\.Management\.Services\.IntuneWindowsAgent)$'; Vendor = 'Microsoft'; Product = 'Intune';           Category = 'MDM';               Role = 'Device management agent' }
    @{ Pattern = '^CcmExec$';                                   Vendor = 'Microsoft';                     Product = 'Configuration Manager (SCCM)'; Category = 'MDM';               Role = 'Device management client' }

    # Other common enterprise EDR/AV
    @{ Pattern = '^(CSFalconService|CSFalconContainer)$';       Vendor = 'CrowdStrike';                   Product = 'Falcon';                       Category = 'EDR';               Role = 'EDR sensor service' }
    @{ Pattern = '^(SentinelAgent|SentinelServiceHost|SentinelStaticEngine|SentinelHelperService)$'; Vendor = 'SentinelOne'; Product = 'Singularity'; Category = 'EDR';               Role = 'EDR agent' }
    @{ Pattern = '^(RepMgr|RepUtils|RepWSC)$';                  Vendor = 'VMware Carbon Black';           Product = 'Cloud/EDR';                    Category = 'EDR';               Role = 'EDR agent' }
    @{ Pattern = '^(ccSvcHst|Rtvscan|SepMasterService|smcgui)$';Vendor = 'Broadcom/Symantec';             Product = 'Endpoint Protection';          Category = 'AV';                Role = 'AV/EDR service' }
    @{ Pattern = '^(mcshield|masvc|mfemms|mfetp)$';             Vendor = 'McAfee/Trellix';                Product = 'Endpoint Security';            Category = 'AV';                Role = 'AV/EDR service' }
    @{ Pattern = '^(ntrtscan|tmlisten|PccNTMon|tmccsf)$';       Vendor = 'Trend Micro';                   Product = 'Apex One';                     Category = 'AV';                Role = 'AV/EDR service' }
    @{ Pattern = '^TaniumClient$';                              Vendor = 'Tanium';                        Product = 'Client';                       Category = 'EDR/Telemetry';     Role = 'Endpoint management/telemetry agent' }
    @{ Pattern = '^QualysAgent$';                               Vendor = 'Qualys';                        Product = 'Cloud Agent';                  Category = 'Vulnerability Mgmt';Role = 'Vulnerability scanning agent' }
    @{ Pattern = '^(ZSAService|ZSATrayManager|ZSATunnel)$';     Vendor = 'Zscaler';                       Product = 'Client Connector';              Category = 'SASE/VPN';          Role = 'Cloud security tunnel client' }
    @{ Pattern = '^(cpd|fw)$';                                  Vendor = 'Check Point';                   Product = 'Harmony/Endpoint';             Category = 'EDR/Firewall';      Role = 'Security daemon' }
    @{ Pattern = '^(nsdiag|stAgentSvc)$';                       Vendor = 'Netskope';                      Product = 'Client';                       Category = 'SASE';              Role = 'Cloud security client' }
    @{ Pattern = '^rpcnet$';                                    Vendor = 'Absolute Software';             Product = 'Absolute';                     Category = 'Asset Mgmt/Anti-theft'; Role = 'Persistence/recovery agent' }
    @{ Pattern = '^CylanceSvc$';                                Vendor = 'BlackBerry';                    Product = 'Cylance';                      Category = 'AV';                Role = 'AI-based AV engine' }
    @{ Pattern = '^MBAMService$';                               Vendor = 'Malwarebytes';                  Product = 'Endpoint Protection';          Category = 'AV';                Role = 'AV/anti-malware service' }
    @{ Pattern = '^ekrn$';                                      Vendor = 'ESET';                          Product = 'Endpoint Protection';          Category = 'AV';                Role = 'AV engine' }
    @{ Pattern = '^(SavService|SophosHealth|SEDservice)$';      Vendor = 'Sophos';                        Product = 'Endpoint';                     Category = 'AV/EDR';            Role = 'AV/EDR service' }
    @{ Pattern = '^(bdagent|epsecurityservice|EPProtectedService)$'; Vendor = 'Bitdefender';               Product = 'GravityZone';                  Category = 'AV/EDR';            Role = 'AV/EDR service' }
    @{ Pattern = '^CybereasonSensor$';                          Vendor = 'Cybereason';                    Product = 'Sensor';                       Category = 'EDR';               Role = 'EDR sensor' }
    @{ Pattern = '^HuntressAgent$';                             Vendor = 'Huntress';                      Product = 'Agent';                        Category = 'EDR';               Role = 'Managed EDR agent' }
    @{ Pattern = '^warp-svc$';                                  Vendor = 'Cloudflare';                    Product = 'WARP';                         Category = 'SASE/VPN';          Role = 'Zero-trust tunnel client' }
    @{ Pattern = '^TwingateService$';                           Vendor = 'Twingate';                      Product = 'Client';                       Category = 'ZTNA';              Role = 'Zero-trust network client' }
    @{ Pattern = '^(PulseSecureService|dsWmc|dsUiTaskWatcher)$';Vendor = 'Ivanti (Pulse Secure)';         Product = 'Secure Access Client';         Category = 'VPN';               Role = 'VPN service' }
    @{ Pattern = '^splunkd$';                                   Vendor = 'Splunk';                        Product = 'Universal Forwarder';          Category = 'Log Forwarding';    Role = 'Log forwarding agent' }
    @{ Pattern = '^(winlogbeat|filebeat|metricbeat)$';          Vendor = 'Elastic';                       Product = 'Beats';                        Category = 'Log Forwarding';    Role = 'Log/metric shipping agent' }
    @{ Pattern = '^(ossec-agent(svc)?|wazuh-agent)$';           Vendor = 'Wazuh/OSSEC';                   Product = 'Agent';                        Category = 'SIEM/EDR';          Role = 'Host-based intrusion detection agent' }
    @{ Pattern = '^Code42Service$';                             Vendor = 'Code42';                        Product = 'Incydr';                       Category = 'DLP';               Role = 'Data-loss/insider-risk agent' }
    @{ Pattern = '^(CyberArkEPMAgent|VfAgent|EPMAgent)$';       Vendor = 'CyberArk';                      Product = 'Endpoint Privilege Manager';   Category = 'PAM';               Role = 'Privilege elevation agent' }
    @{ Pattern = '^AutomoxAgent$';                              Vendor = 'Automox';                       Product = 'Patch Agent';                  Category = 'MDM';               Role = 'Patch/config agent' }
)

# Publisher/company keyword fallback for anything not explicitly mapped above --
# keeps the script useful across coworkers' machines running vendors not in the table.
$SecurityKeywords = @(
    'CrowdStrike','SentinelOne','Carbon Black','VMware Carbon Black','Symantec','Broadcom',
    'McAfee','Trellix','Trend Micro','Micro Focus','OpenText','Tanium','Qualys','Zscaler',
    'Check Point','Netskope','Absolute Software','Cylance','BlackBerry','Malwarebytes','ESET',
    'Sophos','Bitdefender','Cybereason','Huntress','Cloudflare','Twingate','NetMotion','Ivanti',
    'Pulse Secure','Palo Alto Networks','Fortinet','Cisco','Rapid7','Microsoft Defender',
    'BeyondTrust','CyberArk','Splunk','Elastic','Wazuh','Code42','Proofpoint','Forcepoint',
    'Digital Guardian','Darktrace','Vectra','Illumio','Deep Instinct','Automox'
)

function Get-ProcessClassification {
    param([string]$ProcessName, [string]$Company, [string]$SignerCN)

    foreach ($entry in $VendorMap) {
        if ($ProcessName -match $entry.Pattern) {
            return [PSCustomObject]@{
                IsSecurityRelated = $true
                MatchSource       = 'vendor-map'
                Vendor            = $entry.Vendor
                Product           = $entry.Product
                Category          = $entry.Category
                Role              = $entry.Role
            }
        }
    }

    $textToCheck = "$Company $SignerCN"
    foreach ($kw in $SecurityKeywords) {
        if ($textToCheck -match [regex]::Escape($kw)) {
            return [PSCustomObject]@{
                IsSecurityRelated = $true
                MatchSource       = 'publisher-heuristic'
                Vendor            = $kw
                Product           = $null
                Category          = 'Unclassified (heuristic match)'
                Role              = 'Publisher/signer matched a known security vendor keyword; not in the explicit process map -- worth a manual look.'
            }
        }
    }

    return [PSCustomObject]@{
        IsSecurityRelated = $false
        MatchSource       = $null
        Vendor            = $null
        Product           = $null
        Category          = $null
        Role              = $null
    }
}

# ---------------------------------------------------------------------------
# CPU sampling
# ---------------------------------------------------------------------------
function Get-ProcessCpuUsageFallback {
    param([int]$DurationSeconds)
    Write-Status "  (fallback) sampling processor-time deltas over $DurationSeconds s..."
    $before = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, @{n = 'CpuTime'; e = { $_.CPU } }
    Start-Sleep -Seconds $DurationSeconds
    $after = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, @{n = 'CpuTime'; e = { $_.CPU } }

    $beforeMap = @{}
    foreach ($p in $before) { $beforeMap[$p.Id] = $p.CpuTime }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($p in $after) {
        if ($beforeMap.ContainsKey($p.Id) -and $null -ne $p.CpuTime -and $null -ne $beforeMap[$p.Id]) {
            $deltaSeconds = $p.CpuTime - $beforeMap[$p.Id]
            if ($deltaSeconds -lt 0) { continue }
            $pct = ($deltaSeconds / $DurationSeconds) * 100
            $results.Add([PSCustomObject]@{ ProcessId = $p.Id; AvgCpuPercent = [Math]::Round($pct, 2) })
        }
    }
    return $results
}

function Get-ProcessCpuUsage {
    param([int]$DurationSeconds, [int]$IntervalSeconds)

    $maxSamples = [Math]::Max(2, [Math]::Floor($DurationSeconds / $IntervalSeconds))
    $pidTotals = @{}
    $pidCounts = @{}
    $goodSamples = 0
    $badSamples = 0
    $lastError = $null

    Write-Status "  sampling live CPU via Get-Counter ($maxSamples samples, ${IntervalSeconds}s apart)..."

    # Sampled one interval at a time (rather than one batched -MaxSamples call) because
    # \Process(*) wildcards intermittently return "The data in one of the performance
    # counter samples is not valid" -- observed here to fail 40-70% of individual calls,
    # seemingly at random (likely PPL-protected AV/EDR processes or plain process churn
    # on a security-tool-heavy box). A batched -MaxSamples call throws away the ENTIRE
    # window on a single bad instance; isolating each interval -- with a couple of quick
    # retries, since a retry usually succeeds -- means one bad read only costs that read.
    $maxRetries = 6
    for ($i = 0; $i -lt $maxSamples; $i++) {
        $ok = $false
        for ($attempt = 1; $attempt -le $maxRetries -and -not $ok; $attempt++) {
            try {
                $set = Get-Counter -Counter '\Process(*)\% Processor Time', '\Process(*)\ID Process' `
                    -SampleInterval $IntervalSeconds -MaxSamples 1 -ErrorAction Stop

                $idMap = @{}
                foreach ($s in $set.CounterSamples) {
                    if ($s.Path -like '*\id process' -and $s.Status -eq 0) { $idMap[$s.InstanceName] = [int]$s.CookedValue }
                }
                foreach ($s in $set.CounterSamples) {
                    if ($s.Path -like '*\% processor time' -and $s.Status -eq 0 -and $s.InstanceName -notin @('_total', 'idle')) {
                        if ($idMap.ContainsKey($s.InstanceName)) {
                            $procId = $idMap[$s.InstanceName]
                            if (-not $pidTotals.ContainsKey($procId)) { $pidTotals[$procId] = 0.0; $pidCounts[$procId] = 0 }
                            $pidTotals[$procId] += $s.CookedValue
                            $pidCounts[$procId] += 1
                        }
                    }
                }
                $goodSamples++
                $ok = $true
            } catch {
                $lastError = $_
            }
        }
        if (-not $ok) { $badSamples++ }
    }

    if ($goodSamples -eq 0) {
        Add-CollectionWarning "Get-Counter sampling failed on all $maxSamples samples ($($lastError.Exception.Message)); used processor-time delta fallback instead (less precise, single before/after snapshot)."
        return Get-ProcessCpuUsageFallback -DurationSeconds $DurationSeconds
    }
    if ($badSamples -gt 0) {
        Add-CollectionWarning "Get-Counter: $badSamples of $maxSamples samples were discarded (invalid counter data, likely process churn); averages are based on the remaining $goodSamples sample(s)."
    }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($procId in $pidTotals.Keys) {
        $avg = $pidTotals[$procId] / $pidCounts[$procId]
        $results.Add([PSCustomObject]@{ ProcessId = $procId; AvgCpuPercent = [Math]::Round($avg, 2) })
    }
    return $results
}

# ---------------------------------------------------------------------------
# Signer/publisher lookup (cached by path -- can be slow if called per-process)
# ---------------------------------------------------------------------------
$SignerCache = @{}
function Get-SignerCN {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ($SignerCache.ContainsKey($Path)) { return $SignerCache[$Path] }
    $subject = $null
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ($sig.SignerCertificate) {
            $subject = $sig.SignerCertificate.Subject
            if ($subject -match 'CN=([^,]+)') { $subject = $matches[1] }
        }
    } catch { }
    $SignerCache[$Path] = $subject
    return $subject
}

# ===========================================================================
# MAIN
# ===========================================================================
try {
    if (-not (Test-Path -Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $isAdmin = Test-IsAdmin
    Write-Status "=== Endpoint Security Stack Collector ==="
    Write-Status "Host: $env:COMPUTERNAME   Elevated: $isAdmin   Sample window: ${SampleSeconds}s"
    if (-not $isAdmin) {
        Add-CollectionWarning "Not running elevated -- path/company/description for some SYSTEM-owned security processes may be blank. Re-run 'as Administrator' for fuller data if possible."
    }

    # ---- System summary ----
    Write-Status "[1/6] Collecting system info..."
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpus = Get-CimInstance Win32_Processor
    $logicalCores = ($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    $physicalCores = ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum
    $totalMemGB = [Math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    $freeMemGB = [Math]::Round(($os.FreePhysicalMemory * 1KB) / 1GB, 1)
    $usedMemGB = [Math]::Round($totalMemGB - $freeMemGB, 1)
    $uptimeHours = [Math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)

    $systemSummary = [ordered]@{
        Manufacturer     = $cs.Manufacturer
        Model            = $cs.Model
        OSCaption        = $os.Caption
        OSVersion        = $os.Version
        OSBuild          = $os.BuildNumber
        LogicalCores     = $logicalCores
        PhysicalCores    = $physicalCores
        TotalMemoryGB    = $totalMemGB
        UsedMemoryGB     = $usedMemGB
        FreeMemoryGB     = $freeMemGB
        MemoryUsedPercent = [Math]::Round(($usedMemGB / $totalMemGB) * 100, 1)
        UptimeHours      = $uptimeHours
    }

    # ---- Registered AV/Firewall/AntiSpyware (Windows Security Center) ----
    Write-Status "[2/6] Checking registered AV/Firewall products..."
    $avProducts = $null; $fwProducts = $null; $asProducts = $null
    try {
        $avProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
            Select-Object displayName, @{n = 'productStateRaw'; e = { $_.productState } }, @{n = 'productStateHex'; e = { '{0:X6}' -f $_.productState } }, pathToSignedProductExe
        $fwProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct -ErrorAction Stop |
            Select-Object displayName, @{n = 'productStateRaw'; e = { $_.productState } }, @{n = 'productStateHex'; e = { '{0:X6}' -f $_.productState } }
        $asProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiSpywareProduct -ErrorAction Stop |
            Select-Object displayName, @{n = 'productStateRaw'; e = { $_.productState } }, @{n = 'productStateHex'; e = { '{0:X6}' -f $_.productState } }
    } catch {
        Add-CollectionWarning "root/SecurityCenter2 WMI namespace unavailable (common on Server SKUs) -- skipped registered AV/Firewall product check."
    }

    # ---- VPN-related network adapters (which VPN is actually connected) ----
    Write-Status "[3/6] Checking for VPN-related network adapters..."
    $vpnAdapters = $null
    try {
        $vpnAdapters = Get-NetAdapter -ErrorAction Stop |
            Where-Object { $_.InterfaceDescription -match 'VPN|AnyConnect|Secure Client|FortiClient|Fortinet|Zscaler|Palo Alto|GlobalProtect|Check Point|Pulse Secure|Ivanti|WARP|Twingate|TAP-Windows|Wintun' } |
            Select-Object Name, InterfaceDescription, Status, LinkSpeed
    } catch {
        Add-CollectionWarning "Get-NetAdapter unavailable -- skipped VPN adapter check."
    }

    # ---- Security-related services ----
    Write-Status "[4/6] Checking security-related services..."
    $secServices = $null
    try {
        $vendorNameTokens = $VendorMap | ForEach-Object { $_.Vendor } | Select-Object -Unique
        $serviceMatchTerms = @($SecurityKeywords + $vendorNameTokens + @('Defender', 'Sense', 'Sysmon', 'Forti', 'Cortex', 'Rapid7', 'Umbrella', 'Avecto', 'Intune', 'ConfigMgr', 'SCCM')) | Select-Object -Unique
        $secServices = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
            $hay = "$($_.Name) $($_.DisplayName)"
            $hit = $false
            foreach ($term in $serviceMatchTerms) {
                if ($hay -match [regex]::Escape($term)) { $hit = $true; break }
            }
            $hit
        } | Select-Object Name, DisplayName, State, StartMode, StartName
    } catch {
        Add-CollectionWarning "Win32_Service query failed -- skipped security services list."
    }

    # ---- CPU sampling (this is the slow part -- runs for ~SampleSeconds) ----
    Write-Status "[5/6] Sampling CPU for ${SampleSeconds}s (this will pause here)..."
    $cpuUsage = Get-ProcessCpuUsage -DurationSeconds $SampleSeconds -IntervalSeconds $SampleIntervalSeconds
    $cpuLookup = @{}
    foreach ($c in $cpuUsage) { $cpuLookup[$c.ProcessId] = $c.AvgCpuPercent }

    # ---- Process enumeration, metadata, classification ----
    Write-Status "[6/6] Enumerating processes and classifying against vendor map..."
    $rawProcs = Get-Process -ErrorAction SilentlyContinue
    $allProcObjects = New-Object System.Collections.Generic.List[object]

    foreach ($p in $rawProcs) {
        $path = $null; $company = $null; $description = $null
        try { $path = $p.Path } catch { }
        try { $company = $p.Company } catch { }
        try { $description = $p.Description } catch { }

        $signerCN = Get-SignerCN -Path $path
        $classification = Get-ProcessClassification -ProcessName $p.ProcessName -Company $company -SignerCN $signerCN

        $cpuPct = 0
        if ($cpuLookup.ContainsKey($p.Id)) { $cpuPct = $cpuLookup[$p.Id] }

        $cmdLine = $null
        if ($IncludeCommandLines -and $classification.IsSecurityRelated) {
            try {
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction Stop).CommandLine
            } catch { }
        }

        $allProcObjects.Add([PSCustomObject]@{
            ProcessId              = $p.Id
            ProcessName            = $p.ProcessName
            Path                   = $path
            Company                = $company
            Description            = $description
            SignerCN               = $signerCN
            WorkingSetMB           = [Math]::Round($p.WorkingSet64 / 1MB, 1)
            AvgCpuPercentOfOneCore = $cpuPct
            IsSecurityRelated      = $classification.IsSecurityRelated
            MatchSource            = $classification.MatchSource
            Vendor                 = $classification.Vendor
            Product                = $classification.Product
            Category               = $classification.Category
            Role                   = $classification.Role
            CommandLine            = $cmdLine
        })
    }

    $flagged = $allProcObjects | Where-Object { $_.IsSecurityRelated }
    $others = $allProcObjects | Where-Object { -not $_.IsSecurityRelated }

    if ($IncludeAllProcesses) {
        $contextProcs = $others
        $coverageNote = "Includes ALL $($allProcObjects.Count) processes (-IncludeAllProcesses was set): $($flagged.Count) matched a known security/management vendor, $($others.Count) did not."
    } else {
        $topN = 25
        $topCpu = $others | Sort-Object AvgCpuPercentOfOneCore -Descending | Select-Object -First $topN
        $topRam = $others | Sort-Object WorkingSetMB -Descending | Select-Object -First $topN
        $contextProcs = @($topCpu + $topRam) | Sort-Object ProcessId -Unique
        $coverageNote = "Process list includes all $($flagged.Count) processes matched to a known security/management vendor (by name or publisher), plus up to $topN non-matched processes by CPU and $topN by RAM for context (deduped: $($contextProcs.Count) shown). $($others.Count - $contextProcs.Count) unmatched, low-usage processes were omitted. Re-run with -IncludeAllProcesses to capture every process."
    }

    $finalProcessList = @($flagged + $contextProcs) | Sort-Object -Property @{ Expression = 'IsSecurityRelated'; Descending = $true }, @{ Expression = 'AvgCpuPercentOfOneCore'; Descending = $true }

    # ---- Stack-level summary (grouped like the original audit report) ----
    $stackSummary = $flagged | Group-Object Vendor, Product | ForEach-Object {
        $items = $_.Group
        [PSCustomObject]@{
            Vendor                  = $items[0].Vendor
            Product                 = $items[0].Product
            Category                = ($items.Category | Select-Object -Unique) -join ', '
            ProcessCount            = $items.Count
            TotalCpuPercentOfOneCore = [Math]::Round((($items | Measure-Object AvgCpuPercentOfOneCore -Sum).Sum), 2)
            TotalCpuPercentOfSystem = [Math]::Round(((($items | Measure-Object AvgCpuPercentOfOneCore -Sum).Sum) / $logicalCores), 2)
            TotalRamMB              = [Math]::Round((($items | Measure-Object WorkingSetMB -Sum).Sum), 1)
            ProcessNames            = ($items.ProcessName | Select-Object -Unique) -join ', '
        }
    } | Sort-Object TotalCpuPercentOfOneCore -Descending

    # ---- Assemble final report ----
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $metadata = [ordered]@{
        ScriptVersion          = '1.0'
        CollectedAtLocal       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
        CollectedAtUtc         = (Get-Date).ToUniversalTime().ToString('o')
        Hostname               = $env:COMPUTERNAME
        Domain                 = $cs.Domain
        CollectedByUsername    = $env:USERNAME
        RanElevated            = $isAdmin
        SampleWindowSeconds    = $SampleSeconds
        SampleIntervalSeconds  = $SampleIntervalSeconds
        IncludeAllProcesses    = [bool]$IncludeAllProcesses
        IncludeCommandLines    = [bool]$IncludeCommandLines
    }

    $report = [ordered]@{
        Metadata                   = $metadata
        System                     = $systemSummary
        RegisteredSecurityProducts = [ordered]@{
            AntiVirus    = $avProducts
            Firewall     = $fwProducts
            AntiSpyware  = $asProducts
            Note         = 'productState is an undocumented Microsoft bitmask (enabled/up-to-date signaling). Raw decimal + hex included for reference; treat as informational only.'
        }
        VpnNetworkAdapters = $vpnAdapters
        SecurityServices   = $secServices
        StackSummary       = $stackSummary
        Processes          = $finalProcessList
        CoverageNote       = $coverageNote
        CollectionWarnings = $CollectionWarnings
    }

    $jsonPath = Join-Path $OutputDir "SecurityStackAudit-$($env:COMPUTERNAME)-$stamp.json"
    $csvPath = Join-Path $OutputDir "SecurityStackAudit-$($env:COMPUTERNAME)-$stamp-Processes.csv"

    $report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding utf8
    $finalProcessList | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-Status "`nDone."
    Write-Status "  JSON: $jsonPath"
    Write-Status "  CSV : $csvPath"
    if ($CollectionWarnings.Count -gt 0) {
        Write-Status "`nCollection warnings (also embedded in the JSON):"
        foreach ($w in $CollectionWarnings) { Write-Status "  - $w" }
    }
    Write-Status "`nNext step: share the JSON file with Claude (upload it, or paste its contents) and ask, e.g.:"
    Write-Status '  "Analyze this endpoint security stack audit -- what overlaps, redundancies, or performance risks do you see, and what should I raise with IT?"'

} catch {
    Write-Error "Collection failed: $($_.Exception.Message)"
    throw
}
