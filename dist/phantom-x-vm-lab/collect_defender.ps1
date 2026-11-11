<#
.SYNOPSIS
    PHANTOM-X :: Phase 4 / Phase 1 support -- Defender and Windows event collector.

.DESCRIPTION
    Captures a READ-ONLY snapshot of Microsoft Defender posture plus the
    Windows event telemetry needed to answer Phase 1 questions:
      * Is real-time protection actually enabled? (proof, not assumption)
      * What is the current configuration, and are any PDF/attachment
        relevant settings unusual?
      * What did Defender detect, and in which log?
      * What child processes did the PDF reader spawn?
      * Did AMSI engage on any script content?
      * Did anything make a network connection?

    THIS SCRIPT DOES NOT MODIFY DEFENDER OR ANY SETTING.
    It reads configuration and events. It never calls
    Set-MpPreference, Add-MpPreference, Remove-MpPreference,
    Set-MpThreat, or any remediation verb.

.PARAMETER Label
    Short label for this snapshot, e.g. 'before_open' or 'after_open'.

.PARAMETER OutputDir
    Directory to write JSON snapshots into.

.PARAMETER Since
    Only harvest events at or after this timestamp. Defaults to the start
    of the current session if not supplied.

.PARAMETER Full
    Also dump the raw preference document (large) in addition to the curated view.

.EXAMPLE
    .\collect_defender.ps1 -Label before_open
    # ... open the PDF in the reader ...
    .\collect_defender.ps1 -Label after_open
#>
[CmdletBinding()]
param(
    [string]$Label = 'snapshot',
    [string]$OutputDir = 'C:\phantom-x\reports',
    [datetime]$Since = [datetime]::MinValue,
    [switch]$Full
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

function Save-Json {
    param([string]$Path, $Object)
    try {
        $json = $Object | ConvertTo-Json -Depth 8
        Set-Content -Path $Path -Value $json -Encoding UTF8
        Write-Host ("[+] {0}" -f $Path) -ForegroundColor Green
    } catch {
        Write-Host ("[!] failed writing {0}: {1}" -f $Path, $_.Exception.Message) -ForegroundColor Yellow
    }
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Write-Section "PHANTOM-X :: DEFENDER / EVENT SNAPSHOT -- LABEL '$Label'"

# ----------------------------------------------------------------------------
# 1. Defender posture -- read-only
# ----------------------------------------------------------------------------
Write-Section '1. Defender real-time protection posture'

$status = $null
try {
    $status = Get-MpComputerStatus -ErrorAction Stop
} catch {
    Write-Host ("[!] Get-MpComputerStatus failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    Write-Host '    (Is the Microsoft Defender Antivirus PowerShell module present?)' -ForegroundColor DarkGray
}

if ($status) {
    # The critical proof points for this project.
    $proof = [ordered]@{
        AMServiceEnabled          = $status.AMServiceEnabled
        AntispywareEnabled        = $status.AntispywareEnabled
        AntivirusEnabled          = $status.AntivirusEnabled
        RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
        BehaviorMonitorEnabled    = $status.BehaviorMonitorEnabled
        IoavProtectionEnabled     = $status.IoavProtectionEnabled
        OnAccessProtectionEnabled = $status.OnAccessProtectionEnabled
        IsTamperProtected         = $status.IsTamperProtected
        AMRunningMode             = $status.AMRunningMode
        AntivirusSignatureVersion = $status.AntivirusSignatureVersion
        AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
        RealTimeScanDirection      = $status.RealTimeScanDirection
        QuickScanAge              = $status.QuickScanAge
        FullScanAge              = $status.FullScanAge
        ComputerState            = $status.ComputerState
    }
    Write-Host ''
    $proof.GetEnumerator() | ForEach-Object {
        $statusText = if ($_.Value -eq $null) { 'n/a' } else { $_.Value }
        $colour = 'Gray'
        if ($_.Key -eq 'RealTimeProtectionEnabled' -and $_.Value -ne $true) { $colour = 'Red' }
        if ($_.Key -eq 'AntivirusEnabled' -and $_.Value -ne $true) { $colour = 'Red' }
        if ($_.Key -eq 'IsTamperProtected' -and $_.Value -ne $true) { $colour = 'Yellow' }
        Write-Host ("  {0,-30} {1}" -f $_.Key, $statusText) -ForegroundColor $colour
    }
    Write-Host ''
    Write-Host '  NOTE: Red above means the lab precondition is NOT met.' -ForegroundColor Red
    Write-Host '        Defender must stay ENABLED for every experiment in this project.' -ForegroundColor Red
    Save-Json -Path (Join-Path $OutputDir ("{0}_defender_status.json" -f $Label)) -Object $status
}

# ----------------------------------------------------------------------------
# 2. Defender preferences -- read-only, curated
# ----------------------------------------------------------------------------
Write-Section '2. Defender configuration (read-only)'

$prefKeys = @(
    'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection',
    'DisableScriptScanning', 'DisableArchiveScanning', 'DisableIntrusionPreventionSystem',
    'DisableBlockAtFirstSeen', 'PUAProtection', 'EnableControlledFolderAccess',
    'MAPSReporting', 'SubmitSamplesConsent', 'CloudBlockLevel',
    'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress',
    'ExclusionProcess', 'DisableRemovableDriveScanning',
    'EnableNetworkProtection', 'EnableControlledFolderAccess'
)

$prefView = [ordered]@{}
try {
    $prefs = Get-MpPreference -ErrorAction Stop
    foreach ($k in $prefKeys) {
        if ($prefs.PSObject.Properties.Name -contains $k) {
            $prefView[$k] = $prefs.$k
        }
    }
    Write-Host ''
    foreach ($k in $prefView.Keys) {
        $v = $prefView[$k]
        $text = if ($v -is [array]) { ($v -join '; ') } else { "$v" }
        if ([string]::IsNullOrWhiteSpace($text)) { $text = '<empty>' }
        Write-Host ("  {0,-32} {1}" -f $k, $text)
    }
    Save-Json -Path (Join-Path $OutputDir ("{0}_defender_preferences.json" -f $Label)) -Object $prefView

    if ($Full) {
        Save-Json -Path (Join-Path $OutputDir ("{0}_defender_preferences_full.json" -f $Label)) -Object $prefs
    }
} catch {
    Write-Host ("[!] Get-MpPreference failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}

# ----------------------------------------------------------------------------
# 3. Threat detections
# ----------------------------------------------------------------------------
Write-Section '3. Defender detections (threat history)'

$detections = @()
try {
    $detections = @(Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 200)
} catch {
    Write-Host ("[!] Get-MpThreatDetection failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}

if ($detections.Count -gt 0) {
    Write-Host ''
    $detections | Select-Object -Last 20 | ForEach-Object {
        Write-Host ("  {0,-14} {1,-28} {2}" -f `
            $_.InitialDetectionTime, $_.ThreatName, ($_.Resources -join '; '))
    }
} else {
    Write-Host '  (no detections reported)'
}
Save-Json -Path (Join-Path $OutputDir ("{0}_threat_detections.json" -f $Label)) -Object $detections

# ----------------------------------------------------------------------------
# 4. Event log harvesting
# ----------------------------------------------------------------------------
Write-Section '4. Event log harvest'

# Event IDs that matter for a PDF->execution->memory->network chain.
$logPlan = @(
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'
       Ids = @(1006,1007,1008,1116,1117,1118,1119,1121,1122,5001,5004,5007,5010,5012,5013,5014)
       Note = 'Defender detection / remediation / configuration change' }
    @{ Log = 'Microsoft-Windows-Sysmon/Operational'
       Ids = @(1,3,5,7,8,10,11,15,22,25)
       Note = 'Process creation, network, image load, injection, DNS' }
    @{ Log = 'Security'
       Ids = @(4688,4697,1102)
       Note = 'Process creation (needs audit policy), service install, log clear' }
    @{ Log = 'Microsoft-Windows-PowerShell/Operational'
       Ids = @(4103,4104,4105)
       Note = 'Module / script block logging' }
    @{ Log = 'Microsoft-Windows-CodeIntegrity/Operational'
       Ids = @(3076,3077,3089,3033)
       Note = 'Code integrity / image load policy' }
    @{ Log = 'Microsoft-Windows-SmartScreen/Diagnostic'
       Ids = @()
       Note = 'SmartScreen download reputation' }
    @{ Log = 'Microsoft-Windows-AppLocker/EXE and DLL'
       Ids = @(8004,8022,8028)
       Note = 'AppLocker execution decisions' }
    @{ Log = 'Microsoft-Windows-AppLocker/MSI and Script'
       Ids = @(8006,8029)
       Note = 'AppLocker script decisions' }
)

$allEvents = @()
foreach ($plan in $logPlan) {
    $logName = $plan.Log
    Write-Host ''
    Write-Host ("  --- {0}" -f $logName) -ForegroundColor White
    Write-Host ("      {0}" -f $plan.Note) -ForegroundColor DarkGray

    try {
        if (-not (Get-WinEvent -ListLog $logName -ErrorAction Stop)) {
            throw 'log not found'
        }
        $filter = @{
            LogName   = $logName
            StartTime = $Since
        }
        if ($plan.Ids.Count -gt 0) { $filter['Id'] = $plan.Ids }

        $evts = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
        if ($evts.Count -eq 0) {
            Write-Host '      (no matching events)' -ForegroundColor DarkGray
            continue
        }
        Write-Host ("      {0} event(s)" -f $evts.Count) -ForegroundColor Green
        foreach ($e in ($evts | Sort-Object TimeCreated | Select-Object -Last 15)) {
            $msg = ''
            try { $msg = ($e.Message -replace "`r?`n", ' ' ) } catch { $msg = '' }
            if ($msg.Length -gt 240) { $msg = $msg.Substring(0, 240) + '...' }
            Write-Host ("      [{0}] id={1} {2}" -f $e.TimeCreated.ToString('HH:mm:ss'), $e.Id, $msg) -ForegroundColor DarkYellow
        }
        foreach ($e in $evts) {
            $allEvents += [pscustomobject]@{
                LogName         = $e.LogName
                TimeCreated     = $e.TimeCreated.ToString('o')
                Id              = $e.Id
                ProviderName    = $e.ProviderName
                Level           = $e.LevelDisplayName
                ProcessId       = $e.ProcessId
                Message         = try { ($e.Message -replace "`r?`n", ' ') } catch { '' }
            }
        }
    } catch {
        Write-Host ("      (unavailable: {0})" -f $_.Exception.Message) -ForegroundColor DarkGray
    }
}

Save-Json -Path (Join-Path $OutputDir ("{0}_events.json" -f $Label)) -Object $allEvents

# ----------------------------------------------------------------------------
# 5. PDF-reader processes and their children
# ----------------------------------------------------------------------------
Write-Section '5. PDF reader processes and recent children'

$readerNames = @(
    'AcroRd32', 'AcroEdge', 'Acrobat', 'FoxitReader', 'FoxitPDFReader',
    'SumatraPDF', 'msedge', 'chrome', 'firefox', 'WINWORD', 'wps', 'qpdf'
)
$readers = @(Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $readerNames -contains $_.ProcessName } |
    Select-Object ProcessName, Id, StartTime, Path)

if ($readers.Count -gt 0) {
    $readers | ForEach-Object {
        Write-Host ("  {0,-18} pid={1,-6} started={2}" -f $_.ProcessName, $_.Id, $_.StartTime)
    }
} else {
    Write-Host '  (no known PDF reader currently running)'
}
Save-Json -Path (Join-Path $OutputDir ("{0}_reader_processes.json" -f $Label)) -Object $readers

# ----------------------------------------------------------------------------
# 6. Network connections
# ----------------------------------------------------------------------------
Write-Section '6. Established network connections (snapshot)'

$conns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq 'Established' } |
    ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = $_.State
            Process       = if ($p) { $p.ProcessName } else { '?' }
            Pid           = $_.OwningProcess
        }
    })

if ($conns.Count -gt 0) {
    $conns | Sort-Object Process | ForEach-Object {
        Write-Host ("  {0,-16} pid={1,-6} {2}:{3} -> {4}:{5}" -f `
            $_.Process, $_.Pid, $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort)
    }
} else {
    Write-Host '  (no established connections)'
}
Save-Json -Path (Join-Path $OutputDir ("{0}_net_connections.json" -f $Label)) -Object $conns

# ----------------------------------------------------------------------------
# 7. Snapshot summary
# ----------------------------------------------------------------------------
Write-Section '7. Snapshot summary'

$defenderIds = @($allEvents | Where-Object { $_.LogName -like '*Defender*' })
$sysmonIds  = @($allEvents | Where-Object { $_.LogName -like '*Sysmon*' })

$summary = [ordered]@{
    label             = $Label
    collected_utc     = (Get-Date).ToUniversalTime().ToString('o')
    since             = $Since.ToString('o')
    machine           = $env:COMPUTERNAME
    realtime_protection_enabled = if ($status) { $status.RealTimeProtectionEnabled } else { $null }
    antivirus_enabled          = if ($status) { $status.AntivirusEnabled } else { $null }
    tamper_protected           = if ($status) { $status.IsTamperProtected } else { $null }
    signature_version          = if ($status) { $status.AntivirusSignatureVersion } else { $null }
    detections_reported        = $detections.Count
    defender_event_count       = $defenderIds.Count
    sysmon_event_count         = $sysmonIds.Count
    total_event_count          = $allEvents.Count
    defender_event_ids         = @($defenderIds | Group-Object Id | ForEach-Object { "$($_.Name)x$($_.Count)" })
    sysmon_event_ids           = @($sysmonIds  | Group-Object Id | ForEach-Object { "$($_.Name)x$($_.Count)" })
}

Write-Host ''
$summary.GetEnumerator() | ForEach-Object {
    Write-Host ("  {0,-32} {1}" -f $_.Key, $_.Value)
}
Save-Json -Path (Join-Path $OutputDir ("{0}_summary.json" -f $Label)) -Object $summary

Write-Section "Snapshot '$Label' complete -> $OutputDir"
