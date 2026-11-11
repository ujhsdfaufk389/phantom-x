#Requires -Version 5.1
<#
.SYNOPSIS
    PHANTOM-X :: prepare a Windows 11 Pro research VM for the lab.

.DESCRIPTION
    One script that takes a freshly installed Windows 11 Pro VM to the
    point where the lab can be measured. It runs the existing preparation
    steps in the right order and refuses to continue past a step whose
    precondition is not met.

    THE ORDER MATTERS, AND HERE IS WHY

      1. NETWORK LOCKDOWN FIRST
         Everything after this point runs code that can execute arbitrary
         commands. Isolating the network before that code exists is the
         only ordering that actually contains a mistake. Locking the
         network down afterwards is a statement of intent, not a control.

      2. THEN DEFENDER POSTURE, AND IT IS NOT TOUCHED
         The lab's ground rule #1 is "Defender stays on during measurement."
         This script REPORTS the Defender posture and does not change it.
         Changing it is lab_ab_toggle.ps1's job, and that script arms a
         restore guard before it touches anything. This script will not
         quietly weaken an endpoint and leave it that way.

      3. THEN THE MARK-OF-THE-WEB
         Files copied onto the VM carry a Zone.Identifier stream, and
         PowerShell refuses to run them. Unblocking the lab folder fixes
         that without changing any execution policy.

      4. THEN SYSMON
         Sysmon gives the chain its telemetry. Without it the measurement
         has no signal to work with.

    WHAT IT WILL NOT DO
      * It will not disable Defender. See above.
      * It will not install a file association that redirects .pdf. That
        is install_pdf_handler.ps1's job, and it must run AFTER the Phase 1
        reader-behaviour measurement, not before, or that measurement
        measures the wrong thing.
      * It will not disable SmartScreen or Tamper Protection.

.PARAMETER LabFolder
    Folder holding the lab files on the VM.

.PARAMETER LabGateway
    IP of the operator machine on the host-only segment.

.PARAMETER C2Port
    Port the lab C2 listens on.

.PARAMETER ReportDir
    Where reports are written.

.PARAMETER SkipNetwork
    Skip the network lockdown. Only for a VM that is ALREADY on a
    host-only segment and has been verified.

.PARAMETER SkipSysmon
    Skip the Sysmon install step.

.EXAMPLE
    .\vm_prepare.ps1 -LabFolder C:\pxvm -LabGateway 192.168.77.1

.EXAMPLE
    .\vm_prepare.ps1 -LabFolder C:\pxvm -LabGateway 192.168.77.1 -SkipNetwork
#>
[CmdletBinding()]
param(
    [string]$LabFolder = 'C:\pxvm',
    [string]$LabGateway = '192.168.77.1',
    [int]$C2Port = 9001,
    [string]$LabSubnet = '192.168.77.0/24',
    [string]$ReportDir = 'C:\phantom-x\reports',
    [switch]$SkipNetwork,
    [switch]$SkipSysmon
)

$ErrorActionPreference = 'Continue'
$script:problems = @()

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

function Write-Problem {
    param([string]$Text)
    $script:problems += $Text
    Write-Host ("  [!] {0}" -f $Text) -ForegroundColor Red
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Section 'PHANTOM-X :: WINDOWS 11 PRO VM PREPARATION'

if (-not (Test-Admin)) {
    Write-Host '  this script needs Administrator.' -ForegroundColor Red
    Write-Host '  right-click PowerShell -> Run as administrator.' -ForegroundColor Yellow
    exit 1
}

# ---------------------------------------------------------------------------
# 0. Identify the machine
# ---------------------------------------------------------------------------
Write-Section '0. machine'

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
Write-Host ("  computer    : {0}" -f $cs.Name) -ForegroundColor White
Write-Host ("  product     : {0}" -f $os.Caption) -ForegroundColor White
Write-Host ("  version     : {0} (build {1})" -f $os.Version, $os.BuildNumber) -ForegroundColor White
Write-Host ("  RAM         : {0:N1} GB" -f ($cs.TotalPhysicalMemory / 1GB)) -ForegroundColor White

if ($os.Caption -notmatch 'Windows 11') {
    Write-Problem "this is not Windows 11 ($($os.Caption)); the lab targets Windows 11 Pro"
}
if ($os.Caption -notmatch 'Pro') {
    Write-Host '  NOTE: the edition is not Pro. Defender and ASR differ by edition.' -ForegroundColor Yellow
    Write-Host '        the lab measures whatever is actually installed; note it in the report.' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 1. Network lockdown -- FIRST, on purpose
# ---------------------------------------------------------------------------
Write-Section '1. network lockdown'

if ($SkipNetwork) {
    Write-Host '  skipped by request (-SkipNetwork).' -ForegroundColor Yellow
    Write-Host '  The VM must already be on a host-only segment. Verify it:' -ForegroundColor DarkGray
    Write-Host '    .\verify_labnet.ps1' -ForegroundColor DarkGray
} else {
    $setup = Join-Path $PSScriptRoot 'setup_vm_labnet.ps1'
    if (Test-Path $setup) {
        & $setup -Action apply -LabGateway $LabGateway -C2Port $C2Port -LabSubnet $LabSubnet
    } else {
        Write-Problem "setup_vm_labnet.ps1 not found next to this script ($PSScriptRoot)"
    }
}

# ---------------------------------------------------------------------------
# 2. Defender posture -- report, do not change
# ---------------------------------------------------------------------------
Write-Section '2. endpoint posture (reported, not changed)'

try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Write-Host ("  Real-Time Protection : {0}" -f $mp.RealTimeProtectionEnabled) -ForegroundColor $(
        if ($mp.RealTimeProtectionEnabled) { 'Green' } else { 'Red' })
    Write-Host ("  Antivirus Enabled    : {0}" -f $mp.AntivirusEnabled) -ForegroundColor Gray
    Write-Host ("  Behavior Monitor     : {0}" -f $mp.BehaviorMonitorEnabled) -ForegroundColor Gray
    Write-Host ("  IOAV Protection      : {0}" -f $mp.IoavProtectionEnabled) -ForegroundColor Gray
    Write-Host ("  Tamper Protected     : {0}" -f $mp.IsTamperProtected) -ForegroundColor $(
        if ($mp.IsTamperProtected) { 'Yellow' } else { 'Gray' })
    Write-Host ("  Signature version    : {0}  ({1})" -f $mp.AntivirusSignatureVersion, $mp.AntivirusSignatureLastUpdated) -ForegroundColor Gray
    Write-Host ("  AM service enabled   : {0}" -f $mp.AMServiceEnabled) -ForegroundColor Gray

    if (-not $mp.RealTimeProtectionEnabled) {
        Write-Problem 'real-time protection is OFF; every Defender result would be meaningless until it is on'
    }
    if ($mp.IsTamperProtected) {
        Write-Host ''
        Write-Host '  Tamper Protection is ON.' -ForegroundColor Yellow
        Write-Host '  The Defender A/B toggle cannot change settings while it is on.' -ForegroundColor Yellow
        Write-Host '  Turn it off in Windows Security > Virus & threat protection >' -ForegroundColor DarkGray
        Write-Host '  Manage settings > Tamper Protection, then re-run the A/B when you need it.' -ForegroundColor DarkGray
    }
} catch {
    Write-Problem "Get-MpComputerStatus failed: $($_.Exception.Message)"
    Write-Host '  The Defender module is not available. On Windows 11 it should be.' -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 3. Mark of the Web
# ---------------------------------------------------------------------------
Write-Section '3. mark-of-the-web on the lab files'

if (-not (Test-Path $LabFolder)) {
    Write-Problem "lab folder not found: $LabFolder"
    Write-Host "  copy the lab files there first (the QUICKSTART covers how)." -ForegroundColor Yellow
} else {
    $files = Get-ChildItem $LabFolder -Recurse -File -ErrorAction SilentlyContinue
    $unblocked = 0
    $failed = 0
    foreach ($f in $files) {
        try {
            $streams = Get-Item $f.FullName -Stream * -ErrorAction Stop |
                       Where-Object { $_.Stream -eq 'Zone.Identifier' }
            if ($streams) {
                Unblock-File -Path $f.FullName -ErrorAction Stop
                $unblocked++
            }
        } catch {
            $failed++
        }
    }
    Write-Host ("  files scanned   : {0}" -f $files.Count) -ForegroundColor Gray
    Write-Host ("  files unblocked : {0}" -f $unblocked) -ForegroundColor Green
    if ($failed) {
        Write-Host ("  could not unblock: {0}" -f $failed) -ForegroundColor Yellow
    }

    # Report the execution policy but do not change it. PowerShell's
    # execution policy is a safety feature, not a security boundary --
    # Microsoft says so explicitly -- and unblocking the files is the
    # actual fix for the unsigned-script error.
    Write-Host ''
    Write-Host '  execution policy:' -ForegroundColor White
    Get-ExecutionPolicy -List | ForEach-Object {
        Write-Host ("    {0,-14} {1}" -f $_.Scope, $_.ExecutionPolicy) -ForegroundColor DarkGray
    }
    Write-Host ("    effective      : {0}" -f (Get-ExecutionPolicy)) -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 4. Report directories
# ---------------------------------------------------------------------------
Write-Section '4. report directories'
foreach ($d in @($ReportDir, (Join-Path $LabFolder 'reports'))) {
    try {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-Host ("  {0}" -f $d) -ForegroundColor Green
    } catch {
        Write-Problem "could not create $d : $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 5. Sysmon
# ---------------------------------------------------------------------------
Write-Section '5. Sysmon'

if ($SkipSysmon) {
    Write-Host '  skipped by request (-SkipSysmon).' -ForegroundColor Yellow
} else {
    $sysmon = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if (-not $sysmon) { $sysmon = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue }
    if ($sysmon) {
        Write-Host ("  installed: {0} ({1})" -f $sysmon.Name, $sysmon.Status) -ForegroundColor Green
    } else {
        Write-Host '  not installed.' -ForegroundColor Yellow
        Write-Host '  Sysmon provides the telemetry the whole measurement depends on.' -ForegroundColor DarkGray
        Write-Host '  Install it, then apply the lab config:' -ForegroundColor White
        Write-Host '    1. download Sysmon from the official Sysinternals site' -ForegroundColor DarkGray
        Write-Host '    2. .\Sysmon64.exe -i .\sysmon_config.xml' -ForegroundColor DarkGray
        Write-Host '    3. .\Sysmon64.exe -c' -ForegroundColor DarkGray
        Write-Host '  The config is at: ' -ForegroundColor DarkGray
        Write-Host ("    {0}" -f (Join-Path $PSScriptRoot 'sysmon_config.xml')) -ForegroundColor DarkGray
        Write-Problem 'Sysmon is not installed; the Phase 4 measurement has no signal source'
    }
}

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
Write-Section 'summary'

if ($script:problems.Count) {
    Write-Host '  PROBLEMS THAT MUST BE FIXED BEFORE MEASURING:' -ForegroundColor Red
    foreach ($p in $script:problems) { Write-Host ("    ! {0}" -f $p) -ForegroundColor Red }
} else {
    Write-Host '  The VM is prepared.' -ForegroundColor Green
}

Write-Host ''
Write-Host '  NEXT, IN THIS ORDER:' -ForegroundColor White
Write-Host '    1. verify the isolation:  .\verify_labnet.ps1' -ForegroundColor White
Write-Host '    2. capture the BEFORE state:' -ForegroundColor White
Write-Host '       .\collect_defender.ps1 -Label before_chain' -ForegroundColor White
Write-Host '    3. run the chain:' -ForegroundColor White
Write-Host "       `$env:PX_C2_HOST = '$LabGateway'; `$env:PX_C2_PORT = '$C2Port'" -ForegroundColor White
Write-Host '       .\px_loader.exe .\px_attack_chain.pdf .\loader.log' -ForegroundColor White
Write-Host '    4. capture the AFTER state:' -ForegroundColor White
Write-Host '       .\collect_defender.ps1 -Label after_chain' -ForegroundColor White
Write-Host ''
Write-Host '  DO NOT install the PDF handler before step 2 of Phase 1 -- the' -ForegroundColor DarkGray
Write-Host '  reader-behaviour measurement has to see a real reader first.' -ForegroundColor DarkGray
Write-Host ''

if ($script:problems.Count) { exit 1 }
exit 0
