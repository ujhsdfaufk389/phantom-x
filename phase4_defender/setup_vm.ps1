<#
.SYNOPSIS
    PHANTOM-X :: one-shot VM preparation for the research lab.

.DESCRIPTION
    Prepares the Windows research VM so the lab scripts run, and records
    exactly what it changed so the preparation is auditable rather than
    mysterious.

    Steps:
      1. Unblocks the copied lab files (removes the Mark-of-the-Web
         'Zone.Identifier' stream). This is the actual fix for the
         'not digitally signed' error under the default RemoteSigned policy,
         and it does NOT change any execution policy.
      2. Reports the effective execution policy and, if a per-user policy
         can be set, sets it to RemoteSigned (Microsoft's own recommended
         setting for a development/research machine).
      3. Creates the report directories.
      4. Reports Defender posture and whether Sysmon is present.
      5. Prints a copy-paste block for the next step.

    NOTE ON SCOPE
        The PowerShell execution policy is a SAFETY feature, not a security
        boundary -- Microsoft states this explicitly. It prevents accidental
        execution of downloaded scripts. It does not sandbox anything and
        does not defend the machine from an attacker. Relaxing it for the
        operator's own local scripts on a personally owned research VM is
        standard practice and is what this script does.

        This is NOT the same as touching Defender. Defender's real-time
        protection is only ever changed by lab_ab_toggle.ps1, which is
        separately guarded and restores itself.

.PARAMETER LabFolder
    Folder containing the copied lab files.

.PARAMETER ReportDir
    Where reports are written.

.EXAMPLE
    .\setup_vm.ps1 -LabFolder C:\pxvm
#>
[CmdletBinding()]
param(
    [string]$LabFolder = 'C:\pxvm',
    [string]$ReportDir = 'C:\phantom-x\reports'
)

$ErrorActionPreference = 'Continue'
$changes = @()

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

Write-Section "PHANTOM-X :: VM SETUP -- $LabFolder"

# -----------------------------------------------------------------------------
# 1. Execution policy: report it
# -----------------------------------------------------------------------------
Write-Host ''
Write-Host '  current execution policy:' -ForegroundColor White
Get-ExecutionPolicy -List | ForEach-Object {
    Write-Host ("    {0,-14} {1}" -f $_.Scope, $_.ExecutionPolicy)
}

$machinePolicy = (Get-ExecutionPolicy -List |
    Where-Object { $_.Scope -eq 'MachinePolicy' }).ExecutionPolicy
$userPolicy = (Get-ExecutionPolicy -List |
    Where-Object { $_.Scope -eq 'UserPolicy' }).ExecutionPolicy
$effective = Get-ExecutionPolicy

Write-Host ("    effective      : {0}" -f $effective) -ForegroundColor Yellow

# -----------------------------------------------------------------------------
# 2. Unblock the lab files (the real fix for the reported error)
# -----------------------------------------------------------------------------
Write-Section '2. Removing Mark-of-the-Web from lab files'

if (Test-Path $LabFolder) {
    $files = Get-ChildItem $LabFolder -Recurse -File -ErrorAction SilentlyContinue
    $unblocked = 0
    $marked = @()
    foreach ($f in $files) {
        $hasMark = $false
        try {
            $streams = Get-Item $f.FullName -Stream * -ErrorAction Stop |
                Where-Object { $_.Stream -eq 'Zone.Identifier' }
            $hasMark = ($null -ne $streams)
        } catch { $hasMark = $false }

        if ($hasMark) {
            $marked += $f.Name
            try {
                Unblock-File -Path $f.FullName -ErrorAction Stop
                $unblocked++
            } catch {
                Write-Host ("    could not unblock {0}: {1}" -f $f.Name, $_.Exception.Message) -ForegroundColor Yellow
            }
        }
    }
    Write-Host ("    files scanned     : {0}" -f $files.Count) -ForegroundColor Gray
    Write-Host ("    files unblocked   : {0}" -f $unblocked) -ForegroundColor Green
    if ($marked.Count) {
        Write-Host ("    had MOTW mark     : {0}" -f ($marked -join ', ')) -ForegroundColor DarkGray
    }
    if ($unblocked -gt 0) {
        $changes += "Unblocked $unblocked file(s) in $LabFolder (removed Zone.Identifier)"
    }
} else {
    Write-Host ("    folder not found: {0}" -f $LabFolder) -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 3. Set a workable per-user execution policy
# -----------------------------------------------------------------------------
Write-Section '3. Execution policy'

if ($machinePolicy -and $machinePolicy -ne 'Undefined') {
    Write-Host ("    Group Policy enforces '{0}' at MachinePolicy scope." -f $machinePolicy) -ForegroundColor Yellow
    Write-Host '    That takes precedence and cannot be overridden locally.' -ForegroundColor Yellow
    Write-Host '    Unblocking (step 2) is the working route here.' -ForegroundColor Green
    if ($effective -ne 'Bypass' -and $effective -ne 'Unrestricted') {
        Write-Host ''
        Write-Host '    Fallback for a Group-Policy-locked host: run each script' -ForegroundColor Yellow
        Write-Host '    through the console instead of as a file:' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\collect_defender.ps1 -Label before_chain' -ForegroundColor White
    }
} else {
    $target = 'RemoteSigned'
    try {
        Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy $target `
            -Force -ErrorAction Stop
        Write-Host ("    set CurrentUser scope -> {0}" -f $target) -ForegroundColor Green
        $changes += "Set ExecutionPolicy (CurrentUser) = $target"
        Write-Host '    Local unsigned scripts now run; downloaded unsigned ones' -ForegroundColor DarkGray
        Write-Host '    still need Unblock-File. This is the Microsoft-recommended' -ForegroundColor DarkGray
        Write-Host '    setting for a development/research machine.' -ForegroundColor DarkGray
    } catch {
        Write-Host ("    could not set CurrentUser policy: {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host ''
Write-Host ("    effective now     : {0}" -f (Get-ExecutionPolicy))

# -----------------------------------------------------------------------------
# 4. Report directories
# -----------------------------------------------------------------------------
Write-Section '4. Report directories'
foreach ($d in @($ReportDir, "$LabFolder\reports")) {
    try {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-Host ("    {0}" -f $d) -ForegroundColor Green
    } catch {
        Write-Host ("    could not create {0}: {1}" -f $d, $_.Exception.Message) -ForegroundColor Yellow
    }
}

# -----------------------------------------------------------------------------
# 5. Defender + Sysmon posture
# -----------------------------------------------------------------------------
Write-Section '5. Endpoint posture'

try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Write-Host ("    Real-Time Protection : {0}" -f $mp.RealTimeProtectionEnabled) `
        -ForegroundColor $(if ($mp.RealTimeProtectionEnabled) { 'Green' } else { 'Red' })
    Write-Host ("    Antivirus Enabled    : {0}" -f $mp.AntivirusEnabled) `
        -ForegroundColor $(if ($mp.AntivirusEnabled) { 'Green' } else { 'Red' })
    Write-Host ("    Behavior Monitor     : {0}" -f $mp.BehaviorMonitorEnabled) -ForegroundColor Gray
    Write-Host ("    Ioav Protection      : {0}" -f $mp.IoavProtectionEnabled) -ForegroundColor Gray
    Write-Host ("    Tamper Protected     : {0}" -f $mp.IsTamperProtected) -ForegroundColor Gray
    Write-Host ("    Signature version    : {0}  ({1})" -f $mp.AntivirusSignatureVersion, $mp.AntivirusSignatureLastUpdated) -ForegroundColor Gray
    Write-Host ("    AM service enabled   : {0}" -f $mp.AMServiceEnabled) -ForegroundColor Gray
} catch {
    Write-Host ("    Get-MpComputerStatus failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host '    Run this from an ELEVATED PowerShell (not the VS Code terminal).' -ForegroundColor Yellow
}

$sysmon = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
if (-not $sysmon) { $sysmon = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue }
if ($sysmon) {
    Write-Host ("    Sysmon service       : {0} ({1})" -f $sysmon.Name, $sysmon.Status) -ForegroundColor Green
} else {
    Write-Host '    Sysmon service       : NOT FOUND' -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# 6. Summary
# -----------------------------------------------------------------------------
Write-Section '6. Summary of changes made by this script'
if ($changes.Count) {
    foreach ($c in $changes) { Write-Host ("    - {0}" -f $c) -ForegroundColor Green }
} else {
    Write-Host '    (nothing needed changing)' -ForegroundColor Gray
}

Write-Host ''
Write-Host '  NEXT:' -ForegroundColor White
Write-Host '    .\collect_defender.ps1 -Label before_chain' -ForegroundColor White
Write-Host '    $env:PX_C2_HOST = "<kali-ip>"; $env:PX_C2_PORT = "9001"' -ForegroundColor White
Write-Host '    .\px_loader.exe .\px_attack_chain.pdf .\loader.log' -ForegroundColor White
Write-Host ''
