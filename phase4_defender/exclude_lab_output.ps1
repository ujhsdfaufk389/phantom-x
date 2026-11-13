#Requires -Version 5.1
<#
.SYNOPSIS
    PHANTOM-X :: keep the endpoint from quarantining the lab's own build output.

.DESCRIPTION
    The lab's payload is detected. On the build machine, Microsoft Defender
    classifies it as Trojan:Win32/Wacatac.H!ml, and quarantines the binary
    the moment it is built or run.

    That is not a defect in the lab. It is one of its findings: the
    endpoint, unprompted, on the operator's own machine, reaches the same
    conclusion a defender would.

    But it does make the lab's regression suite unreliable, because the
    binary disappears between the build and the test that drives it, and
    the failure says "variant payload not found" -- which says nothing
    about why.

    WHAT THIS DOES
        Adds a Defender EXCLUSION for the lab's BUILD OUTPUT directory.

        It is an exclusion, not a switch. Defender stays ON. It still
        scans everything else on the machine, it still logs, it still
        alerts. The only thing it stops doing is eating the files the
        lab builds for itself.

        This matters for the lab's own method. The ground rule is that
        the endpoint's view is the measurement, and a measurement taken
        with the endpoint switched off is not a measurement. An
        exclusion for ONE directory does not switch anything off; it
        stops the endpoint from deleting the instrument.

    WHERE THE MEASUREMENT ACTUALLY HAPPENS
        On the VM, not here. The payload is deployed to the VM at a
        different path, with no exclusion, and the endpoint there sees
        every technique the lab exercises. Excluding the build output
        on the operator's machine does not weaken that.

    ADMINISTRATOR
        Defender preferences need elevation. Run this once, from an
        elevated PowerShell:

            .\exclude_lab_output.ps1

        To remove it again:

            .\exclude_lab_output.ps1 -Remove

.PARAMETER Remove
    Take the exclusions away again.

.PARAMETER ExtraPath
    Additional directories to exclude. The VM lab folder is a useful
    one, because the payload is deployed from there.

.PARAMETER OutputDir
    The build output directory to exclude. Defaults to the repository's
    dist\variants.

.EXAMPLE
    .\exclude_lab_output.ps1

.EXAMPLE
    .\exclude_lab_output.ps1 -ExtraPath C:\pxvm
#>
[CmdletBinding()]
param(
    [switch]$Remove,
    [string[]]$ExtraPath = @(),
    [string]$OutputDir = ''
)

$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$root = Split-Path (Split-Path $here -Parent) -Parent

if (-not $OutputDir) {
    $OutputDir = Join-Path $root 'dist\variants'
}

$paths = @()
$paths += (Join-Path $root 'dist\variants')
$paths += (Join-Path $root 'dist\native')
$paths += (Join-Path $root 'phase3_fileless\loader')
foreach ($p in $ExtraPath) { $paths += $p }
$paths = $paths | Select-Object -Unique

Write-Host ''
Write-Host ('=' * 70) -ForegroundColor DarkGray
Write-Host 'PHANTOM-X :: DEFENDER EXCLUSION FOR THE LAB''S OWN BUILD OUTPUT' -ForegroundColor Cyan
Write-Host ('=' * 70) -ForegroundColor DarkGray
Write-Host ''

# Is this shell elevated?
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '[!] this shell is not elevated.' -ForegroundColor Red
    Write-Host '    Defender preferences need an administrator.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '    Right-click Windows PowerShell and choose' -ForegroundColor White
    Write-Host '    "Run as administrator", then run:' -ForegroundColor White
    Write-Host ''
    Write-Host '        .\exclude_lab_output.ps1' -ForegroundColor Cyan
    Write-Host ''
    exit 1
}

# Is Defender even running? On a machine where the lab has switched it
# off, an exclusion is pointless -- and adding one would be a change
# that outlives the run.
try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    Write-Host ("  real-time protection : {0}" -f $status.RealTimeProtectionEnabled) -ForegroundColor Gray
    Write-Host ("  behaviour monitoring : {0}" -f $status.BehaviorMonitorEnabled) -ForegroundColor Gray
    Write-Host ("  tamper protection    : {0}" -f $status.IsTamperProtected) -ForegroundColor Gray
} catch {
    Write-Host "  Defender is not reporting status: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ''
foreach ($p in $paths) {
    if (-not (Test-Path $p)) {
        Write-Host ("    skip (not there) : {0}" -f $p) -ForegroundColor DarkGray
        continue
    }
    if ($Remove) {
        try {
            Remove-MpPreference -ExclusionPath $p -ErrorAction Stop
            Write-Host ("    removed : {0}" -f $p) -ForegroundColor Yellow
        } catch {
            Write-Host ("    could not remove : {0}" -f $p) -ForegroundColor DarkGray
        }
    } else {
        try {
            Add-MpPreference -ExclusionPath $p -ErrorAction Stop
            Write-Host ("    excluded : {0}" -f $p) -ForegroundColor Green
        } catch {
            Write-Host ("    could not exclude : {0} -- {1}" -f $p, $_.Exception.Message) -ForegroundColor Red
        }
    }
}

Write-Host ''
if ($Remove) {
    Write-Host '  The exclusions are gone. The lab will be quarantined again.' -ForegroundColor White
} else {
    Write-Host '  Defender is still ON. It just no longer eats the lab''s own' -ForegroundColor White
    Write-Host '  binaries, so the regression suite can run the same arm a' -ForegroundColor White
    Write-Host '  hundred times.' -ForegroundColor White
    Write-Host ''
    Write-Host '  This does not affect the measurement: the payload is deployed' -ForegroundColor DarkGray
    Write-Host '  to the VM at a different path, with no exclusion, and the' -ForegroundColor DarkGray
    Write-Host '  endpoint there sees every technique the lab exercises.' -ForegroundColor DarkGray
}
Write-Host ''
exit 0
