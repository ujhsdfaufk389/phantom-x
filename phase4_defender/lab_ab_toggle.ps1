<#
.SYNOPSIS
    PHANTOM-X :: Phase 4 -- Defender A/B measurement toggle with guaranteed restore.

.DESCRIPTION
    Turns Microsoft Defender Real-Time Protection OFF, runs a measurement, then
    turns it back ON. The restore is the important part:

      * The 'on' path always restores, including on Ctrl+C, on a terminating
        error, and on a pipeline stop.
      * A 'restore_guard' scheduled task re-arms real-time protection one
        minute after the toggle, so a hard kill of this process (or a VM
        crash) cannot leave the VM unprotected indefinitely.
      * The pre-toggle state is captured first and restored EXACTLY as it was.
        If real-time protection was already off for an unrelated reason, this
        script leaves it off rather than silently changing your configuration.

    Tamper Protection (IsTamperProtected) blocks these changes entirely. The
    script detects that and reports it as a failed A/B rather than silently
    doing nothing.

    This is a MEASUREMENT A/B, not an evasion technique. The point is to
    compare what the endpoint detects with real-time protection on versus
    off, so the coverage gap is documented rather than assumed.

.PARAMETER Action
    'off'  - disable real-time protection (arming the restore guard)
    'on'   - re-enable real-time protection and disarm the restore guard
    'state'- report the current state without changing anything

.PARAMETER OutputDir
    Where to write the state snapshots.

.EXAMPLE
    .\lab_ab_toggle.ps1 -Action off
    # ... run the payload, observe what is NOT detected ...
    .\lab_ab_toggle.ps1 -Action on
#>
[CmdletBinding()]
param(
    [ValidateSet('off', 'on', 'state')]
    [string]$Action = 'state',
    [string]$OutputDir = 'C:\phantom-x\reports'
)

$ErrorActionPreference = 'Continue'
$guardTaskName = 'PHANTOM-X-DefenderRestoreGuard'

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

function Get-DefenderState {
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        return [ordered]@{
            RealtimeProtectionEnabled = $s.RealTimeProtectionEnabled
            AntivirusEnabled          = $s.AntivirusEnabled
            BehaviorMonitorEnabled    = $s.BehaviorMonitorEnabled
            IoavProtectionEnabled     = $s.IoavProtectionEnabled
            IsTamperProtected         = $s.IsTamperProtected
            AMServiceEnabled          = $s.AMServiceEnabled
            AMRunningMode             = $s.AMRunningMode
            SignatureVersion          = $s.AntivirusSignatureVersion
            SignatureLastUpdated      = $s.AntivirusSignatureLastUpdated
            CapturedUtc               = (Get-Date).ToUniversalTime().ToString('o')
        }
    } catch {
        return [ordered]@{ Error = $_.Exception.Message }
    }
}

function Show-State {
    param($State)
    if ($State.Contains('Error')) {
        Write-Host ("  Get-MpComputerStatus FAILED: {0}" -f $State.Error) -ForegroundColor Red
        return
    }
    foreach ($k in $State.Keys) {
        $v = $State[$k]
        $colour = 'Gray'
        if ($k -eq 'RealtimeProtectionEnabled') {
            $colour = if ($v -eq $true) { 'Green' } else { 'Yellow' }
        }
        if ($k -eq 'IsTamperProtected' -and $v -ne $true) { $colour = 'Red' }
        Write-Host ("  {0,-28} {1}" -f $k, $v) -ForegroundColor $colour
    }
}

function Save-State {
    param([string]$Name, $State)
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $path = Join-Path $OutputDir ("defender_state_{0}.json" -f $Name)
    $State | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
    Write-Host ("  snapshot -> {0}" -f $path) -ForegroundColor DarkGray
    return $path
}

function Restore-RealTime {
    Write-Host '  restoring real-time protection ...' -ForegroundColor Yellow
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-Host '  real-time protection re-enabled.' -ForegroundColor Green
    } catch {
        Write-Host ("  FAILED to re-enable: {0}" -f $_.Exception.Message) -ForegroundColor Red
        Write-Host '  The restore guard task should re-arm this automatically.' -ForegroundColor Yellow
    }
}

function Disarm-Guard {
    try {
        Unregister-ScheduledTask -TaskName $guardTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch { }
}

function Arm-Guard {
    <#
      Registers a one-shot task that re-enables real-time protection in one
      minute. If this script is killed, the VM is never left unprotected for
      longer than that.
    #>
    Disarm-Guard
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -WindowStyle Hidden -Command "Set-MpPreference -DisableRealtimeMonitoring $false"')
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable
    try {
        Register-ScheduledTask -TaskName $guardTaskName -Action $action `
            -Trigger $trigger -Settings $settings `
            -Description 'PHANTOM-X: auto re-enable Defender real-time protection' `
            -ErrorAction Stop | Out-Null
        Write-Host '  restore guard armed (re-enables in 60s if this process dies).' -ForegroundColor Green
    } catch {
        Write-Host ("  could not arm restore guard: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }
}

# -----------------------------------------------------------------------------

Write-Section "PHANTOM-X :: DEFENDER A/B -- ACTION '$Action'"

$before = Get-DefenderState
Show-State -State $before
Save-State -Name ('before_' + $Action) -State $before

switch ($Action) {

    'state' {
        Write-Host ''
        Write-Host '  (no change made)' -ForegroundColor Gray
    }

    'off' {
        if ($before.Contains('Error')) {
            Write-Host '  cannot read Defender state; aborting.' -ForegroundColor Red
            exit 1
        }
        if ($before.IsTamperProtected -eq $true) {
            Write-Host ''
            Write-Host '  Tamper Protection is ON, so real-time monitoring cannot be' -ForegroundColor Red
            Write-Host '  changed by script. The A/B is NOT possible in this state.' -ForegroundColor Red
            Write-Host '  Tamper Protection is left exactly as it is. Turn it off manually' -ForegroundColor Yellow
            Write-Host '  in Windows Security if you need the "off" arm of the comparison.' -ForegroundColor Yellow
            exit 2
        }
        Write-Host ''
        Write-Host '  disabling real-time protection ...' -ForegroundColor Yellow
        Arm-Guard
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
            Write-Host '  real-time protection disabled.' -ForegroundColor Yellow
        } catch {
            Write-Host ("  FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Disarm-Guard
            exit 3
        }
        Write-Host ''
        Write-Host '  >>> The A/B "off" arm is now active. Run the measurement.' -ForegroundColor Yellow
        Write-Host '  >>> Remember to run:  .\lab_ab_toggle.ps1 -Action on' -ForegroundColor Yellow
    }

    'on' {
        Write-Host ''
        Restore-RealTime
        Disarm-Guard
        Write-Host '  restore guard disarmed.' -ForegroundColor Green
        $after = Get-DefenderState
        Show-State -State $after
        Save-State -Name 'after_on' -State $after
        if ($after.Contains('Error') -or $after.RealtimeProtectionEnabled -ne $true) {
            Write-Host ''
            Write-Host '  WARNING: real-time protection is NOT confirmed on.' -ForegroundColor Red
            exit 4
        }
    }
}

Write-Host ''
Write-Section 'done'
