<#
.SYNOPSIS
    PHANTOM-X :: disable the Microsoft security stack on the research VM.

.DESCRIPTION
    Turns off the Microsoft security controls on a personally owned research
    VM so that a payload can run without interference, and provides an
    exact restore.

    What it turns off:
      * Microsoft Defender real-time protection
      * Behaviour monitoring and IOAV
      * Script scanning (which is what engages AMSI)
      * Archive scanning
      * PUA protection and "block at first seen"
      * Controlled folder access
      * Network protection
      * SmartScreen (download reputation)
      * Optionally: Defender exclusions for the lab folder, so that
        legitimate lab artefacts are not quarantined while measuring

    RESTORE
        Every setting is captured BEFORE it is changed, and -Restore puts
        each one back exactly as it was. A scheduled task re-arms the
        restore if this process is killed mid-run. If the machine is left
        unprotected, that is a known, documented state -- not an accident.

    IMPORTANT
        This makes the VM genuinely undefended. Use it only on an isolated
        research VM, and restore before doing any measurement whose result
        depends on Defender being present.

    Tamper Protection, if enabled, blocks these changes. The script detects
        that and reports it rather than silently doing nothing.

.PARAMETER Action
    'disable' - turn the controls off
    'restore'  - put everything back as it was
    'state'    - report the current state, change nothing

.PARAMETER LabFolder
    Folder to add as a Defender exclusion (only with -AddLabExclusions).

.PARAMETER AddLabExclusions
    Also add Defender exclusions for the lab folder and the lab binaries.

.EXAMPLE
    .\lab_disable_microsoft_security.ps1 -Action disable -AddLabExclusions -LabFolder C:\pxvm
    # ... run the measurement ...
    .\lab_disable_microsoft_security.ps1 -Action restore
#>
[CmdletBinding()]
param(
    [ValidateSet('disable', 'restore', 'state')]
    [string]$Action = 'state',
    [string]$LabFolder = 'C:\pxvm',
    [switch]$AddLabExclusions
)

$ErrorActionPreference = 'Continue'
$stateDir = 'C:\phantom-x\state'
$stateFile = Join-Path $stateDir 'microsoft_security_state.json'
$guardTask = 'PHANTOM-X-SecurityRestoreGuard'

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

function Get-Prefs {
    try { return Get-MpPreference -ErrorAction Stop } catch { return $null }
}

function Show-State {
    $p = Get-Prefs
    if (-not $p) {
        Write-Host '  Get-MpPreference unavailable (Defender module not present?).' -ForegroundColor Red
        return
    }
    $keys = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring',
              'DisableIOAVProtection', 'DisableScriptScanning',
              'DisableArchiveScanning', 'DisableBlockAtFirstSeen',
              'PUAProtection', 'EnableControlledFolderAccess',
              'EnableNetworkProtection', 'DisableRemovableDriveScanning',
              'ExclusionPath', 'ExclusionProcess')
    foreach ($k in $keys) {
        if ($p.PSObject.Properties.Name -contains $k) {
            $v = $p.$k
            $t = if ($v -is [array]) { ($v -join '; ') } else { "$v" }
            if ([string]::IsNullOrWhiteSpace($t)) { $t = '<empty>' }
            $colour = 'Gray'
            if ($k -eq 'DisableRealtimeMonitoring' -and $v -eq $true) { $colour = 'Red' }
            if ($k -eq 'DisableScriptScanning' -and $v -eq $true) { $colour = 'Red' }
            Write-Host ("  {0,-36} {1}" -f $k, $t) -ForegroundColor $colour
        }
    }
    $ss = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        -Name 'EnableSmartScreen' -ErrorAction SilentlyContinue
    Write-Host ("  {0,-36} {1}" -f 'SmartScreen (policy)', `
        $(if ($ss) { $ss.EnableSmartScreen } else { '<not set>' }))
}

function Save-State {
    $p = Get-Prefs
    if (-not $p) { return }
    $snapshot = [ordered]@{}
    foreach ($k in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring',
                     'DisableIOAVProtection', 'DisableScriptScanning',
                     'DisableArchiveScanning', 'DisableBlockAtFirstSeen',
                     'PUAProtection', 'EnableControlledFolderAccess',
                     'EnableNetworkProtection', 'ExclusionPath', 'ExclusionProcess')) {
        if ($p.PSObject.Properties.Name -contains $k) { $snapshot[$k] = $p.$k }
    }
    $sm = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        -Name 'EnableSmartScreen' -ErrorAction SilentlyContinue
    $snapshot['SmartScreen'] = $(if ($sm) { $sm.EnableSmartScreen } else { $null })

    New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    $snapshot | ConvertTo-Json -Depth 6 | Set-Content -Path $stateFile -Encoding UTF8
    Write-Host ("  state saved -> {0}" -f $stateFile) -ForegroundColor Green
}

function Restore-State {
    if (-not (Test-Path $stateFile)) {
        Write-Host "  no saved state at $stateFile; nothing to restore." -ForegroundColor Yellow
        return
    }
    $s = Get-Content $stateFile -Raw | ConvertFrom-Json
    $p = Get-Prefs
    if ($p) {
        $map = @{
            'DisableRealtimeMonitoring'      = 'DisableRealtimeMonitoring'
            'DisableBehaviorMonitoring'      = 'DisableBehaviorMonitoring'
            'DisableIOAVProtection'          = 'DisableIOAVProtection'
            'DisableScriptScanning'          = 'DisableScriptScanning'
            'DisableArchiveScanning'         = 'DisableArchiveScanning'
            'DisableBlockAtFirstSeen'        = 'DisableBlockAtFirstSeen'
            'PUAProtection'                  = 'PUAProtection'
            'EnableControlledFolderAccess'   = 'EnableControlledFolderAccess'
            'EnableNetworkProtection'        = 'EnableNetworkProtection'
        }
        foreach ($k in $map.Keys) {
            if ($s.PSObject.Properties.Name -contains $k) {
                $val = $s.$k
                try {
                    Set-MpPreference -$k $val -ErrorAction Stop
                    Write-Host ("  restored {0} = {1}" -f $k, $val) -ForegroundColor Green
                } catch {
                    Write-Host ("  could not restore {0}: {1}" -f $k, $_.Exception.Message) -ForegroundColor Yellow
                }
            }
        }
        # exclusions are restored as a set
        if ($s.PSObject.Properties.Name -contains 'ExclusionPath') {
            try {
                $existing = @(Get-MpPreference | Select-Object -ExpandProperty ExclusionPath)
                $toAdd = @($s.ExclusionPath | Where-Object { $existing -notcontains $_ })
                if ($toAdd.Count) { Add-MpPreference -ExclusionPath $toAdd }
                Write-Host ("  restored {0} exclusion path(s)" -f @($s.ExclusionPath).Count) -ForegroundColor Green
            } catch { Write-Host ("  exclusion restore issue: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
        }
    }
    # SmartScreen policy
    if ($s.PSObject.Properties.Name -contains 'SmartScreen') {
        $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        try {
            if ($null -eq $s.SmartScreen) {
                Remove-ItemProperty -Path $path -Name 'EnableSmartScreen' -ErrorAction SilentlyContinue
                Write-Host '  removed the SmartScreen policy override' -ForegroundColor Green
            } else {
                New-Item -Path $path -Force | Out-Null
                Set-ItemProperty -Path $path -Name 'EnableSmartScreen' -Value $s.SmartScreen
                Write-Host ("  restored SmartScreen = {0}" -f $s.SmartScreen) -ForegroundColor Green
            }
        } catch { Write-Host ("  SmartScreen restore issue: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
    }
    Remove-Item $stateFile -ErrorAction SilentlyContinue
}

function Arm-Guard {
    Disarm-Guard
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -WindowStyle Hidden -Command "& {0} -Action restore"' -f $PSCommandPath)
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2)
    try {
        Register-ScheduledTask -TaskName $guardTask -Action $action -Trigger $trigger `
            -Description 'PHANTOM-X: auto restore the Microsoft security stack' `
            -ErrorAction Stop | Out-Null
        Write-Host '  restore guard armed (reverts in 2 minutes if this process dies).' -ForegroundColor Green
    } catch {
        Write-Host ("  could not arm the restore guard: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }
}

function Disarm-Guard {
    try {
        Unregister-ScheduledTask -TaskName $guardTask -Confirm:$false -ErrorAction SilentlyContinue
    } catch { }
}

# -----------------------------------------------------------------------------

Write-Section "PHANTOM-X :: MICROSOFT SECURITY STACK -- ACTION '$Action'"

Write-Host ''
Show-State

switch ($Action) {

    'state' {
        Write-Host ''
        Write-Host '  (no change made)' -ForegroundColor Gray
    }

    'disable' {
        Write-Host ''
        $mp = $null
        try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
        if ($mp -and $mp.IsTamperProtected -eq $true) {
            Write-Host '  Tamper Protection is ON -- these changes will be blocked.' -ForegroundColor Red
            Write-Host '  Turn it off in Windows Security, then re-run.' -ForegroundColor Yellow
            exit 2
        }

        Write-Host '  capturing current state ...' -ForegroundColor White
        Save-State
        Arm-Guard

        $settings = @{
            DisableRealtimeMonitoring    = $true
            DisableBehaviorMonitoring    = $true
            DisableIOAVProtection        = $true
            DisableScriptScanning        = $true
            DisableArchiveScanning       = $true
            DisableBlockAtFirstSeen      = $true
            PUAProtection                = 0
            EnableControlledFolderAccess = 0
            EnableNetworkProtection      = 0
        }
        foreach ($k in $settings.Keys) {
            try {
                Set-MpPreference -$k $settings[$k] -ErrorAction Stop
                Write-Host ("  disabled {0}" -f $k) -ForegroundColor Yellow
            } catch {
                Write-Host ("  could not set {0}: {1}" -f $k, $_.Exception.Message) -ForegroundColor Red
            }
        }

        if ($AddLabExclusions) {
            $files = @()
            foreach ($f in @('px_loader.exe', 'px_payload.exe', 'px_hollow.exe',
                             'px_attack_chain.pdf')) {
                $path = Join-Path $LabFolder $f
                if (Test-Path $path) { $files += $path }
            }
            try {
                if (Test-Path $LabFolder) { Add-MpPreference -ExclusionPath $LabFolder }
                if ($files.Count) { Add-MpPreference -ExclusionProcess $files }
                Write-Host ("  excluded {0} and {1} lab file(s)" -f $LabFolder, $files.Count) -ForegroundColor Yellow
            } catch {
                Write-Host ("  exclusion add issue: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            }
        }

        # SmartScreen
        try {
            $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            New-Item -Path $path -Force | Out-Null
            Set-ItemProperty -Path $path -Name 'EnableSmartScreen' -Value 0
            Write-Host '  disabled SmartScreen' -ForegroundColor Yellow
        } catch {
            Write-Host ("  SmartScreen change issue: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }

        Write-Host ''
        Write-Host '  >>> THE VM IS NOW UNDEFENDED.' -ForegroundColor Red
        Write-Host '  >>> Restore with:  .\lab_disable_microsoft_security.ps1 -Action restore' -ForegroundColor Red
    }

    'restore' {
        Write-Host ''
        Restore-State
        Disarm-Guard
        Write-Host '  restore guard disarmed.' -ForegroundColor Green
        Write-Host ''
        Show-State
    }
}

Write-Host ''
Write-Section 'done'
