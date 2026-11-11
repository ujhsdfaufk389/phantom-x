#Requires -Version 5.1
<#
.SYNOPSIS
    PHANTOM-X :: Phase 8 -- collect the telemetry the rules are evaluated against.

.DESCRIPTION
    Runs on the lab VM and exports the Windows events the detection rules
    key on, as JSON, so that px_eval.py can evaluate them.

    WHY THIS EXISTS
        The lab's loop was incomplete. There were variant arms, there
        were detection rules, and there was nothing that connected the
        two -- so the lab could not say whether a rule still worked once
        the payload was obfuscated, once ETW was unhooked, or once the
        channel was encrypted.

        This is the piece that connects them.

    WHAT IT COLLECTS
        The Sysmon operational log, the Defender operational log, the
        Windows Defender and Sysmon service events, and the security log
        where it holds service-creation and log-cleared events.

        It collects the events for a WINDOW rather than the whole log, so
        that a run can be attributed to a run.

    WHAT IT DOES NOT DO
        It does not clear anything. The point is to leave the evidence
        in place so that the operator can look at it in the event viewer
        afterwards with the same eyes as anyone else.

.PARAMETER Label
    A name for this collection, used in the output file name.

.PARAMETER OutputDir
    Where to write the JSON.

.PARAMETER Minutes
    How far back to collect. The default is 10, which covers a run with
    some slack for a slow operator.

.PARAMETER IncludeSecurity
    Also collect the security log. It needs audit policy for some event
    types, and it is slower.

.EXAMPLE
    .\collect_events.ps1 -Label baseline_arm -OutputDir C:\pxvm\events

.EXAMPLE
    .\collect_events.ps1 -Label variant -Minutes 30 -IncludeSecurity
#>
[CmdletBinding()]
param(
    [string]$Label = 'run',
    [string]$OutputDir = 'C:\phantom-x\events',
    [int]$Minutes = 10,
    [switch]$IncludeSecurity
)

$ErrorActionPreference = 'Continue'

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

Write-Section "PHANTOM-X :: TELEMETRY COLLECTION -- $Label"

$start = (Get-Date).AddMinutes(-$Minutes)
$events = New-Object System.Collections.ArrayList

function Add-Log {
    param(
        [string]$LogName,
        [string]$Display,
        [string[]]$Levels = @('Information', 'Warning', 'Error', 'Critical')
    )
    Write-Host ("  reading {0} ..." -f $Display) -ForegroundColor DarkGray
    try {
        $filter = @{
            LogName   = $LogName
            StartTime = $start
        }
        if ($Levels) { $filter.Level = $Levels }
        $records = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
                   Select-Object -First 5000
        foreach ($r in $records) {
            $e = [ordered]@{
                EventID     = $r.Id
                Provider    = $r.ProviderName
                LogName     = $r.LogName
                TimeCreated = $r.TimeCreated.ToUniversalTime().ToString('o')
                Level       = $r.LevelDisplayName
                Message     = ($r.Message -replace '\s+', ' ')
            }
            # Sysmon puts the useful fields in the XML, not in the message.
            # Without them a rule on Image or TargetImage cannot match.
            try {
                $xml = [xml]$r.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) {
                    if ($d.Name) { $data[$d.Name] = $d.'#text' }
                }
                foreach ($k in $data.Keys) {
                    if ($k -and $data[$k] -and -not $e.Contains($k)) {
                        $e[$k] = $data[$k]
                    }
                }
            } catch { }
            [void]$events.Add($e)
        }
        Write-Host ("    {0} events" -f $records.Count) -ForegroundColor DarkGray
    } catch {
        Write-Host ("    unavailable: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host ("  window : the last {0} minutes" -f $Minutes) -ForegroundColor White

Add-Log -LogName 'Microsoft-Windows-Sysmon/Operational' -Display 'Sysmon'
Add-Log -LogName 'Microsoft-Windows-Windows Defender/Operational' -Display 'Defender'
Add-Log -LogName 'Microsoft-Windows-TaskScheduler/Operational' -Display 'Task Scheduler'
Add-Log -LogName 'Microsoft-Windows-DNS-Client/Operational' -Display 'DNS client'
Add-Log -LogName 'Microsoft-Windows-PowerShell/Operational' -Display 'PowerShell'

if ($IncludeSecurity) {
    # The security log is where service creation (7045) and log-cleared
    # (1102) live. It needs the audit policy to be on for some of them.
    Add-Log -LogName 'Security' -Display 'Security' -Levels @()
}

# The service events channel, which is where a service install lands when
# the security log is not collecting it.
Add-Log -LogName 'System' -Display 'System (service events)' -Levels @('Information', 'Warning', 'Error')

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$out = Join-Path $OutputDir ("events_{0}.json" -f $Label)

$payload = [ordered]@{
    label        = $Label
    collected_utc = (Get-Date).ToUniversalTime().ToString('o')
    window_start = $start.ToUniversalTime().ToString('o')
    window_minutes = $Minutes
    computer     = $env:COMPUTERNAME
    event_count  = $events.Count
    events       = $events
}

$payload | ConvertTo-Json -Depth 6 | Set-Content -Path $out -Encoding UTF8

Write-Section 'summary'
Write-Host ("  collected : {0} events" -f $events.Count) -ForegroundColor Green
Write-Host ("  written   : {0}" -f $out) -ForegroundColor Green
Write-Host ''
Write-Host '  NEXT: evaluate the rules against them.' -ForegroundColor White
Write-Host ('    python3 phase8_evaluation\px_eval.py --rules rules.json --events "' + $out + '"') -ForegroundColor White
Write-Host ''
