<#
.SYNOPSIS
    PHANTOM-X :: Phase 0 -- verify the network isolation actually holds.

.DESCRIPTION
    A firewall configuration that was never tested is a configuration that
    does not work. This script probes the live network and reports what it
    found.

    The checks:

      HOME-1  can the VM reach a public address?            expect FAIL
      HOME-2  can the VM reach the gateway's home-LAN IP?   expect FAIL
      DNS-1   can the VM resolve a public name?             expect FAIL
      LAB-1   can the VM reach the C2 port on the gateway?  expect SUCCESS

    A FAIL where SUCCESS was expected is the failure that matters: it means
    the lab is not actually isolated.

    Run this INSIDE the VM.

.PARAMETER LabGateway
    IP of the operator machine on the host-only segment.

.PARAMETER C2Port
    The TCP port the C2 server listens on.

.PARAMETER HomeGateway
    Optional: the operator's HOME router IP. If supplied, HOME-2 probes it
    directly. If omitted, the script tries to infer the home range from the
    default route.

.EXAMPLE
    .\verify_labnet.ps1 -LabGateway 192.168.77.1 -C2Port 9001
#>
[CmdletBinding()]
param(
    [string]$LabGateway = '192.168.77.1',
    [int]$C2Port = 9001,
    [string]$HomeGateway = '',
    [int]$TimeoutSec = 4
)

$ErrorActionPreference = 'Continue'

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

function Test-TcpPort {
    param([string]$Address, [int]$Port, [int]$TimeoutMs = 4000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($iar)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Test-Udp53 {
    param([string]$Server, [int]$TimeoutMs = 4000)
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($Server, 53)
        $q = [byte[]]@(0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01)
        $udp.Send($q, $q.Length)
        $resp = $udp.Receive([ref]([byte[]]::new(512)))
        return ($resp.Length -gt 0)
    } catch {
        return $false
    } finally {
        $udp.Close()
    }
}

$results = @()

function Add-Result {
    param([string]$Name, [string]$Expect, [bool]$Ok, [string]$Detail)
    $script:results += [pscustomobject]@{
        Name = $Name; Expect = $Expect; Passed = $Ok; Detail = $Detail
    }
    $tag = if ($Ok) { 'PASS' } else { 'FAIL' }
    $colour = if ($Ok) { 'Green' } else { 'Red' }
    Write-Host ("  [{0}] {1,-10} expect {2,-8} {3}" -f $tag, $Name, $Expect, $Detail) -ForegroundColor $colour
}

Write-Section 'PHANTOM-X :: NETWORK ISOLATION VERIFICATION'

Write-Host ''
Write-Host '  adapters:' -ForegroundColor White
Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } |
    ForEach-Object {
        Write-Host ("    {0,-30} {1}" -f $_.Name, $_.InterfaceDescription) -ForegroundColor DarkGray
    }

Write-Host ''
Write-Host '  routes:' -ForegroundColor White
Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -notlike '255.*' } |
    Sort-Object RouteMetric |
    ForEach-Object {
        Write-Host ("    {0,-20} via {1,-15} {2}" -f `
            $_.DestinationPrefix, $_.NextHop, $_.InterfaceAlias) -ForegroundColor DarkGray
    }

Write-Section 'checks'

# --- HOME-1: public address -------------------------------------------------
Write-Host '  probing a public address ...' -ForegroundColor DarkGray
$pub = Test-TcpPort -Address '1.1.1.1' -Port 443 -TimeoutMs ($TimeoutSec * 1000)
Add-Result -Name 'HOME-1' -Expect 'UNREACHABLE' -Ok (-not $pub) `
    -Detail "TCP 1.1.1.1:443 -> $(if ($pub) { 'REACHABLE (bad)' } else { 'blocked' })"

# --- HOME-2: home LAN -------------------------------------------------------
if (-not $HomeGateway) {
    $def = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
           -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
    if ($def) { $HomeGateway = $def.NextHop }
}
if ($HomeGateway) {
    Write-Host "  probing the home gateway $HomeGateway ..." -ForegroundColor DarkGray
    $hg = Test-TcpPort -Address $HomeGateway -Port 80 -TimeoutMs ($TimeoutSec * 1000)
    Add-Result -Name 'HOME-2' -Expect 'UNREACHABLE' -Ok (-not $hg) `
        -Detail "$HomeGateway:80 -> $(if ($hg) { 'REACHABLE (bad)' } else { 'blocked' })"
} else {
    Write-Host '  [SKIP] HOME-2 -- no home gateway could be determined.' -ForegroundColor Yellow
}

# --- DNS-1 ------------------------------------------------------------------
Write-Host '  probing DNS ...' -ForegroundColor DarkGray
$dnsOk = Test-Udp53 -Server $LabGateway -TimeoutMs ($TimeoutSec * 1000)
Add-Result -Name 'DNS-1' -Expect 'NO RESOLVE' -Ok (-not $dnsOk) `
    -Detail "DNS via $LabGateway -> $(if ($dnsOk) { 'answered public query (bad)' } else { 'no answer' })"

# --- LAB-1 ------------------------------------------------------------------
Write-Host "  probing the C2 on $LabGateway`:$C2Port ..." -ForegroundColor DarkGray
$c2ok = Test-TcpPort -Address $LabGateway -Port $C2Port -TimeoutMs ($TimeoutSec * 1000)
Add-Result -Name 'LAB-1' -Expect 'REACHABLE' -Ok $c2ok `
    -Detail "$LabGateway`:$C2Port -> $(if ($c2ok) { 'open' } else { 'CLOSED (bad)' })"

# --- summary ----------------------------------------------------------------
Write-Section 'summary'
$failed = @($results | Where-Object { -not $_.Passed })
$results | ForEach-Object {
    $colour = if ($_.Passed) { 'Green' } else { 'Red' }
    Write-Host ("  {0,-8} {1,-12} {2}" -f $_.Name, $_.Expect, $_.Detail) -ForegroundColor $colour
}
Write-Host ''
if ($failed.Count -eq 0) {
    Write-Host '  ISOLATION VERIFIED: the VM reaches the lab and nothing else.' -ForegroundColor Green
    exit 0
} else {
    Write-Host ("  ISOLATION INCOMPLETE: {0} check(s) did not match the expectation." -f $failed.Count) -ForegroundColor Red
    Write-Host '  Fix before running any measurement. An unisolated VM can' -ForegroundColor Yellow
    Write-Host '  reach the home network, and the payload runs arbitrary commands.' -ForegroundColor Yellow
    exit 1
}
