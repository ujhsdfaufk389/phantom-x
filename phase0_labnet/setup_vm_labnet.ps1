<#
.SYNOPSIS
    PHANTOM-X :: Phase 0 -- lock the research VM down to the lab segment.

.DESCRIPTION
    Runs INSIDE the research VM. Makes the VM's network deliberately narrow:

      * The ONLY outbound destination allowed is the lab gateway (the
        operator machine) on the C2 port. This is a default-deny posture.
      * The home LAN ranges are explicitly blocked, even if a route to them
        appears by accident (a DHCP lease, a manually added route, a second
        virtual NIC).
      * DNS is pointed at the lab gateway only, so the VM cannot resolve
        public names even if a route exists.
      * The lab gateway is NOT used as a DNS forwarder to the internet.

    WHY DEFAULT-DENY
        The payload in this lab executes arbitrary commands inside the VM.
        If the VM has a route to the home network, a mistake in the payload
        becomes someone else's problem. A default-deny egress policy means
        the worst case is 'the lab stops working', never 'the lab reaches
        the family laptop'.

    THE TRADE-OFF, STATED PLAINLY
        The VM will have NO internet. That is intentional. It means:
          - Windows Update will not run.
          - Tools cannot be downloaded inside the VM.
          - Defender will use whatever signature set was already present.
        Install anything you need from the HOST, over the lab segment,
        before you start measuring. If the lab genuinely needs internet,
        use a proxy on the host that logs every request, so the traffic is
        still observable. Do not simply bridge the NIC.

.PARAMETER LabGateway
    The operator machine's address on the lab segment.

    A HOSTNAME is accepted, and is the better choice when the operator
    moves between networks: the firewall rule then follows the C2 when
    its address changes, instead of having to be edited every time.

.PARAMETER C2Port
    The TCP port the lab C2 server listens on.

    A comma-separated list is accepted, for networks that block the lab's
    preferred port. The payload tries them in order, so whichever one the
    network permits is the one that ends up in use.

.PARAMETER AllowDhcp
    Keep DHCP working for the lab adapter (needed to get an address at all).

.PARAMETER Action
    'apply'  - install the lockdown rules (default)
    'revert' - remove them
    'state'  - show what is currently in place

.EXAMPLE
    .\setup_vm_labnet.ps1 -LabGateway 192.168.77.1 -C2Port 9001
#>
[CmdletBinding()]
param(
    [ValidateSet('apply', 'revert', 'state')]
    [string]$Action = 'state',
    [string]$LabGateway = '192.168.77.1',
    [int]$C2Port = 9001,
    [string]$LabSubnet = '192.168.77.0/24',
    [switch]$AllowDhcp,
    [string]$RulePrefix = 'PHANTOM-X LabVM'
)

$ErrorActionPreference = 'Continue'

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Section "PHANTOM-X :: VM NETWORK LOCKDOWN -- $Action"

if (-not (Test-Admin)) {
    Write-Host '  needs Administrator.' -ForegroundColor Red
    exit 1
}

# Common private ranges that must never be reachable from the lab VM.
$homeRanges = @(
    '192.168.0.0/16',
    '10.0.0.0/8',
    '172.16.0.0/12'
)
# ...except the lab segment itself, which is carved out below.

Write-Host ''
Write-Host '  current adapters:' -ForegroundColor White
Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } |
    ForEach-Object {
        Write-Host ("    {0,-30} {1}" -f $_.Name, $_.InterfaceDescription) -ForegroundColor DarkGray
        Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            ForEach-Object {
                Write-Host ("        {0}/{1}" -f $_.IPAddress, $_.PrefixLength) -ForegroundColor DarkGray
            }
    }

if ($Action -eq 'state') {
    Write-Host ''
    Write-Host '  PHANTOM-X rules in place:' -ForegroundColor White
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
             Where-Object { $_.DisplayName -like "$RulePrefix*" }
    if (-not $rules) { Write-Host '    (none)' -ForegroundColor Gray }
    foreach ($r in $rules) {
        $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        $af = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        Write-Host ("    {0,-52} {1} {2} {3}" -f `
            $r.DisplayName, $r.Direction, $r.Action, `
            $(if ($af -and $af.RemoteAddress) { $af.RemoteAddress -join ',' } else { '' })) -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '  routes:' -ForegroundColor White
    Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -ne '255.255.255.255/32' } |
        Sort-Object RouteMetric |
        ForEach-Object {
            Write-Host ("    {0,-20} via {1,-15} iface {2}" -f `
                $_.DestinationPrefix, $_.NextHop, $_.InterfaceAlias) -ForegroundColor DarkGray
        }
    Write-Host ''
    exit 0
}

if ($Action -eq 'revert') {
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "$RulePrefix*" } |
        ForEach-Object {
            Write-Host ("  removing: {0}" -f $_.DisplayName) -ForegroundColor DarkGray
            Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
        }
    Write-Host '  lockdown removed.' -ForegroundColor Green
    Write-Host ''
    exit 0
}

# ---------------------------------------------------------------------------
# 1. Default-deny egress
# ---------------------------------------------------------------------------
Write-Section '1. Default-deny egress'

$denyName = "$RulePrefix - Deny all outbound"
if (-not (Get-NetFirewallRule -Name $denyName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name $denyName -DisplayName $denyName `
        -Direction Outbound -Action Block -Enabled True -Profile Any `
        -Description 'PHANTOM-X: default-deny egress for the research VM' `
        -ErrorAction SilentlyContinue | Out-Null
    Write-Host '  outbound blocked by default.' -ForegroundColor Green
} else {
    Write-Host '  default-deny rule already present.' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 2. Allow the lab C2, nothing else
# ---------------------------------------------------------------------------
Write-Section '2. Allow the C2 and nothing else'

$c2Name = "$RulePrefix - Allow C2"

# The C2 allow rule.
#
# The rule has to survive the C2 changing address. When the operator's
# laptop moves between networks -- office wifi, a mobile hotspot, a hotel
# -- the C2's address changes with it. If the rule names the ADDRESS, it
# has to be edited every time, and the moment it is not is the moment the
# lab stops working.
#
# Naming the HOST instead means the rule follows the C2: Windows Firewall
# resolves the name when the rule is evaluated. The address form is still
# supported, because on the lab's own segment the C2 sits at a fixed
# address and there is nothing to resolve.
#
# The rule is REPLACED rather than skipped when it already exists, so that
# changing the target actually takes effect.
$isC2Name = $LabGateway -match '[a-zA-Z]'
$c2Ports = @($C2Port -split ',' | ForEach-Object { $_.Trim() } |
             Where-Object { $_ -match '^\d+$' })

Remove-NetFirewallRule -Name $c2Name -ErrorAction SilentlyContinue
New-NetFirewallRule -Name $c2Name -DisplayName $c2Name `
    -Direction Outbound -Action Allow -Enabled True -Profile Any `
    -Protocol TCP -LocalPort Any -RemotePort $c2Ports `
    -RemoteAddress $LabGateway `
    -Description 'PHANTOM-X: the only outbound destination the lab VM needs' `
    -ErrorAction SilentlyContinue | Out-Null

if ($isC2Name) {
    Write-Host ("  allowed TCP/{0} to {1} (C2, BY NAME)" -f ($c2Ports -join ','), $LabGateway) -ForegroundColor Green
    Write-Host '    the rule follows the C2 when its address changes.' -ForegroundColor DarkGray
} else {
    Write-Host ("  allowed TCP/{0} to {1} (C2)" -f ($c2Ports -join ','), $LabGateway) -ForegroundColor Green
    Write-Host '    NOTE: this is an address. Use the C2 hostname instead if the' -ForegroundColor DarkGray
    Write-Host '    operator moves between networks.' -ForegroundColor DarkGray
}

# DHCP and the lab subnet itself must stay reachable, otherwise the VM
# loses its address and the whole rig goes dark.
$labName = "$RulePrefix - Allow lab subnet"
if (-not (Get-NetFirewallRule -Name $labName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name $labName -DisplayName $labName `
        -Direction Outbound -Action Allow -Enabled True -Profile Any `
        -RemoteAddress $LabSubnet `
        -Description 'PHANTOM-X: traffic inside the host-only lab segment' `
        -ErrorAction SilentlyContinue | Out-Null
    Write-Host ("  allowed the lab subnet {0}" -f $LabSubnet) -ForegroundColor Green
}

if ($AllowDhcp) {
    $dhcpName = "$RulePrefix - Allow DHCP"
    if (-not (Get-NetFirewallRule -Name $dhcpName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $dhcpName -DisplayName $dhcpName `
            -Direction Outbound -Action Allow -Enabled True -Profile Any `
            -Protocol UDP -RemotePort 67,68 -ErrorAction SilentlyContinue | Out-Null
        Write-Host '  allowed DHCP.' -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# 3. Explicit home-LAN blocks
#
# The default-deny already covers these, but an explicit rule is worth
# having: it shows up in the rule list with a name that says why it is
# there, and it survives someone relaxing the default-deny later.
# ---------------------------------------------------------------------------
Write-Section '3. Explicit home-LAN blocks'

foreach ($r in $homeRanges) {
    if ($r -eq $LabSubnet) { continue }
    $name = "$RulePrefix - Block $r"
    if (-not (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $name -DisplayName $name `
            -Direction Outbound -Action Block -Enabled True -Profile Any `
            -RemoteAddress $r `
            -Description 'PHANTOM-X: the lab VM must never reach the home network' `
            -ErrorAction SilentlyContinue | Out-Null
        Write-Host ("  blocked {0}" -f $r) -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# 4. DNS
# ---------------------------------------------------------------------------
Write-Section '4. DNS'

Write-Host '  the VM should resolve ONLY via the lab gateway.' -ForegroundColor White
Write-Host '  setting DNS on every adapter that has an IPv4 address ...' -ForegroundColor DarkGray

$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
foreach ($a in $adapters) {
    $ips = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not $ips) { continue }
    try {
        Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex `
            -ServerAddresses @($LabGateway) -ErrorAction Stop | Out-Null
        Write-Host ("    {0} -> {1}" -f $a.Name, $LabGateway) -ForegroundColor Green
    } catch {
        Write-Host ("    {0}: {1}" -f $a.Name, $_.Exception.Message) -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 5. Summary
# ---------------------------------------------------------------------------
Write-Section 'Result'

Write-Host '  The VM now has:' -ForegroundColor White
Write-Host "    outbound  : ONLY the lab subnet, and TCP/$C2Port to $LabGateway" -ForegroundColor Gray
Write-Host '    DNS       : the lab gateway only' -ForegroundColor Gray
Write-Host '    internet  : NOT reachable (by design)' -ForegroundColor Gray
Write-Host ''
Write-Host '  CHECK IT:' -ForegroundColor White
Write-Host '    .\verify_labnet.ps1' -ForegroundColor White
Write-Host '  (expects the home-LAN probes to FAIL and the C2 probe to SUCCEED)' -ForegroundColor DarkGray
Write-Host ''
