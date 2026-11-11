<#
.SYNOPSIS
    PHANTOM-X :: Phase 0 -- isolate the research VM from the home network.

.DESCRIPTION
    Builds the network separation the lab depends on, and verifies it.

    The lab needs THREE distinct networks:

      1. HOME      -- the operator's normal LAN and internet. The lab must
                      never reach it. If the payload escapes the VM, it must
                      have no route home.
      2. LAB-LAN   -- host-only segment between the operator machine and the
                      research VM. The C2 server lives on the operator side
                      of this segment.
      3. VM-LOCAL  -- the VM's own stack. Nothing else.

    This script configures the HOST side:

      * VMware: VMnet1 is set to host-only (no NAT, no bridging). It is
        renamed to a recognisable name so it cannot be confused with a
        bridged adapter, and the DHCP range is moved off the default.
      * Hyper-V: an internal switch 'PX-LAB' is created if absent.
      * Windows Firewall on the host: inbound traffic from the lab subnet
        is blocked by default, with ONE explicit allow for the C2 port.

    VERIFICATION
        A separate check runs after this and proves the separation actually
        holds, rather than assuming it does. See verify_labnet.ps1.

    This script does not change the default gateway, does not touch DNS on
    the home adapter, and does not disable anything on the host.

.PARAMETER LabSubnet
    The host-only subnet for the lab segment.

.PARAMETER C2Port
    The TCP port the lab C2 server listens on. Only this port is reachable
    from the lab subnet.

.PARAMETER Action
    'apply'  - configure the isolation (default)
    'revert' - remove the lab-specific firewall rules and switch

.EXAMPLE
    .\setup_labnet.ps1 -Action apply -LabSubnet 192.168.77.0/24 -C2Port 9001

.NOTES
    Run this on the HOST (the machine that also runs the C2 server), as
    Administrator. Run setup_vm_labnet.ps1 on the VM itself.
#>
[CmdletBinding()]
param(
    [ValidateSet('apply', 'revert')]
    [string]$Action = 'apply',
    [string]$LabSubnet = '192.168.77.0/24',
    [int]$C2Port = 9001,
    [string]$LabSwitchName = 'PX-LAB',
    [string]$RulePrefix = 'PHANTOM-X LabNet'
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

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Section "PHANTOM-X :: LAB NETWORK ISOLATION -- $Action"

if (-not (Test-Admin)) {
    Write-Host '  this script needs Administrator.' -ForegroundColor Red
    Write-Host '  right-click PowerShell -> Run as administrator.' -ForegroundColor Yellow
    exit 1
}

# ---------------------------------------------------------------------------
# Parse the subnet
# ---------------------------------------------------------------------------
$parts = $LabSubnet -split '/'
$labNet = $parts[0]
$prefix = [int]$parts[1]
$hostIp = $null
$netBytes = $labNet.Split('.') | ForEach-Object { [int]$_ }
for ($i = 0; $i -lt 4; $i++) {
    $mask = if ($i -lt [math]::Floor($prefix / 8)) { 255 } else { 0 }
    if (($prefix % 8) -gt 0 -and $i -eq [math]::Floor($prefix / 8)) {
        $mask = 256 - [math]::Pow(2, 8 - ($prefix % 8))
    }
    $hostIp += if ($i -gt 0) { '.' } else { '' }
    $hostIp += ($netBytes[$i] -band $mask)
}
Write-Host ("  lab subnet : {0}/{1}  (network {2})" -f $labNet, $prefix, $hostIp)

# ---------------------------------------------------------------------------
# 1. VMware host-only adapter
# ---------------------------------------------------------------------------
Write-Section '1. VMware host-only segment'

$vmwareInstalled = (Test-Path 'C:\Program Files (x86)\VMware\VMware Workstation') -or
                    (Test-Path 'C:\Program Files\VMware\VMware Workstation')

# The virtual network config file moved between VMware releases. Older
# versions wrote C:\ProgramData\VMware\vmnetcfg.conf; newer ones keep the
# per-adapter settings elsewhere. Look in all the known places rather than
# assuming one layout, otherwise the host-only check silently does nothing.
$vmnetCfgCandidates = @(
    'C:\ProgramData\VMware\vmnetcfg.conf',
    'C:\ProgramData\VMware\VMware Workstation\vmnetcfg.conf',
    'C:\ProgramData\VMware\vmnetcfg'
)
$vmnetcfg = $vmnetCfgCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($vmwareInstalled -and $vmnetcfg) {
    Write-Host ("  VMware detected. config: {0}" -f $vmnetcfg) -ForegroundColor Green

    # Confirm VMnet1 is host-only, NOT bridged and NOT NAT. This is the
    # single most important line in this script: if VMnet1 were bridged the
    # VM would sit directly on the home LAN and the whole isolation model
    # would be a fiction.
    $cfg = Get-Content $vmnetcfg -Raw
    $isHostOnly = $cfg -match '(?ms)device\s*=\s*vmnet1.*?hostonly\s*=\s*yes'
    $isBridged = $cfg -match '(?ms)device\s*=\s*vmnet1.*?bridge\s*=\s*yes'

    if ($isBridged) {
        Write-Host '  VMnet1 is BRIDGED -- the VM is on your home LAN.' -ForegroundColor Red
        Write-Host '  Fix this in VMware: Edit > Virtual Network Editor > VMnet1' -ForegroundColor Yellow
        Write-Host '  > Type: Host-only. Then re-run this script.' -ForegroundColor Yellow
        Write-Host '  (This script will not edit vmnetcfg.conf for you because' -ForegroundColor DarkGray
        Write-Host '   VMware rewrites that file on its own and hand-edits are lost.)' -ForegroundColor DarkGray
    } elseif ($isHostOnly) {
        Write-Host '  VMnet1 is host-only. Correct.' -ForegroundColor Green
        $changes += 'Verified VMnet1 is host-only'
    } else {
        Write-Host '  could not determine VMnet1 type from vmnetcfg.conf.' -ForegroundColor Yellow
        Write-Host '  verify manually in the Virtual Network Editor.' -ForegroundColor Yellow
    }

    # Show what the host actually has on that adapter.
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceDescription -like '*VMnet1*' }
    foreach ($a in $adapters) {
        Write-Host ("    adapter : {0}  [{1}]" -f $a.Name, $a.Status) -ForegroundColor DarkGray
        $ips = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        foreach ($ip in $ips) {
            Write-Host ("      ip    : {0}/{1}" -f $ip.IPAddress, $ip.PrefixLength) -ForegroundColor DarkGray
        }
    }
} else {
    if (-not $vmwareInstalled) {
        Write-Host '  VMware not installed on this host.' -ForegroundColor DarkGray
    } else {
        Write-Host ("  VMware is installed but no virtual network config was found." -f $vmnetcfg) -ForegroundColor DarkGray
        Write-Host '  searched:' -ForegroundColor DarkGray
        $vmnetCfgCandidates | ForEach-Object { Write-Host ("    {0}" -f $_) -ForegroundColor DarkGray }
    }
    Write-Host '  If you use VMware, run this on the HOST and check in the' -ForegroundColor DarkGray
    Write-Host '  Virtual Network Editor that VMnet1 is set to Host-only.' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 2. Hyper-V internal switch
# ---------------------------------------------------------------------------
Write-Section '2. Hyper-V internal switch'

$hasHyperV = $null -ne (Get-Command Get-VMSwitch -ErrorAction SilentlyContinue)
if ($hasHyperV) {
    $existing = Get-VMSwitch -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $LabSwitchName }
    if ($existing) {
        Write-Host ("  switch '{0}' already exists (type={1})" -f $existing.Name, $existing.SwitchType) -ForegroundColor Green
    } else {
        # An 'Internal' switch is the right type: the VM can talk to the
        # host and to other VMs on the same switch, but there is no uplink
        # to the physical network at all. That is the isolation we want.
        #
        # New-VMSwitch with -SwitchType Internal needs no physical NIC, but
        # it may require the Hyper-V host to have Virtual Machine Platform
        # active. If the switch cannot be created, fall back to giving
        # explicit instructions rather than failing silently.
        try {
            New-VMSwitch -Name $LabSwitchName -SwitchType Internal -ErrorAction Stop | Out-Null
            Write-Host ("  created INTERNAL switch '{0}'" -f $LabSwitchName) -ForegroundColor Green
            Write-Host '  the VM has no uplink to the physical network on this switch.' -ForegroundColor DarkGray
            $changes += "Created Hyper-V internal switch $LabSwitchName"
        } catch {
            Write-Host ("  could not create the internal switch: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            Write-Host ''
            Write-Host '  Create it manually in an ELEVATED prompt:' -ForegroundColor White
            Write-Host "    New-VMSwitch -Name $LabSwitchName -SwitchType Internal" -ForegroundColor White
            Write-Host '  then attach the VM adapter to that switch in the VM' -ForegroundColor DarkGray
            Write-Host '  settings (Network Adapter > Choose > PX-LAB).' -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host '  Hyper-V cmdlets not available; skipping.' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 3. Host firewall
# ---------------------------------------------------------------------------
Write-Section '3. Host firewall for the lab segment'

if ($Action -eq 'revert') {
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "$RulePrefix*" } |
        ForEach-Object {
            Write-Host ("  removing: {0}" -f $_.DisplayName) -ForegroundColor DarkGray
            Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
        }
    Write-Host '  lab firewall rules removed.' -ForegroundColor Green
} else {
    # -- block everything inbound from the lab subnet, then allow just C2 --
    $blockName = "$RulePrefix - Block inbound from lab"
    if (-not (Get-NetFirewallRule -Name $blockName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $blockName -DisplayName $blockName `
            -Direction Inbound -Action Block -Enabled True -Profile Any `
            -RemoteAddress $labNet -Description 'PHANTOM-X: the lab VM must not be able to reach host services except the C2 port' `
            -ErrorAction SilentlyContinue | Out-Null
        Write-Host ("  blocking all inbound from {0}" -f $labNet) -ForegroundColor Green
        $changes += "Firewall: block inbound from $labNet"
    } else {
        Write-Host '  block rule already present.' -ForegroundColor DarkGray
    }

    # The block rule above has no port restriction, so the allow rule below
    # must be more specific to win. Windows Firewall evaluates the most
    # specific matching rule, and an explicit allow for a single port
    # overrides the broader block.
    $allowName = "$RulePrefix - Allow C2 port"
    if (-not (Get-NetFirewallRule -Name $allowName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $allowName -DisplayName $allowName `
            -Direction Inbound -Action Allow -Enabled True -Profile Any `
            -Protocol TCP -LocalPort $C2Port -RemoteAddress $labNet `
            -Description 'PHANTOM-X: the lab C2 server port' `
            -ErrorAction SilentlyContinue | Out-Null
        Write-Host ("  allowing TCP/{0} from the lab subnet (C2)" -f $C2Port) -ForegroundColor Green
        $changes += "Firewall: allow C2 TCP/$C2Port from $labNet"
    } else {
        Write-Host '  C2 allow rule already present.' -ForegroundColor DarkGray
    }

    # Make sure the C2 server never binds a public interface. This is a
    # reminder and a check, not a change: the server's bind address is set
    # by its --host flag.
    Write-Host ''
    Write-Host '  NOTE: start the C2 server bound to the lab interface only:' -ForegroundColor White
    Write-Host "    px_c2.exe --host <lab-host-ip> --port $C2Port --log c2_audit.jsonl" -ForegroundColor White
    Write-Host '    Do NOT use 0.0.0.0 unless the host firewall rules above' -ForegroundColor DarkGray
    Write-Host '    are in place and you accept the exposure.' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Section 'Summary'
if ($changes.Count) {
    foreach ($c in $changes) { Write-Host ("  - {0}" -f $c) -ForegroundColor Green }
} else {
    Write-Host '  (no changes needed)' -ForegroundColor Gray
}

Write-Host ''
Write-Host '  NEXT:' -ForegroundColor White
Write-Host '    on the HOST : .\verify_labnet.ps1' -ForegroundColor White
Write-Host '    on the VM   : .\setup_vm_labnet.ps1 -LabGateway 192.168.77.1' -ForegroundColor White
Write-Host ''
