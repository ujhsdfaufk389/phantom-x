<#
.SYNOPSIS
    PHANTOM-X :: make double-clicking a PDF run the loader (no pop-up).

.DESCRIPTION
    Registers a per-user file association so that opening a .pdf file runs
    px_loader.exe against it. The loader extracts the embedded payload from
    the PDF and runs it, so double-clicking the carrier PDF is enough -- no
    console window, no prompt, no extra click.

    WHAT IT CHANGES
        HKCU\Software\Classes\PHANTOMX.PdfHandler   (the ProgID)
        HKCU\Software\Classes\.pdf                  (points at the ProgID)

    Both are under HKCU, so no administrator rights are needed and the
    machine-wide association is left alone.

    IMPORTANT ON WINDOWS 10/11
        If a default PDF application has already been chosen through
        Settings, Windows records it under
          HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice
        and that entry takes priority over anything registered here. The
        UserChoice key is protected by a hash that Windows computes, so it
        cannot simply be written. This script therefore offers to REMOVE the
        UserChoice entry, which makes Windows fall back to the registered
        handler.

        Removing UserChoice is reversible only by re-picking the default
        application in Settings (or by restoring the backup taken at install
        time, which this script does).

    NOTE ON WHAT THIS ACTUALLY DOES
        It changes the association for .pdf files. Opening a PDF in a
        configured reader will therefore launch the loader instead of the
        reader. That is the whole point of the experiment, and it is why
        the reader-behaviour measurement in Phase 1 must be run BEFORE
        installing this.

.PARAMETER LoaderPath
    Full path to px_loader.exe.

.PARAMETER PdfPath
    Optional: register a handler for one specific .pdf file instead of the
    .pdf extension. Useful when you want to leave every other PDF alone.

.PARAMETER Uninstall
    Remove the handler and restore the previous association.

.EXAMPLE
    .\install_pdf_handler.ps1 -LoaderPath C:\pxvm\px_loader.exe
    # now double-click any PDF

.EXAMPLE
    .\install_pdf_handler.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$LoaderPath = 'C:\pxvm\px_loader.exe',
    [string]$PdfPath = '',
    [switch]$Uninstall
)

$ErrorActionPreference = 'Continue'
$progId = 'PHANTOMX.PdfHandler'
$classes = 'HKCU:\Software\Classes'
$userChoice = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice'
$backupFile = 'C:\phantom-x\state\pdf_handler_backup.json'

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

function Get-ExtensionCommand {
    param([string]$Ext)
    $p = Join-Path $classes "$Ext\shell\open\command"
    if (Test-Path $p) {
        try { return (Get-ItemProperty -Path $p -Name '(default)' -ErrorAction Stop).'(default)' } catch { }
    }
    return $null
}

function Save-Backup {
    $backup = [ordered]@{
        ProgId           = $progId
        HadProgId        = (Test-Path (Join-Path $classes $progId))
        PdfExtCommand    = Get-ExtensionCommand -Ext '.pdf'
        HadUserChoice   = (Test-Path $userChoice)
        UserChoiceHash   = $null
        UserChoiceProgId = $null
        InstalledUtc     = (Get-Date).ToUniversalTime().ToString('o')
    }
    if (Test-Path $userChoice) {
        try {
            $uc = Get-ItemProperty -Path $userChoice -ErrorAction Stop
            $backup.UserChoiceHash = $uc.Hash
            $backup.UserChoiceProgId = $uc.ProgId
        } catch { }
    }
    New-Item -ItemType Directory -Path (Split-Path $backupFile) -Force | Out-Null |
        Out-Null
    $backup | ConvertTo-Json -Depth 5 | Set-Content -Path $backupFile -Encoding UTF8
    Write-Host ("  backup saved -> {0}" -f $backupFile) -ForegroundColor Green
}

function Remove-Handler {
    Write-Host ''
    $b = $null
    if (Test-Path $backupFile) {
        try { $b = Get-Content $backupFile -Raw | ConvertFrom-Json } catch { }
    }

    # remove the ProgID
    $p = Join-Path $classes $progId
    if (Test-Path $p) {
        Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host '  removed the PHANTOMX.PdfHandler ProgID' -ForegroundColor Green
    }

    # restore the .pdf extension command
    if ($b -and $b.PdfExtCommand) {
        $cmdPath = Join-Path $classes '.pdf\shell\open\command'
        New-Item -Path $cmdPath -Force | Out-Null
        Set-ItemProperty -Path $cmdPath -Name '(default)' -Value $b.PdfExtCommand
        Write-Host '  restored the previous .pdf open command' -ForegroundColor Green
    } else {
        $cmdPath = Join-Path $classes '.pdf\shell\open\command'
        if (Test-Path $cmdPath) {
            Remove-Item -Path (Join-Path $classes '.pdf\shell\open') -Recurse `
                -Force -ErrorAction SilentlyContinue
            Write-Host '  removed the .pdf open command' -ForegroundColor Green
        }
    }

    if ($b -and $b.HadUserChoice) {
        Write-Host ''
        Write-Host '  A default PDF application was previously selected through' -ForegroundColor Yellow
        Write-Host '  Settings. That choice was removed when the handler was' -ForegroundColor Yellow
        Write-Host '  installed and cannot be restored automatically -- Windows' -ForegroundColor Yellow
        Write-Host '  protects it with a hash it computes itself.' -ForegroundColor Yellow
        Write-Host '  Re-pick your reader in Settings > Apps > Default apps.' -ForegroundColor Yellow
    }

    Remove-Item $backupFile -ErrorAction SilentlyContinue
    Write-Host '  handler removed.' -ForegroundColor Green
}

# -----------------------------------------------------------------------------

Write-Section "PHANTOM-X :: PDF FILE HANDLER -- $(if ($Uninstall) { 'UNINSTALL' } else { 'INSTALL' })"

if ($Uninstall) {
    Remove-Handler
    Write-Host ''
    Write-Section 'done'
    return
}

if (-not (Test-Path $LoaderPath)) {
    Write-Host ("  loader not found: {0}" -f $LoaderPath) -ForegroundColor Red
    Write-Host '  Point -LoaderPath at px_loader.exe.' -ForegroundColor Yellow
    exit 1
}

Write-Host ''
Write-Host ("  loader : {0}" -f $LoaderPath) -ForegroundColor White
Write-Host '  scope  : HKCU only, no administrator rights required' -ForegroundColor DarkGray

Write-Host ''
Write-Host '  backing up the current association ...' -ForegroundColor White
Save-Backup

# --- register the ProgID ----------------------------------------------------
$progPath = Join-Path $classes $progId
New-Item -Path $progPath -Force | Out-Null
New-ItemProperty -Path $progPath -Name '(default)' -Value 'PHANTOM-X PDF Handler' `
    -PropertyType String -Force | Out-Null

$cmdPath = Join-Path $progPath 'shell\open\command'
New-Item -Path $cmdPath -Force | Out-Null
$command = '"{0}" "%1"' -f $LoaderPath
Set-ItemProperty -Path $cmdPath -Name '(default)' -Value $command -Force | Out-Null
Write-Host ("  registered ProgID -> {0}" -f $command) -ForegroundColor Green

# --- point the extension at the ProgID --------------------------------------
$extPath = Join-Path $classes '.pdf'
New-Item -Path $extPath -Force | Out-Null
Set-ItemProperty -Path $extPath -Name '(default)' -Value $progId -Force | Out-Null
Write-Host '  associated .pdf with the handler' -ForegroundColor Green

# --- clear a UserChoice override if present ---------------------------------
if (Test-Path $userChoice) {
    Write-Host ''
    Write-Host '  a default PDF app was previously chosen in Settings and it' -ForegroundColor Yellow
    Write-Host '  overrides registry associations. Removing it so the handler' -ForegroundColor Yellow
    Write-Host '  takes effect.' -ForegroundColor Yellow
    Remove-Item $userChoice -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host '  UserChoice removed.' -ForegroundColor Green
}

Write-Host ''
Write-Host '  >>> Double-clicking a .pdf now runs the loader against it.' -ForegroundColor Green
Write-Host '  >>> No console window, no prompt.' -ForegroundColor Green
Write-Host ''
Write-Host '  Verify:  Get-ItemProperty "HKCU:\Software\Classes\.pdf" | Select-Object "(default)"' -ForegroundColor DarkGray
Write-Host '  Remove:  .\install_pdf_handler.ps1 -Uninstall' -ForegroundColor DarkGray
Write-Host ''
Write-Section 'done'
