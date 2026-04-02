#!/usr/bin/env bash
#
# autogen.sh — Check dependencies and build the MTC CA/Log C server.
#
# Usage:
#   ./autogen.sh           # check deps + build
#   ./autogen.sh clean     # clean build artifacts
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ -t 1 ]; then
    GREEN='\033[0;32m' RED='\033[0;31m' NC='\033[0m'
else
    GREEN='' RED='' NC=''
fi
ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; return 1; }

# --- clean ---
if [ "${1:-}" = "clean" ]; then
    make clean
    exit 0
fi

# --- dependency check ---
echo "Checking build dependencies..."
missing=0

command -v gcc >/dev/null 2>&1 && ok "gcc" || { fail "gcc not found"; missing=1; }

for lib in wolfssl json-c libpq; do
    if pkg-config --exists "$lib" 2>/dev/null; then
        ok "$lib $(pkg-config --modversion "$lib")"
    else
        fail "$lib not found (install or set PKG_CONFIG_PATH)"
        missing=1
    fi
done

if ldconfig -p 2>/dev/null | grep -q libresolv; then
    ok "libresolv"
else
    fail "libresolv not found (install libc6-dev)"
    missing=1
fi

if [ $missing -ne 0 ]; then
    echo ""
    echo "Install missing dependencies and retry."
    exit 1
fi

# --- build ---
echo ""
echo "Building mtc_server..."
make
echo ""
ok "mtc_server ready"
