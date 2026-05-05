#!/usr/bin/env bash
#
# buildopenssl4.0.sh — build OpenSSL 4.0.0 from source into
# /usr/local/openssl4/ and expose it as /usr/local/bin/openssl40 (wrapper
# that sets LD_LIBRARY_PATH so the system `openssl` stays untouched).
#
# Must run as root (or via sudo).  Idempotent: if /usr/local/bin/openssl40
# already reports 4.x or newer the script exits without rebuilding.
#
# Invoked automatically by install-ca-kit.sh / install-leaf-kit.sh; also
# safe to run on its own.
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "buildopenssl4.0.sh must run as root (or via sudo)." >&2
    exit 1
fi

# --- Skip if already installed --------------------------------------------
if command -v openssl40 >/dev/null 2>&1; then
    ver="$(openssl40 version 2>/dev/null | awk '{print $2}' | head -c 1)"
    if [[ "$ver" == "4" ]]; then
        echo "openssl40 already installed ($(openssl40 version)); skipping build."
        exit 0
    fi
fi

# --- 1. Dependencies ------------------------------------------------------
apt-get update -q
apt-get install -y --no-install-recommends \
    build-essential git perl wget zlib1g-dev libssl-dev

# --- 2. Download OpenSSL 4.0.0 source (tarball — version-pinned) ----------
cd /usr/local/src
if [[ ! -d /usr/local/src/openssl-4.0.0 ]]; then
    wget -q https://github.com/openssl/openssl/releases/download/openssl-4.0.0/openssl-4.0.0.tar.gz
    tar xzf openssl-4.0.0.tar.gz
fi
cd openssl-4.0.0

# --- 3. Build and install (install_sw skips docs — saves ~30 s) -----------
./Configure --prefix=/usr/local/openssl4 --openssldir=/usr/local/openssl4/ssl \
    shared zlib linux-x86_64
make -j"$(nproc)"
make install_sw

# --- 4. Wrapper at /usr/local/bin/openssl40 -------------------------------
cat > /usr/local/bin/openssl40 <<'EOF'
#!/bin/sh
LD_LIBRARY_PATH=/usr/local/openssl4/lib64 exec /usr/local/openssl4/bin/openssl "$@"
EOF
chmod 755 /usr/local/bin/openssl40

# --- 5. Verify ------------------------------------------------------------
openssl40 version
