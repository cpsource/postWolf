#!/usr/bin/env bash
#
# buildopenssl3.5.sh — build OpenSSL 3.5 from source into /usr/local/ssl/
# and expose it as /usr/local/bin/openssl35 (wrapper that sets
# LD_LIBRARY_PATH so the system `openssl` stays on 3.0.x).
#
# Must run as root (or via sudo).  Idempotent: if /usr/local/bin/openssl35
# already reports 3.5.x or newer the script exits without rebuilding.
#
# Invoked automatically by install-leaf-kit.sh; also safe to run on its
# own.
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "buildopenssl3.5.sh must run as root (or via sudo)." >&2
    exit 1
fi

# --- Skip if already installed --------------------------------------------
if command -v openssl35 >/dev/null 2>&1; then
    ver="$(openssl35 version 2>/dev/null | awk '{print $2}' | head -c 3)"
    if [[ "$ver" > "3.4" ]]; then
        echo "openssl35 already installed ($(openssl35 version)); skipping build."
        exit 0
    fi
fi

# --- 1. Dependencies ------------------------------------------------------
apt-get update -q
apt-get install -y --no-install-recommends \
    build-essential git perl wget zlib1g-dev libssl-dev

# --- 2. Download OpenSSL 3.5 source (tarball — version-pinned) ------------
cd /usr/local/src
if [[ ! -d /usr/local/src/openssl-3.5.0 ]]; then
    wget -q https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz
    tar xzf openssl-3.5.0.tar.gz
fi
cd openssl-3.5.0

# --- 3. Build and install (install_sw skips docs — saves ~30 s) -----------
./Configure --prefix=/usr/local/ssl --openssldir=/usr/local/ssl \
    shared zlib linux-x86_64
make -j"$(nproc)"
make install_sw

# --- 4. Wrapper at /usr/local/bin/openssl35 -------------------------------
cat > /usr/local/bin/openssl35 <<'EOF'
#!/bin/sh
LD_LIBRARY_PATH=/usr/local/ssl/lib64 exec /usr/local/ssl/bin/openssl "$@"
EOF
chmod 755 /usr/local/bin/openssl35

# --- 5. Verify ------------------------------------------------------------
openssl35 version
