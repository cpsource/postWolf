#!/usr/bin/env bash
#
# install-leaf-kit.sh — install the extracted postWolf leaf kit into
# /usr/local.  Must run as root.
#
# Layout expected (relative to this script):
#   ./bin/{bootstrap_leaf, show-tpm, revoke-key}
#   ./lib/libpostWolf.so*
#   ./doc/README.md
#   ./VERSION
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Error: install-leaf-kit.sh must be run with sudo." >&2
    echo "Usage: sudo bash install-leaf-kit.sh" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
for d in bin lib doc; do
    if [[ ! -d "$HERE/$d" ]]; then
        echo "Error: expected $HERE/$d not found." >&2
        echo "Run this script from the extracted kit directory "\
             "(tar xzf postWolf-leaf-kit-*.tar.gz && cd payload)." >&2
        exit 1
    fi
done
for f in socket-level-wrapper-MQC.tar.gz mqc.pc buildopenssl3.5.sh; do
    if [[ ! -f "$HERE/$f" ]]; then
        echo "Error: expected $HERE/$f not found in kit." >&2
        exit 1
    fi
done

VERSION="$(cat "$HERE/VERSION" 2>/dev/null || echo unknown)"

# --- 1. Runtime library dependencies ----------------------------------
echo ">>> Ensuring runtime apt prerequisites are present ..."
apt-get update -q >/dev/null 2>&1 || true
# Package names vary across Ubuntu/Debian releases; try a liberal set and
# warn (not fail) on any miss.  Final runtime check is the ldd pass below.
apt-get install -y --no-install-recommends \
    libjson-c5 libcurl4 libpq5 \
    libhiredis1.1.0 libhiredis1.0.0 libhiredis0.14 \
    2>/dev/null || {
    echo "Warning: apt-get could not install every runtime lib; check ldd output below." >&2
}

# --- 1a. OpenSSL 3.5 (openssl35) --------------------------------------
# Leaf key generation (ML-DSA-44/65/87) requires OpenSSL 3.5+, which
# Ubuntu 24.04 doesn't ship.  buildopenssl3.5.sh handles the build +
# wrapper install and is itself idempotent (no-op if openssl35 is
# already 3.5+).
echo ">>> Running buildopenssl3.5.sh (first-time build takes ~5–10 min) ..."
bash "$HERE/buildopenssl3.5.sh"

# --- 2. libpostWolf ---------------------------------------------------
echo ">>> Installing libpostWolf.so → /usr/local/lib/ ..."
install -d /usr/local/lib
cp -a "$HERE/lib/"libpostWolf.so* /usr/local/lib/
ldconfig

# --- 2a. MQC library + headers + pkg-config ---------------------------
echo ">>> Installing MQC (headers, libmqc.a, mqc.pc) → /usr/local/ ..."
mqc_tmp="$(mktemp -d)"
trap 'rm -rf "$mqc_tmp"' EXIT
tar xzf "$HERE/socket-level-wrapper-MQC.tar.gz" -C "$mqc_tmp"
mqc_src="$mqc_tmp/socket-level-wrapper-MQC"

install -d /usr/local/include/mqc
install -m 644 "$mqc_src/mqc.h"       /usr/local/include/mqc/mqc.h
install -m 644 "$mqc_src/mqc_peer.h"  /usr/local/include/mqc/mqc_peer.h

install -m 644 "$mqc_src/libmqc.a"    /usr/local/lib/libmqc.a

install -d /usr/local/lib/pkgconfig
install -m 644 "$HERE/mqc.pc"         /usr/local/lib/pkgconfig/mqc.pc

# --- 3. Leaf tools ----------------------------------------------------
echo ">>> Installing leaf tools → /usr/local/bin/ ..."
install -d /usr/local/bin
install -m 755 "$HERE/bin/bootstrap_leaf" /usr/local/bin/bootstrap_leaf
install -m 755 "$HERE/bin/show-tpm"       /usr/local/bin/show-tpm
install -m 755 "$HERE/bin/revoke-key"     /usr/local/bin/revoke-key

# --- 4. Docs ----------------------------------------------------------
install -d /usr/local/share/doc/postWolf-leaf
install -m 644 "$HERE/doc/README.md" \
    /usr/local/share/doc/postWolf-leaf/README.md

# --- 5. Verify ldd -----------------------------------------------------
missing_libs=0
for t in bootstrap_leaf show-tpm revoke-key; do
    if ldd "/usr/local/bin/$t" 2>/dev/null | grep -q "not found"; then
        echo "Warning: /usr/local/bin/$t has unresolved shared libs:" >&2
        ldd "/usr/local/bin/$t" | grep "not found" >&2
        missing_libs=1
    fi
done

echo
echo "postWolf leaf kit $VERSION installed."
echo
if (( missing_libs )); then
    echo "Install the missing libraries via apt then re-run:" >&2
    echo "    sudo ldconfig" >&2
    echo
fi

cat <<'EOF'
Next steps (ask your CA operator for a nonce, then):

    bootstrap_leaf --domain <DOMAIN> \
                   --server <CA-HOST>:8445 \
                   --nonce  <64-hex-char nonce>

    show-tpm --verify

    revoke-key --list <DOMAIN>     # see who's been revoked in your domain

Full docs: /usr/local/share/doc/postWolf-leaf/README.md
EOF
