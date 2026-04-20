#!/usr/bin/env bash
#
# install-mqc-kit.sh — install the extracted postWolf mqc kit into
# /usr/local on a fresh Ubuntu 24.04 (or compatible) box.
# Must run as root.
#
# Layout expected (relative to this script):
#   ./bin/mqc
#   ./lib/libpostWolf.so*
#   ./doc/README.md
#   ./doc/README-mqc-cli.md
#   ./VERSION
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Error: install-mqc-kit.sh must be run with sudo." >&2
    echo "Usage: sudo bash install-mqc-kit.sh" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
for d in bin lib doc; do
    if [[ ! -d "$HERE/$d" ]]; then
        echo "Error: expected $HERE/$d not found." >&2
        echo "Run this script from the extracted kit directory "\
             "(tar xzf postWolf-mqc-kit-*.tar.gz && cd payload)." >&2
        exit 1
    fi
done

VERSION="$(cat "$HERE/VERSION" 2>/dev/null || echo unknown)"

# --- 1. Runtime library dependencies ----------------------------------
# mqc itself links only against libjson-c and glibc, but libpostWolf.so
# pulls in libcurl transitively (other postWolf consumers use it).
# Both are standard apt packages on Ubuntu 24.04; try both spellings
# (libcurl4 vs libcurl4t64 in noble's transition).
echo ">>> Ensuring runtime apt prerequisites are present ..."
apt-get update -q >/dev/null 2>&1 || true
apt-get install -y --no-install-recommends libjson-c5 libcurl4t64 2>/dev/null \
  || apt-get install -y --no-install-recommends libjson-c5 libcurl4 2>/dev/null \
  || {
      echo "Warning: apt-get could not install every runtime lib; check ldd output below." >&2
  }

# --- 2. libpostWolf ---------------------------------------------------
echo ">>> Installing libpostWolf.so → /usr/local/lib/ ..."
install -d /usr/local/lib
cp -a "$HERE/lib/"libpostWolf.so* /usr/local/lib/
ldconfig

# --- 3. mqc binary ----------------------------------------------------
echo ">>> Installing mqc → /usr/local/bin/ ..."
install -d /usr/local/bin
install -m 755 "$HERE/bin/mqc"  /usr/local/bin/mqc

# --- 4. Docs ----------------------------------------------------------
install -d /usr/local/share/doc/postWolf-mqc
install -m 644 "$HERE/doc/README.md"          /usr/local/share/doc/postWolf-mqc/README.md
install -m 644 "$HERE/doc/README-mqc-cli.md"  /usr/local/share/doc/postWolf-mqc/README-mqc-cli.md

# --- 5. Verify ldd -----------------------------------------------------
missing_libs=0
if ldd /usr/local/bin/mqc 2>/dev/null | grep -q "not found"; then
    echo "Warning: /usr/local/bin/mqc has unresolved shared libs:" >&2
    ldd /usr/local/bin/mqc | grep "not found" >&2
    missing_libs=1
fi

echo
echo "postWolf mqc-kit $VERSION installed."
echo
if (( missing_libs )); then
    echo "Install the missing libraries via apt then re-run:" >&2
    echo "    sudo ldconfig" >&2
    echo
fi

cat <<'EOF'
Next steps:

    1. Set a master password in ~/.env (one line):
         MQC_MASTER_PASSWORD="your-password-here"
       Keep ~/.env at mode 0600.  Generate a strong password with:
         mqc --encode --complex-password </dev/null >/dev/null
       (the generated password is printed to stderr once).

    2. Try a round-trip:
         echo hello | mqc --encode --env --no-cache \
                   | mqc --decode --env --no-cache

    3. Optional: set up a default domain under ~/.TPM/ so mqc can
       use the per-domain cache without --env:
         mkdir -p ~/.TPM/mydomain
         ln -sfn mydomain ~/.TPM/default

Full docs:
  /usr/local/share/doc/postWolf-mqc/README-mqc-cli.md
EOF
