#!/usr/bin/env bash
#
# make-extension-kit.sh — pack gmail-mqc-extension (host + extension
# halves) into a single tarball ready to ship to a Windows box.
#
# The tarball extracts to gmail-mqc-extension/ so paths match what
# the READMEs describe.  Build scripts, cached bytecode, and prior
# tarballs are excluded.
#
set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SELF_DIR/.." && pwd)"
VERSION="$(git -C "$REPO_ROOT" describe --always --dirty 2>/dev/null || echo unversioned)"
TARBALL="$SELF_DIR/postWolf-gmail-mqc-ext-${VERSION}.tar.gz"
# Stage outside the dir we're packing so tar doesn't trip on its own
# output growing underneath it.
STAGE_TAR="$(mktemp -u /tmp/postWolf-gmail-mqc-ext-XXXXXX.tar.gz)"

# --- Sanity ------------------------------------------------------------
for f in host/mqc_native_host.py host/mqc_native_host.cmd \
         host/install.ps1 host/com.postwolf.mqc.json.template \
         host/README.md \
         extension/manifest.json extension/background.js \
         extension/content_script.js extension/overlay.css \
         extension/popup.html extension/popup.js extension/README.md \
         README.md; do
    if [[ ! -f "$SELF_DIR/$f" ]]; then
        echo "Missing: gmail-mqc-extension/$f" >&2
        exit 1
    fi
done

# --- Pack --------------------------------------------------------------
# Drop any prior build artifact so the tar doesn't race against a
# growing file of the same basename.
rm -f "$TARBALL"

echo "Packing $TARBALL ..."
tar czf "$STAGE_TAR" \
    -C "$REPO_ROOT" \
    --exclude='gmail-mqc-extension/Makefile' \
    --exclude='gmail-mqc-extension/make-extension-kit.sh' \
    --exclude='gmail-mqc-extension/postWolf-gmail-mqc-ext-*.tar.gz' \
    --exclude='gmail-mqc-extension/payload' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.DS_Store' \
    --exclude='host.log' \
    gmail-mqc-extension
mv "$STAGE_TAR" "$TARBALL"

echo
echo "Built: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo
echo "Contents:"
tar tzf "$TARBALL"
echo
echo "On the Windows box:"
echo "  tar xzf postWolf-gmail-mqc-ext-${VERSION}.tar.gz"
echo "  # Chrome → chrome://extensions → Load unpacked → gmail-mqc-extension/extension/"
echo "  # PowerShell → cd gmail-mqc-extension\\host ; .\\install.ps1 -ExtensionId <id>"
