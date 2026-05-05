#!/usr/bin/env bash
#
# make-server-kit.sh — build a portable MTC-server install tarball
# from the current postWolf tree.
#
# Assumes all binaries are already built (./make-all.sh).  Stages the
# mtc_server daemon, server-side ops tools (admin_recosign,
# migrate-cosigner, backfill-pubkey, show-tpm), libpostWolf.so, the
# MQC source + prebuilt libmqc.a + pkg-config, the systemd unit
# template, python helpers, buildopenssl4.0.sh, install-server-kit.sh,
# and docs — then tars as postWolf-server-kit-<version>.tar.gz.
#
# Server kit vs CA/leaf: this kit is for operators running an
# `mtc_server` daemon (the transparency log + Merkle CA).  CA-operator
# enrollment tooling (bootstrap_ca, issue_leaf_nonce, ...) is in
# kit-CA — install both kits if this box also hosts its own CA.
#
set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SELF_DIR/.." && pwd)"
STAGE="$SELF_DIR/payload"
VERSION="$(git -C "$REPO_ROOT" describe --always --dirty 2>/dev/null || echo unversioned)"
TARBALL="$SELF_DIR/postWolf-server-kit-${VERSION}.tar.gz"

# --- 1. Sanity: required build artifacts must exist --------------------
required=(
    "mtc-keymaster/server2/c/mtc_server"
    "mtc-keymaster/server2/c/mtc-ca.service"
    "mtc-keymaster/tools/c/admin_recosign"
    "mtc-keymaster/tools/c/migrate-cosigner"
    "mtc-keymaster/tools/c/backfill-pubkey"
    "mtc-keymaster/tools/c/show-tpm"
    "mtc-keymaster/tools/python/create_server_cert.py"
    "mtc-keymaster/tools/python/verify.py"
    "mtc-keymaster/tools/python/verify_certificate.py"
    "src/.libs/libpostWolf.so"
    "socket-level-wrapper-MQC/libmqc.a"
    "socket-level-wrapper-MQC/mqc.h"
    "socket-level-wrapper-MQC/mqc_peer.h"
    "socket-level-wrapper-MQC/config.h"
)
missing=0
for f in "${required[@]}"; do
    if [[ ! -e "$REPO_ROOT/$f" ]]; then
        echo "Missing: $f" >&2
        missing=1
    fi
done
if (( missing )); then
    echo >&2
    echo "Build the full tree first:" >&2
    echo "    cd $REPO_ROOT && ./make-all.sh" >&2
    exit 1
fi

# --- 2. Source scripts next to this one --------------------------------
for src in install-server-kit.sh buildopenssl4.0.sh README-server.md; do
    if [[ ! -f "$SELF_DIR/$src" ]]; then
        echo "Missing: $SELF_DIR/$src" >&2
        exit 1
    fi
done

# --- 3. Stage the payload ---------------------------------------------
echo "Staging payload in $STAGE ..."
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/etc" "$STAGE/doc"

# Server daemon
install -m 755 "$REPO_ROOT/mtc-keymaster/server2/c/mtc_server" "$STAGE/bin/"

# Server-side ops tools
for t in admin_recosign migrate-cosigner backfill-pubkey show-tpm; do
    install -m 755 "$REPO_ROOT/mtc-keymaster/tools/c/$t" "$STAGE/bin/"
done

# Python helpers
for p in create_server_cert.py verify.py verify_certificate.py; do
    install -m 755 "$REPO_ROOT/mtc-keymaster/tools/python/$p" "$STAGE/bin/"
done

# Shared library
cp -a "$REPO_ROOT/src/.libs/"libpostWolf.so*  "$STAGE/lib/"

# Systemd unit (canonical copy from server2/c — installer turns the
# hardcoded factsorlie.com paths into placeholders before installing)
install -m 644 "$REPO_ROOT/mtc-keymaster/server2/c/mtc-ca.service" \
               "$STAGE/etc/mtc-ca.service.template"

# --- 3a. MQC source + libmqc.a -----------------------------------------
echo "Packing socket-level-wrapper-MQC ..."
tar czf "$STAGE/socket-level-wrapper-MQC.tar.gz" \
    -C "$REPO_ROOT" \
    --exclude='*.o' \
    --exclude='examples/echo_server' \
    --exclude='examples/echo_client' \
    socket-level-wrapper-MQC

# --- 3b. mqc.pc pkg-config file ----------------------------------------
cat > "$STAGE/mqc.pc" <<EOF
prefix=/usr/local
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: mqc
Description: Merkle Quantum Connect — post-quantum authenticated socket wrapper (postWolf)
Version: ${VERSION}
Requires: postWolf
Cflags: -I\${includedir}/mqc
Libs: -L\${libdir} -lmqc
EOF

# --- 3c. Docs ---------------------------------------------------------
install -m 644 "$SELF_DIR/README-server.md" "$STAGE/doc/README.md"
if [[ -f "$REPO_ROOT/mtc-keymaster/server2/c/README-using-mtc-server.md" ]]; then
    install -m 644 "$REPO_ROOT/mtc-keymaster/server2/c/README-using-mtc-server.md" \
                   "$STAGE/doc/README-using-mtc-server.md"
fi

install -m 755 "$SELF_DIR/install-server-kit.sh"  "$STAGE/install-server-kit.sh"
install -m 755 "$SELF_DIR/buildopenssl4.0.sh"     "$STAGE/buildopenssl4.0.sh"
echo "$VERSION" > "$STAGE/VERSION"

# --- 4. Pack ----------------------------------------------------------
echo "Packing $TARBALL ..."
tar czf "$TARBALL" -C "$SELF_DIR" payload

echo
echo "Built: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo
echo "Contents:"
tar tzf "$TARBALL" | head -25
