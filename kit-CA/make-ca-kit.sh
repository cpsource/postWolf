#!/usr/bin/env bash
#
# make-ca-kit.sh — build a portable CA-operator install tarball from
# the current postWolf tree.
#
# Assumes all binaries are already built (./make-all.sh).  Stages the
# six CA-side tools, libpostWolf.so, the MQC source + prebuilt libmqc.a,
# pkg-config, buildopenssl3.5.sh, install-ca-kit.sh, docs — then tars
# as postWolf-ca-kit-<version>.tar.gz.
#
# CA vs leaf kit: this one adds bootstrap_ca, issue_leaf_nonce, and
# admin_recosign (tools that only make sense with a CA identity on
# disk).  revoke-key's --target-index mode becomes functional here.
#
set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SELF_DIR/.." && pwd)"
STAGE="$SELF_DIR/payload"
VERSION="$(git -C "$REPO_ROOT" describe --always --dirty 2>/dev/null || echo unversioned)"
TARBALL="$SELF_DIR/postWolf-ca-kit-${VERSION}.tar.gz"

# --- 1. Sanity: required build artifacts must exist --------------------
required=(
    "mtc-keymaster/tools/c/bootstrap_ca"
    "mtc-keymaster/tools/c/bootstrap_leaf"
    "mtc-keymaster/tools/c/show-tpm"
    "mtc-keymaster/tools/c/issue_leaf_nonce"
    "mtc-keymaster/tools/c/admin_recosign"
    "mtc-keymaster/tools/c/revoke-key"
    "mtc-keymaster/tools/python/create_ca_cert.py"
    "mtc-keymaster/tools/python/create_leaf_cert.py"
    "mtc-keymaster/tools/python/ca_dns_txt.py"
    "src/.libs/libpostWolf.so"
    "socket-level-wrapper-MQC/libmqc.a"
    "socket-level-wrapper-MQC/mqc.h"
    "socket-level-wrapper-MQC/mqc_peer.h"
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
for src in install-ca-kit.sh buildopenssl3.5.sh README-ca.md; do
    if [[ ! -f "$SELF_DIR/$src" ]]; then
        echo "Missing: $SELF_DIR/$src" >&2
        exit 1
    fi
done

# --- 3. Stage the payload ---------------------------------------------
echo "Staging payload in $STAGE ..."
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/doc"

for t in bootstrap_ca bootstrap_leaf show-tpm issue_leaf_nonce \
         admin_recosign revoke-key; do
    install -m 755 "$REPO_ROOT/mtc-keymaster/tools/c/$t" "$STAGE/bin/"
done
for p in create_ca_cert.py create_leaf_cert.py ca_dns_txt.py; do
    install -m 755 "$REPO_ROOT/mtc-keymaster/tools/python/$p" "$STAGE/bin/"
done

cp -a "$REPO_ROOT/src/.libs/"libpostWolf.so*  "$STAGE/lib/"

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

install -m 644 "$SELF_DIR/README-ca.md"         "$STAGE/doc/README.md"
install -m 755 "$SELF_DIR/install-ca-kit.sh"    "$STAGE/install-ca-kit.sh"
install -m 755 "$SELF_DIR/buildopenssl3.5.sh"   "$STAGE/buildopenssl3.5.sh"
echo "$VERSION" > "$STAGE/VERSION"

# --- 4. Pack ----------------------------------------------------------
echo "Packing $TARBALL ..."
tar czf "$TARBALL" -C "$SELF_DIR" payload

echo
echo "Built: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo
echo "Contents:"
tar tzf "$TARBALL" | head -25
