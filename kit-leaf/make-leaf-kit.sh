#!/usr/bin/env bash
#
# make-leaf-kit.sh — build a portable leaf-install tarball from the
# current postWolf tree.
#
# Assumes all binaries are already built (./make-all.sh or equivalent
# has run).  Copies the three leaf-side tools, the libpostWolf shared
# library, docs, and install-leaf-kit.sh into kit-leaf/payload/, then
# tars the result as postWolf-leaf-kit-<version>.tar.gz.
#
set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SELF_DIR/.." && pwd)"
STAGE="$SELF_DIR/payload"
VERSION="$(git -C "$REPO_ROOT" describe --always --dirty 2>/dev/null || echo unversioned)"
TARBALL="$SELF_DIR/postWolf-leaf-kit-${VERSION}.tar.gz"

# --- 1. Sanity: required build artifacts must exist --------------------
required=(
    "mtc-keymaster/tools/c/bootstrap_leaf"
    "mtc-keymaster/tools/c/show-tpm"
    "mtc-keymaster/tools/python/create_leaf_keypair.py"
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
for src in install-leaf-kit.sh buildopenssl3.5.sh README-leaf.md; do
    if [[ ! -f "$SELF_DIR/$src" ]]; then
        echo "Missing: $SELF_DIR/$src" >&2
        exit 1
    fi
done

# --- 3. Stage the payload ---------------------------------------------
echo "Staging payload in $STAGE ..."
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/doc"

install -m 755 "$REPO_ROOT/mtc-keymaster/tools/c/bootstrap_leaf"        "$STAGE/bin/"
install -m 755 "$REPO_ROOT/mtc-keymaster/tools/c/show-tpm"              "$STAGE/bin/"
install -m 755 "$REPO_ROOT/mtc-keymaster/tools/python/create_leaf_keypair.py" "$STAGE/bin/"

# libpostWolf.so, libpostWolf.so.N (soname), libpostWolf.so.N.M.P (real file).
# Preserve symlinks with `cp -a`.
cp -a "$REPO_ROOT/src/.libs/"libpostWolf.so*  "$STAGE/lib/"

install -m 644 "$SELF_DIR/README-leaf.md"       "$STAGE/doc/README.md"
install -m 755 "$SELF_DIR/install-leaf-kit.sh"  "$STAGE/install-leaf-kit.sh"
install -m 755 "$SELF_DIR/buildopenssl3.5.sh"   "$STAGE/buildopenssl3.5.sh"
echo "$VERSION" > "$STAGE/VERSION"

# --- 3a. Bundle socket-level-wrapper-MQC source + libmqc.a ------------
# The MQC wrapper ships as a source tarball plus a prebuilt static
# library so downstream code can link against it.  We install headers
# + libmqc.a + pkg-config on the target — see install-leaf-kit.sh.
echo "Packing socket-level-wrapper-MQC ..."
tar czf "$STAGE/socket-level-wrapper-MQC.tar.gz" \
    -C "$REPO_ROOT" \
    --exclude='*.o' \
    --exclude='examples/echo_server' \
    --exclude='examples/echo_client' \
    socket-level-wrapper-MQC

# --- 3b. Generate mqc.pc pkg-config file ------------------------------
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

# --- 4. Pack ----------------------------------------------------------
echo "Packing $TARBALL ..."
tar czf "$TARBALL" -C "$SELF_DIR" payload

echo
echo "Built: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo
echo "Contents:"
tar tzf "$TARBALL" | head -20
