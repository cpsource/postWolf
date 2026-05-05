#!/usr/bin/env bash
#
# install-server-kit.sh — install the extracted postWolf MTC-server
# kit.  Must run as root.
#
# Installs the mtc_server daemon, server-side ops tools
# (admin_recosign, migrate-cosigner, backfill-pubkey, show-tpm),
# libpostWolf, the MQC library + headers + pkg-config, OpenSSL 4.0.0
# (for ML-DSA-87 cosigner-key keygen), and the mtc-ca.service systemd
# unit (substituted for the operator's domain/user if --domain is
# given, otherwise installed as a template under
# /usr/local/share/doc/postWolf-server/).
#
# Usage:
#   sudo bash install-server-kit.sh [--domain <D>] [--user <U>]
#                                   [--data-dir <D>]
#
# --domain    operator's primary domain (substituted for factsorlie.com
#             in the systemd unit; if omitted, the unit is installed as
#             a template and the operator must edit + copy it manually).
# --user      user the daemon runs as (defaults to $SUDO_USER, then
#             whoever owns ~/.mtc-ca-data, then 'ubuntu').
# --data-dir  --data-dir for mtc_server (defaults to $HOME/.mtc-ca-data
#             of the chosen user).
#
set -euo pipefail

# Short-circuit --help/-h before the EUID check so users can read
# usage without sudo.
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            awk '
                NR<3            { next }
                /^set -euo/     { exit }
                /^#$/           { print ""; next }
                /^# /           { sub(/^# /, ""); print; next }
                /^#/            { sub(/^#/,  ""); print }
            ' "$0"
            exit 0
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Error: install-server-kit.sh must be run with sudo." >&2
    echo "Usage: sudo bash install-server-kit.sh [--domain <D>] [--user <U>]" >&2
    echo "       sudo bash install-server-kit.sh --help" >&2
    exit 1
fi

# --- 0. Parse args ----------------------------------------------------
MTC_DOMAIN=""
MTC_USER="${SUDO_USER:-ubuntu}"
MTC_DATA_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)   MTC_DOMAIN="$2";   shift 2 ;;
        --user)     MTC_USER="$2";     shift 2 ;;
        --data-dir) MTC_DATA_DIR="$2"; shift 2 ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
done

if ! id -u "$MTC_USER" >/dev/null 2>&1; then
    echo "Error: user '$MTC_USER' does not exist on this system." >&2
    echo "Create it (\`sudo adduser --system --group $MTC_USER\`) or" >&2
    echo "pass --user <existing-user>." >&2
    exit 1
fi
MTC_HOME="$(getent passwd "$MTC_USER" | cut -d: -f6)"
: "${MTC_DATA_DIR:=$MTC_HOME/.mtc-ca-data}"

HERE="$(cd "$(dirname "$0")" && pwd)"
for d in bin lib etc doc; do
    if [[ ! -d "$HERE/$d" ]]; then
        echo "Error: expected $HERE/$d not found." >&2
        echo "Run this script from the extracted kit directory "\
             "(tar xzf postWolf-server-kit-*.tar.gz && cd payload)." >&2
        exit 1
    fi
done
for f in socket-level-wrapper-MQC.tar.gz mqc.pc buildopenssl4.0.sh \
         etc/mtc-ca.service.template; do
    if [[ ! -f "$HERE/$f" ]]; then
        echo "Error: expected $HERE/$f not found in kit." >&2
        exit 1
    fi
done

VERSION="$(cat "$HERE/VERSION" 2>/dev/null || echo unknown)"

# --- 1. Runtime library + service dependencies ------------------------
echo ">>> Ensuring runtime apt prerequisites are present ..."
apt-get update -q >/dev/null 2>&1 || true
apt-get install -y --no-install-recommends \
    libjson-c5 libcurl4 libpq5 \
    libhiredis1.1.0 libhiredis1.0.0 libhiredis0.14 \
    libunbound8 dns-root-data libaugeas0 \
    postgresql-client redis-server \
    python3 python3-cryptography dnsutils \
    2>/dev/null || {
    echo "Warning: apt-get could not install every runtime dep; check ldd output below." >&2
}

# Redis is required for MQC rate limiting.  Enable but do not block on
# start failure — the operator may want to point at an external redis.
systemctl enable --now redis-server 2>/dev/null || true

# --- 1a. OpenSSL 4.0.0 (openssl40) ------------------------------------
# mtc_server's first-start cosigner-key keygen path uses ML-DSA-87,
# which needs OpenSSL 3.5+; we ship 4.0.0.  buildopenssl4.0.sh is
# idempotent (no-op if already installed).
echo ">>> Running buildopenssl4.0.sh (first-time build takes ~5–10 min) ..."
bash "$HERE/buildopenssl4.0.sh"

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
install -m 644 "$mqc_src/config.h"    /usr/local/include/mqc/config.h

install -m 644 "$mqc_src/libmqc.a"    /usr/local/lib/libmqc.a

install -d /usr/local/lib/pkgconfig
install -m 644 "$HERE/mqc.pc"         /usr/local/lib/pkgconfig/mqc.pc

# --- 3. Server daemon + ops tools ------------------------------------
echo ">>> Installing mtc_server + ops tools → /usr/local/bin/ ..."
install -d /usr/local/bin
install -m 755 "$HERE/bin/mtc_server" /usr/local/bin/mtc_server
for t in admin_recosign migrate-cosigner backfill-pubkey show-tpm; do
    install -m 755 "$HERE/bin/$t" "/usr/local/bin/$t"
done
for p in create_server_cert.py verify.py verify_certificate.py; do
    install -m 755 "$HERE/bin/$p" "/usr/local/bin/$p"
done

# --- 4. systemd unit --------------------------------------------------
install -d /usr/local/share/doc/postWolf-server
install -m 644 "$HERE/etc/mtc-ca.service.template" \
    /usr/local/share/doc/postWolf-server/mtc-ca.service.template

if [[ -n "$MTC_DOMAIN" ]]; then
    echo ">>> Substituting systemd unit for domain '$MTC_DOMAIN', user '$MTC_USER' ..."
    template="$(<"$HERE/etc/mtc-ca.service.template")"

    # The shipped template carries the factsorlie.com reference
    # deployment's paths.  Substitute them for the operator's values.
    out="${template//factsorlie.com/$MTC_DOMAIN}"
    out="${out//\/home\/ubuntu/$MTC_HOME}"
    out="${out//User=ubuntu/User=$MTC_USER}"
    out="${out//Group=ubuntu/Group=$MTC_USER}"
    out="${out//Environment=HOME=\/home\/ubuntu/Environment=HOME=$MTC_HOME}"
    # WorkingDirectory in the dev tree pointed at the source dir; for
    # an installed deployment, point at the data dir instead.
    out="$(printf '%s\n' "$out" | awk -v d="$MTC_DATA_DIR" '
        /^WorkingDirectory=/ { print "WorkingDirectory=" d; next }
        { print }
    ')"

    printf '%s' "$out" > /etc/systemd/system/mtc-ca.service
    chmod 644 /etc/systemd/system/mtc-ca.service
    systemctl daemon-reload
    echo ">>> Wrote /etc/systemd/system/mtc-ca.service (not enabled; see Next steps)."
else
    echo ">>> --domain not given; systemd unit installed as TEMPLATE only."
    echo "    Edit /usr/local/share/doc/postWolf-server/mtc-ca.service.template,"
    echo "    copy to /etc/systemd/system/mtc-ca.service, and run"
    echo "    'systemctl daemon-reload'."
fi

# --- 5. Docs ----------------------------------------------------------
install -m 644 "$HERE/doc/README.md" \
    /usr/local/share/doc/postWolf-server/README.md
if [[ -f "$HERE/doc/README-using-mtc-server.md" ]]; then
    install -m 644 "$HERE/doc/README-using-mtc-server.md" \
        /usr/local/share/doc/postWolf-server/README-using-mtc-server.md
fi

# --- 6. Verify ldd -----------------------------------------------------
missing_libs=0
for t in mtc_server admin_recosign migrate-cosigner backfill-pubkey show-tpm; do
    if ldd "/usr/local/bin/$t" 2>/dev/null | grep -q "not found"; then
        echo "Warning: /usr/local/bin/$t has unresolved shared libs:" >&2
        ldd "/usr/local/bin/$t" | grep "not found" >&2
        missing_libs=1
    fi
done

# --- 7. Pre-create data dir + tokenpath stub --------------------------
if [[ ! -d "$MTC_DATA_DIR" ]]; then
    echo ">>> Creating data dir $MTC_DATA_DIR (owner $MTC_USER:$MTC_USER) ..."
    install -d -o "$MTC_USER" -g "$MTC_USER" -m 0700 "$MTC_DATA_DIR"
fi

echo
echo "postWolf MTC-server kit $VERSION installed."
echo
if (( missing_libs )); then
    echo "Install the missing libraries via apt then re-run:" >&2
    echo "    sudo ldconfig" >&2
    echo
fi

cat <<EOF
Next steps for a fresh MTC-server operator:

  1. Provide database + secrets in $MTC_HOME/.env (chmod 600):

       MERKLE_NEON=postgresql://user:password@host/dbname?sslmode=require
       ABUSEIPDB_KEY=...        # optional (IP-rep feed for MQC rate limit)

     Tables auto-create on first start.

  2. Generate a TLS cert for port 8444 (kept for ad-hoc curl testing):

       sudo -u $MTC_USER python3 /usr/local/bin/create_server_cert.py ${MTC_DOMAIN:-<your-domain>}
       # writes $MTC_DATA_DIR/server-{cert,key}.pem

  3. Start the daemon (auto-generates the ML-DSA-87 cosigner key on
     first run):

       sudo systemctl enable --now mtc-ca
       sudo systemctl status mtc-ca

  4. Open the firewall on 8444 (HTTP API), 8445 (DH bootstrap +
     pre-auth lookup proxy), 8446 (MQC).  Closing 8445 breaks any
     non-enrolled client; closing 8446 breaks every MQC peer.

  5. Optional: this box can also host its own CA — install the
     CA-operator kit (kit-CA) separately for bootstrap_ca,
     issue_leaf_nonce, revoke-key, and the leaf-side tooling.

Full docs:
  /usr/local/share/doc/postWolf-server/README.md
EOF
if [[ -f /usr/local/share/doc/postWolf-server/README-using-mtc-server.md ]]; then
    echo "  /usr/local/share/doc/postWolf-server/README-using-mtc-server.md"
fi
