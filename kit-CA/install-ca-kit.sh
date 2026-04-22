#!/usr/bin/env bash
#
# install-ca-kit.sh — install the extracted postWolf CA-operator kit.
# Must run as root.
#
# Installs six CA-side tools (bootstrap_ca, bootstrap_leaf, show-tpm,
# issue_leaf_nonce, admin_recosign, revoke-key), libpostWolf, the MQC
# library + headers + pkg-config, and OpenSSL 3.5 (for ML-DSA keygen).
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Error: install-ca-kit.sh must be run with sudo." >&2
    echo "Usage: sudo bash install-ca-kit.sh" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
for d in bin lib doc; do
    if [[ ! -d "$HERE/$d" ]]; then
        echo "Error: expected $HERE/$d not found." >&2
        echo "Run this script from the extracted kit directory "\
             "(tar xzf postWolf-ca-kit-*.tar.gz && cd payload)." >&2
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
apt-get install -y --no-install-recommends \
    libjson-c5 libcurl4 libpq5 \
    libhiredis1.1.0 libhiredis1.0.0 libhiredis0.14 \
    python3 python3-cryptography dnsutils \
    2>/dev/null || {
    echo "Warning: apt-get could not install every runtime lib; check ldd output below." >&2
}

# --- 1a. OpenSSL 3.5 (openssl35) --------------------------------------
# CA + leaf key generation (ML-DSA-44/65/87) requires OpenSSL 3.5+.
# buildopenssl3.5.sh is idempotent (no-op if already installed).
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
install -m 644 "$mqc_src/config.h"    /usr/local/include/mqc/config.h

install -m 644 "$mqc_src/libmqc.a"    /usr/local/lib/libmqc.a

install -d /usr/local/lib/pkgconfig
install -m 644 "$HERE/mqc.pc"         /usr/local/lib/pkgconfig/mqc.pc

# --- 3. CA operator tools ---------------------------------------------
echo ">>> Installing CA tools → /usr/local/bin/ ..."
install -d /usr/local/bin
for t in bootstrap_ca bootstrap_leaf show-tpm issue_leaf_nonce \
         admin_recosign migrate-cosigner backfill-pubkey revoke-key \
         renew-cert check-renewal-cert cancel-nonce mqc; do
    install -m 755 "$HERE/bin/$t" "/usr/local/bin/$t"
done
for p in create_ca_cert.py create_leaf_keypair.py ca_dns_txt.py; do
    install -m 755 "$HERE/bin/$p" "/usr/local/bin/$p"
done
install -m 755 "$HERE/bin/register-ca.sh"   /usr/local/bin/register-ca.sh
install -m 755 "$HERE/bin/register-leaf.sh" /usr/local/bin/register-leaf.sh

# --- 3a. Cron-setup helper → /usr/local/sbin -------------------------
install -d /usr/local/sbin
install -m 755 "$HERE/sbin/setup-recert-crond.sh" \
    /usr/local/sbin/setup-recert-crond.sh

# --- 4. Docs ----------------------------------------------------------
install -d /usr/local/share/doc/postWolf-ca
install -m 644 "$HERE/doc/README.md" \
    /usr/local/share/doc/postWolf-ca/README.md
install -m 644 "$HERE/doc/README-ca-registration.md" \
    /usr/local/share/doc/postWolf-ca/README-ca-registration.md
install -m 644 "$HERE/doc/README-leaf-registration.md" \
    /usr/local/share/doc/postWolf-ca/README-leaf-registration.md

# --- 5. Verify ldd -----------------------------------------------------
missing_libs=0
for t in bootstrap_ca bootstrap_leaf show-tpm issue_leaf_nonce \
         admin_recosign migrate-cosigner backfill-pubkey revoke-key \
         renew-cert check-renewal-cert cancel-nonce mqc; do
    if ldd "/usr/local/bin/$t" 2>/dev/null | grep -q "not found"; then
        echo "Warning: /usr/local/bin/$t has unresolved shared libs:" >&2
        ldd "/usr/local/bin/$t" | grep "not found" >&2
        missing_libs=1
    fi
done

echo
echo "postWolf CA-operator kit $VERSION installed."
echo
if (( missing_libs )); then
    echo "Install the missing libraries via apt then re-run:" >&2
    echo "    sudo ldconfig" >&2
    echo
fi

cat <<'EOF'
Next steps for a fresh CA operator:

  Fast path — one command (recommended):
       register-ca.sh --domain <DOMAIN> --server <CA-HOST>:8445
       # walks you through keygen → publish DNS TXT → poll → bootstrap

  Manual path (when you want to watch each phase separately):

    1. Generate your CA's keypair + self-signed cert:
         create_ca_cert.py --domain <DOMAIN>
         # → ~/.mtc-ca-data/<DOMAIN>/{private_key,public_key,ca_cert}.pem

    2. Compute and publish the DNS TXT record at _mtc-ca.<DOMAIN>:
         ca_dns_txt.py ~/.mtc-ca-data/<DOMAIN>/ca_cert.pem

    3. Enrol your CA against an MTC server (e.g. factsorlie.com):
         bootstrap_ca --domain <DOMAIN> --server <CA-HOST>:8445

  Post-enrollment operations:

    4. Issue a leaf nonce to authorise an enrollment:
         issue_leaf_nonce --domain <DOMAIN> --key-file <leaf-pub.pem>
       Or, if the leaf lives on this same box:
         register-leaf.sh --domain <LEAF-DOMAIN> --server <CA-HOST>:8445
       (detects the local CA, issues the nonce, and bootstraps in one go)
       Or pre-provision a team (recipient keeps private key local):
         issue_leaf_nonce --domain <DOMAIN> --label Alice --ttl-days 7
         # Send the printed 64-hex nonce to Alice over a secure channel.
         # If you need to retract a pending reservation early:
         cancel-nonce --domain <DOMAIN> --label Alice
         # See /usr/local/share/doc/postWolf-ca/README-leaf-registration.md

    5. Revoke a leaf under your domain (authenticated, CA-signed):
         revoke-key --target-index N --reason "key compromise"

    6. Inspect your own identity, verify the log:
         show-tpm --verify

    7. Optional: enable the daily auto-renewal cron (00:00, as user
       `ubuntu`, renews any identity in ~/.TPM/* that's within 5 days
       of expiry via the MQC /renew-cert endpoint):
         sudo /usr/local/sbin/setup-recert-crond.sh --start
       Disable again with:
         sudo /usr/local/sbin/setup-recert-crond.sh --stop

Full docs:
  /usr/local/share/doc/postWolf-ca/README.md
  /usr/local/share/doc/postWolf-ca/README-ca-registration.md
EOF
