#!/usr/bin/env bash
#
# prerequisites.sh — apt-install everything a developer needs to clone
# postWolf and run `./make-all.sh` to completion.
#
# Idempotent.  Safe to re-run.  Must be invoked with sudo.
#
# Covers:
#   - autotools + build essentials (build-essential, pkg-config,
#     autoconf, automake, libtool)
#   - libpostWolf / mtc_server / MQC build-time deps (-dev variants of
#     json-c, pq, curl, hiredis, unbound, augeas)
#   - Runtime services for full testing on the same box
#     (postgresql-client, redis-server, dnsutils, dns-root-data)
#   - Python tooling (cryptography, psycopg2-binary via pip3)
#   - Source-build deps for kit-CA/buildopenssl4.0.sh (wget, perl,
#     zlib1g-dev, libssl-dev) so the developer can also produce
#     openssl40 if they want to exercise ML-DSA-87 keygen end-to-end.
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Error: prerequisites.sh must run with sudo." >&2
    echo "Usage: sudo bash prerequisites.sh" >&2
    exit 1
fi

echo ">>> apt update ..."
apt-get update -q

echo ">>> Installing postWolf build + runtime prereqs ..."
apt-get install -y --no-install-recommends \
    build-essential pkg-config autoconf automake libtool \
    git wget perl zlib1g-dev libssl-dev \
    libjson-c-dev libpq-dev libcurl4-openssl-dev \
    libhiredis-dev libunbound-dev libaugeas-dev \
    postgresql-client redis-server \
    dnsutils dns-root-data \
    python3 python3-pip python3-cryptography

# psycopg2-binary is the one Python lib not packaged in apt that the
# CA-operator helpers (verify_certificate.py, etc.) import.
echo ">>> pip3 install psycopg2-binary ..."
pip3 install --break-system-packages psycopg2-binary 2>/dev/null \
    || pip3 install psycopg2-binary

cat <<'EOF'

postWolf developer prereqs installed.

Next:
  git clone https://github.com/cpsource/postWolf.git
  cd postWolf
  ./make-all.sh

If you also need openssl40 (ML-DSA-87 keygen), run:
  sudo bash kit-CA/buildopenssl4.0.sh

EOF
