#!/bin/bash
# make-all.sh — full build from a clean checkout
#
# Builds and installs the postWolf library (autotools), then builds
# and installs the SLC/MQC/QUIC wrappers and the MTC keymaster tools.
#
# The intermediate `sudo make -f Makefile install` is required because
# MQC, QUIC, and mtc-keymaster consume postWolf via `pkg-config`, which
# only resolves after the .pc file and libpostWolf.so are in /usr/local.

set -euo pipefail

cd "$(dirname "$0")"

TOTAL=6
step_num=0

step() {
    local label=$1
    shift
    step_num=$((step_num + 1))
    printf '\n\033[1;36m==> [%d/%d] %s\033[0m\n' "$step_num" "$TOTAL" "$label"
    printf '    $ %s\n\n' "$*"
    "$@"
}

step "Configure postWolf"               nice -n 10 ./configure.sh
step "Build libpostWolf"                nice -n 10 make -f Makefile
step "Install libpostWolf + pkg-config" sudo make -f Makefile install
step "Refresh ldconfig"                 sudo ldconfig
step "Build SLC/MQC/QUIC/MTC tools"     nice -n 10 make -f Makefile.tools
step "Install tools to /usr/local/bin"  sudo make -f Makefile.tools install

printf '\n\033[1;32m==> All %d steps completed.\033[0m\n' "$TOTAL"
