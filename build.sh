#!/bin/bash
set -e
./autogen.sh
./configure --enable-quic --enable-ech --enable-mtc --enable-tls13 --enable-all --quiet
make
make check
