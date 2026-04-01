#!/bin/bash
set +e
pkill -f "quic_mtc" 2>/dev/null
sleep 1

DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS="$(cd "$DIR/../.." && pwd)/certs"

"$DIR/quic_mtc_server" -p 4520 \
    --no-mtc \
    -c "$CERTS/server-cert.pem" \
    -k "$CERTS/server-key.pem" &
SRV=$!

sleep 3

"$DIR/quic_mtc_client" -p 4520 \
    --ca-url http://localhost:8443 \
    --verify-index 1 \
    -A "$CERTS/ca-cert.pem" \
    -m "debug test"

sleep 1
kill $SRV 2>/dev/null
wait $SRV 2>/dev/null
exit 0
