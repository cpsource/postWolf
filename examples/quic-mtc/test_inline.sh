#!/bin/bash
set +e
D="$(cd "$(dirname "$0")" && pwd)"

pkill -f "quic_mtc" 2>/dev/null
sleep 0.5

"$D/quic_mtc_server" -p 4534 --no-mtc \
  -c "$D/mtc-cert.pem" -k "$D/mtc-key.pem" &
SRV=$!
sleep 1

"$D/quic_mtc_client" -p 4534 --no-mtc \
  -A "$D/mtc-ca.pem" \
  -m "MTC inline test"

sleep 1
kill $SRV 2>/dev/null
wait $SRV 2>/dev/null
exit 0
