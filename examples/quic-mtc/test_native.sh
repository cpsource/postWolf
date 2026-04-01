#!/bin/bash
set +e
D="$(cd "$(dirname "$0")" && pwd)"

pkill -f "quic_mtc" 2>/dev/null
sleep 0.5

"$D/quic_mtc_server" -p 4540 --no-mtc \
  --mtc-store "$HOME/.TPM/urn_ajax-inc_app_truthorlieAccess" &
SRV=$!
sleep 2

"$D/quic_mtc_client" -p 4540 --no-mtc \
  -A "$D/mtc-ca.pem" \
  -m "MTC native test"

sleep 1
kill $SRV 2>/dev/null
wait $SRV 2>/dev/null
exit 0
