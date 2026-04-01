#!/bin/bash
set +e
D="$(cd "$(dirname "$0")" && pwd)"

pkill -f "quic_mtc" 2>/dev/null
sleep 0.5

echo "=== TEST: Revoked MTC cert should fail TLS handshake ==="
echo ""

# Server uses MTC cert (wrapping log index 1)
"$D/quic_mtc_server" -p 4550 --no-mtc \
  -c "$D/mtc-cert.pem" -k "$D/mtc-key.pem" &
SRV=$!
sleep 1

# Client marks index 1 as revoked
"$D/quic_mtc_client" -p 4550 --no-mtc \
  -A "$D/mtc-ca.pem" \
  --revoke-index 1 \
  -m "this should fail"

echo ""
echo "=== TEST: Non-revoked cert should succeed ==="
echo ""

sleep 1
kill $SRV 2>/dev/null
wait $SRV 2>/dev/null

# Restart server
"$D/quic_mtc_server" -p 4551 --no-mtc \
  -c "$D/mtc-cert.pem" -k "$D/mtc-key.pem" &
SRV=$!
sleep 1

# Client does NOT revoke index 1
"$D/quic_mtc_client" -p 4551 --no-mtc \
  -A "$D/mtc-ca.pem" \
  -m "this should work"

sleep 1
kill $SRV 2>/dev/null
wait $SRV 2>/dev/null
exit 0
