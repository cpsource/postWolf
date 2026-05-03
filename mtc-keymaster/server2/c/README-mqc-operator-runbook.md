# MQC Operator Runbook

This is the operational reference for running an MQC-enabled
postWolf deployment.  The companion docs are:

- [`README-using-mtc-server.md`](./README-using-mtc-server.md)
  for general server operations (build, install, start/stop,
  log levels, listener ports).
- [`socket-level-wrapper-MQC/README.md`](../../socket-level-wrapper-MQC/README.md)
  for the MQC protocol itself + spec navigation.
- [`socket-level-wrapper-MQC/draft-page-mqc-protocol-00.md`](../../socket-level-wrapper-MQC/draft-page-mqc-protocol-00.md)
  for the normative wire format.

This file focuses on day-to-day operational tasks: tuning knobs,
responding to incidents, and decoding what `MQC_SECURITY` log
lines mean.

## Routine procedures

### Tighten or loosen a rate limit

Every MQC rate limit is a key in `/etc/postWolf/config` under
`[global]`.  The full registry is in spec §11 (or
[`README-using-mtc-server.md`](./README-using-mtc-server.md) §
"MQC Tunables"); the most common ones to touch:

| Knob | Default | When to lower | When to raise |
|---|---|---|---|
| `mqc-rl-connect-per-min` | 100 | A scanner is hitting 8446 with junk | Real CI fleet exceeds the bucket on legitimate traffic |
| `mqc-rl-fail-per-min` | 10 | A bug-hunting client keeps tripping the parser | Same |
| `mqc-rl-cert-per-min` | 10 | An actor is rotating `cert_index` to amplify cosignature work | A multi-identity test runner needs to cycle real identities legitimately |
| `mqc-max-children` | 20 | Memory pressure under burst load | Have spare CPU + RAM and want higher accept throughput |

Apply by editing `/etc/postWolf/config` (or copy from the repo
template at `mtc-keymaster/read-config/config.server`), then
restart:

```sh
sudo cp /etc/postWolf/config /tmp/cfg.bak           # always back up first
sudoedit /etc/postWolf/config                       # uncomment + edit the line
sudo systemctl restart mtc-ca.service
sudo journalctl -u mtc-ca.service -n 20             # confirm new value picked up
```

The init log emits the resolved value of every knob it reads:

```
[INFO ] backpressure: max-children=20
[mqc-rl-connect-per-min] /etc/postWolf/config: 100
...
```

### Switch `mqc-revocation-policy`

Three legal values; pick by operational context:

| Value | When |
|---|---|
| `mandatory` | **Default.** Every cache miss queries the log; query failure aborts the handshake.  The right choice for normal production. |
| `cache-only` | Planned log-endpoint maintenance windows where you know the log will be unreachable but recent caches are still trustworthy.  No network call; abort on cache miss. |
| `disabled` | Emergency recovery only (e.g., catastrophic log loss).  Skips revocation entirely.  Logs a loud `REVOCATION_DISABLED` warning at process startup. |

```sh
# Switch + restart
sudoedit /etc/postWolf/config       # set: mqc-revocation-policy   cache-only
sudo systemctl restart mtc-ca.service
sudo journalctl -u mtc-ca.service -n 5 | grep -i revocation

# Revert to default
sudoedit /etc/postWolf/config       # comment out the line (or set "mandatory")
sudo systemctl restart mtc-ca.service
```

`disabled` is dangerous: while in effect, a revoked peer cert
will be accepted.  Treat any time spent in `disabled` as an
incident window and revert as soon as the underlying log issue
is resolved.

### Lower `mqc-revoked-cache-ttl-sec` for a compliance drill

Default 86400 (24 h).  Lowering forces the verifier to query
the log more often:

```sh
sudoedit /etc/postWolf/config       # set: mqc-revoked-cache-ttl-sec   3600
sudo systemctl restart mtc-ca.service
```

Tradeoff: 1× hourly fresh-fetch per (cert_index, host) pair
across all clients increases /revoked endpoint load by 24×.
Don't leave a low TTL set after the drill.

## Incident playbooks

### Log endpoint unreachable

**Symptom:** `journalctl -u mtc-ca.service` fills with
`REVOCATION_QUERY_FAILED policy=mandatory` lines, handshakes are
dropping at the revocation step.

**Triage path:**

1. Confirm it's a network/log issue, not a config error.  Try
   the bootstrap port directly:
   ```sh
   curl -k -m 5 http://127.0.0.1:8445/revoked/0
   ```
   If that fails locally, the issue is server-side; if it works
   locally but remote callers fail, it's network.

2. While the log is down, switch revocation to `cache-only` to
   keep handshakes flowing on warm caches:
   ```sh
   sudoedit /etc/postWolf/config       # mqc-revocation-policy   cache-only
   sudo systemctl restart mtc-ca.service
   ```

3. Once the log is back, revert:
   ```sh
   sudoedit /etc/postWolf/config       # comment out (default = mandatory)
   sudo systemctl restart mtc-ca.service
   ```

4. **Last resort only:** if cache-only is also failing (cold
   peers needing first-contact), switch to `disabled` for the
   shortest possible window.  Set a calendar reminder to
   revert.  Document the incident.

### Cosigner pubkey rotation (`admin_recosign`)

**When:** the log cosigner key has been rotated (e.g.,
suspected compromise, scheduled rotation, HSM swap).

**Procedure:**

```sh
# 1. The new cosigner pubkey is now in ~/.mtc-ca-data/cosigner-pubkey.pem.
#    admin_recosign re-signs every existing cert in the store with the
#    new key.  Dry-run first:
admin_recosign --dry-run

# 2. Apply.  --write commits to certificates.json + the Neon DB.
admin_recosign --write

# 3. Restart so the running server picks up the new in-memory state.
sudo systemctl restart mtc-ca.service
```

**Expected on the client side:** every MQC client that has a
cached peer cert (in `~/.TPM/peers/<n>/`) will hit the
cosigner-fingerprint cache invariant on its next handshake.
The cache file `cosigner-fp.hex` will mismatch the new
fingerprint, the client logs `COSIGNER_ROTATED`, evicts the
cache, re-fetches the cert, and re-verifies under the new
cosigner.  This is automatic — no per-client action required —
but the first handshake post-rotation is slightly slower
(extra cert fetch + cosignature verify).

**Verify:** after rotation, watch `journalctl -u mtc-ca.service
-f` for a few minutes.  You should see:

- One `COSIGNER_ROTATED` line per peer the first time it
  reconnects (or per client process — the server's own outbound
  MQC traffic also fires this).
- No `PEER_VERIFY_FAILED` lines once the rotation is fully
  propagated.

If `PEER_VERIFY_FAILED` persists past the cache eviction
window, something is wrong with the new cosigner key (e.g., the
DB and the in-memory state diverged).  Re-run
`admin_recosign --dry-run` to compare.

### Suspected DoS

**Symptom:** unusually high rate of `RATE_LIMITED`,
`FAIL_RATE_LIMITED`, `CERT_RATE_LIMITED`, or `MQC backpressure:
N/M active children` lines in the journal.

**Triage path:**

1. Identify the source IP(s):
   ```sh
   sudo journalctl -u mtc-ca.service --since "5 minutes ago" \
       | grep -E "RATE_LIMITED|backpressure" \
       | awk '{print $NF}' | sort | uniq -c | sort -rn | head
   ```

2. If a single IP dominates, decide whether it's hostile or a
   misbehaving real client.  Check Redis state for the IP:
   ```sh
   redis-cli keys "mqc:<ip>:*"
   redis-cli get  "mqc:<ip>:conn:m"
   redis-cli scard "mqc:<ip>:cert:m"
   ```

3. **Hostile:** add an `iptables` block at the host level — MQC
   rate limits cap the cost per IP but don't reduce
   accept-loop work to zero, so for sustained abuse a kernel-
   level drop is more efficient:
   ```sh
   sudo iptables -A INPUT -s <ip> -p tcp --dport 8446 -j DROP
   ```

4. **Misbehaving real client:** identify the bug in the client
   (likely tripping the strict-JSON parser or sending wrong-
   length hex), fix it, then unban by clearing the IP's Redis
   state:
   ```sh
   redis-cli del mqc:<ip>:conn:m mqc:<ip>:conn:h \
                 mqc:<ip>:fail:m mqc:<ip>:fail:h \
                 mqc:<ip>:cert:m mqc:<ip>:cert:h
   ```

5. If the issue is **legitimate-but-bursty** load (CI
   stress, mass migration), raise the relevant knob (see the
   table at the top of this runbook).

## `MQC_SECURITY` log-line decoder

Every line below is a stderr fragment from `mtc_server`'s
journal indicating something the MQC layer rejected.  Format is
`[MQC-SECURITY <function>:<line>] <event>: <details>`.

| Log line | Meaning | Likely remediation |
|---|---|---|
| `RATE_LIMITED: <ip> connect N/min (max M)` | Per-IP connection cap exceeded | Confirm the IP isn't a CI runner; if hostile, iptables; if legit, raise `mqc-rl-connect-per-min` |
| `FAIL_RATE_LIMITED: <ip> failures N/min M/hr` | Per-IP failed-handshake cap exceeded | Look at the failure cause (preceding log lines); fix the buggy client or block hostile IP |
| `CERT_RATE_LIMITED: <ip> distinct cert_index N/min (max M)` | Per-IP distinct-`cert_index` cap exceeded — cert-rotation amplification attempt | Almost always hostile.  iptables block |
| `MQC backpressure: N/M active children, sleeping before accept` | Per-listener fork cap reached | Informational — expected during bursts.  If sustained, raise `mqc-max-children` or investigate why connections aren't completing |
| `JSON_LEN_INVALID len=N` | Handshake JSON outside accepted size range | Misbehaving client.  Probably trying to fingerprint the parser |
| `<ClientHello\|ServerHello>: strict JSON parse failed (...)` | Malformed JSON or json-c-extension input | Strict-parser rejection (spec §5.2) — the parenthetical names the specific failure |
| `<...>: field 'X' appears N times (require 1)` | Duplicate-key smuggling attempt | Always hostile (no legitimate client serializes duplicates) |
| `<...>: unknown field 'X'` | Forward-incompat extension or fingerprinting | v0 has no extension registry; reject is correct |
| `<...>: field 'X' value V out of [min, max]` | Integer overflow on `cert_index` (or version mismatch) | Always hostile |
| `<...>: field 'X' invalid hex (lowercase 0-9 a-f only)` | Non-canonical hex on `kem_pub` or `signature` | Either a buggy client or fingerprinting |
| `<...>: field 'X' hex length M != N` | Wrong-length hex blob | Pre-crypto length filter — caught before any ML-KEM/ML-DSA call |
| `PEER_VERIFY_FAILED: peer for index N` | Cert N failed Merkle proof, cosignature, validity, or revocation check | Look at preceding lines for the specific sub-check that failed |
| `SIG_VERIFY_FAILED: server\|client signature invalid` | The peer's ML-DSA-87 handshake signature didn't validate | Wire-tampered or signer-vs-verifier transcript divergence (the Finished MAC catches the latter cleanly later in the handshake) |
| `NAME_CHECK_FAILED: cert subject 'X' does not match expected 'Y'` | Issue-#9 expected-identity check failure | Either the operator dialed the wrong host or DNS is mis-resolving — investigate the resolution path |
| `NAME_CHECK_FAILED: dialed IP literal 'X' with no expected name` | Caller dialed by IP without `mqc_ctx_set_expected_name()` | Caller's responsibility; defaults are deliberate (IP names a location, not an MTC identity) |
| `REVOCATION_QUERY_FAILED policy=mandatory cert=N` | Log endpoint unreachable with mandatory policy | See the "Log endpoint unreachable" playbook above |
| `REVOCATION_CACHE_MISS policy=cache-only cert=N` | Cold cache under cache-only policy | Either flip back to `mandatory` or pre-warm the cache |
| `CERT_REVOKED: cert N is revoked` | The peer's identity is in the revocation list | Refuse the connection.  Do NOT override |
| `CERT_NOT_YET_VALID` / `CERT_EXPIRED` | Validity-window failure (spec §10.6) | Check the verifier's clock; check whether the peer needs renewal |
| `COSIGNER_ROTATED: cert N cache fp=A current fp=B — dropping cache, re-fetching` | Issue-#8 cache invalidation triggered | Informational — expected after a cosigner rotation, until every cached peer has been re-fetched |
| `HANDSHAKE_DEADLINE_EXCEEDED` (slow-loris detector) | A peer is dripping bytes slowly enough to exceed `mqc-handshake-total-sec` | Almost always hostile |
| `handshake failure recorded for <ip>` | Counter-increment notice; precedes the next `FAIL_RATE_LIMITED` if the bucket fills | Informational |

## Aggregate test suite

The Phase 4 system-level test suite is the canonical "did
anything regress" check.  Run after any operational change:

```sh
make -f Makefile.tools test-mqc-all          # ~5s
make -f Makefile.tools test-mqc-matrix       # ~30s, restarts mtc-ca multiple times
make -f Makefile.tools test-mqc-stress       # ~5s, N=30 concurrent handshakes
make -f Makefile.tools test-cosigner-rotation
make -f Makefile.tools test-mqc-perf         # ~30s, captures a perf snapshot
```

Snapshots from `test-mqc-perf` accumulate at
`mtc-keymaster/perf/perf-snapshot-<date>.txt`; comparing across
dates is the easiest way to spot a latency regression.
