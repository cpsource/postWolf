# redis/ — Rate-limit monitoring tools

## redis-info.sh

Dashboard script that queries Redis and the systemd journal to show
live rate-limit state for both the MTC CA/Log server and the MQC
socket layer.

### What it shows

1. **MTC CA/Log rate limits** (`rl:<ip>:<category>:<window>`)
   — per-IP counters for each endpoint category (read, nonce, enroll,
   revoke, bootstrap, global) against their per-minute and per-hour
   maximums.

2. **MQC socket rate limits** (`mqc:<ip>:<type>:<window>`)
   — per-IP connection, handshake-failure, and distinct-cert_index
   counters against their per-minute, per-hour, and per-day maximums.

3. **AbuseIPDB score cache** (`mqc:<ip>:abuse`)
   — cached abuse-confidence scores (shown when present).

4. **Docker Redis status** — container state, Redis version, uptime,
   memory usage, keyspace summary, and ping check.  On hosts without a
   Docker container (e.g. frflashy with apt-installed `redis-server`),
   falls back to querying `redis-cli` directly.

5. **Global hit counter** (`hits`).

6. **Journal activity (last 24h)** — per-IP summary of handshake
   failures, ACL denials, and successful accepts from `journalctl -u qshd`,
   so IPs whose Redis counters have already expired are still visible.

### Usage

```
./redis-info.sh
```

Requires `redis-cli` and read access to the qshd journal.

### Redis key reference

Every key listed below is written by the MQC or MTC rate-limit code
and read by `redis-info.sh`.  Keys expire automatically via Redis TTL.

#### MTC CA/Log counters (`rl:<ip>:<category>:<window>`)

Source: `mtc_ratelimit.c`.  Hardcoded; not tunable via config.

| Key suffix | Category  | Per-minute (`:m`, 60s TTL) | Per-hour (`:h`, 3600s TTL) |
|-----------|-----------|-----------|---------|
| `0`       | read      | 60        | 600     |
| `1`       | nonce-lf  | 10        | 100     |
| `2`       | nonce-ca  | 3         | 10      |
| `3`       | enroll    | 3         | 10      |
| `4`       | revoke    | 5         | 100     |
| `5`       | bootstrap | 3         | 30      |
| `6`       | global    | 120       | 1200    |

#### MQC socket counters (`mqc:<ip>:<type>:<window>`)

Source: `mqc_ratelimit.c` / `mqc_common.c`.  All defaults are tunable
in `/etc/postWolf/config` under `[global]`:

| Key pattern | Config key | Per-minute (`:m`, 60s TTL) | Per-hour (`:h`, 3600s TTL) | Per-day (`:d`, 86400s TTL) |
|------------|-----------|-----------|---------|---------|
| `mqc:<ip>:conn:<w>` | `mqc-rl-connect-per-{min,hour}` | 100 | 1000 | — |
| `mqc:<ip>:fail:<w>` | `mqc-rl-fail-per-{min,hour,day}` | 10 | 100 | 300 |
| `mqc:<ip>:cert:<w>` | `mqc-rl-cert-per-{min,hour}` | 10 | 100 | — |

The `cert` counter is a Redis SET (distinct `cert_index` values), not
a simple increment — `SCARD` gives the count.

#### AbuseIPDB score cache (`mqc:<ip>:abuse`)

A single integer (the `abuseConfidenceScore` from the AbuseIPDB API).
TTL controlled by `mqc-abuse-cache-ttl-sec` (default 86400s).

#### Other counters

| Key | Type | Description |
|-----|------|-------------|
| `hits` | string (integer) | Global request counter, no TTL |

### Docker Redis deployment

On factsorlie, Redis runs as a Docker container named `redis`, bound
to `127.0.0.1:6379`:

```
docker run -d --name redis --restart unless-stopped \
    -p 127.0.0.1:6379:6379 redis:7
```

On frflashy, Redis is installed via `apt` (`redis-server` package)
and managed by systemd (`redis-server.service`).

Both hosts bind Redis to localhost only — no network exposure.
The MQC rate-limit code connects to `127.0.0.1:6379` unconditionally
(see `mqc_redis_init()` in `mqc_ratelimit.c`).

Common operations:

| Task | Command |
|------|---------|
| Check container health | `docker exec redis redis-cli ping` |
| Flush all rate-limit counters | `docker exec redis redis-cli FLUSHALL` |
| Inspect a specific key | `docker exec redis redis-cli GET "mqc:<ip>:abuse"` |
| View all MQC keys | `docker exec redis redis-cli KEYS "mqc:*"` |
| Container logs | `docker logs redis --tail 20` |

On frflashy (apt), substitute `redis-cli` directly for `docker exec redis redis-cli`.

### Other MQC operational tunables

These are not Redis counters but affect rate-limit behavior.  All are
set in `/etc/postWolf/config` under `[global]`; commented-out lines
show the compiled-in default.

| Config key | Default | Description |
|-----------|---------|-------------|
| `mqc-max-children` | 20 | Max concurrent forked children; gates `accept()` as backpressure |
| `mqc-handshake-stall-sec` | 3 | Per-read stall timeout during handshake |
| `mqc-handshake-total-sec` | 5 | Total wall-clock ceiling for the full handshake |
| `mqc-max-handshake-bytes` | 131072 | Max single handshake frame size |
| `mqc-max-msg-bytes` | 1048576 | Max single post-handshake message size |
| `mqc-revoked-cache-ttl-sec` | 86400 | Revocation-query result cache TTL |
| `mqc-abuse-cache-ttl-sec` | 86400 | AbuseIPDB score cache TTL |
| `mqc-sig-freshness-sec` | 300 | Cert `not_before`/`not_after` skew tolerance |
| `mqc-revocation-policy` | `mandatory` | `mandatory` / `cache-only` / `disabled` |
| `mqc-rl-redis-fail-policy` | `closed-after` | What rate-limit gates do when Redis is down: `open` / `closed` / `closed-after` |
| `mqc-rl-redis-fail-closed-after-sec` | 8 | Grace period before `closed-after` flips to fail-closed |
