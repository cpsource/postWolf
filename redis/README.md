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

4. **Global hit counter** (`hits`).

5. **Journal activity (last 24h)** — per-IP summary of handshake
   failures, ACL denials, and successful accepts from `journalctl -u qshd`,
   so IPs whose Redis counters have already expired are still visible.

### Usage

```
./redis-info.sh
```

Requires `redis-cli` and read access to the qshd journal.

### Rate-limit defaults

MTC CA (`mtc_ratelimit.c`):

| Category  | Per-minute | Per-hour |
|-----------|-----------|---------|
| read      | 60        | 600     |
| nonce-lf  | 10        | 100     |
| nonce-ca  | 3         | 10      |
| enroll    | 3         | 10      |
| revoke    | 5         | 100     |
| bootstrap | 3         | 30      |
| global    | 120       | 1200    |

MQC socket (`mqc_common.c`, tunable via `/etc/postWolf/config`):

| Type | Per-minute | Per-hour | Per-day |
|------|-----------|---------|---------|
| conn | 100       | 1000    | —       |
| fail | 10        | 100     | 300     |
| cert | 10        | 100     | —       |
