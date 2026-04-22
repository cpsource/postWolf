# MTC Neon Database Schema

All tables are stored in a Neon PostgreSQL database, connected via the
`MERKLE_NEON` connection string in `~/.env`.

## Tables

### mtc_log_entries

Merkle tree log entries. Each entry is a serialized TBS (To-Be-Signed)
record added to the append-only transparency log.

```sql
CREATE TABLE mtc_log_entries (
    index INTEGER PRIMARY KEY,
    entry_type SMALLINT NOT NULL,
    tbs_data JSONB,
    serialized BYTEA NOT NULL,
    leaf_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);
```

| Column | Description |
|--------|-------------|
| `index` | Log position (0-based, append-only) |
| `entry_type` | 0x01 = TBS entry |
| `tbs_data` | Parsed TBS JSON (subject, algorithm, validity, extensions) |
| `serialized` | Raw serialized bytes for Merkle hashing |
| `leaf_hash` | SHA-256 leaf hash: `SHA256(0x00 || serialized)` |

### mtc_certificates

Issued certificates with full standalone proofs (Merkle inclusion proof,
cosignature, checkpoint).

```sql
CREATE TABLE mtc_certificates (
    index INTEGER PRIMARY KEY,
    certificate JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);
```

| Column | Description |
|--------|-------------|
| `index` | Certificate log index (matches mtc_log_entries) |
| `certificate` | Full standalone certificate JSON (tbs_entry, inclusion_proof, cosignatures, checkpoint) |

### mtc_checkpoints

Tree state snapshots. Each checkpoint records the root hash at a given
tree size.

```sql
CREATE TABLE mtc_checkpoints (
    id SERIAL PRIMARY KEY,
    log_id TEXT NOT NULL,
    tree_size INTEGER NOT NULL,
    root_hash TEXT NOT NULL,
    ts DOUBLE PRECISION NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);
```

| Column | Description |
|--------|-------------|
| `log_id` | Log identifier (e.g., "32473.2") |
| `tree_size` | Number of entries when checkpoint was taken |
| `root_hash` | Merkle root hash (hex) |
| `ts` | Unix timestamp of checkpoint |

### mtc_landmarks

Landmark entries — tree sizes that serve as trust anchors for efficient
proof verification.

```sql
CREATE TABLE mtc_landmarks (
    id SERIAL PRIMARY KEY,
    tree_size INTEGER NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT now()
);
```

| Column | Description |
|--------|-------------|
| `tree_size` | Tree size at which this landmark was created |

### mtc_revocations

Revoked certificate records.

```sql
CREATE TABLE mtc_revocations (
    id SERIAL PRIMARY KEY,
    cert_index INTEGER NOT NULL,
    reason TEXT,
    revoked_at DOUBLE PRECISION NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);
```

| Column | Description |
|--------|-------------|
| `cert_index` | Log index of the revoked certificate |
| `reason` | Human-readable revocation reason |
| `revoked_at` | Unix timestamp when revocation was recorded |

### mtc_enrollment_nonces

Pending enrollment nonces. Nonces are single-use, time-limited, and
bound to a domain + public key fingerprint.

```sql
CREATE TABLE mtc_enrollment_nonces (
    nonce TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    fp TEXT NOT NULL,
    ca_index INTEGER NOT NULL DEFAULT -1,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_nonce_domain_fp
    ON mtc_enrollment_nonces (domain, fp)
    WHERE status = 'pending';
```

| Column | Description |
|--------|-------------|
| `nonce` | 64-char hex (256-bit random), primary key |
| `domain` | Domain/subject the nonce is issued for |
| `fp` | SHA-256 fingerprint of the enrollee's public key (64 hex chars) |
| `ca_index` | Log index of the CA that authorized this nonce (-1 for CA nonces) |
| `expires_at` | Nonce expiry (TTL = 15 minutes) |
| `status` | `pending`, `consumed`, or `expired` |

### mtc_public_keys

Public key storage for MQC (Merkle Quantum Connect) peer key resolution.

```sql
CREATE TABLE mtc_public_keys (
    idx BIGSERIAL PRIMARY KEY,
    key_name VARCHAR(255) UNIQUE NOT NULL,
    key_value TEXT NOT NULL,
    created_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

| Column | Description |
|--------|-------------|
| `idx` | Auto-incrementing primary key |
| `key_name` | Unique key identifier (e.g., domain name or cert subject) |
| `key_value` | Public key data (PEM or hex-encoded) |
| `created_utc` | Timestamp when the key was stored |

### abuseipdb

AbuseIPDB score cache. Caches IP reputation scores to avoid repeated
API calls. TTL = 5 days.

```sql
CREATE TABLE abuseipdb (
    idx SERIAL PRIMARY KEY,
    ipaddr TEXT NOT NULL,
    response JSONB,
    abuse_confidence_score INTEGER NOT NULL,
    requested_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE UNIQUE INDEX abuseipdb_ipaddr_idx ON abuseipdb (ipaddr);
```

| Column | Description |
|--------|-------------|
| `ipaddr` | IP address (unique) |
| `response` | Full AbuseIPDB JSON response (cached) |
| `abuse_confidence_score` | 0-100 score (>= 25 rejects enrollment, >= 75 rejects all) |
| `requested_at` | When the score was first fetched |
| `updated_at` | When the cached score was last refreshed |

## Source Files

- Schema creation: `mtc-keymaster/server2/c/mtc_db.c` (lines 219-273)
- AbuseIPDB schema: `mtc-keymaster/server2/c/mtc_checkendpoint.c` (lines 187-199)
- Database connection: via `MERKLE_NEON` env var in `~/.env`
