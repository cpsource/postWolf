"""
PostgreSQL persistence layer for the MTC CA/Log server.

Stores log entries, checkpoints, landmarks, and issued certificates
in a Neon PostgreSQL database. On startup, the full Merkle tree is
rebuilt in memory from the stored entries (append-only, so this is
deterministic).

Connection string is read from ~/.env (MERKLE_NEON key).
"""

import json
import os
from pathlib import Path

import psycopg2
import psycopg2.extras


def _load_connection_string() -> str:
    """Read MERKLE_NEON from ~/.env file."""
    # First check environment
    val = os.getenv("MERKLE_NEON")
    if val:
        return val

    # Fall back to reading ~/.env directly
    env_path = Path.home() / ".env"
    if not env_path.exists():
        raise RuntimeError("~/.env not found and MERKLE_NEON not in environment")

    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("MERKLE_NEON="):
                return line.split("=", 1)[1].strip('"').strip("'")

    raise RuntimeError("MERKLE_NEON not found in ~/.env")


def get_connection():
    """Get a new database connection."""
    return psycopg2.connect(_load_connection_string())


def init_schema(conn):
    """Create tables if they don't exist."""
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mtc_log_entries (
                index       INTEGER PRIMARY KEY,
                entry_type  SMALLINT NOT NULL,
                tbs_data    JSONB,
                serialized  BYTEA NOT NULL,
                leaf_hash   BYTEA NOT NULL,
                created_at  TIMESTAMPTZ DEFAULT now()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mtc_checkpoints (
                id          SERIAL PRIMARY KEY,
                log_id      TEXT NOT NULL,
                tree_size   INTEGER NOT NULL,
                root_hash   TEXT NOT NULL,
                ts          DOUBLE PRECISION NOT NULL,
                created_at  TIMESTAMPTZ DEFAULT now()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mtc_landmarks (
                id          SERIAL PRIMARY KEY,
                tree_size   INTEGER NOT NULL UNIQUE,
                created_at  TIMESTAMPTZ DEFAULT now()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mtc_certificates (
                index           INTEGER PRIMARY KEY,
                certificate     JSONB NOT NULL,
                created_at      TIMESTAMPTZ DEFAULT now()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mtc_ca_config (
                key     TEXT PRIMARY KEY,
                value   TEXT NOT NULL
            );
        """)
    conn.commit()


# --- Log entries ---

def save_entry(conn, index: int, entry_type: int, tbs_data: dict | None,
               serialized: bytes, leaf_hash: bytes):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO mtc_log_entries (index, entry_type, tbs_data, serialized, leaf_hash)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (index) DO NOTHING
        """, (index, entry_type, json.dumps(tbs_data) if tbs_data else None,
              psycopg2.Binary(serialized), psycopg2.Binary(leaf_hash)))
    conn.commit()


def load_all_entries(conn) -> list[dict]:
    """Load all log entries ordered by index, for rebuilding the tree."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT index, entry_type, tbs_data, serialized, leaf_hash
            FROM mtc_log_entries
            ORDER BY index
        """)
        rows = cur.fetchall()
    return [
        {
            "index": r["index"],
            "entry_type": r["entry_type"],
            "tbs_data": r["tbs_data"],
            "serialized": bytes(r["serialized"]),
            "leaf_hash": bytes(r["leaf_hash"]),
        }
        for r in rows
    ]


# --- Checkpoints ---

def save_checkpoint(conn, log_id: str, tree_size: int, root_hash: str, ts: float):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO mtc_checkpoints (log_id, tree_size, root_hash, ts)
            VALUES (%s, %s, %s, %s)
        """, (log_id, tree_size, root_hash, ts))
    conn.commit()


def load_checkpoints(conn, log_id: str) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT log_id, tree_size, root_hash, ts
            FROM mtc_checkpoints
            WHERE log_id = %s
            ORDER BY id
        """, (log_id,))
        return [
            {
                "log_id": r["log_id"],
                "tree_size": r["tree_size"],
                "root_hash": r["root_hash"],
                "timestamp": r["ts"],
            }
            for r in cur.fetchall()
        ]


# --- Landmarks ---

def save_landmark(conn, tree_size: int):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO mtc_landmarks (tree_size)
            VALUES (%s)
            ON CONFLICT (tree_size) DO NOTHING
        """, (tree_size,))
    conn.commit()


def load_landmarks(conn) -> list[int]:
    with conn.cursor() as cur:
        cur.execute("SELECT tree_size FROM mtc_landmarks ORDER BY tree_size")
        return [r[0] for r in cur.fetchall()]


# --- Certificates ---

def save_certificate(conn, index: int, certificate: dict):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO mtc_certificates (index, certificate)
            VALUES (%s, %s)
            ON CONFLICT (index) DO UPDATE SET certificate = EXCLUDED.certificate
        """, (index, json.dumps(certificate)))
    conn.commit()


def load_certificate(conn, index: int) -> dict | None:
    with conn.cursor() as cur:
        cur.execute("SELECT certificate FROM mtc_certificates WHERE index = %s", (index,))
        row = cur.fetchone()
        return row[0] if row else None


def load_all_certificates(conn) -> dict[int, dict]:
    with conn.cursor() as cur:
        cur.execute("SELECT index, certificate FROM mtc_certificates ORDER BY index")
        return {r[0]: r[1] for r in cur.fetchall()}


def search_certificates_by_subject(conn, query: str) -> list[dict]:
    """Search certificates by subject (case-insensitive substring match)."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT index, certificate
            FROM mtc_certificates
            WHERE certificate->'standalone_certificate'->'tbs_entry'->>'subject'
                  ILIKE %s
            ORDER BY index
        """, (f"%{query}%",))
        return [{"index": r["index"], "certificate": r["certificate"]} for r in cur.fetchall()]


# --- CA config (for key persistence) ---

def save_ca_config(conn, key: str, value: str):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO mtc_ca_config (key, value)
            VALUES (%s, %s)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        """, (key, value))
    conn.commit()


def load_ca_config(conn, key: str) -> str | None:
    with conn.cursor() as cur:
        cur.execute("SELECT value FROM mtc_ca_config WHERE key = %s", (key,))
        row = cur.fetchone()
        return row[0] if row else None
