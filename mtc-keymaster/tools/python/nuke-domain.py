#!/usr/bin/env python3
"""
nuke-domain.py <domain> [--yes]

TESTING-ONLY tool.  Wipes a domain's first-class state so it can
re-enroll cleanly.  Does NOT touch the Merkle log itself
(mtc_log_entries) — those are append-only by design; the leaf
hashes for the deleted certs remain in the tree as inert
orphans.  Re-enrolling under a different SPK lands at a fresh
log index without conflict.

Surfaces cleaned:
  - Neon mtc_certificates       (rows whose subject is
                                  <domain> or <domain>-ca)
  - Neon mtc_public_keys        (rows whose key_name starts with
                                  <domain> — covers <domain>,
                                  <domain>-ca, and labeled
                                  variants)
  - Neon mtc_enrollment_nonces  (rows whose domain = <domain>)
  - ~/.TPM/peers/<idx>/         (this box's cached view of any
                                  index whose cert was just
                                  deleted)
  - mtc-ca.service              (SIGHUP to reload from DB)

Surfaces NOT touched:
  - Neon mtc_log_entries        (append-only Merkle tree)
  - DNS records (_mqc-ca.<domain>, _mqc-cosigner.*) — operator's
                                  responsibility
  - Other hosts' ~/.TPM         — they own their own caches

Reads MERKLE_NEON DSN from ~/.env.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

import psycopg2


def load_dsn():
    env = os.path.expanduser("~/.env")
    if not os.path.exists(env):
        sys.exit(f"error: {env} not found (need MERKLE_NEON= line)")
    with open(env) as f:
        for line in f:
            m = re.match(r"\s*MERKLE_NEON=(.*)\s*$", line)
            if m:
                v = m.group(1).strip()
                if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                    v = v[1:-1]
                return v
    sys.exit(f"error: MERKLE_NEON= not found in {env}")


def main():
    ap = argparse.ArgumentParser(description="Nuke domain state in Neon + local TPM (testing only).")
    ap.add_argument("domain", help="Bare domain (e.g., frflashy.com).  Both <domain> leaf certs and <domain>-ca CA certs are matched.")
    ap.add_argument("--yes", action="store_true", help="Skip confirmation prompt.")
    args = ap.parse_args()

    domain = args.domain.strip().lower()
    if not domain or "/" in domain or " " in domain:
        sys.exit(f"error: invalid domain '{args.domain}'")

    conn = psycopg2.connect(load_dsn())
    cur = conn.cursor()

    # Find affected cert indices.  Subject can be exactly <domain> (leaf)
    # or <domain>-ca (CA).
    cur.execute(
        """SELECT index,
                  certificate->'standalone_certificate'
                              ->'tbs_entry'->>'subject'
           FROM mtc_certificates
           WHERE certificate->'standalone_certificate'
                            ->'tbs_entry'->>'subject' IN (%s, %s)
           ORDER BY index""",
        (domain, f"{domain}-ca"),
    )
    cert_rows = cur.fetchall()
    cert_indices = [r[0] for r in cert_rows]

    # Find affected pubkey rows.
    cur.execute(
        "SELECT idx, key_name FROM mtc_public_keys WHERE key_name = %s OR key_name = %s OR key_name LIKE %s ORDER BY idx",
        (domain, f"{domain}-ca", f"{domain}-%"),
    )
    pubkey_rows = cur.fetchall()

    # Find affected nonce rows.
    cur.execute(
        "SELECT nonce, domain, label, status FROM mtc_enrollment_nonces WHERE domain = %s",
        (domain,),
    )
    nonce_rows = cur.fetchall()

    # Local peer caches matching the cert indices we're about to drop.
    home = os.path.expanduser("~")
    peers_dir = os.path.join(home, ".TPM", "peers")
    affected_peer_dirs = []
    for idx in cert_indices:
        p = os.path.join(peers_dir, str(idx))
        if os.path.isdir(p):
            affected_peer_dirs.append(p)

    # Summary
    print(f"=== nuke-domain {domain} ===")
    print(f"mtc_certificates rows ({len(cert_rows)}):")
    for idx, subj in cert_rows:
        print(f"  index={idx} subject={subj}")
    print(f"mtc_public_keys rows ({len(pubkey_rows)}):")
    for idx, name in pubkey_rows:
        print(f"  idx={idx} key_name={name}")
    print(f"mtc_enrollment_nonces rows ({len(nonce_rows)}):")
    for nonce, d, label, status in nonce_rows:
        print(f"  nonce={nonce[:16]}... domain={d} label={label} status={status}")
    print(f"local peer caches ({len(affected_peer_dirs)}):")
    for p in affected_peer_dirs:
        print(f"  {p}")
    print(f"NOT touching: mtc_log_entries (append-only) — orphan leaf hashes remain.")

    if not (cert_rows or pubkey_rows or nonce_rows or affected_peer_dirs):
        print("nothing to delete; exiting.")
        cur.close()
        conn.close()
        return 0

    if not args.yes:
        ans = input("Proceed with delete? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("aborted.")
            cur.close()
            conn.close()
            return 1

    # Execute
    if cert_indices:
        cur.execute(
            "DELETE FROM mtc_certificates WHERE index = ANY(%s)",
            (cert_indices,),
        )
        print(f"deleted {cur.rowcount} mtc_certificates rows")
    if pubkey_rows:
        cur.execute(
            "DELETE FROM mtc_public_keys WHERE key_name = %s OR key_name = %s OR key_name LIKE %s",
            (domain, f"{domain}-ca", f"{domain}-%"),
        )
        print(f"deleted {cur.rowcount} mtc_public_keys rows")
    if nonce_rows:
        cur.execute(
            "DELETE FROM mtc_enrollment_nonces WHERE domain = %s",
            (domain,),
        )
        print(f"deleted {cur.rowcount} mtc_enrollment_nonces rows")

    conn.commit()
    cur.close()
    conn.close()

    for p in affected_peer_dirs:
        shutil.rmtree(p, ignore_errors=True)
        print(f"removed {p}")

    # SIGHUP the running server so its in-memory state reloads from DB.
    rc = subprocess.call(["sudo", "systemctl", "kill", "-s", "HUP", "mtc-ca.service"])
    if rc == 0:
        print("SIGHUP sent to mtc-ca.service (in-memory store reloads from DB)")
    else:
        print(f"warning: SIGHUP via systemctl returned rc={rc}; reload manually if needed")

    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
