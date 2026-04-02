#!/usr/bin/env python3
"""
MTC Certificate Renewal Tool.

Scans local ~/.TPM certificates and (optionally) the Neon PostgreSQL
database for MTC certificates approaching expiry, then re-enrolls them
through the MTC CA server.

Designed to run from cron:
    0 3 * * * /path/to/renew.py --config /path/to/renew.conf

Exit codes:
    0 — all certificates OK or renewed successfully
    1 — one or more renewals failed
    2 — configuration / startup error
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Allow importing mtc_client from the tools directory
TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools" / "python"
if TOOLS_DIR.is_dir():
    sys.path.insert(0, str(TOOLS_DIR))

from config import RenewConfig

log = logging.getLogger("mtc-renew")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class CertInfo:
    """A certificate that may need renewal."""

    def __init__(self, subject: str, index: int, not_before: float,
                 not_after: float, source: str, tpm_path: Path | None = None,
                 public_key_pem: str | None = None,
                 key_algorithm: str = "EC-P256",
                 extensions: dict | None = None):
        self.subject = subject
        self.index = index
        self.not_before = not_before
        self.not_after = not_after
        self.source = source          # "tpm" or "neon"
        self.tpm_path = tpm_path      # ~/.TPM/<subject>/ directory
        self.public_key_pem = public_key_pem
        self.key_algorithm = key_algorithm
        self.extensions = extensions or {}

    @property
    def days_remaining(self) -> float:
        return (self.not_after - time.time()) / 86400

    @property
    def expired(self) -> bool:
        return time.time() > self.not_after

    def __repr__(self):
        return (f"CertInfo(subject={self.subject!r}, index={self.index}, "
                f"days_remaining={self.days_remaining:.1f}, source={self.source})")


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_tpm(tpm_dir: Path) -> list[CertInfo]:
    """Scan ~/.TPM for certificates and their expiry times."""
    certs = []
    if not tpm_dir.exists():
        log.warning("TPM directory %s does not exist", tpm_dir)
        return certs

    for subdir in sorted(tpm_dir.iterdir()):
        if not subdir.is_dir():
            continue

        cert_file = subdir / "certificate.json"
        if not cert_file.exists():
            continue

        try:
            with open(cert_file) as f:
                data = json.load(f)

            sc = data.get("standalone_certificate", data)
            tbs = sc["tbs_entry"]

            pub_pem = None
            pub_path = subdir / "public_key.pem"
            if pub_path.exists():
                pub_pem = pub_path.read_text()

            ci = CertInfo(
                subject=tbs["subject"],
                index=sc["index"],
                not_before=tbs["not_before"],
                not_after=tbs["not_after"],
                source="tpm",
                tpm_path=subdir,
                public_key_pem=pub_pem,
                key_algorithm=tbs.get("subject_public_key_algorithm", "EC-P256"),
                extensions=tbs.get("extensions", {}),
            )
            certs.append(ci)
            log.debug("TPM cert: %s", ci)

        except (json.JSONDecodeError, KeyError) as e:
            log.warning("Skipping %s: %s", cert_file, e)

    return certs


def scan_neon(conn_string: str) -> list[CertInfo]:
    """Scan the Neon database for certificates and their expiry times."""
    certs = []
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        log.error("psycopg2 not installed — cannot scan Neon database")
        return certs

    try:
        conn = psycopg2.connect(conn_string)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT index, certificate
                FROM mtc_certificates
                ORDER BY index
            """)
            for row in cur.fetchall():
                try:
                    cert = row["certificate"]
                    sc = cert.get("standalone_certificate", cert)
                    tbs = sc["tbs_entry"]
                    ci = CertInfo(
                        subject=tbs["subject"],
                        index=row["index"],
                        not_before=tbs["not_before"],
                        not_after=tbs["not_after"],
                        source="neon",
                        key_algorithm=tbs.get("subject_public_key_algorithm",
                                              "EC-P256"),
                        extensions=tbs.get("extensions", {}),
                    )
                    certs.append(ci)
                except KeyError as e:
                    log.warning("Skipping Neon cert index %s: %s",
                                row["index"], e)
        conn.close()
    except Exception as e:
        log.error("Neon scan failed: %s", e)

    return certs


def is_revoked(server: str, index: int) -> bool:
    """Check if a single certificate is revoked via the CA server."""
    url = f"{server.rstrip('/')}/revoked/{index}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
        return bool(data.get("revoked", False))
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.warning("Could not check revocation for index #%d: %s", index, e)
        return False


def find_certs_to_renew(certs: list[CertInfo], renew_days: int,
                        server: str) -> list[CertInfo]:
    """Filter to certificates within the renewal window, excluding revoked."""
    threshold = time.time() + (renew_days * 86400)
    to_renew = []
    for ci in certs:
        if ci.not_after <= threshold:
            if is_revoked(server, ci.index):
                log.info("REVOKED: %s (index #%d) — skipping",
                         ci.subject, ci.index)
                continue
            to_renew.append(ci)
            if ci.expired:
                log.warning("EXPIRED: %s (index #%d) expired %.1f days ago",
                            ci.subject, ci.index, -ci.days_remaining)
            else:
                log.info("RENEW: %s (index #%d) expires in %.1f days",
                         ci.subject, ci.index, ci.days_remaining)
        else:
            log.debug("OK: %s (index #%d) expires in %.1f days",
                      ci.subject, ci.index, ci.days_remaining)
    return to_renew


# ---------------------------------------------------------------------------
# Renewal
# ---------------------------------------------------------------------------

def _ca_post(server: str, path: str, data: dict) -> dict:
    """POST JSON to the MTC CA server."""
    url = f"{server.rstrip('/')}{path}"
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def generate_key_pair(algorithm: str = "EC-P256") -> tuple[str, str]:
    """Generate a new key pair. Returns (private_pem, public_pem)."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives import serialization

    if algorithm == "EC-P256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif algorithm == "Ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"unsupported algorithm: {algorithm}")

    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return priv_pem, pub_pem


def run_hook(hook_cmd: str, subject: str, index: int) -> bool:
    """Run a shell hook command. Returns True on success."""
    if not hook_cmd:
        return True
    env = os.environ.copy()
    env["MTC_SUBJECT"] = subject
    env["MTC_INDEX"] = str(index)
    try:
        subprocess.run(hook_cmd, shell=True, check=True, env=env,
                       timeout=60)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log.error("Hook failed: %s — %s", hook_cmd, e)
        return False


def renew_cert(ci: CertInfo, cfg: RenewConfig) -> bool:
    """
    Renew a single certificate.

    1. Run pre-renew hook
    2. Optionally generate fresh keys
    3. POST /certificate/request to CA server
    4. Update ~/.TPM/<subject>/ with new cert, index, and keys
    5. Run post-renew hook
    """
    log.info("Renewing: %s (index #%d, %.1f days remaining)",
             ci.subject, ci.index, ci.days_remaining)

    if cfg.dry_run:
        log.info("  [dry-run] Would renew %s", ci.subject)
        return True

    # Pre-hook
    if not run_hook(cfg.pre_renew_hook, ci.subject, ci.index):
        log.error("  Pre-renew hook failed for %s, skipping", ci.subject)
        return False

    # Key handling
    pub_pem = ci.public_key_pem
    priv_pem = None
    algo = ci.key_algorithm

    if cfg.rotate_keys or pub_pem is None:
        algo = cfg.key_algorithm if cfg.rotate_keys else algo
        log.info("  Generating fresh %s key pair", algo)
        priv_pem, pub_pem = generate_key_pair(algo)
    else:
        log.info("  Reusing existing public key")

    # Request new certificate from CA server
    try:
        result = _ca_post(cfg.server, "/certificate/request", {
            "subject": ci.subject,
            "public_key_pem": pub_pem,
            "key_algorithm": algo,
            "validity_days": cfg.validity_days,
            "extensions": ci.extensions,
        })
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.error("  CA request failed for %s: %s", ci.subject, e)
        run_hook(cfg.on_error_hook, ci.subject, ci.index)
        return False

    new_index = result["index"]
    log.info("  New certificate issued: index #%d", new_index)

    # Update ~/.TPM/<subject>/
    if ci.tpm_path:
        tpm_dir = ci.tpm_path
    else:
        safe = ci.subject.replace("/", "_").replace(":", "_")
        tpm_dir = cfg.tpm_dir / safe
    tpm_dir.mkdir(parents=True, exist_ok=True)

    # Write new certificate
    cert_path = tpm_dir / "certificate.json"
    with open(cert_path, "w") as f:
        json.dump(result, f, indent=2)

    # Update index
    (tpm_dir / "index").write_text(str(new_index))

    # Write new keys if rotated
    if priv_pem:
        key_path = tpm_dir / "private_key.pem"
        key_path.write_text(priv_pem)
        os.chmod(key_path, 0o600)

        pub_path = tpm_dir / "public_key.pem"
        pub_path.write_text(pub_pem)

    log.info("  Updated %s", tpm_dir)

    # Post-hook
    if not run_hook(cfg.post_renew_hook, ci.subject, new_index):
        log.warning("  Post-renew hook failed for %s", ci.subject)

    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def setup_logging(cfg: RenewConfig):
    """Configure logging from config."""
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    handlers = [logging.StreamHandler()]

    if cfg.log_file:
        handlers.append(logging.FileHandler(cfg.log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


def run(cfg: RenewConfig) -> int:
    """
    Run the full renewal cycle.

    Returns 0 if all OK, 1 if any renewal failed.
    """
    # 1. Scan ~/.TPM
    log.info("Scanning %s for MTC certificates...", cfg.tpm_dir)
    certs = scan_tpm(cfg.tpm_dir)
    log.info("Found %d certificate(s) in %s", len(certs), cfg.tpm_dir)

    # 2. Optionally scan Neon
    if cfg.neon_enabled:
        conn_str = cfg.neon_connection_string
        if conn_str:
            log.info("Scanning Neon database for additional certificates...")
            neon_certs = scan_neon(conn_str)
            # Deduplicate: keep TPM version if both exist (TPM has keys)
            tpm_subjects = {c.subject for c in certs}
            new_from_neon = [c for c in neon_certs
                            if c.subject not in tpm_subjects]
            log.info("Found %d additional certificate(s) in Neon "
                     "(%d total in DB, %d already in TPM)",
                     len(new_from_neon), len(neon_certs),
                     len(neon_certs) - len(new_from_neon))
            certs.extend(new_from_neon)
        else:
            log.warning("Neon enabled but no connection string found")

    if not certs:
        log.info("No certificates to check")
        return 0

    # 3. Find certs within renewal window (checks revocation per-cert)
    to_renew = find_certs_to_renew(certs, cfg.renew_days_before, cfg.server)

    if not to_renew:
        log.info("All %d certificate(s) are current — nothing to renew",
                 len(certs))
        return 0

    log.info("%d certificate(s) need renewal", len(to_renew))

    if cfg.dry_run:
        log.info("[dry-run] Would renew the following:")
        for ci in to_renew:
            status = "EXPIRED" if ci.expired else f"{ci.days_remaining:.1f}d left"
            log.info("  %s (index #%d) — %s", ci.subject, ci.index, status)
        return 0

    # 5. Renew each
    failures = 0
    for ci in to_renew:
        if not renew_cert(ci, cfg):
            failures += 1

    # 5. Summary
    renewed = len(to_renew) - failures
    log.info("Renewal complete: %d renewed, %d failed, %d total checked",
             renewed, failures, len(certs))

    return 1 if failures > 0 else 0


def main():
    parser = argparse.ArgumentParser(
        description="MTC Certificate Renewal Tool",
        epilog="Designed for cron: 0 3 * * * %(prog)s --config /path/to/renew.conf",
    )
    parser.add_argument("-c", "--config", default=None,
                        help="Path to renew.conf (default: renew.conf next to this script)")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="Check expiry without renewing")
    parser.add_argument("--server", default=None,
                        help="Override CA server hostname (default: localhost)")
    parser.add_argument("--port", type=int, default=None,
                        help="Override CA server port (default: 8443)")
    parser.add_argument("--days", type=int, default=None,
                        help="Override renew_days_before threshold")
    parser.add_argument("--rotate-keys", action="store_true",
                        help="Force key rotation on renewal")
    parser.add_argument("--neon", action="store_true",
                        help="Also scan Neon database")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose (DEBUG) logging")
    args = parser.parse_args()

    cfg = RenewConfig(args.config)

    # CLI overrides
    if args.dry_run:
        cfg._cp.set("renewal", "dry_run", "true")
    if args.server or args.port:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(cfg.server)
        host = args.server if args.server else parsed.hostname
        port = args.port if args.port else (parsed.port or 8443)
        cfg._cp.set("renewal", "server",
                     urlunparse((parsed.scheme, f"{host}:{port}", "", "", "", "")))
    if args.days is not None:
        cfg._cp.set("renewal", "renew_days_before", str(args.days))
    if args.rotate_keys:
        cfg._cp.set("renewal", "rotate_keys", "true")
    if args.neon:
        cfg._cp.set("neon", "enabled", "true")
    if args.verbose:
        cfg._cp.set("logging", "level", "DEBUG")

    setup_logging(cfg)

    try:
        sys.exit(run(cfg))
    except Exception as e:
        log.error("Fatal error: %s", e, exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
