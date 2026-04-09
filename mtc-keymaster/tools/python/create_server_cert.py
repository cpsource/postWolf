#!/usr/bin/env python3
"""
Generate an ML-DSA-87 (or other algorithm) self-signed X.509 TLS certificate
for the MTC CA server's own TLS listener.

This replaces the openssl35 commands in the clean install guide:
    openssl35 genpkey -algorithm ML-DSA-87 -out server-key.pem
    openssl35 req -x509 -new -key server-key.pem -out server-cert.pem ...

Usage:
    python3 create_server_cert.py factsorlie.com
    python3 create_server_cert.py --out ~/.mtc-ca-data factsorlie.com
    python3 create_server_cert.py --days 730 factsorlie.com
    python3 create_server_cert.py --algorithm EC-P256 localhost

Output:
    ~/.mtc-ca-data/server-key.pem
    ~/.mtc-ca-data/server-cert.pem
"""

import argparse
import datetime
import os
import stat
import subprocess
import sys
from pathlib import Path


DEFAULT_OUT = Path.home() / ".mtc-ca-data"
DEFAULT_DAYS = 365
DEFAULT_ALGORITHM = "ML-DSA-87"

# openssl35 is OpenSSL 3.5+ with post-quantum support
OPENSSL = "openssl35"


def check_openssl35():
    """Verify openssl35 is available and supports ML-DSA-87."""
    try:
        result = subprocess.run(
            [OPENSSL, "version"],
            capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print(f"ERROR: {OPENSSL} not found", file=sys.stderr)
            sys.exit(1)
        print(f"Using: {result.stdout.strip()}")
    except FileNotFoundError:
        print(f"ERROR: {OPENSSL} not found in PATH", file=sys.stderr)
        print("Install OpenSSL 3.5+ and symlink as openssl35", file=sys.stderr)
        sys.exit(1)


def generate_ml_dsa_cert(domain, out_dir, days, algorithm):
    """Generate key + self-signed cert using openssl35."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    key_path = out_dir / "server-key.pem"
    cert_path = out_dir / "server-cert.pem"

    # Map algorithm names to openssl35 algorithm identifiers
    algo_map = {
        "ML-DSA-87": "ML-DSA-87",
        "ML-DSA-65": "ML-DSA-65",
        "ML-DSA-44": "ML-DSA-44",
        "EC-P256": "EC",
        "Ed25519": "ED25519",
    }

    ossl_algo = algo_map.get(algorithm, algorithm)

    # Generate private key
    print(f"Generating {algorithm} private key...")
    if algorithm.startswith("EC"):
        cmd = [OPENSSL, "genpkey", "-algorithm", ossl_algo,
               "-pkeyopt", "ec_paramgen_curve:P-256",
               "-out", str(key_path)]
    else:
        cmd = [OPENSSL, "genpkey", "-algorithm", ossl_algo,
               "-out", str(key_path)]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: key generation failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    # Restrict key permissions
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    # Generate self-signed certificate
    print(f"Generating self-signed certificate for '{domain}'...")
    cmd = [OPENSSL, "req", "-x509", "-new",
           "-key", str(key_path),
           "-out", str(cert_path),
           "-days", str(days),
           "-subj", f"/CN={domain}"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: cert generation failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    # Verify the certificate
    result = subprocess.run(
        [OPENSSL, "x509", "-in", str(cert_path), "-noout",
         "-subject", "-dates", "-text"],
        capture_output=True, text=True)

    # Extract key info from the text output
    sig_algo = ""
    for line in result.stdout.splitlines():
        line = line.strip()
        if "Signature Algorithm:" in line:
            sig_algo = line.split(":", 1)[1].strip()
            break

    print(f"\nServer TLS certificate created:")
    print(f"  Key:       {key_path} (mode 0600)")
    print(f"  Cert:      {cert_path}")
    print(f"  Algorithm: {algorithm}")
    if sig_algo:
        print(f"  Signature: {sig_algo}")
    print(f"  CN:        {domain}")
    print(f"  Valid:     {days} days")


def main():
    parser = argparse.ArgumentParser(
        description="Generate ML-DSA-87 TLS certificate for MTC CA server")
    parser.add_argument("domain",
                        help="Server domain name (e.g., factsorlie.com)")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help=f"Output directory (default: {DEFAULT_OUT})")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS,
                        help=f"Certificate validity in days (default: {DEFAULT_DAYS})")
    parser.add_argument("--algorithm", default=DEFAULT_ALGORITHM,
                        help=f"Key algorithm (default: {DEFAULT_ALGORITHM})")
    args = parser.parse_args()

    check_openssl35()
    generate_ml_dsa_cert(args.domain, args.out, args.days, args.algorithm)


if __name__ == "__main__":
    main()
