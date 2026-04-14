#!/usr/bin/env python3
"""
Generate an ML-DSA-87 self-signed X.509 CA certificate for MTC enrollment
via the DH bootstrap port.

Creates the key and certificate files needed by bootstrap_ca:
    ~/.mtc-ca-data/<domain>/private_key.pem
    ~/.mtc-ca-data/<domain>/public_key.pem
    ~/.mtc-ca-data/<domain>/ca_cert.pem

Usage:
    python3 create_ca_cert.py --domain factsorlie.com
    python3 create_ca_cert.py --domain factsorlie.com --days 365
    python3 create_ca_cert.py --domain factsorlie.com --algorithm EC-P256
    python3 create_ca_cert.py --domain factsorlie.com --out /tmp/my-ca
"""

import argparse
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


DEFAULT_OUT = Path.home() / ".mtc-ca-data"
DEFAULT_DAYS = 365
DEFAULT_ALGORITHM = "ML-DSA-87"

OPENSSL = "openssl35"


def check_openssl35():
    """Verify openssl35 is available."""
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


def generate_ca_cert(domain, out_base, days, algorithm):
    """Generate CA key + self-signed CA certificate using openssl35."""
    out_dir = Path(out_base) / domain
    out_dir.mkdir(parents=True, exist_ok=True)

    key_path = out_dir / "private_key.pem"
    pub_path = out_dir / "public_key.pem"
    cert_path = out_dir / "ca_cert.pem"

    algo_map = {
        "ML-DSA-87": "ML-DSA-87",
        "ML-DSA-65": "ML-DSA-65",
        "ML-DSA-44": "ML-DSA-44",
        "EC-P256": "EC",
        "Ed25519": "ED25519",
    }

    ossl_algo = algo_map.get(algorithm, algorithm)

    # --- Generate private key ---
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

    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    # --- Extract public key ---
    print("Extracting public key...")
    cmd = [OPENSSL, "pkey", "-in", str(key_path),
           "-pubout", "-out", str(pub_path)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: public key extraction failed: {result.stderr}",
              file=sys.stderr)
        sys.exit(1)

    # --- Dump human-readable public key details ---
    print("Writing human-readable public key info...")
    pub_txt_path = out_dir / "public_key.txt"
    cmd = [OPENSSL, "pkey", "-pubin", "-in", str(pub_path),
           "-text", "-noout"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        with open(pub_txt_path, "w") as f:
            f.write(result.stdout)
    else:
        print(f"WARNING: could not dump public key text: {result.stderr}",
              file=sys.stderr)

    # (cert_txt_path written below after certificate is generated)

    # --- Create extensions config for CA certificate ---
    ext_conf = tempfile.NamedTemporaryFile(
        mode="w", suffix=".cnf", delete=False)
    ext_conf.write(f"""\
[req]
distinguished_name = dn
req_extensions = v3_ca
x509_extensions = v3_ca
prompt = no

[dn]
CN = {domain} Intermediate CA
O = {domain}

[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:{domain}
""")
    ext_conf.close()

    # --- Generate self-signed CA certificate ---
    print(f"Generating self-signed CA certificate for '{domain}'...")
    cmd = [OPENSSL, "req", "-x509", "-new",
           "-key", str(key_path),
           "-out", str(cert_path),
           "-days", str(days),
           "-config", ext_conf.name]

    result = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(ext_conf.name)

    if result.returncode != 0:
        print(f"ERROR: cert generation failed: {result.stderr}",
              file=sys.stderr)
        sys.exit(1)

    # --- Verify and display ---
    result = subprocess.run(
        [OPENSSL, "x509", "-in", str(cert_path), "-noout",
         "-subject", "-dates", "-text"],
        capture_output=True, text=True)

    # Save human-readable certificate text
    cert_txt_path = out_dir / "ca_cert.txt"
    if result.returncode == 0 and result.stdout:
        with open(cert_txt_path, "w") as f:
            f.write(result.stdout)
        print(f"Writing human-readable certificate info...")

    sig_algo = ""
    is_ca = False
    san_dns = ""
    for line in result.stdout.splitlines():
        line = line.strip()
        if "Signature Algorithm:" in line and not sig_algo:
            sig_algo = line.split(":", 1)[1].strip()
        if "CA:TRUE" in line:
            is_ca = True
        if "DNS:" in line:
            san_dns = line.strip()

    print(f"\nCA certificate created:")
    print(f"  Private key:  {key_path} (mode 0600)")
    print(f"  Public key:   {pub_path}")
    print(f"  Public (txt): {pub_txt_path}")
    print(f"  CA cert:      {cert_path}")
    print(f"  CA cert (txt):{cert_txt_path}")
    print(f"  Algorithm:    {algorithm}")
    if sig_algo:
        print(f"  Signature:    {sig_algo}")
    print(f"  CA:TRUE:      {is_ca}")
    print(f"  SAN:          {san_dns}")
    print(f"  Valid:        {days} days")
    print(f"  pathlen:      0 (intermediate CA — requires DNS validation)")
    print(f"\nTo enroll via bootstrap:")
    print(f"  bootstrap_ca --server HOST:8445 \\")
    print(f"    --domain \"{domain}\" \\")
    print(f"    --public-key {pub_path} \\")
    print(f"    --private-key {key_path} \\")
    print(f"    --ca-cert {cert_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate ML-DSA-87 CA certificate for MTC bootstrap enrollment")
    parser.add_argument("--domain", required=True,
                        help="CA domain name (e.g., factsorlie.com)")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help=f"Base output directory (default: {DEFAULT_OUT})")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS,
                        help=f"Certificate validity in days (default: {DEFAULT_DAYS})")
    parser.add_argument("--algorithm", default=DEFAULT_ALGORITHM,
                        help=f"Key algorithm (default: {DEFAULT_ALGORITHM})")
    args = parser.parse_args()

    check_openssl35()
    generate_ca_cert(args.domain, args.out, args.days, args.algorithm)


if __name__ == "__main__":
    main()
