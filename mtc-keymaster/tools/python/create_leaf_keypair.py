#!/usr/bin/env python3
"""
Generate a leaf key pair for MTC enrollment via the DH bootstrap port.

Supports EC-P256, Ed25519, and ML-DSA-87 (post-quantum via openssl35).

Creates the key files needed by bootstrap_leaf:
    ~/.mtc-ca-data/<domain>/private_key.pem
    ~/.mtc-ca-data/<domain>/public_key.pem
    ~/.mtc-ca-data/<domain>/public_key.txt

Usage:
    python3 create_leaf_keypair.py --domain my-device.example.com
    python3 create_leaf_keypair.py --domain my-device.example.com --algorithm EC-P256
    python3 create_leaf_keypair.py --domain my-device.example.com --algorithm Ed25519
"""

import argparse
import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path

DEFAULT_OUT = Path.home() / ".mtc-ca-data"
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
        sys.exit(1)


def generate_leaf(domain, out_base, algorithm):
    """Generate leaf keypair using openssl35."""
    out_dir = Path(out_base) / domain
    out_dir.mkdir(parents=True, exist_ok=True)

    key_path = out_dir / "private_key.pem"
    pub_path = out_dir / "public_key.pem"
    pub_txt_path = out_dir / "public_key.txt"

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

    # --- Dump human-readable public key ---
    print("Writing human-readable public key info...")
    cmd = [OPENSSL, "pkey", "-pubin", "-in", str(pub_path),
           "-text", "-noout"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        with open(pub_txt_path, "w") as f:
            f.write(result.stdout)

    # --- Compute fingerprint (SHA-256 of raw PEM text, matching server) ---
    with open(pub_path, "r") as f:
        pub_pem_text = f.read()
    fp = hashlib.sha256(pub_pem_text.encode()).hexdigest()

    print(f"\nLeaf key pair created:")
    print(f"  Private key:  {key_path} (mode 0600)")
    print(f"  Public key:   {pub_path}")
    print(f"  Public (txt): {pub_txt_path}")
    print(f"  Algorithm:    {algorithm}")
    print(f"  Fingerprint:  sha256:{fp}")

    print(f"\nNext steps:")
    print(f"  1. CA operator issues a nonce:")
    print(f"     python3 issue_leaf_nonce.py --domain \"{domain}\" --key-file {pub_path}")
    print(f"")
    print(f"  2. Enroll via bootstrap (after receiving nonce):")
    print(f"     bootstrap_leaf --domain \"{domain}\" --nonce <NONCE>")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a leaf key pair for MTC bootstrap enrollment")
    parser.add_argument("--domain", required=True,
                        help="Leaf domain/subject (e.g., my-device.example.com)")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help=f"Base output directory (default: {DEFAULT_OUT})")
    parser.add_argument("--algorithm", default=DEFAULT_ALGORITHM,
                        help=f"Key algorithm (default: {DEFAULT_ALGORITHM})")
    args = parser.parse_args()

    check_openssl35()
    generate_leaf(args.domain, args.out, args.algorithm)


if __name__ == "__main__":
    main()
