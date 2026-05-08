#!/usr/bin/env python3
"""
Generate a leaf key pair for MTC enrollment via the DH bootstrap port.

Supports EC-P256, Ed25519, and ML-DSA-87 (post-quantum via openssl40).

Both --domain and --label are required: every leaf identity gets its
own per-label directory, so two labeled enrollments under the same
subject cannot accidentally share a private key.  bootstrap_leaf
must be invoked with the same --label to find this key.

Creates the key files needed by bootstrap_leaf:
    ~/.mtc-ca-data/<domain>-<label>/private_key.pem
    ~/.mtc-ca-data/<domain>-<label>/public_key.pem
    ~/.mtc-ca-data/<domain>-<label>/public_key.txt

Usage:
    python3 create_leaf_keypair.py --domain my-device.example.com --label Alice
    python3 create_leaf_keypair.py --domain my-device.example.com --label main --algorithm EC-P256
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

OPENSSL = "openssl40"


def check_openssl40():
    """Verify openssl40 is available."""
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


LABEL_RE = __import__("re").compile(r"^[A-Za-z0-9._-]{1,64}$")


def validate_label(label):
    """Match the bootstrap_leaf / issue_leaf_nonce sanitize_label charset."""
    if not LABEL_RE.match(label):
        print(f"ERROR: --label must be 1..64 chars, [A-Za-z0-9._-] only",
              file=sys.stderr)
        sys.exit(1)
    return label


def generate_leaf(domain, out_base, algorithm, label):
    """Generate leaf keypair using openssl40."""
    out_dir = Path(out_base) / f"{domain}-{label}"
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
    print(f"     issue_leaf_nonce --domain \"{domain}\" --label {label} --key-file {pub_path}")
    print(f"")
    print(f"  2. Enroll via bootstrap (after receiving nonce):")
    print(f"     bootstrap_leaf --domain \"{domain}\" --label {label} --nonce <NONCE>")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a leaf key pair for MTC bootstrap enrollment")
    parser.add_argument("--domain", required=True,
                        help="Leaf domain/subject (e.g., my-device.example.com)")
    parser.add_argument("--label", required=True,
                        help="Per-identity label (1..64 chars, [A-Za-z0-9._-]). "
                             "Output dir is <domain>-<label>; bootstrap_leaf "
                             "must be run with the same --label to find this key.")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help=f"Base output directory (default: {DEFAULT_OUT})")
    parser.add_argument("--algorithm", default=DEFAULT_ALGORITHM,
                        help=f"Key algorithm (default: {DEFAULT_ALGORITHM})")
    args = parser.parse_args()

    label = validate_label(args.label)
    check_openssl40()
    generate_leaf(args.domain, args.out, args.algorithm, label)


if __name__ == "__main__":
    main()
