#!/usr/bin/env python3
"""
Generate an EC-P256 leaf key pair and self-contained certificate files
for use with MTC/TLS 1.3, without contacting the CA server.

The certificate can be enrolled later via:
    python3 main.py enroll <subject>

Usage:
    python3 create_leaf_cert.py factsorlie.com
    python3 create_leaf_cert.py --algorithm Ed25519 mydevice.local
    python3 create_leaf_cert.py --out /tmp/keys factsorlie.com
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.hashes import SHA256
import datetime

TPM_DIR = Path.home() / ".TPM"


def generate_key_pair(algorithm: str = "EC-P256"):
    """Generate a key pair. Returns (private_key, priv_pem, pub_pem)."""
    if algorithm == "EC-P256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif algorithm == "Ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        print(f"ERROR: unsupported algorithm: {algorithm}", file=sys.stderr)
        sys.exit(1)

    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return private_key, priv_pem, pub_pem


def create_self_signed_cert(private_key, subject: str, validity_days: int):
    """Create a minimal self-signed X.509 leaf certificate."""
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(subject)]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        cert = builder.sign(private_key, algorithm=None)
    else:
        cert = builder.sign(private_key, algorithm=SHA256())

    return cert


def main():
    parser = argparse.ArgumentParser(
        description="Generate a leaf key pair and certificate for MTC/TLS 1.3")
    parser.add_argument("subject", help="Certificate subject / DNS name")
    parser.add_argument("--algorithm", default="EC-P256",
                        choices=["EC-P256", "Ed25519"],
                        help="Key algorithm (default: EC-P256)")
    parser.add_argument("--days", type=int, default=90,
                        help="Validity period in days (default: 90)")
    parser.add_argument("--out", default=None,
                        help="Output directory (default: ~/.TPM/<subject>)")
    args = parser.parse_args()

    # Generate key pair
    private_key, priv_pem, pub_pem = generate_key_pair(args.algorithm)

    # Compute fingerprint
    pub_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(pub_der).hexdigest()

    # Create self-signed certificate
    cert = create_self_signed_cert(private_key, args.subject, args.days)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    # Output directory
    if args.out:
        out_dir = Path(args.out)
    else:
        safe = args.subject.replace("/", "_").replace(":", "_")
        out_dir = TPM_DIR / safe
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write files
    key_path = out_dir / "private_key.pem"
    key_path.write_text(priv_pem)
    os.chmod(key_path, 0o600)

    pub_path = out_dir / "public_key.pem"
    pub_path.write_text(pub_pem)

    cert_path = out_dir / "leaf_cert.pem"
    cert_path.write_text(cert_pem)

    print(f"Subject:     {args.subject}")
    print(f"Algorithm:   {args.algorithm}")
    print(f"Validity:    {args.days} days")
    print(f"Fingerprint: sha256:{fp}")
    print()
    print(f"  Private key:   {key_path}")
    print(f"  Public key:    {pub_path}")
    print(f"  Certificate:   {cert_path}")
    print()
    print(f"To enroll with MTC CA server:")
    print(f"  python3 main.py enroll {args.subject}")


if __name__ == "__main__":
    main()
