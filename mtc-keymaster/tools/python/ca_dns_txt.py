#!/usr/bin/env python3
"""
Generate the DNS TXT record for MTC CA domain validation.

Given a CA certificate (PEM or DER), extracts the SAN DNS names and
computes the public key fingerprint, then prints the exact TXT record
the domain owner needs to add to their DNS.

Usage:
    python3 ca_dns_txt.py ~/masterKey/factsorlieCA.crt
    python3 ca_dns_txt.py --domain factsorlie.com ~/masterKey/factsorlieCA.crt

Output:
    _mtc-ca.factsorlie.com.  IN TXT  "v=mtc-ca1; fp=sha256:a1b2c3d4..."
"""

import argparse
import hashlib
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID


def load_cert(path: str) -> x509.Certificate:
    """Load a certificate from PEM or DER file."""
    with open(path, "rb") as f:
        data = f.read()

    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def get_san_dns_names(cert: x509.Certificate) -> list[str]:
    """Extract DNS names from Subject Alternative Name extension."""
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def is_ca(cert: x509.Certificate) -> tuple[bool, int | None]:
    """Check Basic Constraints. Returns (is_ca, pathlen)."""
    try:
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS)
        return bc.value.ca, bc.value.path_length
    except x509.ExtensionNotFound:
        return False, None


def public_key_fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 fingerprint of the public key (DER-encoded SPKI)."""
    pub_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pub_der).hexdigest()


def check_dns_txt(domain: str, expected_fp: str) -> tuple[bool, str]:
    """
    Query DNS for _mtc-ca.<domain> TXT record and check fingerprint.

    Returns (matched, detail).
    """
    qname = f"_mtc-ca.{domain}"
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", qname],
            capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return False, "dig command not found"
    except subprocess.TimeoutExpired:
        return False, "DNS query timed out"

    if result.returncode != 0:
        return False, f"dig failed: {result.stderr.strip()}"

    raw = result.stdout.strip()
    if not raw:
        return False, f"no TXT record found at {qname}"

    # dig returns lines like: "v=mtc-ca1; fp=sha256:abc123..."
    expected_value = f"v=mtc-ca1; fp=sha256:{expected_fp}"
    for line in raw.splitlines():
        # Strip surrounding quotes from dig output
        txt = line.strip().strip('"')
        if txt == expected_value:
            return True, f"MATCH at {qname}"

    return False, f"TXT record found but no matching fingerprint at {qname}"


def main():
    parser = argparse.ArgumentParser(
        description="Generate and verify DNS TXT record for MTC CA domain validation")
    parser.add_argument("cert", help="Path to CA certificate (PEM or DER)")
    parser.add_argument("--domain", default=None,
                        help="Override domain (default: from SAN)")
    parser.add_argument("--check", action="store_true",
                        help="Query DNS and verify the TXT record exists")
    args = parser.parse_args()

    cert = load_cert(args.cert)

    # Verify it's a CA
    ca, pathlen = is_ca(cert)
    if not ca:
        print("ERROR: Certificate does not have CA:TRUE in Basic Constraints",
              file=sys.stderr)
        sys.exit(1)

    print(f"Subject:           {cert.subject.rfc4514_string()}")
    print(f"Basic Constraints: CA:TRUE, pathlen:{pathlen}")

    # Get domains
    dns_names = get_san_dns_names(cert)
    if args.domain:
        domains = [args.domain]
    elif dns_names:
        domains = dns_names
    else:
        # Fall back to CN
        cns = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cns:
            domains = [cns[0].value]
        else:
            print("ERROR: No SAN DNS names or CN found, use --domain",
                  file=sys.stderr)
            sys.exit(1)

    fp = public_key_fingerprint(cert)
    print(f"Public key SHA-256: {fp}")
    print()

    # Output DNS records
    print("Required DNS TXT record(s):")
    print()
    for domain in domains:
        record_name = f"_mtc-ca.{domain}."
        record_value = f"v=mtc-ca1; fp=sha256:{fp}"
        print(f"  {record_name}  IN TXT  \"{record_value}\"")
    print()

    # Check DNS if requested
    if args.check:
        print("DNS Verification:")
        all_ok = True
        for domain in domains:
            matched, detail = check_dns_txt(domain, fp)
            status = "PASS" if matched else "FAIL"
            print(f"  [{status}] {domain} — {detail}")
            if not matched:
                all_ok = False
        print()
        if not all_ok:
            print("RESULT: REJECTED — DNS validation failed")
            sys.exit(1)
        else:
            print("RESULT: ACCEPTED — DNS validation passed")
    else:
        print("Verify with:")
        for domain in domains:
            print(f"  dig TXT _mtc-ca.{domain}")
        print()
        print("Or run this tool with --check to verify automatically")


if __name__ == "__main__":
    main()
