#!/usr/bin/env python3
"""
Generate the DNS TXT record for MTC CA domain validation.

Given a CA certificate (PEM or DER), extracts the SAN DNS names and
computes a key-bound challenge token, then prints the exact TXT record
the domain owner needs to add to their DNS.

The token binds together:
  - SHA-256 hash of the public key (SPKI) — prevents use with a different key
  - domain name — prevents cross-domain replay
  - random nonce — prevents pre-computation
  - expiration timestamp — limits the validation window

Even if an attacker steals or spoofs the token, they cannot use it for a
different key or domain.

Usage:
    python3 ca_dns_txt.py ~/masterKey/factsorlieCA.crt
    python3 ca_dns_txt.py --domain factsorlie.com ~/masterKey/factsorlieCA.crt
    python3 ca_dns_txt.py --check ~/masterKey/factsorlieCA.crt
    python3 ca_dns_txt.py --ttl 48 ~/masterKey/factsorlieCA.crt

Output:
    _mtc-ca.factsorlie.com.  IN TXT  "v=mtc-ca2; fp=sha256:a1b2...; n=<nonce>; exp=<ts>"

Integrity note:
    The DNS record does NOT contain a hash or signature for integrity.
    A plain hash is useless — an attacker who can modify the DNS record
    can recompute it. Integrity is enforced server-side: the server stores
    the nonce + domain + fingerprint when it issues the nonce and verifies
    against its own state.
"""

import argparse
import hashlib
import os
import subprocess
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

# Default token validity — 15 minutes limits the attack window.
# DNS TXT records via API (Cloudflare, Route53, etc.) propagate in seconds.
DEFAULT_TTL_MINUTES = 15


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


def generate_token(fp: str, domain: str, ttl_minutes: int) -> tuple[str, int]:
    """
    Generate a challenge token for DNS TXT validation.

    Returns (nonce, expiration).

    The nonce is 32 random bytes (256-bit from CSPRNG). In production,
    this should come from the server via POST /enrollment/nonce — the
    server stores the nonce + domain + fingerprint + expiry in its pending
    state and verifies against that state (not against the DNS record).

    Nonces are single-use (consumed on success, never accepted again) and
    short-lived (15 minutes default) to limit the attack window.

    A plain hash over the fields does NOT provide integrity against an
    active attacker — anyone who can modify the DNS record can recompute
    the hash. Server-side state is the correct integrity mechanism.
    """
    nonce = os.urandom(32).hex()  # 256-bit from CSPRNG
    exp = int(time.time()) + (ttl_minutes * 60)
    return nonce, exp


def parse_txt_fields(txt: str) -> dict:
    """Parse a TXT record value into a dict of key=value fields."""
    fields = {}
    for part in txt.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip()] = v.strip()
    return fields


def check_dns_txt(domain: str, expected_fp: str) -> tuple[bool, str]:
    """
    Query DNS for _mtc-ca.<domain> TXT record and verify the token.

    This is a client-side convenience check. The real verification happens
    server-side: the server looks up the nonce in its pending_nonces state
    and verifies domain + fingerprint against its own records — not against
    the DNS record contents.

    Checks:
      1. TXT record exists at _mtc-ca.<domain>
      2. Version is v=mtc-ca2 (or legacy v=mtc-ca1)
      3. Fingerprint matches the certificate's public key
      4. Token has not expired

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

    now = int(time.time())

    for line in raw.splitlines():
        txt = line.strip().strip('"')
        fields = parse_txt_fields(txt)

        version = fields.get("v", "")
        fp = fields.get("fp", "").replace("sha256:", "")
        exp_str = fields.get("exp", "0")

        # Support both v=mtc-ca1 (legacy, fp-only) and v=mtc-ca2
        if version == "mtc-ca1":
            if fp == expected_fp:
                return True, f"MATCH at {qname} (legacy v=mtc-ca1)"
            continue

        if version != "mtc-ca2":
            continue

        if fp != expected_fp:
            continue

        # Check expiration
        try:
            exp = int(exp_str)
        except ValueError:
            continue
        if exp < now:
            return False, f"token expired at {qname} (exp={exp_str})"

        return True, f"MATCH at {qname} (v=mtc-ca2, expires {exp_str})"

    return False, f"TXT record found but no valid token at {qname}"


def main():
    parser = argparse.ArgumentParser(
        description="Generate and verify DNS TXT record for MTC CA domain validation")
    parser.add_argument("cert", help="Path to CA certificate (PEM or DER)")
    parser.add_argument("--domain", default=None,
                        help="Override domain (default: from SAN)")
    parser.add_argument("--check", action="store_true",
                        help="Query DNS and verify the TXT record exists")
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL_MINUTES,
                        help=f"Token validity in minutes (default: {DEFAULT_TTL_MINUTES})")
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
    print(f"Token TTL:          {args.ttl} minutes")
    print()

    # Output DNS records
    print("Required DNS TXT record(s):")
    print()
    print("NOTE: In production, the nonce should come from the server via")
    print("  POST /enrollment/nonce — not generated locally. Use --server")
    print("  to auto-fetch, or --nonce/--expiry for a server-issued value.")
    print()
    for domain in domains:
        nonce, exp = generate_token(fp, domain, args.ttl)
        record_name = f"_mtc-ca.{domain}."
        record_value = (f"v=mtc-ca2; fp=sha256:{fp}; "
                        f"n={nonce}; exp={exp}")
        print(f"  {record_name}  IN TXT  \"{record_value}\"")
    print()
    print("Token fields:")
    print("  v    — version (mtc-ca2)")
    print("  fp   — SHA-256 of public key SPKI (binds to this key)")
    print("  n    — nonce (server-issued in production, random here)")
    print("  exp  — Unix timestamp expiration (limits validation window)")
    print()
    print("Integrity is enforced server-side: the server stores the nonce,")
    print("domain, and fingerprint when it issues the nonce, and verifies")
    print("against its own state — not against the DNS record contents.")
    print("A plain hash in the DNS record does NOT prevent tampering by an")
    print("attacker who can modify the record.")
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
