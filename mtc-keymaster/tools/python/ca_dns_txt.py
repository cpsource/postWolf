#!/usr/bin/env python3
"""
Generate the DNS TXT record for MQC CA cosigner-key pinning.

Given the cosigner public-key PEM file (typically
~/.TPM/ca-cosigner.pem), prints the TXT record the domain
owner publishes at _mqc-ca.<domain>.  An MQC client validates
the record via DNSSEC and refuses to trust any cosigner PEM
whose SHA3-256 doesn't match the published `kh` value.

The record format matches what
socket-level-wrapper-MQC/mqc_dnssec_pin.c parses:

    v=MQC1; role=ca; alg=ML-DSA-87; kh=sha3-256:<64-hex>

Hashes the *raw bytes of the PEM file*, not the SPKI DER —
this is what the probe does, so the two must agree.

DNSSEC is mandatory for the publish-side too: the zone holding
_mqc-ca.<domain> MUST have a DS record at its parent and a
signed RRSIG on the TXT, otherwise the probe will refuse with
"DNSSEC insecure or unsigned".  Publish the TXT as a single
character-string when possible; the probe also handles the
case where the resolver returns multiple TXT RRs at the same
name.

Usage:
    python3 ca_dns_txt.py --domain factsorlie.com \\
        ~/.TPM/ca-cosigner.pem
    python3 ca_dns_txt.py --domain factsorlie.com --check \\
        ~/.TPM/ca-cosigner.pem

Output:
    _mqc-ca.factsorlie.com.  IN TXT  "v=MQC1; role=ca; ..."
"""

import argparse
import hashlib
import subprocess
import sys


VERSION_TAG = "MQC1"
ROLE_TAG = "ca"
ALG_TAG = "ML-DSA-87"
HASH_TAG = "sha3-256"


def sha3_256_file_hex(path: str) -> str:
    """SHA3-256 over the raw bytes of the file, lowercase hex."""
    h = hashlib.sha3_256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_txt_fields(txt: str) -> dict:
    """Parse a TXT value into a dict of `key=value` fields, joining
    multiple character-strings the resolver returned with `;` as the
    record separator (matches mqc_dnssec_pin's join logic)."""
    fields = {}
    for part in txt.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip()] = v.strip()
    return fields


def check_dns_txt(domain: str, expected_hash: str) -> tuple[bool, str]:
    """
    Query DNS for _mqc-ca.<domain> TXT.  Walks every RR returned (the
    name can hold multiple RRs, and the probe concatenates them) and
    accepts when any v=MQC1 entry has kh=sha3-256:<expected_hash>.
    Returns (matched, detail).

    Note: this does NOT validate DNSSEC — it just compares the value.
    Run the C probe (tests/mqc_dnssec_pin) for a full DNSSEC-aware
    check.
    """
    qname = f"_mqc-ca.{domain}"
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

    # Concatenate every RR-line's strings the way the probe does.
    pieces = []
    for line in raw.splitlines():
        # dig +short prints one line per RR, each line a sequence of
        # quoted character-strings.  Strip the quotes per piece.
        pieces.append(" ".join(s.strip('"') for s in line.split('" "')))
    joined = ";".join(pieces)
    fields = parse_txt_fields(joined)

    if fields.get("v", "") != VERSION_TAG:
        return False, (f"TXT at {qname} has no v={VERSION_TAG} "
                       f"(found: {fields.get('v', '<missing>')})")
    kh = fields.get("kh", "")
    prefix = f"{HASH_TAG}:"
    if not kh.startswith(prefix):
        return False, f"TXT at {qname} has no kh={prefix}<hex>"
    actual = kh[len(prefix):].lower()
    if actual == expected_hash:
        return True, f"MATCH at {qname}"
    return False, (f"TXT at {qname}: kh={actual[:16]}... "
                   f"!= expected {expected_hash[:16]}...")


def main():
    parser = argparse.ArgumentParser(
        description="Generate the MQC cosigner-pin DNS TXT record")
    parser.add_argument("pem",
                        help="Path to the cosigner public-key PEM "
                             "(e.g., ~/.TPM/ca-cosigner.pem)")
    parser.add_argument("--domain", required=True,
                        help="Domain to publish under "
                             "(_mqc-ca.<domain>)")
    parser.add_argument("--check", action="store_true",
                        help="Query DNS and verify the published TXT "
                             "matches the local PEM (does NOT verify "
                             "DNSSEC — use tests/mqc_dnssec_pin for "
                             "the full chain check)")
    args = parser.parse_args()

    fp = sha3_256_file_hex(args.pem)
    print(f"PEM file:           {args.pem}")
    print(f"Domain:             {args.domain}")
    print(f"PEM SHA3-256:       {fp}")
    print()

    record_name = f"_mqc-ca.{args.domain}."
    record_value = (f"v={VERSION_TAG}; role={ROLE_TAG}; "
                    f"alg={ALG_TAG}; kh={HASH_TAG}:{fp}")
    print("Required DNS TXT record:")
    print()
    print(f"  {record_name}  IN TXT  \"{record_value}\"")
    print()
    print("Token fields:")
    print(f"  v     — version ({VERSION_TAG})")
    print(f"  role  — record role ({ROLE_TAG})")
    print(f"  alg   — signing algorithm of the pinned key "
          f"({ALG_TAG})")
    print(f"  kh    — SHA3-256 of the cosigner PEM file bytes "
          "(matches what the probe hashes)")
    print()

    if args.check:
        matched, detail = check_dns_txt(args.domain, fp)
        print("DNS Verification (value-only, no DNSSEC):")
        status = "PASS" if matched else "FAIL"
        print(f"  [{status}] {args.domain} — {detail}")
        print()
        if not matched:
            print("RESULT: REJECTED — DNS value mismatch")
            sys.exit(1)
        print("RESULT: ACCEPTED — DNS value matches")
        print("To verify the full DNSSEC chain, run:")
        print(f"  socket-level-wrapper-MQC/tests/mqc_dnssec_pin "
              f"{args.domain} {args.pem}")
    else:
        print("Verify with:")
        print(f"  dig TXT _mqc-ca.{args.domain}")
        print()
        print("Or run this tool with --check to compare values, ")
        print("or run socket-level-wrapper-MQC/tests/mqc_dnssec_pin")
        print("for the full DNSSEC-validated check.")


if __name__ == "__main__":
    main()
