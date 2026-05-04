#!/usr/bin/env python3
"""
Generate the DNS TXT record(s) the operator publishes at
_mqc-ca.<domain>.  Two input modes — both emit the same wire
format; the difference is what bytes get hashed:

  PEM-FILE mode (positional `pem` arg):
      python3 ca_dns_txt.py --domain factsorlie.com \\
          ~/.TPM/ca-cosigner.pem

      Hashes the *raw bytes of the file* with SHA3-256.  Used for
      MQC log-cosigner pinning — the probe at
      socket-level-wrapper-MQC/tests/mqc_dnssec_pin hashes the
      same file the same way (today; tracked TODO #53 in
      mtc-keymaster/README-bugsandtodo.md to move both sides to
      SPKI DER).

  X.509-CERT mode (--cert):
      python3 ca_dns_txt.py --domain factsorlie.com \\
          --cert /home/ubuntu/.mtc-ca-data/factsorlie.com/ca_cert.pem

      Extracts the SubjectPublicKeyInfo DER from the cert and
      hashes THAT with SHA3-256.  Used for CA-enrollment domain
      validation on port 8445 — mtc-keymaster/server2/c/
      mtc_ca_validate.c::mtc_validate_ca_dns_txt computes the
      same SPKI-DER SHA3-256 from the requester's
      ca_certificate_pem and looks it up via
      mtc_dnssec_pin.c::mqc_dnssec_validate_ca_kh.

The wire-format string is identical in both modes:

    v=MQC1; role=ca; alg=ML-DSA-87; kh=sha3-256:<64-hex>

DNSSEC is required end-to-end: the zone hosting
_mqc-ca.<domain> MUST have a DS record at its parent and a
valid RRSIG on the TXT, otherwise both the probe and the
server's libunbound check fail with "DNSSEC insecure or
unsigned".  When the operator publishes BOTH a cosigner pin and
a CA-cert pin for the same domain, publish them as two TXT RRs
at the same name; the consumers walk every RR and accept the
first kh that matches what they're looking for.

Examples:

    # Cosigner pin (file-bytes hash):
    python3 ca_dns_txt.py --domain factsorlie.com \\
        ~/.TPM/ca-cosigner.pem

    # CA-enrollment pin (SPKI-DER hash):
    python3 ca_dns_txt.py --domain factsorlie.com \\
        --cert /home/ubuntu/.mtc-ca-data/factsorlie.com/ca_cert.pem

    # Either with --check to compare against live DNS:
    python3 ca_dns_txt.py --domain factsorlie.com --check \\
        --cert /path/to/ca_cert.pem
"""

import argparse
import hashlib
import subprocess
import sys


VERSION_TAG = "MQC1"
ROLE_TAG = "ca"
ALG_TAG = "ML-DSA-87"
HASH_TAG = "sha3-256"

# postWolf ships an OpenSSL 3.5+ build with PQC algorithms
# (kit-CA/buildopenssl3.5.sh).  Stock /usr/bin/openssl on most
# distros doesn't know ML-DSA-87, so prefer the bundled binary
# when extracting SPKI from a CA cert.
OPENSSL = "openssl40"


def sha3_256_file_hex(path: str) -> str:
    """SHA3-256 over the raw bytes of the file, lowercase hex."""
    h = hashlib.sha3_256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha3_256_spki_der_from_cert(cert_path: str) -> str:
    """Extract the SubjectPublicKeyInfo DER from a CA cert and
    SHA3-256 it.  Shells out to OpenSSL so we don't have to
    teach python-cryptography about ML-DSA-{44,65,87}."""
    try:
        pem = subprocess.run(
            [OPENSSL, "x509", "-in", cert_path, "-pubkey", "-noout"],
            capture_output=True, check=True).stdout
        der = subprocess.run(
            [OPENSSL, "pkey", "-pubin",
             "-inform", "PEM", "-outform", "DER"],
            input=pem, capture_output=True, check=True).stdout
    except FileNotFoundError:
        print(f"ERROR: {OPENSSL} not in PATH; install OpenSSL 3.5+ "
              "(buildopenssl3.5.sh in kit-CA/kit-leaf)",
              file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: {OPENSSL} failed to extract SPKI: "
              f"{e.stderr.decode(errors='replace').strip()}",
              file=sys.stderr)
        sys.exit(1)
    return hashlib.sha3_256(der).hexdigest()


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
    name can hold multiple RRs, and the consumers concatenate them)
    and accepts when any v=MQC1 entry has kh=sha3-256:<expected_hash>.
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

    # Walk every RR-line; each line may contain multiple
    # character-strings.  Match per RR (don't pre-concatenate
    # across RRs the way the probe does, because the v= and kh=
    # tokens MUST appear in the same RR for an unambiguous
    # value match).
    expected_kh = f"{HASH_TAG}:{expected_hash}"
    rr_lines = []
    for line in raw.splitlines():
        rr_text = " ".join(s.strip('"') for s in line.split('" "'))
        rr_lines.append(rr_text)
    # Join everything with ';' so multi-RR publishes still parse
    # under the same logic as the probe.
    joined = ";".join(rr_lines)
    fields = parse_txt_fields(joined)

    if fields.get("v", "") != VERSION_TAG:
        return False, (f"TXT at {qname} has no v={VERSION_TAG} "
                       f"(found: {fields.get('v', '<missing>')})")
    kh = fields.get("kh", "")
    if not kh.startswith(f"{HASH_TAG}:"):
        return False, f"TXT at {qname} has no kh={HASH_TAG}:<hex>"
    actual = kh[len(HASH_TAG) + 1:].lower()
    if actual == expected_hash:
        return True, f"MATCH at {qname} ({expected_kh[:24]}...)"
    return False, (f"TXT at {qname}: kh={actual[:16]}... "
                   f"!= expected {expected_hash[:16]}...")


def main():
    parser = argparse.ArgumentParser(
        description="Generate the MQC DNS TXT record")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("pem", nargs="?",
                     help="Path to a public-key PEM "
                          "(file-bytes hash, e.g. cosigner pin)")
    src.add_argument("--cert", metavar="PATH",
                     help="Path to a CA X.509 certificate PEM/DER "
                          "(SPKI-DER hash, e.g. CA-enrollment pin)")
    parser.add_argument("--domain", required=True,
                        help="Domain to publish under "
                             "(_mqc-ca.<domain>)")
    parser.add_argument("--check", action="store_true",
                        help="Query DNS and verify the published TXT "
                             "matches the local hash (does NOT verify "
                             "DNSSEC — use tests/mqc_dnssec_pin for "
                             "the full chain check)")
    args = parser.parse_args()

    if args.cert:
        fp = sha3_256_spki_der_from_cert(args.cert)
        src_label = f"CA cert SPKI DER ({args.cert})"
    else:
        fp = sha3_256_file_hex(args.pem)
        src_label = f"PEM file bytes ({args.pem})"

    print(f"Source:             {src_label}")
    print(f"Domain:             {args.domain}")
    print(f"SHA3-256:           {fp}")
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
    print(f"  kh    — SHA3-256 of {'SPKI DER' if args.cert else 'PEM file bytes'}")
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
        if not args.cert:
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
