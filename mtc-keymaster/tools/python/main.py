#!/usr/bin/env python3
"""
MTC Client CLI.

Interactive client for the MTC CA/Log server that demonstrates the
full relying party workflow:

  1. Bootstrap trust (fetch and store CA's public key)
  2. Generate key pairs
  3. Request certificates
  4. Verify standalone certificates (proof + cosignature)
  5. Verify landmark certificates (proof against cached landmark)
  6. Monitor log consistency
  7. Fetch and cache landmarks

Usage:
  python main.py [--server URL] [--store PATH]
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from mtc_client import MTCClient

TPM_DIR = Path.home() / ".TPM"


def pp(label: str, data, indent: int = 2):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    if isinstance(data, dict) or isinstance(data, list):
        print(json.dumps(data, indent=indent))
    else:
        print(data)


def cmd_bootstrap(client: MTCClient):
    """Bootstrap: fetch CA key and add to trust store."""
    info = client.server_info()
    print(f"Connected to: {info['server']} v{info['version']}")
    print(f"  CA: {info['ca_name']}, Log: {info['log_id']}, Size: {info['tree_size']}")

    ca_info = client.bootstrap_trust()
    print(f"\nTrusted cosigner added:")
    print(f"  ID:        {ca_info['cosigner_id']}")
    print(f"  Algorithm: {ca_info['algorithm']}")
    print(f"  CA Name:   {ca_info['ca_name']}")

    # Also fetch initial log state
    log = client.fetch_log_state()
    print(f"\nLog state cached:")
    print(f"  Size: {log['tree_size']}, Root: {log['root_hash'][:32]}...")


def _subject_dir(subject: str) -> Path:
    """Get the ~/.TPM subdirectory for a subject, sanitizing the name."""
    safe = subject.replace("/", "_").replace(":", "_")
    return TPM_DIR / safe


def cmd_enroll(client: MTCClient, subject: str, algorithm: str = "EC-P256",
               extensions: dict = None):
    """Generate a key pair and request a certificate."""
    print(f"Generating {algorithm} key pair for '{subject}'...")
    priv_pem, pub_pem = client.generate_key_pair(algorithm)

    # Save keys to ~/.TPM/<subject>/
    subdir = _subject_dir(subject)
    subdir.mkdir(parents=True, exist_ok=True)

    key_path = subdir / "private_key.pem"
    key_path.write_text(priv_pem)
    os.chmod(key_path, 0o600)

    pub_path = subdir / "public_key.pem"
    pub_path.write_text(pub_pem)

    print(f"  Private key: {key_path}")
    print(f"  Public key:  {pub_path}")

    ext = {"key_usage": "digitalSignature"}
    if extensions:
        ext.update(extensions)

    print(f"\nRequesting certificate from CA...")
    result = client.request_certificate(
        subject=subject,
        public_key_pem=pub_pem,
        key_algorithm=algorithm,
        validity_days=90,
        extensions=ext,
    )

    idx = result["index"]

    # Save certificate to ~/.TPM/<subject>/
    cert_path = subdir / "certificate.json"
    with open(cert_path, "w") as f:
        json.dump(result, f, indent=2)

    # Save index for quick lookup
    (subdir / "index").write_text(str(idx))

    print(f"  Certificate issued: index #{idx}")
    print(f"  Certificate saved:  {cert_path}")
    print(f"  Trust anchor: {result['standalone_certificate']['trust_anchor_id']}")

    if "landmark_certificate" in result:
        lc = result["landmark_certificate"]
        print(f"  Landmark cert also available: landmark #{lc['landmark_id']}")

    return result


def cmd_enroll_ca(client: MTCClient, cert_path: str):
    """Register a CA certificate in the MTC log and store locally."""
    # Load and parse the X.509 CA cert
    with open(cert_path, "rb") as f:
        data = f.read()

    if b"-----BEGIN CERTIFICATE-----" in data:
        cert = x509.load_pem_x509_certificate(data)
        pem_str = data.decode()
    else:
        cert = x509.load_der_x509_certificate(data)
        pem_str = cert.public_bytes(serialization.Encoding.PEM).decode()

    # Check Basic Constraints
    try:
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS)
        if not bc.value.ca:
            print("ERROR: Certificate does not have CA:TRUE")
            sys.exit(1)
        pathlen = bc.value.path_length
    except x509.ExtensionNotFound:
        print("ERROR: No Basic Constraints extension found")
        sys.exit(1)

    subject_str = cert.subject.rfc4514_string()
    print(f"CA Certificate: {subject_str}")
    print(f"Basic Constraints: CA:TRUE, pathlen:{pathlen}")

    # Determine if this is a root (no pathlen constraint or pathlen > 0)
    # vs intermediate (pathlen:0). Root CAs skip DNS validation.
    is_root = pathlen is None or pathlen > 0

    # Extract public key PEM
    pub_pem = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # Compute fingerprint
    pub_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(pub_der).hexdigest()
    print(f"Public key SHA-256: {fp}")

    # Build subject name for storage
    # Use CN or first SAN DNS name
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        dns_names = []

    cns = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    ca_subject = dns_names[0] if dns_names else (cns[0].value if cns else "unknown-ca")

    if is_root:
        print(f"Root CA detected — skipping DNS validation")
    else:
        print(f"Intermediate CA — DNS validation will be performed by server")

    # Build extensions with the CA cert PEM
    extensions = {
        "ca_certificate_pem": pem_str,
        "is_ca": True,
        "ca_fingerprint": f"sha256:{fp}",
    }
    if is_root:
        extensions["root_ca"] = True

    print(f"\nRegistering CA '{ca_subject}' with server...")

    # Request certificate from server
    # For root CAs, the server won't find ca_certificate_pem SAN to check DNS,
    # so it passes through. For intermediates, DNS TXT is checked.
    result = client.request_certificate(
        subject=ca_subject,
        public_key_pem=pub_pem,
        validity_days=365,
        extensions=extensions,
    )

    idx = result["index"]
    print(f"  Registered in log: index #{idx}")

    # Save to ~/.TPM/<subject>/
    safe = ca_subject.replace("/", "_").replace(":", "_")
    subdir = TPM_DIR / safe
    subdir.mkdir(parents=True, exist_ok=True)

    cert_out = subdir / "certificate.json"
    with open(cert_out, "w") as f:
        json.dump(result, f, indent=2)

    # Also save the original X.509 CA cert
    ca_cert_path = subdir / "ca_cert.pem"
    ca_cert_path.write_text(pem_str)

    (subdir / "public_key.pem").write_text(pub_pem)
    (subdir / "index").write_text(str(idx))

    print(f"  Saved to: {subdir}")
    print(f"  CA cert:  {ca_cert_path}")
    print(f"  MTC cert: {cert_out}")

    return result


def cmd_verify(client: MTCClient, index: int):
    """Fetch and verify a certificate."""
    # Check ~/.TPM for a local copy first
    cert = None
    for subdir in TPM_DIR.iterdir() if TPM_DIR.exists() else []:
        idx_file = subdir / "index"
        if idx_file.exists() and idx_file.read_text().strip() == str(index):
            cert_file = subdir / "certificate.json"
            if cert_file.exists():
                with open(cert_file) as f:
                    cert = json.load(f)
                print(f"(loaded from {cert_file})")
                break

    if cert is None:
        cert = client.get_certificate(index)
    if cert is None:
        print(f"Certificate #{index} not found")
        return

    subject = cert["standalone_certificate"]["tbs_entry"]["subject"]
    print(f"Verifying certificate #{index} for '{subject}'...")

    # Verify standalone
    print(f"\n--- Standalone Certificate ---")
    sv = client.verify_standalone_certificate(cert["standalone_certificate"])
    print(f"  Inclusion proof: {'PASS' if sv['checks']['inclusion_proof'] else 'FAIL'}")
    for cosig in sv["checks"]["cosignatures"]:
        status = "PASS" if cosig["valid"] else f"FAIL ({cosig.get('reason', '')})"
        print(f"  Cosignature [{cosig['cosigner_id']}]: {status}")
    print(f"  Not expired:     {'PASS' if sv['checks']['not_expired'] else 'FAIL'}")
    print(f"  Overall:         {'VALID' if sv['valid'] else 'INVALID'}")

    # Verify landmark if present
    if "landmark_certificate" in cert:
        print(f"\n--- Landmark Certificate ---")
        lv = client.verify_landmark_certificate(cert["landmark_certificate"])
        cached = lv["checks"].get("landmark_cached", False)
        print(f"  Landmark cached: {'YES' if cached else 'NO'}")
        if cached:
            print(f"  Inclusion proof: {'PASS' if lv['checks']['inclusion_proof'] else 'FAIL'}")
            print(f"  Not expired:     {'PASS' if lv['checks']['not_expired'] else 'FAIL'}")
        print(f"  Overall:         {'VALID' if lv['valid'] else 'INVALID'}")
        if "reason" in lv:
            print(f"  Reason:          {lv['reason']}")

    return sv


def cmd_monitor(client: MTCClient):
    """Check log state and verify consistency with last known state."""
    print("Fetching log state...")
    log = client.fetch_log_state()
    print(f"  Log ID:    {log['log_id']}")
    print(f"  Tree size: {log['tree_size']}")
    print(f"  Root hash: {log['root_hash'][:32]}...")
    print(f"  Landmarks: {log['landmarks']}")

    if log["consistency"]:
        c = log["consistency"]
        if "error" in c:
            print(f"\n  Consistency check: ERROR - {c['error']}")
        else:
            status = "CONSISTENT" if c["consistent"] else "INCONSISTENT"
            print(f"\n  Consistency: {status}")
            print(f"    {c['old_size']} -> {c['new_size']}")
    else:
        print(f"\n  Consistency: first observation (nothing to compare)")


def cmd_landmarks(client: MTCClient):
    """Fetch and cache landmark subtree hashes."""
    print("Fetching landmarks from server...")
    newly_cached = client.fetch_landmarks()

    if not newly_cached:
        print("  No new landmarks to cache.")
    else:
        for lm in newly_cached:
            if "error" in lm:
                print(f"  FAIL: {lm['trust_anchor_id']} - {lm['error']}")
            else:
                print(f"  Cached: {lm['trust_anchor_id']} (tree_size={lm['tree_size']})")

    pp("Trust Store", client.store.summary())


def cmd_list_local():
    """List locally stored certificates in ~/.TPM."""
    if not TPM_DIR.exists():
        print("No local certificates (~/.TPM does not exist)")
        return

    entries = []
    for subdir in sorted(TPM_DIR.iterdir()):
        if not subdir.is_dir():
            continue
        idx_file = subdir / "index"
        cert_file = subdir / "certificate.json"
        has_key = (subdir / "private_key.pem").exists()

        idx = idx_file.read_text().strip() if idx_file.exists() else "?"
        subject = subdir.name
        if cert_file.exists():
            with open(cert_file) as f:
                cert = json.load(f)
            subject = cert.get("standalone_certificate", {}).get("tbs_entry", {}).get("subject", subdir.name)

        entries.append((idx, subject, has_key))

    if not entries:
        print("No local certificates in ~/.TPM")
        return

    print(f"Local certificates in ~/.TPM:\n")
    for idx, subject, has_key in entries:
        key_icon = "+" if has_key else "-"
        print(f"  [{key_icon}] index #{idx:>4s}  {subject}")
    print(f"\n  [+] = private key present, [-] = no private key")


def cmd_find(client: MTCClient, query: str):
    """Search certificates by subject."""
    result = client.search_certificates(query)
    matches = result.get("results", [])
    if not matches:
        print(f"No certificates found matching '{query}'")
        return
    print(f"Found {len(matches)} certificate(s) matching '{query}':\n")
    for m in matches:
        print(f"  index #{m['index']:4d}  {m['subject']}")


def cmd_trust_store(client: MTCClient):
    """Display the current trust store contents."""
    pp("Trust Store", client.store.summary())


def main():
    parser = argparse.ArgumentParser(description="MTC Client CLI")
    parser.add_argument("--server", default="http://localhost:8443", help="CA/Log server URL")
    parser.add_argument("--store", default="trust_store.json", help="Trust store file path")

    sub = parser.add_subparsers(dest="command", help="Command to run")

    sub.add_parser("bootstrap", help="Bootstrap trust (fetch CA key)")
    sub.add_parser("info", help="Show server info")
    sub.add_parser("list", help="List local certificates in ~/.TPM")
    sub.add_parser("trust-store", help="Show trust store contents")
    sub.add_parser("monitor", help="Check log consistency")
    sub.add_parser("landmarks", help="Fetch and cache landmarks")

    p_enroll_ca = sub.add_parser("enroll-ca",
        help="Register a CA certificate (root or intermediate)")
    p_enroll_ca.add_argument("cert", help="Path to CA certificate (PEM or DER)")

    p_enroll = sub.add_parser("enroll", help="Generate key + request certificate")
    p_enroll.add_argument("subject", help="Certificate subject (e.g. example.com)")
    p_enroll.add_argument("--algorithm", default="EC-P256", choices=["EC-P256", "Ed25519"])
    p_enroll.add_argument("--ext", action="append", metavar="KEY=VALUE",
                          help="Add extension (repeatable, e.g. --ext human_id='Cal Page')")

    p_verify = sub.add_parser("verify", help="Verify a certificate")
    p_verify.add_argument("index", type=int, help="Certificate index")

    p_find = sub.add_parser("find", help="Search certificates by subject")
    p_find.add_argument("query", help="Subject to search for (substring match)")

    p_demo = sub.add_parser("demo", help="Run full demo workflow")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    client = MTCClient(args.server, args.store)

    if args.command == "bootstrap":
        cmd_bootstrap(client)

    elif args.command == "info":
        pp("Server Info", client.server_info())

    elif args.command == "list":
        cmd_list_local()

    elif args.command == "trust-store":
        cmd_trust_store(client)

    elif args.command == "monitor":
        cmd_monitor(client)

    elif args.command == "landmarks":
        cmd_landmarks(client)

    elif args.command == "enroll-ca":
        cmd_enroll_ca(client, args.cert)

    elif args.command == "enroll":
        ext = {}
        for e in (args.ext or []):
            k, _, v = e.partition("=")
            ext[k] = v
        cmd_enroll(client, args.subject, args.algorithm, ext or None)

    elif args.command == "find":
        cmd_find(client, args.query)

    elif args.command == "verify":
        cmd_verify(client, args.index)

    elif args.command == "demo":
        run_demo(client)


def run_demo(client: MTCClient):
    """Run the full MTC client demo workflow."""
    print("=" * 60)
    print("  MTC Client - Full Demo")
    print("=" * 60)

    # 1. Bootstrap
    print("\n[1/7] Bootstrapping trust...")
    cmd_bootstrap(client)

    # 2. Enroll several subjects
    print("\n\n[2/7] Enrolling subjects...")
    certs = []
    for subject in ["alice.example.com", "bob.example.com", "urn:example:device:sensor-42"]:
        result = cmd_enroll(client, subject)
        certs.append(result)

    # 3. Verify each standalone certificate
    print("\n\n[3/7] Verifying standalone certificates...")
    for cert in certs:
        cmd_verify(client, cert["index"])

    # 4. Issue more certs to trigger landmarks
    print("\n\n[4/7] Issuing more certificates to trigger landmark allocation...")
    for i in range(20):
        client.request_certificate(
            subject=f"service-{i}.internal",
            public_key_pem=f"-----BEGIN PUBLIC KEY-----\nbulk-key-{i}\n-----END PUBLIC KEY-----",
            validity_days=47,
        )
    print(f"  Issued 20 additional certificates")

    # 5. Monitor log
    print("\n\n[5/7] Monitoring log consistency...")
    cmd_monitor(client)

    # 6. Fetch landmarks
    print("\n\n[6/7] Fetching and caching landmarks...")
    cmd_landmarks(client)

    # 7. Verify a landmark certificate
    print("\n\n[7/7] Verifying landmark certificates...")
    # Find a cert that has a landmark
    log_state = client.fetch_log_state()
    for idx in range(1, log_state["tree_size"]):
        cert = client.get_certificate(idx)
        if cert and "landmark_certificate" in cert:
            cmd_verify(client, idx)
            break
    else:
        print("  No landmark certificates found to verify")

    print(f"\n{'='*60}")
    print("  Demo complete!")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
