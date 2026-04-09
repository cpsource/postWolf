#!/usr/bin/env python3
"""
Issue a leaf enrollment nonce — CA operator tool.

The CA operator runs this to authorize a specific leaf key for enrollment.
The nonce is sent to the leaf user out-of-band (email, API, etc.).
The leaf user then calls: main.py enroll <domain> --nonce <nonce>

Usage:
    python3 issue_leaf_nonce.py --server https://localhost:8444 example.com sha256:abc123...
    python3 issue_leaf_nonce.py --server https://localhost:8444 example.com --key-file leaf-pubkey.pem

The server verifies that a registered CA exists for this domain before
issuing the nonce.
"""

import argparse
import hashlib
import json
import sys
import urllib.request
import urllib.error

from cryptography.hazmat.primitives import serialization


def fingerprint_from_pem(pem_path: str) -> str:
    """Compute SHA-256 fingerprint of a public key PEM file."""
    with open(pem_path, "rb") as f:
        data = f.read()

    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    pub = load_pem_public_key(data)
    pub_der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pub_der).hexdigest()


def request_nonce(server_url: str, domain: str, fp: str) -> dict:
    """Request a leaf enrollment nonce from the server."""
    url = f"{server_url.rstrip('/')}/enrollment/nonce"
    body = json.dumps({
        "domain": domain,
        "public_key_fingerprint": f"sha256:{fp}",
        "type": "leaf",
    }).encode("utf-8")

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        print(f"ERROR: server returned {e.code}: {err}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Issue a leaf enrollment nonce (CA operator tool)")
    parser.add_argument("domain", help="Domain for the leaf (e.g., example.com)")
    parser.add_argument("fingerprint", nargs="?", default=None,
                        help="Leaf public key fingerprint (sha256:hex)")
    parser.add_argument("--key-file", default=None,
                        help="Path to leaf public key PEM (alternative to fingerprint)")
    parser.add_argument("--server", required=True,
                        help="MTC server URL")
    args = parser.parse_args()

    # Get fingerprint
    if args.key_file:
        fp = fingerprint_from_pem(args.key_file)
        print(f"Leaf public key fingerprint: sha256:{fp}")
    elif args.fingerprint:
        fp = args.fingerprint
        if fp.startswith("sha256:"):
            fp = fp[7:]
    else:
        print("ERROR: provide fingerprint or --key-file", file=sys.stderr)
        sys.exit(1)

    print(f"Requesting leaf nonce for '{args.domain}'...")
    result = request_nonce(args.server, args.domain, fp)

    nonce = result["nonce"]
    expires = result["expires"]
    ca_index = result.get("ca_index", "?")

    print(f"\nLeaf enrollment nonce issued:")
    print(f"  Domain:    {args.domain}")
    print(f"  Nonce:     {nonce}")
    print(f"  Expires:   {expires} (15 minutes)")
    print(f"  CA index:  {ca_index}")
    print(f"\nSend this nonce to the leaf user. They enroll with:")
    print(f"  python3 main.py --server {args.server} enroll {args.domain} --nonce {nonce}")


if __name__ == "__main__":
    main()
