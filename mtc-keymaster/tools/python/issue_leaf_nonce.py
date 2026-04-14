#!/usr/bin/env python3
"""
Issue a leaf enrollment nonce — CA operator tool.

The CA operator runs this to authorize a specific leaf key for enrollment.
The nonce is sent to the leaf user out-of-band (email, API, etc.).
The leaf user then enrolls via the DH bootstrap port using bootstrap_leaf.

Usage:
    python3 issue_leaf_nonce.py --domain example.com --key-file leaf-pubkey.pem --server https://localhost:8444
    python3 issue_leaf_nonce.py --domain example.com --fingerprint sha256:abc123... --server https://localhost:8444

The nonce is saved to ~/.mtc-ca-data/<domain>/nonce.txt and displayed in hex.
"""

import argparse
import hashlib
import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from pathlib import Path

DEFAULT_OUT = Path.home() / ".mtc-ca-data"


def fingerprint_from_pem(pem_path: str) -> str:
    """Compute SHA-256 fingerprint of a public key PEM file (raw PEM text hash)."""
    with open(pem_path, "r") as f:
        pem_text = f.read()
    return hashlib.sha256(pem_text.encode()).hexdigest()


def make_ssl_ctx():
    """Create an SSL context that accepts self-signed certs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


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
    req.add_header("Content-Length", str(len(body)))

    ctx = make_ssl_ctx()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        print(f"ERROR: server returned {e.code}: {err}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Issue a leaf enrollment nonce (CA operator tool)",
        epilog="Examples:\n"
        "  issue_leaf_nonce.py --domain example.com --key-file leaf.pub --server https://localhost:8444\n"
        "  issue_leaf_nonce.py --domain example.com --fingerprint sha256:abc... --server https://localhost:8444\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--domain", required=True,
                        help="Domain/subject for the leaf")
    parser.add_argument("--fingerprint", default=None,
                        help="Leaf public key fingerprint (sha256:hex)")
    parser.add_argument("--key-file", default=None,
                        help="Path to leaf public key PEM (alternative to --fingerprint)")
    parser.add_argument("--server", default="https://factsorlie.com:8444",
                        help="MTC server URL (default: https://factsorlie.com:8444)")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help=f"Base output directory (default: {DEFAULT_OUT})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be sent without contacting the server")
    args = parser.parse_args()

    # Get fingerprint — try --key-file, --fingerprint, or auto-detect from domain
    if args.key_file:
        fp = fingerprint_from_pem(args.key_file)
        print(f"Leaf public key fingerprint: sha256:{fp}")
    elif args.fingerprint:
        fp = args.fingerprint
        if fp.startswith("sha256:"):
            fp = fp[7:]
    else:
        # Auto-detect from ~/.mtc-ca-data/<domain>/public_key.pem
        auto_path = Path(args.out) / args.domain / "public_key.pem"
        if auto_path.exists():
            fp = fingerprint_from_pem(str(auto_path))
            print(f"Auto-detected public key: {auto_path}")
            print(f"Leaf public key fingerprint: sha256:{fp}")
        else:
            print(f"ERROR: no public key found at {auto_path}", file=sys.stderr)
            print("Provide --key-file or --fingerprint, or place the key at "
                  f"{auto_path}", file=sys.stderr)
            sys.exit(1)

    if args.dry_run:
        print(f"\n*** DRY RUN — would send to {args.server}:")
        print(f"  POST /enrollment/nonce")
        print(f"  {{")
        print(f'    "domain": "{args.domain}",')
        print(f'    "public_key_fingerprint": "sha256:{fp}",')
        print(f'    "type": "leaf"')
        print(f"  }}")
        return

    print(f"Requesting leaf nonce for '{args.domain}' from {args.server}...")
    result = request_nonce(args.server, args.domain, fp)

    nonce = result["nonce"]
    expires = result["expires"]
    ca_index = result.get("ca_index", "?")

    print(f"\nLeaf enrollment nonce issued:")
    print(f"  Domain:    {args.domain}")
    print(f"  Nonce:     {nonce}")
    print(f"  Expires:   {expires} (15 minutes)")
    print(f"  CA index:  {ca_index}")

    # Save nonce to file
    out_dir = Path(args.out) / args.domain
    out_dir.mkdir(parents=True, exist_ok=True)
    nonce_path = out_dir / "nonce.txt"
    with open(nonce_path, "w") as f:
        f.write(f"{nonce}\n")
    print(f"\n  Saved to:  {nonce_path}")

    print(f"\nSend this nonce to the leaf user. They enroll with:")
    print(f"  bootstrap_leaf --domain \"{args.domain}\" --nonce {nonce}")


if __name__ == "__main__":
    main()
