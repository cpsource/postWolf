#!/usr/bin/env python3
"""Show the contents of the ~/.TPM credential store."""

import argparse
import datetime
import json
import os
import ssl
import stat
import sys
import urllib.request
import urllib.error
from pathlib import Path

DEFAULT_TPM_DIR = Path.home() / ".TPM"
DEFAULT_SERVER = "localhost:8444"


def normalize_server_url(server):
    """Ensure server URL has https:// prefix."""
    if not server.startswith("http://") and not server.startswith("https://"):
        server = "https://" + server
    return server


def fmt_ts(ts):
    """Format a Unix timestamp as a human-readable UTC string."""
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def time_remaining(not_after):
    """Return a human-readable string for time until expiry."""
    now = datetime.datetime.now(datetime.timezone.utc)
    expiry = datetime.datetime.fromtimestamp(not_after, datetime.timezone.utc)
    delta = expiry - now
    if delta.total_seconds() <= 0:
        return "EXPIRED"
    days = delta.days
    hours, rem = divmod(delta.seconds, 3600)
    minutes = rem // 60
    if days > 0:
        return f"{days}d {hours}h remaining"
    return f"{hours}h {minutes}m remaining"


def file_perms(path):
    """Return file permission string like -rw------- ."""
    mode = path.stat().st_mode
    return stat.filemode(mode)


def load_cert(cert_path):
    """Load and return parsed certificate.json, or None on failure."""
    try:
        with open(cert_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def make_ssl_ctx():
    """Create an SSL context that accepts the server's self-signed cert."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def server_get(server, path, ssl_ctx):
    """GET a JSON endpoint from the MTC CA server. Returns parsed dict or None."""
    url = f"{server}{path}"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError):
        return None


def verify_entry(entry_dir, server, ssl_ctx):
    """Verify a TPM entry against the MTC CA server.

    Returns a dict with check results:
      server_found, revoked, proof_match, time_valid, errors[]
    """
    result = {
        "server_found": None,
        "revoked": None,
        "proof_match": None,
        "time_valid": None,
        "errors": [],
    }

    cert_path = entry_dir / "certificate.json"
    local_cert = load_cert(cert_path) if cert_path.exists() else None
    if not local_cert:
        result["errors"].append("no valid local certificate.json")
        return result

    sc = local_cert.get("standalone_certificate", {})
    cert_index = sc.get("index", local_cert.get("index"))
    if cert_index is None:
        result["errors"].append("no certificate index")
        return result

    # Fetch the certificate from the server
    server_cert = server_get(server, f"/certificate/{cert_index}", ssl_ctx)
    if server_cert is None:
        result["server_found"] = False
        result["errors"].append(f"certificate {cert_index} not found on server")
        return result
    result["server_found"] = True

    # Check revocation
    revoke_resp = server_get(server, f"/revoked/{cert_index}", ssl_ctx)
    if revoke_resp is not None:
        revoked = revoke_resp.get("revoked", False)
        result["revoked"] = revoked
        if revoked:
            result["errors"].append("REVOKED on server")
    else:
        result["revoked"] = False

    # Compare local proof against server proof
    local_sc = local_cert.get("standalone_certificate", {})
    server_sc = server_cert.get("standalone_certificate", {})

    local_tbs = local_sc.get("tbs_entry", {})
    server_tbs = server_sc.get("tbs_entry", {})

    # Compare subject and key hash
    if local_tbs.get("subject_public_key_hash") == server_tbs.get("subject_public_key_hash"):
        result["proof_match"] = True
    else:
        result["proof_match"] = False
        result["errors"].append("local key hash differs from server")

    # Time validity
    tbs = local_sc.get("tbs_entry", {})
    not_before = tbs.get("not_before")
    not_after = tbs.get("not_after")
    if not_before is not None and not_after is not None:
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        result["time_valid"] = (not_before <= now <= not_after)
        if not result["time_valid"]:
            result["errors"].append("certificate has expired")
    else:
        result["errors"].append("missing validity timestamps")

    return result


def show_entry(entry_dir, verbose=False, verify_result=None):
    """Display information about a single TPM entry."""
    name = entry_dir.name
    cert_path = entry_dir / "certificate.json"
    index_path = entry_dir / "index"
    has_private = (entry_dir / "private_key.pem").exists()
    has_public = (entry_dir / "public_key.pem").exists()
    has_ca_cert = (entry_dir / "ca_cert.pem").exists()

    # Determine entry type
    if has_ca_cert:
        entry_type = "CA"
    elif has_private:
        entry_type = "leaf"
    else:
        entry_type = "unknown"

    cert = load_cert(cert_path) if cert_path.exists() else None

    # Extract fields from certificate
    subject = None
    algorithm = None
    not_before = None
    not_after = None
    cert_index = None
    is_ca = False
    extensions = {}

    if cert:
        sc = cert.get("standalone_certificate", {})
        tbs = sc.get("tbs_entry", {})
        subject = tbs.get("subject")
        algorithm = tbs.get("subject_public_key_algorithm")
        not_before = tbs.get("not_before")
        not_after = tbs.get("not_after")
        cert_index = sc.get("index", cert.get("index"))
        extensions = tbs.get("extensions", {})
        is_ca = extensions.get("is_ca", False)
        if is_ca:
            entry_type = "CA"

    # Status line
    if not_after is not None:
        status = time_remaining(not_after)
    else:
        status = "no cert"

    expired = status == "EXPIRED"
    status_marker = "X" if expired else "+"

    print(f"  [{status_marker}] {name}")
    if subject and subject != name:
        print(f"      Subject:    {subject}")
    print(f"      Type:       {entry_type}")
    if algorithm:
        print(f"      Algorithm:  {algorithm}")
    if cert_index is not None:
        print(f"      Index:      {cert_index}")
    if not_before is not None and not_after is not None:
        print(f"      Valid:      {fmt_ts(not_before)} -> {fmt_ts(not_after)}")
        print(f"      Status:     {status}")

    if verbose:
        files = sorted(entry_dir.iterdir())
        print("      Files:")
        for f in files:
            perms = file_perms(f)
            size = f.stat().st_size
            print(f"        {perms}  {size:>6}  {f.name}")

        if extensions:
            key_usage = extensions.get("key_usage")
            if key_usage:
                print(f"      Key usage:  {key_usage}")
            if is_ca:
                fp = extensions.get("ca_fingerprint", "")
                print(f"      CA fingerprint: {fp}")
                if extensions.get("root_ca"):
                    print("      Root CA:    yes")

        if cert:
            cp = cert.get("checkpoint", {})
            if cp:
                log_id = cp.get("log_id", "")
                tree_size = cp.get("tree_size", "")
                print(f"      Log ID:     {log_id}")
                print(f"      Tree size:  {tree_size}")

    if verify_result is not None:
        ok = lambda v: "OK" if v else ("FAIL" if v is False else "?")
        print(f"      Verify:     server={ok(verify_result['server_found'])}  "
              f"revoked={'YES' if verify_result['revoked'] else 'no'}  "
              f"proof={ok(verify_result['proof_match'])}  "
              f"time={ok(verify_result['time_valid'])}")
        if verify_result["errors"]:
            for err in verify_result["errors"]:
                print(f"      *** {err}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Show the contents of the ~/.TPM credential store.",
        epilog="Examples:\n"
        "  show-tpm.py              List all entries with status\n"
        "  show-tpm.py -v           Verbose: show files, permissions, log info\n"
        "  show-tpm.py --verify     Verify entries against the MTC CA server\n"
        "  show-tpm.py --verify -s https://host:8444  Use a different server\n"
        "  show-tpm.py --cnt 3      Show only the first 3 entries\n"
        "  show-tpm.py -d /tmp/TPM  Use alternate TPM directory\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="show file details, permissions, and extended certificate info",
    )
    parser.add_argument(
        "-d", "--dir", type=Path, default=DEFAULT_TPM_DIR,
        help=f"path to TPM directory (default: {DEFAULT_TPM_DIR})",
    )
    parser.add_argument(
        "--cnt", type=int, default=0, metavar="N",
        help="only show the first N entries",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="output as JSON",
    )
    parser.add_argument(
        "--verify", action="store_true",
        help="verify each entry against the MTC CA server",
    )
    parser.add_argument(
        "-s", "--server", type=str, default=DEFAULT_SERVER,
        help=f"MTC CA server (default: {DEFAULT_SERVER})",
    )
    args = parser.parse_args()

    tpm_dir = args.dir
    if not tpm_dir.is_dir():
        print(f"Error: TPM directory not found: {tpm_dir}", file=sys.stderr)
        sys.exit(1)

    entries = sorted(
        [e for e in tpm_dir.iterdir() if e.is_dir()],
        key=lambda p: p.name,
    )

    if not entries:
        print(f"No entries found in {tpm_dir}")
        sys.exit(0)

    if args.cnt > 0:
        entries = entries[:args.cnt]

    if args.json_output:
        result = []
        for entry_dir in entries:
            cert_path = entry_dir / "certificate.json"
            cert = load_cert(cert_path) if cert_path.exists() else None
            info = {"name": entry_dir.name, "files": [f.name for f in sorted(entry_dir.iterdir())]}
            if cert:
                sc = cert.get("standalone_certificate", {})
                tbs = sc.get("tbs_entry", {})
                info["subject"] = tbs.get("subject")
                info["algorithm"] = tbs.get("subject_public_key_algorithm")
                info["not_before"] = tbs.get("not_before")
                info["not_after"] = tbs.get("not_after")
                info["index"] = sc.get("index", cert.get("index"))
                info["extensions"] = tbs.get("extensions", {})
                if tbs.get("not_after"):
                    info["status"] = time_remaining(tbs["not_after"])
            result.append(info)
        print(json.dumps(result, indent=2))
        sys.exit(0)

    # Set up verification if requested
    ssl_ctx = None
    verify_ok = True
    if args.verify:
        args.server = normalize_server_url(args.server)
        ssl_ctx = make_ssl_ctx()
        # Quick connectivity check
        info = server_get(args.server, "/", ssl_ctx)
        if info is None:
            print(f"Error: cannot reach MTC CA server at {args.server}", file=sys.stderr)
            sys.exit(1)
        server_name = info.get("ca_name", info.get("server", "unknown"))
        print(f"Server:    {args.server} ({server_name})")

    # Summary header
    perms = file_perms(tpm_dir)
    print(f"TPM Store: {tpm_dir}  ({perms})")
    print(f"Entries:   {len(entries)}")
    print(f"Legend:    [+] valid  [X] expired\n")

    for entry_dir in entries:
        vr = None
        if args.verify:
            vr = verify_entry(entry_dir, args.server, ssl_ctx)
            if vr["errors"]:
                verify_ok = False
        show_entry(entry_dir, verbose=args.verbose, verify_result=vr)

    if args.verify:
        if verify_ok:
            print("All entries verified OK.")
        else:
            print("Some entries have verification issues (see above).")
            sys.exit(2)


if __name__ == "__main__":
    main()
