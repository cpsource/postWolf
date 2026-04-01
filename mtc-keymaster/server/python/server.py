#!/usr/bin/env python3
"""
MTC CA/Log HTTP Server.

Implements a REST API for a Merkle Tree Certificate Authority and
Transparency Log, based on draft-ietf-plants-merkle-tree-certs-02.

Endpoints:

  GET  /                          - Server info and API overview
  GET  /log                       - Current log state (tree size, root, landmarks)
  GET  /log/entry/<index>         - Get a specific log entry
  GET  /log/proof/<index>         - Get and verify an inclusion proof
  GET  /log/checkpoint            - Get latest checkpoint
  GET  /log/consistency?old=N&new=M - Consistency proof between sizes
  POST /certificate/request       - Request a new certificate
  GET  /certificate/<index>       - Get an issued certificate
  GET  /trust-anchors             - List trust anchor IDs
  GET  /ca/public-key             - CA's public key (for cosignature verification)

Usage:
  python server.py [--host HOST] [--port PORT] [--data-dir DIR]
"""

import argparse
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from ca import CertificateAuthority


# Global CA instance
_ca: CertificateAuthority = None


class MTCRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the MTC CA/Log server."""

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str):
        self._send_json({"error": message}, status)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)

        if path == "" or path == "/":
            self._handle_index()
        elif path == "/log":
            self._handle_log_state()
        elif path.startswith("/log/entry/"):
            self._handle_log_entry(path)
        elif path.startswith("/log/proof/"):
            self._handle_log_proof(path)
        elif path == "/log/checkpoint":
            self._handle_checkpoint()
        elif path == "/log/consistency":
            self._handle_consistency(qs)
        elif path == "/certificate/search":
            self._handle_search_certificates(qs)
        elif path.startswith("/certificate/"):
            self._handle_get_certificate(path)
        elif path == "/trust-anchors":
            self._handle_trust_anchors()
        elif path == "/ca/public-key":
            self._handle_ca_public_key()
        else:
            self._send_error(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/certificate/request":
            self._handle_certificate_request()
        else:
            self._send_error(404, "not found")

    # --- Handlers ---

    def _handle_index(self):
        self._send_json({
            "server": "MTC CA/Log Server",
            "version": "0.1.0",
            "draft": "draft-ietf-plants-merkle-tree-certs-02",
            "ca_name": _ca.ca_name,
            "log_id": _ca.log_id,
            "tree_size": _ca.log.size,
            "endpoints": {
                "GET /": "This info page",
                "GET /log": "Current log state",
                "GET /log/entry/<index>": "Get log entry",
                "GET /log/proof/<index>": "Get inclusion proof",
                "GET /log/checkpoint": "Latest checkpoint",
                "GET /log/consistency?old=N&new=M": "Consistency proof",
                "POST /certificate/request": "Request a certificate",
                "GET /certificate/search?q=<subject>": "Search certificates by subject",
                "GET /certificate/<index>": "Get issued certificate",
                "GET /trust-anchors": "List trust anchor IDs",
                "GET /ca/public-key": "CA public key",
            },
        })

    def _handle_log_state(self):
        self._send_json(_ca.get_log_state())

    def _handle_log_entry(self, path: str):
        try:
            index = int(path.split("/")[-1])
        except ValueError:
            self._send_error(400, "invalid index")
            return

        entry = _ca.get_entry(index)
        if entry is None:
            self._send_error(404, f"entry {index} not found")
        else:
            self._send_json(entry)

    def _handle_log_proof(self, path: str):
        try:
            index = int(path.split("/")[-1])
        except ValueError:
            self._send_error(400, "invalid index")
            return

        result = _ca.verify_inclusion(index)
        if result is None:
            self._send_error(404, f"entry {index} not found")
        else:
            self._send_json(result)

    def _handle_checkpoint(self):
        if _ca.log.checkpoints:
            self._send_json(_ca.log.checkpoints[-1])
        else:
            # Create one
            cp = _ca.log.checkpoint()
            self._send_json(cp)

    def _handle_consistency(self, qs: dict):
        try:
            old_size = int(qs["old"][0])
            new_size = int(qs["new"][0])
        except (KeyError, ValueError, IndexError):
            self._send_error(400, "requires ?old=N&new=M query parameters")
            return

        if old_size < 1 or new_size > _ca.log.size or old_size > new_size:
            self._send_error(400, f"invalid sizes: old={old_size}, new={new_size}, log_size={_ca.log.size}")
            return

        proof = _ca.log.tree.consistency_proof(old_size, new_size)
        self._send_json({
            "old_size": old_size,
            "new_size": new_size,
            "old_root": _ca.log.tree.root_hash(old_size).hex(),
            "new_root": _ca.log.tree.root_hash(new_size).hex(),
            "proof": [h.hex() for h in proof],
        })

    def _handle_certificate_request(self):
        try:
            body = json.loads(self._read_body())
        except (json.JSONDecodeError, ValueError):
            self._send_error(400, "invalid JSON body")
            return

        subject = body.get("subject")
        public_key_pem = body.get("public_key_pem")
        if not subject or not public_key_pem:
            self._send_error(400, "requires 'subject' and 'public_key_pem' fields")
            return

        key_algorithm = body.get("key_algorithm", "EC-P256")
        validity_days = body.get("validity_days", 90)
        extensions = body.get("extensions", {})

        result = _ca.request_certificate(
            subject=subject,
            public_key_pem=public_key_pem,
            key_algorithm=key_algorithm,
            validity_days=validity_days,
            extensions=extensions,
        )

        self._send_json(result, 201)

    def _handle_search_certificates(self, qs: dict):
        query = qs.get("q", [""])[0]
        if not query:
            self._send_error(400, "requires ?q=<subject> query parameter")
            return
        results = _ca.search_certificates(query)
        self._send_json({"query": query, "results": results})

    def _handle_get_certificate(self, path: str):
        try:
            index = int(path.split("/")[-1])
        except ValueError:
            self._send_error(400, "invalid index")
            return

        cert = _ca.get_certificate(index)
        if cert is None:
            self._send_error(404, f"certificate {index} not found")
        else:
            self._send_json(cert)

    def _handle_trust_anchors(self):
        anchors = [
            {
                "id": _ca.log_id,
                "type": "standalone",
                "description": f"Log ID for CA {_ca.ca_name}",
            }
        ]
        for i, lm_size in enumerate(_ca.log.landmarks):
            anchors.append({
                "id": f"{_ca.log_id}.{i}",
                "type": "landmark",
                "landmark_index": i,
                "tree_size": lm_size,
            })
        self._send_json({"trust_anchors": anchors})

    def _handle_ca_public_key(self):
        self._send_json({
            "ca_name": _ca.ca_name,
            "cosigner_id": _ca.cosigner_id,
            "algorithm": "Ed25519",
            "public_key_pem": _ca.public_key_pem(),
        })

    def log_message(self, format, *args):
        """Override to add structured logging."""
        sys.stderr.write(
            f"[MTC] {self.client_address[0]} - {format % args}\n"
        )


def main():
    parser = argparse.ArgumentParser(description="MTC CA/Log Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=8443, help="Bind port")
    parser.add_argument("--ca-name", default="MTC-CA-1", help="CA name")
    parser.add_argument("--log-id", default="32473.1", help="Issuance log ID")
    args = parser.parse_args()

    global _ca
    _ca = CertificateAuthority(
        ca_name=args.ca_name,
        log_id=args.log_id,
    )

    server = HTTPServer((args.host, args.port), MTCRequestHandler)
    print(f"MTC CA/Log Server starting on {args.host}:{args.port}")
    print(f"  CA Name:  {args.ca_name}")
    print(f"  Log ID:   {args.log_id}")
    print(f"  Database: Neon PostgreSQL (MERKLE_NEON)")
    print(f"  Log size: {_ca.log.size} entries (rebuilt from DB)")
    print()
    print("Endpoints:")
    print(f"  http://{args.host}:{args.port}/")
    print(f"  http://{args.host}:{args.port}/log")
    print(f"  http://{args.host}:{args.port}/certificate/request  (POST)")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
