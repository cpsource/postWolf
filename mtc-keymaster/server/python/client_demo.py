#!/usr/bin/env python3
"""
Demo client for the MTC CA/Log Server.

Demonstrates the full workflow:
1. Check server info
2. Request certificates for several subjects
3. Retrieve issued certificates
4. Verify inclusion proofs
5. Check trust anchors
6. Check consistency between log states
"""

import json
import sys
import urllib.request
import urllib.error

BASE = "http://localhost:8443"


def api_get(path: str) -> dict:
    url = f"{BASE}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def api_post(path: str, data: dict) -> dict:
    url = f"{BASE}{path}"
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def pp(label: str, data):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(json.dumps(data, indent=2))


def main():
    print("MTC CA/Log Server - Demo Client")
    print("Connecting to", BASE)

    # 1. Server info
    try:
        info = api_get("/")
    except urllib.error.URLError:
        print(f"\nERROR: Cannot connect to {BASE}")
        print("Start the server first:  python server.py")
        sys.exit(1)

    pp("Server Info", info)

    # 2. Request certificates
    subjects = [
        {"subject": "example.com", "key_algorithm": "EC-P256"},
        {"subject": "mail.example.com", "key_algorithm": "EC-P256"},
        {"subject": "urn:example:user:alice", "key_algorithm": "Ed25519"},
        {"subject": "urn:example:device:laptop-017", "key_algorithm": "EC-P256"},
    ]

    issued = []
    for s in subjects:
        # In a real system, each subject would generate their own key pair.
        # Here we use a placeholder.
        fake_pubkey = f"-----BEGIN PUBLIC KEY-----\nMFkwEwYH...fake-key-for-{s['subject']}\n-----END PUBLIC KEY-----"
        result = api_post("/certificate/request", {
            "subject": s["subject"],
            "public_key_pem": fake_pubkey,
            "key_algorithm": s["key_algorithm"],
            "validity_days": 90,
            "extensions": {"key_usage": "digitalSignature"},
        })
        issued.append(result)
        print(f"\n  Issued certificate #{result['index']} for {s['subject']}")

    pp("Last Issued Certificate (standalone)", issued[-1]["standalone_certificate"])

    if "landmark_certificate" in issued[-1]:
        pp("Last Issued Certificate (landmark)", issued[-1]["landmark_certificate"])

    # 3. Log state
    log_state = api_get("/log")
    pp("Log State", {
        "tree_size": log_state["tree_size"],
        "root_hash": log_state["root_hash"],
        "landmarks": log_state["landmarks"],
        "num_checkpoints": len(log_state["checkpoints"]),
    })

    # 4. Retrieve a certificate
    cert = api_get(f"/certificate/{issued[0]['index']}")
    pp(f"Retrieved Certificate #{issued[0]['index']}", {
        "subject": cert["standalone_certificate"]["tbs_entry"]["subject"],
        "trust_anchor_id": cert["standalone_certificate"]["trust_anchor_id"],
        "proof_length": len(cert["standalone_certificate"]["inclusion_proof"]),
    })

    # 5. Verify inclusion proofs
    for c in issued:
        proof_result = api_get(f"/log/proof/{c['index']}")
        status = "VALID" if proof_result["valid"] else "INVALID"
        print(f"\n  Inclusion proof for entry #{c['index']}: {status}")

    # 6. Check log entries
    for i in range(min(3, log_state["tree_size"])):
        entry = api_get(f"/log/entry/{i}")
        entry_type = "null_entry" if entry["type"] == 0 else "tbs_cert_entry"
        subject = entry["data"]["subject"] if entry["data"] else "(null)"
        print(f"  Entry {i}: type={entry_type}, subject={subject}")

    # 7. Trust anchors
    anchors = api_get("/trust-anchors")
    pp("Trust Anchors", anchors)

    # 8. CA public key
    ca_key = api_get("/ca/public-key")
    pp("CA Public Key", ca_key)

    # 9. Issue more certs to trigger landmarks, then check consistency
    old_size = log_state["tree_size"]
    print(f"\n  Issuing more certificates to grow log (current size: {old_size})...")

    for i in range(20):
        api_post("/certificate/request", {
            "subject": f"service-{i}.internal",
            "public_key_pem": f"-----BEGIN PUBLIC KEY-----\nfake-{i}\n-----END PUBLIC KEY-----",
            "key_algorithm": "EC-P256",
            "validity_days": 47,
        })

    new_state = api_get("/log")
    new_size = new_state["tree_size"]
    print(f"  Log grew to {new_size} entries")

    if old_size >= 1 and new_size > old_size:
        consistency = api_get(f"/log/consistency?old={old_size}&new={new_size}")
        pp("Consistency Proof", {
            "old_size": consistency["old_size"],
            "new_size": consistency["new_size"],
            "proof_hashes": len(consistency["proof"]),
        })

    # 10. Check landmarks after growth
    final_state = api_get("/log")
    if final_state["landmarks"]:
        print(f"\n  Landmarks: {final_state['landmarks']}")
        # Get a cert that has a landmark
        for idx in range(1, new_size):
            cert = api_get(f"/certificate/{idx}")
            if cert and "landmark_certificate" in cert:
                pp(f"Landmark Certificate (entry #{idx})", {
                    "landmark_id": cert["landmark_certificate"]["landmark_id"],
                    "landmark_tree_size": cert["landmark_certificate"]["landmark_subtree_end"],
                    "trust_anchor_id": cert["landmark_certificate"]["trust_anchor_id"],
                })
                break

    print(f"\n{'='*60}")
    print("  Demo complete!")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
