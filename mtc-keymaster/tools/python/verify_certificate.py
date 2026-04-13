#!/usr/bin/env python3
import argparse
import base64
import binascii
import hashlib
import json
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except Exception:
    Ed25519PublicKey = None
    load_pem_public_key = None


def canonical_json_bytes(obj) -> bytes:
    """
    Assumption:
      Canonical form is compact JSON with sorted keys and no extra whitespace.
    If your issuer used RFC 8785 JCS or another canonicalization, adjust here.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_pair_hex(left_hex: str, right_hex: str) -> str:
    left = bytes.fromhex(left_hex)
    right = bytes.fromhex(right_hex)
    return hashlib.sha256(left + right).hexdigest()


def compute_leaf_hash(tbs_entry: dict) -> str:
    """
    Assumption:
      leaf_hash = SHA256(canonical_json(tbs_entry))
    """
    return sha256_hex(canonical_json_bytes(tbs_entry))


def compute_merkle_root_from_proof(leaf_hash_hex: str, proof_hex_list, leaf_index: int) -> str:
    """
    Standard binary Merkle proof:
      if index is even: parent = H(node || sibling)
      if index is odd:  parent = H(sibling || node)
    """
    node = leaf_hash_hex
    idx = leaf_index

    for sibling in proof_hex_list:
        if idx % 2 == 0:
            node = hash_pair_hex(node, sibling)
        else:
            node = hash_pair_hex(sibling, node)
        idx //= 2

    return node


def build_cosignature_message(log_id: str, start: int, end: int, subtree_hash: str) -> bytes:
    """
    Assumption:
      The signed payload is canonical JSON of these fields.
    If your signer used a different format, change this function.
    """
    payload = {
        "log_id": log_id,
        "start": start,
        "end": end,
        "subtree_hash": subtree_hash,
    }
    return canonical_json_bytes(payload)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def require(d: dict, key: str):
    if key not in d:
        raise ValueError(f"Missing required field: {key}")
    return d[key]


def fmt_ts(ts: float) -> str:
    import datetime as dt
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat()


def verify_times(tbs_entry: dict, now: float):
    nb = require(tbs_entry, "not_before")
    na = require(tbs_entry, "not_after")

    status = {
        "not_before": nb,
        "not_after": na,
        "valid_now": (nb <= now <= na),
    }
    return status


def verify_cosignature(cosig: dict, pubkey_pem_path: Path | None):
    result = {
        "checked": False,
        "valid": None,
        "reason": None,
    }

    if pubkey_pem_path is None:
        result["reason"] = "No log public key supplied; skipped"
        return result

    if Ed25519PublicKey is None or load_pem_public_key is None:
        result["reason"] = "cryptography package not available"
        return result

    try:
        pem = pubkey_pem_path.read_bytes()
        pub = load_pem_public_key(pem)
        if not isinstance(pub, Ed25519PublicKey):
            result["reason"] = "Provided public key is not Ed25519"
            return result

        log_id = require(cosig, "log_id")
        start = require(cosig, "start")
        end = require(cosig, "end")
        subtree_hash = require(cosig, "subtree_hash")
        sig_hex = require(cosig, "signature")

        msg = build_cosignature_message(log_id, start, end, subtree_hash)
        sig = bytes.fromhex(sig_hex)
        pub.verify(sig, msg)

        result["checked"] = True
        result["valid"] = True
        return result
    except Exception as e:
        result["checked"] = True
        result["valid"] = False
        result["reason"] = str(e)
        return result


def main():
    ap = argparse.ArgumentParser(description="Verify MTC-style certificate.json")
    ap.add_argument("certificate_json", help="Path to certificate.json")
    ap.add_argument("--log-pubkey", help="Optional PEM Ed25519 public key for cosignature verification")
    ap.add_argument("--now", type=float, help="Override current Unix time")
    args = ap.parse_args()

    cert_path = Path(args.certificate_json)
    pubkey_path = Path(args.log_pubkey) if args.log_pubkey else None
    now = args.now if args.now is not None else time.time()

    doc = load_json(cert_path)

    sc = require(doc, "standalone_certificate")
    checkpoint = require(doc, "checkpoint")

    tbs_entry = require(sc, "tbs_entry")
    inclusion_proof = require(sc, "inclusion_proof")
    subtree_start = require(sc, "subtree_start")
    subtree_end = require(sc, "subtree_end")
    subtree_hash = require(sc, "subtree_hash")
    trust_anchor_id = require(sc, "trust_anchor_id")
    cosignatures = sc.get("cosignatures", [])

    cert_index = require(sc, "index")
    leaf_index = cert_index - subtree_start
    if leaf_index < 0:
        raise ValueError(f"Invalid index math: leaf_index={leaf_index}")

    # 1. Time validity
    time_status = verify_times(tbs_entry, now)

    # 2. Recompute leaf hash
    computed_leaf_hash = compute_leaf_hash(tbs_entry)
    declared_leaf_hash = tbs_entry.get("subject_public_key_hash")  # informational only, not the leaf hash

    # 3. Recompute Merkle root from proof
    computed_root = compute_merkle_root_from_proof(computed_leaf_hash, inclusion_proof, leaf_index)

    # 4. Check subtree and checkpoint consistency
    subtree_match = (computed_root == subtree_hash)
    checkpoint_root_hash = require(checkpoint, "root_hash")
    checkpoint_match = (subtree_hash == checkpoint_root_hash)

    # 5. Check checkpoint log id consistency
    checkpoint_log_id = require(checkpoint, "log_id")
    trust_anchor_match = (trust_anchor_id == checkpoint_log_id)

    # 6. Cosignatures
    cosig_results = []
    for cosig in cosignatures:
        r = verify_cosignature(cosig, pubkey_path)
        r["cosigner_id"] = cosig.get("cosigner_id")
        r["log_id"] = cosig.get("log_id")
        r["start"] = cosig.get("start")
        r["end"] = cosig.get("end")
        r["subtree_hash"] = cosig.get("subtree_hash")
        cosig_results.append(r)

    overall_ok = (
        time_status["valid_now"]
        and subtree_match
        and checkpoint_match
        and trust_anchor_match
    )

    report = {
        "subject": tbs_entry.get("subject"),
        "human_id": tbs_entry.get("extensions", {}).get("human_id"),
        "app_instance": tbs_entry.get("extensions", {}).get("app_instance"),
        "not_before": fmt_ts(time_status["not_before"]),
        "not_after": fmt_ts(time_status["not_after"]),
        "valid_now": time_status["valid_now"],
        "certificate_index": cert_index,
        "subtree_start": subtree_start,
        "subtree_end": subtree_end,
        "leaf_index_within_subtree": leaf_index,
        "computed_leaf_hash": computed_leaf_hash,
        "subject_public_key_hash_field": declared_leaf_hash,
        "computed_root_from_proof": computed_root,
        "subtree_hash_in_cert": subtree_hash,
        "checkpoint_root_hash": checkpoint_root_hash,
        "subtree_match": subtree_match,
        "checkpoint_match": checkpoint_match,
        "trust_anchor_id": trust_anchor_id,
        "checkpoint_log_id": checkpoint_log_id,
        "trust_anchor_match": trust_anchor_match,
        "cosignatures": cosig_results,
        "overall_ok_without_cosig_requirement": overall_ok,
        "notes": [
            "Leaf hash and cosignature message format are assumed; change compute_leaf_hash() and build_cosignature_message() if your issuer uses a different spec.",
            "subject_public_key_hash is treated as informational here; the Merkle leaf is derived from the entire tbs_entry.",
        ],
    }

    print(json.dumps(report, indent=2))

    if not overall_ok:
        sys.exit(2)

    for r in cosig_results:
        if r["checked"] and not r["valid"]:
            sys.exit(3)


if __name__ == "__main__":
    main()
