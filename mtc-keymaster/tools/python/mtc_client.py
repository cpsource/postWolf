"""
MTC Relying Party / Client.

Implements the relying party role from the MTC draft
(draft-ietf-plants-merkle-tree-certs-02) Section 7.

Capabilities:
- Generate key pairs and request certificates from a CA/Log server
- Verify standalone certificates (inclusion proof + cosignature)
- Verify landmark certificates (inclusion proof against cached landmark)
- Monitor log consistency over time
- Fetch and cache landmark subtree hashes
- Manage a local trust store
"""

import json
import time
import urllib.request
import urllib.error
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization

from verify import hash_leaf, verify_inclusion_proof, verify_consistency_proof, verify_cosignature
from trust_store import TrustStore


class MTCClient:
    """
    MTC relying party client.

    Talks to a CA/Log server, verifies certificates locally, and
    maintains a trust store of cosigner keys and landmark caches.
    """

    def __init__(self, server_url: str, store_path: str = "trust_store.json"):
        self.server_url = server_url.rstrip("/")
        self.store = TrustStore(store_path)

    # --- HTTP helpers ---

    def _get(self, path: str) -> dict:
        url = f"{self.server_url}{path}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    def _post(self, path: str, data: dict) -> dict:
        url = f"{self.server_url}{path}"
        body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    # --- Bootstrap: fetch and trust the CA ---

    def bootstrap_trust(self) -> dict:
        """
        Fetch the CA's public key and register it as a trusted cosigner.

        In production, this would be done out-of-band (e.g. shipped with
        the OS or browser). Here we fetch it from the server on first use.

        Returns the CA info dict.
        """
        ca_info = self._get("/ca/public-key")
        self.store.add_cosigner(
            cosigner_id=ca_info["cosigner_id"],
            log_id=ca_info["cosigner_id"].rsplit(".ca", 1)[0],
            public_key_pem=ca_info["public_key_pem"],
            algorithm=ca_info["algorithm"],
            ca_name=ca_info["ca_name"],
        )
        return ca_info

    # --- Key generation ---

    @staticmethod
    def generate_key_pair(algorithm: str = "EC-P256") -> tuple[str, str]:
        """
        Generate a key pair for certificate enrollment.

        Returns (private_key_pem, public_key_pem).
        """
        if algorithm == "EC-P256":
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif algorithm == "Ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(f"unsupported algorithm: {algorithm}")

        priv_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        pub_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        return priv_pem, pub_pem

    # --- Certificate request ---

    def request_certificate(
        self,
        subject: str,
        public_key_pem: str,
        key_algorithm: str = "EC-P256",
        validity_days: int = 90,
        extensions: Optional[dict] = None,
    ) -> dict:
        """
        Request a certificate from the CA/Log server.
        Returns the full issuance result (standalone + optional landmark).
        """
        return self._post("/certificate/request", {
            "subject": subject,
            "public_key_pem": public_key_pem,
            "key_algorithm": key_algorithm,
            "validity_days": validity_days,
            "extensions": extensions or {},
        })

    # --- Certificate verification ---

    def verify_standalone_certificate(self, cert: dict) -> dict:
        """
        Verify a standalone MTC certificate.

        Per MTC draft Section 7:
        1. Reconstruct the entry hash from the TBS data
        2. Verify the inclusion proof against the subtree hash
        3. Verify the cosignature over the subtree
        4. Check the certificate is not expired

        Returns a dict with verification results.
        """
        sc = cert if "tbs_entry" in cert else cert.get("standalone_certificate", cert)

        results = {
            "type": "standalone",
            "index": sc["index"],
            "subject": sc["tbs_entry"]["subject"],
            "checks": {},
        }

        # 1. Reconstruct entry hash
        tbs = sc["tbs_entry"]
        tbs_serialized = json.dumps({
            "subject": tbs["subject"],
            "spk_algorithm": tbs["subject_public_key_algorithm"],
            "spk_hash": tbs["subject_public_key_hash"],
            "not_before": tbs["not_before"],
            "not_after": tbs["not_after"],
            "extensions": tbs["extensions"],
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

        entry_data = b"\x01" + tbs_serialized
        entry_hash = hash_leaf(entry_data)

        # 2. Verify inclusion proof
        proof = [bytes.fromhex(h) for h in sc["inclusion_proof"]]
        subtree_hash = bytes.fromhex(sc["subtree_hash"])

        inclusion_valid = verify_inclusion_proof(
            entry_hash=entry_hash,
            index=sc["index"],
            start=sc["subtree_start"],
            end=sc["subtree_end"],
            proof=proof,
            expected_root=subtree_hash,
        )
        results["checks"]["inclusion_proof"] = inclusion_valid

        # 3. Verify cosignatures
        cosig_results = []
        for cosig in sc.get("cosignatures", []):
            cosigner = self.store.get_cosigner(cosig["cosigner_id"])
            if cosigner is None:
                cosig_results.append({
                    "cosigner_id": cosig["cosigner_id"],
                    "valid": False,
                    "reason": "cosigner not in trust store",
                })
                continue

            sig_valid = verify_cosignature(
                public_key_pem=cosigner.public_key_pem,
                cosigner_id=cosig["cosigner_id"],
                log_id=cosig["log_id"],
                start=cosig["start"],
                end=cosig["end"],
                subtree_hash=bytes.fromhex(cosig["subtree_hash"]),
                signature=bytes.fromhex(cosig["signature"]),
            )
            cosig_results.append({
                "cosigner_id": cosig["cosigner_id"],
                "valid": sig_valid,
            })

        results["checks"]["cosignatures"] = cosig_results
        all_cosigs_valid = all(c["valid"] for c in cosig_results) and len(cosig_results) > 0

        # 4. Check expiry
        now = time.time()
        not_expired = tbs["not_before"] <= now <= tbs["not_after"]
        results["checks"]["not_expired"] = not_expired

        # Overall
        results["valid"] = inclusion_valid and all_cosigs_valid and not_expired
        return results

    def verify_landmark_certificate(self, cert: dict) -> dict:
        """
        Verify a landmark MTC certificate.

        Per MTC draft Section 6.3 / 7.4:
        1. Reconstruct the entry hash
        2. Look up the landmark subtree hash in the local trust store
        3. Verify the inclusion proof against the cached landmark hash
        4. Check expiry

        No signatures needed — trust comes from the predistributed landmark.

        Returns a dict with verification results.
        """
        lc = cert if "landmark_id" in cert else cert.get("landmark_certificate", cert)

        results = {
            "type": "landmark",
            "index": lc["index"],
            "subject": lc["tbs_entry"]["subject"],
            "landmark_id": lc["landmark_id"],
            "checks": {},
        }

        # 1. Reconstruct entry hash
        tbs = lc["tbs_entry"]
        tbs_serialized = json.dumps({
            "subject": tbs["subject"],
            "spk_algorithm": tbs["subject_public_key_algorithm"],
            "spk_hash": tbs["subject_public_key_hash"],
            "not_before": tbs["not_before"],
            "not_after": tbs["not_after"],
            "extensions": tbs["extensions"],
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

        entry_data = b"\x01" + tbs_serialized
        entry_hash = hash_leaf(entry_data)

        # 2. Check if we have this landmark cached
        trust_anchor_id = lc["trust_anchor_id"]
        cached = self.store.get_landmark(trust_anchor_id)

        if cached is None:
            results["checks"]["landmark_cached"] = False
            results["checks"]["inclusion_proof"] = False
            results["valid"] = False
            results["reason"] = f"landmark {trust_anchor_id} not in trust store"
            return results

        results["checks"]["landmark_cached"] = True

        # 3. Verify inclusion proof against cached landmark hash
        proof = [bytes.fromhex(h) for h in lc["inclusion_proof"]]
        landmark_hash = bytes.fromhex(cached.subtree_hash)

        inclusion_valid = verify_inclusion_proof(
            entry_hash=entry_hash,
            index=lc["index"],
            start=lc["landmark_subtree_start"],
            end=lc["landmark_subtree_end"],
            proof=proof,
            expected_root=landmark_hash,
        )
        results["checks"]["inclusion_proof"] = inclusion_valid

        # 4. Check expiry
        now = time.time()
        not_expired = tbs["not_before"] <= now <= tbs["not_after"]
        results["checks"]["not_expired"] = not_expired

        results["valid"] = inclusion_valid and not_expired
        return results

    # --- Log monitoring ---

    def fetch_log_state(self) -> dict:
        """Fetch and cache the current log state."""
        state = self._get("/log")
        log_id = state["log_id"]

        # Check consistency with previously known state
        prev = self.store.get_log_state(log_id)
        consistency = None

        if prev and state["tree_size"] > prev.tree_size:
            try:
                cp = self._get(
                    f"/log/consistency?old={prev.tree_size}&new={state['tree_size']}"
                )
                proof = [bytes.fromhex(h) for h in cp["proof"]]
                consistent = verify_consistency_proof(
                    old_size=prev.tree_size,
                    new_size=state["tree_size"],
                    old_root=bytes.fromhex(prev.root_hash),
                    new_root=bytes.fromhex(state["root_hash"]),
                    proof=proof,
                )
                consistency = {
                    "checked": True,
                    "old_size": prev.tree_size,
                    "new_size": state["tree_size"],
                    "consistent": consistent,
                }
            except Exception as e:
                consistency = {"checked": True, "error": str(e)}

        # Update cached state
        self.store.update_log_state(log_id, state["tree_size"], state["root_hash"])

        return {
            "log_id": log_id,
            "tree_size": state["tree_size"],
            "root_hash": state["root_hash"],
            "landmarks": state.get("landmarks", []),
            "consistency": consistency,
        }

    def fetch_landmarks(self) -> list[dict]:
        """
        Fetch trust anchors from the server and cache any new landmarks.

        Per MTC draft Section 7.4: relying parties periodically update
        their trusted subtree state from an update service.

        Returns list of newly cached landmarks.
        """
        anchors = self._get("/trust-anchors")
        newly_cached = []

        for anchor in anchors.get("trust_anchors", []):
            if anchor["type"] != "landmark":
                continue

            ta_id = anchor["id"]
            if self.store.has_landmark(ta_id):
                continue

            # Fetch the landmark subtree hash from the log state
            # The server's /log endpoint includes landmarks
            log_state = self._get("/log")
            tree_size = anchor["tree_size"]

            # Get the checkpoint that covers this landmark to obtain its hash
            # We ask the server for a proof at this tree size
            # For now, use the log/proof endpoint on an entry within the landmark
            # to indirectly get the subtree hash, or fetch it from the log state.
            # The server exposes root_hash for the full tree, not per-landmark.
            # We need to compute or request the landmark subtree hash.
            # Request a consistency proof from 0 to landmark_size to get the hash.
            # Actually, the simplest approach: fetch the checkpoint data.
            # Let's use entry 0's proof at the landmark tree size to get the root.
            try:
                # Ask the server for a proof that produces the landmark root
                proof_data = self._get(f"/log/consistency?old=1&new={tree_size}")
                landmark_root = proof_data["new_root"]

                self.store.cache_landmark(
                    landmark_id=anchor["landmark_index"],
                    tree_size=tree_size,
                    subtree_hash=landmark_root,
                    trust_anchor_id=ta_id,
                )
                newly_cached.append({
                    "trust_anchor_id": ta_id,
                    "tree_size": tree_size,
                    "subtree_hash": landmark_root,
                })
            except Exception as e:
                newly_cached.append({
                    "trust_anchor_id": ta_id,
                    "error": str(e),
                })

        return newly_cached

    def get_certificate(self, index: int) -> Optional[dict]:
        """Fetch a certificate from the server."""
        try:
            return self._get(f"/certificate/{index}")
        except urllib.error.HTTPError:
            return None

    def search_certificates(self, query: str) -> list[dict]:
        """Search certificates by subject."""
        return self._get(f"/certificate/search?q={query}")

    def server_info(self) -> dict:
        """Fetch basic server info."""
        return self._get("/")
