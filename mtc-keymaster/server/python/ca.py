"""
Merkle Tree Certificate Authority and Issuance Log.

Implements the CA and issuance log roles from the MTC draft
(draft-ietf-plants-merkle-tree-certs-02).

The CA:
- Maintains an append-only issuance log (Merkle Tree)
- Validates certificate requests
- Issues standalone MTC certificates with inclusion proofs
- Signs checkpoints (subtree roots) as the CA cosigner
- Supports landmarks for optimized certificates
- Tracks trust anchor IDs

All state is persisted to a Neon PostgreSQL database via db.py.
On startup, the Merkle tree is rebuilt in memory from stored entries.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from merkle import MerkleTree, hash_leaf
import db


@dataclass
class TBSCertificateLogEntry:
    """
    Simplified TBSCertificateLogEntry per MTC draft Section 5.3.

    In a full implementation this would be DER-encoded ASN.1.
    Here we use a JSON-serializable representation for clarity.
    """

    subject: str
    subject_public_key_algorithm: str
    subject_public_key_hash: str
    not_before: float
    not_after: float
    extensions: dict = field(default_factory=dict)

    def serialize(self) -> bytes:
        """Deterministic serialization for Merkle Tree hashing."""
        d = {
            "subject": self.subject,
            "spk_algorithm": self.subject_public_key_algorithm,
            "spk_hash": self.subject_public_key_hash,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "extensions": self.extensions,
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class MerkleTreeCertEntry:
    """
    MerkleTreeCertEntry per MTC draft Section 5.3.
    type 0 = null_entry, type 1 = tbs_cert_entry
    """

    entry_type: int
    tbs_entry: Optional[TBSCertificateLogEntry] = None

    def serialize(self) -> bytes:
        if self.entry_type == 0:
            return b"\x00"
        return b"\x01" + self.tbs_entry.serialize()


@dataclass
class Cosignature:
    """A cosignature over a subtree."""

    cosigner_id: str
    log_id: str
    start: int
    end: int
    subtree_hash: str
    signature: str
    algorithm: str


@dataclass
class StandaloneCertificate:
    """Standalone MTC Certificate per MTC draft Section 6.2."""

    index: int
    tbs_entry: dict
    inclusion_proof: list[str]
    subtree_start: int
    subtree_end: int
    subtree_hash: str
    cosignatures: list[dict]
    trust_anchor_id: str


@dataclass
class LandmarkCertificate:
    """Landmark MTC Certificate per MTC draft Section 6.3."""

    index: int
    tbs_entry: dict
    inclusion_proof: list[str]
    landmark_id: int
    landmark_subtree_start: int
    landmark_subtree_end: int
    landmark_subtree_hash: str
    trust_anchor_id: str


class IssuanceLog:
    """
    Append-only issuance log per MTC draft Section 5.

    Wraps a MerkleTree and maintains the log of MerkleTreeCertEntry objects.
    Persists entries, checkpoints, and landmarks to PostgreSQL.
    """

    def __init__(self, log_id: str, conn):
        self.log_id = log_id
        self.conn = conn
        self.tree = MerkleTree()
        self.entries: list[MerkleTreeCertEntry] = []
        self.checkpoints: list[dict] = []
        self.landmarks: list[int] = []
        self.landmark_interval = 16

        self._rebuild_from_db()

    def _rebuild_from_db(self):
        """Rebuild in-memory state from the database."""
        rows = db.load_all_entries(self.conn)

        if not rows:
            # Fresh database: insert the null entry (index 0)
            null_entry = MerkleTreeCertEntry(entry_type=0)
            serialized = null_entry.serialize()
            lh = hash_leaf(serialized)
            self.entries.append(null_entry)
            self.tree.append(serialized)
            db.save_entry(self.conn, 0, 0, None, serialized, lh)
        else:
            # Replay entries into the in-memory tree
            for row in rows:
                serialized = row["serialized"]
                entry_type = row["entry_type"]
                tbs_data = row["tbs_data"]

                if entry_type == 0:
                    entry = MerkleTreeCertEntry(entry_type=0)
                else:
                    entry = MerkleTreeCertEntry(
                        entry_type=1,
                        tbs_entry=TBSCertificateLogEntry(**tbs_data),
                    )

                self.entries.append(entry)
                self.tree.append(serialized)

        # Reload checkpoints and landmarks
        self.checkpoints = db.load_checkpoints(self.conn, self.log_id)
        self.landmarks = db.load_landmarks(self.conn)

    @property
    def size(self) -> int:
        return self.tree.size

    def add_entry(self, tbs: TBSCertificateLogEntry) -> int:
        """Add a TBS certificate entry to the log. Returns the entry index."""
        entry = MerkleTreeCertEntry(entry_type=1, tbs_entry=tbs)
        serialized = entry.serialize()
        lh = hash_leaf(serialized)

        self.entries.append(entry)
        idx = self.tree.append(serialized)

        # Persist to database
        db.save_entry(self.conn, idx, 1, asdict(tbs), serialized, lh)

        # Check if we should designate a new landmark
        if self.size % self.landmark_interval == 0:
            self.landmarks.append(self.size)
            db.save_landmark(self.conn, self.size)

        return idx

    def checkpoint(self) -> dict:
        """Create a checkpoint (snapshot) of the current log state."""
        root_hash = self.tree.root_hash().hex()
        ts = time.time()
        cp = {
            "log_id": self.log_id,
            "tree_size": self.size,
            "root_hash": root_hash,
            "timestamp": ts,
        }
        self.checkpoints.append(cp)
        db.save_checkpoint(self.conn, self.log_id, self.size, root_hash, ts)
        return cp

    def get_inclusion_proof(self, index: int, start: int = 0, end: Optional[int] = None) -> list[bytes]:
        if end is None:
            end = self.size
        return self.tree.inclusion_proof(index, start, end)

    def get_subtree_hash(self, start: int, end: int) -> bytes:
        return self.tree.subtree_hash(start, end)

    def find_landmark_for(self, index: int) -> Optional[int]:
        """Find the smallest landmark tree_size that includes the given index."""
        for lm in self.landmarks:
            if lm > index:
                return lm
        return None


class CertificateAuthority:
    """
    Merkle Tree Certificate Authority.

    Combines the CA role and CA cosigner role from the MTC draft.
    Manages the issuance log, signs checkpoints, and issues certificates.
    All state is persisted to PostgreSQL.
    """

    def __init__(
        self,
        ca_name: str = "MTC-CA-1",
        log_id: str = "32473.1",
    ):
        self.ca_name = ca_name
        self.log_id = log_id
        self.cosigner_id = f"{log_id}.ca"

        # Connect to database and initialize schema
        self.conn = db.get_connection()
        db.init_schema(self.conn)

        # Load or generate CA signing key (Ed25519)
        self._init_ca_key()

        # Initialize the issuance log (rebuilds tree from DB)
        self.log = IssuanceLog(log_id, self.conn)

        # Load issued certificates from DB
        self.certificates: dict[int, dict] = db.load_all_certificates(self.conn)

    def _init_ca_key(self):
        """Load CA key from database, or generate and store a new one."""
        stored_key = db.load_ca_config(self.conn, "ca_private_key_pem")
        if stored_key:
            self._private_key = serialization.load_pem_private_key(
                stored_key.encode(), password=None
            )
        else:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
            pem = self._private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()
            db.save_ca_config(self.conn, "ca_private_key_pem", pem)

        self._public_key = self._private_key.public_key()

    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def cosign_subtree(self, start: int, end: int) -> Cosignature:
        """
        Sign a subtree as the CA cosigner.
        Per MTC draft Section 5.4.1 / 5.5.
        """
        subtree_hash = self.log.get_subtree_hash(start, end)

        sig_input = b"mtc-subtree/v1\n\x00"
        sig_input += self.cosigner_id.encode("utf-8")
        sig_input += self.log_id.encode("utf-8")
        sig_input += start.to_bytes(8, "big")
        sig_input += end.to_bytes(8, "big")
        sig_input += subtree_hash

        signature = self._private_key.sign(sig_input)

        return Cosignature(
            cosigner_id=self.cosigner_id,
            log_id=self.log_id,
            start=start,
            end=end,
            subtree_hash=subtree_hash.hex(),
            signature=signature.hex(),
            algorithm="Ed25519",
        )

    def request_certificate(
        self,
        subject: str,
        public_key_pem: str,
        key_algorithm: str = "EC-P256",
        validity_days: int = 90,
        extensions: Optional[dict] = None,
    ) -> dict:
        """
        Process a certificate issuance request.

        1. Validate the request
        2. Build TBSCertificateLogEntry
        3. Add to issuance log
        4. Create checkpoint
        5. Cosign the subtree
        6. Assemble standalone certificate
        7. Optionally assemble landmark certificate
        """
        spk_hash = hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()

        now = time.time()
        tbs = TBSCertificateLogEntry(
            subject=subject,
            subject_public_key_algorithm=key_algorithm,
            subject_public_key_hash=spk_hash,
            not_before=now,
            not_after=now + (validity_days * 86400),
            extensions=extensions or {},
        )

        # Add to issuance log (persisted to DB)
        index = self.log.add_entry(tbs)

        # Checkpoint (persisted to DB)
        checkpoint = self.log.checkpoint()

        # Subtree covering this entry
        start = 0
        end = self.log.size

        # Cosign
        cosig = self.cosign_subtree(start, end)

        # Build inclusion proof
        proof = self.log.get_inclusion_proof(index, start, end)
        subtree_hash = self.log.get_subtree_hash(start, end)

        trust_anchor_id = self.log_id

        standalone = StandaloneCertificate(
            index=index,
            tbs_entry=asdict(tbs),
            inclusion_proof=[h.hex() for h in proof],
            subtree_start=start,
            subtree_end=end,
            subtree_hash=subtree_hash.hex(),
            cosignatures=[asdict(cosig)],
            trust_anchor_id=trust_anchor_id,
        )

        result = {
            "index": index,
            "standalone_certificate": asdict(standalone),
            "checkpoint": checkpoint,
        }

        # Check for landmark certificate
        landmark_size = self.log.find_landmark_for(index)
        if landmark_size is not None:
            lm_start = 0
            lm_end = landmark_size
            lm_proof = self.log.get_inclusion_proof(index, lm_start, lm_end)
            lm_hash = self.log.get_subtree_hash(lm_start, lm_end)
            lm_id = self.log.landmarks.index(landmark_size)

            lm_trust_anchor_id = f"{self.log_id}.{lm_id}"

            landmark = LandmarkCertificate(
                index=index,
                tbs_entry=asdict(tbs),
                inclusion_proof=[h.hex() for h in lm_proof],
                landmark_id=lm_id,
                landmark_subtree_start=lm_start,
                landmark_subtree_end=lm_end,
                landmark_subtree_hash=lm_hash.hex(),
                trust_anchor_id=lm_trust_anchor_id,
            )
            result["landmark_certificate"] = asdict(landmark)

        self.certificates[index] = result
        db.save_certificate(self.conn, index, result)
        return result

    def get_certificate(self, index: int) -> Optional[dict]:
        # Try in-memory first, fall back to DB
        cert = self.certificates.get(index)
        if cert is None:
            cert = db.load_certificate(self.conn, index)
            if cert is not None:
                self.certificates[index] = cert
        return cert

    def search_certificates(self, query: str) -> list[dict]:
        """Search certificates by subject (case-insensitive substring match)."""
        results = db.search_certificates_by_subject(self.conn, query)
        return [
            {
                "index": r["index"],
                "subject": r["certificate"]["standalone_certificate"]["tbs_entry"]["subject"],
            }
            for r in results
        ]

    def get_log_state(self) -> dict:
        """Return current log state for monitors / relying parties."""
        return {
            "log_id": self.log_id,
            "ca_name": self.ca_name,
            "cosigner_id": self.cosigner_id,
            "tree_size": self.log.size,
            "root_hash": self.log.tree.root_hash().hex(),
            "landmarks": self.log.landmarks,
            "checkpoints": self.log.checkpoints,
            "ca_public_key": self.public_key_pem(),
        }

    def get_entry(self, index: int) -> Optional[dict]:
        if 0 <= index < self.log.size:
            entry = self.log.entries[index]
            return {
                "index": index,
                "type": entry.entry_type,
                "data": asdict(entry.tbs_entry) if entry.tbs_entry else None,
                "leaf_hash": hash_leaf(entry.serialize()).hex(),
            }
        return None

    def verify_inclusion(self, index: int) -> Optional[dict]:
        """Generate and self-verify an inclusion proof for an entry."""
        if index < 0 or index >= self.log.size:
            return None

        entry = self.log.entries[index]
        entry_hash = hash_leaf(entry.serialize())

        start = 0
        end = self.log.size
        proof = self.log.get_inclusion_proof(index, start, end)
        root = self.log.get_subtree_hash(start, end)

        from merkle import verify_inclusion_proof
        valid = verify_inclusion_proof(entry_hash, index, start, end, proof, root)

        return {
            "index": index,
            "entry_hash": entry_hash.hex(),
            "subtree": {"start": start, "end": end},
            "root_hash": root.hex(),
            "proof": [h.hex() for h in proof],
            "valid": valid,
        }
