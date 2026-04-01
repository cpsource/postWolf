"""
Client-side trust store for MTC relying parties.

Manages:
- Trusted cosigner public keys (keyed by trust anchor ID)
- Cached landmark subtree hashes (for landmark certificate verification)
- Known log state (for consistency checking)

Per MTC draft Section 7: relying parties are configured with trusted
cosigners and optionally predistributed landmark subtree hashes.

State is persisted to a local JSON file so it survives across runs.
"""

import json
import time
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class TrustedCosigner:
    """A cosigner the client trusts."""
    cosigner_id: str
    log_id: str
    public_key_pem: str
    algorithm: str
    ca_name: str = ""
    added_at: float = 0.0


@dataclass
class CachedLandmark:
    """A cached landmark subtree hash for landmark certificate verification."""
    landmark_id: int
    tree_size: int
    subtree_hash: str  # hex
    trust_anchor_id: str
    fetched_at: float = 0.0


@dataclass
class LogState:
    """Cached state of a known log, for consistency checking."""
    log_id: str
    tree_size: int
    root_hash: str  # hex
    updated_at: float = 0.0


class TrustStore:
    """
    Local trust store for an MTC relying party.

    Persists to a JSON file. Manages trusted cosigners, landmark caches,
    and known log state.
    """

    def __init__(self, store_path: str = "trust_store.json"):
        self.store_path = Path(store_path)
        self.cosigners: dict[str, TrustedCosigner] = {}
        self.landmarks: dict[str, CachedLandmark] = {}  # keyed by trust_anchor_id
        self.log_states: dict[str, LogState] = {}  # keyed by log_id
        self._load()

    def _load(self):
        if not self.store_path.exists():
            return
        with open(self.store_path) as f:
            data = json.load(f)
        for c in data.get("cosigners", []):
            cs = TrustedCosigner(**c)
            self.cosigners[cs.cosigner_id] = cs
        for lm in data.get("landmarks", []):
            cl = CachedLandmark(**lm)
            self.landmarks[cl.trust_anchor_id] = cl
        for ls in data.get("log_states", []):
            s = LogState(**ls)
            self.log_states[s.log_id] = s

    def save(self):
        data = {
            "cosigners": [asdict(c) for c in self.cosigners.values()],
            "landmarks": [asdict(lm) for lm in self.landmarks.values()],
            "log_states": [asdict(s) for s in self.log_states.values()],
        }
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.store_path, "w") as f:
            json.dump(data, f, indent=2)

    # --- Cosigners ---

    def add_cosigner(
        self, cosigner_id: str, log_id: str, public_key_pem: str,
        algorithm: str, ca_name: str = "",
    ):
        self.cosigners[cosigner_id] = TrustedCosigner(
            cosigner_id=cosigner_id,
            log_id=log_id,
            public_key_pem=public_key_pem,
            algorithm=algorithm,
            ca_name=ca_name,
            added_at=time.time(),
        )
        self.save()

    def get_cosigner(self, cosigner_id: str) -> Optional[TrustedCosigner]:
        return self.cosigners.get(cosigner_id)

    def has_cosigner(self, cosigner_id: str) -> bool:
        return cosigner_id in self.cosigners

    # --- Landmarks ---

    def cache_landmark(
        self, landmark_id: int, tree_size: int,
        subtree_hash: str, trust_anchor_id: str,
    ):
        self.landmarks[trust_anchor_id] = CachedLandmark(
            landmark_id=landmark_id,
            tree_size=tree_size,
            subtree_hash=subtree_hash,
            trust_anchor_id=trust_anchor_id,
            fetched_at=time.time(),
        )
        self.save()

    def get_landmark(self, trust_anchor_id: str) -> Optional[CachedLandmark]:
        return self.landmarks.get(trust_anchor_id)

    def has_landmark(self, trust_anchor_id: str) -> bool:
        return trust_anchor_id in self.landmarks

    def highest_landmark_id(self, log_id: str) -> int:
        """Return the highest landmark ID cached for a given log, or -1."""
        best = -1
        for lm in self.landmarks.values():
            if lm.trust_anchor_id.startswith(log_id + "."):
                best = max(best, lm.landmark_id)
        return best

    # --- Log state ---

    def update_log_state(self, log_id: str, tree_size: int, root_hash: str):
        self.log_states[log_id] = LogState(
            log_id=log_id,
            tree_size=tree_size,
            root_hash=root_hash,
            updated_at=time.time(),
        )
        self.save()

    def get_log_state(self, log_id: str) -> Optional[LogState]:
        return self.log_states.get(log_id)

    def summary(self) -> dict:
        return {
            "trusted_cosigners": len(self.cosigners),
            "cached_landmarks": len(self.landmarks),
            "known_logs": len(self.log_states),
            "cosigner_ids": list(self.cosigners.keys()),
            "landmark_ids": [
                f"{lm.trust_anchor_id} (size={lm.tree_size})"
                for lm in self.landmarks.values()
            ],
            "log_summaries": {
                s.log_id: f"size={s.tree_size}"
                for s in self.log_states.values()
            },
        }
