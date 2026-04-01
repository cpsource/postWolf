"""
Merkle Tree implementation following RFC 9162 Section 2.1 and the
MTC draft (draft-ietf-plants-merkle-tree-certs-02) Section 4.

Supports:
- Building a Merkle Tree over an append-only log
- Inclusion proofs (prove an entry is in a subtree)
- Subtree hashes
- Consistency proofs between tree sizes
"""

import hashlib
from typing import Optional


def hash_leaf(data: bytes) -> bytes:
    """RFC 9162 Section 2.1: HASH(0x00 || leaf_data)"""
    return hashlib.sha256(b"\x00" + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """RFC 9162 Section 2.1: HASH(0x01 || left || right)"""
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleTree:
    """Append-only Merkle Tree over byte-string entries."""

    def __init__(self):
        self.entries: list[bytes] = []
        self._leaf_hashes: list[bytes] = []

    @property
    def size(self) -> int:
        return len(self.entries)

    def append(self, entry: bytes) -> int:
        """Append an entry, return its index."""
        idx = len(self.entries)
        self.entries.append(entry)
        self._leaf_hashes.append(hash_leaf(entry))
        return idx

    def root_hash(self, tree_size: Optional[int] = None) -> bytes:
        """Compute MTH(D[0:tree_size]). Uses current size if omitted."""
        if tree_size is None:
            tree_size = self.size
        if tree_size == 0:
            return hashlib.sha256(b"").digest()
        return self._mth(0, tree_size)

    def _mth(self, start: int, end: int) -> bytes:
        """Compute MTH(D[start:end]) recursively."""
        n = end - start
        if n == 1:
            return self._leaf_hashes[start]
        # k = largest power of 2 < n
        k = 1 << (n - 1).bit_length() - 1
        left = self._mth(start, start + k)
        right = self._mth(start + k, end)
        return hash_node(left, right)

    def subtree_hash(self, start: int, end: int) -> bytes:
        """Hash of subtree [start, end)."""
        return self._mth(start, end)

    def inclusion_proof(self, index: int, start: int, end: int) -> list[bytes]:
        """
        Subtree inclusion proof for entry `index` in subtree [start, end).
        Returns list of sibling hashes needed to reconstruct the subtree root.
        """
        if not (start <= index < end):
            raise ValueError(f"index {index} not in [{start}, {end})")
        return self._inclusion_path(index - start, end - start, start)

    def _inclusion_path(self, m: int, n: int, offset: int) -> list[bytes]:
        """PATH(m, D_n) per RFC 9162 Section 2.1.3."""
        if n == 1:
            return []
        k = 1 << (n - 1).bit_length() - 1
        if m < k:
            path = self._inclusion_path(m, k, offset)
            path.append(self._mth(offset + k, offset + n))
            return path
        else:
            path = self._inclusion_path(m - k, n - k, offset + k)
            path.append(self._mth(offset, offset + k))
            return path

    def consistency_proof(self, old_size: int, new_size: int) -> list[bytes]:
        """
        Consistency proof between tree sizes, per RFC 9162 Section 2.1.4.
        Proves the tree of old_size is a prefix of the tree of new_size.
        """
        if old_size == 0 or old_size > new_size or new_size > self.size:
            raise ValueError("invalid sizes for consistency proof")
        return self._consistency_subproof(old_size, new_size, 0, True)

    def _consistency_subproof(
        self, m: int, n: int, offset: int, start_from_old: bool
    ) -> list[bytes]:
        if m == n:
            if start_from_old:
                return []
            else:
                return [self._mth(offset, offset + n)]
        k = 1 << (n - 1).bit_length() - 1
        if m <= k:
            proof = self._consistency_subproof(m, k, offset, start_from_old)
            proof.append(self._mth(offset + k, offset + n))
            return proof
        else:
            proof = self._consistency_subproof(m - k, n - k, offset + k, False)
            proof.append(self._mth(offset, offset + k))
            return proof


def verify_inclusion_proof(
    entry_hash: bytes,
    index: int,
    start: int,
    end: int,
    proof: list[bytes],
    expected_root: bytes,
) -> bool:
    """
    Verify a subtree inclusion proof per MTC draft Section 4.3.2-4.3.3.
    """
    fn = index - start
    sn = end - start - 1
    r = entry_hash

    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = hash_node(p, r)
            # "Until LSB(fn) is set, right-shift fn and sn equally"
            # i.e. while LSB is NOT set (and fn > 0), shift
            while fn > 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            r = hash_node(r, p)
        fn >>= 1
        sn >>= 1

    return sn == 0 and r == expected_root
