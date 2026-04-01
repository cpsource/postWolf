"""
Client-side Merkle proof verification.

Implements the relying party verification logic from the MTC draft
(draft-ietf-plants-merkle-tree-certs-02) Sections 4.3 and 7.

This is intentionally a standalone module — a relying party should not
depend on CA/server code to verify certificates.
"""

import hashlib


def hash_leaf(data: bytes) -> bytes:
    """RFC 9162 Section 2.1: HASH(0x00 || leaf_data)"""
    return hashlib.sha256(b"\x00" + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """RFC 9162 Section 2.1: HASH(0x01 || left || right)"""
    return hashlib.sha256(b"\x01" + left + right).digest()


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

    Args:
        entry_hash: The leaf hash of the entry being proven.
        index: The entry's index in the log.
        start: Start of the subtree interval.
        end: End of the subtree interval.
        proof: List of sibling hashes constituting the proof.
        expected_root: The expected subtree root hash.

    Returns:
        True if the proof is valid.
    """
    fn = index - start
    sn = end - start - 1
    r = entry_hash

    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = hash_node(p, r)
            while fn > 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            r = hash_node(r, p)
        fn >>= 1
        sn >>= 1

    return sn == 0 and r == expected_root


def verify_consistency_proof(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: list[bytes],
) -> bool:
    """
    Verify a consistency proof between two tree sizes.
    Per RFC 9162 Section 2.1.4.2.

    Proves that the tree of old_size is a prefix of the tree of new_size.

    Args:
        old_size: The earlier tree size.
        new_size: The later tree size.
        old_root: Root hash at old_size.
        new_root: Root hash at new_size.
        proof: List of hashes constituting the consistency proof.

    Returns:
        True if the proof is valid.
    """
    if old_size == new_size:
        return old_root == new_root and len(proof) == 0

    if old_size < 1 or old_size > new_size:
        return False

    # Step 1: proof must not be empty
    if not proof:
        return False

    proof = list(proof)

    # Step 2: if old_size is an exact power of 2, prepend old_root
    if old_size & (old_size - 1) == 0:
        proof = [old_root] + proof

    # Step 3
    fn = old_size - 1
    sn = new_size - 1

    # Step 4: strip trailing 1-bits from fn
    while fn & 1:
        fn >>= 1
        sn >>= 1

    # Step 5: initialize fr and sr from the first proof element
    fr = proof[0]
    sr = proof[0]

    # Step 6: process remaining proof elements
    for c in proof[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = hash_node(c, fr)
            sr = hash_node(c, sr)
            # Same inner shift as inclusion proof: shift while LSB NOT set
            while fn > 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = hash_node(sr, c)
        fn >>= 1
        sn >>= 1

    # Step 7
    return sn == 0 and fr == old_root and sr == new_root


def verify_cosignature(
    public_key_pem: str,
    cosigner_id: str,
    log_id: str,
    start: int,
    end: int,
    subtree_hash: bytes,
    signature: bytes,
) -> bool:
    """
    Verify a CA cosignature over a subtree.
    Per MTC draft Section 5.4.1.

    Args:
        public_key_pem: The cosigner's Ed25519 public key in PEM format.
        cosigner_id: The cosigner's trust anchor ID.
        log_id: The issuance log's ID.
        start: Subtree start index.
        end: Subtree end index.
        subtree_hash: The subtree's hash value.
        signature: The Ed25519 signature bytes.

    Returns:
        True if the signature is valid.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature

    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    # Reconstruct MTCSubtreeSignatureInput
    sig_input = b"mtc-subtree/v1\n\x00"
    sig_input += cosigner_id.encode("utf-8")
    sig_input += log_id.encode("utf-8")
    sig_input += start.to_bytes(8, "big")
    sig_input += end.to_bytes(8, "big")
    sig_input += subtree_hash

    try:
        public_key.verify(signature, sig_input)
        return True
    except InvalidSignature:
        return False
