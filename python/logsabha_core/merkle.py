"""Merkle tree exactly as RFC 6962 (Certificate Transparency).

  empty tree : SHA-256("")                      (nothing at all hashed in)
  leaf       : SHA-256(0x00 + leaf_data)
  node       : SHA-256(0x01 + left + right)
  split      : at the largest power of two LESS than n. A leaf is never duplicated.

For logs, leaf_data is the 32-byte entry hash.
The proof checker follows RFC 9162 section 2.1.3.2.
"""
from .signing import sha256


def leaf_hash(data: bytes) -> bytes:
    return sha256(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves) -> bytes:
    n = len(leaves)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return leaf_hash(leaves[0])
    k = _split(n)
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves, index: int):
    """List of hashes proving leaves[index] is inside the tree."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def verify_inclusion(leaf_data: bytes, index: int, tree_size: int, proof, root: bytes) -> bool:
    """True only if leaf_data at index really belongs to the tree with this root."""
    try:
        if tree_size < 1 or not 0 <= index < tree_size:
            return False
        if any(len(p) != 32 for p in proof):
            return False
        fn, sn = index, tree_size - 1
        r = leaf_hash(leaf_data)
        for p in proof:
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                r = node_hash(p, r)
                if not fn & 1:
                    while not fn & 1 and fn != 0:
                        fn >>= 1
                        sn >>= 1
            else:
                r = node_hash(r, p)
            fn >>= 1
            sn >>= 1
        return sn == 0 and r == root
    except (TypeError, ValueError):
        return False
