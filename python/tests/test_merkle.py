"""Merkle tests.

The 8 leaf inputs below are the standard Certificate Transparency test
inputs, and EXPECTED_ROOTS are the published roots for the first n of them
(RFC 6962 hashing: leaf 0x00, node 0x01, split at largest power of two < n).
You can compare them yourself with the CT reference tests
(github.com/google/certificate-transparency, merkle_tree_test / RFC 6962).
"""
import hashlib

import pytest

from logsabha_core import inclusion_proof, merkle_root, verify_inclusion

LEAVES = [bytes.fromhex(h) for h in (
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
)]

EXPECTED_ROOTS = {
    0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    4: "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    5: "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    7: "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    8: "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}


def test_print_roots_for_manual_checking():
    print("\n  n  root")
    for n in (0, 1, 2, 3, 4, 5, 7, 8):
        print("  %d  %s" % (n, merkle_root(LEAVES[:n]).hex()))


@pytest.mark.parametrize("n", sorted(EXPECTED_ROOTS))
def test_roots_match_rfc6962_reference(n):
    assert merkle_root(LEAVES[:n]).hex() == EXPECTED_ROOTS[n]


def test_empty_tree_root_is_sha256_of_empty_bytes():
    assert merkle_root([]) == hashlib.sha256(b"").digest()


def test_leaf_is_never_duplicated_for_odd_sizes():
    # With 3 leaves RFC 6962 gives node(node(l0,l1), l2). A "duplicate the
    # last leaf" tree would give node(node(l0,l1), node(l2,l2)).
    l = [hashlib.sha256(b"\x00" + x).digest() for x in LEAVES[:3]]
    node = lambda a, b: hashlib.sha256(b"\x01" + a + b).digest()
    assert merkle_root(LEAVES[:3]) == node(node(l[0], l[1]), l[2])
    assert merkle_root(LEAVES[:3]) != node(node(l[0], l[1]), node(l[2], l[2]))


@pytest.mark.parametrize("n", range(1, 18))
def test_every_proof_verifies(n):
    leaves = [bytes([i]) * 32 for i in range(n)]
    root = merkle_root(leaves)
    for i in range(n):
        proof = inclusion_proof(leaves, i)
        assert verify_inclusion(leaves[i], i, n, proof, root)


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 9])
def test_any_changed_byte_makes_the_proof_fail(n):
    leaves = [bytes([i]) * 32 for i in range(n)]
    root = merkle_root(leaves)

    def flip(b: bytes, pos: int) -> bytes:
        return b[:pos] + bytes([b[pos] ^ 1]) + b[pos + 1:]

    for i in range(n):
        proof = inclusion_proof(leaves, i)
        # every byte of the leaf
        for pos in range(32):
            assert not verify_inclusion(flip(leaves[i], pos), i, n, proof, root)
        # every byte of the root
        for pos in range(32):
            assert not verify_inclusion(leaves[i], i, n, proof, flip(root, pos))
        # every byte of every proof hash
        for j in range(len(proof)):
            for pos in range(32):
                bad = list(proof)
                bad[j] = flip(proof[j], pos)
                assert not verify_inclusion(leaves[i], i, n, bad, root)


def test_wrong_index_wrong_size_and_bad_proof_shape_fail():
    leaves = [bytes([i]) * 32 for i in range(6)]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 2)
    assert verify_inclusion(leaves[2], 2, 6, proof, root)
    assert not verify_inclusion(leaves[2], 3, 6, proof, root)      # wrong index
    # Tree size: a proof cannot always tell size 6 from 7 for a leaf in the
    # left half (the right half is one opaque hash in the proof). That is how
    # RFC 6962 works, so the size must come from the SIGNED batch header
    # (first_seq..last_seq), never from the proof. A size that changes the
    # shape of the path is still rejected:
    assert verify_inclusion(leaves[2], 2, 7, proof, root)          # documented RFC behaviour
    assert not verify_inclusion(leaves[2], 2, 3, proof, root)      # different path shape
    assert not verify_inclusion(leaves[2], 2, 12, proof, root)     # different path shape
    assert not verify_inclusion(leaves[2], 2, 6, proof[:-1], root) # proof too short
    assert not verify_inclusion(leaves[2], 2, 6, proof + [b"\x00" * 32], root)  # too long
    assert not verify_inclusion(leaves[2], 2, 6, [b"short"], root)
    assert not verify_inclusion(leaves[2], 9, 6, proof, root)      # index out of range
    assert not verify_inclusion(leaves[2], 0, 0, [], root)         # empty tree has no leaves
