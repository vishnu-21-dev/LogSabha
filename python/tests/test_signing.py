from logsabha_core import (
    DOMAIN_AUTH, DOMAIN_BATCH, DOMAIN_ENTRY, DOMAIN_RECEIPT,
    build_batch_header, make_authenticator, sign, sign_entry, sign_receipt, verify,
    verify_authenticator, verify_batch_header, verify_entry_signature, verify_receipt,
)
from conftest import entry_fields

HASH = b"\x11" * 32


def make_entry(sk):
    body = {**entry_fields(1), "seq": 1, "prev_hash": "00" * 32}
    return sign_entry(sk, body)


def test_good_signature_verifies(sk, vk):
    assert verify(DOMAIN_ENTRY, vk, HASH, sign(DOMAIN_ENTRY, sk, HASH))


def test_bad_signature_fails(sk, vk):
    sig = bytearray(sign(DOMAIN_ENTRY, sk, HASH))
    sig[0] ^= 1
    assert not verify(DOMAIN_ENTRY, vk, HASH, bytes(sig))
    assert not verify(DOMAIN_ENTRY, vk, HASH, b"too short")
    assert not verify(DOMAIN_ENTRY, vk, HASH, sign(DOMAIN_ENTRY, sk, b"\x22" * 32))  # other message


def test_wrong_key_fails(sk, other_sk):
    sig = sign(DOMAIN_ENTRY, sk, HASH)
    assert not verify(DOMAIN_ENTRY, other_sk.verify_key, HASH, sig)


def test_wrong_domain_prefix_fails(sk, vk):
    sig = sign(DOMAIN_ENTRY, sk, HASH)
    for other in (DOMAIN_BATCH, DOMAIN_AUTH, DOMAIN_RECEIPT, b"B3-ENTRY-V2"):
        assert not verify(other, vk, HASH, sig)


def test_entry_signature_checks(sk, vk, other_sk):
    e = make_entry(sk)
    assert verify_entry_signature(vk, e)
    assert not verify_entry_signature(other_sk.verify_key, e)          # wrong key
    assert not verify_entry_signature(vk, {**e, "sig": "00" * 64})     # bad signature
    assert not verify_entry_signature(vk, {**e, "sig": "not hex"})     # garbage
    assert not verify_entry_signature(vk, {k: v for k, v in e.items() if k != "sig"})


def test_a_signature_from_one_message_type_cannot_be_reused_for_another(sk, vk, make_chain):
    # An entry signature signs the 32-byte entry hash with the ENTRY domain.
    # Even if someone builds a receipt whose digest were identical, the domain differs.
    e = make_chain(sk, 1)[0]
    stolen = e["sig"]
    auth = {"witness_id": e["witness_id"], "seq": e["seq"], "hash": e["hash"], "sig": stolen}
    assert not verify_authenticator(vk, auth)


def fields_batch(sk, chain):
    return build_batch_header(sk, "app", "boot-1", 1, chain, "00" * 32, "ab" * 32)


def test_batch_header_sign_and_verify(sk, vk, other_sk, make_chain):
    chain = make_chain(sk, 5)
    h = fields_batch(sk, chain)
    assert h["first_seq"] == 1 and h["last_seq"] == 5
    assert verify_batch_header(vk, h)
    assert not verify_batch_header(other_sk.verify_key, h)                 # wrong key
    assert not verify_batch_header(vk, {**h, "last_seq": 6})               # changed field
    assert not verify_batch_header(vk, {**h, "entries_root": "ff" * 32})   # changed root
    assert not verify_batch_header(vk, {**h, "extra": 1})                  # extra field
    assert not verify_batch_header(vk, {k: v for k, v in h.items() if k != "policy_hash"})
    assert not verify_batch_header(vk, {**h, "sig": "00" * 64})            # bad signature


def test_authenticator_sign_and_verify(sk, vk, other_sk, make_chain):
    e = make_chain(sk, 3)[2]
    a = make_authenticator(sk, e)
    assert set(a) == {"witness_id", "seq", "hash", "sig"}
    assert verify_authenticator(vk, a)
    assert not verify_authenticator(other_sk.verify_key, a)
    assert not verify_authenticator(vk, {**a, "seq": 2})
    assert not verify_authenticator(vk, {**a, "hash": "00" * 32})


def test_receipt_sign_and_verify(sk, vk, other_sk):
    r = sign_receipt(sk, {
        "recipient": "network", "source": "app", "source_batch": 4,
        "source_root": "aa" * 32, "first_seq": 1, "last_seq": 50,
        "recipient_batch": 9, "received_at": "2026-11-20T02:06:00Z",
    })
    assert verify_receipt(vk, r)
    assert not verify_receipt(other_sk.verify_key, r)
    assert not verify_receipt(vk, {**r, "source_root": "bb" * 32})
    assert not verify_receipt(vk, {**r, "recipient_batch": 10})
    assert not verify_batch_header(vk, r)   # a receipt is not a batch header
