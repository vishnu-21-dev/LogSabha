import copy

from logsabha_core import (
    GENESIS_PREV_HASH, build_batch_header, entries_root_hex, entry_body,
    inclusion_proof, make_authenticator, merkle_root, sign_entry, verify_authenticator,
    verify_batch_header, verify_chain, verify_inclusion,
)


def test_clean_chain_is_valid(sk, vk, make_chain):
    chain = make_chain(sk, 10)
    assert chain[0]["seq"] == 1 and chain[0]["prev_hash"] == GENESIS_PREV_HASH
    assert [e["seq"] for e in chain] == list(range(1, 11))
    result = verify_chain(chain, vk)
    assert result.valid, str(result)


def test_editing_one_entry_fails_at_that_exact_seq(sk, vk, make_chain):
    chain = make_chain(sk, 10)
    chain[4]["bytes"] = 999999            # edit seq 5, change nothing else
    result = verify_chain(chain, vk)
    assert not result.valid
    assert [f.seq for f in result.failures] == [5]
    assert result.first_failure.code == "HASH_MISMATCH"
    print("\n  edit seq 5 ->", result)


def test_edit_and_recompute_hash_but_no_key_fails_signature_and_link(sk, vk, other_sk, make_chain):
    # Attacker WITHOUT the signing key edits seq 5 and re-signs with their own key.
    chain = make_chain(sk, 10)
    body = entry_body(chain[4])
    body["bytes"] = 1
    chain[4] = sign_entry(other_sk, body)
    result = verify_chain(chain, vk)
    assert not result.valid
    codes = {(f.seq, f.code) for f in result.failures}
    assert (5, "BAD_SIGNATURE") in codes   # not signed by the witness key
    assert (6, "BAD_PREV_HASH") in codes   # next entry no longer links
    print("\n  edit + rehash, wrong key ->", result)


def test_deleted_reordered_and_wrong_witness_entries_are_caught(sk, vk, make_chain):
    chain = make_chain(sk, 6)
    assert [f.seq for f in verify_chain(chain[:2] + chain[3:], vk).failures if f.code == "SEQ_NOT_CONSECUTIVE"] == [4]
    swapped = chain[:]
    swapped[2], swapped[3] = swapped[3], swapped[2]
    assert not verify_chain(swapped, vk).valid
    changed = copy.deepcopy(chain)
    changed[3]["witness_id"] = "network"
    assert any(f.code == "WITNESS_CHANGED" for f in verify_chain(changed, vk).failures)


def test_a_slice_can_be_checked_with_expected_start(sk, vk, make_chain):
    chain = make_chain(sk, 10)
    part = chain[4:]  # seq 5..10
    assert verify_chain(part, vk, expected_first_seq=5, expected_prev_hash=chain[3]["hash"]).valid
    assert not verify_chain(part, vk, expected_first_seq=6, expected_prev_hash=chain[3]["hash"]).valid
    assert not verify_chain(part, vk, expected_first_seq=5, expected_prev_hash="11" * 32).valid


def test_malformed_input_is_reported_not_raised(sk, vk, make_chain):
    chain = make_chain(sk, 3)
    del chain[1]["result"]
    result = verify_chain(chain + ["junk"], vk)
    assert any(f.code == "MALFORMED" and f.seq == 2 for f in result.failures)
    assert any(f.code == "MALFORMED" and f.seq is None for f in result.failures)


# ----------------------------------------------------------------------------
# THE KEY CASE
# ----------------------------------------------------------------------------
def rebuild_chain_after_edit(sk, chain, seq, changes):
    """What an attacker with root does: change entry `seq`, then recompute the
    hash, prev_hash link and signature of it and every entry after it."""
    forged = []
    for e in chain:
        body = entry_body(e)
        if e["seq"] == seq:
            body.update(changes)
        if forged:
            body["prev_hash"] = forged[-1]["hash"]
        forged.append(sign_entry(sk, body) if e["seq"] >= seq else e)
    return forged


def test_KEY_CASE_attacker_with_root_rebuilds_chain_and_it_still_looks_valid(sk, vk, make_chain):
    chain = make_chain(sk, 10)

    # Things that were created BEFORE the attack and live somewhere else:
    header = build_batch_header(sk, "app", "boot-1", 1, chain, "00" * 32, "ab" * 32)
    onchain_root = header["entries_root"]          # the root anchored on the blockchain
    old_auth = make_authenticator(sk, chain[4])    # a witness elsewhere kept this for seq 5
    old_proof = inclusion_proof([bytes.fromhex(e["hash"]) for e in chain], 4)

    # The attack: root on the box means the attacker can read the signing key,
    # so they edit seq 5 (bytes 500 -> 1) and rebuild everything after it.
    forged = rebuild_chain_after_edit(sk, chain, 5, {"bytes": 1})
    assert forged[4]["bytes"] == 1 and chain[4]["bytes"] == 500   # it really changed

    # 1) THE LIMIT: the chain checker cannot see the attack.
    result = verify_chain(forged, vk)
    assert result.valid, "limit: a fully rebuilt, re-signed chain passes the chain checker"
    print("\n  forged chain, chain checker says:", result)

    # 2) ...but the OLD signed header is still genuinely signed by the witness
    assert verify_batch_header(vk, header)
    # ...and the forged chain no longer produces the root that header (and the chain) recorded.
    forged_root = entries_root_hex(forged)
    assert forged_root != header["entries_root"]
    assert forged_root != onchain_root
    print("  old signed header / on-chain root :", onchain_root)
    print("  root of the forged chain          :", forged_root)

    # 3) The authenticator held by another witness no longer matches seq 5
    assert verify_authenticator(vk, old_auth)               # it is genuine...
    assert old_auth["hash"] != forged[4]["hash"]            # ...and disagrees with the forgery

    # 4) The forged entry cannot be proven to be inside the OLD root
    old_root_bytes = bytes.fromhex(onchain_root)
    assert not verify_inclusion(bytes.fromhex(forged[4]["hash"]), 4, 10, old_proof, old_root_bytes)
    # while the genuine entry still can
    assert verify_inclusion(bytes.fromhex(chain[4]["hash"]), 4, 10, old_proof, old_root_bytes)
    # untouched entries before the edit are identical, so detection points at seq 5
    assert [e["hash"] for e in forged[:4]] == [e["hash"] for e in chain[:4]]
    assert forged[4]["hash"] != chain[4]["hash"]
