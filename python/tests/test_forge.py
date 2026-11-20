"""Tests for attacks/forge.py: what a witness's OWN key holder can do to its OWN database.

No chain, no other witness: this only needs one small local database, built with the same
test helpers test_witness.py already uses.
"""
import json
import sqlite3

import pytest

from logsabha_core import verify_batch_header, verify_chain

from attacks.forge import ForgeError, delete_and_reseal
from test_witness import KEYS, add, make


def entries_of(db_path):
    con = sqlite3.connect(str(db_path))
    try:
        return [json.loads(r[0]) for r in con.execute("SELECT entry_json FROM entries ORDER BY seq")]
    finally:
        con.close()


def batches_of(db_path):
    con = sqlite3.connect(str(db_path))
    try:
        return [json.loads(r[0]) for r in con.execute("SELECT header_json FROM batches ORDER BY batch_no")]
    finally:
        con.close()


def build(tmp_path, n=5):
    w = make(tmp_path, "app", wire=None, peers=())
    add(w, n)                                 # seq 1 is the restart marker; export entries are 2..n+1
    w.close_batch()
    w.store.close()
    return tmp_path / "app.db"


def test_a_deleted_entry_is_truly_gone_and_the_rest_stays_valid(tmp_path):
    db = build(tmp_path, 5)
    before = entries_of(db)
    assert len(before) == 6                                   # restart marker + 5 export entries
    target = before[3]["seq"]                                  # drop one entry in the middle

    out = delete_and_reseal(db, KEYS["app"], [target])
    assert out["dropped"] == [target]

    after = entries_of(db)
    assert len(after) == 5
    assert [e["seq"] for e in after] == list(range(1, 6))       # renumbered, no gap

    result = verify_chain(after, KEYS["app"].verify_key)
    assert result.valid, result                                 # the rebuilt chain is fully self-consistent

    # the deleted content does not survive under any other seq number either
    dropped_request_id = before[3]["request_id"]
    assert dropped_request_id not in {e["request_id"] for e in after}


def test_the_batch_header_recomputes_and_still_verifies(tmp_path):
    db = build(tmp_path, 5)
    before = entries_of(db)
    delete_and_reseal(db, KEYS["app"], [before[3]["seq"]])

    headers = batches_of(db)
    assert len(headers) == 1
    header = headers[0]
    assert header["first_seq"] == 1 and header["last_seq"] == 5         # the range closed up
    assert verify_batch_header(KEYS["app"].verify_key, header)           # still a valid signature
    # it was signed by the SAME key, not a different (forged) one: a wrong key must fail
    assert not verify_batch_header(KEYS["network"].verify_key, header)


def test_a_batch_entirely_before_the_drop_is_left_untouched(tmp_path):
    w = make(tmp_path, "app", wire=None, peers=())
    add(w, 3)
    w.close_batch()                            # batch 1: seq 1-4
    add(w, 3)
    w.close_batch()                            # batch 2: seq 5-7
    w.store.close()
    db = tmp_path / "app.db"

    before_headers = {h["batch_no"]: h for h in [json.loads(r[0]) for r in
                      sqlite3.connect(str(db)).execute("SELECT header_json FROM batches")]}
    first_batch_header_before = before_headers[1]

    drop_target = entries_of(db)[5]["seq"]      # an entry inside batch 2 (seq 5-7), not batch 1
    delete_and_reseal(db, KEYS["app"], [drop_target])

    after_headers = {json.loads(r[0])["batch_no"]: json.loads(r[0]) for r in
                     sqlite3.connect(str(db)).execute("SELECT header_json FROM batches")}
    assert after_headers[1] == first_batch_header_before         # batch 1 is byte-for-byte unchanged
    assert after_headers[2]["first_seq"] == 5 and after_headers[2]["last_seq"] == 6


def test_dropping_an_unknown_seq_is_an_error(tmp_path):
    db = build(tmp_path, 3)
    with pytest.raises(ForgeError):
        delete_and_reseal(db, KEYS["app"], [9999])


def test_dropping_a_whole_batch_is_refused(tmp_path):
    w = make(tmp_path, "app", wire=None, peers=())
    w.close_batch()                            # batch 1: just the restart marker (seq 1) on its own
    add(w, 1)
    w.close_batch()                            # batch 2: exactly one entry (seq 2), nothing else
    w.store.close()
    db = tmp_path / "app.db"
    only_entry_in_batch_2 = entries_of(db)[-1]["seq"]
    with pytest.raises(ForgeError):
        delete_and_reseal(db, KEYS["app"], [only_entry_in_batch_2])
